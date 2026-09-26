//! Test d'intégration bout-en-bout de la machine à états RA : soumission,
//! idempotence, approbation, émission, rejet, et politique « une seule
//! unité active par sujet » (renouvellement). CSR construites directement
//! avec `rsa`/`x509_cert` (pas via `oe_hsm`) : ce qui est sous test ici est
//! le protocole HMAC + PKCS#10, pas la primitive de signature HSM, déjà
//! couverte par les tests d'`oe-hsm`/`oe-ca-core`.

use std::str::FromStr;
use std::sync::Arc;

use der::asn1::BitString;
use der::{Decode, Encode};
use rsa::pkcs1v15::Pkcs1v15Sign;
use rsa::pkcs8::EncodePublicKey;
use rsa::{RsaPrivateKey, RsaPublicKey};
use sha2::{Digest, Sha256};
use x509_cert::attr::Attributes;
use x509_cert::name::Name;
use x509_cert::request::{CertReq, CertReqInfo};

use oe_ca_core::ceremony::{run_ceremony, CeremonyOptions};
use oe_ca_core::{profile, Issuer, Options as CaOptions};
use oe_castore::{Memory, RequestState, Store};
use oe_hsm::testing::SoftwareToken;
use oe_raflow::{Decider, DeciderOptions, Flow, Options, RaflowError};

const HMAC_SECRET: &str = "secret-de-test";

fn build_csr(cn: &str) -> (Vec<u8>, RsaPrivateKey) {
    build_csr_with_bits(cn, 3072)
}

fn build_csr_with_bits(cn: &str, bits: usize) -> (Vec<u8>, RsaPrivateKey) {
    let mut rng = rand::thread_rng();
    let key = RsaPrivateKey::new(&mut rng, bits).expect("clé RSA de test");
    let public_key = RsaPublicKey::from(&key);
    let spki_der = public_key
        .to_public_key_der()
        .expect("encodage SPKI")
        .as_bytes()
        .to_vec();
    let spki = x509_cert::SubjectPublicKeyInfo::from_der(&spki_der).unwrap();

    let subject = Name::from_str(&format!("CN={cn}")).unwrap();
    let info = CertReqInfo {
        version: x509_cert::request::Version::V1,
        subject,
        public_key: spki,
        attributes: Attributes::new(),
    };
    let tbs_der = info.to_der().unwrap();
    let digest = Sha256::digest(&tbs_der);
    let sig = key.sign(Pkcs1v15Sign::new::<Sha256>(), &digest).unwrap();

    let algorithm = spki::AlgorithmIdentifierOwned {
        oid: der::asn1::ObjectIdentifier::new("1.2.840.113549.1.1.11").unwrap(),
        parameters: None,
    };
    let csr = CertReq {
        info,
        algorithm,
        signature: BitString::from_bytes(&sig).unwrap(),
    };
    (csr.to_der().unwrap(), key)
}

async fn test_flow() -> (Flow, Arc<Memory>) {
    test_flow_with(None).await
}

async fn test_flow_with(recorder: Option<Arc<dyn oe_raflow::Recorder>>) -> (Flow, Arc<Memory>) {
    let store = Arc::new(Memory::new());
    let root_signer = Arc::new(SoftwareToken::generate(2048));
    let issuing_signer = Arc::new(SoftwareToken::generate(2048));
    let hierarchy = run_ceremony(CeremonyOptions {
        root_signer,
        issuing_signer: issuing_signer.clone(),
        root_cn: "Test Root CA".to_string(),
        issuing_cn: "Test Issuing CA".to_string(),
        organization: "Open eIDAS Test".to_string(),
        country: "FR".to_string(),
        root_validity: time::Duration::days(20 * 365),
        issuing_validity: time::Duration::days(10 * 365),
        root_token_label: "root".to_string(),
        root_key_label: "root-key".to_string(),
        issuing_token_label: "issuing".to_string(),
        issuing_key_label: "issuing-key".to_string(),
        store: store.clone(),
        operator: "test-operator".to_string(),
        recorder: None,
    })
    .await
    .unwrap();

    let issuer = Issuer::new(CaOptions {
        signer: issuing_signer,
        certificate: hierarchy.issuing,
        chain: vec![],
        store: store.clone(),
        public_url: "https://ca.example.test".to_string(),
        ocsp_url: None,
        crl_validity: time::Duration::hours(24),
        crl_grace: time::Duration::hours(1),
        recorder: None,
    })
    .unwrap();

    let flow = Flow::new(Options {
        store: store.clone(),
        issuer: Arc::new(issuer),
        hmac_secret: HMAC_SECRET.to_string(),
        recorder,
        retry_after: time::Duration::seconds(5),
        clock: None,
    })
    .unwrap();
    (flow, store)
}

#[tokio::test]
async fn submit_without_valid_hmac_is_unauthenticated() {
    let (flow, _store) = test_flow().await;
    let (csr_der, _key) = build_csr("tsu.example.test");
    let err = flow
        .submit(&csr_der, profile::PROFILE_TSA_SIGNER, "00")
        .await;
    assert!(matches!(err, Err(RaflowError::Unauthenticated)));
}

/// ETSI TS 119 312 §6.2 : une CSR authentifiée et correctement signée, mais
/// dont la clé publique est trop courte, doit tout de même être refusée —
/// l'authentification HMAC prouve l'identité du demandeur, pas que sa clé
/// est acceptable.
#[tokio::test]
async fn submit_rejects_a_csr_with_an_undersized_key() {
    let (flow, _store) = test_flow().await;
    let (csr_der, _key) = build_csr_with_bits("tsu.example.test", 2048);
    let sig = oe_raflow::signature(&csr_der, HMAC_SECRET);
    let err = flow
        .submit(&csr_der, profile::PROFILE_TSA_SIGNER, &sig)
        .await;
    assert!(
        err.is_err(),
        "une clé RSA de 2048 bits doit être refusée (< 3072 bits, ETSI TS 119 312 §6.2)"
    );
}

#[tokio::test]
async fn submit_opens_a_pending_request_idempotently() {
    let (flow, store) = test_flow().await;
    let (csr_der, _key) = build_csr("tsu.example.test");
    let sig = oe_raflow::signature(&csr_der, HMAC_SECRET);

    let first = flow
        .submit(&csr_der, profile::PROFILE_TSA_SIGNER, &sig)
        .await
        .unwrap();
    assert_eq!(first.state, RequestState::Pending);
    assert!(first.certificate.is_none());

    let second = flow
        .submit(&csr_der, profile::PROFILE_TSA_SIGNER, &sig)
        .await
        .unwrap();
    assert_eq!(
        second.transaction_id, first.transaction_id,
        "re-soumettre la même CSR doit retrouver la même demande"
    );
    assert_eq!(second.state, RequestState::Pending);

    let pending = store.requests(Some(RequestState::Pending)).await.unwrap();
    assert_eq!(
        pending.len(),
        1,
        "la resoumission ne doit pas créer une seconde demande"
    );
}

#[tokio::test]
async fn approve_then_resubmit_issues_a_certificate_signed_by_the_issuing_key() {
    let (flow, _store) = test_flow().await;
    let (csr_der, _key) = build_csr("tsu.example.test");
    let sig = oe_raflow::signature(&csr_der, HMAC_SECRET);

    let opened = flow
        .submit(&csr_der, profile::PROFILE_TSA_SIGNER, &sig)
        .await
        .unwrap();
    flow.decider()
        .approve(&opened.transaction_id, "operateur-ra", "conforme")
        .await
        .unwrap();

    let issued = flow
        .submit(&csr_der, profile::PROFILE_TSA_SIGNER, &sig)
        .await
        .unwrap();
    assert_eq!(issued.state, RequestState::Issued);
    let cert = issued.certificate.expect("un certificat doit être renvoyé");
    assert_eq!(
        cert.tbs_certificate().subject().to_string(),
        "C=FR,O=Open eIDAS,OU=Time Stamping Authority,CN=tsu.example.test"
    );
    assert!(
        !issued.chain.is_empty(),
        "la chaîne complète doit accompagner le certificat"
    );

    // Resoumission après émission : doit retrouver le même certificat sans
    // en produire un second.
    let again = flow
        .submit(&csr_der, profile::PROFILE_TSA_SIGNER, &sig)
        .await
        .unwrap();
    assert_eq!(again.state, RequestState::Issued);
    assert_eq!(
        again.certificate.unwrap().to_der().unwrap(),
        cert.to_der().unwrap()
    );
}

/// Constat O-1 de l'audit du 2026-09-25 : sans republication immédiate, un
/// certificat qui vient d'être émis répondrait `unknown` en OCSP jusqu'à la
/// prochaine republication périodique de la CRL — aussi grave qu'une
/// révocation non publiée. `Flow::issue` doit republier avant de rendre la
/// main à l'appelant.
#[tokio::test]
async fn issuance_immediately_republishes_the_crl_with_the_new_serial() {
    let (flow, store) = test_flow().await;
    let (csr_der, _key) = build_csr("tsu.example.test");
    let sig = oe_raflow::signature(&csr_der, HMAC_SECRET);

    let opened = flow
        .submit(&csr_der, profile::PROFILE_TSA_SIGNER, &sig)
        .await
        .unwrap();
    flow.decider()
        .approve(&opened.transaction_id, "operateur-ra", "conforme")
        .await
        .unwrap();
    let issued = flow
        .submit(&csr_der, profile::PROFILE_TSA_SIGNER, &sig)
        .await
        .unwrap();
    let cert = issued.certificate.expect("un certificat doit être renvoyé");
    let serial = oe_ca_core::canonical_serial(cert.tbs_certificate().serial_number());

    let crl = store.latest_crl().await.expect("une CRL doit être publiée");
    let parsed: x509_cert::crl::CertificateList =
        x509_cert::crl::CertificateList::from_der(&crl.der).unwrap();
    let issued_oid =
        der::asn1::ObjectIdentifier::new(oe_conformance::OID_CRL_ISSUED_SERIALS).unwrap();
    let ext = parsed
        .tbs_cert_list
        .crl_extensions
        .expect("la CRL doit porter des extensions")
        .into_iter()
        .find(|e| e.extn_id == issued_oid)
        .expect("l'extension des séries émises doit être présente");
    let serials: Vec<x509_cert::serial_number::SerialNumber> =
        der::Decode::from_der(ext.extn_value.as_bytes()).unwrap();
    assert!(
        serials
            .iter()
            .any(|s| oe_ca_core::canonical_serial(s) == serial),
        "le certificat tout juste émis doit déjà figurer dans la CRL republiée"
    );
}

#[tokio::test]
async fn reject_then_resubmit_reports_the_operator_and_comment() {
    let (flow, _store) = test_flow().await;
    let (csr_der, _key) = build_csr("tsu.example.test");
    let sig = oe_raflow::signature(&csr_der, HMAC_SECRET);

    let opened = flow
        .submit(&csr_der, profile::PROFILE_TSA_SIGNER, &sig)
        .await
        .unwrap();
    flow.decider()
        .reject(&opened.transaction_id, "operateur-ra", "sujet non autorisé")
        .await
        .unwrap();

    let err = flow
        .submit(&csr_der, profile::PROFILE_TSA_SIGNER, &sig)
        .await;
    match err {
        Err(RaflowError::Rejected { operator, comment }) => {
            assert_eq!(operator, "operateur-ra");
            assert_eq!(comment, "sujet non autorisé");
        }
        // Le résultat entier n'est pas affiché : un `Ok` porte le certificat émis.
        Ok(_) => panic!("attendu RaflowError::Rejected, obtenu un succès"),
        Err(e) => panic!("attendu RaflowError::Rejected, obtenu l'erreur : {e}"),
    }
}

#[tokio::test]
async fn issuing_a_renewal_revokes_the_previous_certificate_for_the_same_subject() {
    let (flow, store) = test_flow().await;

    let (csr1, _key1) = build_csr("tsu.example.test");
    let sig1 = oe_raflow::signature(&csr1, HMAC_SECRET);
    let opened1 = flow
        .submit(&csr1, profile::PROFILE_TSA_SIGNER, &sig1)
        .await
        .unwrap();
    flow.decider()
        .approve(&opened1.transaction_id, "operateur-ra", "")
        .await
        .unwrap();
    let issued1 = flow
        .submit(&csr1, profile::PROFILE_TSA_SIGNER, &sig1)
        .await
        .unwrap();
    let serial1 = oe_ca_core::canonical_serial(
        issued1
            .certificate
            .unwrap()
            .tbs_certificate()
            .serial_number(),
    );

    let (csr2, _key2) = build_csr("tsu.example.test");
    let sig2 = oe_raflow::signature(&csr2, HMAC_SECRET);
    let opened2 = flow
        .submit(&csr2, profile::PROFILE_TSA_SIGNER, &sig2)
        .await
        .unwrap();
    flow.decider()
        .approve(&opened2.transaction_id, "operateur-ra", "")
        .await
        .unwrap();
    let issued2 = flow
        .submit(&csr2, profile::PROFILE_TSA_SIGNER, &sig2)
        .await
        .unwrap();
    let serial2 = oe_ca_core::canonical_serial(
        issued2
            .certificate
            .unwrap()
            .tbs_certificate()
            .serial_number(),
    );

    assert_ne!(serial1, serial2);
    let stored1 = store.certificate(&serial1).await.unwrap();
    assert_eq!(
        stored1.status,
        oe_castore::CertificateStatus::Revoked,
        "l'ancien certificat du même sujet doit être révoqué lors du renouvellement"
    );
    assert_eq!(stored1.revocation_reason, 4, "motif RFC 5280 superseded");
    let stored2 = store.certificate(&serial2).await.unwrap();
    assert_eq!(stored2.status, oe_castore::CertificateStatus::Issued);
}

#[tokio::test]
async fn decide_without_operator_identity_is_refused() {
    let (flow, _store) = test_flow().await;
    let (csr_der, _key) = build_csr("tsu.example.test");
    let sig = oe_raflow::signature(&csr_der, HMAC_SECRET);
    let opened = flow
        .submit(&csr_der, profile::PROFILE_TSA_SIGNER, &sig)
        .await
        .unwrap();

    let err = flow.decider().approve(&opened.transaction_id, "", "").await;
    assert!(
        err.is_err(),
        "approuver sans identité d'opérateur doit être refusé — traçabilité de la décision"
    );
}

#[tokio::test]
async fn approve_unknown_transaction_is_not_found() {
    let store = Arc::new(Memory::new());
    let decider = Decider::new(DeciderOptions {
        store,
        recorder: None,
        clock: None,
    });
    let err = decider
        .approve("transaction-inconnue", "operateur-ra", "")
        .await;
    assert!(matches!(err, Err(RaflowError::NotFound)));
}

/// Un journal qui échoue systématiquement (docs/WEBUI.md §15 étape 2b) :
/// preuve que `Flow::open` bloque bien la création de la demande, et que
/// `Decider::decide` — l'exception documentée — laisse au contraire la
/// décision déjà appliquée par l'écriture optimiste, malgré l'échec du
/// journal qui suit.
struct FailingRecorder;

#[async_trait::async_trait]
impl oe_raflow::Recorder for FailingRecorder {
    async fn append(&self, _event: &str, _data: serde_json::Value) -> Result<(), String> {
        Err("stockage du journal injoignable (test)".to_string())
    }
}

#[tokio::test]
async fn a_journal_failure_blocks_submission_before_any_request_is_created() {
    let (flow, store) = test_flow_with(Some(Arc::new(FailingRecorder))).await;
    let (csr_der, _key) = build_csr("audit.example.test");
    let signature = oe_raflow::signature(&csr_der, HMAC_SECRET);

    let err = flow
        .submit(&csr_der, "tsa_signer", &signature)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("journal"), "{err}");

    let fp_hex = hex::encode(Sha256::digest(&csr_der));
    assert!(
        store.request_by_fingerprint(&fp_hex).await.is_err(),
        "aucune demande ne doit être créée : le journal a échoué avant"
    );
}

/// Exception documentée : l'écriture optimiste qui départage deux décisions
/// concurrentes reste *avant* le journal. Une conséquence assumée : la
/// décision est déjà appliquée quand le journal échoue ensuite — testée ici
/// pour que ce compromis reste visible, pas une régression silencieuse.
#[tokio::test]
async fn a_journal_failure_on_decide_still_leaves_the_decision_applied() {
    let (flow, store) = test_flow().await;
    let (csr_der, _key) = build_csr("audit.example.test");
    let signature = oe_raflow::signature(&csr_der, HMAC_SECRET);
    flow.submit(&csr_der, "tsa_signer", &signature)
        .await
        .unwrap();
    let fp_hex = hex::encode(Sha256::digest(&csr_der));
    let request = store.request_by_fingerprint(&fp_hex).await.unwrap();

    let failing_decider = Decider::new(DeciderOptions {
        store: store.clone(),
        recorder: Some(Arc::new(FailingRecorder)),
        clock: None,
    });
    let err = failing_decider
        .approve(&request.transaction_id, "operateur-ra", "")
        .await
        .unwrap_err();
    assert!(err.to_string().contains("journal"), "{err}");

    let updated = store
        .request_by_transaction_id(&request.transaction_id)
        .await
        .unwrap();
    assert_eq!(
        updated.state,
        RequestState::Approved,
        "la décision reste appliquée malgré l'échec du journal (exception documentée)"
    );
}
