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
use oe_raflow::{Decider, DeciderOptions, Flow, Options, RaflowError, Via};

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
    test_flow_with(None, None).await
}

async fn test_flow_with(
    recorder: Option<Arc<dyn oe_raflow::Recorder>>,
    ca_recorder: Option<Arc<dyn oe_ca_core::Recorder>>,
) -> (Flow, Arc<Memory>) {
    test_flow_full(recorder, ca_recorder, HMAC_SECRET, vec![]).await
}

async fn test_flow_full(
    recorder: Option<Arc<dyn oe_raflow::Recorder>>,
    ca_recorder: Option<Arc<dyn oe_ca_core::Recorder>>,
    hmac_secret: &str,
    requesters: Vec<oe_raflow::Requester>,
) -> (Flow, Arc<Memory>) {
    let store = Arc::new(Memory::new());
    let root_signer = Arc::new(SoftwareToken::generate(2048));
    let issuing_signer = Arc::new(SoftwareToken::generate(2048));
    let hierarchy = run_ceremony(CeremonyOptions {
        scheme: oe_hsm::Scheme::Pkcs1v15,
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
        public_url: "https://ca.example.test".to_string(),
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
        recorder: ca_recorder,
    })
    .unwrap();

    let flow = Flow::new(Options {
        store: store.clone(),
        issuer: Arc::new(issuer),
        hmac_secret: hmac_secret.to_string(),
        requesters,
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

/// ETSI TS 119 312 §8.4 : une CSR authentifiée et correctement signée, mais
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
        "une clé RSA de 2048 bits doit être refusée (< 3072 bits, ETSI TS 119 312 §8.4)"
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
        .approve(
            &opened.transaction_id,
            "operateur-ra",
            "conforme",
            &Via::WebAuthn,
        )
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
        .approve(
            &opened.transaction_id,
            "operateur-ra",
            "conforme",
            &Via::WebAuthn,
        )
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
        .reject(
            &opened.transaction_id,
            "operateur-ra",
            "sujet non autorisé",
            &Via::WebAuthn,
        )
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
        .approve(&opened1.transaction_id, "operateur-ra", "", &Via::WebAuthn)
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
        .approve(&opened2.transaction_id, "operateur-ra", "", &Via::WebAuthn)
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

    let err = flow
        .decider()
        .approve(&opened.transaction_id, "", "", &Via::WebAuthn)
        .await;
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
        .approve("transaction-inconnue", "operateur-ra", "", &Via::WebAuthn)
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
    let (flow, store) = test_flow_with(Some(Arc::new(FailingRecorder)), None).await;
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
        .approve(&request.transaction_id, "operateur-ra", "", &Via::WebAuthn)
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

/// Journal en mémoire qui garde les données de chaque événement, des deux
/// sources (`oe_raflow` et `oe_ca_core`).
#[derive(Default, Clone)]
struct DataLog(Arc<std::sync::Mutex<Vec<(String, serde_json::Value)>>>);

impl DataLog {
    fn last(&self, event: &str) -> serde_json::Value {
        self.0
            .lock()
            .unwrap()
            .iter()
            .rev()
            .find(|(e, _)| e == event)
            .map(|(_, d)| d.clone())
            .unwrap_or_else(|| panic!("événement {event} absent du journal"))
    }
}

#[async_trait::async_trait]
impl oe_raflow::Recorder for DataLog {
    async fn append(&self, event: &str, data: serde_json::Value) -> Result<(), String> {
        self.0.lock().unwrap().push((event.to_string(), data));
        Ok(())
    }
}

#[async_trait::async_trait]
impl oe_ca_core::Recorder for DataLog {
    async fn append(&self, event: &str, data: serde_json::Value) -> Result<(), String> {
        self.0.lock().unwrap().push((event.to_string(), data));
        Ok(())
    }
}

async fn open_request(flow: &Flow, cn: &str) -> (String, Vec<u8>, String) {
    let (csr_der, _key) = build_csr(cn);
    let sig = oe_raflow::signature(&csr_der, HMAC_SECRET);
    let opened = flow
        .submit(&csr_der, profile::PROFILE_TSA_SIGNER, &sig)
        .await
        .unwrap();
    (opened.transaction_id, csr_der, sig)
}

/// Constat R-1 : chaque décision dit par quelle voie son opérateur a été
/// identifié (docs/WEBUI.md §20) — la voie signée, la voie de secours (avec
/// l'identité système réelle, marquée non authentifiée) et le remplacement
/// automatique au renouvellement.
#[tokio::test]
async fn each_decision_records_how_its_operator_was_identified() {
    let log = DataLog::default();
    let (flow, _store) =
        test_flow_with(Some(Arc::new(log.clone())), Some(Arc::new(log.clone()))).await;

    let (tx1, csr1, sig1) = open_request(&flow, "tsu.example.test").await;
    let cli = Via::Cli(oe_raflow::SystemIdentity {
        uid: Some(0),
        user: "root".to_string(),
        host: "open-eidas-ca-0".to_string(),
    });
    flow.decider()
        .approve(&tx1, "prenom.nom", "identité vérifiée au guichet", &cli)
        .await
        .unwrap();
    let approved = log.last("ca.request_approved");
    assert_eq!(approved["authenticated_via"], "cli");
    assert_eq!(approved["identite_systeme"]["authentifiee"], false);
    assert_eq!(approved["identite_systeme"]["uid"], 0);
    assert_eq!(approved["identite_systeme"]["hote"], "open-eidas-ca-0");
    flow.submit(&csr1, profile::PROFILE_TSA_SIGNER, &sig1)
        .await
        .unwrap();

    // Renouvellement : la décision signée, puis la révocation automatique de
    // l'ancien certificat du même sujet.
    let (tx2, csr2, sig2) = open_request(&flow, "tsu.example.test").await;
    flow.decider()
        .approve(&tx2, "operateur-ra", "", &Via::WebAuthn)
        .await
        .unwrap();
    let approved = log.last("ca.request_approved");
    assert_eq!(approved["authenticated_via"], "webauthn");
    assert!(approved.get("identite_systeme").is_none());
    flow.submit(&csr2, profile::PROFILE_TSA_SIGNER, &sig2)
        .await
        .unwrap();
    let superseded = log.last("ca.certificate_revoked");
    assert_eq!(superseded["authenticated_via"], "automatique");
    assert_eq!(superseded["motif"], 4);
}

/// Constat R-1 : une décision prise par le CLI (voie de secours) sans
/// commentaire est refusée avant que la demande ne change d'état.
#[tokio::test]
async fn a_cli_decision_without_a_comment_is_refused_before_the_request_changes() {
    let (flow, store) = test_flow().await;
    let (tx, _csr, _sig) = open_request(&flow, "tsu.example.test").await;
    let cli = Via::Cli(oe_raflow::SystemIdentity::current());

    let err = flow
        .decider()
        .approve(&tx, "prenom.nom", "  ", &cli)
        .await
        .expect_err("une décision CLI sans commentaire doit être refusée");
    assert!(err.to_string().contains("commentaire"), "{err}");
    let request = store.request_by_transaction_id(&tx).await.unwrap();
    assert_eq!(request.state, RequestState::Pending);
}

/// CSR PKCS#10 signée par un `SoftwareToken` selon le schéma demandé, avec
/// l'identifiant d'algorithme que `oe_hsm` associe à ce schéma. Le schéma de la
/// signature et celui de l'identifiant peuvent être dissociés pour fabriquer
/// une CSR incohérente.
fn build_csr_scheme(
    cn: &str,
    algid_scheme: oe_hsm::Scheme,
    sign_scheme: oe_hsm::Scheme,
) -> Vec<u8> {
    use oe_hsm::SigningToken;
    let token = SoftwareToken::generate(3072);
    let spki = x509_cert::SubjectPublicKeyInfo::from_der(&token.public_key_der().unwrap()).unwrap();
    let info = CertReqInfo {
        version: x509_cert::request::Version::V1,
        subject: Name::from_str(&format!("CN={cn}")).unwrap(),
        public_key: spki,
        attributes: Attributes::new(),
    };
    let digest = Sha256::digest(info.to_der().unwrap());
    let sig = token
        .sign_digest_with(sign_scheme, oe_hsm::DigestAlg::Sha256, &digest)
        .unwrap();
    CertReq {
        info,
        algorithm: oe_hsm::signature_algorithm(algid_scheme, oe_hsm::DigestAlg::Sha256).unwrap(),
        signature: BitString::from_bytes(&sig).unwrap(),
    }
    .to_der()
    .unwrap()
}

/// Décision du 2026-10-21 (RSASSA-PSS partout) : une CSR signée en PSS est
/// acceptée, et une CSR dont l'identifiant d'algorithme annonce un schéma
/// différent de celui de la signature est refusée.
#[tokio::test]
async fn submit_accepts_a_pss_csr_and_rejects_a_scheme_mismatch() {
    use oe_hsm::Scheme;
    let (flow, _store) = test_flow().await;

    let pss = build_csr_scheme("tsu.example.test", Scheme::Pss, Scheme::Pss);
    let sig = oe_raflow::signature(&pss, HMAC_SECRET);
    let accepted = flow
        .submit(&pss, profile::PROFILE_TSA_SIGNER, &sig)
        .await
        .unwrap();
    assert_eq!(accepted.state, RequestState::Pending);

    for (algid, signed) in [
        (Scheme::Pss, Scheme::Pkcs1v15),
        (Scheme::Pkcs1v15, Scheme::Pss),
    ] {
        let bad = build_csr_scheme("tsu2.example.test", algid, signed);
        let sig = oe_raflow::signature(&bad, HMAC_SECRET);
        let err = flow.submit(&bad, profile::PROFILE_TSA_SIGNER, &sig).await;
        assert!(
            err.is_err(),
            "annonce {algid:?}, signature {signed:?} : doit être refusée"
        );
    }
}

fn requester(
    name: &str,
    secret: &str,
    profiles: &[&str],
    cn: Option<&str>,
) -> oe_raflow::Requester {
    oe_raflow::Requester {
        name: name.to_string(),
        secret: secret.to_string(),
        profiles: profiles.iter().map(|p| p.to_string()).collect(),
        subject_cn: cn.map(str::to_string),
        ..Default::default()
    }
}

/// Soumet, approuve puis réémet : le certificat délivré à ce demandeur.
async fn issue_for(flow: &Flow, csr: &[u8], profile: &str, secret: &str) -> Vec<u8> {
    let sig = oe_raflow::signature(csr, secret);
    let opened = flow.submit(csr, profile, &sig).await.unwrap();
    flow.decider()
        .approve(&opened.transaction_id, "operateur-ra", "", &Via::WebAuthn)
        .await
        .unwrap();
    let issued = flow.submit(csr, profile, &sig).await.unwrap();
    oe_ca_core::canonical_serial(
        issued
            .certificate
            .unwrap()
            .tbs_certificate()
            .serial_number(),
    )
}

/// Constat R-3 : le secret d'un demandeur ne vaut que pour ses profils et son CN.
#[tokio::test]
async fn a_requester_obtains_only_its_profiles_and_its_cn() {
    let secret = "s".repeat(40);
    let (flow, _store) = test_flow_full(
        None,
        None,
        "",
        vec![requester(
            "tsa",
            &secret,
            &[profile::PROFILE_TSA_SIGNER],
            Some("tsu.example.test"),
        )],
    )
    .await;

    // Le profil du répondeur OCSP n'est pas le sien.
    let (csr, _k) = build_csr("ocsp.example.test");
    let sig = oe_raflow::signature(&csr, &secret);
    let err = flow
        .submit(&csr, profile::PROFILE_OCSP_RESPONDER, &sig)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("n'est pas autorisé"), "{err}");

    // Un autre CN que le sien, sur son profil.
    let (csr, _k) = build_csr("autre.example.test");
    let sig = oe_raflow::signature(&csr, &secret);
    let err = flow
        .submit(&csr, profile::PROFILE_TSA_SIGNER, &sig)
        .await
        .unwrap_err();
    assert!(
        err.to_string().contains("ne peut demander que le CN"),
        "{err}"
    );

    // Son profil et son CN : ouvert.
    let (csr, _k) = build_csr("tsu.example.test");
    let sig = oe_raflow::signature(&csr, &secret);
    let ok = flow
        .submit(&csr, profile::PROFILE_TSA_SIGNER, &sig)
        .await
        .unwrap();
    assert_eq!(ok.state, RequestState::Pending);

    // Sans secret historique configuré, un autre secret n'ouvre rien.
    let (csr, _k) = build_csr("tsu.example.test");
    let sig = oe_raflow::signature(&csr, HMAC_SECRET);
    assert!(matches!(
        flow.submit(&csr, profile::PROFILE_TSA_SIGNER, &sig).await,
        Err(RaflowError::Unauthenticated)
    ));
}

/// Constat R-3 : un renouvellement ne révoque que les certificats du même
/// demandeur. Un autre porteur de secret qui soumet le même CN n'éteint pas la
/// TSU légitime.
#[tokio::test]
async fn a_renewal_never_revokes_the_certificate_of_another_requester() {
    let (a, b) = ("a".repeat(40), "b".repeat(40));
    let (flow, store) = test_flow_full(
        None,
        None,
        "",
        vec![
            requester("tsa", &a, &["tsa_signer"], None),
            requester("intrus", &b, &["tsa_signer"], None),
        ],
    )
    .await;

    let (csr, _k) = build_csr("tsu.example.test");
    let legitimate = issue_for(&flow, &csr, profile::PROFILE_TSA_SIGNER, &a).await;

    // L'autre demandeur obtient un certificat de même CN : l'ancien reste valide.
    let (csr, _k) = build_csr("tsu.example.test");
    let intruder = issue_for(&flow, &csr, profile::PROFILE_TSA_SIGNER, &b).await;
    assert_eq!(
        store.certificate(&legitimate).await.unwrap().status,
        oe_castore::CertificateStatus::Issued,
        "le certificat d'un autre demandeur ne doit pas être révoqué"
    );
    assert_eq!(
        store.certificate(&intruder).await.unwrap().status,
        oe_castore::CertificateStatus::Issued
    );

    // Le renouvellement du demandeur légitime révoque le sien, pas celui de l'intrus.
    let (csr, _k) = build_csr("tsu.example.test");
    let renewed = issue_for(&flow, &csr, profile::PROFILE_TSA_SIGNER, &a).await;
    assert_eq!(
        store.certificate(&legitimate).await.unwrap().status,
        oe_castore::CertificateStatus::Revoked
    );
    assert_eq!(
        store.certificate(&intruder).await.unwrap().status,
        oe_castore::CertificateStatus::Issued
    );
    assert_eq!(
        store.certificate(&renewed).await.unwrap().status,
        oe_castore::CertificateStatus::Issued
    );
}

/// Docs/R3-MTLS-DEMANDEURS.md : un demandeur identifié par son certificat client
/// (nom courant déjà vérifié par la couche TLS) n'a pas besoin de secret, mais
/// garde ses profils et son CN.
#[tokio::test]
async fn a_client_certificate_identifies_a_requester_without_a_secret() {
    let (flow, _store) = test_flow_full(
        None,
        None,
        "",
        vec![oe_raflow::Requester {
            name: "tsa".to_string(),
            client_cn: Some("tsa-1".to_string()),
            profiles: vec![profile::PROFILE_TSA_SIGNER.to_string()],
            subject_cn: Some("tsu.example.test".to_string()),
            ..Default::default()
        }],
    )
    .await;

    let (csr, _k) = build_csr("tsu.example.test");
    let ok = flow
        .submit_mtls(&csr, profile::PROFILE_TSA_SIGNER, "tsa-1")
        .await
        .unwrap();
    assert_eq!(ok.state, RequestState::Pending);

    // Un certificat client inconnu n'est personne.
    let (csr2, _k) = build_csr("tsu.example.test");
    assert!(matches!(
        flow.submit_mtls(&csr2, profile::PROFILE_TSA_SIGNER, "inconnu")
            .await,
        Err(RaflowError::Unauthenticated)
    ));
    // Ses profils et son CN le lient encore.
    let (csr3, _k) = build_csr("ocsp.example.test");
    assert!(flow
        .submit_mtls(&csr3, profile::PROFILE_OCSP_RESPONDER, "tsa-1")
        .await
        .is_err());
    let (csr4, _k) = build_csr("autre.example.test");
    assert!(flow
        .submit_mtls(&csr4, profile::PROFILE_TSA_SIGNER, "tsa-1")
        .await
        .is_err());
    // Et il n'a aucun secret : un HMAC, même vide, ne l'authentifie pas.
    let sig = oe_raflow::signature(&csr2, "");
    assert!(matches!(
        flow.submit(&csr2, profile::PROFILE_TSA_SIGNER, &sig).await,
        Err(RaflowError::Unauthenticated)
    ));
}

/// Amorçage : le secret ne vaut qu'une fois pour un certificat client, à son
/// nom, tant qu'il n'a pas expiré.
#[tokio::test]
async fn a_bootstrap_secret_opens_one_client_certificate_request() {
    let secret = "b".repeat(40);
    let requester = |expires: time::OffsetDateTime| oe_raflow::Requester {
        name: "tsa".to_string(),
        secret: secret.clone(),
        secret_expires_at: Some(expires),
        client_cn: Some("tsa-1".to_string()),
        profiles: vec![profile::PROFILE_ENROLL_CLIENT.to_string()],
        ..Default::default()
    };
    let (flow, _store) = test_flow_full(
        None,
        None,
        "",
        vec![requester(
            time::OffsetDateTime::now_utc() + time::Duration::hours(24),
        )],
    )
    .await;

    // Le certificat client porte le nom du demandeur, et pas un autre.
    let (wrong, _k) = build_csr("autre-nom");
    let sig = oe_raflow::signature(&wrong, &secret);
    assert!(flow
        .submit(&wrong, profile::PROFILE_ENROLL_CLIENT, &sig)
        .await
        .is_err());

    let (csr, _k) = build_csr("tsa-1");
    let sig = oe_raflow::signature(&csr, &secret);
    let opened = flow
        .submit(&csr, profile::PROFILE_ENROLL_CLIENT, &sig)
        .await
        .unwrap();
    assert_eq!(opened.state, RequestState::Pending);
    // La même CSR se reprend (le demandeur attend la décision) ...
    let again = flow
        .submit(&csr, profile::PROFILE_ENROLL_CLIENT, &sig)
        .await
        .unwrap();
    assert_eq!(again.transaction_id, opened.transaction_id);
    // ... une autre, avec le même secret, non.
    let (second, _k) = build_csr("tsa-1");
    let sig2 = oe_raflow::signature(&second, &secret);
    let err = flow
        .submit(&second, profile::PROFILE_ENROLL_CLIENT, &sig2)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("a déjà servi"), "{err}");

    // Un secret expiré n'authentifie plus.
    let (flow, _store) = test_flow_full(
        None,
        None,
        "",
        vec![requester(
            time::OffsetDateTime::now_utc() - time::Duration::hours(1),
        )],
    )
    .await;
    let (csr, _k) = build_csr("tsa-1");
    let sig = oe_raflow::signature(&csr, &secret);
    assert!(matches!(
        flow.submit(&csr, profile::PROFILE_ENROLL_CLIENT, &sig)
            .await,
        Err(RaflowError::Unauthenticated)
    ));
}

/// Fin de la double authentification : avec `hmac_bootstrap_only`, le secret d'un
/// demandeur qui a son certificat client n'amorce plus que ce certificat ; un
/// demandeur sans certificat client garde son secret.
#[tokio::test]
async fn once_bootstrap_only_a_secret_no_longer_enrolls_a_requester_with_a_client_certificate() {
    let secret = "c".repeat(40);
    let other = "d".repeat(40);
    let requesters = vec![
        oe_raflow::Requester {
            name: "tsa".to_string(),
            secret: secret.clone(),
            client_cn: Some("tsa-1".to_string()),
            profiles: vec!["enroll_client".into(), "tsa_signer".into()],
            ..Default::default()
        },
        oe_raflow::Requester {
            name: "ancien".to_string(),
            secret: other.clone(),
            profiles: vec!["ocsp_responder".into()],
            ..Default::default()
        },
    ];
    let (flow, _store) = test_flow_full(None, None, "", requesters).await;
    let flow = flow.with_hmac_bootstrap_only(true);

    // Son secret ne l'enrôle plus pour un certificat de TSU ...
    let (csr, _k) = build_csr("tsu.example.test");
    let sig = oe_raflow::signature(&csr, &secret);
    assert!(matches!(
        flow.submit(&csr, profile::PROFILE_TSA_SIGNER, &sig).await,
        Err(RaflowError::Unauthenticated)
    ));
    // ... mais l'amorce encore (une fois) ...
    let (csr, _k) = build_csr("tsa-1");
    let sig = oe_raflow::signature(&csr, &secret);
    assert!(flow
        .submit(&csr, profile::PROFILE_ENROLL_CLIENT, &sig)
        .await
        .is_ok());
    // ... et son certificat client, lui, enrôle.
    let (csr, _k) = build_csr("tsu.example.test");
    assert!(flow
        .submit_mtls(&csr, profile::PROFILE_TSA_SIGNER, "tsa-1")
        .await
        .is_ok());
    // Un demandeur sans certificat client n'est pas encore migré : il garde son secret.
    let (csr, _k) = build_csr("ocsp.example.test");
    let sig = oe_raflow::signature(&csr, &other);
    assert!(flow
        .submit(&csr, profile::PROFILE_OCSP_RESPONDER, &sig)
        .await
        .is_ok());
}
