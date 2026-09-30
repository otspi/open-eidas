//! Test d'intégration bout-en-bout : cérémonie → émission → révocation →
//! publication de CRL, sur clés RSA logicielles de test
//! ([`oe_hsm::testing::SoftwareToken`]) et magasin en mémoire
//! ([`oe_castore::Memory`]) — pas de HSM réel requis, contrairement aux
//! tests de `oe-tsa-server`/`oe-ocsp-responder` qui, eux, s'appuient sur
//! SoftHSM2 : ce moteur n'a rien de spécifique au transport PKCS#11 au-delà
//! de ce que `oe-hsm::SigningToken` couvre déjà.

use std::sync::Arc;

use der::{Decode, Encode};
use x509_cert::Certificate;

use oe_ca_core::ceremony::{run_ceremony, CeremonyOptions, AUTHORITY_ISSUING, AUTHORITY_ROOT};
use oe_ca_core::{profile, Issuer, Options};
use oe_castore::{Memory, Store};
use oe_hsm::testing::SoftwareToken;
use oe_hsm::SigningToken;

fn store() -> Arc<Memory> {
    Arc::new(Memory::new())
}

async fn run_test_ceremony(
    store: Arc<Memory>,
) -> (
    Arc<SoftwareToken>,
    Arc<SoftwareToken>,
    x509_cert::Certificate,
    x509_cert::Certificate,
) {
    let root_signer = Arc::new(SoftwareToken::generate(2048));
    let issuing_signer = Arc::new(SoftwareToken::generate(2048));

    let hierarchy = run_ceremony(CeremonyOptions {
        root_signer: root_signer.clone(),
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
    .expect("la cérémonie doit réussir");

    assert!(
        hierarchy.created,
        "première cérémonie : la hiérarchie doit être créée"
    );
    (
        root_signer,
        issuing_signer,
        hierarchy.root,
        hierarchy.issuing,
    )
}

#[tokio::test]
async fn ceremony_is_idempotent() {
    let store = store();
    let (root_signer, issuing_signer, root1, issuing1) = run_test_ceremony(store.clone()).await;

    let hierarchy2 = run_ceremony(CeremonyOptions {
        root_signer,
        issuing_signer,
        root_cn: String::new(),
        issuing_cn: String::new(),
        organization: String::new(),
        country: String::new(),
        root_validity: time::Duration::ZERO,
        issuing_validity: time::Duration::ZERO,
        root_token_label: "root".to_string(),
        root_key_label: "root-key".to_string(),
        issuing_token_label: "issuing".to_string(),
        issuing_key_label: "issuing-key".to_string(),
        store: store.clone(),
        operator: "test-operator".to_string(),
        recorder: None,
    })
    .await
    .expect("la seconde cérémonie doit se contenter de relire la hiérarchie existante");

    assert!(
        !hierarchy2.created,
        "seconde cérémonie : la hiérarchie ne doit pas être recréée"
    );
    assert_eq!(root1.to_der().unwrap(), hierarchy2.root.to_der().unwrap());
    assert_eq!(
        issuing1.to_der().unwrap(),
        hierarchy2.issuing.to_der().unwrap()
    );

    let authorities: Vec<_> = [AUTHORITY_ROOT, AUTHORITY_ISSUING].into_iter().collect();
    for name in authorities {
        store
            .authority(name)
            .await
            .expect("l'autorité doit être persistée");
    }
}

#[tokio::test]
async fn ceremony_rejects_mismatched_signer_on_replay() {
    let store = store();
    let (_root_signer, issuing_signer, ..) = run_test_ceremony(store.clone()).await;

    let other_root_signer = Arc::new(SoftwareToken::generate(2048));
    let err = run_ceremony(CeremonyOptions {
        root_signer: other_root_signer,
        issuing_signer,
        root_cn: String::new(),
        issuing_cn: String::new(),
        organization: String::new(),
        country: String::new(),
        root_validity: time::Duration::ZERO,
        issuing_validity: time::Duration::ZERO,
        root_token_label: "root".to_string(),
        root_key_label: "root-key".to_string(),
        issuing_token_label: "issuing".to_string(),
        issuing_key_label: "issuing-key".to_string(),
        store,
        operator: "test-operator".to_string(),
        recorder: None,
    })
    .await;

    assert!(
        err.is_err(),
        "une clé de token différente de celle déjà scellée doit être rejetée"
    );
}

async fn issuer_from_ceremony(store: Arc<Memory>) -> (Issuer, Arc<SoftwareToken>) {
    let (_root_signer, issuing_signer, _root, issuing) = run_test_ceremony(store.clone()).await;
    let issuer = Issuer::new(Options {
        signer: issuing_signer.clone(),
        certificate: issuing,
        chain: vec![],
        store: store.clone(),
        public_url: "https://ca.example.test".to_string(),
        ocsp_url: Some("https://ocsp.example.test".to_string()),
        crl_validity: time::Duration::hours(24),
        crl_grace: time::Duration::hours(1),
        recorder: None,
    })
    .expect("l'émetteur doit accepter une autorité dont la clé correspond au signataire");
    (issuer, issuing_signer)
}

#[tokio::test]
async fn issue_produces_a_certificate_signed_by_the_issuing_key() {
    let store = store();
    let (issuer, _issuing_signer) = issuer_from_ceremony(store.clone()).await;

    let end_entity = SoftwareToken::generate(2048);
    let public_key_der = end_entity
        .public_key_der()
        .expect("clé publique de l'entité finale");
    let tsa_profile = profile::tsa_signer();

    let cert = issuer
        .issue(&public_key_der, "tsu.example.test", &tsa_profile, "txn-1")
        .await
        .expect("l'émission doit réussir");

    assert_eq!(
        cert.tbs_certificate().issuer().to_string(),
        issuer.certificate().tbs_certificate().subject().to_string()
    );
    assert_ski_and_aki_present_and_linked(&cert, issuer.certificate());

    let serial = oe_ca_core::canonical_serial(cert.tbs_certificate().serial_number());
    let stored = store
        .certificate(&serial)
        .await
        .expect("le certificat doit être persisté");
    assert_eq!(stored.status, oe_castore::CertificateStatus::Issued);
    assert_eq!(stored.request_transaction_id, "txn-1");

    // Vérification indépendante de la signature par openssl aurait besoin
    // d'écrire les fichiers sur disque ; on se contente ici de revérifier
    // que le certificat encode/décode bit-à-bit correctement (round-trip
    // DER), le HSM logiciel de test faisant déjà foi pour la primitive de
    // signature elle-même (couverte par les tests de `oe-hsm`).
    let der = cert.to_der().unwrap();
    let reparsed = Certificate::from_der(&der).unwrap();
    assert_eq!(reparsed.to_der().unwrap(), der);
}

#[tokio::test]
async fn revoke_then_publish_crl_lists_the_certificate() {
    let store = store();
    let (issuer, _issuing_signer) = issuer_from_ceremony(store.clone()).await;

    let end_entity = SoftwareToken::generate(2048);
    let public_key_der = end_entity.public_key_der().unwrap();
    let ocsp_profile = profile::ocsp_responder();
    let cert = issuer
        .issue(&public_key_der, "ocsp.example.test", &ocsp_profile, "txn-2")
        .await
        .unwrap();
    let serial = oe_ca_core::canonical_serial(cert.tbs_certificate().serial_number());

    let empty_crl = issuer
        .publish_crl()
        .await
        .expect("une CRL vide doit pouvoir être publiée");
    let parsed_empty: x509_cert::crl::CertificateList =
        x509_cert::crl::CertificateList::from_der(&empty_crl.der).unwrap();
    assert!(parsed_empty.tbs_cert_list.revoked_certificates.is_none());

    issuer
        .revoke(&serial, 1, "test-operator", "")
        .await
        .expect("la révocation doit réussir");

    let crl = issuer
        .publish_crl()
        .await
        .expect("la republication doit réussir");
    assert!(
        crl.number > empty_crl.number,
        "le numéro de CRL doit augmenter à chaque publication"
    );

    let parsed: x509_cert::crl::CertificateList =
        x509_cert::crl::CertificateList::from_der(&crl.der).unwrap();
    let revoked = parsed
        .tbs_cert_list
        .revoked_certificates
        .expect("la CRL doit lister le certificat révoqué");
    assert_eq!(revoked.len(), 1);
    assert_eq!(
        oe_ca_core::canonical_serial(&revoked[0].serial_number),
        serial
    );

    let current = issuer.current_crl().await.unwrap();
    assert_eq!(current.number, crl.number);
}

/// Constat O-1 de l'audit du 2026-09-25 : la CRL porte, en plus des
/// révoqués, tous les numéros émis — c'est ce qui permet au répondeur OCSP
/// de distinguer un numéro jamais émis d'un numéro émis mais non révoqué
/// (`oe_conformance::OID_CRL_ISSUED_SERIALS`).
#[tokio::test]
async fn published_crl_lists_every_issued_serial_not_only_the_revoked_ones() {
    let store = store();
    let (issuer, _issuing_signer) = issuer_from_ceremony(store.clone()).await;

    let end_entity = SoftwareToken::generate(2048);
    let public_key_der = end_entity.public_key_der().unwrap();
    let cert = issuer
        .issue(
            &public_key_der,
            "ocsp.example.test",
            &profile::ocsp_responder(),
            "txn-o1",
        )
        .await
        .unwrap();
    let serial = oe_ca_core::canonical_serial(cert.tbs_certificate().serial_number());

    let crl = issuer.publish_crl().await.unwrap();
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
    let issued: Vec<x509_cert::serial_number::SerialNumber> =
        der::Decode::from_der(ext.extn_value.as_bytes()).unwrap();
    assert!(
        issued
            .iter()
            .any(|s| oe_ca_core::canonical_serial(s) == serial),
        "le certificat non révoqué doit figurer parmi les séries émises"
    );
}

#[tokio::test]
async fn revoke_is_idempotent_and_keeps_first_reason() {
    let store = store();
    let (issuer, _issuing_signer) = issuer_from_ceremony(store.clone()).await;

    let end_entity = SoftwareToken::generate(2048);
    let public_key_der = end_entity.public_key_der().unwrap();
    let tsa_profile = profile::tsa_signer();
    let cert = issuer
        .issue(&public_key_der, "tsu2.example.test", &tsa_profile, "txn-3")
        .await
        .unwrap();
    let serial = oe_ca_core::canonical_serial(cert.tbs_certificate().serial_number());

    issuer
        .revoke(&serial, 1, "test-operator", "")
        .await
        .unwrap();
    issuer
        .revoke(&serial, 5, "test-operator", "")
        .await
        .unwrap();

    let stored = store.certificate(&serial).await.unwrap();
    assert_eq!(stored.status, oe_castore::CertificateStatus::Revoked);
    assert_eq!(
        stored.revocation_reason, 1,
        "la première raison de révocation doit être conservée"
    );
}

/// Vérification croisée par un tiers indépendant du code sous test : la
/// chaîne racine→émettrice→entité finale doit être acceptée par `openssl
/// verify`, et une fois le certificat feuille révoqué et la CRL republiée,
/// `openssl verify -crl_check` doit le rejeter — preuve que la révocation
/// produit un effet observable en dehors de notre propre code, à l'identique
/// du protocole déjà utilisé pour `oe-tsa-core`/`oe-ocsp-core` avec `openssl
/// ts`/`openssl ocsp`.
#[tokio::test]
async fn openssl_accepts_the_chain_and_honors_revocation() {
    if std::process::Command::new("openssl")
        .arg("version")
        .output()
        .is_err()
    {
        eprintln!("openssl indisponible : test de vérification croisée ignoré");
        return;
    }

    let store = store();
    let (_root_signer, issuing_signer, root, issuing) = run_test_ceremony(store.clone()).await;
    let issuer = Issuer::new(Options {
        signer: issuing_signer,
        certificate: issuing.clone(),
        chain: vec![root.clone()],
        store: store.clone(),
        public_url: "https://ca.example.test".to_string(),
        ocsp_url: None,
        crl_validity: time::Duration::hours(24),
        crl_grace: time::Duration::hours(1),
        recorder: None,
    })
    .unwrap();

    let end_entity = SoftwareToken::generate(2048);
    let public_key_der = end_entity.public_key_der().unwrap();
    let tsa_profile = profile::tsa_signer();
    let leaf = issuer
        .issue(
            &public_key_der,
            "leaf.example.test",
            &tsa_profile,
            "txn-openssl",
        )
        .await
        .unwrap();
    let serial = oe_ca_core::canonical_serial(leaf.tbs_certificate().serial_number());

    let dir = std::env::temp_dir().join(format!("oe-ca-core-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let root_pem = dir.join("root.pem");
    let issuing_pem = dir.join("issuing.pem");
    let leaf_pem = dir.join("leaf.pem");
    write_pem(&root_pem, &root.to_der().unwrap());
    write_pem(&issuing_pem, &issuing.to_der().unwrap());
    write_pem(&leaf_pem, &leaf.to_der().unwrap());

    let verify_before = std::process::Command::new("openssl")
        .args(["verify", "-CAfile"])
        .arg(&root_pem)
        .arg("-untrusted")
        .arg(&issuing_pem)
        .arg(&leaf_pem)
        .output()
        .expect("openssl doit s'exécuter");
    assert!(
        verify_before.status.success(),
        "openssl doit accepter la chaîne avant révocation : {}",
        String::from_utf8_lossy(&verify_before.stderr)
    );

    issuer
        .revoke(&serial, 1, "test-operator", "")
        .await
        .unwrap();
    let crl = issuer.publish_crl().await.unwrap();
    let crl_pem = dir.join("issuing.crl.pem");
    write_crl_pem(&crl_pem, &crl.der);

    let verify_after = std::process::Command::new("openssl")
        .args(["verify", "-crl_check", "-CAfile"])
        .arg(&root_pem)
        .arg("-untrusted")
        .arg(&issuing_pem)
        .arg("-CRLfile")
        .arg(&crl_pem)
        .arg(&leaf_pem)
        .output()
        .expect("openssl doit s'exécuter");
    assert!(
        !verify_after.status.success(),
        "openssl doit rejeter le certificat révoqué"
    );
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&verify_after.stdout),
        String::from_utf8_lossy(&verify_after.stderr)
    );
    assert!(
        combined.to_lowercase().contains("revoked"),
        "le rejet doit être motivé par la révocation, pas par une autre erreur : {combined}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

fn write_pem(path: &std::path::Path, der: &[u8]) {
    use base64::Engine;
    let b64 = base64::engine::general_purpose::STANDARD.encode(der);
    let mut out = String::from("-----BEGIN CERTIFICATE-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).unwrap());
        out.push('\n');
    }
    out.push_str("-----END CERTIFICATE-----\n");
    std::fs::write(path, out).unwrap();
}

fn write_crl_pem(path: &std::path::Path, der: &[u8]) {
    use base64::Engine;
    let b64 = base64::engine::general_purpose::STANDARD.encode(der);
    let mut out = String::from("-----BEGIN X509 CRL-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).unwrap());
        out.push('\n');
    }
    out.push_str("-----END X509 CRL-----\n");
    std::fs::write(path, out).unwrap();
}

/// RFC 5280 §4.2.1.1/§4.2.1.2 : vérifie que le certificat porte un
/// subjectKeyIdentifier non critique (SHA-1 de sa clé publique, méthode 1)
/// et un authorityKeyIdentifier dont le keyIdentifier pointe vers le
/// subjectKeyIdentifier du certificat émetteur — pas seulement que la chaîne
/// se vérifie par ailleurs (subject/issuer/signature suffiraient à openssl
/// sans ces extensions).
fn assert_ski_and_aki_present_and_linked(cert: &Certificate, issuer_cert: &Certificate) {
    use x509_cert::ext::pkix::{AuthorityKeyIdentifier, SubjectKeyIdentifier};

    fn find<'a>(cert: &'a Certificate, oid: &str) -> &'a der::asn1::OctetString {
        let target = der::asn1::ObjectIdentifier::new(oid).unwrap();
        &cert
            .tbs_certificate()
            .extensions()
            .expect("le certificat doit porter des extensions")
            .iter()
            .find(|e| e.extn_id == target)
            .unwrap_or_else(|| panic!("extension {oid} absente"))
            .extn_value
    }

    let ski_ext = find(cert, "2.5.29.14");
    let ski = SubjectKeyIdentifier::from_der(ski_ext.as_bytes()).expect("SKI doit se décoder");
    assert_eq!(
        ski.0.as_bytes().len(),
        20,
        "le SKI doit être un condensé SHA-1 (méthode 1, RFC 5280 §4.2.1.2)"
    );

    let aki_ext = find(cert, "2.5.29.35");
    let aki = AuthorityKeyIdentifier::from_der(aki_ext.as_bytes()).expect("AKI doit se décoder");
    let aki_key_id = aki
        .key_identifier
        .expect("l'AKI doit porter un keyIdentifier");

    let issuer_ski_ext = find(issuer_cert, "2.5.29.14");
    let issuer_ski = SubjectKeyIdentifier::from_der(issuer_ski_ext.as_bytes())
        .expect("SKI de l'émetteur doit se décoder");

    assert_eq!(
        aki_key_id.as_bytes(),
        issuer_ski.0.as_bytes(),
        "l'AKI du certificat émis doit pointer vers le SKI de son émetteur"
    );
}

/// Recorder de test qui capture les noms d'événement reçus — sert à vérifier
/// que chaque décision de l'autorité (cérémonie, émission, révocation, CRL)
/// laisse bien une trace, condition posée par le plan de portage (le journal
/// d'audit est une preuve légale, pas un détail d'implémentation).
#[derive(Default, Clone)]
struct EventLog(Arc<std::sync::Mutex<Vec<String>>>);

#[async_trait::async_trait]
impl oe_ca_core::Recorder for EventLog {
    async fn append(&self, event: &str, _data: serde_json::Value) -> Result<(), String> {
        self.0.lock().unwrap().push(event.to_string());
        Ok(())
    }
}

#[tokio::test]
async fn every_authority_decision_is_recorded() {
    let store = store();
    let log = EventLog::default();

    let root_signer = Arc::new(SoftwareToken::generate(2048));
    let issuing_signer = Arc::new(SoftwareToken::generate(2048));
    let hierarchy = run_ceremony(CeremonyOptions {
        root_signer: root_signer.clone(),
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
        recorder: Some(Arc::new(log.clone())),
    })
    .await
    .unwrap();

    let issuer = Issuer::new(Options {
        signer: issuing_signer,
        certificate: hierarchy.issuing,
        chain: vec![],
        store: store.clone(),
        public_url: "https://ca.example.test".to_string(),
        ocsp_url: None,
        crl_validity: time::Duration::hours(24),
        crl_grace: time::Duration::hours(1),
        recorder: Some(Arc::new(log.clone())),
    })
    .unwrap();

    let end_entity = SoftwareToken::generate(2048);
    let public_key_der = end_entity.public_key_der().unwrap();
    let tsa_profile = profile::tsa_signer();
    let cert = issuer
        .issue(
            &public_key_der,
            "audit.example.test",
            &tsa_profile,
            "txn-audit",
        )
        .await
        .unwrap();
    let serial = oe_ca_core::canonical_serial(cert.tbs_certificate().serial_number());
    issuer
        .revoke(&serial, 1, "test-operator", "test")
        .await
        .unwrap();
    issuer.publish_crl().await.unwrap();

    let events = log.0.lock().unwrap().clone();
    assert_eq!(
        events,
        vec![
            "ca.ceremony",
            "ca.certificate_issued",
            "ca.certificate_revoked",
            "ca.crl_published"
        ]
    );
}

#[tokio::test]
async fn revoke_rejects_empty_operator() {
    let store = store();
    let (issuer, _issuing_signer) = issuer_from_ceremony(store.clone()).await;

    let end_entity = SoftwareToken::generate(2048);
    let public_key_der = end_entity.public_key_der().unwrap();
    let tsa_profile = profile::tsa_signer();
    let cert = issuer
        .issue(&public_key_der, "tsu3.example.test", &tsa_profile, "txn-4")
        .await
        .unwrap();
    let serial = oe_ca_core::canonical_serial(cert.tbs_certificate().serial_number());

    let err = issuer.revoke(&serial, 1, "", "").await;
    assert!(
        err.is_err(),
        "révoquer sans identité d'opérateur doit être refusé — traçabilité de la décision"
    );
}

fn public_key() -> Vec<u8> {
    SoftwareToken::generate(2048).public_key_der().unwrap()
}

#[tokio::test]
async fn internal_client_only_accepts_its_fixed_common_name() {
    let store = store();
    let (issuer, _) = issuer_from_ceremony(store.clone()).await;
    let p = profile::internal_client();

    let err = issuer
        .issue(&public_key(), "quelqu-un-d-autre", &p, "txn-x")
        .await
        .expect_err("un autre CN doit être refusé");
    assert!(err.to_string().contains("ra-console"), "{err}");

    let cert = issuer
        .issue(&public_key(), "ra-console", &p, "txn-c")
        .await
        .expect("le CN imposé est admis");
    oe_conformance::check_internal_client_certificate("client", &cert).unwrap();
    assert!(oe_conformance::has_certificate_policy(
        &cert,
        oe_conformance::OID_POLICY_INTERNAL_CLIENT
    ));
    // Aucune politique de l'autre profil, aucun SAN.
    assert!(!oe_conformance::has_certificate_policy(
        &cert,
        oe_conformance::OID_POLICY_INTERNAL_SERVER
    ));
    assert!(oe_conformance::dns_names(&cert).is_empty());
}

#[tokio::test]
async fn internal_server_takes_its_san_from_a_dns_common_name() {
    let store = store();
    let (issuer, _) = issuer_from_ceremony(store.clone()).await;
    let p = profile::internal_server();

    for bad in ["CA", "ca server", "*.example.test", "10.0.0.1", "-ca", ""] {
        assert!(
            issuer.issue(&public_key(), bad, &p, "txn-x").await.is_err(),
            "{bad:?} ne doit pas être admis"
        );
    }

    let cert = issuer
        .issue(&public_key(), "ca.internal.svc", &p, "txn-s")
        .await
        .unwrap();
    oe_conformance::check_internal_server_certificate("serveur", &cert).unwrap();
    assert_eq!(oe_conformance::dns_names(&cert), vec!["ca.internal.svc"]);
}

#[tokio::test]
async fn the_internal_checks_tell_the_profiles_apart() {
    let store = store();
    let (issuer, _) = issuer_from_ceremony(store.clone()).await;
    let client = issuer
        .issue(
            &public_key(),
            "ra-console",
            &profile::internal_client(),
            "t1",
        )
        .await
        .unwrap();
    let server = issuer
        .issue(
            &public_key(),
            "ca.internal.svc",
            &profile::internal_server(),
            "t2",
        )
        .await
        .unwrap();
    let tsu = issuer
        .issue(
            &public_key(),
            "tsu.example.test",
            &profile::tsa_signer(),
            "t3",
        )
        .await
        .unwrap();

    // Un certificat de serveur ne passe pas pour un client, et inversement.
    assert!(oe_conformance::check_internal_client_certificate("x", &server).is_err());
    assert!(oe_conformance::check_internal_server_certificate("x", &client).is_err());
    // Un certificat de TSU (autre EKU, aucune politique) n'est ni l'un ni l'autre.
    assert!(oe_conformance::check_internal_client_certificate("x", &tsu).is_err());
    assert!(oe_conformance::check_internal_server_certificate("x", &tsu).is_err());
}

/// Un journal qui échoue systématiquement : preuve que le journal *avant*
/// l'écriture durable (§15 étape 2b) n'est pas qu'une clause de commentaire,
/// mais bloque réellement la cérémonie, l'émission, la révocation et la
/// publication de CRL avant qu'elles ne touchent le store.
struct FailingRecorder;

#[async_trait::async_trait]
impl oe_ca_core::Recorder for FailingRecorder {
    async fn append(&self, _event: &str, _data: serde_json::Value) -> Result<(), String> {
        Err("stockage du journal injoignable (test)".to_string())
    }
}

#[tokio::test]
async fn a_journal_failure_blocks_the_ceremony_before_any_authority_is_saved() {
    let store = store();
    let err = run_ceremony(CeremonyOptions {
        root_signer: Arc::new(SoftwareToken::generate(2048)),
        issuing_signer: Arc::new(SoftwareToken::generate(2048)),
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
        recorder: Some(Arc::new(FailingRecorder)),
    })
    .await
    .err()
    .expect("la cérémonie doit échouer");
    assert!(err.to_string().contains("journal"), "{err}");
    assert!(
        store.authority(AUTHORITY_ROOT).await.is_err(),
        "aucune autorité ne doit être persistée : la cérémonie a échoué avant"
    );
    assert!(store.authority(AUTHORITY_ISSUING).await.is_err());
}

#[tokio::test]
async fn a_journal_failure_blocks_issuance_before_any_certificate_is_saved() {
    let store = store();
    let (_root_signer, issuing_signer, _root, issuing) = run_test_ceremony(store.clone()).await;
    let issuer = Issuer::new(Options {
        signer: issuing_signer.clone(),
        certificate: issuing.clone(),
        chain: vec![],
        store: store.clone(),
        public_url: "https://ca.example.test".to_string(),
        ocsp_url: None,
        crl_validity: time::Duration::hours(24),
        crl_grace: time::Duration::hours(1),
        recorder: Some(Arc::new(FailingRecorder)),
    })
    .unwrap();

    let err = issuer
        .issue(
            &public_key(),
            "audit.example.test",
            &profile::tsa_signer(),
            "txn-fail",
        )
        .await
        .unwrap_err();
    assert!(err.to_string().contains("journal"), "{err}");

    // Un second essai, même signataire et même certificat émetteur, mais
    // cette fois sans journal défaillant : doit réussir, rien n'a été laissé
    // dans un état à moitié écrit qui empêcherait de rejouer l'émission.
    let issuer_ok = Issuer::new(Options {
        signer: issuing_signer,
        certificate: issuing,
        chain: vec![],
        store: store.clone(),
        public_url: "https://ca.example.test".to_string(),
        ocsp_url: None,
        crl_validity: time::Duration::hours(24),
        crl_grace: time::Duration::hours(1),
        recorder: None,
    })
    .unwrap();
    let cert = issuer_ok
        .issue(
            &public_key(),
            "audit.example.test",
            &profile::tsa_signer(),
            "txn-fail",
        )
        .await
        .expect("l'émission doit réussir une fois le journal disponible");
    let serial = oe_ca_core::canonical_serial(cert.tbs_certificate().serial_number());
    let stored = store.certificate(&serial).await.unwrap();
    assert_eq!(stored.status, oe_castore::CertificateStatus::Issued);
}

#[tokio::test]
async fn a_journal_failure_blocks_revocation_before_the_store_is_touched() {
    let store = store();
    let (_root_signer, issuing_signer, _root, issuing) = run_test_ceremony(store.clone()).await;
    let issuer = Issuer::new(Options {
        signer: issuing_signer.clone(),
        certificate: issuing.clone(),
        chain: vec![],
        store: store.clone(),
        public_url: "https://ca.example.test".to_string(),
        ocsp_url: None,
        crl_validity: time::Duration::hours(24),
        crl_grace: time::Duration::hours(1),
        recorder: None,
    })
    .unwrap();
    let cert = issuer
        .issue(
            &public_key(),
            "audit.example.test",
            &profile::tsa_signer(),
            "txn-rev",
        )
        .await
        .unwrap();
    let serial = oe_ca_core::canonical_serial(cert.tbs_certificate().serial_number());

    // Même signataire, même certificat émetteur : seul le journal change.
    let failing_issuer = Issuer::new(Options {
        signer: issuing_signer,
        certificate: issuing,
        chain: vec![],
        store: store.clone(),
        public_url: "https://ca.example.test".to_string(),
        ocsp_url: None,
        crl_validity: time::Duration::hours(24),
        crl_grace: time::Duration::hours(1),
        recorder: Some(Arc::new(FailingRecorder)),
    })
    .unwrap();

    let err = failing_issuer
        .revoke(&serial, 1, "test-operator", "test")
        .await
        .unwrap_err();
    assert!(err.to_string().contains("journal"), "{err}");

    let still_active = store.certificate(&serial).await.unwrap();
    assert_eq!(
        still_active.status,
        oe_castore::CertificateStatus::Issued,
        "le certificat ne doit pas être révoqué : le journal a échoué avant l'écriture"
    );
}

#[tokio::test]
async fn a_journal_failure_blocks_crl_publication_before_the_store_is_touched() {
    let store = store();
    let (_root_signer, issuing_signer, _root, issuing) = run_test_ceremony(store.clone()).await;
    let issuer = Issuer::new(Options {
        signer: issuing_signer,
        certificate: issuing,
        chain: vec![],
        store: store.clone(),
        public_url: "https://ca.example.test".to_string(),
        ocsp_url: None,
        crl_validity: time::Duration::hours(24),
        crl_grace: time::Duration::hours(1),
        recorder: Some(Arc::new(FailingRecorder)),
    })
    .unwrap();

    let err = issuer.publish_crl().await.unwrap_err();
    assert!(err.to_string().contains("journal"), "{err}");
    assert!(
        store.latest_crl().await.is_err(),
        "aucune CRL ne doit être publiée : le journal a échoué avant"
    );
}
