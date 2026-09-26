//! Révocation d'un certificat par une action signée (docs/WEBUI.md §5) : la
//! vraie CA (`Issuer`, clés logicielles de test), le vrai registre PostgreSQL,
//! un authentificateur logiciel. Ce que le test prouve : sans signature valide
//! d'un `ca_operateur`, rien n'est révoqué ; avec, le certificat l'est et la CRL
//! republiée le porte.
//!
//! DSN dans `OE_CASTORE_TEST_DSN` ; test ignoré si elle n'est pas définie.

use std::sync::Arc;

use ca_server::revoker::IssuerRevoker;
use der::Decode;
use oe_actions::{Action, Error, NewCredential, Registry, Role, Service};
use oe_ca_core::ceremony::{run_ceremony, CeremonyOptions};
use oe_ca_core::{profile, Issuer, Options};
use oe_castore::{CertificateStatus, Postgres, Store};
use oe_hsm::testing::SoftwareToken;
use oe_hsm::SigningToken;
use oe_raflow::{Decider, DeciderOptions, Recorder};
use oe_webauthn::{trusted_models, TrustedModel, Url, Uuid, Verifier};
use sqlx::postgres::PgPoolOptions;
use time::OffsetDateTime;
use webauthn_authenticator_rs::softtoken::{SoftToken, AAGUID};
use webauthn_authenticator_rs::WebauthnAuthenticator;

fn origin() -> Url {
    Url::parse("https://console.example.com").unwrap()
}

struct NullJournal;
#[async_trait::async_trait]
impl Recorder for NullJournal {
    async fn append(&self, _: &str, _: serde_json::Value) -> Result<(), String> {
        Ok(())
    }
}

struct Env {
    store: Arc<dyn Store>,
    issuer: Arc<Issuer>,
    registry: Registry,
    with: Service,
    without: Service,
    authn: WebauthnAuthenticator<SoftToken>,
    verifier: Verifier,
}

impl Env {
    async fn new() -> Option<Env> {
        let base = std::env::var("OE_CASTORE_TEST_DSN").ok()?;
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let name = format!("rev_{nanos}");
        let admin = PgPoolOptions::new().connect(&base).await.unwrap();
        sqlx::query(&format!("CREATE DATABASE {name}"))
            .execute(&admin)
            .await
            .unwrap();
        let dsn = format!("{}/{name}", base.rsplit_once('/').unwrap().0);
        let store: Arc<dyn Store> = Arc::new(Postgres::open(&dsn).await.unwrap());
        let registry = Registry::connect(&dsn).await.unwrap();

        let issuing = Arc::new(SoftwareToken::generate(2048));
        let h = run_ceremony(CeremonyOptions {
            root_signer: Arc::new(SoftwareToken::generate(2048)),
            issuing_signer: issuing.clone(),
            root_cn: "Test Root CA".into(),
            issuing_cn: "Test Issuing CA".into(),
            organization: "Open eIDAS Test".into(),
            country: "FR".into(),
            root_validity: time::Duration::days(3650),
            issuing_validity: time::Duration::days(3650),
            root_token_label: "r".into(),
            root_key_label: "r".into(),
            issuing_token_label: "i".into(),
            issuing_key_label: "i".into(),
            store: store.clone(),
            operator: "test".into(),
            public_url: "https://ca.example.test".to_string(),
            recorder: None,
        })
        .await
        .unwrap();
        let issuer = Arc::new(
            Issuer::new(Options {
                signer: issuing,
                certificate: h.issuing,
                chain: vec![],
                store: store.clone(),
                public_url: "https://ca.example.test".into(),
                ocsp_url: None,
                crl_validity: time::Duration::hours(24),
                crl_grace: time::Duration::hours(1),
                recorder: None,
            })
            .unwrap(),
        );

        let (token, root) = SoftToken::new(true).unwrap();
        let root_pem = root.to_pem().unwrap();
        let make_verifier = || {
            Verifier::new(
                "console.example.com",
                &origin(),
                "test",
                trusted_models(&[TrustedModel {
                    root_pem: &root_pem,
                    aaguid: AAGUID,
                    description: "SoftToken (test)",
                }])
                .unwrap(),
            )
            .unwrap()
        };
        let journal: Arc<dyn Recorder> = Arc::new(NullJournal);
        let make_service = || {
            Service::new(
                registry.clone(),
                make_verifier(),
                store.clone(),
                Decider::new(DeciderOptions {
                    store: store.clone(),
                    recorder: None,
                    clock: None,
                }),
                journal.clone(),
                Arc::new(OffsetDateTime::now_utc),
            )
        };
        let with = make_service().with_revoker(Arc::new(IssuerRevoker(issuer.clone())));
        let without = make_service();
        Some(Env {
            store,
            issuer,
            registry,
            with,
            without,
            authn: WebauthnAuthenticator::new(token),
            verifier: make_verifier(),
        })
    }

    async fn operator(&mut self, name: &str, role: Role) -> Uuid {
        let now = OffsetDateTime::now_utc();
        let id = self
            .registry
            .add_operator(name, role, "test", now)
            .await
            .unwrap();
        let (options, state) = self.verifier.start_registration(id, name, None).unwrap();
        let reg = self.authn.do_registration(origin(), options).unwrap();
        let key = self.verifier.finish_registration(&reg, &state).unwrap();
        self.registry
            .add_credential(
                NewCredential {
                    operator_id: id,
                    passkey: &key,
                    aaguid: AAGUID,
                    attestation_format: "basic",
                    attestation_object: reg.response.attestation_object.as_ref(),
                    label: "test",
                    initiated_by: "test",
                    confirmed_by: Some("test"),
                },
                now,
            )
            .await
            .unwrap();
        id
    }

    /// Un certificat de TSU émis, et son numéro de série en hexadécimal.
    async fn certificate(&self, tx: &str) -> String {
        let key = SoftwareToken::generate(2048);
        let cert = self
            .issuer
            .issue(
                &key.public_key_der().unwrap(),
                "tsu.example.test",
                &profile::tsa_signer(),
                tx,
            )
            .await
            .unwrap();
        hex::encode(oe_ca_core::canonical_serial(
            cert.tbs_certificate().serial_number(),
        ))
    }
}

impl Env {
    /// Deux `ca_operateur` distincts signent la même action figée.
    async fn revoke_with_two(&mut self, first: Uuid, second: Uuid, action: Action) {
        let issued = self.with.issue_challenge(action, first).await.unwrap();
        let a = self
            .authn
            .do_authentication(origin(), issued.options.clone())
            .unwrap();
        let done = self.with.execute(issued.challenge_id, &a).await.unwrap();
        assert!(!done.executed, "une seule signature ne révoque pas");
        let issued = self
            .with
            .issue_challenge_for(issued.action_id, second)
            .await
            .unwrap();
        let a = self
            .authn
            .do_authentication(origin(), issued.options.clone())
            .unwrap();
        let done = self.with.execute(issued.challenge_id, &a).await.unwrap();
        assert!(done.executed);
    }
}

fn revoke(serial: &str, reason: i32, comment: &str) -> Action {
    Action::RevokeCertificate {
        serial: serial.to_string(),
        reason,
        comment: comment.to_string(),
    }
}

#[tokio::test]
async fn a_ca_operator_revokes_a_certificate_and_the_crl_carries_it() {
    let Some(mut env) = Env::new().await else {
        eprintln!("OE_CASTORE_TEST_DSN non définie : test PostgreSQL ignoré");
        return;
    };
    let carla = env.operator("carla", Role::CaOperateur).await;
    let dave = env.operator("dave", Role::CaOperateur).await;
    let rita = env.operator("rita", Role::RaOperateur).await;
    let serial = env.certificate("t1").await;
    let action = revoke(&serial, 1, "Signalement CERT-FR 2026-991");

    // Un opérateur RA ne révoque pas : pas de challenge du tout.
    let err = env
        .with
        .issue_challenge(action.clone(), rita)
        .await
        .expect_err("rôle insuffisant");
    assert!(matches!(err, Error::Denied(_)), "{err}");
    assert_eq!(status(&env, &serial).await, CertificateStatus::Issued);

    // Un seul ca_operateur ne suffit pas : la première signature est recueillie,
    // le certificat reste valide.
    let issued = env
        .with
        .issue_challenge(action.clone(), carla)
        .await
        .unwrap();
    assert_eq!(issued.required_signatures, 2);
    let assertion = env
        .authn
        .do_authentication(origin(), issued.options.clone())
        .unwrap();
    let first = env
        .with
        .execute(issued.challenge_id, &assertion)
        .await
        .unwrap();
    assert!(!first.executed);
    assert_eq!(status(&env, &serial).await, CertificateStatus::Issued);

    // Un second, distinct, signe le même corps figé : la révocation a lieu.
    let issued = env
        .with
        .issue_challenge_for(issued.action_id, dave)
        .await
        .unwrap();
    let assertion = env
        .authn
        .do_authentication(origin(), issued.options.clone())
        .unwrap();
    let done = env
        .with
        .execute(issued.challenge_id, &assertion)
        .await
        .unwrap();
    assert!(done.executed);

    assert_eq!(done.operator, "dave");
    let result = done.result.unwrap();
    assert_eq!(result["crl_published"], true);
    assert_eq!(status(&env, &serial).await, CertificateStatus::Revoked);

    // La CRL publiée porte ce numéro de série.
    let crl = env.store.latest_crl().await.unwrap();
    assert_eq!(crl.number, result["crl_number"].as_i64().unwrap());
    let list =
        x509_cert::crl::CertificateList::<x509_cert::certificate::Rfc5280>::from_der(&crl.der)
            .unwrap();
    let listed: Vec<String> = list
        .tbs_cert_list
        .revoked_certificates
        .unwrap_or_default()
        .iter()
        .map(|r| hex::encode(r.serial_number.as_bytes()))
        .collect();
    // Ni la liste ni le numéro ne sont affichés : ils dérivent du certificat émis.
    assert!(
        listed.iter().any(|s| s.trim_start_matches("00") == serial),
        "la CRL ne contient pas le numéro de série révoqué ({} entrées)",
        listed.len()
    );
}

async fn status(env: &Env, serial: &str) -> CertificateStatus {
    env.store
        .certificate(&hex::decode(serial).unwrap())
        .await
        .unwrap()
        .status
}

#[tokio::test]
async fn refused_revocations_leave_the_certificate_untouched() {
    let Some(mut env) = Env::new().await else {
        eprintln!("OE_CASTORE_TEST_DSN non définie : test PostgreSQL ignoré");
        return;
    };
    let carla = env.operator("carla", Role::CaOperateur).await;
    let dave = env.operator("dave", Role::CaOperateur).await;
    let serial = env.certificate("t1").await;

    let cases: Vec<(&str, Action, bool)> = vec![
        ("motif 0 (non précisé)", revoke(&serial, 0, "x"), false),
        ("motif 6 (suspension)", revoke(&serial, 6, "x"), false),
        ("motif 2 (CA)", revoke(&serial, 2, "x"), false),
        ("sans commentaire", revoke(&serial, 1, "  "), false),
        (
            "série en majuscules",
            revoke(&serial.to_uppercase(), 1, "x"),
            false,
        ),
        ("série impaire", revoke(&serial[1..], 1, "x"), false),
        ("série inconnue", revoke("00ff00ff00ff", 1, "x"), true),
    ];
    for (label, action, denied) in cases {
        let err = env
            .with
            .issue_challenge(action, carla)
            .await
            .expect_err(label);
        if denied {
            assert!(matches!(err, Error::Denied(_)), "{label} : {err}");
        } else {
            assert!(matches!(err, Error::BadRequest(_)), "{label} : {err}");
        }
    }
    assert_eq!(status(&env, &serial).await, CertificateStatus::Issued);

    // Un service sans autorité branchée ne fait signer aucune révocation.
    let err = env
        .without
        .issue_challenge(revoke(&serial, 1, "x"), carla)
        .await
        .expect_err("sans révocateur");
    assert!(matches!(err, Error::Denied(_)), "{err}");

    // Déjà révoqué : refusé, sans nouvelle signature demandée.
    env.revoke_with_two(carla, dave, revoke(&serial, 1, "x"))
        .await;
    let err = env
        .with
        .issue_challenge(revoke(&serial, 1, "encore"), carla)
        .await
        .expect_err("déjà révoqué");
    assert!(matches!(err, Error::Denied(_)), "{err}");
}
