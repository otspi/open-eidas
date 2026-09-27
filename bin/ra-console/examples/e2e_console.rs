//! Harnais des tests de bout en bout du frontend (bin/ra-console/web/e2e,
//! Playwright) : une console réelle (`ra_console::http::app`, assets embarqués
//! et en-têtes de sécurité compris) sur un vrai PostgreSQL, un opérateur
//! enregistré, et sa clé privée exportée pour l'authentificateur virtuel du
//! navigateur (CDP `WebAuthn.addCredential`).
//!
//! La liste blanche de modèles de clés refuserait l'attestation d'un
//! authentificateur virtuel : l'opérateur est donc enregistré avec le
//! `SoftToken` des tests Rust, dont la clé est ensuite confiée au navigateur.
//!
//! Variables : `OE_CASTORE_TEST_DSN` (obligatoire), `E2E_PORT` (défaut 8431),
//! `E2E_FIXTURE` (défaut `target/e2e-fixture.json`).
//! Ne sert qu'aux tests : jamais construit dans l'image.

#[path = "../tests/common/mod.rs"]
mod common;

use std::sync::Arc;

use base64::Engine;
use oe_actions::{NewCredential, Registry, Role};
use oe_webauthn::{trusted_models, TrustedModel, Url, Verifier};
use ra_console::ca_link::CaLink;
use ra_console::http::{app, AppState};
use ra_console::login::LoginService;
use sqlx::postgres::PgPoolOptions;
use webauthn_authenticator_rs::softtoken::{SoftToken, SoftTokenFile, AAGUID};
use webauthn_authenticator_rs::WebauthnAuthenticator;

#[tokio::main]
async fn main() {
    let base = std::env::var("OE_CASTORE_TEST_DSN").expect("OE_CASTORE_TEST_DSN est obligatoire");
    let port: u16 = std::env::var("E2E_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(8431);
    let fixture = std::env::var("E2E_FIXTURE").unwrap_or_else(|_| "target/e2e-fixture.json".into());
    let origin = Url::parse(&format!("http://localhost:{port}")).unwrap();

    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let name = format!("e2e_{nanos}");
    let admin = PgPoolOptions::new().connect(&base).await.unwrap();
    sqlx::query(&format!("CREATE DATABASE {name}"))
        .execute(&admin)
        .await
        .unwrap();
    let dsn = format!("{}/{name}", base.rsplit_once('/').unwrap().0);
    let store: Arc<dyn oe_castore::Store> =
        Arc::new(oe_castore::Postgres::open(&dsn).await.unwrap());
    let registry = Registry::connect(&dsn).await.unwrap();

    let (token, root) = SoftToken::new(true).unwrap();
    let root_pem = root.to_pem().unwrap();
    let verifier = || {
        Verifier::new(
            "localhost",
            &origin,
            "Open eIDAS Console — e2e",
            trusted_models(&[TrustedModel {
                root_pem: &root_pem,
                aaguid: AAGUID,
                description: "SoftToken (e2e)",
            }])
            .unwrap(),
        )
        .unwrap()
    };

    // L'opérateur et sa clé, comme en production mais sans passer par
    // l'enregistrement relayé (qui a ses propres tests).
    let now = time::OffsetDateTime::now_utc();
    let operator = registry
        .add_operator("alice", Role::RaOperateur, "e2e", now)
        .await
        .unwrap();
    let reg_verifier = verifier();
    // Le SoftToken s'enregistre dans ce fichier à sa fermeture : c'est ainsi que
    // la clé du credential créé ci-dessous se relit (aucun accesseur public).
    let token_path = std::env::temp_dir().join(format!("{name}.softtoken"));
    let token_file = std::fs::File::create(&token_path).unwrap();
    let mut authn = WebauthnAuthenticator::new(SoftTokenFile::new(token, token_file));
    let (options, state) = reg_verifier
        .start_registration(operator, "alice", None)
        .unwrap();
    let reg = authn.do_registration(origin.clone(), options).unwrap();
    drop(authn);
    let key = reg_verifier.finish_registration(&reg, &state).unwrap();
    registry
        .add_credential(
            NewCredential {
                operator_id: operator,
                passkey: &key,
                aaguid: AAGUID,
                attestation_format: "packed",
                attestation_object: reg.response.attestation_object.as_ref(),
                label: "e2e",
                initiated_by: "e2e",
                confirmed_by: Some("e2e"),
            },
            now,
        )
        .await
        .unwrap();

    // La clé privée du SoftToken (SEC1), convertie en PKCS#8 pour le navigateur.
    let credential_id: Vec<u8> = reg.raw_id.as_ref().to_vec();
    let soft: serde_cbor_2::Value =
        serde_cbor_2::from_slice(&std::fs::read(&token_path).unwrap()).unwrap();
    let _ = std::fs::remove_file(&token_path);
    let (sec1, counter) = soft_key(&soft, &credential_id);
    let ec = openssl::ec::EcKey::private_key_from_der(&sec1).unwrap();
    let pkcs8 = openssl::pkey::PKey::from_ec_key(ec)
        .unwrap()
        .private_key_to_pkcs8()
        .unwrap();
    let b64 = base64::engine::general_purpose::STANDARD;
    let pending: Vec<String> = (1..=8).map(|i| format!("tx-e2e-{i}")).collect();
    let out = serde_json::json!({
        "origin": origin.as_str().trim_end_matches('/'),
        "pending": pending,
        "operator": "alice",
        "role": "ra_operateur",
        "credential": {
            "credentialId": b64.encode(&credential_id),
            "isResidentCredential": false,
            "rpId": "localhost",
            "privateKey": b64.encode(pkcs8),
            "userHandle": b64.encode(operator.as_bytes()),
            "signCount": counter,
        },
    });
    if let Some(parent) = std::path::Path::new(&fixture).parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    std::fs::write(&fixture, serde_json::to_vec_pretty(&out).unwrap()).unwrap();

    // Des demandes d'enrôlement en attente, pour les écrans de décision (6b).
    for (i, tx) in pending.iter().enumerate() {
        store
            .create_request(oe_castore::Request {
                transaction_id: tx.clone(),
                csr_fingerprint: format!("empreinte-{tx}"),
                csr_der: vec![0x30, 0x00],
                profile: "tsa_signer".to_string(),
                subject_cn: format!("tsu-{}.example.test", i + 1),
                state: oe_castore::RequestState::Pending,
                created_at: now,
                decided_at: None,
                operator: String::new(),
                comment: String::new(),
                issued_at: None,
                certificate_serial: None,
            })
            .await
            .unwrap();
    }

    // Le vrai service d'actions de ca-server, derrière son routeur interne et le
    // lien mTLS : les décisions signées dans le navigateur y sont vérifiées.
    let service = Arc::new(oe_actions::Service::new(
        registry.clone(),
        verifier(),
        store.clone(),
        oe_raflow::Decider::new(oe_raflow::DeciderOptions {
            store: store.clone(),
            recorder: None,
            clock: None,
        }),
        Arc::new(NullJournal),
        Arc::new(time::OffsetDateTime::now_utc),
    ));
    let pki = common::pki().await;
    let internal = pki
        .serve_router(ca_server::internal::router(service, 64 * 1024))
        .await;
    let dir = common::tempdir::Dir::new();
    let client = pki
        .cert(&oe_ca_core::profile::internal_client(), "ra-console")
        .await;
    let link = CaLink::new(&pki.files(&dir, &client, internal)).unwrap();
    let pool = PgPoolOptions::new().connect(&dsn).await.unwrap();
    let console = app(
        Arc::new(AppState {
            pool: pool.clone(),
            link,
            login: LoginService::new(
                registry.clone(),
                verifier(),
                b"secret-de-test-au-moins-16-octets".to_vec(),
                Arc::new(ra_console::audit::NullRecorder),
            ),
            sessions: common::sessions(pool),
            journal: Arc::new(ra_console::audit::NullRecorder),
        }),
        ra_console::web::Console {
            environment: ra_console::web::Environment::Staging,
        },
    );
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", port))
        .await
        .unwrap();
    eprintln!("e2e : console prête sur {origin}, fixture {fixture}");
    axum::serve(listener, console).await.unwrap();
}

/// La clé privée (DER SEC1) d'un credential, et le compteur de signatures.
fn soft_key(token: &serde_cbor_2::Value, credential_id: &[u8]) -> (Vec<u8>, u64) {
    use serde_cbor_2::Value;
    let Value::Map(fields) = token else {
        panic!("SoftToken : format inattendu")
    };
    let field = |name: &str| {
        fields
            .iter()
            .find(|(k, _)| matches!(k, Value::Text(t) if t == name))
            .map(|(_, v)| v)
            .unwrap_or_else(|| panic!("SoftToken : champ {name} absent"))
    };
    let Value::Map(tokens) = field("tokens") else {
        panic!("SoftToken : tokens inattendu")
    };
    let key = tokens
        .iter()
        .find_map(|(k, v)| match (k, v) {
            (Value::Bytes(id), Value::Bytes(der)) if id == credential_id => Some(der.clone()),
            (Value::Array(id), Value::Array(der)) if bytes_of(id) == credential_id => {
                Some(bytes_of(der))
            }
            _ => None,
        })
        .expect("SoftToken : clé du credential introuvable");
    let counter = match field("counter") {
        Value::Integer(n) => *n as u64,
        _ => 0,
    };
    (key, counter)
}

fn bytes_of(values: &[serde_cbor_2::Value]) -> Vec<u8> {
    values
        .iter()
        .map(|v| match v {
            serde_cbor_2::Value::Integer(n) => *n as u8,
            _ => panic!("octet attendu"),
        })
        .collect()
}

struct NullJournal;

#[async_trait::async_trait]
impl oe_raflow::Recorder for NullJournal {
    async fn append(&self, _: &str, _: serde_json::Value) -> Result<(), String> {
        Ok(())
    }
}
