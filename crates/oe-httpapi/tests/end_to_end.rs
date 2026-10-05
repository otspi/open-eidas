//! Test bout-en-bout du jalon J7 du plan de migration
//! (`/home/philippe/.claude/plans/witty-hopping-nest.md`) : démarre le
//! serveur HTTP réel (`axum::serve` sur un port éphémère), envoie une
//! requête RFC 3161 avec un client HTTP réel (`reqwest`), et vérifie la
//! réponse avec `openssl ts -verify` — reproduit `helm-kind-smoke-test`
//! côté Go, mais contre le binaire Rust.

use std::path::PathBuf;
use std::process::Command;
use std::sync::Arc;

use der::Decode;
use oe_hsm::testing::SoftwareToken;
use oe_tsa_core::{Authority, Clock, Options as TsaOptions};
use x509_cert::Certificate;

fn fixtures_dir() -> PathBuf {
    PathBuf::from(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../oe-tsa-core/../../tests/fixtures/tsa"
    ))
}

struct FixedClock;
impl Clock for FixedClock {
    fn now(&self) -> Result<time::OffsetDateTime, String> {
        Ok(time::OffsetDateTime::now_utc())
    }
}

fn load_authority() -> Arc<Authority> {
    let dir = fixtures_dir();
    let key_pem = std::fs::read_to_string(dir.join("tsu-key.pem")).unwrap();
    let cert_pem = std::fs::read_to_string(dir.join("tsu-cert.pem")).unwrap();
    let signer = SoftwareToken::from_pkcs8_pem(&key_pem).unwrap();
    let cert_block = pem::parse(cert_pem.as_bytes()).unwrap();
    let certificate = Certificate::from_der(cert_block.contents()).unwrap();

    Arc::new(
        Authority::new(TsaOptions {
            signer: Arc::new(signer),
            certificate,
            chain: Vec::new(),
            policy: der::asn1::ObjectIdentifier::new("1.3.6.1.4.1.67027.9.1.1.1").unwrap(),
            accuracy: std::time::Duration::from_secs(1),
            signing_digest: oe_hsm::DigestAlg::Sha256,
            clock: Arc::new(FixedClock),
            recorder: None,
        })
        .unwrap(),
    )
}

#[tokio::test]
async fn serves_a_verifiable_token_over_http() {
    let authority = load_authority();
    let time_source = oe_timesource::Monitor::new(oe_timesource::Options {
        policy: oe_timesource::Policy::Disabled,
        ..Default::default()
    })
    .unwrap();

    let app = oe_httpapi::router(oe_httpapi::Options {
        authority,
        time_source,
        max_request_bytes: 64 * 1024,
        version: "test".to_string(),
        cors_allowed_origin: None,
    });

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    let client = reqwest::Client::new();

    // /healthz doit répondre 200 (politique de temps désactivée => traçable).
    let health = client
        .get(format!("http://{addr}/healthz"))
        .send()
        .await
        .unwrap();
    assert_eq!(health.status(), 200);

    // /api/v1/policy doit lister les algorithmes admis.
    let policy = client
        .get(format!("http://{addr}/api/v1/policy"))
        .send()
        .await
        .unwrap();
    assert_eq!(policy.status(), 200);
    let policy_json: serde_json::Value = policy.json().await.unwrap();
    assert!(policy_json["accepted_hashes"]
        .as_array()
        .unwrap()
        .contains(&serde_json::json!("sha256")));

    // /api/v1/certificate doit publier le certificat en PEM.
    let cert_resp = client
        .get(format!("http://{addr}/api/v1/certificate"))
        .send()
        .await
        .unwrap();
    assert_eq!(cert_resp.status(), 200);
    let cert_pem_served = cert_resp.text().await.unwrap();
    assert!(cert_pem_served.contains("BEGIN CERTIFICATE"));

    // POST /tsa avec une vraie requête du corpus, vérifiée par openssl.
    let req_path = PathBuf::from(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/fixtures/rfc3161/granted-sha256-with-cert/request.der"
    ));
    let req_der = std::fs::read(&req_path).unwrap();

    let resp = client
        .post(format!("http://{addr}/tsa"))
        .header("Content-Type", "application/timestamp-query")
        .body(req_der)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(
        resp.headers().get("content-type").unwrap(),
        "application/timestamp-reply"
    );
    let resp_der = resp.bytes().await.unwrap();

    let out_path = std::env::temp_dir().join("oe-httpapi-e2e-response.der");
    std::fs::write(&out_path, &resp_der).unwrap();
    let cert_path = fixtures_dir().join("tsu-cert.pem");

    let output = Command::new("openssl")
        .args([
            "ts",
            "-verify",
            "-in",
            out_path.to_str().unwrap(),
            "-queryfile",
            req_path.to_str().unwrap(),
            "-CAfile",
            cert_path.to_str().unwrap(),
            "-untrusted",
            cert_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "openssl ts -verify a rejeté la réponse HTTP: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let _ = std::fs::remove_file(&out_path);
}

#[tokio::test]
async fn cors_header_present_only_when_configured() {
    let time_source = || {
        oe_timesource::Monitor::new(oe_timesource::Options {
            policy: oe_timesource::Policy::Disabled,
            ..Default::default()
        })
        .unwrap()
    };

    // Sans cors_allowed_origin : pas d'en-tête CORS, même pour une origine
    // qui enverrait un Origin arbitraire — le navigateur bloquera la lecture
    // de la réponse.
    let app = oe_httpapi::router(oe_httpapi::Options {
        authority: load_authority(),
        time_source: time_source(),
        max_request_bytes: 64 * 1024,
        version: "test".to_string(),
        cors_allowed_origin: None,
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let resp = reqwest::Client::new()
        .get(format!("http://{addr}/api/v1/policy"))
        .header("Origin", "https://demo.open-eidas.eu")
        .send()
        .await
        .unwrap();
    assert!(resp.headers().get("access-control-allow-origin").is_none());

    // Avec cors_allowed_origin configuré : l'en-tête reflète exactement
    // l'origine autorisée, pas un wildcard ni l'origine de la requête.
    let app = oe_httpapi::router(oe_httpapi::Options {
        authority: load_authority(),
        time_source: time_source(),
        max_request_bytes: 64 * 1024,
        version: "test".to_string(),
        cors_allowed_origin: Some("https://demo.open-eidas.eu".to_string()),
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let resp = reqwest::Client::new()
        .get(format!("http://{addr}/api/v1/policy"))
        .header("Origin", "https://demo.open-eidas.eu")
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.headers().get("access-control-allow-origin").unwrap(),
        "https://demo.open-eidas.eu"
    );

    // Une origine différente, elle, ne doit PAS recevoir l'en-tête : sinon
    // `AllowOrigin::exact` renverrait cette même valeur à n'importe qui
    // (fuite d'information sur la configuration, pas une vraie restriction
    // par origine — voir la revue du commit qui a introduit ce test).
    let resp = reqwest::Client::new()
        .get(format!("http://{addr}/api/v1/policy"))
        .header("Origin", "https://evil.example")
        .send()
        .await
        .unwrap();
    assert!(resp.headers().get("access-control-allow-origin").is_none());
}
