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

/// Horloge en retard de 90 s, à la seconde près : l'heure de la réponse et celle
/// du jeton ne peuvent plus se confondre.
struct LateClock;
impl Clock for LateClock {
    fn now(&self) -> Result<time::OffsetDateTime, String> {
        let t = time::OffsetDateTime::now_utc() - time::Duration::seconds(90);
        Ok(t.replace_nanosecond(0).unwrap())
    }
}

fn load_authority() -> Arc<Authority> {
    load_authority_with(Arc::new(FixedClock))
}

fn load_authority_with(clock: Arc<dyn Clock>) -> Arc<Authority> {
    load_authority_full(clock, None)
}

fn load_authority_full(
    clock: Arc<dyn Clock>,
    recorder: Option<Arc<dyn oe_tsa_core::Recorder>>,
) -> Arc<Authority> {
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
            signature_scheme: oe_hsm::Scheme::Pkcs1v15,
            clock,
            recorder,
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
        max_concurrent: 0,
        version: "test".to_string(),
        cors_allowed_origin: None,
        journal: None,
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
        max_concurrent: 0,
        version: "test".to_string(),
        cors_allowed_origin: None,
        journal: None,
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
        max_concurrent: 0,
        version: "test".to_string(),
        cors_allowed_origin: Some("https://demo.open-eidas.eu".to_string()),
        journal: None,
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

/// Constat J-1 de l'audit du 2026-09-25 : /healthz dit où en sont le
/// scellement et la copie hors site du journal. Un journal dégradé se voit,
/// mais ne coupe pas le service (/healthz est aussi la sonde de vivacité).
#[tokio::test]
async fn health_reports_the_journal_without_taking_the_service_down() {
    struct Journal(Option<&'static str>);
    impl oe_httpapi::JournalHealth for Journal {
        fn report(&self) -> oe_httpapi::JournalReport {
            oe_httpapi::JournalReport {
                degraded: self.0.map(str::to_string),
                detail: serde_json::json!({ "degraded": self.0.is_some(), "seal_failures": 3 }),
            }
        }
    }
    let serve = |journal: Option<Arc<dyn oe_httpapi::JournalHealth>>, policy| async move {
        let app = oe_httpapi::router(oe_httpapi::Options {
            authority: load_authority(),
            // Une source injoignable, jamais sondée : sous `enforce`,
            // l'heure n'est donc pas traçable.
            time_source: oe_timesource::Monitor::new(oe_timesource::Options {
                servers: vec!["127.0.0.1:9".to_string()],
                policy,
                ..Default::default()
            })
            .unwrap(),
            max_request_bytes: 64 * 1024,
            max_concurrent: 0,
            version: "test".to_string(),
            cors_allowed_origin: None,
            journal,
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let resp = reqwest::get(format!("http://{addr}/healthz"))
            .await
            .unwrap();
        let status = resp.status();
        (status, resp.json::<serde_json::Value>().await.unwrap())
    };
    let disabled = oe_timesource::Policy::Disabled;

    // Sans scellement branché : rien n'est dit du journal.
    let (status, body) = serve(None, disabled).await;
    assert_eq!(status, reqwest::StatusCode::OK);
    assert_eq!(body["status"], "ok");
    assert!(body.get("journal").is_none(), "{body}");

    // Journal sain.
    let (status, body) = serve(Some(Arc::new(Journal(None))), disabled).await;
    assert_eq!(status, reqwest::StatusCode::OK);
    assert_eq!(body["status"], "ok");
    assert_eq!(body["journal"]["degraded"], false);

    // Journal dégradé : toujours 200, mais dit.
    let reason = "scellement en échec depuis 3 passes";
    let (status, body) = serve(Some(Arc::new(Journal(Some(reason)))), disabled).await;
    assert_eq!(status, reqwest::StatusCode::OK, "{body}");
    assert_eq!(
        body["status"],
        format!("dégradé — journal d'audit : {reason}")
    );
    assert_eq!(body["journal"]["degraded"], true);

    // L'heure non traçable sous `enforce` reste un 503, et son libellé prime.
    let (status, body) = serve(
        Some(Arc::new(Journal(Some(reason)))),
        oe_timesource::Policy::Enforce,
    )
    .await;
    assert_eq!(status, reqwest::StatusCode::SERVICE_UNAVAILABLE, "{body}");
    assert!(
        body["status"]
            .as_str()
            .unwrap()
            .starts_with("heure non traçable"),
        "{body}"
    );
    assert_eq!(body["journal"]["degraded"], true);
}

/// Constat S-3 : le `gen_time` de la façade JSON est le `genTime` du jeton, pas
/// l'heure de la réponse.
#[tokio::test]
async fn the_json_facade_reports_the_gen_time_of_the_token() {
    let time_source = oe_timesource::Monitor::new(oe_timesource::Options {
        policy: oe_timesource::Policy::Disabled,
        ..Default::default()
    })
    .unwrap();
    let app = oe_httpapi::router(oe_httpapi::Options {
        authority: load_authority_with(Arc::new(LateClock)),
        time_source,
        max_request_bytes: 64 * 1024,
        max_concurrent: 0,
        version: "test".to_string(),
        cors_allowed_origin: None,
        journal: None,
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/api/v1/timestamp"))
        .json(&serde_json::json!({
            "algorithm": "sha256",
            "hash": "00".repeat(32),
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();

    use base64::Engine;
    let resp_der = base64::engine::general_purpose::STANDARD
        .decode(body["token"].as_str().unwrap())
        .unwrap();
    let info = oe_rfc3161_asn1::token::tst_info_of_response(&resp_der).unwrap();
    let from_token = oe_rfc3161_asn1::gen_time::to_rfc3339(&info.gen_time).unwrap();
    assert_eq!(body["gen_time"], from_token);

    let reported = time::OffsetDateTime::parse(
        from_token.as_str(),
        &time::format_description::well_known::Rfc3339,
    )
    .unwrap();
    assert!(
        time::OffsetDateTime::now_utc() - reported > time::Duration::seconds(60),
        "le gen_time doit être celui du jeton (en retard de 90 s), pas l'heure de la réponse : {from_token}"
    );
}

/// Un journal lent : chaque jeton occupe sa place de signature assez longtemps
/// pour qu'une seconde requête arrive pendant ce temps.
struct SlowRecorder;
impl oe_tsa_core::Recorder for SlowRecorder {
    fn append(&self, _event: &str, _data: serde_json::Value) -> Result<(), String> {
        std::thread::sleep(std::time::Duration::from_millis(800));
        Ok(())
    }
}

/// Au-delà de `max_concurrent` signatures simultanées, le service répond 503 avec
/// `Retry-After` au lieu de mettre la requête en file derrière l'unique session
/// PKCS#11 ; `/healthz` reste disponible, et la place se libère ensuite.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_saturated_service_sheds_signing_requests_but_not_health() {
    let time_source = oe_timesource::Monitor::new(oe_timesource::Options {
        policy: oe_timesource::Policy::Disabled,
        ..Default::default()
    })
    .unwrap();
    let app = oe_httpapi::router(oe_httpapi::Options {
        authority: load_authority_full(Arc::new(FixedClock), Some(Arc::new(SlowRecorder))),
        time_source,
        max_request_bytes: 64 * 1024,
        max_concurrent: 1,
        version: "test".to_string(),
        cors_allowed_origin: None,
        journal: None,
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let client = reqwest::Client::new();
    let post = |c: reqwest::Client| async move {
        c.post(format!("http://{addr}/api/v1/timestamp"))
            .json(&serde_json::json!({"algorithm": "sha256", "hash": "00".repeat(32)}))
            .send()
            .await
            .unwrap()
    };

    let first = tokio::spawn(post(client.clone()));
    tokio::time::sleep(std::time::Duration::from_millis(250)).await;

    let shed = post(client.clone()).await;
    assert_eq!(shed.status(), 503);
    assert_eq!(shed.headers()["retry-after"], "1");
    let health = client
        .get(format!("http://{addr}/healthz"))
        .send()
        .await
        .unwrap();
    assert_eq!(health.status(), 200, "healthz ne doit jamais être délesté");

    assert_eq!(first.await.unwrap().status(), 200);
    // La place s'est libérée.
    assert_eq!(post(client).await.status(), 200);
}
