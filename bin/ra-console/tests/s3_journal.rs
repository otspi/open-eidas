//! Copie best-effort du journal de `ra-console` sur un stockage S3-compatible
//! auto-hébergé (docs/WEBUI.md §7, §15 étape 2b-C) : contre un serveur HTTP
//! qui se comporte comme un service S3-compatible (même contrainte que
//! `crates/oe-s3/tests/client.rs` : pas d'image MinIO accessible dans cet
//! environnement).
//!
//! Ce qui distingue ce journal de celui de `ca-server` : un échec, local ou
//! S3, ne doit **jamais** se voir de l'appelant — `Recorder::append` ne rend
//! rien, à la différence des `Recorder` async/bloquants du reste du dépôt
//! (décision déjà prise, `bin/ra-console/src/audit.rs`). L'envoi S3 est donc
//! testé pour ce qu'il est : une copie qui arrive quand tout va bien, sans
//! jamais bloquer ni faire paniquer quand le service S3 est en panne.

use axum::extract::{Path, State};
use axum::http::{Method, StatusCode};
use axum::routing::any;
use axum::Router;
use ra_console::audit::AuditRecorder;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[derive(Default)]
struct Objects(Mutex<HashMap<String, Vec<u8>>>);

async fn handle_ok(
    State(objects): State<Arc<Objects>>,
    method: Method,
    Path((bucket, key)): Path<(String, String)>,
    body: axum::body::Bytes,
) -> StatusCode {
    if method == Method::PUT {
        objects
            .0
            .lock()
            .unwrap()
            .insert(format!("{bucket}/{key}"), body.to_vec());
    }
    StatusCode::OK
}

async fn handle_failing() -> StatusCode {
    StatusCode::INTERNAL_SERVER_ERROR
}

async fn serve(app: Router) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    format!("http://{addr}")
}

fn s3_client(endpoint: String) -> Arc<oe_s3::Client> {
    Arc::new(
        oe_s3::Client::new(oe_s3::Options {
            endpoint,
            bucket: "audit".to_string(),
            region: "us-east-1".to_string(),
            access_key: "test".to_string(),
            secret_key: "test-secret-au-moins-16-octets".to_string(),
            timeout: Duration::from_secs(5),
        })
        .unwrap(),
    )
}

/// Laisse le temps à la tâche détachée (`tokio::spawn` dans `append`) de
/// s'exécuter : `append` rend la main avant que l'envoi S3 ne soit terminé,
/// par construction (best-effort, non bloquant).
async fn settle() {
    tokio::time::sleep(Duration::from_millis(200)).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_configured_s3_eventually_receives_a_copy_of_the_local_journal() {
    let objects = Arc::new(Objects::default());
    let app = Router::new()
        .route("/{bucket}/{*key}", any(handle_ok))
        .with_state(objects.clone());
    let endpoint = serve(app).await;

    let dir = std::env::temp_dir().join(format!(
        "ra-console-s3-ok-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let audit_file = dir.join("audit.log");

    let log = Arc::new(oe_audit::Log::open(&audit_file).unwrap());
    let recorder = AuditRecorder::new(
        log,
        audit_file.to_string_lossy().into_owned(),
        Some((s3_client(endpoint), "ra-console/audit.log".to_string())),
    );

    ra_console::audit::Recorder::append(
        &recorder,
        "ra.login_succeeded",
        serde_json::json!({ "operateur": "alice" }),
    );
    settle().await;

    let local = std::fs::read(&audit_file).unwrap();
    let remote = objects
        .0
        .lock()
        .unwrap()
        .get("audit/ra-console/audit.log")
        .cloned()
        .expect("le journal a été envoyé à S3");
    assert_eq!(
        local, remote,
        "le contenu envoyé à S3 doit être une copie exacte du journal local"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_failing_s3_does_not_stop_the_journal_from_being_usable() {
    let app = Router::new().route("/{*path}", any(handle_failing));
    let endpoint = serve(app).await;

    let dir = std::env::temp_dir().join(format!(
        "ra-console-s3-ko-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let audit_file = dir.join("audit.log");

    let log = Arc::new(oe_audit::Log::open(&audit_file).unwrap());
    let recorder = AuditRecorder::new(
        log,
        audit_file.to_string_lossy().into_owned(),
        Some((s3_client(endpoint), "ra-console/audit.log".to_string())),
    );

    // `append` ne rend rien : un service S3 en panne ne doit ni bloquer ni
    // faire paniquer l'appelant (décision déjà prise pour ce journal).
    ra_console::audit::Recorder::append(
        &recorder,
        "ra.login_succeeded",
        serde_json::json!({ "operateur": "bob" }),
    );
    settle().await;

    let local = std::fs::read_to_string(&audit_file).unwrap();
    assert!(
        local.contains("ra.login_succeeded"),
        "l'échec de S3 ne doit pas empêcher l'écriture locale : {local}"
    );
}
