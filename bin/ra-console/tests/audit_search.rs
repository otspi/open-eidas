//! `ra_console::audit_search::search` (docs/WEBUI.md §7, §15 étape 2b-D) :
//! relit et vérifie les deux journaux chaînés depuis S3, avant de répondre.
//! Contre un serveur HTTP qui se comporte comme un service S3-compatible
//! (même contrainte que `crates/oe-s3/tests/client.rs` : pas d'image MinIO
//! accessible dans cet environnement).
//!
//! Ce que ces tests prouvent : les deux journaux sont fusionnés et triés, le
//! filtre par série fonctionne, et surtout — un journal rompu ou illisible
//! **bloque tout l'affichage** (`chain_verified: false`, `results` vide)
//! plutôt que de montrer une moitié de la vérité à côté d'une alerte (§7).

use axum::extract::{Path, State};
use axum::http::{Method, StatusCode};
use axum::routing::any;
use axum::Router;
use ra_console::config::S3Config;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

#[derive(Default)]
struct Objects(Mutex<HashMap<String, Vec<u8>>>);

async fn handle(
    State(objects): State<Arc<Objects>>,
    method: Method,
    Path((bucket, key)): Path<(String, String)>,
    body: axum::body::Bytes,
) -> (StatusCode, Vec<u8>) {
    let full_key = format!("{bucket}/{key}");
    match method {
        Method::PUT => {
            objects.0.lock().unwrap().insert(full_key, body.to_vec());
            (StatusCode::OK, Vec::new())
        }
        Method::GET => match objects.0.lock().unwrap().get(&full_key) {
            Some(bytes) => (StatusCode::OK, bytes.clone()),
            None => (StatusCode::NOT_FOUND, Vec::new()),
        },
        _ => (StatusCode::METHOD_NOT_ALLOWED, Vec::new()),
    }
}

async fn serve(objects: Arc<Objects>) -> String {
    let app = Router::new()
        .route("/{bucket}/{*key}", any(handle))
        .with_state(objects);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    format!("http://{addr}")
}

fn s3_config(endpoint: String) -> S3Config {
    S3Config {
        endpoint,
        bucket: "audit".to_string(),
        region: "us-east-1".to_string(),
        access_key: "test".to_string(),
        secret_key: "test-secret-au-moins-16-octets".to_string(),
        key: "ra-console/audit.log".to_string(),
        ca_key: "ca-server/audit.log".to_string(),
    }
}

/// Écrit un journal chaîné valide (via `oe_audit::Log`) et rend ses octets.
fn write_journal(events: &[(&str, serde_json::Value)]) -> Vec<u8> {
    let path = std::env::temp_dir().join(format!(
        "ra-console-audit-search-test-{}-{}.log",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let log = oe_audit::Log::open(&path).unwrap();
    for (event, data) in events {
        let data = data
            .as_object()
            .map(|m| m.iter().map(|(k, v)| (k.clone(), v.clone())).collect());
        log.append(event, data).unwrap();
    }
    let bytes = std::fs::read(&path).unwrap();
    let _ = std::fs::remove_file(&path);
    bytes
}

async fn put(endpoint: &str, bucket_key: &str, bytes: Vec<u8>) {
    let client = oe_s3::Client::new(oe_s3::Options {
        endpoint: endpoint.to_string(),
        bucket: "audit".to_string(),
        region: "us-east-1".to_string(),
        access_key: "test".to_string(),
        secret_key: "test-secret-au-moins-16-octets".to_string(),
        timeout: std::time::Duration::from_secs(5),
    })
    .unwrap();
    client.put(bucket_key, bytes).await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn merges_and_sorts_both_journals() {
    let objects = Arc::new(Objects::default());
    let endpoint = serve(objects).await;

    let ca = write_journal(&[(
        "ca.certificate_issued",
        serde_json::json!({ "serie": "aabbcc" }),
    )]);
    let ra = write_journal(&[(
        "ra.login_succeeded",
        serde_json::json!({ "operateur": "alice" }),
    )]);
    put(&endpoint, "ca-server/audit.log", ca).await;
    put(&endpoint, "ra-console/audit.log", ra).await;

    let report = ra_console::audit_search::search(
        &s3_config(endpoint),
        &ra_console::audit_search::Query::default(),
    )
    .await
    .unwrap();

    assert!(report.chain_verified);
    assert_eq!(report.entries_checked, 2);
    assert_eq!(report.results.len(), 2);
    let sources: Vec<_> = report.results.iter().map(|e| e.source).collect();
    assert!(sources.contains(&ra_console::audit_search::Source::CaServer));
    assert!(sources.contains(&ra_console::audit_search::Source::RaConsole));
}

#[tokio::test(flavor = "multi_thread")]
async fn filters_by_serial() {
    let objects = Arc::new(Objects::default());
    let endpoint = serve(objects).await;

    let ca = write_journal(&[
        (
            "ca.certificate_issued",
            serde_json::json!({ "serie": "aabbcc" }),
        ),
        (
            "ca.certificate_issued",
            serde_json::json!({ "serie": "ddeeff" }),
        ),
    ]);
    let ra = write_journal(&[]);
    put(&endpoint, "ca-server/audit.log", ca).await;
    put(&endpoint, "ra-console/audit.log", ra).await;

    let report = ra_console::audit_search::search(
        &s3_config(endpoint),
        &ra_console::audit_search::Query {
            serial: Some("AABBCC".to_string()),
            ..Default::default()
        },
    )
    .await
    .unwrap();

    assert!(report.chain_verified);
    assert_eq!(report.entries_checked, 2, "les deux entrées sont relues");
    assert_eq!(report.results.len(), 1, "une seule correspond au filtre");
    assert_eq!(report.results[0].data.as_ref().unwrap()["serie"], "aabbcc");
}

/// La preuve décisive (docs/WEBUI.md §7) : un journal rompu ne doit **jamais**
/// se voir mélangé à des résultats par ailleurs valides. Testé par mutation
/// (voir le commit) : sans le blocage, ce test échoue.
#[tokio::test(flavor = "multi_thread")]
async fn a_broken_chain_blocks_the_entire_response() {
    let objects = Arc::new(Objects::default());
    let endpoint = serve(objects).await;

    let ca = write_journal(&[(
        "ca.certificate_issued",
        serde_json::json!({ "serie": "aabbcc" }),
    )]);
    let ra = write_journal(&[(
        "ra.login_succeeded",
        serde_json::json!({ "operateur": "alice" }),
    )]);
    // Corrompt le journal de ra-console : une chaîne rompue, comme une
    // altération malveillante ou une copie partielle sur S3.
    let mut corrupted = ra.clone();
    if let Some(byte) = corrupted.last_mut() {
        *byte ^= 0xFF;
    }
    put(&endpoint, "ca-server/audit.log", ca).await;
    put(&endpoint, "ra-console/audit.log", corrupted).await;

    let report = ra_console::audit_search::search(
        &s3_config(endpoint),
        &ra_console::audit_search::Query::default(),
    )
    .await
    .unwrap();

    assert!(
        !report.chain_verified,
        "un journal rompu ne doit jamais être déclaré vérifié"
    );
    assert!(
        report.results.is_empty(),
        "aucun résultat ne doit être montré quand une chaîne est rompue, même l'autre valide"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn an_unreachable_s3_is_reported_as_an_error_not_a_broken_chain() {
    // Aucun serveur : le port n'écoute pas.
    let endpoint = "http://127.0.0.1:1".to_string();
    let err = ra_console::audit_search::search(
        &s3_config(endpoint),
        &ra_console::audit_search::Query::default(),
    )
    .await
    .unwrap_err();
    assert!(matches!(err, ra_console::audit_search::Error::Fetch(_, _)));
}
