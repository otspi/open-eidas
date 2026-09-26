//! Vérifie la republication périodique de la CRL et la dégradation de
//! `/healthz` sur CRL périmée — cmd/ca-server/server_test.go (Go) testait ce
//! même comportement, resté sans équivalent Rust jusqu'ici (§6.3.10 de la
//! matrice de conformité). Requêtes envoyées en mémoire (`tower::ServiceExt::
//! oneshot`), sans lien réseau.

use std::sync::Arc;

use ca_server::http;
use http_body_util::BodyExt;
use oe_ca_core::ceremony::{run_ceremony, CeremonyOptions};
use oe_ca_core::{Issuer, Options as CaOptions};
use oe_castore::Memory;
use oe_hsm::testing::SoftwareToken;
use tower::ServiceExt;

async fn build_server(crl_validity: time::Duration) -> Arc<http::Server> {
    build_server_with(crl_validity, None).await
}

async fn build_server_with(
    crl_validity: time::Duration,
    guard: Option<Arc<oe_actions::RegistryGuard>>,
) -> Arc<http::Server> {
    let store = Arc::new(Memory::new());
    let root_signer = Arc::new(SoftwareToken::generate(3072));
    let issuing_signer = Arc::new(SoftwareToken::generate(3072));
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
        public_url: "https://ca.example.test".to_string(),
        recorder: None,
    })
    .await
    .unwrap();

    let issuer = Arc::new(
        Issuer::new(CaOptions {
            signer: issuing_signer,
            certificate: hierarchy.issuing,
            chain: vec![hierarchy.root],
            store: store.clone(),
            public_url: "https://ca.example.test".to_string(),
            ocsp_url: None,
            crl_validity,
            crl_grace: time::Duration::hours(1),
            recorder: None,
        })
        .unwrap(),
    );

    let flow = Arc::new(
        oe_raflow::Flow::new(oe_raflow::Options {
            store,
            issuer: issuer.clone(),
            hmac_secret: "test-secret".to_string(),
            recorder: None,
            retry_after: time::Duration::seconds(5),
            clock: None,
        })
        .unwrap(),
    );

    let mut server = http::Server::new(issuer, flow, "test-version".to_string());
    if let Some(guard) = guard {
        server = server.with_registry_guard(guard);
    }
    Arc::new(server)
}

async fn get(
    server: &Arc<http::Server>,
    path: &str,
) -> (axum::http::StatusCode, serde_json::Value) {
    let app = http::router(server.clone(), 64 * 1024);
    let request = axum::http::Request::builder()
        .uri(path)
        .body(axum::body::Body::empty())
        .unwrap();
    let response = app.oneshot(request).await.unwrap();
    let status = response.status();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json = serde_json::from_slice(&body).unwrap_or_else(|_| serde_json::json!({}));
    (status, json)
}

#[tokio::test]
async fn crl_is_republished_periodically() {
    let server = build_server(time::Duration::hours(24)).await;
    let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    server
        .start_crl_publication(std::time::Duration::from_millis(50), shutdown_rx)
        .await
        .expect("la publication initiale doit réussir");

    let (status, body) = get(&server, "/healthz").await;
    assert_eq!(status, axum::http::StatusCode::OK);
    let first_number = body["crl_numero"]
        .as_i64()
        .expect("crl_numero doit être présent");
    assert_eq!(first_number, 1);

    // Le cycle de republication tourne toutes les 50ms : après une pause
    // largement supérieure, le numéro doit avoir augmenté au moins une fois.
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;

    let (status, body) = get(&server, "/healthz").await;
    assert_eq!(status, axum::http::StatusCode::OK);
    let second_number = body["crl_numero"].as_i64().unwrap();
    assert!(
        second_number > first_number,
        "la CRL doit avoir été republiée au moins une fois (n°{first_number} -> n°{second_number})"
    );
}

#[tokio::test]
async fn healthz_degrades_when_the_published_crl_is_stale() {
    // Une durée de validité négative place next_update dans le passé dès la
    // première publication : pas besoin d'attendre une vraie péremption.
    let server = build_server(time::Duration::seconds(-1)).await;
    let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    server
        .start_crl_publication(std::time::Duration::from_secs(3600), shutdown_rx)
        .await
        .expect("la publication initiale doit réussir même avec une validité négative");

    let (status, body) = get(&server, "/healthz").await;
    assert_eq!(
        status,
        axum::http::StatusCode::SERVICE_UNAVAILABLE,
        "un service dont la CRL est périmée ne doit pas se déclarer sain"
    );
    assert_eq!(body["statut"], "degrade");
}

/// Le dépôt public (`GET /`) doit lister le sujet réel de chaque
/// certificat de la hiérarchie — c'est ce Subject, pas une mention codée
/// en dur dans le service, qui distingue un environnement de test d'une
/// production certifiée.
#[tokio::test]
async fn repository_page_lists_the_real_hierarchy() {
    let server = build_server(time::Duration::hours(24)).await;
    let app = http::router(server.clone(), 64 * 1024);
    let request = axum::http::Request::builder()
        .uri("/")
        .body(axum::body::Body::empty())
        .unwrap();
    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), axum::http::StatusCode::OK);
    assert_eq!(
        response.headers().get("content-type").unwrap(),
        "text/html; charset=utf-8"
    );
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let html = String::from_utf8(body.to_vec()).expect("la page doit être de l'UTF-8 valide");
    assert!(
        html.contains("Test Issuing CA"),
        "sujet de la CA émettrice absent"
    );
    assert!(
        html.contains("Test Root CA"),
        "sujet de la CA racine absent"
    );
    assert!(
        html.contains("/api/v1/ca.pem"),
        "lien de téléchargement absent"
    );
}

/// Un registre qui diverge du journal (docs/WEBUI.md §21) met le service en 503,
/// avec le détail, et le rétablit dès que la garde se rouvre.
#[tokio::test]
async fn healthz_degrades_while_the_registry_is_blocked() {
    let guard = oe_actions::RegistryGuard::new();
    let server = build_server_with(time::Duration::hours(24), Some(guard.clone())).await;
    let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    server
        .start_crl_publication(std::time::Duration::from_secs(3600), shutdown_rx)
        .await
        .unwrap();

    let (status, body) = get(&server, "/healthz").await;
    assert_eq!(status, axum::http::StatusCode::OK, "{body}");
    assert!(body["registre_bloque"].is_null());

    guard.block(vec![
        "la clé abc de bob est révoquée au journal mais active".to_string(),
    ]);
    let (status, body) = get(&server, "/healthz").await;
    assert_eq!(
        status,
        axum::http::StatusCode::SERVICE_UNAVAILABLE,
        "{body}"
    );
    assert_eq!(body["statut"], "degrade");
    assert!(body["detail"]
        .as_str()
        .unwrap()
        .contains("la clé abc de bob"));
    assert_eq!(
        body["registre_bloque"][0],
        "la clé abc de bob est révoquée au journal mais active"
    );

    guard.open();
    let (status, _) = get(&server, "/healthz").await;
    assert_eq!(status, axum::http::StatusCode::OK);
}
