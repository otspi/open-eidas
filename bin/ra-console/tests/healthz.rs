//! `/healthz` (docs/WEBUI.md §16) : sain seulement si la base répond ET si le lien
//! vers `ca-server` fonctionne. Vrai PostgreSQL, vrai serveur TLS.
//!
//! DSN dans `OE_CASTORE_TEST_DSN` ; test ignoré si elle n'est pas définie.

mod common;

use common::{pki, tempdir::Dir};
use http_body_util::BodyExt;
use oe_ca_core::profile;
use ra_console::ca_link::CaLink;
use ra_console::http::{router, AppState};
use sqlx::postgres::PgPoolOptions;
use std::sync::Arc;
use tower::ServiceExt;

async fn get(app: &axum::Router) -> (axum::http::StatusCode, serde_json::Value) {
    let res = app
        .clone()
        .oneshot(
            axum::http::Request::builder()
                .uri("/healthz")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = res.status();
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    (status, serde_json::from_slice(&bytes).unwrap())
}

#[tokio::test]
async fn healthz_needs_both_the_database_and_the_link() {
    let Ok(dsn) = std::env::var("OE_CASTORE_TEST_DSN") else {
        eprintln!("OE_CASTORE_TEST_DSN non définie : test PostgreSQL ignoré");
        return;
    };
    let pool = PgPoolOptions::new().connect(&dsn).await.unwrap();
    let pki = pki().await;
    let dir = Dir::new();
    let client = pki.cert(&profile::internal_client(), "ra-console").await;

    // Lien et base en état : sain.
    let port = pki.serve().await;
    let link = CaLink::new(&pki.files(&dir, &client, port)).unwrap();
    let app = router(Arc::new(AppState {
        pool: pool.clone(),
        link,
        login: common::login_service(pool.clone()),
        sessions: common::sessions(pool.clone()),
        s3: None,
    }));
    let (status, body) = get(&app).await;
    assert_eq!(status, axum::http::StatusCode::OK, "{body}");
    assert_eq!(body["base"], "ok");
    assert_eq!(body["lien_ca"], "ok");
    assert!(body["certificat_client_expire_le"].is_string());

    // ca-server injoignable : dégradé, avec la raison, sans exposer autre chose.
    let dead = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };
    let link = CaLink::new(&pki.files(&dir, &client, dead)).unwrap();
    let app = router(Arc::new(AppState {
        pool: pool.clone(),
        link,
        login: common::login_service(pool.clone()),
        sessions: common::sessions(pool),
        s3: None,
    }));
    let (status, body) = get(&app).await;
    assert_eq!(
        status,
        axum::http::StatusCode::SERVICE_UNAVAILABLE,
        "{body}"
    );
    assert_eq!(body["statut"], "degrade");
    assert_eq!(body["base"], "ok");
    assert!(
        body["lien_ca"].as_str().unwrap().starts_with("ko"),
        "{body}"
    );
}
