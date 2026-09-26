//! Le frontend embarqué et les en-têtes de sécurité (docs/UI-UX.md §6.3, §7),
//! vérifiés sans navigateur : chaque réponse de l'application complète — API
//! comprise — porte la CSP stricte et les protections contre l'intégration en
//! cadre, et les assets servis sont bien ceux de `web/dist`. Les parcours dans
//! un vrai navigateur sont dans `web/e2e` (Playwright).
//!
//! DSN dans `OE_CASTORE_TEST_DSN` ; test ignoré si elle n'est pas définie
//! (l'`AppState` exige un pool PostgreSQL).

mod common;

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use common::{pki, tempdir::Dir};
use http_body_util::BodyExt;
use ra_console::ca_link::CaLink;
use ra_console::http::{app, AppState};
use ra_console::web::{Console, Environment, CONTENT_SECURITY_POLICY};
use sqlx::postgres::PgPoolOptions;
use tower::ServiceExt;

async fn console(environment: Environment) -> Option<axum::Router> {
    let dsn = std::env::var("OE_CASTORE_TEST_DSN").ok()?;
    let pool = PgPoolOptions::new().connect_lazy(&dsn).unwrap();
    let ca = pki().await;
    let dir = Box::leak(Box::new(Dir::new()));
    let client = ca
        .cert(&oe_ca_core::profile::internal_client(), "ra-console")
        .await;
    let link = CaLink::new(&ca.files(dir, &client, 9)).unwrap();
    Some(app(
        Arc::new(AppState {
            pool: pool.clone(),
            link,
            login: common::login_service(pool.clone()),
            sessions: common::sessions(pool),
            journal: Arc::new(ra_console::audit::NullRecorder),
            s3: None,
        }),
        Console { environment },
    ))
}

async fn get(app: &axum::Router, path: &str) -> (StatusCode, axum::http::HeaderMap, Vec<u8>) {
    let res = app
        .clone()
        .oneshot(Request::get(path).body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = res.status();
    let headers = res.headers().clone();
    let body = res.into_body().collect().await.unwrap().to_bytes().to_vec();
    (status, headers, body)
}

#[tokio::test]
async fn every_response_carries_the_security_headers() {
    let Some(app) = console(Environment::Production).await else {
        eprintln!("OE_CASTORE_TEST_DSN non définie : test ignoré");
        return;
    };
    // Des assets, une route anonyme, une route refusée sans session : toutes.
    for path in [
        "/",
        "/assets/console.js",
        "/assets/console.css",
        "/api/v1/console",
        "/api/v1/me",
    ] {
        let (_, headers, _) = get(&app, path).await;
        let header = |name: &str| {
            headers
                .get(name)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
        };
        assert_eq!(
            header("content-security-policy"),
            CONTENT_SECURITY_POLICY,
            "{path}"
        );
        assert_eq!(header("x-frame-options"), "DENY", "{path}");
        assert_eq!(header("x-content-type-options"), "nosniff", "{path}");
        assert_eq!(header("referrer-policy"), "no-referrer", "{path}");
        assert_eq!(header("cache-control"), "no-store", "{path}");
    }
    // La politique elle-même : ni `unsafe-inline`, ni `unsafe-eval`, ni cadre.
    assert!(!CONTENT_SECURITY_POLICY.contains("unsafe"));
    assert!(CONTENT_SECURITY_POLICY.contains("frame-ancestors 'none'"));
}

#[tokio::test]
async fn the_embedded_assets_are_served_with_their_types() {
    let Some(app) = console(Environment::Production).await else {
        eprintln!("OE_CASTORE_TEST_DSN non définie : test ignoré");
        return;
    };
    let (status, headers, html) = get(&app, "/").await;
    assert_eq!(status, StatusCode::OK);
    assert!(headers["content-type"]
        .to_str()
        .unwrap()
        .starts_with("text/html"));
    let html = String::from_utf8(html).unwrap();
    assert!(html.contains(r#"<script type="module" src="/assets/console.js">"#));
    assert!(!html.contains("style="), "aucun style en ligne");

    let (status, headers, js) = get(&app, "/assets/console.js").await;
    assert_eq!(status, StatusCode::OK);
    assert!(headers["content-type"]
        .to_str()
        .unwrap()
        .starts_with("text/javascript"));
    assert_eq!(js, std::fs::read("web/dist/console.js").unwrap());

    let (_, headers, _) = get(&app, "/assets/console.css").await;
    assert!(headers["content-type"]
        .to_str()
        .unwrap()
        .starts_with("text/css"));
}

#[tokio::test]
async fn the_declared_environment_is_announced_before_login() {
    let Some(app) = console(Environment::Production).await else {
        eprintln!("OE_CASTORE_TEST_DSN non définie : test ignoré");
        return;
    };
    let (status, _, body) = get(&app, "/api/v1/console").await;
    assert_eq!(status, StatusCode::OK);
    let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(body["environment"], "production");

    assert_eq!(Environment::parse("").unwrap(), Environment::Undeclared);
    assert_eq!(Environment::parse("staging").unwrap(), Environment::Staging);
    assert!(
        Environment::parse("prod").is_err(),
        "une valeur inconnue est refusée"
    );
}
