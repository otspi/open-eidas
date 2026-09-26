//! `GET /api/v1/requests` (docs/WEBUI.md §5, §15 étape 2a) de bout en bout :
//! un vrai PostgreSQL, le vrai routeur HTTP de `ra-console`. Ce que le test
//! prouve : la route exige une session, lit `enrollment_requests` en lecture
//! seule, et filtre par état sans rien relayer à `ca-server`.
//!
//! DSN dans `OE_CASTORE_TEST_DSN` ; test ignoré si elle n'est pas définie.

mod common;

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use common::{pki, tempdir::Dir};
use http_body_util::BodyExt;
use oe_actions::{NewCredential, Registry, Role};
use oe_webauthn::{trusted_models, TrustedModel, Url, Verifier};
use ra_console::ca_link::CaLink;
use ra_console::http::{router, AppState};
use ra_console::login::LoginService;
use sqlx::postgres::PgPoolOptions;
use tower::ServiceExt;
use webauthn_authenticator_rs::softtoken::{SoftToken, AAGUID};
use webauthn_authenticator_rs::WebauthnAuthenticator;

fn origin() -> Url {
    Url::parse("https://console.example.com").unwrap()
}

struct Env {
    console: axum::Router,
    pool: sqlx::PgPool,
    registry: Registry,
    authn: WebauthnAuthenticator<SoftToken>,
    verifier: Verifier,
    _dir: Dir,
    _pki: common::Pki,
}

impl Env {
    async fn new() -> Option<Env> {
        let base = std::env::var("OE_CASTORE_TEST_DSN").ok()?;
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let name = format!("requests_{nanos}");
        let admin = PgPoolOptions::new().connect(&base).await.unwrap();
        sqlx::query(&format!("CREATE DATABASE {name}"))
            .execute(&admin)
            .await
            .unwrap();
        let dsn = format!("{}/{name}", base.rsplit_once('/').unwrap().0);
        let _ = oe_castore::Postgres::open(&dsn).await.unwrap();
        let registry = Registry::connect(&dsn).await.unwrap();

        let (token, root) = SoftToken::new(true).unwrap();
        let root_pem = root.to_pem().unwrap();
        let models = || {
            trusted_models(&[TrustedModel {
                root_pem: &root_pem,
                aaguid: AAGUID,
                description: "SoftToken (test)",
            }])
            .unwrap()
        };
        let verifier = Verifier::new("console.example.com", &origin(), "test", models()).unwrap();
        let login = LoginService::new(
            registry.clone(),
            Verifier::new("console.example.com", &origin(), "test", models()).unwrap(),
            b"secret-de-test-au-moins-16-octets".to_vec(),
            Arc::new(ra_console::audit::NullRecorder),
        );

        let pool = PgPoolOptions::new().connect(&dsn).await.unwrap();
        let ca_pki = pki().await;
        let dir = Dir::new();
        let client = ca_pki
            .cert(&oe_ca_core::profile::internal_client(), "ra-console")
            .await;
        let dead = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let link = CaLink::new(&ca_pki.files(&dir, &client, dead)).unwrap();

        let console = router(Arc::new(AppState {
            sessions: common::sessions(pool.clone()),
            pool: pool.clone(),
            link,
            login,
            s3: None,
        }));
        Some(Env {
            console,
            pool,
            registry,
            authn: WebauthnAuthenticator::new(token),
            verifier,
            _dir: dir,
            _pki: ca_pki,
        })
    }

    async fn get_with_cookie(
        &self,
        path: &str,
        cookie: Option<&str>,
    ) -> (StatusCode, serde_json::Value) {
        let mut req = Request::get(path);
        if let Some(c) = cookie {
            req = req.header("cookie", c);
        }
        let res = self
            .console
            .clone()
            .oneshot(req.body(Body::empty()).unwrap())
            .await
            .unwrap();
        let status = res.status();
        let bytes = res.into_body().collect().await.unwrap().to_bytes();
        (status, serde_json::from_slice(&bytes).unwrap_or_default())
    }

    async fn operator_with_key(&mut self, name: &str) -> oe_webauthn::Uuid {
        let now = time::OffsetDateTime::now_utc();
        let id = self
            .registry
            .add_operator(name, Role::Auditeur, "test", now)
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
                    attestation_format: "packed",
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

    /// Connexion complète, rend le cookie de session posé par `Set-Cookie`.
    async fn log_in(&mut self, name: &str) -> String {
        let mut req = Request::post("/api/v1/webauthn/login/begin")
            .header("content-type", "application/json");
        let body = serde_json::json!({"name": name}).to_string();
        let res = self
            .console
            .clone()
            .oneshot(req.body(Body::from(body)).unwrap())
            .await
            .unwrap();
        let bytes = res.into_body().collect().await.unwrap().to_bytes();
        let begun: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let options: oe_webauthn::RequestChallengeResponse =
            serde_json::from_value(serde_json::json!({ "publicKey": begun["webauthn"] })).unwrap();
        let assertion = self.authn.do_authentication(origin(), options).unwrap();
        req = Request::post("/api/v1/webauthn/login/finish")
            .header("content-type", "application/json");
        let body = serde_json::json!({
            "challenge_id": begun["challenge_id"],
            "credential": assertion,
        })
        .to_string();
        let res = self
            .console
            .clone()
            .oneshot(req.body(Body::from(body)).unwrap())
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let set_cookie = res
            .headers()
            .get(axum::http::header::SET_COOKIE)
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        set_cookie.split(';').next().unwrap().to_string()
    }

    async fn insert_request(&self, transaction_id: &str, state: &str, subject_cn: &str) {
        let now = time::OffsetDateTime::now_utc();
        let (operator, decided_at) = if state == "PENDING" {
            (String::new(), None)
        } else {
            ("bob".to_string(), Some(now))
        };
        sqlx::query(
            "INSERT INTO enrollment_requests
               (transaction_id, csr_fingerprint, csr_der, profile, subject_cn,
                state, created_at, decided_at, operator)
             VALUES ($1, $1, '\\x00', 'tsa_signer', $2, $3, $4, $5, $6)",
        )
        .bind(transaction_id)
        .bind(subject_cn)
        .bind(state)
        .bind(now)
        .bind(decided_at)
        .bind(&operator)
        .execute(&self.pool)
        .await
        .unwrap();
    }
}

macro_rules! env {
    () => {
        match Env::new().await {
            Some(e) => e,
            None => {
                eprintln!("OE_CASTORE_TEST_DSN non définie : test PostgreSQL ignoré");
                return;
            }
        }
    };
}

#[tokio::test]
async fn unauthenticated_requests_are_refused() {
    let env = env!();
    let (status, err) = env.get_with_cookie("/api/v1/requests", None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{err}");
    assert_eq!(err["error"], "unauthenticated");
}

#[tokio::test]
async fn an_authenticated_operator_lists_and_filters_requests() {
    let mut env = env!();
    env.operator_with_key("alice").await;
    env.insert_request("t-pending", "PENDING", "tsu.example.test")
        .await;
    env.insert_request("t-issued", "ISSUED", "autre.example.test")
        .await;
    let cookie = env.log_in("alice").await;

    let (status, all) = env.get_with_cookie("/api/v1/requests", Some(&cookie)).await;
    assert_eq!(status, StatusCode::OK, "{all}");
    assert_eq!(all.as_array().unwrap().len(), 2);

    let (status, pending) = env
        .get_with_cookie("/api/v1/requests?state=PENDING", Some(&cookie))
        .await;
    assert_eq!(status, StatusCode::OK, "{pending}");
    let pending = pending.as_array().unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0]["transaction_id"], "t-pending");
    assert_eq!(pending[0]["state"], "PENDING");
    assert!(pending[0]["operator"].is_null(), "{pending:?}");

    let (status, issued) = env
        .get_with_cookie("/api/v1/requests?state=ISSUED", Some(&cookie))
        .await;
    let issued = issued.as_array().unwrap();
    assert_eq!(issued.len(), 1);
    assert_eq!(issued[0]["operator"], "bob");
    assert_eq!(status, StatusCode::OK);

    let (status, err) = env
        .get_with_cookie("/api/v1/requests?state=PAS_UN_ETAT", Some(&cookie))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{err}");
    assert_eq!(err["error"], "bad_request");
}
