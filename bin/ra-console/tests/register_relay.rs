//! Le relais de l'enregistrement de clé (docs/WEBUI.md §5, §10) de bout en bout :
//! un navigateur factice → `ra-console` → le lien mTLS → le **vrai** routeur
//! interne de `ca-server`, sur un vrai PostgreSQL, avec un authentificateur
//! logiciel. La console ne lit ni n'interprète l'attestation : ce que le test
//! prouve, c'est que `ca-server` en décide, et que la console ne fuit ni jeton ni
//! détail interne.
//!
//! DSN dans `OE_CASTORE_TEST_DSN` ; test ignoré si elle n'est pas définie.

mod common;

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use common::{pki, tempdir::Dir, Pki};
use http_body_util::BodyExt;
use oe_actions::{bootstrap_admin, Registry, RegistryGuard, Service};
use oe_castore::{Postgres, Store};
use oe_raflow::{Decider, DeciderOptions, Recorder};
use oe_webauthn::{trusted_models, TrustedModel, Url, Verifier};
use ra_console::ca_link::CaLink;
use ra_console::http::{router, AppState};
use sqlx::postgres::PgPoolOptions;
use tower::ServiceExt;
use webauthn_authenticator_rs::softtoken::{SoftToken, AAGUID};
use webauthn_authenticator_rs::WebauthnAuthenticator;

struct NullJournal;
#[async_trait::async_trait]
impl Recorder for NullJournal {
    async fn append(&self, _: &str, _: serde_json::Value) -> Result<(), String> {
        Ok(())
    }
}

struct Env {
    console: axum::Router,
    registry: Registry,
    guard: Arc<RegistryGuard>,
    authn: WebauthnAuthenticator<SoftToken>,
    _dir: Dir,
    _pki: Pki,
}

fn origin() -> Url {
    Url::parse("https://console.example.com").unwrap()
}

impl Env {
    async fn new() -> Option<Env> {
        let base = std::env::var("OE_CASTORE_TEST_DSN").ok()?;
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let name = format!("rel_{nanos}");
        let admin = PgPoolOptions::new().connect(&base).await.unwrap();
        sqlx::query(&format!("CREATE DATABASE {name}"))
            .execute(&admin)
            .await
            .unwrap();
        let dsn = format!("{}/{name}", base.rsplit_once('/').unwrap().0);
        let store: Arc<dyn Store> = Arc::new(Postgres::open(&dsn).await.unwrap());
        let registry = Registry::connect(&dsn).await.unwrap();

        // Le vrai service d'actions de ca-server, derrière son vrai routeur interne.
        let (token, root) = SoftToken::new(true).unwrap();
        let root_pem = root.to_pem().unwrap();
        let verifier = Verifier::new(
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
        .unwrap();
        let journal: Arc<dyn Recorder> = Arc::new(NullJournal);
        let guard = RegistryGuard::new();
        let service = Arc::new(
            Service::new(
                registry.clone(),
                verifier,
                store.clone(),
                Decider::new(DeciderOptions {
                    store,
                    recorder: None,
                    clock: None,
                }),
                journal,
                Arc::new(time::OffsetDateTime::now_utc),
            )
            .with_guard(guard.clone()),
        );

        let pki = pki().await;
        let port = pki
            .serve_router(ca_server::internal::router(service, 64 * 1024))
            .await;
        let dir = Dir::new();
        let client = pki
            .cert(&oe_ca_core::profile::internal_client(), "ra-console")
            .await;
        let link = CaLink::new(&pki.files(&dir, &client, port)).unwrap();
        let pool = PgPoolOptions::new().connect(&dsn).await.unwrap();
        let console = router(Arc::new(AppState {
            pool: pool.clone(),
            link,
            login: common::login_service(pool.clone()),
            sessions: common::sessions(pool),
            s3: None,
        }));

        Some(Env {
            console,
            registry,
            guard,
            authn: WebauthnAuthenticator::new(token),
            _dir: dir,
            _pki: pki,
        })
    }

    async fn post(
        &self,
        path: &str,
        content_type: Option<&str>,
        body: Vec<u8>,
    ) -> (StatusCode, serde_json::Value) {
        let mut req = Request::post(path);
        if let Some(ct) = content_type {
            req = req.header("content-type", ct);
        }
        let res = self
            .console
            .clone()
            .oneshot(req.body(Body::from(body)).unwrap())
            .await
            .unwrap();
        let status = res.status();
        let bytes = res.into_body().collect().await.unwrap().to_bytes();
        (status, serde_json::from_slice(&bytes).unwrap_or_default())
    }

    async fn json(&self, path: &str, body: serde_json::Value) -> (StatusCode, serde_json::Value) {
        self.post(
            path,
            Some("application/json"),
            body.to_string().into_bytes(),
        )
        .await
    }

    /// Le jeton d'invitation d'un premier administrateur, comme au Jour 0.
    async fn invitation(&self, name: &str) -> String {
        bootstrap_admin(
            &self.registry,
            &NullJournal,
            name,
            time::Duration::minutes(15),
            time::OffsetDateTime::now_utc(),
        )
        .await
        .unwrap()
        .token
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

const BEGIN: &str = "/api/v1/webauthn/register/begin";
const FINISH: &str = "/api/v1/webauthn/register/finish";

#[tokio::test]
async fn an_invited_admin_registers_a_key_through_the_console() {
    let mut env = env!();
    let token = env.invitation("alice").await;

    let (status, begun) = env.json(BEGIN, serde_json::json!({ "token": token })).await;
    assert_eq!(status, StatusCode::OK, "{begun}");
    assert_eq!(begun["operator"], "alice");

    // Le navigateur passe les options à `navigator.credentials.create` : ici, le
    // SoftToken. La console n'a rien vu de l'attestation qu'elle va relayer.
    let options: oe_webauthn::CreationChallengeResponse =
        serde_json::from_value(serde_json::json!({ "publicKey": begun["webauthn"] })).unwrap();
    let credential = env.authn.do_registration(origin(), options).unwrap();

    let (status, done) = env
        .json(
            FINISH,
            serde_json::json!({ "ceremony_id": begun["ceremony_id"], "credential": credential }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{done}");
    assert_eq!(done["status"], "active");
    assert_eq!(done["operator"], "alice");
    assert!(done["key_fingerprint"].as_str().unwrap().len() > 30);

    // La clé est dans le registre : c'est ca-server qui l'y a rangée.
    let alice = env
        .registry
        .active_keys(
            sqlx::query_scalar::<_, oe_webauthn::Uuid>(
                "SELECT id FROM operators WHERE name = 'alice'",
            )
            .fetch_one(env.registry.pool())
            .await
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(alice.len(), 1);

    // Le jeton est consommé : ca-server refuse, la console relaie le refus, sans
    // jamais renvoyer le jeton.
    let (status, again) = env.json(BEGIN, serde_json::json!({ "token": token })).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{again}");
    assert_eq!(again["error"], "denied");
    assert!(!again.to_string().contains(&token));
}

#[tokio::test]
async fn the_console_only_relays_what_it_has_validated() {
    let env = env!();
    let token = env.invitation("alice").await;
    let ok_finish = serde_json::json!({
        "ceremony_id": "3f2b8c1e-9d4a-4e6b-8a7c-1234567890ab",
        "credential": {"id": "x"},
    });

    // Un navigateur qui n'annonce pas du JSON.
    for content_type in [
        None,
        Some("text/plain"),
        Some("application/x-www-form-urlencoded"),
    ] {
        let (status, body) = env
            .post(BEGIN, content_type, br#"{"token":"x"}"#.to_vec())
            .await;
        assert_eq!(
            status,
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "{content_type:?} {body}"
        );
    }

    // Des corps que la console refuse elle-même, sans déranger ca-server.
    for body in [
        serde_json::json!({}),
        serde_json::json!({"token": ""}),
        serde_json::json!({"token": "x".repeat(257)}),
        // Un champ qu'elle ne connaît pas n'est pas relayé.
        serde_json::json!({"token": token, "operator_name": "root"}),
    ] {
        let (status, err) = env.json(BEGIN, body.clone()).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body} {err}");
        assert_eq!(err["error"], "bad_request");
    }
    let (status, _) = env
        .post(BEGIN, Some("application/json"), b"pas du json".to_vec())
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    for body in [
        serde_json::json!({"ceremony_id": "pas-un-uuid", "credential": {"id": "x"}}),
        serde_json::json!({"ceremony_id": "3f2b8c1e-9d4a-4e6b-8a7c-1234567890ab", "credential": "texte"}),
        serde_json::json!({"ceremony_id": "3f2b8c1e-9d4a-4e6b-8a7c-1234567890ab", "credential": {}, "extra": 1}),
    ] {
        let (status, err) = env.json(FINISH, body.clone()).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body} {err}");
    }

    // Trop gros : refusé avant d'être lu.
    let (status, _) = env
        .post(
            FINISH,
            Some("application/json"),
            serde_json::json!({"ceremony_id": "x", "credential": {"pad": "x".repeat(70_000)}})
                .to_string()
                .into_bytes(),
        )
        .await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);

    // Et une requête conforme, mais sans cérémonie ouverte : c'est ca-server qui la
    // refuse (409, cérémonie perdue), et la console relaie son code.
    let (status, err) = env.json(FINISH, ok_finish).await;
    assert!(status.is_client_error(), "{status} {err}");
    assert!(err["error"].is_string());
}

#[tokio::test]
async fn an_unknown_token_gets_the_same_refusal_as_ca_server_gives() {
    let env = env!();
    let (status, err) = env
        .json(BEGIN, serde_json::json!({"token": "pas-un-jeton"}))
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{err}");
    assert_eq!(err["error"], "denied");
    assert!(!err.to_string().contains("pas-un-jeton"));
}

#[tokio::test]
async fn a_ca_server_failure_leaks_no_detail() {
    let env = env!();
    let token = env.invitation("alice").await;

    // ca-server ferme son registre (divergence du journal) : il répond 503 avec les
    // divergences. La console ne les répète pas à un navigateur anonyme.
    env.guard.block(vec![
        "la clé SECRETE-abc de bob est révoquée au journal".to_string()
    ]);
    let (status, err) = env.json(BEGIN, serde_json::json!({ "token": token })).await;
    assert_eq!(status, StatusCode::BAD_GATEWAY, "{err}");
    assert_eq!(err["error"], "ca_unavailable");
    assert!(!err.to_string().contains("SECRETE"), "{err}");
    assert!(!err.to_string().contains("bob"), "{err}");
}

/// Sans `ca-server` : le relais échoue proprement, sans rien révéler du réseau
/// interne. Ne demande aucune base (le pool est paresseux), donc s'exécute partout.
#[tokio::test]
async fn an_unreachable_ca_server_gives_a_generic_bad_gateway() {
    let pki = pki().await;
    let dir = Dir::new();
    let client = pki
        .cert(&oe_ca_core::profile::internal_client(), "ra-console")
        .await;
    let dead = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };
    let link = CaLink::new(&pki.files(&dir, &client, dead)).unwrap();
    let pool = PgPoolOptions::new()
        .connect_lazy("postgres://x@127.0.0.1:1/x")
        .unwrap();
    let console = router(Arc::new(AppState {
        pool: pool.clone(),
        link,
        login: common::login_service(pool.clone()),
        sessions: common::sessions(pool),
        s3: None,
    }));

    let res = console
        .oneshot(
            Request::post(BEGIN)
                .header("content-type", "application/json")
                .body(Body::from(r#"{"token":"un-jeton"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::BAD_GATEWAY);
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    let body = String::from_utf8_lossy(&bytes);
    assert!(body.contains("ca_unavailable"), "{body}");
    // Ni l'adresse, ni le port, ni la cause de la panne, ni le jeton.
    for leak in [
        "127.0.0.1",
        &dead.to_string(),
        "refused",
        "connect",
        "un-jeton",
    ] {
        assert!(!body.contains(leak), "fuite de {leak:?} : {body}");
    }
}
