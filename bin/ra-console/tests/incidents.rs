//! Dossiers d'incident (docs/WEBUI.md §6, §15 étape 5a) de bout en bout : un
//! vrai PostgreSQL, le vrai routeur HTTP de `ra-console`. Ce que les tests
//! prouvent : la console juge elle-même du rôle de qui ouvre un dossier
//! (`ca-server` n'en voit rien passer), le dossier porte le nom de l'opérateur
//! de la session, et il n'existe pas sans sa trace au journal.
//!
//! DSN dans `OE_CASTORE_TEST_DSN` ; test ignoré si elle n'est pas définie.

mod common;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use axum::body::Body;
use axum::http::{Request, StatusCode};
use common::{pki, tempdir::Dir};
use http_body_util::BodyExt;
use oe_actions::{NewCredential, Registry, Role};
use oe_webauthn::{trusted_models, TrustedModel, Url, Verifier};
use ra_console::audit::{JournalError, Recorder};
use ra_console::ca_link::CaLink;
use ra_console::http::{router, AppState};
use ra_console::login::LoginService;
use sqlx::postgres::PgPoolOptions;
use tower::ServiceExt;
use webauthn_authenticator_rs::softtoken::{SoftToken, AAGUID};
use webauthn_authenticator_rs::WebauthnAuthenticator;

const INCIDENTS: &str = "/api/v1/incidents";

fn origin() -> Url {
    Url::parse("https://console.example.com").unwrap()
}

/// Le journal de la console, relu par les tests, et qu'on peut mettre en
/// panne : une écriture bloquante ([`Recorder::record`]) échoue alors.
#[derive(Default)]
struct Journal {
    entries: Mutex<Vec<(String, serde_json::Value)>>,
    broken: AtomicBool,
}

impl Journal {
    fn events(&self, event: &str) -> Vec<serde_json::Value> {
        self.entries
            .lock()
            .unwrap()
            .iter()
            .filter(|(e, _)| e == event)
            .map(|(_, d)| d.clone())
            .collect()
    }
}

impl Recorder for Journal {
    fn append(&self, event: &str, data: serde_json::Value) {
        let _ = self.record(event, data);
    }

    fn record(&self, event: &str, data: serde_json::Value) -> Result<(), JournalError> {
        if self.broken.load(Ordering::SeqCst) {
            return Err(JournalError("disque plein (test)".into()));
        }
        self.entries.lock().unwrap().push((event.to_string(), data));
        Ok(())
    }
}

struct Env {
    console: axum::Router,
    pool: sqlx::PgPool,
    registry: Registry,
    journal: Arc<Journal>,
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
        let name = format!("incidents_{nanos}_{}_{}", std::process::id(), {
            static SEQ: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
            SEQ.fetch_add(1, Ordering::Relaxed)
        });
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

        let journal = Arc::new(Journal::default());
        let console = router(Arc::new(AppState {
            sessions: common::sessions(pool.clone()),
            pool: pool.clone(),
            link,
            login,
            journal: journal.clone(),
            s3: None,
        }));
        Some(Env {
            console,
            pool,
            registry,
            journal,
            authn: WebauthnAuthenticator::new(token),
            verifier,
            _dir: dir,
            _pki: ca_pki,
        })
    }

    async fn send(&self, req: Request<Body>) -> (StatusCode, serde_json::Value) {
        let res = self.console.clone().oneshot(req).await.unwrap();
        let status = res.status();
        let bytes = res.into_body().collect().await.unwrap().to_bytes();
        (status, serde_json::from_slice(&bytes).unwrap_or_default())
    }

    async fn get(&self, path: &str, cookie: Option<&str>) -> (StatusCode, serde_json::Value) {
        let mut req = Request::get(path);
        if let Some(c) = cookie {
            req = req.header("cookie", c);
        }
        self.send(req.body(Body::empty()).unwrap()).await
    }

    async fn post(
        &self,
        path: &str,
        cookie: Option<&str>,
        body: serde_json::Value,
    ) -> (StatusCode, serde_json::Value) {
        let mut req = Request::post(path).header("content-type", "application/json");
        if let Some(c) = cookie {
            req = req.header("cookie", c);
        }
        self.send(req.body(Body::from(body.to_string())).unwrap())
            .await
    }

    async fn open(&self, cookie: &str, title: &str) -> (StatusCode, serde_json::Value) {
        self.post(
            INCIDENTS,
            Some(cookie),
            serde_json::json!({ "title": title }),
        )
        .await
    }

    async fn stored(&self) -> i64 {
        sqlx::query_scalar("SELECT count(*) FROM incidents")
            .fetch_one(&self.pool)
            .await
            .unwrap()
    }

    /// Un opérateur du rôle donné, sa clé, et sa session ouverte : rend le
    /// cookie posé par `Set-Cookie`.
    async fn session(&mut self, name: &str, role: Role) -> String {
        let now = time::OffsetDateTime::now_utc();
        let id = self
            .registry
            .add_operator(name, role, "test", now)
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

        let (_, begun) = self
            .post(
                "/api/v1/webauthn/login/begin",
                None,
                serde_json::json!({ "name": name }),
            )
            .await;
        let options: oe_webauthn::RequestChallengeResponse =
            serde_json::from_value(serde_json::json!({ "publicKey": begun["webauthn"] })).unwrap();
        let assertion = self.authn.do_authentication(origin(), options).unwrap();
        let req = Request::post("/api/v1/webauthn/login/finish")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::json!({
                    "challenge_id": begun["challenge_id"],
                    "credential": assertion,
                })
                .to_string(),
            ))
            .unwrap();
        let res = self.console.clone().oneshot(req).await.unwrap();
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
async fn without_a_session_nothing_is_read_or_written() {
    let env = env!();
    let (status, err) = env
        .post(
            INCIDENTS,
            None,
            serde_json::json!({ "title": "sans session" }),
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{err}");
    assert_eq!(err["error"], "unauthenticated");
    assert_eq!(env.stored().await, 0);

    for path in [
        INCIDENTS.to_string(),
        format!("{INCIDENTS}/{}", oe_webauthn::Uuid::new_v4()),
    ] {
        let (status, err) = env.get(&path, None).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{path} : {err}");
    }
}

/// `ca-server` ne voit rien passer : c'est la console qui refuse. Un auditeur
/// et un administrateur ont une session parfaitement valide ; seul leur rôle
/// les écarte, et rien n'est écrit, ni en base ni au journal.
#[tokio::test]
async fn only_ra_and_ca_operators_open_an_incident() {
    let mut env = env!();
    for (name, role) in [("audrey", Role::Auditeur), ("adam", Role::Admin)] {
        let cookie = env.session(name, role).await;
        let (status, err) = env.open(&cookie, "tentative").await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{name} : {err}");
        assert_eq!(err["error"], "forbidden");
    }
    assert_eq!(env.stored().await, 0);
    assert!(env.journal.events("ra.incident_opened").is_empty());

    for (name, role) in [("rachel", Role::RaOperateur), ("carl", Role::CaOperateur)] {
        let cookie = env.session(name, role).await;
        let (status, opened) = env.open(&cookie, "clé TSU suspecte").await;
        assert_eq!(status, StatusCode::CREATED, "{name} : {opened}");
        assert_eq!(opened["opened_by"], name);
    }
    assert_eq!(env.stored().await, 2);
}

#[tokio::test]
async fn an_incident_is_opened_in_the_name_of_the_session_and_read_back() {
    let mut env = env!();
    let cookie = env.session("rachel", Role::RaOperateur).await;

    let (status, opened) = env.open(&cookie, "  Signalement CERT-FR 2026-991  ").await;
    assert_eq!(status, StatusCode::CREATED, "{opened}");
    assert_eq!(opened["title"], "Signalement CERT-FR 2026-991");
    assert_eq!(opened["state"], "OUVERT");
    assert_eq!(opened["opened_by"], "rachel");
    assert!(opened["closed_by"].is_null(), "{opened}");
    assert!(opened["closed_at"].is_null(), "{opened}");
    assert!(opened["closing_note"].is_null(), "{opened}");
    let id = opened["id"].as_str().unwrap().to_string();

    // Le nom de qui ouvre ne se choisit pas : un champ en trop est refusé.
    let (status, err) = env
        .post(
            INCIDENTS,
            Some(&cookie),
            serde_json::json!({ "title": "usurpation", "opened_by": "carl" }),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{err}");
    assert_eq!(env.stored().await, 1);

    // Relu par un auditeur : la lecture n'exige que la session.
    let reader = env.session("audrey", Role::Auditeur).await;
    let (status, one) = env.get(&format!("{INCIDENTS}/{id}"), Some(&reader)).await;
    assert_eq!(status, StatusCode::OK, "{one}");
    assert_eq!(one, opened);

    let (status, all) = env.get(INCIDENTS, Some(&reader)).await;
    assert_eq!(status, StatusCode::OK, "{all}");
    assert_eq!(all.as_array().unwrap().len(), 1);
    assert_eq!(all[0]["id"], id.as_str());

    let (_, open) = env
        .get(&format!("{INCIDENTS}?state=OUVERT"), Some(&reader))
        .await;
    assert_eq!(open.as_array().unwrap().len(), 1);
    let (_, closed) = env
        .get(&format!("{INCIDENTS}?state=CLOS"), Some(&reader))
        .await;
    assert!(closed.as_array().unwrap().is_empty(), "{closed}");

    let (status, err) = env
        .get(&format!("{INCIDENTS}?state=PAS_UN_ETAT"), Some(&reader))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{err}");

    for unknown in [
        format!("{INCIDENTS}/{}", oe_webauthn::Uuid::new_v4()),
        format!("{INCIDENTS}/pas-un-identifiant"),
    ] {
        let (status, err) = env.get(&unknown, Some(&reader)).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{unknown} : {err}");
        assert_eq!(err["error"], "unknown_incident");
    }
}

#[tokio::test]
async fn the_most_recent_incident_comes_first() {
    let mut env = env!();
    let cookie = env.session("rachel", Role::RaOperateur).await;
    for title in ["premier", "deuxième", "troisième"] {
        let (status, _) = env.open(&cookie, title).await;
        assert_eq!(status, StatusCode::CREATED);
    }
    let (_, all) = env.get(INCIDENTS, Some(&cookie)).await;
    let titles: Vec<&str> = all
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i["title"].as_str().unwrap())
        .collect();
    assert_eq!(titles, ["troisième", "deuxième", "premier"]);
}

#[tokio::test]
async fn a_title_is_required_bounded_and_printable() {
    let mut env = env!();
    let cookie = env.session("rachel", Role::RaOperateur).await;
    let too_long = "x".repeat(ra_console::incidents::MAX_TITLE_CHARS + 1);
    for title in ["", "   ", "ligne\ncoupée", too_long.as_str()] {
        let (status, err) = env.open(&cookie, title).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{title:?} : {err}");
        assert_eq!(err["error"], "bad_request");
    }
    assert_eq!(env.stored().await, 0);
    assert!(env.journal.events("ra.incident_opened").is_empty());

    let longest = "é".repeat(ra_console::incidents::MAX_TITLE_CHARS);
    let (status, opened) = env.open(&cookie, &longest).await;
    assert_eq!(status, StatusCode::CREATED, "{opened}");
}

/// Le journal d'abord : chaque dossier y est consigné avec son identifiant, et
/// un journal en panne empêche l'ouverture — aucun dossier sans trace.
#[tokio::test]
async fn no_incident_exists_without_its_journal_entry() {
    let mut env = env!();
    let cookie = env.session("rachel", Role::RaOperateur).await;

    let (status, opened) = env.open(&cookie, "clé TSU suspecte").await;
    assert_eq!(status, StatusCode::CREATED, "{opened}");
    let events = env.journal.events("ra.incident_opened");
    assert_eq!(events.len(), 1, "{events:?}");
    assert_eq!(events[0]["incident_id"], opened["id"]);
    assert_eq!(events[0]["title"], "clé TSU suspecte");
    assert_eq!(events[0]["operator"], "rachel");

    env.journal.broken.store(true, Ordering::SeqCst);
    let (status, err) = env.open(&cookie, "pendant la panne").await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{err}");
    assert_eq!(err["error"], "unavailable");
    assert_eq!(env.stored().await, 1, "un dossier a été écrit sans trace");

    env.journal.broken.store(false, Ordering::SeqCst);
    let (status, _) = env.open(&cookie, "après la panne").await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(env.stored().await, 2);
    assert_eq!(env.journal.events("ra.incident_opened").len(), 2);
}
