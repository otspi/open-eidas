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
        let journal = Arc::new(Journal::default());
        let login = LoginService::new(
            registry.clone(),
            Verifier::new("console.example.com", &origin(), "test", models()).unwrap(),
            b"secret-de-test-au-moins-16-octets".to_vec(),
            journal.clone(),
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

    /// Ouvre un dossier et rend son identifiant.
    async fn opened(&self, cookie: &str, title: &str) -> String {
        let (status, opened) = self.open(cookie, title).await;
        assert_eq!(status, StatusCode::CREATED, "{opened}");
        opened["id"].as_str().unwrap().to_string()
    }

    async fn add(
        &self,
        cookie: &str,
        incident: &str,
        entry: serde_json::Value,
    ) -> (StatusCode, serde_json::Value) {
        self.post(
            &format!("{INCIDENTS}/{incident}/actions"),
            Some(cookie),
            entry,
        )
        .await
    }

    async fn detail(&self, cookie: &str, incident: &str) -> serde_json::Value {
        let (status, detail) = self
            .get(&format!("{INCIDENTS}/{incident}"), Some(cookie))
            .await;
        assert_eq!(status, StatusCode::OK, "{detail}");
        detail
    }

    /// Une action figée telle que `ca-server` en range : rend son identifiant
    /// et l'empreinte de son corps.
    async fn frozen_action(&self, action: &str) -> (String, String) {
        let row = sqlx::query(
            "INSERT INTO actions (id, body, body_hash, created_at, expires_at)
             VALUES (gen_random_uuid(), jsonb_build_object('action', $1::text),
                     sha256(convert_to($1, 'UTF8')), now(), now() + interval '1 day')
             RETURNING id::text AS id, encode(body_hash, 'hex') AS hash",
        )
        .bind(action)
        .fetch_one(&self.pool)
        .await
        .unwrap();
        (sqlx::Row::get(&row, "id"), sqlx::Row::get(&row, "hash"))
    }

    /// Demande le challenge de clôture d'un dossier.
    async fn close_challenge(
        &self,
        cookie: &str,
        incident: &str,
        note: &str,
    ) -> (StatusCode, serde_json::Value) {
        self.post(
            &format!("{INCIDENTS}/{incident}/close/challenge"),
            Some(cookie),
            serde_json::json!({ "closing_note": note }),
        )
        .await
    }

    /// Signe, avec la clé logicielle, les options WebAuthn rendues par une
    /// route `…/challenge` ou `login/begin`.
    fn sign(&mut self, issued: &serde_json::Value) -> serde_json::Value {
        let options: oe_webauthn::RequestChallengeResponse =
            serde_json::from_value(serde_json::json!({ "publicKey": issued["webauthn"] })).unwrap();
        serde_json::to_value(self.authn.do_authentication(origin(), options).unwrap()).unwrap()
    }

    /// Présente une assertion à la route de clôture d'un dossier.
    async fn close(
        &self,
        cookie: &str,
        incident: &str,
        issued: &serde_json::Value,
        assertion: &serde_json::Value,
    ) -> (StatusCode, serde_json::Value) {
        self.post(
            &format!("{INCIDENTS}/{incident}/close"),
            Some(cookie),
            serde_json::json!({
                "challenge_id": issued["challenge_id"],
                "assertion": assertion,
            }),
        )
        .await
    }

    async fn state_of(&self, incident: &str) -> String {
        sqlx::query_scalar("SELECT state FROM incidents WHERE id = $1::uuid")
            .bind(incident)
            .fetch_one(&self.pool)
            .await
            .unwrap()
    }

    async fn count(&self, table: &str) -> i64 {
        sqlx::query_scalar(&format!("SELECT count(*) FROM {table}"))
            .fetch_one(&self.pool)
            .await
            .unwrap()
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
    for field in ["id", "title", "state", "opened_by", "opened_at"] {
        assert_eq!(one[field], opened[field], "{field}");
    }
    assert!(one["actions"].as_array().unwrap().is_empty(), "{one}");
    assert!(one["closure"].is_null(), "{one}");

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

/// Un dossier désigne, il ne déclenche pas : une note, puis la référence d'une
/// action que `ca-server` a figée, dont l'empreinte est lue chez lui.
#[tokio::test]
async fn notes_and_action_references_are_recorded_in_order() {
    let mut env = env!();
    let cookie = env.session("rachel", Role::RaOperateur).await;
    let incident = env.opened(&cookie, "clé TSU suspecte").await;
    let (action, hash) = env.frozen_action("revoke_certificate").await;

    let (status, note) = env
        .add(
            &cookie,
            &incident,
            serde_json::json!({ "kind": "note", "detail": "  signalement reçu\nà 9 h  " }),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{note}");
    assert_eq!(note["detail"], "signalement reçu\nà 9 h");
    assert_eq!(note["operator"], "rachel");

    let (status, linked) = env
        .add(
            &cookie,
            &incident,
            serde_json::json!({ "kind": "action_liee", "action_id": action, "detail": "révocation du TSU" }),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{linked}");
    assert_eq!(linked["body_hash"], hash.as_str());
    assert_eq!(linked["action"], "revoke_certificate");
    assert_eq!(linked["executed"], false);

    let detail = env.detail(&cookie, &incident).await;
    let entries = detail["actions"].as_array().unwrap();
    assert_eq!(entries.len(), 2, "{detail}");
    assert_eq!(entries[0]["kind"], "note");
    assert_eq!(entries[1]["kind"], "action_liee");
    assert_eq!(entries[1]["action_id"], action.as_str());
    assert_eq!(entries[1]["body_hash"], hash.as_str());

    let journal = env.journal.events("ra.incident_action");
    assert_eq!(journal.len(), 2, "{journal:?}");
    assert_eq!(journal[0]["incident_id"], incident.as_str());
    assert_eq!(journal[1]["action_id"], action.as_str());
    assert_eq!(journal[1]["body_hash"], hash.as_str());

    // L'empreinte ne se déclare pas, l'action doit exister, et elle ne se
    // rattache qu'une fois.
    let refused = [
        (
            serde_json::json!({ "kind": "action_liee", "action_id": action, "body_hash": "00" }),
            StatusCode::BAD_REQUEST,
            "bad_request",
        ),
        (
            serde_json::json!({ "kind": "action_liee", "action_id": oe_webauthn::Uuid::new_v4() }),
            StatusCode::NOT_FOUND,
            "unknown_action",
        ),
        (
            serde_json::json!({ "kind": "action_liee", "action_id": action }),
            StatusCode::CONFLICT,
            "already_linked",
        ),
        (
            serde_json::json!({ "kind": "note", "detail": "   " }),
            StatusCode::BAD_REQUEST,
            "bad_request",
        ),
        (
            serde_json::json!({ "kind": "revocation", "detail": "exécute" }),
            StatusCode::BAD_REQUEST,
            "bad_request",
        ),
    ];
    for (entry, expected, code) in refused {
        let (status, err) = env.add(&cookie, &incident, entry.clone()).await;
        assert_eq!(status, expected, "{entry} : {err}");
        assert_eq!(err["error"], code, "{entry}");
    }
    assert_eq!(env.count("incident_actions").await, 2);

    let (status, err) = env
        .add(
            &cookie,
            &oe_webauthn::Uuid::new_v4().to_string(),
            serde_json::json!({ "kind": "note", "detail": "nulle part" }),
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{err}");
    assert_eq!(err["error"], "unknown_incident");
}

/// Écrire dans un dossier ou le clore relève du même rôle que l'ouvrir, et du
/// même journal : pas d'entrée sans trace.
#[tokio::test]
async fn writing_into_an_incident_needs_the_role_and_the_journal() {
    let mut env = env!();
    let cookie = env.session("rachel", Role::RaOperateur).await;
    let incident = env.opened(&cookie, "clé TSU suspecte").await;

    for (name, role) in [("audrey", Role::Auditeur), ("adam", Role::Admin)] {
        let other = env.session(name, role).await;
        let (status, err) = env
            .add(
                &other,
                &incident,
                serde_json::json!({ "kind": "note", "detail": "sans le rôle" }),
            )
            .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{name} : {err}");
        let (status, err) = env.close_challenge(&other, &incident, "sans le rôle").await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{name} : {err}");
    }
    assert_eq!(env.count("incident_actions").await, 0);
    assert_eq!(
        env.count("webauthn_challenges WHERE kind = 'incident_close'")
            .await,
        0
    );

    env.journal.broken.store(true, Ordering::SeqCst);
    let (action, _) = env.frozen_action("revoke_certificate").await;
    for entry in [
        serde_json::json!({ "kind": "note", "detail": "pendant la panne" }),
        serde_json::json!({ "kind": "action_liee", "action_id": action }),
    ] {
        let (status, err) = env.add(&cookie, &incident, entry).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{err}");
    }
    assert_eq!(env.count("incident_actions").await, 0, "entrée sans trace");
}

/// La clôture porte la signature de l'opérateur sur le corps qui lui a été
/// montré ; la note enregistrée est celle de ce corps. Après quoi le dossier
/// ne reçoit plus rien.
#[tokio::test]
async fn closing_takes_the_operators_signature_over_the_frozen_note() {
    let mut env = env!();
    let cookie = env.session("rachel", Role::RaOperateur).await;
    let incident = env.opened(&cookie, "clé TSU suspecte").await;

    let (status, issued) = env
        .close_challenge(&cookie, &incident, "  faux positif, clé intacte  ")
        .await;
    assert_eq!(status, StatusCode::OK, "{issued}");
    let body: serde_json::Value = serde_json::from_str(issued["body"].as_str().unwrap()).unwrap();
    assert_eq!(body["action"], "close_incident");
    assert_eq!(body["incident_id"], incident.as_str());
    assert_eq!(body["closing_note"], "faux positif, clé intacte");
    assert_eq!(body["operator"], "rachel");
    // Rien n'est clos tant que rien n'est signé.
    assert_eq!(env.state_of(&incident).await, "OUVERT");

    let assertion = env.sign(&issued);
    let (status, closed) = env.close(&cookie, &incident, &issued, &assertion).await;
    assert_eq!(status, StatusCode::OK, "{closed}");
    assert_eq!(closed["state"], "CLOS");
    assert_eq!(closed["closed_by"], "rachel");
    assert_eq!(closed["closing_note"], "faux positif, clé intacte");
    assert_eq!(closed["closure"]["body"], issued["body"]);
    assert_eq!(closed["closure"]["body_hash"], issued["body_hash"]);

    // La preuve brute est conservée : de quoi revérifier la signature.
    let proof = sqlx::query(
        "SELECT c.credential_id, o.name, length(c.signature) AS sig,
                convert_from(c.client_data_json, 'UTF8') AS client_data,
                encode(sha256(convert_to(c.body, 'UTF8')), 'hex') AS recomputed,
                encode(c.body_hash, 'hex') AS stored
         FROM incident_closures c JOIN operators o ON o.id = c.operator_id
         WHERE c.incident_id = $1::uuid",
    )
    .bind(&incident)
    .fetch_one(&env.pool)
    .await
    .unwrap();
    let get = |c: &str| sqlx::Row::get::<String, _>(&proof, c);
    assert_eq!(get("name"), "rachel");
    assert_eq!(get("credential_id"), closed["closure"]["credential_id"]);
    assert_eq!(get("recomputed"), get("stored"));
    assert_eq!(get("stored"), issued["body_hash"]);
    assert!(sqlx::Row::get::<i32, _>(&proof, "sig") > 0);
    // Le challenge signé est celui qui a été émis pour cette clôture.
    let challenge = issued["webauthn"]["challenge"].as_str().unwrap();
    assert!(
        get("client_data").contains(challenge),
        "{}",
        get("client_data")
    );

    let journal = env.journal.events("ra.incident_closed");
    assert_eq!(journal.len(), 1, "{journal:?}");
    assert_eq!(journal[0]["incident_id"], incident.as_str());
    assert_eq!(journal[0]["operator"], "rachel");
    assert_eq!(journal[0]["body_hash"], issued["body_hash"]);

    // Clos : ni note, ni nouvelle clôture.
    let (status, err) = env
        .add(
            &cookie,
            &incident,
            serde_json::json!({ "kind": "note", "detail": "après coup" }),
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT, "{err}");
    assert_eq!(err["error"], "incident_closed");
    let (status, err) = env.close_challenge(&cookie, &incident, "encore").await;
    assert_eq!(status, StatusCode::CONFLICT, "{err}");
    assert_eq!(err["error"], "incident_closed");

    let (_, closed_list) = env
        .get(&format!("{INCIDENTS}?state=CLOS"), Some(&cookie))
        .await;
    assert_eq!(closed_list.as_array().unwrap().len(), 1);
}

/// Une assertion ne clôt que le dossier pour lequel son challenge a été émis.
/// Présentée ailleurs, elle est refusée sans être consommée.
#[tokio::test]
async fn a_closing_signature_only_closes_its_own_incident() {
    let mut env = env!();
    let cookie = env.session("rachel", Role::RaOperateur).await;
    let first = env.opened(&cookie, "premier dossier").await;
    let second = env.opened(&cookie, "second dossier").await;

    let (_, issued) = env
        .close_challenge(&cookie, &first, "note du premier")
        .await;
    let assertion = env.sign(&issued);

    let (status, err) = env.close(&cookie, &second, &issued, &assertion).await;
    assert_eq!(status, StatusCode::CONFLICT, "{err}");
    assert_eq!(err["error"], "challenge_mismatch");
    assert_eq!(env.state_of(&second).await, "OUVERT");
    assert_eq!(env.count("incident_closures").await, 0);

    // Sur la bonne route, la même assertion vaut toujours.
    let (status, closed) = env.close(&cookie, &first, &issued, &assertion).await;
    assert_eq!(status, StatusCode::OK, "{closed}");
    assert_eq!(closed["closing_note"], "note du premier");
    assert_eq!(env.state_of(&second).await, "OUVERT");
}

/// Sans la signature de l'opérateur de la session sur un challenge de clôture,
/// rien ne se clôt : ni avec l'assertion d'un collègue, ni avec celle d'une
/// connexion, ni avec n'importe quoi.
#[tokio::test]
async fn nothing_closes_without_the_session_operators_own_signature() {
    let mut env = env!();
    let rachel = env.session("rachel", Role::RaOperateur).await;
    let carl = env.session("carl", Role::CaOperateur).await;
    let incident = env.opened(&rachel, "clé TSU suspecte").await;

    // Le challenge de Rachel, signé par sa clé, présenté par la session de Carl.
    let (_, issued) = env
        .close_challenge(&rachel, &incident, "note de Rachel")
        .await;
    let assertion = env.sign(&issued);
    let (status, err) = env.close(&carl, &incident, &issued, &assertion).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{err}");
    assert_eq!(err["error"], "invalid_assertion");

    // Une assertion de connexion n'est pas une assertion de clôture.
    let (_, login) = env
        .post(
            "/api/v1/webauthn/login/begin",
            None,
            serde_json::json!({ "name": "rachel" }),
        )
        .await;
    let login_assertion = env.sign(&login);
    let (status, err) = env
        .close(&rachel, &incident, &login, &login_assertion)
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{err}");

    // Une assertion qui n'en est pas une, ou un challenge inconnu.
    let (_, fresh) = env
        .close_challenge(&rachel, &incident, "note de Rachel")
        .await;
    for (challenge, forged) in [
        (fresh.clone(), serde_json::json!({ "id": "x" })),
        (
            serde_json::json!({ "challenge_id": oe_webauthn::Uuid::new_v4() }),
            assertion.clone(),
        ),
        // Le bon challenge, mais l'assertion d'un autre.
        (fresh.clone(), assertion.clone()),
    ] {
        let (status, err) = env.close(&rachel, &incident, &challenge, &forged).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{err}");
        assert_eq!(err["error"], "invalid_assertion");
    }

    assert_eq!(env.state_of(&incident).await, "OUVERT");
    assert_eq!(env.count("incident_closures").await, 0);
    assert!(env.journal.events("ra.incident_closed").is_empty());
    assert!(!env.journal.events("ra.reassertion_refused").is_empty());
}

/// Le journal d'abord, pour la clôture aussi ; et un challenge ne sert qu'une
/// fois, que la clôture ait abouti ou non.
#[tokio::test]
async fn a_closing_challenge_is_single_use_and_waits_for_the_journal() {
    let mut env = env!();
    let cookie = env.session("rachel", Role::RaOperateur).await;
    let incident = env.opened(&cookie, "clé TSU suspecte").await;
    let (_, issued) = env
        .close_challenge(&cookie, &incident, "faux positif")
        .await;
    let assertion = env.sign(&issued);

    env.journal.broken.store(true, Ordering::SeqCst);
    let (status, err) = env.close(&cookie, &incident, &issued, &assertion).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{err}");
    assert_eq!(env.state_of(&incident).await, "OUVERT", "clos sans trace");
    assert_eq!(env.count("incident_closures").await, 0);

    // Le journal revient : l'assertion déjà présentée ne se rejoue pas. Le
    // compteur de signatures la refuserait aussi ; on l'efface pour que seul
    // l'usage unique du challenge puisse encore l'écarter.
    env.journal.broken.store(false, Ordering::SeqCst);
    sqlx::query("DELETE FROM login_counters")
        .execute(&env.pool)
        .await
        .unwrap();
    let (status, err) = env.close(&cookie, &incident, &issued, &assertion).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{err}");
    assert_eq!(err["error"], "invalid_assertion");
    assert_eq!(env.state_of(&incident).await, "OUVERT");

    // Une nouvelle signature, elle, clôt.
    let (_, again) = env
        .close_challenge(&cookie, &incident, "faux positif")
        .await;
    let assertion = env.sign(&again);
    let (status, closed) = env.close(&cookie, &incident, &again, &assertion).await;
    assert_eq!(status, StatusCode::OK, "{closed}");
}
