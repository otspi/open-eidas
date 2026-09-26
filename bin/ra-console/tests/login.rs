//! La connexion par nom (docs/WEBUI.md §15 étape 1c, §16 « connexion par nom,
//! réponses uniformes ») de bout en bout : un vrai PostgreSQL, un vrai
//! authentificateur logiciel, le vrai routeur HTTP de `ra-console`. Ce que le
//! test prouve : `ra-console` vérifie elle-même l'assertion (aucun aller-retour
//! vers `ca-server`), un nom inconnu reçoit un défi de même forme qu'un nom
//! réel, et tout ce qui échoue après `begin` se refuse de la même façon.
//!
//! DSN dans `OE_CASTORE_TEST_DSN` ; test ignoré si elle n'est pas définie.

mod common;

use std::sync::Arc;

use axum::body::Body;
use axum::http::{HeaderMap, Request, StatusCode};
use common::{pki, tempdir::Dir};
use http_body_util::BodyExt;
use oe_actions::{NewCredential, Registry, Role};
use oe_webauthn::{trusted_models, TrustedModel, Url, Uuid, Verifier};
use ra_console::ca_link::CaLink;
use ra_console::http::{router, AppState};
use ra_console::login::LoginService;
use sqlx::postgres::PgPoolOptions;
use tower::ServiceExt;
use webauthn_authenticator_rs::softtoken::{SoftToken, AAGUID};
use webauthn_authenticator_rs::WebauthnAuthenticator;

const DECOY_SECRET: &[u8] = b"secret-de-test-au-moins-16-octets";

fn origin() -> Url {
    Url::parse("https://console.example.com").unwrap()
}

struct Env {
    console: axum::Router,
    registry: Registry,
    authn: WebauthnAuthenticator<SoftToken>,
    verifier: Verifier,
    audit_file: std::path::PathBuf,
    _dir: Dir,
    _pki: common::Pki,
}

impl Env {
    /// Le contenu du journal propre à `ra-console` (docs/WEBUI.md §7), tel
    /// qu'un test le relit — jamais celui de `ca-server`.
    fn journal_text(&self) -> String {
        std::fs::read_to_string(&self.audit_file).unwrap_or_default()
    }
}

impl Env {
    async fn new() -> Option<Env> {
        let base = std::env::var("OE_CASTORE_TEST_DSN").ok()?;
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let name = format!("login_{nanos}");
        let admin = PgPoolOptions::new().connect(&base).await.unwrap();
        sqlx::query(&format!("CREATE DATABASE {name}"))
            .execute(&admin)
            .await
            .unwrap();
        let dsn = format!("{}/{name}", base.rsplit_once('/').unwrap().0);
        // Applique les migrations (webauthn_challenges, login_counters, §16).
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
        let audit_file = std::env::temp_dir().join(format!("{name}.ra-audit.log"));
        let journal: Arc<dyn ra_console::audit::Recorder> =
            Arc::new(ra_console::audit::AuditRecorder::new(
                Arc::new(oe_audit::Log::open(&audit_file).unwrap()),
                audit_file.to_string_lossy().into_owned(),
                None,
            ));
        let login = LoginService::new(
            registry.clone(),
            Verifier::new("console.example.com", &origin(), "test", models()).unwrap(),
            DECOY_SECRET.to_vec(),
            journal.clone(),
        );

        // Un lien vers ca-server injoignable : les routes de login ne le
        // sollicitent jamais, seul /healthz s'en soucierait. Un vrai certificat
        // client (jamais présenté à personne), pour que CaLink::new l'accepte.
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

        let sessions = ra_console::session::Sessions::new(Registry::new(pool.clone()), journal);
        let console = router(Arc::new(AppState {
            sessions,
            pool,
            link,
            login,
            s3: None,
        }));
        Some(Env {
            console,
            registry,
            authn: WebauthnAuthenticator::new(token),
            verifier,
            audit_file,
            _dir: dir,
            _pki: ca_pki,
        })
    }

    async fn post(&self, path: &str, body: serde_json::Value) -> (StatusCode, serde_json::Value) {
        let (status, _, body) = self.post_with_headers(path, body, None).await;
        (status, body)
    }

    /// Comme `post`, mais expose les en-têtes de la réponse (`Set-Cookie`) et
    /// accepte d'en présenter un (`Cookie`) — pour exercer la session.
    async fn post_with_headers(
        &self,
        path: &str,
        body: serde_json::Value,
        cookie: Option<&str>,
    ) -> (StatusCode, HeaderMap, serde_json::Value) {
        let mut req = Request::post(path).header("content-type", "application/json");
        if let Some(c) = cookie {
            req = req.header("cookie", c);
        }
        let res = self
            .console
            .clone()
            .oneshot(req.body(Body::from(body.to_string())).unwrap())
            .await
            .unwrap();
        let status = res.status();
        let headers = res.headers().clone();
        let bytes = res.into_body().collect().await.unwrap().to_bytes();
        (
            status,
            headers,
            serde_json::from_slice(&bytes).unwrap_or_default(),
        )
    }

    /// `GET` avec un cookie éventuel, pour `/api/v1/me`.
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

    /// Un opérateur avec une clé active, attestée par le même authentificateur
    /// que `self.authn`, admise par le même vérificateur que la console.
    async fn operator_with_key(&mut self, name: &str) -> Uuid {
        let now = time::OffsetDateTime::now_utc();
        let id = self
            .registry
            .add_operator(name, Role::RaOperateur, "test", now)
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
}

impl Env {
    /// Connexion complète (begin + finish réels) : rend le cookie de session
    /// posé par `Set-Cookie`, tel qu'un navigateur le renverrait ensuite.
    async fn log_in(&mut self, name: &str) -> String {
        let (_, begun) = self.post(BEGIN, serde_json::json!({"name": name})).await;
        let options: oe_webauthn::RequestChallengeResponse =
            serde_json::from_value(serde_json::json!({ "publicKey": begun["webauthn"] })).unwrap();
        let assertion = self.authn.do_authentication(origin(), options).unwrap();
        let (status, headers, _) = self
            .post_with_headers(
                FINISH,
                serde_json::json!({
                    "challenge_id": begun["challenge_id"],
                    "credential": assertion,
                }),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::OK);
        let set_cookie = headers
            .get(axum::http::header::SET_COOKIE)
            .unwrap()
            .to_str()
            .unwrap();
        // Ce qu'un navigateur renvoie ensuite dans `Cookie` : seul le couple
        // nom=valeur, sans les attributs (`Path`, `HttpOnly`…).
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

const BEGIN: &str = "/api/v1/webauthn/login/begin";
const FINISH: &str = "/api/v1/webauthn/login/finish";

#[tokio::test]
async fn a_registered_operator_logs_in() {
    let mut env = env!();
    env.operator_with_key("alice").await;

    let (status, begun) = env.post(BEGIN, serde_json::json!({"name": "alice"})).await;
    assert_eq!(status, StatusCode::OK, "{begun}");
    assert_eq!(
        begun["webauthn"]["allowCredentials"]
            .as_array()
            .unwrap()
            .len(),
        1
    );

    let options: oe_webauthn::RequestChallengeResponse =
        serde_json::from_value(serde_json::json!({ "publicKey": begun["webauthn"] })).unwrap();
    let assertion = env.authn.do_authentication(origin(), options).unwrap();

    let (status, done) = env
        .post(
            FINISH,
            serde_json::json!({
                "challenge_id": begun["challenge_id"],
                "credential": assertion,
            }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{done}");
    assert_eq!(done["operator"], "alice");
    assert_eq!(done["role"], "ra_operateur");

    // Le compteur anti-clonage est bien le sien, pas celui de ca-server.
    let credential_id = sqlx::query_scalar::<_, String>(
        "SELECT credential_id FROM webauthn_credentials WHERE operator_id = \
         (SELECT id FROM operators WHERE name = 'alice')",
    )
    .fetch_one(env.registry.pool())
    .await
    .unwrap();
    let counted: i64 =
        sqlx::query_scalar("SELECT count(*) FROM login_counters WHERE credential_id = $1")
            .bind(&credential_id)
            .fetch_one(env.registry.pool())
            .await
            .unwrap();
    assert_eq!(counted, 1);

    // Le challenge est marqué consommé (usage unique, docs/WEBUI.md §15) : pas
    // seulement en effet (la régression du compteur anti-clonage refuserait de
    // toute façon la même assertion rejouée, testé juste après), mais en ligne.
    let challenge_id: Uuid = serde_json::from_value(begun["challenge_id"].clone()).unwrap();
    let consumed: bool =
        sqlx::query_scalar("SELECT consumed_at IS NOT NULL FROM webauthn_challenges WHERE id = $1")
            .bind(challenge_id)
            .fetch_one(env.registry.pool())
            .await
            .unwrap();
    assert!(consumed, "le challenge devrait être marqué consommé");

    // Rejouer la même assertion est refusé (ici, par la régression du compteur
    // anti-clonage : le challenge consommé le serait de toute façon).
    let (status, err) = env
        .post(
            FINISH,
            serde_json::json!({
                "challenge_id": begun["challenge_id"],
                "credential": assertion,
            }),
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{err}");
    assert_eq!(err["error"], "invalid_credential");
}

/// La révocation est décidée par `ca-server` (§16) ; `ra-console` n'a que la
/// lecture. Mais elle doit la respecter : une clé révoquée ne se connecte pas,
/// même avec une assertion par ailleurs valide.
#[tokio::test]
async fn a_revoked_key_cannot_log_in() {
    let mut env = env!();
    env.operator_with_key("alice").await;

    let (_, begun) = env.post(BEGIN, serde_json::json!({"name": "alice"})).await;
    let options: oe_webauthn::RequestChallengeResponse =
        serde_json::from_value(serde_json::json!({ "publicKey": begun["webauthn"] })).unwrap();
    let assertion = env.authn.do_authentication(origin(), options).unwrap();

    let credential_id = sqlx::query_scalar::<_, String>(
        "SELECT credential_id FROM webauthn_credentials WHERE operator_id = \
         (SELECT id FROM operators WHERE name = 'alice')",
    )
    .fetch_one(env.registry.pool())
    .await
    .unwrap();
    env.registry
        .revoke_key(
            &credential_id,
            "test",
            "perte",
            time::OffsetDateTime::now_utc(),
        )
        .await
        .unwrap();

    let (status, err) = env
        .post(
            FINISH,
            serde_json::json!({
                "challenge_id": begun["challenge_id"],
                "credential": assertion,
            }),
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{err}");
    assert_eq!(err["error"], "invalid_credential");
}

#[tokio::test]
async fn an_unknown_name_gets_the_same_shape_as_a_registered_one() {
    let mut env = env!();
    env.operator_with_key("alice").await;

    let (_, real) = env.post(BEGIN, serde_json::json!({"name": "alice"})).await;
    let (_, decoy) = env
        .post(BEGIN, serde_json::json!({"name": "personne-de-ce-nom"}))
        .await;

    for field in ["rpId", "timeout", "userVerification", "hints"] {
        assert_eq!(
            real["webauthn"][field], decoy["webauthn"][field],
            "champ {field} distinct entre un nom réel et un nom inconnu"
        );
    }
    assert_eq!(
        real["webauthn"]["allowCredentials"]
            .as_array()
            .unwrap()
            .len(),
        decoy["webauthn"]["allowCredentials"]
            .as_array()
            .unwrap()
            .len(),
    );
    // Le challenge, lui, ne se répète jamais.
    assert_ne!(
        real["webauthn"]["challenge"],
        decoy["webauthn"]["challenge"]
    );

    // Un nom inconnu redemandé deux fois reçoit une clé factice stable (même
    // HMAC), mais jamais le même challenge.
    let (_, decoy2) = env
        .post(BEGIN, serde_json::json!({"name": "personne-de-ce-nom"}))
        .await;
    assert_eq!(
        decoy["webauthn"]["allowCredentials"][0]["id"],
        decoy2["webauthn"]["allowCredentials"][0]["id"]
    );
    assert_ne!(
        decoy["webauthn"]["challenge"],
        decoy2["webauthn"]["challenge"]
    );
}

#[tokio::test]
async fn an_unknown_challenge_or_a_decoy_assertion_is_uniformly_refused() {
    let mut env = env!();
    env.operator_with_key("alice").await;

    // Un challenge_id qui n'existe pas.
    let (status, err) = env
        .post(
            FINISH,
            serde_json::json!({
                "challenge_id": "3f2b8c1e-9d4a-4e6b-8a7c-1234567890ab",
                "credential": {"id": "x", "rawId": "eA", "response": {
                    "authenticatorData": "eA", "clientDataJSON": "eA", "signature": "eA"
                }, "type": "public-key"},
            }),
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{err}");
    assert_eq!(err["error"], "invalid_credential");

    // Un nom inconnu : ra-console propose un leurre, mais aucune assertion ne
    // peut jamais réussir contre lui (aucun état à vérifier n'existe).
    let (_, begun) = env
        .post(BEGIN, serde_json::json!({"name": "personne-de-ce-nom"}))
        .await;
    let (status, err) = env
        .post(
            FINISH,
            serde_json::json!({
                "challenge_id": begun["challenge_id"],
                "credential": {"id": "x", "rawId": "eA", "response": {
                    "authenticatorData": "eA", "clientDataJSON": "eA", "signature": "eA"
                }, "type": "public-key"},
            }),
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{err}");
    assert_eq!(err["error"], "invalid_credential");
}

#[tokio::test]
async fn malformed_requests_are_rejected_before_touching_the_database() {
    let env = env!();

    for content_type in [None, Some("text/plain")] {
        let mut req = Request::post(BEGIN);
        if let Some(ct) = content_type {
            req = req.header("content-type", ct);
        }
        let res = env
            .console
            .clone()
            .oneshot(req.body(Body::from(r#"{"name":"x"}"#)).unwrap())
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
    }

    for body in [
        serde_json::json!({}),
        serde_json::json!({"name": ""}),
        serde_json::json!({"name": "x".repeat(257)}),
        serde_json::json!({"name": "x", "role_hint": "admin"}),
    ] {
        let (status, err) = env.post(BEGIN, body.clone()).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body} {err}");
        assert_eq!(err["error"], "bad_request");
    }

    for body in [
        serde_json::json!({"challenge_id": "pas-un-uuid", "credential": {}}),
        serde_json::json!({"challenge_id": "x", "credential": "texte"}),
    ] {
        let (status, err) = env.post(FINISH, body.clone()).await;
        assert!(
            status == StatusCode::BAD_REQUEST || status == StatusCode::UNAUTHORIZED,
            "{body} {status} {err}"
        );
    }
}

const ME: &str = "/api/v1/me";
const LOGOUT: &str = "/api/v1/logout";

/// La connexion ouvre une session (docs/WEBUI.md §15 étape 1c-2) : le cookie
/// qu'elle pose authentifie ensuite `/api/v1/me`, avec l'identité et le rôle
/// relus en base, pas mis en cache dans la session.
#[tokio::test]
async fn login_opens_a_session_that_me_reports() {
    let mut env = env!();
    env.operator_with_key("alice").await;
    let cookie = env.log_in("alice").await;
    assert!(cookie.starts_with("session="), "{cookie}");

    let (status, me) = env.get_with_cookie(ME, Some(&cookie)).await;
    assert_eq!(status, StatusCode::OK, "{me}");
    assert_eq!(me["operator"], "alice");
    assert_eq!(me["role"], "ra_operateur");

    // Sans cookie, ou avec un cookie inventé : refusé, sans distinction.
    let (status, err) = env.get_with_cookie(ME, None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{err}");
    assert_eq!(err["error"], "unauthenticated");
    let (status, err) = env
        .get_with_cookie(ME, Some("session=n-importe-quoi"))
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{err}");
    assert_eq!(err["error"], "unauthenticated");
}

/// Un opérateur désactivé après l'ouverture de sa session perd l'accès sans
/// attendre l'expiration (§16 : l'identité et le rôle sont relus à chaque
/// requête, jamais mis en cache).
#[tokio::test]
async fn a_session_stops_working_once_the_operator_is_disabled() {
    let mut env = env!();
    let id = env.operator_with_key("alice").await;
    let cookie = env.log_in("alice").await;

    sqlx::query("UPDATE operators SET disabled_at = now() WHERE id = $1")
        .bind(id)
        .execute(env.registry.pool())
        .await
        .unwrap();

    let (status, err) = env.get_with_cookie(ME, Some(&cookie)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{err}");
    assert_eq!(err["error"], "unauthenticated");
}

/// La déconnexion révoque la session : le même cookie ne rouvre plus rien
/// ensuite, et elle est idempotente (sans cookie, ou rejouée, elle ne casse
/// pas — le résultat visible est le même : plus de session).
#[tokio::test]
async fn logout_revokes_the_session() {
    let mut env = env!();
    env.operator_with_key("alice").await;
    let cookie = env.log_in("alice").await;

    let (status, headers, _) = env
        .post_with_headers(LOGOUT, serde_json::json!({}), Some(&cookie))
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let cleared = headers
        .get(axum::http::header::SET_COOKIE)
        .unwrap()
        .to_str()
        .unwrap();
    assert!(cleared.contains("Max-Age=0"), "{cleared}");

    let (status, err) = env.get_with_cookie(ME, Some(&cookie)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{err}");
    assert_eq!(err["error"], "unauthenticated");

    // Rejouer la déconnexion, ou sans cookie du tout : toujours 204.
    let (status, _, _) = env
        .post_with_headers(LOGOUT, serde_json::json!({}), Some(&cookie))
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _, _) = env
        .post_with_headers(LOGOUT, serde_json::json!({}), None)
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    // Une seule fermeture consignée : la déconnexion rejouée n'a rien fermé.
    let journal = env.journal_text();
    assert_eq!(journal.matches("ra.session_closed").count(), 1, "{journal}");
}

/// Le journal propre à `ra-console` (docs/WEBUI.md §7) consigne connexions et
/// sessions, avec la vraie raison d'un refus — jamais visible, elle, dans la
/// réponse HTTP uniforme (§16).
#[tokio::test]
async fn the_console_journal_records_connections_and_their_real_refusal_reason() {
    let mut env = env!();
    env.operator_with_key("alice").await;
    env.log_in("alice").await;

    let journal = env.journal_text();
    assert!(journal.contains("ra.login_succeeded"), "{journal}");
    assert!(journal.contains("ra.session_opened"), "{journal}");
    assert!(journal.contains("\"alice\""), "{journal}");

    // Un nom inconnu : le leurre est journalisé avec sa vraie raison, jamais
    // uniforme comme la réponse HTTP.
    let (_, begun) = env
        .post(BEGIN, serde_json::json!({"name": "personne-de-ce-nom"}))
        .await;
    env.post(
        FINISH,
        serde_json::json!({
            "challenge_id": begun["challenge_id"],
            "credential": {"id": "x", "rawId": "eA", "response": {
                "authenticatorData": "eA", "clientDataJSON": "eA", "signature": "eA"
            }, "type": "public-key"},
        }),
    )
    .await;
    let journal = env.journal_text();
    assert!(journal.contains("ra.login_refused"), "{journal}");
    assert!(journal.contains("leurre"), "{journal}");
}
