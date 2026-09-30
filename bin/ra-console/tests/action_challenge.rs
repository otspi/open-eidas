//! Actions signées approve/reject (docs/WEBUI.md §4, §15 étape 3 : 3a
//! préparation, 3b exécution) de bout en bout : un navigateur factice connecté → `ra-console` → le
//! lien mTLS → le **vrai** service d'actions de `ca-server`, sur un vrai
//! PostgreSQL. Ce que le test prouve : le challenge est émis pour l'opérateur
//! de la session et pour personne d'autre, la console ne prépare que les
//! actions de l'étape 3, et c'est `ca-server` qui juge du rôle.
//!
//! DSN dans `OE_CASTORE_TEST_DSN` ; test ignoré si elle n'est pas définie.

mod common;

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use common::{pki, tempdir::Dir, Pki};
use http_body_util::BodyExt;
use oe_actions::{NewCredential, Registry, Role, Service};
use oe_castore::{Postgres, RequestState, Store};
use oe_raflow::{Decider, DeciderOptions, Recorder};
use oe_webauthn::{trusted_models, TrustedModel, Url, Uuid, Verifier};
use ra_console::ca_link::CaLink;
use ra_console::http::{router, AppState};
use ra_console::login::LoginService;
use sqlx::postgres::PgPoolOptions;
use tower::ServiceExt;
use webauthn_authenticator_rs::softtoken::{SoftToken, AAGUID};
use webauthn_authenticator_rs::WebauthnAuthenticator;

const HOST: &str = "console.example.com";
const LOGIN_BEGIN: &str = "/api/v1/webauthn/login/begin";
const LOGIN_FINISH: &str = "/api/v1/webauthn/login/finish";
const CHALLENGE: &str = "/api/v1/webauthn/challenge";

struct NullJournal;
#[async_trait::async_trait]
impl Recorder for NullJournal {
    async fn append(&self, _: &str, _: serde_json::Value) -> Result<(), String> {
        Ok(())
    }
}

fn origin() -> Url {
    Url::parse(&format!("https://{HOST}")).unwrap()
}

/// Le journal de la console, relu par les tests : un jeton d'invitation ne
/// doit jamais y figurer.
#[derive(Default)]
struct ConsoleJournal(std::sync::Mutex<Vec<String>>);

impl ra_console::audit::Recorder for ConsoleJournal {
    fn append(&self, event: &str, data: serde_json::Value) {
        self.0.lock().unwrap().push(format!("{event} {data}"));
    }
}

struct Env {
    console: axum::Router,
    journal: Arc<ConsoleJournal>,
    registry: Registry,
    store: Arc<dyn Store>,
    issuer: Arc<oe_ca_core::Issuer>,
    verifier: Verifier,
    authn: WebauthnAuthenticator<SoftToken>,
    _dir: Dir,
    _pki: Pki,
}

impl Env {
    async fn new() -> Option<Env> {
        let base = std::env::var("OE_CASTORE_TEST_DSN").ok()?;
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let seq = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let name = format!("chal_{nanos}_{seq}");
        let admin = PgPoolOptions::new().connect(&base).await.unwrap();
        sqlx::query(&format!("CREATE DATABASE {name}"))
            .execute(&admin)
            .await
            .unwrap();
        let dsn = format!("{}/{name}", base.rsplit_once('/').unwrap().0);
        let store: Arc<dyn Store> = Arc::new(Postgres::open(&dsn).await.unwrap());
        let registry = Registry::connect(&dsn).await.unwrap();

        // Une vraie CA sur la même base, pour que la révocation porte sur un
        // certificat réellement émis (étape 4).
        let issuing = Arc::new(oe_hsm::testing::SoftwareToken::generate(2048));
        let h = oe_ca_core::ceremony::run_ceremony(oe_ca_core::ceremony::CeremonyOptions {
            root_signer: Arc::new(oe_hsm::testing::SoftwareToken::generate(2048)),
            issuing_signer: issuing.clone(),
            root_cn: "Test Root CA".into(),
            issuing_cn: "Test Issuing CA".into(),
            organization: "Open eIDAS Test".into(),
            country: "FR".into(),
            root_validity: time::Duration::days(3650),
            issuing_validity: time::Duration::days(3650),
            root_token_label: "r".into(),
            root_key_label: "r".into(),
            issuing_token_label: "i".into(),
            issuing_key_label: "i".into(),
            store: store.clone(),
            operator: "test".into(),
            public_url: "https://ca.example.test".into(),
            recorder: None,
        })
        .await
        .unwrap();
        let issuer = Arc::new(
            oe_ca_core::Issuer::new(oe_ca_core::Options {
                signer: issuing,
                certificate: h.issuing,
                chain: vec![],
                store: store.clone(),
                public_url: "https://ca.example.test".into(),
                ocsp_url: None,
                crl_validity: time::Duration::hours(24),
                crl_grace: time::Duration::hours(1),
                recorder: None,
            })
            .unwrap(),
        );

        // Un seul modèle de clé de confiance, le même pour ca-server (qui
        // vérifiera les assertions d'action) et pour la console (connexion).
        let (token, root) = SoftToken::new(true).unwrap();
        let root_pem = root.to_pem().unwrap();
        let verifier = || {
            Verifier::new(
                HOST,
                &origin(),
                "test",
                trusted_models(&[TrustedModel {
                    root_pem: &root_pem,
                    aaguid: AAGUID,
                    description: "SoftToken (test)",
                }])
                .unwrap(),
            )
            .unwrap()
        };

        let service = Arc::new(
            Service::new(
                registry.clone(),
                verifier(),
                store.clone(),
                Decider::new(DeciderOptions {
                    store: store.clone(),
                    recorder: None,
                    clock: None,
                }),
                Arc::new(NullJournal),
                Arc::new(time::OffsetDateTime::now_utc),
            )
            .with_revoker(Arc::new(ca_server::revoker::IssuerRevoker(issuer.clone()))),
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
        let journal = Arc::new(ConsoleJournal::default());
        let console = router(Arc::new(AppState {
            pool: pool.clone(),
            link,
            login: LoginService::new(
                registry.clone(),
                verifier(),
                b"secret-de-test-au-moins-16-octets".to_vec(),
                Arc::new(ra_console::audit::NullRecorder),
            ),
            sessions: common::sessions(pool),
            journal: journal.clone(),
        }));

        Some(Env {
            console,
            journal,
            registry,
            store,
            issuer,
            verifier: verifier(),
            authn: WebauthnAuthenticator::new(token),
            _dir: dir,
            _pki: pki,
        })
    }

    /// Un opérateur actif avec une clé enregistrée, posé directement dans le
    /// registre : l'enrôlement a ses propres tests (register_relay.rs).
    async fn operator_with_key(&mut self, name: &str, role: Role) -> Uuid {
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
        id
    }

    async fn post(
        &self,
        path: &str,
        body: serde_json::Value,
        cookie: Option<&str>,
        content_type: &str,
    ) -> (StatusCode, axum::http::HeaderMap, serde_json::Value) {
        let mut req = Request::post(path).header("content-type", content_type);
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

    async fn challenge(
        &self,
        cookie: Option<&str>,
        body: serde_json::Value,
    ) -> (StatusCode, serde_json::Value) {
        let (status, _, body) = self.post(CHALLENGE, body, cookie, "application/json").await;
        (status, body)
    }

    async fn log_in(&mut self, name: &str) -> String {
        let (_, _, begun) = self
            .post(
                LOGIN_BEGIN,
                serde_json::json!({ "name": name }),
                None,
                "application/json",
            )
            .await;
        let options: oe_webauthn::RequestChallengeResponse =
            serde_json::from_value(serde_json::json!({ "publicKey": begun["webauthn"] })).unwrap();
        let assertion = self.authn.do_authentication(origin(), options).unwrap();
        let (status, headers, body) = self
            .post(
                LOGIN_FINISH,
                serde_json::json!({ "challenge_id": begun["challenge_id"], "credential": assertion }),
                None,
                "application/json",
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let set_cookie = headers.get("set-cookie").unwrap().to_str().unwrap();
        set_cookie.split(';').next().unwrap().to_string()
    }

    async fn pending_request(&self, transaction_id: &str) {
        self.store
            .create_request(oe_castore::Request {
                transaction_id: transaction_id.to_string(),
                csr_fingerprint: format!("empreinte-{transaction_id}"),
                csr_der: vec![0x30, 0x00],
                profile: "tsa_signer".to_string(),
                subject_cn: "tsu.example.test".to_string(),
                state: RequestState::Pending,
                created_at: time::OffsetDateTime::now_utc(),
                decided_at: None,
                operator: String::new(),
                comment: String::new(),
                issued_at: None,
                certificate_serial: None,
            })
            .await
            .unwrap();
    }

    async fn actions_frozen(&self) -> i64 {
        sqlx::query_scalar("SELECT count(*) FROM actions")
            .fetch_one(self.registry.pool())
            .await
            .unwrap()
    }

    /// Identifiants (base64url) des clés d'un opérateur, tels que l'option
    /// `allowCredentials` d'un challenge les désigne.
    async fn credential_ids(&self, operator: Uuid) -> Vec<String> {
        sqlx::query_scalar("SELECT credential_id FROM webauthn_credentials WHERE operator_id = $1")
            .bind(operator)
            .fetch_all(self.registry.pool())
            .await
            .unwrap()
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

fn approve(tx: &str) -> serde_json::Value {
    serde_json::json!({ "action": "approve_request", "transaction_id": tx, "comment": "identité vérifiée" })
}

fn allowed(challenge: &serde_json::Value) -> Vec<String> {
    challenge["webauthn"]["allowCredentials"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["id"].as_str().unwrap().to_string())
        .collect()
}

#[tokio::test]
async fn a_logged_in_operator_gets_a_challenge_for_their_own_keys() {
    let mut env = env!();
    let alice = env.operator_with_key("alice", Role::RaOperateur).await;
    let bob = env.operator_with_key("bob", Role::RaOperateur).await;
    let cookie = env.log_in("alice").await;
    env.pending_request("tx-1").await;

    // Le navigateur glisse l'identifiant de bob : la console ne le relaie pas,
    // le challenge vise les clés de la session (alice), pas celles de bob.
    let mut body = approve("tx-1");
    body["operator_hint"] = serde_json::json!(bob);
    let (status, issued) = env.challenge(Some(&cookie), body).await;
    assert_eq!(status, StatusCode::OK, "{issued}");
    assert_eq!(issued["body"]["action"], "approve_request");
    assert_eq!(issued["body"]["transaction_id"], "tx-1");
    assert_eq!(issued["body_hash"].as_str().unwrap().len(), 64);
    assert!(issued["challenge_id"].is_string() && issued["action_id"].is_string());
    let keys = allowed(&issued);
    assert_eq!(keys, env.credential_ids(alice).await, "{issued}");
    assert!(env
        .credential_ids(bob)
        .await
        .iter()
        .all(|k| !keys.contains(k)));
    assert_eq!(env.actions_frozen().await, 1);
}

#[tokio::test]
async fn the_console_prepares_nothing_without_a_session_or_outside_step_3() {
    let mut env = env!();
    env.operator_with_key("alice", Role::CaOperateur).await;
    let cookie = env.log_in("alice").await;
    env.pending_request("tx-1").await;

    // Sans session, ou avec une session inventée.
    for c in [None, Some("session=n-importe-quoi")] {
        let (status, err) = env.challenge(c, approve("tx-1")).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{err}");
    }

    // La gestion du registre est relayée, mais réservée aux administrateurs :
    // c'est ca-server qui refuse à un ca_operateur, sans rien figer.
    for action in [
        serde_json::json!({ "action": "invite_operator", "name": "eve", "role": "auditeur" }),
        serde_json::json!({ "action": "set_role", "operator": "alice", "role": "auditeur" }),
    ] {
        let (status, err) = env.challenge(Some(&cookie), action).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{err}");
        assert_eq!(err["error"], "denied");
    }

    // Une action inconnue, ou un corps qui n'est pas une action.
    for body in [
        serde_json::json!({ "action": "delete_everything" }),
        serde_json::json!({ "transaction_id": "tx-1" }),
    ] {
        let (status, err) = env.challenge(Some(&cookie), body).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{err}");
    }

    // Un corps qui ne se déclare pas JSON.
    let (status, _, _) = env
        .post(CHALLENGE, approve("tx-1"), Some(&cookie), "text/plain")
        .await;
    assert_eq!(status, StatusCode::UNSUPPORTED_MEDIA_TYPE);

    assert_eq!(
        env.actions_frozen().await,
        0,
        "rien n'a été figé côté ca-server"
    );
}

/// Le rôle affiché par la console n'est pas une barrière (§3) : c'est
/// `ca-server` qui refuse une approbation à un administrateur, et la console
/// relaie son refus.
#[tokio::test]
async fn ca_server_judges_the_role_not_the_console() {
    let mut env = env!();
    env.operator_with_key("root", Role::Admin).await;
    let cookie = env.log_in("root").await;
    env.pending_request("tx-1").await;

    let (status, err) = env.challenge(Some(&cookie), approve("tx-1")).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{err}");
    assert_eq!(env.actions_frozen().await, 0);

    // Et une demande qui n'existe pas n'est pas figée non plus.
    let mut env2 = env!();
    env2.operator_with_key("alice", Role::RaOperateur).await;
    let cookie = env2.log_in("alice").await;
    let (status, err) = env2.challenge(Some(&cookie), approve("tx-inconnue")).await;
    assert!(status.is_client_error(), "{status} {err}");
    assert_eq!(env2.actions_frozen().await, 0);
}

impl Env {
    /// L'opérateur touche sa clé : l'assertion du challenge rendu par la console.
    fn sign(&mut self, issued: &serde_json::Value) -> serde_json::Value {
        let options: oe_webauthn::RequestChallengeResponse =
            serde_json::from_value(serde_json::json!({ "publicKey": issued["webauthn"] })).unwrap();
        serde_json::to_value(self.authn.do_authentication(origin(), options).unwrap()).unwrap()
    }

    async fn decide(
        &self,
        cookie: Option<&str>,
        path: &str,
        issued: &serde_json::Value,
        assertion: &serde_json::Value,
    ) -> (StatusCode, serde_json::Value) {
        let (status, _, body) = self
            .post(
                path,
                serde_json::json!({ "challenge_id": issued["challenge_id"], "assertion": assertion }),
                cookie,
                "application/json",
            )
            .await;
        (status, body)
    }

    async fn state_of(&self, tx: &str) -> (RequestState, String) {
        let r = self.store.request_by_transaction_id(tx).await.unwrap();
        (r.state, r.operator)
    }
}

fn reject(tx: &str) -> serde_json::Value {
    serde_json::json!({ "action": "reject_request", "transaction_id": tx, "comment": "sujet non reconnu" })
}

#[tokio::test]
async fn an_operator_approves_and_rejects_through_the_console() {
    let mut env = env!();
    env.operator_with_key("alice", Role::RaOperateur).await;
    let cookie = env.log_in("alice").await;
    env.pending_request("tx-1").await;
    env.pending_request("tx-2").await;

    let (_, issued) = env.challenge(Some(&cookie), approve("tx-1")).await;
    let assertion = env.sign(&issued);
    let (status, done) = env
        .decide(
            Some(&cookie),
            "/api/v1/requests/tx-1/approve",
            &issued,
            &assertion,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{done}");
    assert_eq!(done["transaction_id"], "tx-1");
    assert_eq!(done["state"], "APPROVED");
    // L'identité qui a décidé est celle du registre de ca-server.
    assert_eq!(done["decided_by"], "alice");
    assert_eq!(
        env.state_of("tx-1").await,
        (RequestState::Approved, "alice".to_string())
    );

    // Rejouer la même assertion ne décide rien de plus.
    let (status, again) = env
        .decide(
            Some(&cookie),
            "/api/v1/requests/tx-1/approve",
            &issued,
            &assertion,
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT, "{again}");
    assert_eq!(again["error"], "already_used");

    let (_, issued) = env.challenge(Some(&cookie), reject("tx-2")).await;
    let assertion = env.sign(&issued);
    let (status, done) = env
        .decide(
            Some(&cookie),
            "/api/v1/requests/tx-2/reject",
            &issued,
            &assertion,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{done}");
    assert_eq!(done["state"], "REJECTED");
    assert_eq!(env.state_of("tx-2").await.0, RequestState::Rejected);
}

/// Une signature obtenue pour une demande ne décide jamais d'une autre, ni
/// l'inverse de ce qui a été signé : `ca-server` compare la cible de la route
/// au corps figé **avant** de rien consommer, si bien que la même assertion
/// reste utilisable sur la bonne route.
#[tokio::test]
async fn a_signature_only_decides_what_was_signed() {
    let mut env = env!();
    env.operator_with_key("alice", Role::RaOperateur).await;
    let cookie = env.log_in("alice").await;
    env.pending_request("tx-a").await;
    env.pending_request("tx-b").await;

    let (_, issued) = env.challenge(Some(&cookie), approve("tx-a")).await;
    let assertion = env.sign(&issued);

    for path in [
        "/api/v1/requests/tx-b/approve",
        "/api/v1/requests/tx-a/reject",
    ] {
        let (status, err) = env.decide(Some(&cookie), path, &issued, &assertion).await;
        assert_eq!(status, StatusCode::CONFLICT, "{path} {err}");
        assert_eq!(err["error"], "action_mismatch", "{path}");
    }
    assert_eq!(env.state_of("tx-a").await.0, RequestState::Pending);
    assert_eq!(env.state_of("tx-b").await.0, RequestState::Pending);

    let (status, done) = env
        .decide(
            Some(&cookie),
            "/api/v1/requests/tx-a/approve",
            &issued,
            &assertion,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{done}");
    assert_eq!(env.state_of("tx-a").await.0, RequestState::Approved);
    assert_eq!(env.state_of("tx-b").await.0, RequestState::Pending);
}

#[tokio::test]
async fn the_console_relays_no_decision_it_has_not_validated() {
    let mut env = env!();
    env.operator_with_key("alice", Role::RaOperateur).await;
    let cookie = env.log_in("alice").await;
    env.pending_request("tx-1").await;
    let (_, issued) = env.challenge(Some(&cookie), approve("tx-1")).await;
    let assertion = env.sign(&issued);
    let path = "/api/v1/requests/tx-1/approve";

    // Sans session.
    let (status, _) = env.decide(None, path, &issued, &assertion).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // Des corps que la console ne relaie pas : identifiant de challenge qui
    // n'est pas un UUID, assertion absente, et un corps d'action glissé en plus.
    for body in [
        serde_json::json!({ "challenge_id": "pas-un-uuid", "assertion": assertion }),
        serde_json::json!({ "challenge_id": issued["challenge_id"] }),
        serde_json::json!({ "challenge_id": issued["challenge_id"], "assertion": assertion, "body": approve("tx-1") }),
    ] {
        let (status, _, err) = env
            .post(path, body, Some(&cookie), "application/json")
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{err}");
    }
    let (status, _, _) = env
        .post(path, serde_json::json!({}), Some(&cookie), "text/plain")
        .await;
    assert_eq!(status, StatusCode::UNSUPPORTED_MEDIA_TYPE);

    // Rien n'a été décidé, et l'assertion reste utilisable.
    assert_eq!(env.state_of("tx-1").await.0, RequestState::Pending);
    let (status, done) = env.decide(Some(&cookie), path, &issued, &assertion).await;
    assert_eq!(status, StatusCode::OK, "{done}");
}

impl Env {
    /// Un certificat de TSU émis par la CA de test, et son numéro de série
    /// dans la forme canonique des corps signés (hexadécimal minuscule).
    async fn certificate(&self, tx: &str) -> String {
        let key = oe_hsm::testing::SoftwareToken::generate(2048);
        let cert = self
            .issuer
            .issue(
                &oe_hsm::SigningToken::public_key_der(&key).unwrap(),
                "tsu.example.test",
                &oe_ca_core::profile::tsa_signer(),
                tx,
            )
            .await
            .unwrap();
        oe_ca_core::canonical_serial(cert.tbs_certificate().serial_number())
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }

    async fn status_of(&self, serial: &str) -> oe_castore::CertificateStatus {
        let bytes: Vec<u8> = (0..serial.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&serial[i..i + 2], 16).unwrap())
            .collect();
        self.store.certificate(&bytes).await.unwrap().status
    }
}

fn revoke(serial: &str) -> serde_json::Value {
    serde_json::json!({ "action": "revoke_certificate", "serial": serial, "reason": 1, "comment": "clé exposée" })
}

/// Étape 4a : la première signature d'une révocation est enregistrée par
/// `ca-server`, mais rien n'est révoqué avant le second `ca_operateur` (§8) ;
/// la cible de la route est contrôlée comme pour les décisions.
#[tokio::test]
async fn one_ca_operator_alone_does_not_revoke() {
    let mut env = env!();
    env.operator_with_key("alice", Role::CaOperateur).await;
    env.operator_with_key("bob", Role::CaOperateur).await;
    let cookie = env.log_in("alice").await;
    let serial = env.certificate("tx-rev-1").await;
    let other = env.certificate("tx-rev-2").await;

    let (status, issued) = env.challenge(Some(&cookie), revoke(&serial)).await;
    assert_eq!(status, StatusCode::OK, "{issued}");
    assert_eq!(issued["required_signatures"], 2, "{issued}");
    let assertion = env.sign(&issued);

    // Présentée pour un autre certificat : refusée, rien de consommé.
    let (status, err) = env
        .decide(
            Some(&cookie),
            &format!("/api/v1/certificates/{other}/revoke"),
            &issued,
            &assertion,
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT, "{err}");
    assert_eq!(err["error"], "action_mismatch");

    let path = format!("/api/v1/certificates/{serial}/revoke");
    let (status, done) = env.decide(Some(&cookie), &path, &issued, &assertion).await;
    assert_eq!(status, StatusCode::OK, "{done}");
    assert_eq!(done["status"], "AWAITING_QUORUM", "{done}");
    assert_eq!(done["signatures"], 1);
    assert_eq!(done["required"], 2);
    assert_eq!(done["signed_by"], "alice");
    assert_eq!(
        env.status_of(&serial).await,
        oe_castore::CertificateStatus::Issued
    );
    assert_eq!(
        env.status_of(&other).await,
        oe_castore::CertificateStatus::Issued
    );

    // Un numéro de série hors de la forme canonique n'est pas relayé.
    for (label, bad) in [
        ("majuscules", serial.to_uppercase()),
        ("préfixe 0x", format!("0x{serial}")),
        ("non hexadécimal", "zz".to_string()),
    ] {
        let (status, _) = env
            .decide(
                Some(&cookie),
                &format!("/api/v1/certificates/{bad}/revoke"),
                &issued,
                &assertion,
            )
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{label}");
    }
}

/// La révocation est réservée aux `ca_operateur` : `ca-server` refuse d'en
/// préparer une pour un `ra_operateur`, la console relaie le refus.
#[tokio::test]
async fn an_ra_operator_cannot_prepare_a_revocation() {
    let mut env = env!();
    env.operator_with_key("alice", Role::RaOperateur).await;
    let cookie = env.log_in("alice").await;
    let serial = env.certificate("tx-rev").await;
    let (status, err) = env.challenge(Some(&cookie), revoke(&serial)).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{err}");
    assert_eq!(env.actions_frozen().await, 0);
}

impl Env {
    async fn get(&self, path: &str, cookie: &str) -> (StatusCode, serde_json::Value) {
        let res = self
            .console
            .clone()
            .oneshot(
                Request::get(path)
                    .header("cookie", cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = res.status();
        let bytes = res.into_body().collect().await.unwrap().to_bytes();
        (status, serde_json::from_slice(&bytes).unwrap_or_default())
    }

    /// Première signature d'une révocation par l'opérateur de `cookie` : rend
    /// l'identifiant de l'action figée.
    async fn first_signature(&mut self, cookie: &str, serial: &str) -> String {
        let (_, issued) = self.challenge(Some(cookie), revoke(serial)).await;
        let assertion = self.sign(&issued);
        let (status, done) = self
            .decide(
                Some(cookie),
                &format!("/api/v1/certificates/{serial}/revoke"),
                &issued,
                &assertion,
            )
            .await;
        assert_eq!(done["status"], "AWAITING_QUORUM", "{status} {done}");
        done["action_id"].as_str().unwrap().to_string()
    }
}

/// Étape 4b : deux `ca_operateur` distincts révoquent ensemble. La salle
/// d'attente lit l'état de `ca-server` ; une seconde signature du même
/// opérateur ne compte pas ; la dernière signature exécute, une seule fois.
#[tokio::test]
async fn two_distinct_ca_operators_revoke_together() {
    let mut env = env!();
    env.operator_with_key("alice", Role::CaOperateur).await;
    env.operator_with_key("bob", Role::CaOperateur).await;
    let alice = env.log_in("alice").await;
    let bob = env.log_in("bob").await;
    let serial = env.certificate("tx-quorum").await;
    let action_id = env.first_signature(&alice, &serial).await;

    let (status, waiting) = env.get("/api/v1/quorum?state=PENDING", &bob).await;
    assert_eq!(status, StatusCode::OK, "{waiting}");
    let waiting = waiting.as_array().unwrap();
    assert_eq!(waiting.len(), 1);
    assert_eq!(waiting[0]["action_id"], action_id.as_str());
    assert_eq!(waiting[0]["action"], "revoke_certificate");
    assert_eq!(waiting[0]["body"]["serial"], serial.as_str());
    assert_eq!(waiting[0]["signatures"], 1);
    assert_eq!(waiting[0]["required"], 2);
    assert_eq!(waiting[0]["signed_by"], serde_json::json!(["alice"]));

    // Alice ne peut pas signer une seconde fois sa propre action.
    let (status, err) = env
        .challenge(Some(&alice), serde_json::json!({ "action_id": action_id }))
        .await;
    if status == StatusCode::OK {
        let assertion = env.sign(&err);
        let (status, err) = env
            .decide(
                Some(&alice),
                &format!("/api/v1/quorum/{action_id}/sign"),
                &err,
                &assertion,
            )
            .await;
        assert!(status.is_client_error(), "{status} {err}");
    } else {
        assert!(status.is_client_error(), "{status} {err}");
    }
    assert_eq!(
        env.status_of(&serial).await,
        oe_castore::CertificateStatus::Issued
    );

    // Bob co-signe : la révocation s'exécute.
    let (status, issued) = env
        .challenge(Some(&bob), serde_json::json!({ "action_id": action_id }))
        .await;
    assert_eq!(status, StatusCode::OK, "{issued}");
    let assertion = env.sign(&issued);
    let (status, done) = env
        .decide(
            Some(&bob),
            &format!("/api/v1/quorum/{action_id}/sign"),
            &issued,
            &assertion,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{done}");
    assert_eq!(done["status"], "EXECUTED", "{done}");
    assert_eq!(done["signatures"], 2);
    assert_eq!(done["signed_by"], "bob");
    assert_eq!(
        env.status_of(&serial).await,
        oe_castore::CertificateStatus::Revoked
    );

    let (_, waiting) = env.get("/api/v1/quorum?state=PENDING", &bob).await;
    assert_eq!(waiting, serde_json::json!([]));
    // Une action exécutée ne se prépare plus.
    let (status, err) = env
        .challenge(Some(&bob), serde_json::json!({ "action_id": action_id }))
        .await;
    assert_eq!(status, StatusCode::CONFLICT, "{err}");
    assert_eq!(err["error"], "already_executed");
}

/// Une co-signature ne compte que pour l'action pour laquelle son challenge a
/// été émis : présentée pour une autre, elle est refusée sans rien consommer.
/// Les deux actions visent le même certificat : seul leur identifiant les
/// distingue, c'est bien lui qui est contrôlé.
#[tokio::test]
async fn a_co_signature_only_counts_for_its_action() {
    let mut env = env!();
    env.operator_with_key("alice", Role::CaOperateur).await;
    env.operator_with_key("bob", Role::CaOperateur).await;
    let alice = env.log_in("alice").await;
    let bob = env.log_in("bob").await;
    let x = env.certificate("tx-x").await;
    let action_x = env.first_signature(&alice, &x).await;
    let action_y = env.first_signature(&alice, &x).await;
    assert_ne!(action_x, action_y);

    let (_, issued) = env
        .challenge(Some(&bob), serde_json::json!({ "action_id": action_x }))
        .await;
    let assertion = env.sign(&issued);
    let (status, err) = env
        .decide(
            Some(&bob),
            &format!("/api/v1/quorum/{action_y}/sign"),
            &issued,
            &assertion,
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT, "{err}");
    assert_eq!(err["error"], "action_mismatch");
    assert_eq!(
        env.status_of(&x).await,
        oe_castore::CertificateStatus::Issued
    );

    let (status, done) = env
        .decide(
            Some(&bob),
            &format!("/api/v1/quorum/{action_x}/sign"),
            &issued,
            &assertion,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{done}");
    assert_eq!(done["action_id"], action_x.as_str());
    assert_eq!(
        env.status_of(&x).await,
        oe_castore::CertificateStatus::Revoked
    );

    // Une action inconnue, ou un identifiant qui n'en est pas un.
    for id in ["3f2b8c1e-9d4a-4e6b-8a7c-1234567890ab", "pas-un-uuid"] {
        let (status, err) = env
            .challenge(Some(&bob), serde_json::json!({ "action_id": id }))
            .await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{id} {err}");
    }
}

/// `GET /api/v1/certificates` (étape 6c) : les certificats émis, lus dans la
/// table de `ca-server`, avec leur numéro de série sous la forme canonique
/// qu'attend la révocation ; filtre par état ; rien sans session.
#[tokio::test]
async fn the_console_lists_issued_certificates() {
    let mut env = env!();
    env.operator_with_key("alice", Role::CaOperateur).await;
    env.operator_with_key("bob", Role::CaOperateur).await;
    let alice = env.log_in("alice").await;
    let bob = env.log_in("bob").await;
    let serial = env.certificate("tx-list").await;

    let (status, issued) = env.get("/api/v1/certificates?status=issued", &alice).await;
    assert_eq!(status, StatusCode::OK, "{issued}");
    let found = issued
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["serial_hex"] == serial.as_str())
        .unwrap_or_else(|| panic!("certificat émis absent de la liste : {issued}"));
    assert_eq!(found["profile"], "tsa_signer");
    assert_eq!(found["request_transaction_id"], "tx-list");

    // Révoqué par deux opérateurs : il change de liste.
    let action = env.first_signature(&alice, &serial).await;
    let (_, issued_c) = env
        .challenge(Some(&bob), serde_json::json!({ "action_id": action }))
        .await;
    let assertion = env.sign(&issued_c);
    env.decide(
        Some(&bob),
        &format!("/api/v1/quorum/{action}/sign"),
        &issued_c,
        &assertion,
    )
    .await;
    let (_, revoked) = env.get("/api/v1/certificates?status=revoked", &alice).await;
    let found = revoked
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["serial_hex"] == serial.as_str())
        .unwrap_or_else(|| panic!("certificat révoqué absent de la liste : {revoked}"));
    assert_eq!(found["revocation_reason"], 1);
    let (_, issued) = env.get("/api/v1/certificates?status=issued", &alice).await;
    assert!(issued
        .as_array()
        .unwrap()
        .iter()
        .all(|c| c["serial_hex"] != serial.as_str()));

    let (status, _) = env
        .get("/api/v1/certificates?status=reserved", &alice)
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, _) = env
        .get("/api/v1/certificates", "session=n-importe-quoi")
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

// --- Gestion du registre depuis la console (invitation, clés, rôles) ---

impl Env {
    /// Prépare `action`, la signe, et la relaie sur `path` : rend la réponse.
    async fn sign_and_send(
        &mut self,
        cookie: &str,
        action: serde_json::Value,
        path: &str,
    ) -> (StatusCode, serde_json::Value) {
        let (status, issued) = self.challenge(Some(cookie), action).await;
        assert_eq!(status, StatusCode::OK, "{issued}");
        let assertion = self.sign(&issued);
        self.decide(Some(cookie), path, &issued, &assertion).await
    }

    async fn role_of(&self, name: &str) -> String {
        sqlx::query_scalar("SELECT role FROM operators WHERE name = $1")
            .bind(name)
            .fetch_one(self.registry.pool())
            .await
            .unwrap()
    }

    async fn key_revoked(&self, credential_id: &str) -> bool {
        sqlx::query_scalar(
            "SELECT revoked_at IS NOT NULL FROM webauthn_credentials WHERE credential_id = $1",
        )
        .bind(credential_id)
        .fetch_one(self.registry.pool())
        .await
        .unwrap()
    }

    /// Une seconde clé pour un opérateur existant, posée dans le registre.
    async fn second_key(&mut self, operator: Uuid, name: &str) -> String {
        let before = self.credential_ids(operator).await;
        let now = time::OffsetDateTime::now_utc();
        let (options, state) = self
            .verifier
            .start_registration(operator, name, None)
            .unwrap();
        let reg = self.authn.do_registration(origin(), options).unwrap();
        let key = self.verifier.finish_registration(&reg, &state).unwrap();
        self.registry
            .add_credential(
                NewCredential {
                    operator_id: operator,
                    passkey: &key,
                    aaguid: AAGUID,
                    attestation_format: "packed",
                    attestation_object: reg.response.attestation_object.as_ref(),
                    label: "secours",
                    initiated_by: "test",
                    confirmed_by: Some("test"),
                },
                now,
            )
            .await
            .unwrap();
        self.credential_ids(operator)
            .await
            .into_iter()
            .find(|k| !before.contains(k))
            .unwrap()
    }
}

/// Un administrateur invite un opérateur par la console : le jeton n'est rendu
/// qu'une fois, dans la réponse, et ne figure dans aucun journal de la console.
/// L'invité enregistre sa clé par le relais existant ; l'administrateur la
/// confirme en signant son empreinte, transmise hors bande (§10).
#[tokio::test]
async fn an_admin_invites_and_confirms_an_operator_through_the_console() {
    let mut env = env!();
    env.operator_with_key("root", Role::Admin).await;
    let admin = env.log_in("root").await;

    let invite =
        serde_json::json!({ "action": "invite_operator", "name": "eve", "role": "ra_operateur" });
    let (status, done) = env.sign_and_send(&admin, invite, "/api/v1/operators").await;
    assert_eq!(status, StatusCode::OK, "{done}");
    assert_eq!(done["status"], "EXECUTED", "{done}");
    let token = done["result"]["invite_token"].as_str().unwrap().to_string();
    assert!(token.len() > 30);
    assert_eq!(env.role_of("eve").await, "ra_operateur");
    let journal = env.journal.0.lock().unwrap().join("\n");
    assert!(journal.contains("ra.action_relayed"), "{journal}");
    assert!(
        !journal.contains(&token),
        "le jeton est journalisé : {journal}"
    );

    // L'invitée enregistre sa clé : elle attend la confirmation d'un tiers.
    let (_, _, begun) = env
        .post(
            "/api/v1/webauthn/register/begin",
            serde_json::json!({ "token": token }),
            None,
            "application/json",
        )
        .await;
    let options: oe_webauthn::CreationChallengeResponse =
        serde_json::from_value(serde_json::json!({ "publicKey": begun["webauthn"] })).unwrap();
    let credential = env.authn.do_registration(origin(), options).unwrap();
    let (status, _, pending) = env
        .post(
            "/api/v1/webauthn/register/finish",
            serde_json::json!({ "ceremony_id": begun["ceremony_id"], "credential": credential }),
            None,
            "application/json",
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{pending}");
    assert_eq!(pending["status"], "pending_confirmation", "{pending}");
    let credential_id = pending["credential_id"].as_str().unwrap().to_string();

    // La console montre la clé en attente, avec l'empreinte même que ca-server a
    // remise à l'invitée : c'est elle que l'administrateur compare hors bande.
    let (status, registry) = env.get("/api/v1/operators", &admin).await;
    assert_eq!(status, StatusCode::OK, "{registry}");
    let shown = registry["pending"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["credential_id"] == credential_id.as_str())
        .unwrap_or_else(|| panic!("clé en attente absente : {registry}"));
    assert_eq!(shown["operator"], "eve");
    assert_eq!(shown["key_fingerprint"], pending["key_fingerprint"]);

    let confirm = serde_json::json!({
        "action": "confirm_key",
        "credential_id": credential_id,
        "key_fingerprint": pending["key_fingerprint"],
    });
    let (status, done) = env
        .sign_and_send(
            &admin,
            confirm,
            &format!("/api/v1/credentials/{credential_id}/confirm"),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{done}");
    assert_eq!(done["status"], "EXECUTED", "{done}");
    // La clé est active : l'invitée peut se connecter.
    let eve = env.log_in("eve").await;
    assert!(eve.starts_with("session="));
    let (_, registry) = env.get("/api/v1/operators", &admin).await;
    assert_eq!(registry["pending"], serde_json::json!([]), "{registry}");
    let eve_entry = registry["operators"]
        .as_array()
        .unwrap()
        .iter()
        .find(|o| o["name"] == "eve")
        .unwrap();
    assert_eq!(eve_entry["credentials"].as_array().unwrap().len(), 1);
    let (status, _) = env.get("/api/v1/operators", "session=n-importe-quoi").await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

/// Révocation d'une clé : la cible de la route est contrôlée par ca-server.
/// Les deux clés appartiennent au même opérateur et l'action est la même :
/// seul l'identifiant de la clé distingue, c'est bien lui qui est comparé.
#[tokio::test]
async fn a_key_revocation_only_revokes_the_signed_key() {
    let mut env = env!();
    env.operator_with_key("root", Role::Admin).await;
    let carol = env.operator_with_key("carol", Role::RaOperateur).await;
    let k1 = env.credential_ids(carol).await.remove(0);
    let k2 = env.second_key(carol, "carol").await;
    assert_ne!(k1, k2);
    let admin = env.log_in("root").await;

    let (_, issued) = env
        .challenge(
            Some(&admin),
            serde_json::json!({ "action": "revoke_key", "credential_id": k1, "reason": "perdue" }),
        )
        .await;
    let assertion = env.sign(&issued);
    let (status, err) = env
        .decide(
            Some(&admin),
            &format!("/api/v1/credentials/{k2}/revoke"),
            &issued,
            &assertion,
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT, "{err}");
    assert_eq!(err["error"], "action_mismatch");
    assert!(!env.key_revoked(&k1).await && !env.key_revoked(&k2).await);

    let (status, done) = env
        .decide(
            Some(&admin),
            &format!("/api/v1/credentials/{k1}/revoke"),
            &issued,
            &assertion,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{done}");
    assert_eq!(done["status"], "EXECUTED");
    assert!(env.key_revoked(&k1).await);
    assert!(!env.key_revoked(&k2).await);

    // Un identifiant de clé hors de la forme base64url n'est pas relayé.
    let (status, _) = env
        .decide(
            Some(&admin),
            "/api/v1/credentials/cl%C3%A9%20invalide/revoke",
            &issued,
            &assertion,
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

/// Changement de rôle : la cible (l'opérateur, par son nom) est contrôlée ;
/// élever au rôle admin exige deux administrateurs (co-signature par la salle
/// d'attente).
#[tokio::test]
async fn role_changes_target_the_signed_operator_and_admin_needs_two() {
    let mut env = env!();
    env.operator_with_key("root", Role::Admin).await;
    env.operator_with_key("root2", Role::Admin).await;
    env.operator_with_key("carol", Role::RaOperateur).await;
    env.operator_with_key("dave", Role::RaOperateur).await;
    let admin = env.log_in("root").await;

    // Même action, même rôle : seul l'opérateur visé distingue.
    let (_, issued) = env
        .challenge(
            Some(&admin),
            serde_json::json!({ "action": "set_role", "operator": "carol", "role": "auditeur" }),
        )
        .await;
    let assertion = env.sign(&issued);
    let (status, err) = env
        .decide(
            Some(&admin),
            "/api/v1/operators/dave/role",
            &issued,
            &assertion,
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT, "{err}");
    assert_eq!(err["error"], "action_mismatch");
    let (status, done) = env
        .decide(
            Some(&admin),
            "/api/v1/operators/carol/role",
            &issued,
            &assertion,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{done}");
    assert_eq!(env.role_of("carol").await, "auditeur");
    assert_eq!(env.role_of("dave").await, "ra_operateur");

    // Élever dave au rôle admin : une signature ne suffit pas.
    let (status, done) = env
        .sign_and_send(
            &admin,
            serde_json::json!({ "action": "set_role", "operator": "dave", "role": "admin" }),
            "/api/v1/operators/dave/role",
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{done}");
    assert_eq!(done["status"], "AWAITING_QUORUM", "{done}");
    assert_eq!(env.role_of("dave").await, "ra_operateur");
    let action_id = done["action_id"].as_str().unwrap().to_string();

    let second = env.log_in("root2").await;
    let (status, issued) = env
        .challenge(Some(&second), serde_json::json!({ "action_id": action_id }))
        .await;
    assert_eq!(status, StatusCode::OK, "{issued}");
    let assertion = env.sign(&issued);
    let (status, done) = env
        .decide(
            Some(&second),
            &format!("/api/v1/quorum/{action_id}/sign"),
            &issued,
            &assertion,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{done}");
    assert_eq!(done["status"], "EXECUTED", "{done}");
    assert_eq!(env.role_of("dave").await, "admin");
}
