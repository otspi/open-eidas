//! Vérifie `oe_actions::Service` contre un vrai PostgreSQL et un
//! authentificateur logiciel réel (`SoftToken`) : c'est la preuve exécutable
//! que la faille R2a est fermée (docs/WEBUI.md §16, §19). Aucune décision ne
//! s'applique sans une signature valide, neuve, d'un opérateur habilité, lu
//! dans le registre.
//!
//! DSN dans `OE_CASTORE_TEST_DSN` ; test ignoré si elle n'est pas définie.

use oe_actions::{Action, Error, Issued, NewCredential, Registry, Role, Service};
use oe_castore::{Postgres, Request, RequestState, Store};
use oe_raflow::{Decider, DeciderOptions, Recorder};
use oe_webauthn::{trusted_models, PublicKeyCredential, TrustedModel, Url, Uuid, Verifier};
use sha2::{Digest, Sha256};
use sqlx::postgres::PgPoolOptions;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use time::OffsetDateTime;
use webauthn_authenticator_rs::softtoken::{SoftToken, AAGUID};
use webauthn_authenticator_rs::WebauthnAuthenticator;

static SEQ: AtomicU64 = AtomicU64::new(0);

fn unique(prefix: &str) -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!("{prefix}-{nanos}-{}", SEQ.fetch_add(1, Ordering::Relaxed))
}

fn origin() -> Url {
    Url::parse("https://console.example.com").unwrap()
}

#[derive(Default)]
struct MemJournal {
    events: Mutex<Vec<(String, serde_json::Value)>>,
    fail: AtomicBool,
}

#[async_trait::async_trait]
impl Recorder for MemJournal {
    async fn append(&self, event: &str, data: serde_json::Value) -> Result<(), String> {
        if self.fail.load(Ordering::SeqCst) {
            return Err("disque plein".to_string());
        }
        self.events.lock().unwrap().push((event.to_string(), data));
        Ok(())
    }
}

impl MemJournal {
    fn names(&self) -> Vec<String> {
        self.events
            .lock()
            .unwrap()
            .iter()
            .map(|(n, _)| n.clone())
            .collect()
    }

    fn find(&self, name: &str) -> Option<serde_json::Value> {
        self.events
            .lock()
            .unwrap()
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, d)| d.clone())
    }
}

struct Env {
    svc: Arc<Service>,
    registry: Registry,
    store: Arc<dyn Store>,
    decider: Arc<Decider>,
    journal: Arc<MemJournal>,
    authn: WebauthnAuthenticator<SoftToken>,
    verifier: Verifier,
    now: Arc<Mutex<OffsetDateTime>>,
}

/// Un opérateur inscrit, avec sa clé.
struct Op {
    id: Uuid,
    name: String,
    credential_id: String,
}

impl Env {
    async fn new() -> Option<Env> {
        let dsn = std::env::var("OE_CASTORE_TEST_DSN").ok()?;
        // Ouvre le magasin pour appliquer les migrations, comme en production.
        let pg = Postgres::open(&dsn).await.expect("connexion et migration");
        let store: Arc<dyn Store> = Arc::new(pg);
        let pool = PgPoolOptions::new()
            .max_connections(8)
            .connect(&dsn)
            .await
            .expect("pool de test");
        let registry = Registry::new(pool);

        let (token, root) = SoftToken::new(true).expect("SoftToken");
        let root_pem = root.to_pem().unwrap();
        let models = |pem: &[u8]| {
            trusted_models(&[TrustedModel {
                root_pem: pem,
                aaguid: AAGUID,
                description: "SoftToken (test)",
            }])
            .unwrap()
        };
        let make_verifier = || {
            Verifier::new(
                "console.example.com",
                &origin(),
                "Open eIDAS Console — test",
                models(&root_pem),
            )
            .unwrap()
        };

        let journal = Arc::new(MemJournal::default());
        let decider = Arc::new(Decider::new(DeciderOptions {
            store: store.clone(),
            recorder: Some(journal.clone() as Arc<dyn Recorder>),
            clock: None,
        }));
        let now = Arc::new(Mutex::new(OffsetDateTime::now_utc()));
        let clock_now = now.clone();
        let svc = Arc::new(Service::new(
            registry.clone(),
            make_verifier(),
            store.clone(),
            // Second décideur, même magasin : Service en possède un, les
            // tests en gardent un pour simuler une décision concurrente.
            Decider::new(DeciderOptions {
                store: store.clone(),
                recorder: Some(journal.clone() as Arc<dyn Recorder>),
                clock: None,
            }),
            journal.clone() as Arc<dyn Recorder>,
            Arc::new(move || *clock_now.lock().unwrap()),
        ));
        Some(Env {
            svc,
            registry,
            store,
            decider,
            journal,
            authn: WebauthnAuthenticator::new(token),
            verifier: make_verifier(),
            now,
        })
    }

    /// Inscrit un opérateur et une clé attestée, comme le fera l'onboarding.
    async fn operator(&mut self, role: Role) -> Op {
        let name = unique("op");
        let now = *self.now.lock().unwrap();
        let id = self
            .registry
            .add_operator(&name, role, "test-admin", now)
            .await
            .unwrap();
        let (options, state) = self.verifier.start_registration(id, &name, None).unwrap();
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
                    initiated_by: "test-admin",
                    confirmed_by: Some("test-admin"),
                },
                now,
            )
            .await
            .unwrap();
        Op {
            id,
            name,
            credential_id: oe_actions::credential_id(key.cred_id().as_ref()),
        }
    }

    /// Une demande d'enrôlement en attente de décision.
    async fn pending_request(&self) -> Request {
        let r = Request {
            transaction_id: unique("tx"),
            csr_fingerprint: unique("fp"),
            csr_der: vec![1, 2, 3],
            profile: "tsa_signer".to_string(),
            subject_cn: "Unité de test".to_string(),
            state: RequestState::Pending,
            created_at: OffsetDateTime::now_utc(),
            decided_at: None,
            operator: String::new(),
            comment: String::new(),
            issued_at: None,
            certificate_serial: None,
        };
        self.store.create_request(r.clone()).await.unwrap();
        r
    }

    async fn state_of(&self, r: &Request) -> RequestState {
        self.store
            .request_by_transaction_id(&r.transaction_id)
            .await
            .unwrap()
            .state
    }

    fn approve(r: &Request) -> Action {
        Action::ApproveRequest {
            transaction_id: r.transaction_id.clone(),
            csr_fingerprint: None,
            comment: "identité vérifiée".to_string(),
        }
    }

    fn sign(&mut self, issued: &Issued) -> PublicKeyCredential {
        self.authn
            .do_authentication(origin(), issued.options.clone())
            .expect("l'authentificateur signe")
    }

    fn advance(&self, by: time::Duration) {
        *self.now.lock().unwrap() += by;
    }

    async fn count(&self, sql: &str, id: Uuid) -> i64 {
        sqlx::query_scalar(sql)
            .bind(id)
            .fetch_one(self.registry.pool())
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

#[tokio::test]
async fn an_approval_signed_by_an_authorised_operator_is_executed() {
    let mut env = env!();
    let alice = env.operator(Role::RaOperateur).await;
    let r = env.pending_request().await;

    let issued = env
        .svc
        .issue_challenge(Env::approve(&r), alice.id)
        .await
        .unwrap();
    let assertion = env.sign(&issued);
    let done = env
        .svc
        .execute(issued.challenge_id, &assertion)
        .await
        .unwrap();

    // L'identité vient du registre, pas de l'appelant.
    assert_eq!(done.operator, alice.name);
    assert_eq!(done.role, Role::RaOperateur);
    let stored = env
        .store
        .request_by_transaction_id(&r.transaction_id)
        .await
        .unwrap();
    assert_eq!(stored.state, RequestState::Approved);
    assert_eq!(stored.operator, alice.name);

    // La preuve est conservée : une ligne, pour cette action.
    let n = env
        .count(
            "SELECT count(*) FROM decision_evidence WHERE action_id = $1",
            issued.action_id,
        )
        .await;
    assert_eq!(n, 1);

    // Le lien challenge → corps est au journal, écrit AVANT la signature, et
    // les octets journalisés se re-hachent en body_hash.
    let names = env.journal.names();
    let issued_at = names
        .iter()
        .position(|n| n == "operators.action_challenge_issued")
        .expect("challenge journalisé");
    let executed_at = names
        .iter()
        .position(|n| n == "operators.action_executed")
        .expect("exécution journalisée");
    assert!(issued_at < executed_at);
    let entry = env
        .journal
        .find("operators.action_challenge_issued")
        .unwrap();
    let canonical = entry["body"].as_str().unwrap();
    assert_eq!(
        hex::encode(Sha256::digest(canonical.as_bytes())),
        issued.body_hash
    );
}

#[tokio::test]
async fn a_signature_cannot_be_replayed() {
    let mut env = env!();
    let alice = env.operator(Role::RaOperateur).await;
    let r = env.pending_request().await;
    let issued = env
        .svc
        .issue_challenge(Env::approve(&r), alice.id)
        .await
        .unwrap();
    let assertion = env.sign(&issued);

    env.svc
        .execute(issued.challenge_id, &assertion)
        .await
        .unwrap();
    assert!(matches!(
        env.svc.execute(issued.challenge_id, &assertion).await,
        Err(Error::AlreadyUsed)
    ));
}

#[tokio::test]
async fn concurrent_executions_of_one_signature_run_only_once() {
    let mut env = env!();
    let alice = env.operator(Role::RaOperateur).await;
    let r = env.pending_request().await;
    let issued = env
        .svc
        .issue_challenge(Env::approve(&r), alice.id)
        .await
        .unwrap();
    let assertion = env.sign(&issued);

    let (s1, s2) = (env.svc.clone(), env.svc.clone());
    let (a1, a2) = (assertion.clone(), assertion);
    let id = issued.challenge_id;
    let (r1, r2) = tokio::join!(
        tokio::spawn(async move { s1.execute(id, &a1).await }),
        tokio::spawn(async move { s2.execute(id, &a2).await }),
    );
    let outcomes = [r1.unwrap().is_ok(), r2.unwrap().is_ok()];
    assert_eq!(outcomes.iter().filter(|ok| **ok).count(), 1, "{outcomes:?}");
    assert_eq!(env.state_of(&r).await, RequestState::Approved);
}

#[tokio::test]
async fn the_signed_action_affects_only_its_own_request() {
    let mut env = env!();
    let alice = env.operator(Role::RaOperateur).await;
    let (x, y) = (env.pending_request().await, env.pending_request().await);
    let issued = env
        .svc
        .issue_challenge(Env::approve(&x), alice.id)
        .await
        .unwrap();
    let assertion = env.sign(&issued);
    env.svc
        .execute(issued.challenge_id, &assertion)
        .await
        .unwrap();

    assert_eq!(env.state_of(&x).await, RequestState::Approved);
    assert_eq!(env.state_of(&y).await, RequestState::Pending);
}

#[tokio::test]
async fn roles_that_cannot_decide_get_no_challenge() {
    let mut env = env!();
    let r = env.pending_request().await;
    for role in [Role::Auditeur, Role::Admin] {
        let op = env.operator(role).await;
        assert!(
            matches!(
                env.svc.issue_challenge(Env::approve(&r), op.id).await,
                Err(Error::Denied(_))
            ),
            "{role:?}"
        );
    }
    assert_eq!(env.state_of(&r).await, RequestState::Pending);
}

#[tokio::test]
async fn a_role_downgrade_between_issue_and_execute_is_honoured() {
    let mut env = env!();
    let alice = env.operator(Role::RaOperateur).await;
    let r = env.pending_request().await;
    let issued = env
        .svc
        .issue_challenge(Env::approve(&r), alice.id)
        .await
        .unwrap();
    let assertion = env.sign(&issued);

    env.registry
        .set_role(alice.id, Role::Auditeur)
        .await
        .unwrap();

    assert!(matches!(
        env.svc.execute(issued.challenge_id, &assertion).await,
        Err(Error::Denied(_))
    ));
    assert_eq!(env.state_of(&r).await, RequestState::Pending);
}

#[tokio::test]
async fn a_revoked_key_cannot_execute() {
    let mut env = env!();
    let alice = env.operator(Role::RaOperateur).await;
    let r = env.pending_request().await;
    let issued = env
        .svc
        .issue_challenge(Env::approve(&r), alice.id)
        .await
        .unwrap();
    let assertion = env.sign(&issued);

    let now = *env.now.lock().unwrap();
    env.registry
        .revoke_key(&alice.credential_id, "test-admin", "perdue", now)
        .await
        .unwrap();

    assert!(matches!(
        env.svc.execute(issued.challenge_id, &assertion).await,
        Err(Error::Denied(_))
    ));
    assert_eq!(env.state_of(&r).await, RequestState::Pending);
}

#[tokio::test]
async fn an_expired_challenge_is_refused() {
    let mut env = env!();
    let alice = env.operator(Role::RaOperateur).await;
    let r = env.pending_request().await;
    let issued = env
        .svc
        .issue_challenge(Env::approve(&r), alice.id)
        .await
        .unwrap();
    let assertion = env.sign(&issued);

    env.advance(oe_actions::CHALLENGE_TTL + time::Duration::seconds(1));

    assert!(matches!(
        env.svc.execute(issued.challenge_id, &assertion).await,
        Err(Error::Expired)
    ));
    assert_eq!(env.state_of(&r).await, RequestState::Pending);
}

#[tokio::test]
async fn an_assertion_for_another_challenge_is_refused() {
    let mut env = env!();
    let alice = env.operator(Role::RaOperateur).await;
    let (x, y) = (env.pending_request().await, env.pending_request().await);
    let for_x = env
        .svc
        .issue_challenge(Env::approve(&x), alice.id)
        .await
        .unwrap();
    let for_y = env
        .svc
        .issue_challenge(Env::approve(&y), alice.id)
        .await
        .unwrap();
    let signed_for_x = env.sign(&for_x);

    // On présente la signature de X sur le challenge de Y.
    assert!(matches!(
        env.svc.execute(for_y.challenge_id, &signed_for_x).await,
        Err(Error::Verification(_))
    ));
    assert_eq!(env.state_of(&y).await, RequestState::Pending);
    assert_eq!(env.state_of(&x).await, RequestState::Pending);
}

#[tokio::test]
async fn a_journal_failure_prevents_any_challenge() {
    let mut env = env!();
    let alice = env.operator(Role::RaOperateur).await;
    let r = env.pending_request().await;

    env.journal.fail.store(true, Ordering::SeqCst);
    let res = env.svc.issue_challenge(Env::approve(&r), alice.id).await;
    assert!(matches!(res, Err(Error::Journal(_))));

    // Restreint à la demande de ce test : les autres tests tournent en
    // parallèle sur la même base et créent leurs propres actions.
    let created: i64 =
        sqlx::query_scalar("SELECT count(*) FROM actions WHERE body->>'transaction_id' = $1")
            .bind(&r.transaction_id)
            .fetch_one(env.registry.pool())
            .await
            .unwrap();
    assert_eq!(created, 0, "aucune action ne doit exister sans journal");
}

#[tokio::test]
async fn a_request_decided_meanwhile_is_not_overwritten() {
    let mut env = env!();
    let alice = env.operator(Role::RaOperateur).await;
    let r = env.pending_request().await;
    let issued = env
        .svc
        .issue_challenge(Env::approve(&r), alice.id)
        .await
        .unwrap();
    let assertion = env.sign(&issued);

    // Un autre chemin (le CLI de secours) rejette la demande entre-temps.
    env.decider
        .reject(
            &r.transaction_id,
            "cli",
            "refusée par le secours",
            &oe_raflow::Via::Cli(oe_raflow::SystemIdentity::current()),
        )
        .await
        .unwrap();

    assert!(matches!(
        env.svc.execute(issued.challenge_id, &assertion).await,
        Err(Error::Denied(_))
    ));
    assert_eq!(env.state_of(&r).await, RequestState::Rejected);
}

#[tokio::test]
async fn the_csr_fingerprint_shown_to_the_operator_must_be_the_requests() {
    let mut env = env!();
    let alice = env.operator(Role::RaOperateur).await;
    let r = env.pending_request().await;

    let wrong = Action::ApproveRequest {
        transaction_id: r.transaction_id.clone(),
        csr_fingerprint: Some("0000".to_string()),
        comment: "x".to_string(),
    };
    assert!(matches!(
        env.svc.issue_challenge(wrong, alice.id).await,
        Err(Error::Denied(_))
    ));

    let right = Action::ApproveRequest {
        transaction_id: r.transaction_id.clone(),
        csr_fingerprint: Some(r.csr_fingerprint.clone()),
        comment: "x".to_string(),
    };
    env.svc
        .issue_challenge(right, alice.id)
        .await
        .expect("empreinte correcte");
}

#[tokio::test]
async fn a_rejection_needs_a_written_reason() {
    let mut env = env!();
    let alice = env.operator(Role::RaOperateur).await;
    let r = env.pending_request().await;
    let silent = Action::RejectRequest {
        transaction_id: r.transaction_id.clone(),
        comment: "  ".to_string(),
    };
    assert!(matches!(
        env.svc.issue_challenge(silent, alice.id).await,
        Err(Error::BadRequest(_))
    ));
}

#[tokio::test]
async fn a_counter_that_goes_backwards_blocks_the_key() {
    let mut env = env!();
    let alice = env.operator(Role::RaOperateur).await;
    let r = env.pending_request().await;

    // Le registre a déjà vu un compteur très supérieur : la clé a été clonée.
    sqlx::query("UPDATE webauthn_credentials SET sign_count = 1000000 WHERE credential_id = $1")
        .bind(&alice.credential_id)
        .execute(env.registry.pool())
        .await
        .unwrap();

    let issued = env
        .svc
        .issue_challenge(Env::approve(&r), alice.id)
        .await
        .unwrap();
    let assertion = env.sign(&issued);
    assert!(matches!(
        env.svc.execute(issued.challenge_id, &assertion).await,
        Err(Error::Verification(_))
    ));
    assert_eq!(env.state_of(&r).await, RequestState::Pending);
}
