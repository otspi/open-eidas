//! Le lien interne HTTP (docs/WEBUI.md §5, §16) contre un vrai PostgreSQL et un
//! authentificateur logiciel : challenge, signature, exécution, et les refus
//! avec leurs codes. `oe-actions` prouve la logique ; ici on prouve ce que voit
//! l'appelant HTTP.
//!
//! DSN dans `OE_CASTORE_TEST_DSN` ; test ignoré si elle n'est pas définie.

use axum::body::Body;
use axum::http::{Request as HttpRequest, StatusCode};
use http_body_util::BodyExt;
use oe_actions::{NewCredential, Registry, Role, Service};
use oe_castore::{Postgres, Request, RequestState, Store};
use oe_raflow::{Decider, DeciderOptions, Recorder};
use oe_webauthn::{trusted_models, TrustedModel, Url, Uuid, Verifier};
use std::sync::Arc;
use time::OffsetDateTime;
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

fn origin() -> Url {
    Url::parse("https://console.example.com").unwrap()
}

fn unique(prefix: &str) -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!("{prefix}-{nanos}_{}_{}", std::process::id(), {
        static SEQ: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    })
}

async fn call(
    app: &axum::Router,
    path: &str,
    body: serde_json::Value,
) -> (StatusCode, serde_json::Value) {
    let res = app
        .clone()
        .oneshot(
            HttpRequest::post(path)
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = res.status();
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    (status, serde_json::from_slice(&bytes).unwrap_or_default())
}

#[tokio::test]
async fn an_action_goes_through_the_two_routes() {
    let Ok(dsn) = std::env::var("OE_CASTORE_TEST_DSN") else {
        eprintln!("OE_CASTORE_TEST_DSN non définie : test PostgreSQL ignoré");
        return;
    };
    let pg = Postgres::open(&dsn).await.unwrap();
    let store: Arc<dyn Store> = Arc::new(pg);
    let registry = Registry::connect(&dsn).await.unwrap();

    let (token, root) = SoftToken::new(true).unwrap();
    let root_pem = root.to_pem().unwrap();
    let verifier = || {
        Verifier::new(
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
        .unwrap()
    };
    let journal: Arc<dyn Recorder> = Arc::new(NullJournal);
    let service = Arc::new(Service::new(
        registry.clone(),
        verifier(),
        store.clone(),
        Decider::new(DeciderOptions {
            store: store.clone(),
            recorder: Some(journal.clone()),
            clock: None,
        }),
        journal,
        Arc::new(OffsetDateTime::now_utc),
    ));
    let app = ca_server::internal::router(service, 64 * 1024);

    // Un opérateur RA avec une clé attestée.
    let mut authn = WebauthnAuthenticator::new(token);
    let name = unique("alice");
    let now = OffsetDateTime::now_utc();
    let op = registry
        .add_operator(&name, Role::RaOperateur, "test-admin", now)
        .await
        .unwrap();
    let v = verifier();
    let (options, state) = v.start_registration(op, &name, None).unwrap();
    let reg = authn.do_registration(origin(), options).unwrap();
    let key = v.finish_registration(&reg, &state).unwrap();
    registry
        .add_credential(
            NewCredential {
                operator_id: op,
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

    let tx = unique("tx");
    store
        .create_request(Request {
            transaction_id: tx.clone(),
            csr_fingerprint: unique("fp"),
            csr_der: vec![1, 2, 3],
            profile: "tsa_signer".to_string(),
            subject_cn: "Unité de test".to_string(),
            state: RequestState::Pending,
            created_at: now,
            decided_at: None,
            operator: String::new(),
            comment: String::new(),
            issued_at: None,
            certificate_serial: None,
        })
        .await
        .unwrap();

    // Le lien répond (sondé par ra-console) sans rien exécuter.
    let res = app
        .clone()
        .oneshot(
            HttpRequest::get("/internal/v1/ping")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    // 1. Challenge : le corps est figé par ca-server.
    let (status, issued) = call(
        &app,
        "/internal/v1/challenge",
        serde_json::json!({
            "body": {"action": "approve_request", "transaction_id": tx, "comment": "ok"},
            "operator_hint": op,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{issued}");
    assert_eq!(issued["body"]["transaction_id"], tx);
    assert!(issued["body"]["expires_at"].is_string());
    assert_eq!(issued["body_hash"].as_str().unwrap().len(), 64);
    let challenge_id = issued["challenge_id"].as_str().unwrap().to_string();

    // 2. L'opérateur signe les options WebAuthn renvoyées telles quelles.
    let options: oe_webauthn::RequestChallengeResponse =
        serde_json::from_value(serde_json::json!({ "publicKey": issued["webauthn"] })).unwrap();
    let assertion = authn.do_authentication(origin(), options).unwrap();

    // Une assertion sans challenge connu : refusée, rien ne s'exécute.
    let (status, err) = call(
        &app,
        "/internal/v1/actions",
        serde_json::json!({"challenge_id": Uuid::new_v4(), "assertion": assertion}),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{err}");
    assert_eq!(err["error"], "unknown_challenge");

    // Un corps glissé dans la requête d'exécution est refusé, pas ignoré.
    let (status, _) = call(
        &app,
        "/internal/v1/actions",
        serde_json::json!({
            "challenge_id": challenge_id, "assertion": assertion,
            "body": {"action": "approve_request", "transaction_id": "autre", "comment": "x"},
        }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(
        store.request_by_transaction_id(&tx).await.unwrap().state,
        RequestState::Pending
    );

    // 3. Exécution : l'identité renvoyée vient du registre.
    let (status, done) = call(
        &app,
        "/internal/v1/actions",
        serde_json::json!({"challenge_id": challenge_id, "assertion": assertion}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{done}");
    assert_eq!(done["operator"], name);
    assert_eq!(done["role"], "ra_operateur");
    assert_eq!(done["status"], "executed");
    assert_eq!(
        (done["signatures"].as_u64(), done["required"].as_u64()),
        (Some(1), Some(1))
    );
    assert_eq!(
        store.request_by_transaction_id(&tx).await.unwrap().state,
        RequestState::Approved
    );

    // Rejeu : la même signature ne sert pas deux fois.
    let (status, err) = call(
        &app,
        "/internal/v1/actions",
        serde_json::json!({"challenge_id": challenge_id, "assertion": assertion}),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{err}");
    assert_eq!(err["error"], "already_used");

    // Un opérateur inconnu n'obtient pas de challenge.
    let (status, err) = call(
        &app,
        "/internal/v1/challenge",
        serde_json::json!({
            "body": {"action": "reject_request", "transaction_id": tx, "comment": "non"},
            "operator_hint": Uuid::new_v4(),
        }),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{err}");

    // `body` et `action_id` s'excluent : on ne choisit pas un corps par-dessus
    // une action déjà figée, et il faut l'un des deux.
    for bad in [
        serde_json::json!({
            "body": {"action": "reject_request", "transaction_id": tx, "comment": "non"},
            "action_id": Uuid::new_v4(), "operator_hint": op,
        }),
        serde_json::json!({"operator_hint": op}),
    ] {
        let (status, err) = call(&app, "/internal/v1/challenge", bad).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{err}");
    }
    // Une action figée inconnue ne reçoit aucun signataire.
    let (status, _) = call(
        &app,
        "/internal/v1/challenge",
        serde_json::json!({"action_id": Uuid::new_v4(), "operator_hint": op}),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // Une action hors de l'énumération fermée ne peut pas être demandée.
    let (status, _) = call(
        &app,
        "/internal/v1/challenge",
        serde_json::json!({"body": {"action": "drop_everything"}, "operator_hint": op}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

/// L'enregistrement de la clé du premier administrateur, par les deux routes.
/// Base neuve : l'amorçage refuse dès qu'un administrateur actif existe.
#[tokio::test]
async fn the_bootstrap_admin_registers_a_key_through_the_routes() {
    let Ok(base) = std::env::var("OE_CASTORE_TEST_DSN") else {
        eprintln!("OE_CASTORE_TEST_DSN non définie : test PostgreSQL ignoré");
        return;
    };
    let name = unique("reg").replace('-', "_");
    let admin = sqlx::postgres::PgPoolOptions::new()
        .connect(&base)
        .await
        .unwrap();
    sqlx::query(&format!("CREATE DATABASE {name}"))
        .execute(&admin)
        .await
        .unwrap();
    let dsn = format!("{}/{name}", base.rsplit_once('/').unwrap().0);
    let store: Arc<dyn Store> = Arc::new(Postgres::open(&dsn).await.unwrap());
    let registry = Registry::connect(&dsn).await.unwrap();

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
    let service = Arc::new(Service::new(
        registry.clone(),
        verifier,
        store.clone(),
        Decider::new(DeciderOptions {
            store,
            recorder: None,
            clock: None,
        }),
        journal.clone(),
        Arc::new(OffsetDateTime::now_utc),
    ));
    let app = ca_server::internal::router(service, 64 * 1024);
    let invite = oe_actions::bootstrap_admin(
        &registry,
        journal.as_ref(),
        "alice",
        time::Duration::minutes(15),
        OffsetDateTime::now_utc(),
    )
    .await
    .unwrap();

    // Un jeton inconnu et un corps mal formé sont refusés.
    let (status, err) = call(
        &app,
        "/internal/v1/register/begin",
        serde_json::json!({"token": "pas-un-jeton"}),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{err}");
    let (status, _) = call(
        &app,
        "/internal/v1/register/begin",
        serde_json::json!({"token": invite.token, "operator_name": "root"}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let (status, begun) = call(
        &app,
        "/internal/v1/register/begin",
        serde_json::json!({"token": invite.token}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{begun}");
    assert_eq!(begun["operator"], "alice");
    let options: oe_webauthn::CreationChallengeResponse =
        serde_json::from_value(serde_json::json!({ "publicKey": begun["webauthn"] })).unwrap();
    let mut authn = WebauthnAuthenticator::new(token);
    let credential = authn.do_registration(origin(), options).unwrap();

    let (status, done) = call(
        &app,
        "/internal/v1/register/finish",
        serde_json::json!({"ceremony_id": begun["ceremony_id"], "credential": credential}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{done}");
    assert_eq!(done["status"], "active");
    assert_eq!(done["operator"], "alice");
    assert!(done["key_fingerprint"].as_str().unwrap().len() > 30);

    // Le jeton est consommé.
    let (status, _) = call(
        &app,
        "/internal/v1/register/begin",
        serde_json::json!({"token": invite.token}),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}
