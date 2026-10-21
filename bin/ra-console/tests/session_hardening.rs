//! Constat A-2 de l'audit du 2026-09-25 (EN 319 401 `REQ-7.4.1-05`) : la base
//! ne garde que l'empreinte de l'identifiant de session, et une session
//! inactive plus de 30 minutes n'est plus acceptée. Contre un vrai
//! PostgreSQL (`OE_CASTORE_TEST_DSN` ; test ignoré sinon).

use std::sync::Arc;

use oe_actions::Registry;
use ra_console::audit::NullRecorder;
use ra_console::session::{stored_id, SessionError, Sessions, SESSION_IDLE};
use sqlx::postgres::PgPoolOptions;
use time::OffsetDateTime;

async fn fixture() -> Option<(sqlx::PgPool, oe_webauthn::Uuid, String)> {
    let base = std::env::var("OE_CASTORE_TEST_DSN").ok()?;
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let name = format!("sess_{nanos}_{}", std::process::id());
    let admin = PgPoolOptions::new().connect(&base).await.unwrap();
    sqlx::query(&format!("CREATE DATABASE {name}"))
        .execute(&admin)
        .await
        .unwrap();
    let dsn = format!("{}/{name}", base.rsplit_once('/').unwrap().0);
    let _ = oe_castore::Postgres::open(&dsn).await.unwrap();
    let pool = PgPoolOptions::new().connect(&dsn).await.unwrap();
    let operator_id = oe_webauthn::Uuid::new_v4();
    sqlx::query(
        "INSERT INTO operators (id, name, role, created_at, created_by)
         VALUES ($1, 'alice', 'ra_operateur', now(), 'test')",
    )
    .bind(operator_id)
    .execute(&pool)
    .await
    .unwrap();
    let credential_id = "cle-de-test".to_string();
    sqlx::query(
        "INSERT INTO webauthn_credentials
           (credential_id, operator_id, public_key, aaguid, attestation_format,
            attestation_object, backup_eligible, initiated_by, initiated_at,
            confirmed_by, confirmed_at, passkey)
         VALUES ($1, $2, '\\x00', gen_random_uuid(), 'packed', '\\x00', false,
                 'test', now(), 'test', now(), '{}'::jsonb)",
    )
    .bind(&credential_id)
    .bind(operator_id)
    .execute(&pool)
    .await
    .unwrap();
    Some((pool, operator_id, credential_id))
}

#[tokio::test]
async fn only_a_hash_is_stored_and_an_idle_session_expires() {
    let Some((pool, operator_id, credential_id)) = fixture().await else {
        eprintln!("OE_CASTORE_TEST_DSN non définie : test PostgreSQL ignoré");
        return;
    };
    let sessions = Sessions::new(Registry::new(pool.clone()), Arc::new(NullRecorder));
    let cookie = sessions.create(operator_id, &credential_id).await.unwrap();

    // La base garde l'empreinte, jamais l'identifiant du cookie.
    let stored: String = sqlx::query_scalar("SELECT id FROM sessions")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_ne!(stored, cookie);
    assert_eq!(stored, stored_id(&cookie));
    assert_eq!(stored.len(), 64);

    sessions
        .authenticate(&cookie)
        .await
        .expect("la session est valide");
    // Ce qui est en base ne permet pas de se faire passer pour la session.
    assert_eq!(
        sessions.authenticate(&stored).await.err(),
        Some(SessionError::Invalid)
    );

    // Inactive depuis plus de 30 minutes : refusée. Moins : acceptée.
    let set_last_seen = |ago: time::Duration| {
        let pool = pool.clone();
        let stored = stored.clone();
        async move {
            sqlx::query("UPDATE sessions SET last_seen_at = $2 WHERE id = $1")
                .bind(stored)
                .bind(OffsetDateTime::now_utc() - ago)
                .execute(&pool)
                .await
                .unwrap();
        }
    };
    set_last_seen(SESSION_IDLE + time::Duration::minutes(1)).await;
    assert_eq!(
        sessions.authenticate(&cookie).await.err(),
        Some(SessionError::Invalid)
    );
    set_last_seen(SESSION_IDLE - time::Duration::minutes(5)).await;
    sessions.authenticate(&cookie).await.expect("encore active");

    // La déconnexion se fait avec l'identifiant du cookie.
    sessions.revoke(&cookie).await.unwrap();
    assert_eq!(
        sessions.authenticate(&cookie).await.err(),
        Some(SessionError::Invalid)
    );
}
