//! La purge périodique des sessions et des challenges expirés (docs/WEBUI.md
//! §15 étape 1c-2b), contre un vrai PostgreSQL : ce qui est retiré, ce qui ne
//! l'est pas.
//!
//! DSN dans `OE_CASTORE_TEST_DSN` ; test ignoré si elle n'est pas définie.

use ra_console::purge;
use sqlx::postgres::PgPoolOptions;
use time::OffsetDateTime;

async fn fixture(prefix: &str) -> Option<(sqlx::PgPool, oe_webauthn::Uuid, String)> {
    let base = std::env::var("OE_CASTORE_TEST_DSN").ok()?;
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let name = format!("{prefix}_{nanos}_{}_{}", std::process::id(), {
        static SEQ: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    });
    let admin = PgPoolOptions::new().connect(&base).await.unwrap();
    sqlx::query(&format!("CREATE DATABASE {name}"))
        .execute(&admin)
        .await
        .unwrap();
    let dsn = format!("{}/{name}", base.rsplit_once('/').unwrap().0);
    // Applique les migrations.
    let _ = oe_castore::Postgres::open(&dsn).await.unwrap();
    let pool = PgPoolOptions::new().connect(&dsn).await.unwrap();

    // Un opérateur et une clé, pour respecter les clés étrangères des tables
    // propres à ra-console.
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

macro_rules! fixture {
    ($prefix:expr) => {
        match fixture($prefix).await {
            Some(f) => f,
            None => {
                eprintln!("OE_CASTORE_TEST_DSN non définie : test PostgreSQL ignoré");
                return;
            }
        }
    };
}

#[tokio::test]
async fn expired_sessions_and_challenges_are_purged_live_ones_are_not() {
    let (pool, operator_id, credential_id) = fixture!("purge1");
    let now = OffsetDateTime::now_utc();

    // Une session expirée, révoquée ou non — l'échéance seule compte.
    sqlx::query(
        "INSERT INTO sessions (id, operator_id, credential_id, created_at, last_seen_at, expires_at)
         VALUES ('expiree', $1, $2, $3, $4, $5)",
    )
    .bind(operator_id)
    .bind(&credential_id)
    .bind(now - time::Duration::hours(9))
    .bind(now - time::Duration::hours(1))
    .bind(now - time::Duration::hours(1))
    .execute(&pool)
    .await
    .unwrap();
    // Une session vivante.
    sqlx::query(
        "INSERT INTO sessions (id, operator_id, credential_id, created_at, last_seen_at, expires_at)
         VALUES ('vivante', $1, $2, $3, $4, $5)",
    )
    .bind(operator_id)
    .bind(&credential_id)
    .bind(now)
    .bind(now)
    .bind(now + time::Duration::hours(8))
    .execute(&pool)
    .await
    .unwrap();

    // Un challenge de connexion expiré, un vivant.
    sqlx::query(
        "INSERT INTO webauthn_challenges (id, kind, challenge, created_at, expires_at)
         VALUES (gen_random_uuid(), 'login', '\\x00', $1, $2)",
    )
    .bind(now - time::Duration::minutes(10))
    .bind(now - time::Duration::minutes(5))
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO webauthn_challenges (id, kind, challenge, created_at, expires_at)
         VALUES (gen_random_uuid(), 'login', '\\x00', $1, $2)",
    )
    .bind(now)
    .bind(now + time::Duration::minutes(5))
    .execute(&pool)
    .await
    .unwrap();

    let purged = purge::once(&pool).await.unwrap();
    assert_eq!(purged.sessions, 1, "{purged:?}");
    assert_eq!(purged.challenges, 1, "{purged:?}");

    let remaining_sessions: Vec<String> = sqlx::query_scalar("SELECT id FROM sessions")
        .fetch_all(&pool)
        .await
        .unwrap();
    assert_eq!(remaining_sessions, vec!["vivante".to_string()]);

    let remaining_challenges: i64 = sqlx::query_scalar("SELECT count(*) FROM webauthn_challenges")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(remaining_challenges, 1);

    // Idempotent : plus rien à purger.
    let purged = purge::once(&pool).await.unwrap();
    assert_eq!(purged, ra_console::purge::Purged::default());
}
