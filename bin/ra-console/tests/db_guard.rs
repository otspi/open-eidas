//! La garde de démarrage (docs/WEBUI.md §16) : la console refuse de servir avec un
//! rôle PostgreSQL qui peut écrire dans les tables de `ca-server`. Rôles réels,
//! droits réels, sur une base neuve.
//!
//! DSN dans `OE_CASTORE_TEST_DSN` ; test ignoré si elle n'est pas définie.

use oe_castore::Postgres;
use ra_console::db_guard::check_read_only;
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;

const GRANTS: &str = include_str!("../../../crates/oe-castore/sql/ra_console_grants.sql");

async fn fresh() -> Option<(PgPool, String)> {
    let base = std::env::var("OE_CASTORE_TEST_DSN").ok()?;
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let name = format!("dbg_{nanos}_{}_{}", std::process::id(), {
        static SEQ: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    });
    let admin = PgPoolOptions::new().connect(&base).await.unwrap();
    sqlx::query(&format!("CREATE DATABASE {name}"))
        .execute(&admin)
        .await
        .unwrap();
    let dsn = format!("{}/{name}", base.rsplit_once('/').unwrap().0);
    Postgres::open(&dsn).await.unwrap();
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&dsn)
        .await
        .unwrap();
    sqlx::raw_sql(GRANTS).execute(&pool).await.unwrap();
    Some((pool, dsn))
}

/// Un pool dont chaque connexion prend le rôle donné, comme le ferait un DSN
/// propre à ce rôle.
async fn as_role(dsn: &str, role: &str) -> PgPool {
    let sql = format!("SET ROLE {role}");
    PgPoolOptions::new()
        .max_connections(1)
        .after_connect(move |conn, _| {
            let sql = sql.clone();
            Box::pin(async move { sqlx::query(&sql).execute(conn).await.map(|_| ()) })
        })
        .connect(dsn)
        .await
        .unwrap()
}

macro_rules! fresh {
    () => {
        match fresh().await {
            Some(f) => f,
            None => {
                eprintln!("OE_CASTORE_TEST_DSN non définie : test PostgreSQL ignoré");
                return;
            }
        }
    };
}

#[tokio::test]
async fn the_console_role_passes_the_guard() {
    let (_, dsn) = fresh!();
    let pool = as_role(&dsn, "openeidas_ra_console").await;
    check_read_only(&pool)
        .await
        .expect("le rôle de la console est en lecture seule");
}

#[tokio::test]
async fn a_superuser_dsn_is_refused() {
    let (admin_pool, _) = fresh!();
    // Le DSN de l'administrateur de la base : il peut tout écrire.
    let err = check_read_only(&admin_pool)
        .await
        .expect_err("superutilisateur");
    assert!(err.contains("superutilisateur"), "{err}");
    assert!(err.contains("INSERT accordé sur operators"), "{err}");
}

#[tokio::test]
async fn a_role_that_can_write_the_registry_is_refused_with_every_violation() {
    let (admin_pool, dsn) = fresh!();
    let role = format!(
        "bad_console_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    for sql in [
        format!("CREATE ROLE {role} NOLOGIN"),
        format!("GRANT SELECT, INSERT ON operators TO {role}"),
        format!("GRANT UPDATE ON enrollment_requests TO {role}"),
    ] {
        sqlx::query(&sql).execute(&admin_pool).await.unwrap();
    }
    let pool = as_role(&dsn, &role).await;

    let err = check_read_only(&pool)
        .await
        .expect_err("rôle trop puissant");
    assert!(err.contains("INSERT accordé sur operators"), "{err}");
    assert!(
        err.contains("UPDATE accordé sur enrollment_requests"),
        "{err}"
    );
    // La lecture, elle, reste admise : seule l'écriture est fautive.
    assert!(!err.contains("SELECT"), "{err}");
    assert!(!err.contains("superutilisateur"), "{err}");
}

#[tokio::test]
async fn a_privilege_inherited_through_a_group_is_seen() {
    let (admin_pool, dsn) = fresh!();
    let suffix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let (group, member) = (format!("grp_{suffix}"), format!("mem_{suffix}"));
    for sql in [
        format!("CREATE ROLE {group} NOLOGIN"),
        format!("GRANT DELETE ON certificates TO {group}"),
        format!("CREATE ROLE {member} NOLOGIN INHERIT"),
        format!("GRANT {group} TO {member}"),
    ] {
        sqlx::query(&sql).execute(&admin_pool).await.unwrap();
    }
    let err = check_read_only(&as_role(&dsn, &member).await)
        .await
        .expect_err("droit hérité d'un groupe");
    assert!(err.contains("DELETE accordé sur certificates"), "{err}");
}
