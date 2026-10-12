//! `ca-server operators audit` (docs/WEBUI.md §21), exécuté pour de vrai contre
//! un PostgreSQL : le code de sortie et ce que voit l'opérateur. La logique de
//! l'audit est éprouvée par `oe-actions/tests/audit.rs`.
//!
//! DSN dans `OE_CASTORE_TEST_DSN` ; test ignoré si elle n'est pas définie.

use sqlx::postgres::PgPoolOptions;
use std::process::{Command, Output};

#[tokio::test]
async fn the_audit_command_reports_what_the_journal_cannot_vouch_for() {
    let Ok(base) = std::env::var("OE_CASTORE_TEST_DSN") else {
        eprintln!("OE_CASTORE_TEST_DSN non définie : test PostgreSQL ignoré");
        return;
    };
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let name = format!("audcli_{nanos}_{}_{}", std::process::id(), {
        static SEQ: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    });
    let admin = PgPoolOptions::new().connect(&base).await.unwrap();
    sqlx::query(&format!("CREATE DATABASE {name}"))
        .execute(&admin)
        .await
        .unwrap();
    let dsn = format!("{}/{name}", base.rsplit_once('/').unwrap().0);
    let audit = std::env::temp_dir().join(format!("{name}.audit.log"));

    let run = |args: &[&str]| -> Output {
        Command::new(env!("CARGO_BIN_EXE_ca-server"))
            .args(args)
            .env("OPENEIDAS_DB_DSN", &dsn)
            .env("OPENEIDAS_ISSUING_PIN", "1234")
            .env("OPENEIDAS_PKI_PUBLIC_URL", "https://pki.example.test")
            .env("OPENEIDAS_AUDIT_FILE", &audit)
            .output()
            .expect("lancement de ca-server")
    };

    // Un journal existe (l'amorçage y écrit), mais aucune clé n'est enregistrée.
    let out = run(&["operators", "bootstrap-admin", "alice"]);
    assert!(out.status.success(), "{out:?}");
    let out = run(&["operators", "audit"]);
    assert_eq!(out.status.code(), Some(0), "{out:?}");
    assert!(String::from_utf8_lossy(&out.stderr).contains("0 clé(s) active(s)"));

    // Une clé d'ancre insérée en SQL : le journal ne l'atteste pas.
    let pool = PgPoolOptions::new().connect(&dsn).await.unwrap();
    sqlx::query(
        "INSERT INTO webauthn_credentials
           (credential_id, operator_id, public_key, aaguid, attestation_format,
            attestation_object, backup_eligible, initiated_by, initiated_at, passkey)
         SELECT 'cle-forgee-0123456789', id, '\\x00', gen_random_uuid(), 'packed',
                '\\x00', false, 'bootstrap-admin', now(), '{}'::jsonb
         FROM operators WHERE name = 'alice'",
    )
    .execute(&pool)
    .await
    .unwrap();
    let out = run(&["operators", "audit"]);
    assert_eq!(out.status.code(), Some(1), "{out:?}");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.starts_with("KO\talice\tcle-forgee-01234"),
        "{stdout}"
    );
    assert!(stdout.contains("absente du journal"), "{stdout}");
    assert!(String::from_utf8_lossy(&out.stderr).contains("1 constat(s)"));

    // Un journal altéré n'est pas une base de jugement : code 2, pas de verdict.
    let raw = std::fs::read_to_string(&audit).unwrap();
    std::fs::write(&audit, raw.replacen("alice", "mallory", 1)).unwrap();
    let out = run(&["operators", "audit"]);
    assert_eq!(out.status.code(), Some(2), "{out:?}");
    assert!(out.stdout.is_empty());
}

/// `operators audit` n'ouvre aucun token PKCS#11 et ne grave aucune adresse
/// dans un certificat : ni `OPENEIDAS_ISSUING_PIN` ni `OPENEIDAS_PKI_PUBLIC_URL`
/// ne doivent être exigées (`Config::load_without_hsm`).
#[tokio::test]
async fn the_audit_command_does_not_require_hsm_configuration() {
    let Ok(base) = std::env::var("OE_CASTORE_TEST_DSN") else {
        eprintln!("OE_CASTORE_TEST_DSN non définie : test PostgreSQL ignoré");
        return;
    };
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let name = format!("audnohsm_{nanos}_{}_{}", std::process::id(), {
        static SEQ: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    });
    let admin = PgPoolOptions::new().connect(&base).await.unwrap();
    sqlx::query(&format!("CREATE DATABASE {name}"))
        .execute(&admin)
        .await
        .unwrap();
    let dsn = format!("{}/{name}", base.rsplit_once('/').unwrap().0);
    let audit = std::env::temp_dir().join(format!("{name}.audit.log"));

    let run = |args: &[&str]| -> Output {
        Command::new(env!("CARGO_BIN_EXE_ca-server"))
            .args(args)
            .env("OPENEIDAS_DB_DSN", &dsn)
            .env_remove("OPENEIDAS_ISSUING_PIN")
            .env_remove("OPENEIDAS_PKI_PUBLIC_URL")
            .env("OPENEIDAS_AUDIT_FILE", &audit)
            .output()
            .expect("lancement de ca-server")
    };

    let out = run(&["operators", "bootstrap-admin", "alice"]);
    assert!(out.status.success(), "{out:?}");
    let out = run(&["operators", "audit"]);
    assert_eq!(out.status.code(), Some(0), "{out:?}");
}
