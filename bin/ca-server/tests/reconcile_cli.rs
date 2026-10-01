//! `ca-server operators reconcile` et le contrôle du registre (docs/WEBUI.md §21),
//! exécutés pour de vrai contre un PostgreSQL et un vrai journal chaîné. La logique
//! est éprouvée par `oe-actions/tests/reconcile.rs` ; ici, ce que voit l'opérateur.
//!
//! DSN dans `OE_CASTORE_TEST_DSN` ; test ignoré si elle n'est pas définie.

use sqlx::postgres::PgPoolOptions;
use std::process::{Command, Output};

struct Fixture {
    dsn: String,
    audit: std::path::PathBuf,
    pool: sqlx::PgPool,
}

async fn fixture(prefix: &str) -> Option<Fixture> {
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
    let f = Fixture {
        audit: std::env::temp_dir().join(format!("{name}.audit.log")),
        pool: PgPoolOptions::new().connect(&dsn).await.unwrap(),
        dsn,
    };
    // Migre la base, et crée l'opérateur « alice » par l'amorçage.
    let out = f.run(&["operators", "bootstrap-admin", "alice"]);
    assert!(out.status.success(), "{out:?}");
    Some(f)
}

impl Fixture {
    fn run(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_ca-server"))
            .args(args)
            .env("OPENEIDAS_DB_DSN", &self.dsn)
            .env("OPENEIDAS_ISSUING_PIN", "1234")
            .env("OPENEIDAS_PKI_PUBLIC_URL", "https://pki.example.test")
            .env("OPENEIDAS_AUDIT_FILE", &self.audit)
            .output()
            .expect("lancement de ca-server")
    }

    /// Ajoute des événements au journal, comme le service l'aurait fait.
    fn log(&self, events: &[(&str, serde_json::Value)]) {
        let log = oe_audit::Log::open(&self.audit).unwrap();
        for (name, data) in events {
            let data = data
                .as_object()
                .unwrap()
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect();
            log.append(name, Some(data)).unwrap();
        }
    }

    async fn active_key(&self, id: &str) {
        sqlx::query(
            "INSERT INTO webauthn_credentials
               (credential_id, operator_id, public_key, aaguid, attestation_format,
                attestation_object, backup_eligible, initiated_by, initiated_at, passkey)
             SELECT $1, id, '\\x00', gen_random_uuid(), 'packed', '\\x00', false,
                    'bootstrap-admin', now(), '{}'::jsonb
             FROM operators WHERE name = 'alice'",
        )
        .bind(id)
        .execute(&self.pool)
        .await
        .unwrap();
    }

    async fn revoked(&self, id: &str) -> bool {
        sqlx::query_scalar(
            "SELECT revoked_at IS NOT NULL FROM webauthn_credentials WHERE credential_id = $1",
        )
        .bind(id)
        .fetch_one(&self.pool)
        .await
        .unwrap()
    }

    fn journal_text(&self) -> String {
        std::fs::read_to_string(&self.audit).unwrap_or_default()
    }
}

fn registered(id: &str) -> (&'static str, serde_json::Value) {
    (
        "operators.credential_registered",
        serde_json::json!({"credential_id": id, "operateur": "alice", "statut": "active"}),
    )
}

#[tokio::test]
async fn reconcile_reapplies_a_revocation_the_restored_database_lost() {
    let Some(f) = fixture("rec1").await else {
        eprintln!("OE_CASTORE_TEST_DSN non définie : test PostgreSQL ignoré");
        return;
    };
    // La base garde la clé active ; le journal atteste qu'elle a été révoquée.
    f.active_key("cle-a").await;
    f.log(&[
        registered("cle-a"),
        (
            "operators.key_revoked",
            serde_json::json!({"credential_id": "cle-a", "operateur": "alice", "motif": "perdue", "par": "alice"}),
        ),
    ]);

    // Sans motif : refusé par la ligne de commande.
    assert!(!f.run(&["operators", "reconcile"]).status.success());

    // Essai à blanc : on voit, on ne touche pas.
    let out = f.run(&[
        "operators",
        "reconcile",
        "--reason",
        "base restaurée",
        "--dry-run",
    ]);
    assert_eq!(out.status.code(), Some(0), "{out:?}");
    assert!(String::from_utf8_lossy(&out.stdout).contains("à ré-appliquer"));
    assert!(!f.revoked("cle-a").await);
    assert!(!f.journal_text().contains("operators.reconciled"));

    // Pour de vrai : la révocation est ré-appliquée et consignée.
    let out = f.run(&["operators", "reconcile", "--reason", "base restaurée"]);
    assert_eq!(out.status.code(), Some(0), "{out:?}");
    assert!(f.revoked("cle-a").await);
    assert!(f.journal_text().contains("reapplied_revocation"));

    // Idempotent : plus rien à faire.
    let out = f.run(&["operators", "reconcile", "--reason", "encore"]);
    assert_eq!(out.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&out.stderr).contains("0 résolue(s), 0 en suspens"));
}

#[tokio::test]
async fn a_lost_key_stays_pending_until_explicitly_acknowledged() {
    let Some(f) = fixture("rec2").await else {
        eprintln!("OE_CASTORE_TEST_DSN non définie : test PostgreSQL ignoré");
        return;
    };
    // Le journal dit la clé active ; la base ne l'a jamais eue.
    f.log(&[registered("cle-perdue")]);

    let out = f.run(&["operators", "reconcile", "--reason", "base restaurée"]);
    assert_eq!(out.status.code(), Some(1), "{out:?}");
    assert!(String::from_utf8_lossy(&out.stdout).starts_with("KO\t"));
    assert!(String::from_utf8_lossy(&out.stderr).contains("ré-enrôle"));

    // Acquitter autre chose qu'une vraie perte est refusé.
    let out = f.run(&[
        "operators",
        "reconcile",
        "--reason",
        "x",
        "--acknowledge-missing",
        "n-importe-quoi",
    ]);
    assert!(!out.status.success());

    let out = f.run(&[
        "operators",
        "reconcile",
        "--reason",
        "clé de alice perdue, à ré-enrôler",
        "--acknowledge-missing",
        "cle-perdue",
    ]);
    assert_eq!(out.status.code(), Some(0), "{out:?}");
    assert!(f.journal_text().contains("acknowledged_missing"));
    // L'acquittement est consigné : le rejeu suivant ne rouvre pas la divergence.
    let out = f.run(&["operators", "reconcile", "--reason", "contrôle"]);
    assert_eq!(out.status.code(), Some(0), "{out:?}");
}

#[tokio::test]
async fn a_broken_journal_resolves_nothing() {
    let Some(f) = fixture("rec3").await else {
        eprintln!("OE_CASTORE_TEST_DSN non définie : test PostgreSQL ignoré");
        return;
    };
    f.active_key("cle-a").await;
    f.log(&[
        registered("cle-a"),
        (
            "operators.key_revoked",
            serde_json::json!({"credential_id": "cle-a", "operateur": "alice"}),
        ),
    ]);
    let raw = f.journal_text();
    std::fs::write(&f.audit, raw.replacen("cle-a", "cle-z", 1)).unwrap();

    let out = f.run(&["operators", "reconcile", "--reason", "x"]);
    assert_eq!(out.status.code(), Some(2), "{out:?}");
    assert!(
        !f.revoked("cle-a").await,
        "rien ne se résout contre un journal douteux"
    );
}

#[tokio::test]
async fn the_registry_check_closes_the_guard_and_reopens_it() {
    let Some(f) = fixture("rec4").await else {
        eprintln!("OE_CASTORE_TEST_DSN non définie : test PostgreSQL ignoré");
        return;
    };
    let registry = oe_actions::Registry::connect(&f.dsn).await.unwrap();
    let guard = oe_actions::RegistryGuard::new();
    let path = f.audit.to_str().unwrap();
    let zero = std::time::Duration::ZERO;

    ca_server::registry_check::refresh(&registry, path, &guard, zero).await;
    assert!(guard.blocked().is_none(), "registre sain");

    // Divergence : clé active en base, révoquée au journal.
    f.active_key("cle-a").await;
    f.log(&[
        registered("cle-a"),
        (
            "operators.key_revoked",
            serde_json::json!({"credential_id": "cle-a", "operateur": "alice"}),
        ),
    ]);
    ca_server::registry_check::refresh(&registry, path, &guard, zero).await;
    let reasons = guard.blocked().expect("garde fermée");
    assert!(reasons[0].contains("cle-a"), "{reasons:?}");

    // Résolue, la garde se rouvre au contrôle suivant.
    let out = f.run(&["operators", "reconcile", "--reason", "x"]);
    assert!(out.status.success(), "{out:?}");
    ca_server::registry_check::refresh(&registry, path, &guard, zero).await;
    assert!(guard.blocked().is_none());

    // Un journal rompu ferme la garde : on ne juge pas contre un journal douteux.
    let raw = f.journal_text();
    std::fs::write(&f.audit, raw.replacen("cle-a", "cle-z", 1)).unwrap();
    ca_server::registry_check::refresh(&registry, path, &guard, zero).await;
    assert!(guard.blocked().unwrap()[0].contains("journal illisible ou rompu"));
}

/// `operators reconcile` n'ouvre aucun token PKCS#11 et ne grave aucune adresse
/// dans un certificat : ni `OPENEIDAS_ISSUING_PIN` ni `OPENEIDAS_PKI_PUBLIC_URL`
/// ne doivent être exigées (`Config::load_without_hsm`).
#[tokio::test]
async fn the_reconcile_command_does_not_require_hsm_configuration() {
    let Ok(base) = std::env::var("OE_CASTORE_TEST_DSN") else {
        eprintln!("OE_CASTORE_TEST_DSN non définie : test PostgreSQL ignoré");
        return;
    };
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let name = format!("reconohsm_{nanos}_{}_{}", std::process::id(), {
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
    let out = run(&["operators", "reconcile", "--reason", "contrôle"]);
    assert_eq!(out.status.code(), Some(0), "{out:?}");
}
