//! `ca-server operators recover-admin` (docs/WEBUI.md §21), exécuté pour de vrai
//! contre un SoftHSM et un PostgreSQL : la preuve de garde de l'hôte est le PIN du
//! token, présenté sur l'entrée standard, et **pas** la valeur de
//! `OPENEIDAS_ISSUING_PIN` du service, lisible de tout accès shell.
//!
//! DSN dans `OE_CASTORE_TEST_DSN` et `softhsm2-util` installé ; sinon le test
//! s'ignore, en le disant.

use sqlx::postgres::PgPoolOptions;
use std::io::Write;
use std::process::{Command, Output, Stdio};

const TOKEN_PIN: &str = "1234";

fn have_softhsm() -> bool {
    Command::new("softhsm2-util")
        .arg("--version")
        .output()
        .is_ok()
        && std::path::Path::new("/usr/lib/softhsm/libsofthsm2.so").exists()
}

#[tokio::test]
async fn the_token_pin_from_stdin_is_the_proof_of_custody() {
    let Ok(base) = std::env::var("OE_CASTORE_TEST_DSN") else {
        eprintln!("OE_CASTORE_TEST_DSN non définie : test PostgreSQL ignoré");
        return;
    };
    if !have_softhsm() {
        eprintln!("softhsm2-util absent : test du PIN ignoré");
        return;
    }

    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let name = format!("recli_{nanos}_{}_{}", std::process::id(), {
        static SEQ: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    });
    let dir = std::env::temp_dir().join(&name);
    std::fs::create_dir_all(dir.join("tokens")).unwrap();
    std::fs::write(
        dir.join("softhsm.conf"),
        format!(
            "directories.tokendir = {}\nobjectstore.backend = file\nlog.level = ERROR\n",
            dir.join("tokens").display()
        ),
    )
    .unwrap();
    let init = Command::new("softhsm2-util")
        .args([
            "--init-token",
            "--free",
            "--label",
            "open-eidas-issuing",
            "--pin",
            TOKEN_PIN,
            "--so-pin",
            "5678",
        ])
        .env("SOFTHSM2_CONF", dir.join("softhsm.conf"))
        .output()
        .unwrap();
    assert!(init.status.success(), "{init:?}");

    let admin = PgPoolOptions::new().connect(&base).await.unwrap();
    sqlx::query(&format!("CREATE DATABASE {name}"))
        .execute(&admin)
        .await
        .unwrap();
    let dsn = format!("{}/{name}", base.rsplit_once('/').unwrap().0);
    let pool = PgPoolOptions::new().connect(&dsn).await.unwrap();
    let audit = dir.join("audit.log");

    // `env_pin` : ce que porte le service dans son environnement. `None` :
    // absente, comme un opérateur sans ce secret la lancerait
    // (`Config::load_without_hsm`).
    let run = |args: &[&str], stdin: &str, env_pin: Option<&str>| -> Output {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_ca-server"));
        cmd.args(["operators", "recover-admin", "alice"])
            .args(args)
            .env("SOFTHSM2_CONF", dir.join("softhsm.conf"))
            .env("OPENEIDAS_DB_DSN", &dsn)
            .env("OPENEIDAS_AUDIT_FILE", &audit);
        match env_pin {
            Some(pin) => {
                cmd.env("OPENEIDAS_ISSUING_PIN", pin)
                    .env("OPENEIDAS_PKI_PUBLIC_URL", "https://pki.example.test");
            }
            None => {
                cmd.env_remove("OPENEIDAS_ISSUING_PIN")
                    .env_remove("OPENEIDAS_PKI_PUBLIC_URL");
            }
        }
        let mut child = cmd
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(stdin.as_bytes())
            .unwrap();
        child.wait_with_output().unwrap()
    };
    let journal = || std::fs::read_to_string(&audit).unwrap_or_default();
    let operators = || async {
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM operators")
            .fetch_one(&pool)
            .await
            .unwrap_or(0)
    };

    // Sans la confirmation explicite : refusé, sans même chercher le PIN.
    let out = run(
        &["--reason", "perte", "--pin-stdin"],
        "1234\n",
        Some(TOKEN_PIN),
    );
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("--confirm-recovery"));

    // Sans --pin-stdin : refusé par la ligne de commande elle-même.
    let out = run(
        &["--reason", "perte", "--confirm-recovery"],
        "1234\n",
        Some(TOKEN_PIN),
    );
    assert!(!out.status.success());

    // Un mauvais PIN, alors que le service porte le bon dans son environnement :
    // c'est bien le PIN présenté qui compte. Refusé, et consigné.
    let out = run(
        &["--reason", "perte", "--confirm-recovery", "--pin-stdin"],
        "0000\n",
        Some(TOKEN_PIN),
    );
    assert!(!out.status.success());
    assert!(out.stdout.is_empty(), "aucun jeton ne doit sortir");
    assert!(
        journal().contains("operators.admin_recovery_refused"),
        "{}",
        journal()
    );
    assert!(!journal().contains("\"operators.admin_recovery\""));
    assert_eq!(operators().await, 0);

    // Le bon PIN présenté, alors que le service n'a ni `OPENEIDAS_ISSUING_PIN`
    // ni `OPENEIDAS_PKI_PUBLIC_URL` dans son environnement (`load_without_hsm`) :
    // ce n'est pas ce que porte le service qui compte, et ce n'est pas exigé.
    let out = run(
        &[
            "--reason",
            "perte de la clé de alice",
            "--confirm-recovery",
            "--pin-stdin",
        ],
        "1234\n",
        None,
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{stderr}");
    // La sortie standard ne porte que le jeton.
    let token = String::from_utf8_lossy(&out.stdout).trim_end().to_string();
    assert_eq!(token.len(), 43, "{token:?}");
    assert!(token
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'));
    assert!(journal().contains("operators.admin_recovery"));
    assert!(journal().contains("perte de la clé de alice"));
    assert!(
        !journal().contains(&token),
        "le jeton ne va jamais au journal"
    );
    assert_eq!(operators().await, 1);
}
