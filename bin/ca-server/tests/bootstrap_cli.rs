//! Exécute le vrai binaire `ca-server operators bootstrap-admin` contre un
//! PostgreSQL (docs/WEBUI.md §10) : ce que voit l'opérateur, pas seulement ce
//! que fait la bibliothèque.
//!
//! DSN dans `OE_CASTORE_TEST_DSN` ; test ignoré si elle n'est pas définie.

use sqlx::postgres::PgPoolOptions;
use std::process::Command;

fn token_chars(s: &str) -> bool {
    s.chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

#[tokio::test]
async fn standard_output_carries_only_the_token() {
    let Ok(base) = std::env::var("OE_CASTORE_TEST_DSN") else {
        eprintln!("OE_CASTORE_TEST_DSN non définie : test PostgreSQL ignoré");
        return;
    };

    // Base neuve : la commande ouvre le magasin, donc migre, et écrit une
    // notice de migration au premier passage comme au second.
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let name = format!("cli_{nanos}");
    let admin = PgPoolOptions::new().connect(&base).await.unwrap();
    sqlx::query(&format!("CREATE DATABASE {name}"))
        .execute(&admin)
        .await
        .unwrap();
    let (head, _) = base.rsplit_once('/').unwrap();
    let dsn = format!("{head}/{name}");
    let audit = std::env::temp_dir().join(format!("{name}.audit.log"));

    let run = || {
        Command::new(env!("CARGO_BIN_EXE_ca-server"))
            .args(["operators", "bootstrap-admin", "alice"])
            .env("OPENEIDAS_DB_DSN", &dsn)
            // Ni PIN de l'émettrice ni adresse publique : `bootstrap-admin` n'ouvre
            // aucun token et ne grave aucune adresse, il ne doit pas les exiger.
            .env("OPENEIDAS_AUDIT_FILE", &audit)
            .output()
            .expect("lancement de ca-server")
    };

    // Idem pour la liste des demandes : commande d'exploitation, sans secret de HSM.
    let out = Command::new(env!("CARGO_BIN_EXE_ca-server"))
        .args(["ra", "list"])
        .env("OPENEIDAS_DB_DSN", &dsn)
        .env("OPENEIDAS_AUDIT_FILE", &audit)
        .output()
        .expect("lancement de ca-server");
    assert!(
        out.status.success(),
        "ra list sans PIN : {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let mut tokens = Vec::new();
    // Deux passages : le second ré-invite, et sqlx y écrit une notice
    // (« relation _sqlx_migrations already exists »).
    for pass in 1..=2 {
        let out = run();
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(out.status.success(), "passage {pass} : {stderr}");

        let token = stdout.trim_end_matches('\n');
        assert_eq!(
            token.len(),
            43,
            "passage {pass} : la sortie standard doit être le seul jeton, obtenu {stdout:?}"
        );
        assert!(token_chars(token), "passage {pass} : {token:?}");
        assert!(
            stderr.contains("Invitation créée"),
            "passage {pass} : {stderr}"
        );
        assert!(
            !stderr.contains(token),
            "le jeton ne doit pas être répété sur la sortie d'erreur"
        );
        tokens.push(token.to_string());
    }
    assert_ne!(tokens[0], tokens[1], "chaque invitation a son propre jeton");

    let _ = std::fs::remove_file(&audit);
}

/// Les commandes qui ouvrent le token ou gravent l'adresse publique dans un
/// certificat, elles, exigent toujours ces deux valeurs : assouplir les autres
/// ne doit rien relâcher ici. Pas besoin de base : la configuration est refusée
/// avant toute connexion.
#[test]
fn commands_that_sign_still_require_the_pin_and_the_public_address() {
    let run = |args: &[&str], pin: Option<&str>, url: Option<&str>| -> String {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_ca-server"));
        cmd.args(args)
            .env("OPENEIDAS_DB_DSN", "postgres://x@127.0.0.1:1/x")
            .env_remove("OPENEIDAS_ISSUING_PIN")
            .env_remove("OPENEIDAS_PKI_PUBLIC_URL");
        if let Some(p) = pin {
            cmd.env("OPENEIDAS_ISSUING_PIN", p);
        }
        if let Some(u) = url {
            cmd.env("OPENEIDAS_PKI_PUBLIC_URL", u);
        }
        let out = cmd.output().expect("lancement de ca-server");
        assert!(!out.status.success());
        String::from_utf8_lossy(&out.stderr).to_string()
    };

    for args in [&["serve"][..], &["revoke", "00", "1", "alice", "test"][..]] {
        let err = run(args, None, Some("https://pki.example.test"));
        assert!(err.contains("OPENEIDAS_ISSUING_PIN"), "{args:?} : {err}");
        let err = run(args, Some("1234"), None);
        assert!(err.contains("OPENEIDAS_PKI_PUBLIC_URL"), "{args:?} : {err}");
    }
}

/// ETSI TS 119 312 §8.4 (constat D-2 : preuve sur le binaire) : une clé
/// d'autorité de moins de 3072 bits est refusée avant tout, y compris par une
/// commande qui n'ouvre aucun token.
#[test]
fn undersized_ca_keys_are_refused_by_the_binary() {
    for (bits, refused) in [("2048", true), ("3072", false)] {
        let out = Command::new(env!("CARGO_BIN_EXE_ca-server"))
            .args(["ra", "list"])
            // Sans DSN : une clé admise échoue ensuite sur la base, ce qui
            // prouve que le contrôle de longueur est passé.
            .env_remove("OPENEIDAS_DB_DSN")
            .env("OPENEIDAS_CA_KEY_BITS", bits)
            .output()
            .expect("lancement de ca-server");
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(!out.status.success(), "{bits} : {stderr}");
        assert_eq!(
            stderr.contains("OPENEIDAS_DB_DSN"),
            !refused,
            "{bits} : {stderr}"
        );
        assert_eq!(
            stderr.contains("ETSI TS 119 312 impose au moins 3072 bits"),
            refused,
            "{bits} : {stderr}"
        );
    }
}
