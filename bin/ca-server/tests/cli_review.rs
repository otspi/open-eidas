//! Revue a posteriori des décisions de la voie de secours (constat R-1,
//! docs/WEBUI.md §20, décision O4) : `ca-server audit cli-decisions`, contre un
//! vrai journal chaîné `oe-audit`, sans base de données.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use ca_server::cli_review;

fn journal_path(name: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("oe-cli-review-{name}-{nanos}.log"))
}

fn append(path: &Path, event: &str, data: serde_json::Value) {
    let log = oe_audit::Log::open(path).unwrap();
    let data = match data {
        serde_json::Value::Object(map) => Some(map.into_iter().collect()),
        _ => None,
    };
    log.append(event, data).unwrap();
}

fn cli_decision(path: &Path, transaction: &str) {
    append(
        path,
        "ca.request_approved",
        serde_json::json!({
            "transaction": transaction,
            "operateur": "prenom.nom",
            "commentaire": "identité vérifiée",
            "authenticated_via": "cli",
            "identite_systeme": {"authentifiee": false, "uid": 0, "utilisateur": "root", "hote": "open-eidas-ca-0"},
        }),
    );
}

/// Un journal typique : une décision signée, une révocation automatique, et
/// deux décisions de la voie de secours (une approbation, une révocation).
fn seeded_journal(name: &str) -> PathBuf {
    let path = journal_path(name);
    append(
        &path,
        "ca.request_approved",
        serde_json::json!({"transaction": "tx-signee", "operateur": "alice", "authenticated_via": "webauthn"}),
    );
    cli_decision(&path, "tx-secours");
    append(
        &path,
        "ca.certificate_revoked",
        serde_json::json!({"serie": "0a", "operateur": "raflow:renouvellement", "authenticated_via": "automatique"}),
    );
    append(
        &path,
        "ca.certificate_revoked",
        serde_json::json!({
            "serie": "0b", "operateur": "prenom.nom", "commentaire": "clé exposée",
            "authenticated_via": "cli",
            "identite_systeme": {"authentifiee": false, "uid": 1000, "utilisateur": "ops", "hote": "open-eidas-ca-0"},
        }),
    );
    path
}

#[test]
fn only_decisions_of_the_emergency_path_are_listed_until_acknowledged() {
    let path = seeded_journal("logic");
    let records = oe_audit::read(&path).unwrap();
    let review = cli_review::review(&records, None).unwrap();
    assert_eq!(review.acknowledged_up_to, 0);
    let subjects: Vec<_> = review
        .decisions
        .iter()
        .map(|d| d.subject.as_str())
        .collect();
    assert_eq!(subjects, ["tx-secours", "0b"]);
    assert_eq!(review.decisions[1].posix_id, Some(1000));
    assert_eq!(review.decisions[1].host, "open-eidas-ca-0");

    // Acquittement jusqu'à la tête lue : plus rien à revoir…
    append(
        &path,
        cli_review::REVIEW_EVENT,
        cli_review::acknowledgement(&review, "relecteur", "rien d'anormal"),
    );
    let records = oe_audit::read(&path).unwrap();
    let after = cli_review::review(&records, None).unwrap();
    assert_eq!(after.acknowledged_up_to, review.head);
    assert!(after.decisions.is_empty());

    // …jusqu'à la décision de secours suivante.
    cli_decision(&path, "tx-suivante");
    let records = oe_audit::read(&path).unwrap();
    let next = cli_review::review(&records, None).unwrap();
    assert_eq!(next.decisions.len(), 1);
    assert_eq!(next.decisions[0].subject, "tx-suivante");

    // `since` relit une période passée, acquittements ou non.
    let since = time::OffsetDateTime::UNIX_EPOCH;
    let all = cli_review::review(&records, Some(since)).unwrap();
    assert_eq!(all.decisions.len(), 3);

    let _ = std::fs::remove_file(&path);
}

fn run(path: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_ca-server"))
        .args(["audit", "cli-decisions"])
        .args(args)
        .env("OPENEIDAS_AUDIT_FILE", path)
        .env_remove("OPENEIDAS_DB_DSN")
        .output()
        .expect("lancement de ca-server")
}

#[test]
fn the_command_exits_1_until_the_review_is_acknowledged() {
    let path = seeded_journal("cli");

    let out = run(&path, &[]);
    assert_eq!(out.status.code(), Some(1), "{out:?}");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("tx-secours") && stdout.contains("0b"),
        "{stdout}"
    );
    assert!(!stdout.contains("tx-signee"), "{stdout}");

    // Un acquittement sans commentaire, ou sur une copie, est refusé.
    let before = oe_audit::read(&path).unwrap().len();
    let out = run(&path, &["--acknowledge", "--reviewer", "relecteur"]);
    assert!(!out.status.success(), "{out:?}");
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("exige un commentaire"),
        "{out:?}"
    );
    let copy = path.to_string_lossy().to_string();
    let out = run(
        &path,
        &[
            "--acknowledge",
            "--reviewer",
            "relecteur",
            "--journal",
            &copy,
            "vu",
        ],
    );
    assert!(!out.status.success(), "{out:?}");
    assert_eq!(
        oe_audit::read(&path).unwrap().len(),
        before,
        "un acquittement refusé n'écrit rien"
    );

    let out = run(
        &path,
        &[
            "--acknowledge",
            "--reviewer",
            "relecteur",
            "décisions justifiées",
        ],
    );
    assert_eq!(out.status.code(), Some(0), "{out:?}");
    let last = oe_audit::read(&path).unwrap().pop().unwrap();
    assert_eq!(last.event, cli_review::REVIEW_EVENT);
    let data = last.data.unwrap();
    assert_eq!(data["relecteur"], "relecteur");
    assert_eq!(data["decisions"], 2);
    assert_eq!(data["authenticated_via"], "cli");

    let out = run(&path, &[]);
    assert_eq!(out.status.code(), Some(0), "{out:?}");

    let _ = std::fs::remove_file(&path);
}

#[test]
fn a_tampered_journal_is_not_reviewed() {
    let path = seeded_journal("tampered");
    let content = std::fs::read_to_string(&path).unwrap();
    std::fs::write(&path, content.replacen("tx-secours", "tx-falsifie", 1)).unwrap();

    let out = run(&path, &[]);
    assert_eq!(out.status.code(), Some(2), "{out:?}");
    assert!(out.stdout.is_empty(), "rien n'est listé d'un journal rompu");

    let _ = std::fs::remove_file(&path);
}
