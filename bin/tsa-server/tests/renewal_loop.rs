//! Constat H-3 : l'entrypoint de la TSA relance `tsa-server enroll` en
//! arrière-plan pendant que le service tourne, pour que le certificat se
//! renouvelle avant son expiration (le service l'adopte à chaud). Exercé avec
//! un `tsa-server` factice qui consigne ses sous-commandes.

use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::Duration;

fn root() -> PathBuf {
    PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/../.."))
}

fn run(extra: &[(&str, &str)]) -> Vec<String> {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("tsa-renewal-{nanos}"));
    let bin = dir.join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    let log = dir.join("calls.log");
    let fake = |name: &str, body: &str| {
        let path = bin.join(name);
        std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    };
    fake(
        "softhsm2-util",
        "case \"$1\" in --show-slots) echo 'Label: open-eidas-tsa';; esac\nexit 0",
    );
    // Le premier `enroll` (celui du démarrage) réussit, les suivants échouent :
    // un échec n'arrête pas la boucle. `serve` reste en vie quelques secondes.
    fake(
        "tsa-server",
        &format!(
            "echo \"$1\" >> {log}\ncase \"$1\" in\n serve) sleep 4;;\n enroll) [ \"$(grep -c enroll {log})\" -le 1 ];;\nesac",
            log = log.display()
        ),
    );
    let mut cmd = Command::new("sh");
    cmd.arg(root().join("deploy/tsa/entrypoint.sh"))
        .arg("serve")
        .env_clear()
        .env(
            "PATH",
            format!(
                "{}:{}",
                bin.display(),
                std::env::var("PATH").unwrap_or_default()
            ),
        )
        .env("OPENEIDAS_PIN", "user-1234")
        .env(
            "OPENEIDAS_ENROLL_ENDPOINT",
            "http://ca.invalid/api/v1/enroll",
        )
        .env("OPENEIDAS_ENROLL_ATTEMPTS", "1")
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    for (k, v) in extra {
        cmd.env(k, v);
    }
    let status = cmd.status().unwrap();
    assert!(status.success());
    std::thread::sleep(Duration::from_millis(300));
    let calls = std::fs::read_to_string(&log).unwrap_or_default();
    let _ = std::fs::remove_dir_all(&dir);
    calls.lines().map(str::to_string).collect()
}

#[test]
fn the_entrypoint_renews_in_the_background_while_the_service_runs() {
    let calls = run(&[("OPENEIDAS_RENEW_CHECK_SECONDS", "1")]);
    assert_eq!(calls[0], "enroll", "enrôlement de démarrage : {calls:?}");
    assert_eq!(calls[1], "serve", "{calls:?}");
    let later = calls.iter().skip(2).filter(|c| *c == "enroll").count();
    assert!(later >= 2, "la boucle doit relancer enroll : {calls:?}");
}

#[test]
fn the_background_renewal_can_be_disabled() {
    let calls = run(&[("OPENEIDAS_RENEW_CHECK_SECONDS", "0")]);
    assert_eq!(calls, ["enroll", "serve"], "{calls:?}");
}
