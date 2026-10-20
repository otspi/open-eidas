//! Constat C-2 de l'audit du 2026-09-25 (EN 319 411-1 `OVR-6.5.7-05`,
//! `GEN-6.5.1-04`) : en production (`OPENEIDAS_PRODUCTION`), aucun PIN n'est
//! repris d'un autre — ni celui de la racine sur celui de l'émettrice, ni un
//! PIN SO sur le PIN utilisateur de son token. Hors production, les replis de
//! la démonstration restent admis.
//!
//! La configuration est exercée par le binaire lui-même ; les entrypoints par
//! `sh`, avec un `softhsm2-util` factice qui consigne ses arguments : un refus
//! doit survenir avant tout appel, et un démarrage admis doit transmettre les
//! PIN SO distincts.

use std::path::PathBuf;
use std::process::{Command, Output};

fn root() -> PathBuf {
    PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/../.."))
}

fn tmp(name: &str) -> PathBuf {
    static COUNTER: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let p = std::env::temp_dir().join(format!("oe-pins-{name}-{}-{n}", std::process::id()));
    let _ = std::fs::remove_dir_all(&p);
    std::fs::create_dir_all(&p).unwrap();
    p
}

fn text(out: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

/// Le binaire avec la configuration minimale d'une CA ; les variables de
/// `extra` s'y ajoutent.
fn ca_config(extra: &[(&str, &str)]) -> Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_ca-server"));
    cmd.arg("ceremony")
        .env_clear()
        .env("OPENEIDAS_DB_DSN", "postgres://x:x@127.0.0.1:1/x")
        .env("OPENEIDAS_PKI_PUBLIC_URL", "https://ca.example.test")
        .env("OPENEIDAS_ISSUING_PIN", "1111-issuing")
        .env("OPENEIDAS_CEREMONY_OPERATOR", "test");
    for (k, v) in extra {
        cmd.env(k, v);
    }
    cmd.output().unwrap()
}

#[test]
fn production_refuses_a_root_pin_that_falls_back_on_the_issuing_pin() {
    let out = ca_config(&[("OPENEIDAS_PRODUCTION", "true")]);
    assert!(!out.status.success());
    assert!(
        text(&out).contains("OPENEIDAS_ROOT_PIN est obligatoire"),
        "{}",
        text(&out)
    );

    let out = ca_config(&[
        ("OPENEIDAS_PRODUCTION", "true"),
        ("OPENEIDAS_ROOT_PIN", "1111-issuing"),
    ]);
    assert!(!out.status.success());
    assert!(text(&out).contains("doit différer"), "{}", text(&out));
}

#[test]
fn outside_production_the_root_pin_may_fall_back() {
    // Pas de refus de configuration : le binaire passe la lecture de la
    // configuration et s'attarde sur la base injoignable (on l'arrête).
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_ca-server"));
    cmd.arg("ceremony")
        .env_clear()
        .env("OPENEIDAS_DB_DSN", "postgres://x:x@127.0.0.1:1/x")
        .env("OPENEIDAS_PKI_PUBLIC_URL", "https://ca.example.test")
        .env("OPENEIDAS_ISSUING_PIN", "1111-issuing")
        .env("OPENEIDAS_CEREMONY_OPERATOR", "test")
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    let mut child = cmd.spawn().unwrap();
    std::thread::sleep(std::time::Duration::from_secs(2));
    let exited = child.try_wait().unwrap().is_some();
    let _ = child.kill();
    let out = child.wait_with_output().unwrap();
    assert!(!text(&out).contains("OPENEIDAS_ROOT_PIN"), "{}", text(&out));
    let _ = exited;
}

/// Lance un entrypoint avec un `softhsm2-util` factice et `ca-server` /
/// `tsa-server` remplacés par des commandes inoffensives. Rend la sortie et
/// les arguments passés à `softhsm2-util`.
fn entrypoint(script: &str, env: &[(&str, &str)]) -> (Output, String) {
    let dir = tmp(&script.replace('/', "_"));
    let log = dir.join("softhsm.log");
    let bin = dir.join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    let fake = |name: &str, body: &str| {
        let path = bin.join(name);
        std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    };
    fake(
        "softhsm2-util",
        &format!(
            "case \"$1\" in --show-slots) exit 0;; esac\necho \"$@\" >> {}\nexit 0",
            log.display()
        ),
    );
    for name in ["ca-server", "tsa-server", "ocsp-responder"] {
        fake(name, "exit 0");
    }
    let mut cmd = Command::new("sh");
    cmd.arg(root().join(script)).arg("version").env_clear().env(
        "PATH",
        format!(
            "{}:{}",
            bin.display(),
            std::env::var("PATH").unwrap_or_default()
        ),
    );
    for (k, v) in env {
        cmd.env(k, v);
    }
    let out = cmd.output().unwrap();
    (out, std::fs::read_to_string(&log).unwrap_or_default())
}

#[test]
fn the_ca_entrypoint_refuses_shared_pins_in_production() {
    let base = [
        ("OPENEIDAS_PRODUCTION", "true"),
        ("OPENEIDAS_ISSUING_PIN", "iss-1234"),
        ("OPENEIDAS_ROOT_PIN", "root-1234"),
        ("OPENEIDAS_ROOT_SO_PIN", "root-so-1234"),
        ("OPENEIDAS_ISSUING_SO_PIN", "iss-so-1234"),
    ];
    // Réglage complet : accepté, et les PIN SO distincts atteignent SoftHSM.
    let (out, log) = entrypoint("deploy/ca-server/entrypoint.sh", &base);
    assert!(out.status.success(), "{}", text(&out));
    assert!(
        log.contains("--so-pin root-so-1234") && log.contains("--so-pin iss-so-1234"),
        "{log}"
    );

    let without = |key: &str| -> Vec<(&str, &str)> {
        base.iter().copied().filter(|(k, _)| *k != key).collect()
    };
    for missing in [
        "OPENEIDAS_ROOT_PIN",
        "OPENEIDAS_ROOT_SO_PIN",
        "OPENEIDAS_ISSUING_SO_PIN",
    ] {
        let (out, log) = entrypoint("deploy/ca-server/entrypoint.sh", &without(missing));
        assert!(!out.status.success(), "{missing} absent doit être refusé");
        assert!(text(&out).contains(missing), "{}", text(&out));
        assert!(
            log.is_empty(),
            "aucun token ne doit être initialisé : {log}"
        );
    }
    // Racine = émettrice, ou PIN SO = PIN utilisateur : refusés.
    for (key, value) in [
        ("OPENEIDAS_ROOT_PIN", "iss-1234"),
        ("OPENEIDAS_ROOT_SO_PIN", "root-1234"),
        ("OPENEIDAS_ISSUING_SO_PIN", "iss-1234"),
    ] {
        let mut env = without(key);
        env.push((key, value));
        let (out, log) = entrypoint("deploy/ca-server/entrypoint.sh", &env);
        assert!(!out.status.success(), "{key}={value} doit être refusé");
        assert!(log.is_empty(), "{log}");
    }
}

#[test]
fn the_ca_entrypoint_keeps_the_demo_fallbacks_outside_production() {
    let (out, log) = entrypoint(
        "deploy/ca-server/entrypoint.sh",
        &[("OPENEIDAS_ISSUING_PIN", "iss-1234")],
    );
    assert!(out.status.success(), "{}", text(&out));
    assert!(log.contains("--pin iss-1234 --so-pin iss-1234"), "{log}");
}

#[test]
fn the_tsa_and_ocsp_entrypoints_refuse_a_so_pin_that_falls_back_in_production() {
    for script in [
        "deploy/tsa/entrypoint.sh",
        "deploy/ocsp-responder/entrypoint.sh",
    ] {
        let base = [
            ("OPENEIDAS_PRODUCTION", "true"),
            ("OPENEIDAS_PIN", "user-1234"),
        ];
        let (out, log) = entrypoint(script, &base);
        assert!(
            !out.status.success(),
            "{script} sans PIN SO doit être refusé"
        );
        assert!(text(&out).contains("OPENEIDAS_SO_PIN"), "{}", text(&out));
        assert!(log.is_empty(), "{log}");

        let (out, _) = entrypoint(
            script,
            &[base[0], base[1], ("OPENEIDAS_SO_PIN", "user-1234")],
        );
        assert!(!out.status.success(), "{script} PIN SO = PIN utilisateur");

        let (out, log) = entrypoint(script, &[base[0], base[1], ("OPENEIDAS_SO_PIN", "so-5678")]);
        assert!(out.status.success(), "{script}: {}", text(&out));
        assert!(log.contains("--so-pin so-5678"), "{log}");

        // Hors production : repli admis.
        let (out, log) = entrypoint(script, &[("OPENEIDAS_PIN", "user-1234")]);
        assert!(out.status.success(), "{script}: {}", text(&out));
        assert!(log.contains("--so-pin user-1234"), "{log}");
    }
}
