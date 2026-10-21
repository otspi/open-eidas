//! Cérémonie de clé du vrai binaire `ca-server` avec `OPENEIDAS_RSA_SCHEME=pss`,
//! sur deux vrais tokens SoftHSM2 (`CKM_RSA_PKCS_PSS`) et un PostgreSQL : la
//! racine, l'émettrice et l'ARL initiale doivent être vérifiés par openssl,
//! vérificateur indépendant (décision du 2026-10-21, RSASSA-PSS partout).
//!
//! Ignoré, en le disant, sans `OE_CASTORE_TEST_DSN`, `softhsm2-util` ou
//! `openssl` — sauf si `OE_REQUIRE_SOFTHSM` est posée (CI) : il échoue alors.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use der::Encode;
use sqlx::postgres::PgPoolOptions;

const MODULE: &str = "/usr/lib/softhsm/libsofthsm2.so";

fn runs(cmd: &str, arg: &str) -> bool {
    Command::new(cmd)
        .arg(arg)
        .output()
        .is_ok_and(|o| o.status.success())
}

fn pem(label: &str, der: &[u8]) -> String {
    pem::encode(&pem::Pem::new(label, der.to_vec()))
}

fn text(out: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

fn openssl(dir: &Path, args: &[&str]) -> Output {
    Command::new("openssl")
        .args(args)
        .current_dir(dir)
        .output()
        .unwrap()
}

#[tokio::test]
async fn a_pss_ceremony_yields_a_hierarchy_openssl_verifies() {
    let dsn_base = std::env::var("OE_CASTORE_TEST_DSN").ok();
    let tools = runs("softhsm2-util", "--version")
        && runs("openssl", "version")
        && Path::new(MODULE).exists();
    let (Some(base), true) = (dsn_base, tools) else {
        assert!(
            std::env::var_os("OE_REQUIRE_SOFTHSM").is_none(),
            "OE_REQUIRE_SOFTHSM est posée mais PostgreSQL, softhsm2-util ou openssl manque"
        );
        eprintln!("PostgreSQL, softhsm2-util ou openssl absent : cérémonie PSS ignorée");
        return;
    };

    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir: PathBuf = std::env::temp_dir().join(format!("pss-ceremony-{nanos}"));
    std::fs::create_dir_all(dir.join("tokens")).unwrap();
    let conf = dir.join("softhsm.conf");
    std::fs::write(
        &conf,
        format!(
            "directories.tokendir = {}\nobjectstore.backend = file\nlog.level = ERROR\n",
            dir.join("tokens").display()
        ),
    )
    .unwrap();
    for (label, pin) in [
        ("open-eidas-root", "1111-root"),
        ("open-eidas-issuing", "2222-issuing"),
    ] {
        let init = Command::new("softhsm2-util")
            .args([
                "--init-token",
                "--free",
                "--label",
                label,
                "--pin",
                pin,
                "--so-pin",
                "9999-so",
            ])
            .env("SOFTHSM2_CONF", &conf)
            .output()
            .unwrap();
        assert!(init.status.success(), "{init:?}");
    }

    let db = format!("pss_{nanos}_{}", std::process::id());
    let admin = PgPoolOptions::new().connect(&base).await.unwrap();
    sqlx::query(&format!("CREATE DATABASE {db}"))
        .execute(&admin)
        .await
        .unwrap();
    let (head, _) = base.rsplit_once('/').unwrap();
    let dsn = format!("{head}/{db}");

    let out = Command::new(env!("CARGO_BIN_EXE_ca-server"))
        .arg("ceremony")
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("SOFTHSM2_CONF", &conf)
        .env("OPENEIDAS_PKCS11_MODULE", MODULE)
        .env("OPENEIDAS_DB_DSN", &dsn)
        .env("OPENEIDAS_AUDIT_FILE", dir.join("audit.log"))
        .env("OPENEIDAS_PKI_PUBLIC_URL", "https://ca.example.test")
        .env("OPENEIDAS_ROOT_PIN", "1111-root")
        .env("OPENEIDAS_ISSUING_PIN", "2222-issuing")
        .env("OPENEIDAS_CEREMONY_OPERATOR", "test")
        .env("OPENEIDAS_RSA_SCHEME", "pss")
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", text(&out));

    let store = oe_castore::Postgres::open(&dsn).await.unwrap();
    let h = oe_ca_core::ceremony::load_hierarchy(&store)
        .await
        .unwrap()
        .expect("hiérarchie enregistrée par la cérémonie");
    let arl = oe_castore::Store::latest_arl(&store).await.unwrap();
    std::fs::write(
        dir.join("root.pem"),
        pem("CERTIFICATE", &h.root.to_der().unwrap()),
    )
    .unwrap();
    std::fs::write(
        dir.join("issuing.pem"),
        pem("CERTIFICATE", &h.issuing.to_der().unwrap()),
    )
    .unwrap();
    std::fs::write(dir.join("arl.pem"), pem("X509 CRL", &arl.der)).unwrap();

    // Les trois objets annoncent RSASSA-PSS, et openssl vérifie les signatures.
    for file in ["root.pem", "issuing.pem"] {
        let t = openssl(&dir, &["x509", "-in", file, "-noout", "-text"]);
        assert!(
            text(&t).contains("Signature Algorithm: rsassaPss"),
            "{file}: {}",
            text(&t)
        );
    }
    let t = openssl(&dir, &["crl", "-in", "arl.pem", "-noout", "-text"]);
    assert!(text(&t).contains("rsassaPss"), "{}", text(&t));

    let v = openssl(&dir, &["verify", "-CAfile", "root.pem", "root.pem"]);
    assert!(v.status.success(), "racine auto-signée : {}", text(&v));
    let v = openssl(&dir, &["verify", "-CAfile", "root.pem", "issuing.pem"]);
    assert!(
        v.status.success(),
        "émettrice signée par la racine : {}",
        text(&v)
    );
    let v = openssl(
        &dir,
        &["crl", "-in", "arl.pem", "-CAfile", "root.pem", "-noout"],
    );
    assert!(
        v.status.success() && text(&v).contains("verify OK"),
        "ARL signée par la racine : {}",
        text(&v)
    );

    // Pour `pkilint` en CI (.github/workflows/ci.yml) : la hiérarchie PSS
    // produite par la cérémonie est exportée si le dossier est demandé.
    if let Some(export) = std::env::var_os("OE_PKI_EXPORT_DIR") {
        let export = PathBuf::from(export);
        std::fs::create_dir_all(&export).unwrap();
        for file in ["root.pem", "issuing.pem", "arl.pem"] {
            std::fs::copy(dir.join(file), export.join(format!("pss-{file}"))).unwrap();
        }
    }

    let _ = std::fs::remove_dir_all(&dir);
}
