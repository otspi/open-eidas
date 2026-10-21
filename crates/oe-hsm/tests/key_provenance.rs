//! Constats H-1 et H-3 de l'audit du 2026-09-25 (EN 319 421 `TIS-7.6.2-03`,
//! `TIS-7.6.2-06`, `TIS-7.6.3-02` ; EN 319 401 `REQ-7.5-01`) contre un vrai
//! SoftHSM2 : une clé générée dans le module est acceptée, avec les attributs
//! qui le prouvent ; une clé importée est refusée, et deux objets répondant
//! au même label aussi.
//!
//! Fabrique ses propres tokens (répertoire temporaire, `SOFTHSM2_CONF`) : pas
//! de token de développement à préparer. Sans `softhsm2-util` ni `openssl`, le
//! test est ignoré — sauf si `OE_REQUIRE_SOFTHSM` est posée (CI), où il échoue.

#![cfg(feature = "pkcs11")]

use std::process::Command;

use oe_hsm::{DigestAlg, HsmError, Options, Pkcs11Token, SigningToken};
use sha2::{Digest, Sha256};

const MODULE_PATH: &str = "/usr/lib/softhsm/libsofthsm2.so";
const PIN: &str = "12345678";
const SO_PIN: &str = "87654321";
const KEY_LABEL: &str = "tsu-signing-key";

fn have(tool: &str) -> bool {
    Command::new(tool).arg("--help").output().is_ok() && std::path::Path::new(MODULE_PATH).exists()
}

fn run(cmd: &mut Command) {
    let out = cmd.output().unwrap();
    assert!(
        out.status.success(),
        "{cmd:?}: {}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

fn init_token(label: &str) {
    run(Command::new("softhsm2-util").args([
        "--init-token",
        "--free",
        "--label",
        label,
        "--pin",
        PIN,
        "--so-pin",
        SO_PIN,
    ]));
}

fn options(token: &str) -> Options {
    Options {
        module_path: MODULE_PATH.to_string(),
        token_label: token.to_string(),
        key_label: KEY_LABEL.to_string(),
        pin: PIN.to_string(),
    }
}

/// Importe dans `token` une clé RSA fabriquée à l'extérieur, sous le label et
/// le `CKA_ID` que le service cherche.
fn import_foreign_key(dir: &std::path::Path, token: &str, name: &str) {
    let key = dir.join(format!("{name}.pem"));
    run(Command::new("openssl")
        .args([
            "genpkey",
            "-algorithm",
            "RSA",
            "-pkeyopt",
            "rsa_keygen_bits:2048",
            "-out",
        ])
        .arg(&key));
    let id = hex::encode(&Sha256::digest(KEY_LABEL.as_bytes())[..8]);
    run(Command::new("softhsm2-util")
        .args(["--import"])
        .arg(&key)
        .args([
            "--token", token, "--label", KEY_LABEL, "--id", &id, "--pin", PIN, "--force",
        ]));
}

#[test]
fn only_a_key_born_in_the_module_is_used() {
    if !(have("softhsm2-util") && have("openssl")) {
        assert!(
            std::env::var_os("OE_REQUIRE_SOFTHSM").is_none(),
            "OE_REQUIRE_SOFTHSM est posée mais softhsm2-util, openssl ou le module manque"
        );
        eprintln!("softhsm2-util ou openssl absent : test de provenance ignoré");
        return;
    }
    let dir = std::env::temp_dir().join(format!("oe-hsm-prov-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("tokens")).unwrap();
    let conf = dir.join("softhsm2.conf");
    std::fs::write(
        &conf,
        format!(
            "directories.tokendir = {}\nobjectstore.backend = file\nlog.level = ERROR\n",
            dir.join("tokens").display()
        ),
    )
    .unwrap();
    // Avant la première ouverture : le module est chargé une fois par processus.
    std::env::set_var("SOFTHSM2_CONF", &conf);
    let digest = Sha256::digest(b"provenance");

    // Les trois tokens et les clés importées sont préparés avant la première
    // ouverture : le module ne voit pas un token créé après son chargement.
    init_token("generated");
    init_token("imported");
    init_token("ambiguous");
    import_foreign_key(&dir, "imported", "foreign");
    import_foreign_key(&dir, "ambiguous", "first");
    import_foreign_key(&dir, "ambiguous", "second");

    // Clé générée par le module : acceptée, et ses attributs le prouvent.
    let token = Pkcs11Token::open(&options("generated")).unwrap();
    token.generate_rsa_key(2048).unwrap();
    // Constat H-2 : une session perdue (utilisateur déconnecté par le module)
    // n'arrête pas le service, le token se reconnecte et rejoue la signature.
    token
        .sign_digest(DigestAlg::Sha256, &digest)
        .expect("signature");
    token.lose_session_for_test();
    token
        .sign_digest(DigestAlg::Sha256, &digest)
        .expect("signature après perte de session : reconnexion");
    token.lose_session_for_test();
    token
        .public_key_der()
        .expect("clé publique après perte de session");
    let p = token
        .verify_key_provenance()
        .expect("une clé générée est acceptée");
    assert!(
        p.local && p.never_extractable && p.always_sensitive && p.sign,
        "{p:?}"
    );
    // Constat H-3 : gabarit restreint à la signature par construction.
    assert!(!p.decrypt && !p.unwrap && !p.derive, "{p:?}");
    token
        .sign_digest(DigestAlg::Sha256, &digest)
        .expect("signature");

    // Clé importée : CKA_LOCAL faux, refusée avant toute signature.
    let token = Pkcs11Token::open(&options("imported")).unwrap();
    let err = token.sign_digest(DigestAlg::Sha256, &digest).unwrap_err();
    assert!(
        matches!(
            err,
            HsmError::KeyAttribute {
                attribute: "CKA_LOCAL",
                ..
            }
        ),
        "{err}"
    );
    assert!(token.verify_key_provenance().is_err());

    // Deux objets pour le même label et le même CKA_ID : ambigu, refusé.
    let token = Pkcs11Token::open(&options("ambiguous")).unwrap();
    let err = token.sign_digest(DigestAlg::Sha256, &digest).unwrap_err();
    assert!(matches!(err, HsmError::KeyAmbiguous(2, _)), "{err}");

    let _ = std::fs::remove_dir_all(&dir);
}
