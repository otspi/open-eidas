//! `tsa-server serve`, lancé pour de vrai (constat D-2 de l'audit du
//! 2026-09-25) : la matrice de conformité ne déclare « couvert » que ce que le
//! binaire en service applique, pas seulement ce qu'une bibliothèque sait
//! faire. Un vrai token SoftHSM porte la clé TSU, une CA de test émet son
//! certificat, et `openssl` relit les réponses en tiers indépendant.
//!
//! Ignoré, en le disant, si `softhsm2-util` ou `openssl` manquent — sauf si
//! `OE_REQUIRE_SOFTHSM` est posée (CI) : il échoue alors.

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use der::Encode;
use oe_ca_core::ceremony::{run_ceremony, CeremonyOptions};
use oe_ca_core::{profile, Issuer, Options as CaOptions};
use oe_hsm::testing::SoftwareToken;
use oe_hsm::SigningToken;

const MODULE: &str = "/usr/lib/softhsm/libsofthsm2.so";
const TOKEN: &str = "tsa-wiring";
const KEY: &str = "tsu-key";
const PIN: &str = "1234";

fn have_tools() -> bool {
    let runs = |cmd: &str, arg: &str| Command::new(cmd).arg(arg).output().is_ok();
    runs("softhsm2-util", "--version") && runs("openssl", "version") && Path::new(MODULE).exists()
}

fn pem(label: &str, der: &[u8]) -> String {
    let b64 = base64::engine::general_purpose::STANDARD.encode(der);
    let mut out = format!("-----BEGIN {label}-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).unwrap());
        out.push('\n');
    }
    out.push_str(&format!("-----END {label}-----\n"));
    out
}

/// Le processus est tué à la fin du test, même en cas d'échec d'assertion.
struct Server(Child);

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

struct Fixture {
    dir: PathBuf,
    conf: PathBuf,
}

impl Fixture {
    fn command(&self, cert: &str, policy: &str, port: u16, audit: &str) -> Command {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_tsa-server"));
        cmd.arg("serve")
            .env_clear()
            .env("PATH", std::env::var("PATH").unwrap_or_default())
            .env("SOFTHSM2_CONF", &self.conf)
            .env("OPENEIDAS_PKCS11_MODULE", MODULE)
            .env("OPENEIDAS_TOKEN_LABEL", TOKEN)
            .env("OPENEIDAS_KEY_LABEL", KEY)
            .env("OPENEIDAS_PIN", PIN)
            .env("OPENEIDAS_CERT_FILE", self.dir.join(cert))
            .env("OPENEIDAS_CHAIN_FILE", self.dir.join("chain.pem"))
            .env("OPENEIDAS_AUDIT_FILE", self.dir.join(audit))
            .env("OPENEIDAS_LISTEN", format!("127.0.0.1:{port}"))
            // Pas de TSA tierce par défaut : le test ne sort pas de la machine.
            .env("OPENEIDAS_CROSS_TSA_URLS", "")
            .env("OPENEIDAS_TIME_POLICY", policy)
            // Aucune source joignable : l'heure n'est jamais traçable.
            .env("OPENEIDAS_TIME_SOURCES", "127.0.0.1:9")
            .env("OPENEIDAS_TIME_MIN_SOURCES", "1")
            .env("OPENEIDAS_TIME_TIMEOUT", "200ms")
            .stdout(Stdio::null())
            .stderr(Stdio::piped());
        cmd
    }

    async fn serve(&self, cert: &str, policy: &str, audit: &str) -> (Server, String) {
        self.serve_with(cert, policy, audit, &[]).await
    }

    async fn serve_with(
        &self,
        cert: &str,
        policy: &str,
        audit: &str,
        env: &[(&str, &str)],
    ) -> (Server, String) {
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let child = self
            .command(cert, policy, port, audit)
            .envs(env.iter().copied())
            .spawn()
            .unwrap();
        let server = Server(child);
        for _ in 0..100 {
            if tokio::net::TcpStream::connect(("127.0.0.1", port))
                .await
                .is_ok()
            {
                return (server, format!("http://127.0.0.1:{port}"));
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        panic!("tsa-server n'écoute pas sur {port}");
    }

    fn openssl(&self, args: &[&str]) -> Output {
        Command::new("openssl")
            .args(args)
            .current_dir(&self.dir)
            .output()
            .unwrap()
    }

    /// Soumet une requête RFC 3161 fabriquée par openssl, rend le texte de la
    /// réponse tel qu'openssl le relit.
    async fn timestamp(&self, base: &str, digest: &str, name: &str) -> String {
        let query = format!("{name}.tsq");
        let reply = format!("{name}.tsr");
        let out = self.openssl(&[
            "ts", "-query", "-data", "data.txt", digest, "-cert", "-out", &query,
        ]);
        assert!(out.status.success(), "{out:?}");
        let body = std::fs::read(self.dir.join(&query)).unwrap();
        let resp = reqwest::Client::new()
            .post(format!("{base}/tsa"))
            .header("Content-Type", "application/timestamp-query")
            .body(body)
            .send()
            .await
            .unwrap();
        std::fs::write(self.dir.join(&reply), resp.bytes().await.unwrap()).unwrap();
        let text = self.openssl(&["ts", "-reply", "-in", &reply, "-text"]);
        String::from_utf8_lossy(&text.stdout).to_string()
    }
}

#[tokio::test]
async fn the_binary_applies_what_the_matrix_declares() {
    if !have_tools() {
        // En CI, cette preuve de mise en service ne doit jamais sauter en silence.
        assert!(
            std::env::var_os("OE_REQUIRE_SOFTHSM").is_none(),
            "OE_REQUIRE_SOFTHSM est posée mais softhsm2-util ou openssl manque"
        );
        eprintln!("softhsm2-util ou openssl absent : test du binaire tsa-server ignoré");
        return;
    }
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("tsa-serve-{nanos}"));
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
    let init = Command::new("softhsm2-util")
        .args([
            "--init-token",
            "--free",
            "--label",
            TOKEN,
            "--pin",
            PIN,
            "--so-pin",
            "5678",
        ])
        .env("SOFTHSM2_CONF", &conf)
        .output()
        .unwrap();
    assert!(init.status.success(), "{init:?}");

    // La clé TSU est générée dans le token, comme en service. Ce fichier de
    // test ne contient qu'un test : la variable ne fuit vers aucun autre.
    std::env::set_var("SOFTHSM2_CONF", &conf);
    let spki = {
        let token = oe_hsm::Pkcs11Token::open(&oe_hsm::Options {
            module_path: MODULE.to_string(),
            token_label: TOKEN.to_string(),
            key_label: KEY.to_string(),
            pin: PIN.to_string(),
        })
        .unwrap();
        token.generate_rsa_key(3072).unwrap();
        token.public_key_der().unwrap()
    };

    // Une CA de test émet, pour cette clé, un certificat au profil TSU et un
    // autre au profil du répondeur OCSP.
    let store = Arc::new(oe_castore::Memory::new());
    let issuing_signer = Arc::new(SoftwareToken::generate(3072));
    let hierarchy = run_ceremony(CeremonyOptions {
        root_signer: Arc::new(SoftwareToken::generate(3072)),
        issuing_signer: issuing_signer.clone(),
        root_cn: "Test Root CA".to_string(),
        issuing_cn: "Test Issuing CA".to_string(),
        organization: "Open eIDAS Test".to_string(),
        country: "FR".to_string(),
        root_validity: time::Duration::days(20 * 365),
        issuing_validity: time::Duration::days(10 * 365),
        root_token_label: "root".to_string(),
        root_key_label: "root-key".to_string(),
        issuing_token_label: "issuing".to_string(),
        issuing_key_label: "issuing-key".to_string(),
        store: store.clone(),
        operator: "test-operator".to_string(),
        public_url: "https://ca.example.test".to_string(),
        recorder: None,
    })
    .await
    .unwrap();
    let issuer = Issuer::new(CaOptions {
        signer: issuing_signer,
        certificate: hierarchy.issuing.clone(),
        chain: vec![hierarchy.root.clone()],
        store,
        public_url: "https://ca.example.test".to_string(),
        ocsp_url: None,
        crl_validity: time::Duration::hours(24),
        recorder: None,
    })
    .unwrap();
    let tsu = issuer
        .issue(&spki, "tsu.example.test", &profile::tsa_signer(), "tx-tsu")
        .await
        .unwrap();
    let ocsp = issuer
        .issue(
            &spki,
            "ocsp.example.test",
            &profile::ocsp_responder(),
            "tx-ocsp",
        )
        .await
        .unwrap();
    std::fs::write(
        dir.join("tsu.pem"),
        pem("CERTIFICATE", &tsu.to_der().unwrap()),
    )
    .unwrap();
    std::fs::write(
        dir.join("ocsp.pem"),
        pem("CERTIFICATE", &ocsp.to_der().unwrap()),
    )
    .unwrap();
    // Constat T-3 : un certificat TSU par ailleurs valide, mais dont la clé a
    // déjà dépassé sa propre date d'expiration (privateKeyUsagePeriod).
    let expired_key_profile = oe_ca_core::Profile {
        private_key_validity: Some(time::Duration::minutes(-5)),
        ..profile::tsa_signer()
    };
    let expired_key = issuer
        .issue(
            &spki,
            "tsu.example.test",
            &expired_key_profile,
            "tx-tsu-old",
        )
        .await
        .unwrap();
    std::fs::write(
        dir.join("tsu-expired-key.pem"),
        pem("CERTIFICATE", &expired_key.to_der().unwrap()),
    )
    .unwrap();
    let chain = [&hierarchy.issuing, &hierarchy.root]
        .iter()
        .map(|c| pem("CERTIFICATE", &c.to_der().unwrap()))
        .collect::<String>();
    std::fs::write(dir.join("chain.pem"), &chain).unwrap();
    std::fs::write(dir.join("data.txt"), "facture de test\n").unwrap();

    let fx = Fixture {
        dir: dir.clone(),
        conf,
    };

    // EN 319 422 §6 : un certificat qui n'est pas au profil TSU est refusé au
    // démarrage (oe_conformance::check_tsu_certificate, via Authority::new).
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let refused = fx
        .command("ocsp.pem", "monitor", port, "audit-refused.log")
        .output()
        .unwrap();
    assert!(!refused.status.success(), "{refused:?}");
    let stderr = String::from_utf8_lossy(&refused.stderr);
    assert!(stderr.contains("certificat TSU"), "{stderr}");

    // EN 319 421 TIS-7.7.1-05/-06 (constat T-1) : une exactitude annoncée
    // plus serrée que la dérive tolérée plus la résolution de genTime est
    // refusée au démarrage (oe_config::Config::load).
    let refused = fx
        .command("tsu.pem", "monitor", port, "audit-accuracy.log")
        .env("OPENEIDAS_ACCURACY", "500ms")
        .env("OPENEIDAS_TIME_MAX_OFFSET", "500ms")
        .output()
        .unwrap();
    assert!(!refused.status.success(), "{refused:?}");
    let stderr = String::from_utf8_lossy(&refused.stderr);
    assert!(stderr.contains("OPENEIDAS_ACCURACY"), "{stderr}");

    // EN 319 421 TIS-7.7.1-09 (constat T-3) : la clé de signature a dépassé
    // sa date d'expiration, le certificat non — aucun jeton ne sort.
    {
        let (_server, base) = fx
            .serve("tsu-expired-key.pem", "monitor", "audit-expired-key.log")
            .await;
        let text = fx.timestamp(&base, "-sha256", "expired-key").await;
        assert!(text.contains("Status: Rejected"), "{text}");
        assert!(!text.contains("Status: Granted"), "{text}");
    }

    // EN 319 421 TIS-7.7.1-07 : politique enforce et heure non traçable → la
    // TSU cesse d'émettre (timeNotAvailable) et /healthz le dit.
    {
        let (_server, base) = fx.serve("tsu.pem", "enforce", "audit-enforce.log").await;
        let health = reqwest::get(format!("{base}/healthz")).await.unwrap();
        assert_eq!(health.status(), reqwest::StatusCode::SERVICE_UNAVAILABLE);
        let text = fx.timestamp(&base, "-sha256", "enforce").await;
        assert!(text.contains("Status: Rejected"), "{text}");
        assert!(text.contains("time source is not available"), "{text}");
    }

    // Politique monitor : le jeton est émis, et openssl le vérifie (EN 319 422
    // §7, clé dans le token : EN 319 401 REQ-7.5-01). TS 119 312 §5.1 : une
    // empreinte SHA-1 est refusée (badAlg).
    {
        let (_server, base) = fx.serve("tsu.pem", "monitor", "audit-monitor.log").await;

        // EN 319 401 REQ-7.10-02, REQ-7.10-08 (constat J-1) : dès le démarrage,
        // le service fait horodater la tête de son journal par sa propre TSU,
        // et /healthz dit où en sont le scellement et la copie hors site.
        let mut journal = serde_json::Value::Null;
        for _ in 0..100 {
            let health: serde_json::Value = reqwest::get(format!("{base}/healthz"))
                .await
                .unwrap()
                .json()
                .await
                .unwrap();
            journal = health["journal"].clone();
            if journal["last_seal"].is_string() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert!(journal["last_seal"].is_string(), "{journal}");
        assert_eq!(journal["degraded"], false, "{journal}");
        assert_eq!(journal["offsite_copy"], "non configurée", "{journal}");
        let sealed: Vec<_> = oe_audit::read(fx.dir.join("audit-monitor.log"))
            .unwrap()
            .into_iter()
            .filter(|r| r.event == "log.sealed")
            .collect();
        assert_eq!(sealed.len(), 1, "{sealed:?}");
        let seal = sealed[0].data.as_ref().expect("données du sceau");
        // Le jeton du sceau, relu par openssl : signé par la clé du token, sur
        // la tête de chaîne que le sceau déclare.
        std::fs::write(
            fx.dir.join("seal.tsr"),
            base64::engine::general_purpose::STANDARD
                .decode(seal["token"].as_str().unwrap())
                .unwrap(),
        )
        .unwrap();
        let verify = fx.openssl(&[
            "ts",
            "-verify",
            "-digest",
            seal["sealed_head"].as_str().unwrap(),
            "-in",
            "seal.tsr",
            "-CAfile",
            "chain.pem",
        ]);
        assert!(
            verify.status.success(),
            "{}{}",
            String::from_utf8_lossy(&verify.stdout),
            String::from_utf8_lossy(&verify.stderr)
        );

        let text = fx.timestamp(&base, "-sha256", "granted").await;
        assert!(text.contains("Status: Granted"), "{text}");
        let verify = fx.openssl(&[
            "ts",
            "-verify",
            "-in",
            "granted.tsr",
            "-queryfile",
            "granted.tsq",
            "-CAfile",
            "chain.pem",
        ]);
        assert!(
            verify.status.success(),
            "{}{}",
            String::from_utf8_lossy(&verify.stdout),
            String::from_utf8_lossy(&verify.stderr)
        );

        // EN 319 421 OVR-7.13-05 (constat J-3) : le journal du service consigne
        // la série du **jeton** relu (celle qu'openssl lit dans la réponse),
        // l'empreinte soumise et l'état de l'horloge à l'instant de l'émission.
        let serial = text
            .lines()
            .find_map(|l| l.trim().strip_prefix("Serial number: 0x"))
            .expect("openssl affiche la série du jeton")
            .trim()
            .to_ascii_lowercase();
        let records = oe_audit::read(fx.dir.join("audit-monitor.log")).unwrap();
        // Le jeton du sceau est un jeton comme un autre : il est journalisé
        // lui aussi. Celui du client se reconnaît à son empreinte, qui n'est
        // pas la tête de chaîne scellée.
        let granted: Vec<_> = records
            .iter()
            .filter(|r| r.event == "timestamp.granted")
            .filter(|r| {
                r.data
                    .as_ref()
                    .is_some_and(|d| d["message_imprint"] != seal["sealed_head"])
            })
            .collect();
        assert_eq!(granted.len(), 1, "{records:?}");
        assert_eq!(
            records
                .iter()
                .filter(|r| r.event == "timestamp.granted")
                .count(),
            2,
            "{records:?}"
        );
        let data = granted[0].data.as_ref().expect("données du jeton");
        let journaled = data["serial_number"]
            .as_str()
            .unwrap()
            .trim_start_matches('0');
        assert_eq!(journaled, serial.trim_start_matches('0'), "{data:?}");
        assert_eq!(
            data["message_imprint_alg"], "2.16.840.1.101.3.4.2.1",
            "{data:?}"
        );
        assert_eq!(
            data["message_imprint"].as_str().unwrap().len(),
            64,
            "{data:?}"
        );
        assert_eq!(data["horloge"]["politique"], "monitor", "{data:?}");
        assert!(
            data["gen_time"].as_str().unwrap().ends_with('Z'),
            "{data:?}"
        );

        // EN 319 422 §5.2.2 (constat T-1) : genTime porte une fraction de
        // seconde. Une fraction exactement nulle est omise (forme canonique
        // DER) : deux jetons ne peuvent pas l'être tous les deux par hasard.
        let has_fraction = |t: &str| {
            t.lines()
                .find(|l| l.trim().starts_with("Time stamp:"))
                .is_some_and(|l| l.contains('.'))
        };
        let fractional = has_fraction(&text) || {
            let again = fx.timestamp(&base, "-sha256", "granted-bis").await;
            has_fraction(&again)
        };
        assert!(fractional, "genTime sans fraction de seconde : {text}");

        // Constat J-1, contreseing : une seconde instance du binaire prend la
        // première pour TSA tierce. La tête qu'elle scelle elle-même est aussi
        // horodatée par l'autre, et ce jeton-là se vérifie de la même façon.
        {
            let tierce = format!("{base}/tsa");
            let (_second, second) = fx
                .serve_with(
                    "tsu.pem",
                    "monitor",
                    "audit-cross.log",
                    &[("OPENEIDAS_CROSS_TSA_URLS", tierce.as_str())],
                )
                .await;
            let mut journal = serde_json::Value::Null;
            for _ in 0..100 {
                let health: serde_json::Value = reqwest::get(format!("{second}/healthz"))
                    .await
                    .unwrap()
                    .json()
                    .await
                    .unwrap();
                journal = health["journal"].clone();
                if journal["last_cross_seal"].is_string() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            assert_eq!(journal["cross_tsas"], 1, "{journal}");
            assert_eq!(journal["last_cross_seal_count"], 1, "{journal}");
            assert_eq!(journal["degraded"], false, "{journal}");
            let records = oe_audit::read(fx.dir.join("audit-cross.log")).unwrap();
            let own = records
                .iter()
                .find(|r| r.event == "log.sealed")
                .and_then(|r| r.data.clone())
                .expect("sceau de la TSU");
            let cross = records
                .iter()
                .find(|r| r.event == "log.cross_sealed")
                .and_then(|r| r.data.clone())
                .expect("contreseing tiers");
            assert_eq!(cross["sealed_head"], own["sealed_head"]);
            std::fs::write(
                fx.dir.join("cross.tsr"),
                base64::engine::general_purpose::STANDARD
                    .decode(cross["token"].as_str().unwrap())
                    .unwrap(),
            )
            .unwrap();
            let verify = fx.openssl(&[
                "ts",
                "-verify",
                "-digest",
                cross["sealed_head"].as_str().unwrap(),
                "-in",
                "cross.tsr",
                "-CAfile",
                "chain.pem",
            ]);
            assert!(
                verify.status.success(),
                "{}{}",
                String::from_utf8_lossy(&verify.stdout),
                String::from_utf8_lossy(&verify.stderr)
            );
            // Ce contreseing est un jeton de plus dans le journal de la première.
            let first = oe_audit::read(fx.dir.join("audit-monitor.log")).unwrap();
            assert!(
                first.iter().any(|r| r.event == "timestamp.granted"
                    && r.data
                        .as_ref()
                        .is_some_and(|d| d["message_imprint"] == cross["sealed_head"])),
                "la TSA tierce n'a pas journalisé le jeton du contreseing"
            );
        }

        let text = fx.timestamp(&base, "-sha1", "sha1").await;
        assert!(text.contains("Status: Rejected"), "{text}");
        assert!(
            text.to_lowercase()
                .contains("unrecognized or unsupported algorithm"),
            "{text}"
        );
    }

    let _ = std::fs::remove_dir_all(&dir);
}
