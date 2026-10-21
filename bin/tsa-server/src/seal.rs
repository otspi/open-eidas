//! Scellement du journal d'audit de `tsa-server` par sa propre TSU (constat
//! J-1 de l'audit du 2026-09-25) : la boucle, le contreseing tiers et la copie
//! hors site sont ceux d'`oe-seal`, communs aux trois services ; ici, seule
//! l'autorité qui scelle est particulière — la TSU du service, en mémoire,
//! sans passer par HTTP.

use std::sync::Arc;

use der::Encode;
use oe_tsa_core::Authority;

/// Scelle par la TSU du service : une signature HSM, bloquante, faite hors
/// de l'exécuteur asynchrone.
pub struct AuthorityStamper(pub Arc<Authority>);

#[async_trait::async_trait]
impl oe_seal::Stamper for AuthorityStamper {
    async fn stamp(&self, digest: &[u8]) -> Result<oe_seal::Stamp, String> {
        let request = oe_rfc3161_asn1::TimeStampReq {
            version: 1,
            message_imprint: oe_rfc3161_asn1::MessageImprint {
                hash_algorithm: oe_seal::sha256()?,
                hashed_message: der::asn1::OctetString::new(digest.to_vec())
                    .map_err(|e| e.to_string())?,
            },
            req_policy: None,
            nonce: None,
            // Le certificat de la TSU voyage avec le jeton : le sceau se
            // vérifie des années plus tard sans avoir à le retrouver.
            cert_req: true,
            extensions: None,
        }
        .to_der()
        .map_err(|e| e.to_string())?;
        let authority = self.0.clone();
        let token = tokio::task::spawn_blocking(move || authority.timestamp(&request))
            .await
            .map_err(|e| e.to_string())?
            .map_err(|e| e.to_string())?;
        Ok(oe_seal::Stamp { token, tsa: None })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;

    use base64::Engine;
    use der::Decode;
    use oe_audit::JournalHealth;
    use oe_hsm::testing::SoftwareToken;
    use oe_seal::{Outcome, Sealer, MAX_FAILURES};
    use time::OffsetDateTime;

    struct Dir(std::path::PathBuf);

    impl Dir {
        fn new(name: &str) -> Dir {
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let p = std::env::temp_dir()
                .join(format!("tsa-seal-{name}-{nanos}-{}", std::process::id()));
            std::fs::create_dir_all(&p).unwrap();
            Dir(p)
        }
    }

    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// Une horloge qu'on peut rendre indisponible : l'autorité refuse alors
    /// d'horodater, donc de sceller.
    struct SwitchClock(Arc<AtomicBool>);

    impl oe_tsa_core::Clock for SwitchClock {
        fn now(&self) -> Result<OffsetDateTime, String> {
            if self.0.load(Ordering::SeqCst) {
                Err("heure non traçable (test)".into())
            } else {
                Ok(OffsetDateTime::now_utc())
            }
        }
    }

    fn fixtures() -> std::path::PathBuf {
        std::path::PathBuf::from(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../tests/fixtures/tsa"
        ))
    }

    fn authority(clock_down: Arc<AtomicBool>) -> Arc<Authority> {
        let key = std::fs::read_to_string(fixtures().join("tsu-key.pem")).unwrap();
        let cert = std::fs::read_to_string(fixtures().join("tsu-cert.pem")).unwrap();
        let cert = pem::parse(cert.as_bytes()).unwrap();
        Arc::new(
            Authority::new(oe_tsa_core::Options {
                signer: Arc::new(SoftwareToken::from_pkcs8_pem(&key).unwrap()),
                certificate: x509_cert::Certificate::from_der(cert.contents()).unwrap(),
                chain: Vec::new(),
                policy: der::asn1::ObjectIdentifier::new("1.3.6.1.4.1.67027.9.1.1.1").unwrap(),
                accuracy: Duration::from_secs(1),
                signing_digest: oe_hsm::DigestAlg::Sha256,
                signature_scheme: oe_hsm::Scheme::Pkcs1v15,
                clock: Arc::new(SwitchClock(clock_down)),
                recorder: None,
            })
            .unwrap(),
        )
    }

    struct Env {
        sealer: Arc<Sealer>,
        log: Arc<oe_audit::Log>,
        path: std::path::PathBuf,
        clock_down: Arc<AtomicBool>,
        _dir: Dir,
    }

    fn env(name: &str) -> Env {
        let dir = Dir::new(name);
        let path = dir.0.join("audit.log");
        let log = Arc::new(oe_audit::Log::open(&path).unwrap());
        log.append(oe_audit::EVENT_OPENED, None).unwrap();
        let clock_down = Arc::new(AtomicBool::new(false));
        let sealer = Arc::new(Sealer::new(oe_seal::Options {
            log: log.clone(),
            path: path.to_string_lossy().into_owned(),
            stamper: Arc::new(AuthorityStamper(authority(clock_down.clone()))),
            cross_tsas: Vec::new(),
            cross_timeout: Duration::from_secs(2),
            s3: None,
        }));
        Env {
            sealer,
            log,
            path,
            clock_down,
            _dir: dir,
        }
    }

    fn seals(path: &std::path::Path) -> Vec<oe_audit::Record> {
        oe_audit::read(path)
            .unwrap()
            .into_iter()
            .filter(|r| r.event == oe_audit::EVENT_SEALED)
            .collect()
    }

    /// Le sceau porte un jeton RFC 3161 de la TSU dont l'empreinte est la tête
    /// de chaîne d'avant le scellement : openssl, tiers indépendant, le vérifie.
    /// Scellé en mémoire, sans HTTP : aucun nom d'autorité n'est consigné, le
    /// jeton porte le certificat de la TSU.
    #[tokio::test]
    async fn a_pass_seals_the_head_with_a_tsu_token_openssl_verifies() {
        let env = env("seal");
        let (seq, head) = env.log.head().unwrap();

        let outcome = env.sealer.once().await;
        assert_eq!(
            outcome,
            Outcome {
                sealed: true,
                cross_sealed: None,
                copied: None
            }
        );

        let seals = seals(&env.path);
        assert_eq!(seals.len(), 1);
        let data = seals[0].data.as_ref().unwrap();
        assert_eq!(data["sealed_seq"], seq);
        assert_eq!(data["sealed_head"], head.as_str());
        assert!(data.get("tsa").is_none(), "{data:?}");
        assert_eq!(oe_audit::verify(&env.path).unwrap().seals, 1);

        let token = base64::engine::general_purpose::STANDARD
            .decode(data["token"].as_str().unwrap())
            .unwrap();
        let token_path = env.path.with_file_name("seal.tsr");
        std::fs::write(&token_path, token).unwrap();
        let cert = fixtures().join("tsu-cert.pem");
        let verify = |digest: &str| {
            std::process::Command::new("openssl")
                .args(["ts", "-verify", "-digest", digest, "-in"])
                .arg(&token_path)
                .arg("-CAfile")
                .arg(&cert)
                .output()
                .unwrap()
        };
        let ok = verify(&head);
        assert!(
            ok.status.success(),
            "{}",
            String::from_utf8_lossy(&ok.stderr)
        );
        // Le même jeton ne vaut pour aucune autre tête de chaîne.
        let (_, later) = env.log.head().unwrap();
        assert_ne!(later, head);
        assert!(!verify(&later).status.success());
    }

    /// L'heure n'est plus traçable : la TSU refuse d'horodater, donc de
    /// sceller, et `/healthz` le dit au bout de trois passes.
    #[tokio::test]
    async fn an_untraceable_clock_seals_nothing_and_degrades_health() {
        let env = env("clock-down");
        env.sealer.once().await;
        assert_eq!(seals(&env.path).len(), 1);

        env.clock_down.store(true, Ordering::SeqCst);
        for _ in 0..MAX_FAILURES {
            assert!(!env.sealer.once().await.sealed);
        }
        assert_eq!(seals(&env.path).len(), 1);
        assert!(env
            .sealer
            .health()
            .report()
            .degraded
            .unwrap()
            .contains("scellement"));
    }
}
