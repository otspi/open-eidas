//! Scellement périodique du journal d'audit et copie hors site (constat J-1 de
//! l'audit du 2026-09-25 ; EN 319 401 `REQ-7.10-02`, `REQ-7.10-08`).
//!
//! Le chaînage SHA-256 d'`oe-audit` n'a pas de clé : qui peut écrire dans le
//! fichier peut le tronquer ou le réécrire en recalculant la chaîne. À chaque
//! intervalle (`OPENEIDAS_AUDIT_SEAL_INTERVAL`), cette tâche :
//!
//! 1. fait horodater la tête de chaîne par la TSU elle-même (`log.sealed`,
//!    avec le jeton RFC 3161) : toute réécriture antérieure devrait reforger un
//!    jeton signé par la clé du module cryptographique ;
//! 2. dépose une copie du journal entier, sceau compris, sur un stockage objet
//!    compatible S3 (`log.replicated`), si `OPENEIDAS_S3_ENDPOINT` est défini.
//!
//! La copie est périodique, pas faite à chaque jeton : le journal reçoit une
//! entrée par horodatage, et l'émission ne doit pas dépendre du stockage
//! distant. En contrepartie, un échec prolongé se voit : au-delà de
//! [`MAX_FAILURES`] passes en échec, `/healthz` se déclare dégradé. Un
//! scellement en échec est retenté après [`SEAL_RETRY`] au plus.
//!
//! Le contreseing par une TSA tierce (`log.cross_sealed`) n'est pas encore
//! branché : le sceau reste auto-référentiel tant qu'il ne l'est pas.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::Engine;
use der::Encode;
use oe_httpapi::{JournalHealth, JournalReport};
use oe_tsa_core::Authority;
use time::OffsetDateTime;

/// Nombre de passes consécutives en échec au-delà duquel `/healthz` signale le
/// journal comme dégradé.
pub const MAX_FAILURES: u32 = 3;

/// Délai avant de retenter un scellement qui vient d'échouer. Au démarrage
/// sous `enforce`, l'heure n'est pas encore traçable à la première passe :
/// sans cette reprise rapide, le journal resterait sans sceau pendant tout un
/// intervalle après chaque redémarrage.
pub const SEAL_RETRY: Duration = Duration::from_secs(60);

const SHA256_OID: &str = "2.16.840.1.101.3.4.2.1";

#[derive(Default)]
struct State {
    last_seal: Option<OffsetDateTime>,
    seal_failures: u32,
    last_copy: Option<OffsetDateTime>,
    copy_failures: u32,
}

/// L'état du scellement et de la copie, partagé avec `/healthz`.
pub struct Health {
    state: Mutex<State>,
    copy_configured: bool,
}

fn rfc3339(t: Option<OffsetDateTime>) -> Option<String> {
    t.and_then(|t| {
        t.format(&time::format_description::well_known::Rfc3339)
            .ok()
    })
}

impl JournalHealth for Health {
    fn report(&self) -> JournalReport {
        let state = self.state.lock().expect("verrou de l'état du journal");
        let mut reasons = Vec::new();
        if state.seal_failures >= MAX_FAILURES {
            reasons.push(format!(
                "scellement en échec depuis {} passes",
                state.seal_failures
            ));
        }
        if state.copy_failures >= MAX_FAILURES {
            reasons.push(format!(
                "copie hors site en échec depuis {} passes",
                state.copy_failures
            ));
        }
        JournalReport {
            degraded: (!reasons.is_empty()).then(|| reasons.join(" ; ")),
            detail: serde_json::json!({
                "degraded": !reasons.is_empty(),
                "last_seal": rfc3339(state.last_seal),
                "seal_failures": state.seal_failures,
                "offsite_copy": if self.copy_configured { "s3" } else { "non configurée" },
                "last_copy": rfc3339(state.last_copy),
                "copy_failures": state.copy_failures,
            }),
        }
    }
}

/// Ce qu'une passe a fait. `copied` vaut `None` sans stockage configuré.
#[derive(Debug, PartialEq, Eq)]
pub struct Outcome {
    pub sealed: bool,
    pub copied: Option<bool>,
}

pub struct Sealer {
    log: Arc<oe_audit::Log>,
    path: String,
    authority: Arc<Authority>,
    s3: Option<(oe_s3::Client, String)>,
    health: Arc<Health>,
}

impl Sealer {
    pub fn new(
        log: Arc<oe_audit::Log>,
        path: String,
        authority: Arc<Authority>,
        s3: Option<(oe_s3::Client, String)>,
    ) -> Sealer {
        let health = Arc::new(Health {
            state: Mutex::new(State::default()),
            copy_configured: s3.is_some(),
        });
        Sealer {
            log,
            path,
            authority,
            s3,
            health,
        }
    }

    pub fn health(&self) -> Arc<Health> {
        self.health.clone()
    }

    /// Fait horodater la tête de chaîne par la TSU et consigne le jeton. La
    /// tête scellée est celle d'avant l'horodatage : le jeton lui-même, puis
    /// le sceau, s'ajoutent derrière et seront couverts par le sceau suivant.
    fn seal(&self) -> Result<(), String> {
        let (seq, head) = self.log.head().map_err(|e| e.to_string())?;
        let digest = decode_head(&head)?;
        let request = oe_rfc3161_asn1::TimeStampReq {
            version: 1,
            message_imprint: oe_rfc3161_asn1::MessageImprint {
                hash_algorithm: spki::AlgorithmIdentifierOwned {
                    oid: der::asn1::ObjectIdentifier::new(SHA256_OID).map_err(|e| e.to_string())?,
                    parameters: None,
                },
                hashed_message: der::asn1::OctetString::new(digest).map_err(|e| e.to_string())?,
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
        let token = self
            .authority
            .timestamp(&request)
            .map_err(|e| e.to_string())?;

        let mut data = oe_audit::Data::new();
        data.insert("sealed_seq".into(), serde_json::json!(seq));
        data.insert("sealed_head".into(), serde_json::json!(head));
        data.insert(
            "token".into(),
            serde_json::json!(base64::engine::general_purpose::STANDARD.encode(token)),
        );
        self.log
            .append(oe_audit::EVENT_SEALED, Some(data))
            .map_err(|e| e.to_string())
    }

    /// Dépose le journal entier sur le stockage distant, puis le consigne.
    async fn copy(&self, client: &oe_s3::Client, key: &str) -> Result<(), String> {
        let bytes = std::fs::read(&self.path).map_err(|e| e.to_string())?;
        let size = bytes.len();
        client.put(key, bytes).await.map_err(|e| e.to_string())?;
        let mut data = oe_audit::Data::new();
        data.insert("key".into(), serde_json::json!(key));
        data.insert("bytes".into(), serde_json::json!(size));
        self.log
            .append(oe_audit::EVENT_REPLICATED, Some(data))
            .map_err(|e| e.to_string())
    }

    /// Une passe : sceller, puis copier. La copie est tentée même si le
    /// scellement a échoué — une copie sans sceau frais vaut mieux que pas de
    /// copie.
    pub async fn once(self: &Arc<Self>) -> Outcome {
        let this = self.clone();
        // L'horodatage est une signature HSM, bloquante.
        let sealed = match tokio::task::spawn_blocking(move || this.seal()).await {
            Ok(result) => result,
            Err(e) => Err(e.to_string()),
        };
        let now = OffsetDateTime::now_utc();
        if let Err(e) = &sealed {
            tracing::error!(erreur = %e, "journal d'audit : scellement en échec");
        }
        let copied = match &self.s3 {
            Some((client, key)) => {
                let result = self.copy(client, key).await;
                if let Err(e) = &result {
                    tracing::error!(erreur = %e, "journal d'audit : copie hors site en échec");
                }
                Some(result.is_ok())
            }
            None => None,
        };

        let mut state = self
            .health
            .state
            .lock()
            .expect("verrou de l'état du journal");
        if sealed.is_ok() {
            state.last_seal = Some(now);
            state.seal_failures = 0;
        } else {
            state.seal_failures = state.seal_failures.saturating_add(1);
        }
        match copied {
            Some(true) => {
                state.last_copy = Some(OffsetDateTime::now_utc());
                state.copy_failures = 0;
            }
            Some(false) => state.copy_failures = state.copy_failures.saturating_add(1),
            None => {}
        }
        Outcome {
            sealed: sealed.is_ok(),
            copied,
        }
    }

    /// Boucle de fond : une passe au démarrage, puis toutes les `every`.
    /// S'arrête à l'arrêt du service ; un échec n'interrompt pas la boucle.
    pub fn spawn_periodic(self: Arc<Self>, every: Duration) {
        tokio::spawn(async move {
            loop {
                let outcome = self.once().await;
                tokio::select! {
                    _ = tokio::time::sleep(next_delay(&outcome, every)) => {}
                    _ = tokio::signal::ctrl_c() => return,
                }
            }
        });
    }
}

/// Quand repasser : à l'intervalle prévu, ou plus tôt si le scellement a
/// échoué. Une copie en échec, elle, attend l'intervalle : la retenter sans
/// délai ajouterait un sceau et un jeton au journal à chaque essai.
fn next_delay(outcome: &Outcome, every: Duration) -> Duration {
    if outcome.sealed {
        every
    } else {
        every.min(SEAL_RETRY)
    }
}

/// La tête de chaîne est une empreinte SHA-256 en hexadécimal : c'est elle,
/// telle quelle, qui devient l'empreinte horodatée.
fn decode_head(head: &str) -> Result<Vec<u8>, String> {
    let invalid = || format!("tête de chaîne inattendue : {head:?}");
    if head.len() != 64 || !head.is_ascii() {
        return Err(invalid());
    }
    (0..32)
        .map(|i| u8::from_str_radix(&head[2 * i..2 * i + 2], 16).map_err(|_| invalid()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};

    use axum::extract::State as AxumState;
    use axum::http::StatusCode;
    use der::Decode;
    use oe_hsm::testing::SoftwareToken;

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
                clock: Arc::new(SwitchClock(clock_down)),
                recorder: None,
            })
            .unwrap(),
        )
    }

    /// Un stockage S3 minimal : garde le dernier corps reçu, ou refuse tout.
    #[derive(Clone, Default)]
    struct Bucket {
        stored: Arc<Mutex<Option<Vec<u8>>>>,
        down: Arc<AtomicBool>,
    }

    async fn put(AxumState(bucket): AxumState<Bucket>, body: axum::body::Bytes) -> StatusCode {
        if bucket.down.load(Ordering::SeqCst) {
            return StatusCode::SERVICE_UNAVAILABLE;
        }
        *bucket.stored.lock().unwrap() = Some(body.to_vec());
        StatusCode::OK
    }

    async fn s3(bucket: Bucket) -> (oe_s3::Client, String) {
        let app = axum::Router::new()
            .fallback(axum::routing::put(put))
            .with_state(bucket);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let client = oe_s3::Client::new(oe_s3::Options {
            endpoint,
            bucket: "journaux".into(),
            region: "us-east-1".into(),
            access_key: "test".into(),
            secret_key: "test".into(),
            timeout: Duration::from_secs(5),
        })
        .unwrap();
        (client, "tsa-server/audit.log".to_string())
    }

    struct Env {
        sealer: Arc<Sealer>,
        log: Arc<oe_audit::Log>,
        path: std::path::PathBuf,
        clock_down: Arc<AtomicBool>,
        _dir: Dir,
    }

    fn env(name: &str, s3: Option<(oe_s3::Client, String)>) -> Env {
        let dir = Dir::new(name);
        let path = dir.0.join("audit.log");
        let log = Arc::new(oe_audit::Log::open(&path).unwrap());
        log.append(oe_audit::EVENT_OPENED, None).unwrap();
        let clock_down = Arc::new(AtomicBool::new(false));
        let sealer = Arc::new(Sealer::new(
            log.clone(),
            path.to_string_lossy().into_owned(),
            authority(clock_down.clone()),
            s3,
        ));
        Env {
            sealer,
            log,
            path,
            clock_down,
            _dir: dir,
        }
    }

    fn events(path: &std::path::Path, event: &str) -> Vec<oe_audit::Record> {
        oe_audit::read(path)
            .unwrap()
            .into_iter()
            .filter(|r| r.event == event)
            .collect()
    }

    /// Le sceau porte un jeton RFC 3161 de la TSU dont l'empreinte est la tête
    /// de chaîne d'avant le scellement : openssl, tiers indépendant, le vérifie.
    #[tokio::test]
    async fn a_pass_seals_the_head_with_a_token_openssl_verifies() {
        let env = env("seal", None);
        let (seq, head) = env.log.head().unwrap();

        let outcome = env.sealer.once().await;
        assert_eq!(
            outcome,
            Outcome {
                sealed: true,
                copied: None
            }
        );

        let seals = events(&env.path, oe_audit::EVENT_SEALED);
        assert_eq!(seals.len(), 1);
        let data = seals[0].data.as_ref().unwrap();
        assert_eq!(data["sealed_seq"], seq);
        assert_eq!(data["sealed_head"], head.as_str());
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

    /// La copie hors site contient le journal jusqu'à son sceau compris, et
    /// elle est consignée ensuite.
    #[tokio::test]
    async fn the_offsite_copy_holds_the_journal_and_its_seal() {
        let bucket = Bucket::default();
        let env = env("copy", Some(s3(bucket.clone()).await));

        let outcome = env.sealer.once().await;
        assert_eq!(
            outcome,
            Outcome {
                sealed: true,
                copied: Some(true)
            }
        );

        let stored = bucket.stored.lock().unwrap().clone().expect("rien reçu");
        let local = std::fs::read(&env.path).unwrap();
        assert!(local.starts_with(&stored), "la copie n'est pas un préfixe");
        let copy = String::from_utf8(stored).unwrap();
        assert!(copy.contains(oe_audit::EVENT_SEALED), "copie sans sceau");
        // Ce qui s'ajoute après la copie : son propre enregistrement, seul.
        let tail = String::from_utf8(local[copy.len()..].to_vec()).unwrap();
        assert_eq!(tail.lines().count(), 1, "{tail}");
        let replicated = events(&env.path, oe_audit::EVENT_REPLICATED);
        assert_eq!(replicated.len(), 1);
        let data = replicated[0].data.as_ref().unwrap();
        assert_eq!(data["key"], "tsa-server/audit.log");
        assert_eq!(data["bytes"], copy.len());
        assert_eq!(oe_audit::verify(&env.path).unwrap().seals, 1);
    }

    /// Un échec ne bloque rien, mais il se compte : au-delà de trois passes,
    /// `/healthz` le dit ; une passe réussie remet le compteur à zéro.
    #[tokio::test]
    async fn prolonged_failures_degrade_health_until_a_pass_succeeds() {
        let bucket = Bucket::default();
        let env = env("health", Some(s3(bucket.clone()).await));
        let health = env.sealer.health();

        env.sealer.once().await;
        let report = health.report();
        assert!(report.degraded.is_none(), "{:?}", report.degraded);
        assert_eq!(report.detail["offsite_copy"], "s3");
        assert!(report.detail["last_seal"].is_string());
        assert!(report.detail["last_copy"].is_string());

        // Le stockage tombe : la TSU scelle toujours.
        bucket.down.store(true, Ordering::SeqCst);
        for pass in 1..=MAX_FAILURES {
            let outcome = env.sealer.once().await;
            assert_eq!(
                outcome,
                Outcome {
                    sealed: true,
                    copied: Some(false)
                }
            );
            let report = health.report();
            assert_eq!(report.detail["copy_failures"], pass);
            assert_eq!(
                report.degraded.is_some(),
                pass >= MAX_FAILURES,
                "passe {pass}"
            );
        }
        assert!(health
            .report()
            .degraded
            .unwrap()
            .contains("copie hors site"));
        assert_eq!(health.report().detail["degraded"], true);
        // Aucune copie n'a été consignée pendant la panne.
        assert_eq!(events(&env.path, oe_audit::EVENT_REPLICATED).len(), 1);

        bucket.down.store(false, Ordering::SeqCst);
        env.sealer.once().await;
        assert!(health.report().degraded.is_none());
        assert_eq!(health.report().detail["copy_failures"], 0);

        // L'heure n'est plus traçable : la TSU refuse d'horodater, donc de
        // sceller ; la copie, elle, continue.
        env.clock_down.store(true, Ordering::SeqCst);
        let seals = events(&env.path, oe_audit::EVENT_SEALED).len();
        for _ in 0..MAX_FAILURES {
            let outcome = env.sealer.once().await;
            assert_eq!(
                outcome,
                Outcome {
                    sealed: false,
                    copied: Some(true)
                }
            );
        }
        assert_eq!(events(&env.path, oe_audit::EVENT_SEALED).len(), seals);
        assert!(health.report().degraded.unwrap().contains("scellement"));
    }

    /// Sans stockage configuré, la copie n'est ni tentée ni comptée en échec.
    #[tokio::test]
    async fn without_storage_no_copy_is_attempted_or_reported_failing() {
        let env = env("local", None);
        for _ in 0..=MAX_FAILURES {
            assert_eq!(env.sealer.once().await.copied, None);
        }
        let report = env.sealer.health().report();
        assert!(report.degraded.is_none());
        assert_eq!(report.detail["offsite_copy"], "non configurée");
        assert!(report.detail["last_copy"].is_null());
        assert!(events(&env.path, oe_audit::EVENT_REPLICATED).is_empty());
    }

    #[test]
    fn a_failed_seal_is_retried_sooner_a_failed_copy_is_not() {
        let hour = Duration::from_secs(3600);
        let outcome = |sealed, copied| Outcome { sealed, copied };
        assert_eq!(next_delay(&outcome(true, Some(true)), hour), hour);
        assert_eq!(next_delay(&outcome(true, Some(false)), hour), hour);
        assert_eq!(next_delay(&outcome(true, None), hour), hour);
        assert_eq!(next_delay(&outcome(false, Some(true)), hour), SEAL_RETRY);
        // Jamais plus tard que l'intervalle configuré.
        let short = Duration::from_secs(5);
        assert_eq!(next_delay(&outcome(false, None), short), short);
    }

    #[test]
    fn only_a_sha256_head_is_sealed() {
        assert_eq!(decode_head(&"ab".repeat(32)).unwrap(), vec![0xab; 32]);
        for bad in ["", "abcd", &"zz".repeat(32), &"é".repeat(32)] {
            assert!(decode_head(bad).is_err(), "{bad:?}");
        }
    }
}
