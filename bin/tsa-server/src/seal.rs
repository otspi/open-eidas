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
//! 2. fait horodater la même tête par les TSA tierces de
//!    `OPENEIDAS_CROSS_TSA_URLS` (`log.cross_sealed`, un enregistrement par
//!    autorité qui a répondu) : le sceau de la TSU est auto-référentiel, il ne
//!    prouve rien à qui ne lui fait pas déjà confiance ; un jeton d'une
//!    autorité indépendante, vérifiable avec des outils standards, si ;
//! 3. dépose une copie du journal entier, sceaux compris, sur un stockage
//!    objet compatible S3 (`log.replicated`), si `OPENEIDAS_S3_ENDPOINT` est
//!    défini.
//!
//! La copie est périodique, pas faite à chaque jeton : le journal reçoit une
//! entrée par horodatage, et l'émission ne doit pas dépendre du stockage
//! distant. En contrepartie, un échec prolongé se voit : au-delà de
//! [`MAX_FAILURES`] passes en échec, `/healthz` se déclare dégradé. Un
//! scellement en échec est retenté après [`SEAL_RETRY`] au plus.
//!
//! Le jeton d'une TSA tierce est conservé tel quel, après contrôle qu'il
//! porte bien l'empreinte soumise. Sa signature n'est pas vérifiée ici, faute
//! d'ancres de confiance pour ces autorités : elle se vérifie après coup, par
//! `openssl ts -verify` et leur certificat.

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
    last_cross_seal: Option<OffsetDateTime>,
    /// Combien d'autorités tierces ont contresigné à la dernière passe.
    last_cross_seal_count: usize,
    cross_seal_failures: u32,
}

/// L'état du scellement, du contreseing et de la copie, partagé avec
/// `/healthz`.
pub struct Health {
    state: Mutex<State>,
    copy_configured: bool,
    /// Nombre de TSA tierces configurées ; zéro = contreseing désactivé.
    cross_tsas: usize,
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
        if state.cross_seal_failures >= MAX_FAILURES {
            reasons.push(format!(
                "aucun contreseing tiers depuis {} passes",
                state.cross_seal_failures
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
                "cross_tsas": self.cross_tsas,
                "last_cross_seal": rfc3339(state.last_cross_seal),
                "last_cross_seal_count": state.last_cross_seal_count,
                "cross_seal_failures": state.cross_seal_failures,
            }),
        }
    }
}

/// Ce qu'une passe a fait. `cross_sealed` (le nombre d'autorités tierces qui
/// ont contresigné) vaut `None` sans TSA tierce configurée ; `copied`, sans
/// stockage configuré.
#[derive(Debug, PartialEq, Eq)]
pub struct Outcome {
    pub sealed: bool,
    pub cross_sealed: Option<usize>,
    pub copied: Option<bool>,
}

pub struct Sealer {
    log: Arc<oe_audit::Log>,
    path: String,
    authority: Arc<Authority>,
    cross: Option<oe_crosstsa::Client>,
    s3: Option<(oe_s3::Client, String)>,
    health: Arc<Health>,
}

/// La tête de chaîne qu'une passe scelle : la même pour la TSU et pour les
/// autorités tierces.
#[derive(Clone)]
struct Head {
    seq: u64,
    hash: String,
    digest: Vec<u8>,
}

fn sha256() -> Result<spki::AlgorithmIdentifierOwned, String> {
    Ok(spki::AlgorithmIdentifierOwned {
        oid: der::asn1::ObjectIdentifier::new(SHA256_OID).map_err(|e| e.to_string())?,
        parameters: None,
    })
}

impl Sealer {
    pub fn new(
        log: Arc<oe_audit::Log>,
        path: String,
        authority: Arc<Authority>,
        cross_tsas: Vec<String>,
        cross_timeout: Duration,
        s3: Option<(oe_s3::Client, String)>,
    ) -> Sealer {
        let health = Arc::new(Health {
            state: Mutex::new(State::default()),
            copy_configured: s3.is_some(),
            cross_tsas: cross_tsas.len(),
        });
        let cross = (!cross_tsas.is_empty()).then(|| {
            oe_crosstsa::Client::new(oe_crosstsa::Options {
                urls: cross_tsas,
                timeout: cross_timeout,
            })
        });
        Sealer {
            log,
            path,
            authority,
            cross,
            s3,
            health,
        }
    }

    fn head(&self) -> Result<Head, String> {
        let (seq, hash) = self.log.head().map_err(|e| e.to_string())?;
        let digest = decode_head(&hash)?;
        Ok(Head { seq, hash, digest })
    }

    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        self.health
            .state
            .lock()
            .expect("verrou de l'état du journal")
    }

    pub fn health(&self) -> Arc<Health> {
        self.health.clone()
    }

    /// Fait horodater la tête de chaîne par la TSU et consigne le jeton. La
    /// tête scellée est celle d'avant l'horodatage : le jeton lui-même, puis
    /// le sceau, s'ajoutent derrière et seront couverts par le sceau suivant.
    fn seal(&self, head: &Head) -> Result<(), String> {
        let request = oe_rfc3161_asn1::TimeStampReq {
            version: 1,
            message_imprint: oe_rfc3161_asn1::MessageImprint {
                hash_algorithm: sha256()?,
                hashed_message: der::asn1::OctetString::new(head.digest.clone())
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
        let token = self
            .authority
            .timestamp(&request)
            .map_err(|e| e.to_string())?;

        let mut data = oe_audit::Data::new();
        data.insert("sealed_seq".into(), serde_json::json!(head.seq));
        data.insert("sealed_head".into(), serde_json::json!(head.hash));
        data.insert(
            "token".into(),
            serde_json::json!(base64::engine::general_purpose::STANDARD.encode(token)),
        );
        self.log
            .append(oe_audit::EVENT_SEALED, Some(data))
            .map_err(|e| e.to_string())
    }

    /// Fait horodater la même tête par chaque TSA tierce et consigne un
    /// enregistrement par autorité qui a répondu. Rend leur nombre : une
    /// autorité injoignable n'empêche pas les autres de compter.
    async fn cross_seal(&self, client: &oe_crosstsa::Client, head: &Head) -> Result<usize, String> {
        let attestations = client.seal(&head.digest, sha256()?).await;
        let mut recorded = 0;
        for a in attestations {
            let mut data = oe_audit::Data::new();
            data.insert("sealed_seq".into(), serde_json::json!(head.seq));
            data.insert("sealed_head".into(), serde_json::json!(head.hash));
            data.insert("tsa".into(), serde_json::json!(a.tsa));
            data.insert("gen_time".into(), serde_json::json!(a.gen_time));
            data.insert("serial".into(), serde_json::json!(a.serial));
            data.insert("token".into(), serde_json::json!(a.token));
            self.log
                .append(oe_audit::EVENT_CROSS_SEALED, Some(data))
                .map_err(|e| e.to_string())?;
            recorded += 1;
        }
        Ok(recorded)
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

    /// Une passe : sceller, faire contresigner, puis copier. Chaque étape est
    /// tentée quoi qu'il soit arrivé aux précédentes — un contreseing ou une
    /// copie sans sceau frais valent mieux que rien — et l'état rendu par
    /// `/healthz` est mis à jour au fil de l'eau, sans attendre les tiers.
    pub async fn once(self: &Arc<Self>) -> Outcome {
        let head = self.head();
        if let Err(e) = &head {
            tracing::error!(erreur = %e, "journal d'audit : tête de chaîne illisible");
        }

        // L'horodatage est une signature HSM, bloquante.
        let sealed = match head.clone() {
            Ok(head) => {
                let this = self.clone();
                match tokio::task::spawn_blocking(move || this.seal(&head)).await {
                    Ok(result) => result,
                    Err(e) => Err(e.to_string()),
                }
            }
            Err(e) => Err(e),
        };
        match &sealed {
            Ok(()) => {
                let mut state = self.state();
                state.last_seal = Some(OffsetDateTime::now_utc());
                state.seal_failures = 0;
            }
            Err(e) => {
                tracing::error!(erreur = %e, "journal d'audit : scellement en échec");
                let mut state = self.state();
                state.seal_failures = state.seal_failures.saturating_add(1);
            }
        }

        let cross_sealed = match (&self.cross, &head) {
            (Some(client), Ok(head)) => {
                let count = match self.cross_seal(client, head).await {
                    Ok(count) => count,
                    Err(e) => {
                        tracing::error!(erreur = %e, "journal d'audit : contreseing non consigné");
                        0
                    }
                };
                Some(count)
            }
            (Some(_), Err(_)) => Some(0),
            (None, _) => None,
        };
        if let Some(count) = cross_sealed {
            let mut state = self.state();
            state.last_cross_seal_count = count;
            if count > 0 {
                state.last_cross_seal = Some(OffsetDateTime::now_utc());
                state.cross_seal_failures = 0;
            } else {
                tracing::error!("journal d'audit : aucune TSA tierce n'a contresigné");
                state.cross_seal_failures = state.cross_seal_failures.saturating_add(1);
            }
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
        match copied {
            Some(true) => {
                let mut state = self.state();
                state.last_copy = Some(OffsetDateTime::now_utc());
                state.copy_failures = 0;
            }
            Some(false) => {
                let mut state = self.state();
                state.copy_failures = state.copy_failures.saturating_add(1);
            }
            None => {}
        }
        Outcome {
            sealed: sealed.is_ok(),
            cross_sealed,
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
/// échoué. Une copie ou un contreseing en échec, eux, attendent l'intervalle :
/// les retenter sans délai ajouterait un sceau et un jeton au journal à chaque
/// essai, et solliciterait des autorités tierces plus que de raison.
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
        env_with(name, Vec::new(), s3)
    }

    /// Une TSA tierce réelle (RFC 3161 sur HTTP), indépendante du service
    /// sous test : rend son URL.
    async fn third_party_tsa() -> String {
        let app = oe_httpapi::router(oe_httpapi::Options {
            authority: authority(Arc::new(AtomicBool::new(false))),
            time_source: oe_timesource::Monitor::new(oe_timesource::Options {
                policy: oe_timesource::Policy::Disabled,
                ..Default::default()
            })
            .unwrap(),
            max_request_bytes: 64 * 1024,
            version: "tierce".to_string(),
            cors_allowed_origin: None,
            journal: None,
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/tsa", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        url
    }

    /// Une adresse où rien n'écoute.
    const UNREACHABLE: &str = "http://127.0.0.1:9/tsa";

    fn env_with(name: &str, cross: Vec<String>, s3: Option<(oe_s3::Client, String)>) -> Env {
        let dir = Dir::new(name);
        let path = dir.0.join("audit.log");
        let log = Arc::new(oe_audit::Log::open(&path).unwrap());
        log.append(oe_audit::EVENT_OPENED, None).unwrap();
        let clock_down = Arc::new(AtomicBool::new(false));
        let sealer = Arc::new(Sealer::new(
            log.clone(),
            path.to_string_lossy().into_owned(),
            authority(clock_down.clone()),
            cross,
            Duration::from_secs(2),
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
                cross_sealed: None,
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
                cross_sealed: None,
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

    /// La tête que la TSU scelle est aussi horodatée par chaque autorité
    /// tierce joignable ; son jeton, conservé, se vérifie avec openssl. Une
    /// autorité injoignable n'empêche pas l'autre de compter.
    #[tokio::test]
    async fn the_sealed_head_is_countersigned_by_each_reachable_third_party() {
        let tsa = third_party_tsa().await;
        let env = env_with("cross", vec![UNREACHABLE.to_string(), tsa], None);
        let (seq, head) = env.log.head().unwrap();

        let outcome = env.sealer.once().await;
        assert_eq!(
            outcome,
            Outcome {
                sealed: true,
                cross_sealed: Some(1),
                copied: None
            }
        );

        let seal = &events(&env.path, oe_audit::EVENT_SEALED)[0];
        let cross = events(&env.path, oe_audit::EVENT_CROSS_SEALED);
        assert_eq!(cross.len(), 1, "{cross:?}");
        let data = cross[0].data.as_ref().unwrap();
        // La même tête que celle du sceau de la TSU.
        assert_eq!(data["sealed_seq"], seq);
        assert_eq!(data["sealed_head"], head.as_str());
        assert_eq!(
            data["sealed_head"],
            seal.data.as_ref().unwrap()["sealed_head"]
        );
        assert!(
            data["tsa"].as_str().is_some_and(|t| !t.is_empty()),
            "{data:?}"
        );
        assert!(
            data["serial"].as_str().is_some_and(|t| !t.is_empty()),
            "{data:?}"
        );

        let token_path = env.path.with_file_name("cross.tsr");
        std::fs::write(
            &token_path,
            base64::engine::general_purpose::STANDARD
                .decode(data["token"].as_str().unwrap())
                .unwrap(),
        )
        .unwrap();
        let verify = |digest: &str| {
            std::process::Command::new("openssl")
                .args(["ts", "-verify", "-digest", digest, "-in"])
                .arg(&token_path)
                .arg("-CAfile")
                .arg(fixtures().join("tsu-cert.pem"))
                .output()
                .unwrap()
        };
        let ok = verify(&head);
        assert!(
            ok.status.success(),
            "{}",
            String::from_utf8_lossy(&ok.stderr)
        );
        let (_, later) = env.log.head().unwrap();
        assert!(!verify(&later).status.success());

        let report = env.sealer.health().report();
        assert!(report.degraded.is_none(), "{:?}", report.degraded);
        assert_eq!(report.detail["cross_tsas"], 2);
        assert_eq!(report.detail["last_cross_seal_count"], 1);
        assert!(report.detail["last_cross_seal"].is_string());
        assert_eq!(oe_audit::verify(&env.path).unwrap().seals, 1);
    }

    /// Sans aucun contreseing pendant trois passes, le sceau n'est plus
    /// qu'auto-référentiel : `/healthz` le dit. La TSU, elle, scelle toujours.
    #[tokio::test]
    async fn three_passes_without_any_countersignature_degrade_health() {
        let env = env_with("cross-down", vec![UNREACHABLE.to_string()], None);
        let health = env.sealer.health();
        for pass in 1..=MAX_FAILURES {
            let outcome = env.sealer.once().await;
            assert_eq!(
                outcome,
                Outcome {
                    sealed: true,
                    cross_sealed: Some(0),
                    copied: None
                }
            );
            let report = health.report();
            assert_eq!(report.detail["cross_seal_failures"], pass);
            assert_eq!(
                report.degraded.is_some(),
                pass >= MAX_FAILURES,
                "passe {pass}"
            );
        }
        assert!(health.report().degraded.unwrap().contains("contreseing"));
        assert!(events(&env.path, oe_audit::EVENT_CROSS_SEALED).is_empty());
        assert_eq!(
            events(&env.path, oe_audit::EVENT_SEALED).len() as u32,
            MAX_FAILURES
        );
    }

    /// Sans TSA tierce configurée, le contreseing n'est ni tenté ni compté.
    #[tokio::test]
    async fn without_third_parties_no_countersignature_is_attempted() {
        let env = env("cross-off", None);
        for _ in 0..=MAX_FAILURES {
            assert_eq!(env.sealer.once().await.cross_sealed, None);
        }
        let report = env.sealer.health().report();
        assert!(report.degraded.is_none());
        assert_eq!(report.detail["cross_tsas"], 0);
        assert!(report.detail["last_cross_seal"].is_null());
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
                    cross_sealed: None,
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
                    cross_sealed: None,
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
        let outcome = |sealed, copied| Outcome {
            sealed,
            cross_sealed: None,
            copied,
        };
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
