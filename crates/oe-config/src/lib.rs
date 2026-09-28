//! Portage de `internal/config` : chargement 12-factor de la configuration du
//! service via des variables d'environnement `OPENEIDAS_*`, sans fichier de
//! config. Voir `internal/config/config.go` pour la version Go de référence —
//! chaque valeur par défaut et chaque contrainte de validation ci-dessous doit
//! rester alignée avec ce fichier.

use std::env;
use std::time::Duration;

use oe_timesource::Policy;

/// Identifiant d'objet ASN.1 (équivalent de `asn1.ObjectIdentifier` en Go).
pub type ObjectIdentifier = Vec<u64>;

/// Algorithme de hachage utilisé pour la signature (équivalent de `crypto.Hash`
/// restreint aux valeurs acceptées par le service).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigningDigest {
    Sha256,
    Sha384,
    Sha512,
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("{key}: entier attendu, reçu {value:?}")]
    InvalidInt { key: &'static str, value: String },
    #[error("{key}: durée attendue (ex. 1s, 500ms), reçu {value:?}")]
    InvalidDuration { key: &'static str, value: String },
    #[error("{key}: booléen attendu, reçu {value:?}")]
    InvalidBool { key: &'static str, value: String },
    #[error("OPENEIDAS_KEY_BITS={0}: ETSI TS 119 312 impose au moins 3072 bits pour RSA")]
    KeyBitsTooSmall(i64),
    #[error("OID invalide: {0:?}")]
    InvalidOid(String),
    #[error("OPENEIDAS_POLICY_OID={0:?} appartient à l'arc de test : refusé quand OPENEIDAS_PRODUCTION est activé")]
    TestPolicyOidInProduction(String),
    #[error("algorithme de signature non supporté: {0:?} (sha256, sha384 ou sha512)")]
    UnsupportedDigest(String),
    #[error("OPENEIDAS_PIN est obligatoire (code PIN du token PKCS#11)")]
    MissingPin,
    #[error(transparent)]
    InvalidTimePolicy(#[from] oe_timesource::ParsePolicyError),
}

/// Configuration complète du service, entièrement pilotée par l'environnement.
#[derive(Debug, Clone)]
pub struct Config {
    pub listen: String,
    pub shutdown_timeout: Duration,
    pub max_request_bytes: i64,

    pub pkcs11_module: String,
    pub token_label: String,
    pub key_label: String,
    pub key_bits: i64,
    pub pin: String,

    pub cert_file: String,
    pub chain_file: String,

    pub audit_file: String,
    pub audit_seal_interval: Duration,

    pub cross_tsa_urls: Vec<String>,
    pub cross_tsa_timeout: Duration,

    pub audit_replica_url: String,
    pub audit_replica_user: String,
    pub audit_replica_password: String,
    pub audit_replica_timeout: Duration,

    pub policy_oid: ObjectIdentifier,
    /// Mode production : refuse de démarrer avec un OID de politique de test.
    pub production: bool,
    pub accuracy: Duration,
    pub signing_digest: SigningDigest,

    pub time_policy: Policy,
    pub time_sources: Vec<String>,
    pub time_min_sources: i64,
    pub time_max_offset: Duration,
    pub time_max_age: Duration,
    pub time_poll: Duration,
    pub time_timeout: Duration,

    pub enroll_endpoint: String,
    pub enroll_ca_file: String,
    pub enroll_insecure: bool,
    pub enroll_timeout: Duration,
    pub enroll_hmac_key: String,
    /// Profil de certificat demandé à la CA (voir `internal/ca`).
    pub enroll_profile: String,
    /// Seule partie du sujet que le demandeur choisit : unité, organisation et
    /// pays sont imposés par le profil côté autorité.
    pub subject_cn: String,
    pub renew_before: Duration,
    /// Origine autorisée à appeler l'API HTTP depuis un navigateur
    /// (Access-Control-Allow-Origin). Vide/absent = pas de CORS, aucune
    /// requête cross-origin n'est autorisée — comportement par défaut,
    /// préservé pour tout déploiement qui n'a pas de démo web tierce.
    pub cors_allowed_origin: Option<String>,
}

impl Config {
    pub fn load() -> Result<Config, ConfigError> {
        let pin = env::var("OPENEIDAS_PIN").unwrap_or_default();
        if pin.is_empty() {
            return Err(ConfigError::MissingPin);
        }

        let key_bits = env_int("OPENEIDAS_KEY_BITS", 3072)?;
        if key_bits < 3072 {
            return Err(ConfigError::KeyBitsTooSmall(key_bits));
        }

        let policy_oid = parse_oid(&env_str("OPENEIDAS_POLICY_OID", "1.3.6.1.4.1.99999.1.1.1"))?;
        let production = env_bool("OPENEIDAS_PRODUCTION", false)?;
        if production && is_test_oid(&policy_oid) {
            return Err(ConfigError::TestPolicyOidInProduction(oid_to_string(
                &policy_oid,
            )));
        }

        Ok(Config {
            listen: env_str("OPENEIDAS_LISTEN", ":8318"),
            shutdown_timeout: Duration::from_secs(15),
            max_request_bytes: env_int("OPENEIDAS_MAX_REQUEST_BYTES", 64 * 1024)?,

            pkcs11_module: env_str("OPENEIDAS_PKCS11_MODULE", "/usr/lib/softhsm/libsofthsm2.so"),
            token_label: env_str("OPENEIDAS_TOKEN_LABEL", "open-eidas-tsa"),
            key_label: env_str("OPENEIDAS_KEY_LABEL", "tsu-signing-key"),
            key_bits,
            pin,

            cert_file: env_str("OPENEIDAS_CERT_FILE", "/var/lib/open-eidas/tsu.pem"),
            chain_file: env_str("OPENEIDAS_CHAIN_FILE", "/var/lib/open-eidas/chain.pem"),

            audit_file: env_str("OPENEIDAS_AUDIT_FILE", "/var/lib/open-eidas/audit.log"),
            audit_seal_interval: env_duration(
                "OPENEIDAS_AUDIT_SEAL_INTERVAL",
                Duration::from_secs(3600),
            )?,

            cross_tsa_urls: split_list(&env_str(
                "OPENEIDAS_CROSS_TSA_URLS",
                "https://freetsa.org/tsr,http://timestamp.digicert.com",
            )),
            cross_tsa_timeout: env_duration(
                "OPENEIDAS_CROSS_TSA_TIMEOUT",
                Duration::from_secs(15),
            )?,

            audit_replica_url: env_str("OPENEIDAS_AUDIT_REPLICA_URL", ""),
            audit_replica_user: env_str("OPENEIDAS_AUDIT_REPLICA_USER", ""),
            audit_replica_password: env::var("OPENEIDAS_AUDIT_REPLICA_PASSWORD")
                .unwrap_or_default(),
            audit_replica_timeout: env_duration(
                "OPENEIDAS_AUDIT_REPLICA_TIMEOUT",
                Duration::from_secs(30),
            )?,

            policy_oid,
            production,
            accuracy: env_duration("OPENEIDAS_ACCURACY", Duration::from_secs(1))?,
            signing_digest: parse_digest(&env_str("OPENEIDAS_SIGNING_DIGEST", "sha256"))?,

            time_policy: env_str("OPENEIDAS_TIME_POLICY", "enforce").parse()?,
            time_sources: split_list(&env_str(
                "OPENEIDAS_TIME_SOURCES",
                "ntp.obspm.fr,ptbtime1.ptb.de",
            )),
            time_min_sources: env_int("OPENEIDAS_TIME_MIN_SOURCES", 2)?,
            time_max_offset: env_duration("OPENEIDAS_TIME_MAX_OFFSET", Duration::from_millis(500))?,
            time_max_age: env_duration("OPENEIDAS_TIME_MAX_AGE", Duration::from_secs(3600))?,
            time_poll: env_duration("OPENEIDAS_TIME_POLL", Duration::from_secs(300))?,
            time_timeout: env_duration("OPENEIDAS_TIME_TIMEOUT", Duration::from_secs(5))?,

            enroll_endpoint: env_str("OPENEIDAS_ENROLL_ENDPOINT", ""),
            enroll_ca_file: env_str("OPENEIDAS_ENROLL_CA_FILE", ""),
            enroll_insecure: env_bool("OPENEIDAS_ENROLL_INSECURE", false)?,
            enroll_timeout: env_duration("OPENEIDAS_ENROLL_TIMEOUT", Duration::from_secs(300))?,
            enroll_hmac_key: env::var("OPENEIDAS_ENROLL_HMAC_KEY").unwrap_or_default(),
            enroll_profile: env_str("OPENEIDAS_ENROLL_PROFILE", "tsa_signer"),
            subject_cn: env_str("OPENEIDAS_SUBJECT_CN", "Open eIDAS Time-Stamping Unit 1"),
            renew_before: env_duration(
                "OPENEIDAS_RENEW_BEFORE",
                Duration::from_secs(30 * 24 * 3600),
            )?,
            cors_allowed_origin: env::var("OPENEIDAS_CORS_ALLOWED_ORIGIN")
                .ok()
                .filter(|s| !s.is_empty()),
        })
    }
}

fn split_list(s: &str) -> Vec<String> {
    s.split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(str::to_string)
        .collect()
}

/// Préfixe des numéros d'entreprise privés : `1.3.6.1.4.1.<PEN>`.
const PEN_PREFIX: [u64; 6] = [1, 3, 6, 1, 4, 1];
/// Numéro d'entreprise historiquement utilisé pour le banc d'essai, non attribué à OTSPI.
const LEGACY_TEST_PEN: u64 = 99999;
/// Sous-arc réservé au test et au staging sous le numéro d'entreprise d'OTSPI
/// (`<PEN>.9`, voir docs/cadrage/oid-arc.md du dépôt de gouvernance).
const TEST_SUB_ARC: u64 = 9;

/// Indique si l'OID appartient à un arc de test : l'ancien numéro d'essai `99999`, ou le
/// sous-arc `9` de tout numéro d'entreprise.
pub fn is_test_oid(oid: &[u64]) -> bool {
    if oid.len() < 8 || oid[..6] != PEN_PREFIX {
        return false;
    }
    oid[6] == LEGACY_TEST_PEN || oid[7] == TEST_SUB_ARC
}

fn oid_to_string(oid: &[u64]) -> String {
    oid.iter().map(u64::to_string).collect::<Vec<_>>().join(".")
}

fn parse_oid(s: &str) -> Result<ObjectIdentifier, ConfigError> {
    let parts: Vec<&str> = s.trim().split('.').collect();
    if parts.len() < 2 {
        return Err(ConfigError::InvalidOid(s.to_string()));
    }
    parts
        .into_iter()
        .map(|p| {
            p.parse::<u64>()
                .map_err(|_| ConfigError::InvalidOid(s.to_string()))
        })
        .collect()
}

fn parse_digest(s: &str) -> Result<SigningDigest, ConfigError> {
    match s.trim().to_lowercase().as_str() {
        "sha256" => Ok(SigningDigest::Sha256),
        "sha384" => Ok(SigningDigest::Sha384),
        "sha512" => Ok(SigningDigest::Sha512),
        other => Err(ConfigError::UnsupportedDigest(other.to_string())),
    }
}

fn env_str(key: &str, fallback: &str) -> String {
    match env::var(key) {
        Ok(v) if !v.is_empty() => v,
        _ => fallback.to_string(),
    }
}

fn env_int(key: &'static str, fallback: i64) -> Result<i64, ConfigError> {
    match env::var(key) {
        Ok(v) if !v.is_empty() => v
            .parse()
            .map_err(|_| ConfigError::InvalidInt { key, value: v }),
        _ => Ok(fallback),
    }
}

fn env_duration(key: &'static str, fallback: Duration) -> Result<Duration, ConfigError> {
    match env::var(key) {
        Ok(v) if !v.is_empty() => {
            let dur = parse_go_duration(&v);
            dur.ok_or(ConfigError::InvalidDuration { key, value: v })
        }
        _ => Ok(fallback),
    }
}

fn env_bool(key: &'static str, fallback: bool) -> Result<bool, ConfigError> {
    match env::var(key) {
        Ok(v) if !v.is_empty() => v
            .parse()
            .map_err(|_| ConfigError::InvalidBool { key, value: v }),
        _ => Ok(fallback),
    }
}

/// Parse un sous-ensemble du format `time.ParseDuration` de Go (ex. "1s",
/// "500ms", "1h30m") suffisant pour les valeurs acceptées par ce service.
fn parse_go_duration(s: &str) -> Option<Duration> {
    let mut total = Duration::ZERO;
    let mut num = String::new();
    let mut chars = s.chars().peekable();
    let mut matched_any = false;
    while let Some(&c) = chars.peek() {
        if c.is_ascii_digit() || c == '.' {
            num.push(c);
            chars.next();
            continue;
        }
        // unité : ns, us, µs, ms, s, m, h
        let unit: String = if c == 'n' || c == 'u' || c == 'm' {
            let mut u = String::new();
            u.push(c);
            chars.next();
            if let Some(&c2) = chars.peek() {
                if c2 == 's' {
                    u.push(c2);
                    chars.next();
                }
            }
            u
        } else {
            let u = c.to_string();
            chars.next();
            u
        };
        if num.is_empty() {
            return None;
        }
        let value: f64 = num.parse().ok()?;
        num.clear();
        let unit_dur = match unit.as_str() {
            "ns" => Duration::from_nanos(1),
            "us" | "µs" => Duration::from_micros(1),
            "ms" => Duration::from_millis(1),
            "s" => Duration::from_secs(1),
            "m" => Duration::from_secs(60),
            "h" => Duration::from_secs(3600),
            _ => return None,
        };
        total += unit_dur.mul_f64(value);
        matched_any = true;
    }
    if !matched_any || !num.is_empty() {
        return None;
    }
    Some(total)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    fn clear_env() {
        for (key, _) in env::vars() {
            if key.starts_with("OPENEIDAS_") {
                env::remove_var(key);
            }
        }
    }

    #[test]
    #[serial]
    fn load_fails_without_pin() {
        clear_env();
        let err = Config::load().unwrap_err();
        assert!(matches!(err, ConfigError::MissingPin));
    }

    #[test]
    #[serial]
    fn load_fails_on_undersized_key_bits() {
        clear_env();
        env::set_var("OPENEIDAS_PIN", "1234");
        env::set_var("OPENEIDAS_KEY_BITS", "2048");
        let err = Config::load().unwrap_err();
        assert!(matches!(err, ConfigError::KeyBitsTooSmall(2048)));
        clear_env();
    }

    #[test]
    #[serial]
    fn load_applies_defaults() {
        clear_env();
        env::set_var("OPENEIDAS_PIN", "1234");
        let cfg = Config::load().unwrap();
        assert_eq!(cfg.listen, ":8318");
        assert_eq!(cfg.key_bits, 3072);
        assert_eq!(cfg.policy_oid, vec![1, 3, 6, 1, 4, 1, 99999, 1, 1, 1]);
        assert_eq!(cfg.signing_digest, SigningDigest::Sha256);
        assert_eq!(cfg.time_policy, Policy::Enforce);
        assert_eq!(cfg.accuracy, Duration::from_secs(1));
        assert_eq!(cfg.time_max_offset, Duration::from_millis(500));
        assert_eq!(cfg.cors_allowed_origin, None);
        clear_env();
    }

    #[test]
    fn test_oid_detection() {
        assert!(is_test_oid(&[1, 3, 6, 1, 4, 1, 99999, 1, 1, 1]));
        assert!(is_test_oid(&[1, 3, 6, 1, 4, 1, 12345, 9, 1, 1, 1]));
        assert!(!is_test_oid(&[1, 3, 6, 1, 4, 1, 12345, 1, 1, 1]));
        assert!(!is_test_oid(&[0, 4, 0, 2023, 1, 1]));
        assert!(!is_test_oid(&[1, 3, 6, 1, 4, 1]));
    }

    #[test]
    #[serial]
    fn load_refuses_test_oid_in_production() {
        clear_env();
        env::set_var("OPENEIDAS_PIN", "1234");
        env::set_var("OPENEIDAS_PRODUCTION", "true");
        let err = Config::load().unwrap_err();
        assert!(matches!(err, ConfigError::TestPolicyOidInProduction(_)));
        clear_env();
    }

    #[test]
    #[serial]
    fn load_accepts_production_oid_in_production() {
        clear_env();
        env::set_var("OPENEIDAS_PIN", "1234");
        env::set_var("OPENEIDAS_PRODUCTION", "true");
        env::set_var("OPENEIDAS_POLICY_OID", "1.3.6.1.4.1.12345.1.1.1");
        let cfg = Config::load().unwrap();
        assert!(cfg.production);
        clear_env();
    }

    #[test]
    #[serial]
    fn load_reads_cors_allowed_origin() {
        clear_env();
        env::set_var("OPENEIDAS_PIN", "1234");
        env::set_var(
            "OPENEIDAS_CORS_ALLOWED_ORIGIN",
            "https://demo.open-eidas.eu",
        );
        let cfg = Config::load().unwrap();
        assert_eq!(
            cfg.cors_allowed_origin.as_deref(),
            Some("https://demo.open-eidas.eu")
        );
        clear_env();
    }

    #[test]
    fn parses_go_style_durations() {
        assert_eq!(parse_go_duration("500ms"), Some(Duration::from_millis(500)));
        assert_eq!(parse_go_duration("1s"), Some(Duration::from_secs(1)));
        assert_eq!(parse_go_duration("1h"), Some(Duration::from_secs(3600)));
        assert_eq!(parse_go_duration("bogus"), None);
    }
}
