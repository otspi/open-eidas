//! Paramètres de `ra-console`, pilotés par variables d'environnement (12-factor).

use std::time::Duration;

#[derive(Debug, Clone)]
pub struct Config {
    pub listen: String,
    /// DSN du rôle PostgreSQL **de ra-console** (jamais celui de `ca-server`, ni un
    /// superutilisateur) : le démarrage refuse un rôle qui pourrait écrire dans les
    /// tables de la CA (`db_guard`).
    pub database_url: String,
    pub link: LinkConfig,
    pub enroll: EnrollConfig,
    pub webauthn: WebauthnConfig,
    /// Fréquence de la purge des sessions et challenges expirés (docs/WEBUI.md
    /// §15 étape 1c-2b).
    pub purge_interval: Duration,
    /// Journal chaîné propre à `ra-console` (docs/WEBUI.md §7, §15 étape 2b-A) :
    /// jamais celui de `ca-server`, une chaîne distincte.
    pub audit_file: String,
    /// Copie best-effort du journal sur un stockage objet compatible S3, auto-hébergé
    /// (docs/WEBUI.md §7, §15 étape 2b-C) : `None` si non configuré. À la différence de
    /// `ca-server`, un échec (local ou S3) ne bloque jamais connexion/déconnexion —
    /// décision déjà prise pour ce journal (voir `ra_console::audit::Recorder`), non
    /// remise en cause par l'ajout de S3.
    pub s3: Option<S3Config>,
}

/// Mêmes champs que `ca_server::config::S3Config` (même stockage S3-compatible
/// auto-hébergé, mêmes variables `OPENEIDAS_S3_*` — chaque service lit son propre
/// environnement, `OPENEIDAS_S3_KEY` distingue les deux journaux dans le même
/// compartiment) ; dupliqué plutôt que partagé, comme `ra_console::audit::Recorder`.
#[derive(Debug, Clone)]
pub struct S3Config {
    pub endpoint: String,
    pub bucket: String,
    pub region: String,
    pub access_key: String,
    pub secret_key: String,
    pub key: String,
    /// Clé du journal **de `ca-server`** dans le même compartiment
    /// (docs/WEBUI.md §7, §15 étape 2b-D) : `GET /api/v1/audit/search` relit
    /// et vérifie les deux chaînes, `ra-console` n'a aucun accès local au
    /// journal de `ca-server`, seul S3 les met en commun.
    pub ca_key: String,
}

fn s3_config() -> Result<Option<S3Config>, String> {
    let endpoint = optional("OPENEIDAS_S3_ENDPOINT", "");
    if endpoint.is_empty() {
        return Ok(None);
    }
    Ok(Some(S3Config {
        endpoint,
        bucket: required("OPENEIDAS_S3_BUCKET")?,
        region: optional("OPENEIDAS_S3_REGION", "us-east-1"),
        access_key: required("OPENEIDAS_S3_ACCESS_KEY")?,
        secret_key: required("OPENEIDAS_S3_SECRET_KEY")?,
        key: optional("OPENEIDAS_S3_KEY", "ra-console/audit.log"),
        ca_key: optional("OPENEIDAS_S3_CA_KEY", "ca-server/audit.log"),
    }))
}

/// Vérification des connexions (docs/WEBUI.md §15, étape 1c, §16) : `ra-console`
/// vérifie elle-même l'assertion, contre le registre en lecture seule.
#[derive(Debug, Clone)]
pub struct WebauthnConfig {
    pub rp_id: String,
    pub origin: String,
    pub rp_name: String,
    /// Même format que `OPENEIDAS_WEBAUTHN_MODELS_FILE` côté `ca-server`
    /// (`ca_server::webauthn_models`) : les deux services doivent admettre les
    /// mêmes modèles de clés, sans quoi une clé admise à l'enregistrement
    /// pourrait être refusée à la connexion, ou l'inverse.
    pub models_file: String,
    /// Secret du service, jamais transmis : dérive l'identifiant de la clé
    /// factice qu'un nom inconnu se voit proposer (anti-énumération, §16
    /// « connexion par nom, réponses uniformes »). Une valeur vide ferait des
    /// factices toutes identiques (dérivées du seul nom) : facile à
    /// distinguer d'une vraie clé, dont l'identifiant ne dépend d'aucun nom.
    pub login_decoy_secret: String,
}

/// Le lien mTLS vers `ca-server` (docs/WEBUI.md §16 « Lien interne »).
#[derive(Debug, Clone)]
pub struct LinkConfig {
    /// `https://<nom DNS du service>:<port interne>`. Le nom doit figurer au SAN du
    /// certificat `internal_server` de la CA.
    pub ca_url: String,
    /// Certificat `internal_client` de la console et sa clé (PEM).
    pub cert_file: String,
    pub key_file: String,
    /// Certificat de la CA émettrice, seule racine de confiance du lien (PEM).
    pub ca_file: String,
}

/// Demande du certificat client (`ra-console internal-cert`).
#[derive(Debug, Clone)]
pub struct EnrollConfig {
    /// API d'enrôlement publique de la CA (`http://ca:8320/api/v1/enroll`).
    pub url: String,
    pub hmac_key: String,
    pub timeout: Duration,
}

fn required(key: &str) -> Result<String, String> {
    match std::env::var(key).ok().filter(|v| !v.is_empty()) {
        Some(v) => Ok(v),
        None => Err(format!("{key} est obligatoire")),
    }
}

fn optional(key: &str, fallback: &str) -> String {
    std::env::var(key)
        .ok()
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| fallback.to_string())
}

impl Config {
    /// Ce que `serve` exige. La demande du certificat (`enroll`) n'y est pas :
    /// une console qui tourne n'a pas besoin du secret d'enrôlement.
    pub fn load() -> Result<Config, String> {
        let ca_url = required("OPENEIDAS_CA_INTERNAL_URL")?;
        if !ca_url.starts_with("https://") {
            return Err(format!(
                "OPENEIDAS_CA_INTERNAL_URL={ca_url:?} : le lien interne est en https (mTLS)"
            ));
        }
        Ok(Config {
            listen: optional("OPENEIDAS_RA_LISTEN", ":8330"),
            database_url: required("OPENEIDAS_DATABASE_URL")?,
            link: LinkConfig {
                ca_url,
                cert_file: required("OPENEIDAS_INTERNAL_TLS_CERT_FILE")?,
                key_file: required("OPENEIDAS_INTERNAL_TLS_KEY_FILE")?,
                ca_file: required("OPENEIDAS_CA_CERT_FILE")?,
            },
            enroll: EnrollConfig::from_env_lenient(),
            webauthn: WebauthnConfig {
                rp_id: required("OPENEIDAS_WEBAUTHN_RP_ID")?,
                origin: required("OPENEIDAS_WEBAUTHN_ORIGIN")?,
                rp_name: optional("OPENEIDAS_WEBAUTHN_RP_NAME", "Open eIDAS Console"),
                models_file: required("OPENEIDAS_WEBAUTHN_MODELS_FILE")?,
                login_decoy_secret: {
                    let secret = required("OPENEIDAS_LOGIN_DECOY_SECRET")?;
                    if secret.len() < 16 {
                        return Err(
                            "OPENEIDAS_LOGIN_DECOY_SECRET: au moins 16 octets (secret du service)"
                                .to_string(),
                        );
                    }
                    secret
                },
            },
            purge_interval: duration_seconds("OPENEIDAS_PURGE_INTERVAL_SECONDS", 60)?,
            audit_file: optional(
                "OPENEIDAS_RA_AUDIT_FILE",
                "/var/lib/open-eidas/state/ra-console-audit.log",
            ),
            s3: s3_config()?,
        })
    }

    /// Ce que `internal-cert` exige, en plus des fichiers du lien : l'API
    /// d'enrôlement et le secret partagé. Pas de base de données.
    pub fn load_for_enrollment() -> Result<(LinkConfig, EnrollConfig), String> {
        let link = LinkConfig {
            ca_url: optional("OPENEIDAS_CA_INTERNAL_URL", ""),
            cert_file: required("OPENEIDAS_INTERNAL_TLS_CERT_FILE")?,
            key_file: required("OPENEIDAS_INTERNAL_TLS_KEY_FILE")?,
            ca_file: optional("OPENEIDAS_CA_CERT_FILE", ""),
        };
        let enroll = EnrollConfig {
            url: required("OPENEIDAS_ENROLL_URL")?,
            hmac_key: required("OPENEIDAS_ENROLL_HMAC_KEY")?,
            timeout: enroll_timeout()?,
        };
        Ok((link, enroll))
    }
}

/// Un entier de secondes dans une variable d'environnement, ou une valeur par
/// défaut si elle est absente ou vide.
fn duration_seconds(key: &str, fallback_secs: u64) -> Result<Duration, String> {
    match std::env::var(key).ok().filter(|v| !v.is_empty()) {
        None => Ok(Duration::from_secs(fallback_secs)),
        Some(v) => v
            .parse::<u64>()
            .map(Duration::from_secs)
            .map_err(|_| format!("{key}: entier attendu, reçu {v:?}")),
    }
}

fn enroll_timeout() -> Result<Duration, String> {
    duration_seconds("OPENEIDAS_ENROLL_TIMEOUT_SECONDS", 10 * 60)
}

impl EnrollConfig {
    fn from_env_lenient() -> EnrollConfig {
        EnrollConfig {
            url: optional("OPENEIDAS_ENROLL_URL", ""),
            hmac_key: String::new(),
            timeout: Duration::from_secs(10 * 60),
        }
    }
}
