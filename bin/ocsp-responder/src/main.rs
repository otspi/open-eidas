//! Portage Rust de `cmd/ocsp-responder/main.go` : répond aux requêtes OCSP
//! (RFC 6960) pour la CA émettrice de la TSU, en s'appuyant sur la CRL
//! publiée par l'autorité plutôt que sur un accès direct à son registre.
//! Rang 2 de l'ordre de portage post-`tsa-server`
//! (`/home/philippe/.claude/plans/witty-hopping-nest.md`).

use std::sync::Arc;
use std::time::Duration;

use clap::{Parser, Subcommand};
use der::Encode;
use oe_hsm::SigningToken;

#[derive(Parser)]
#[command(
    name = "ocsp-responder",
    version,
    about = "Répondeur OCSP RFC 6960 (open-eidas)"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Serve,
    Enroll,
    Conformance {
        #[arg(long)]
        markdown: bool,
    },
    /// Affiche la version (identique à `--version`, sous forme de
    /// sous-commande — reproduit `cmd/ocsp-responder` (Go), qui n'a que
    /// celle-ci).
    Version,
}

fn die(context: &str, err: impl std::fmt::Display) -> ! {
    eprintln!("ocsp-responder: {context}: {err}");
    std::process::exit(1);
}

/// `":8319"` (forme conventionnelle de `net.Listen`, Go, pour « toutes les
/// interfaces ») n'est pas un hôte résoluble pour `tokio::net::TcpListener` :
/// contrairement à Go, un hôte vide avant les deux-points échoue la
/// résolution DNS au lieu d'être compris comme un joker. Reproduit ici la
/// même convention en préfixant `0.0.0.0`.
fn bind_addr(listen: &str) -> String {
    match listen.strip_prefix(':') {
        Some(port) => format!("0.0.0.0:{port}"),
        None => listen.to_string(),
    }
}

/// Paramètres du répondeur, tous pilotés par variables d'environnement —
/// un jeu séparé de `oe-config`, à l'identique de `cmd/ocsp-responder/config.go`
/// (Go) : ce service n'a pas besoin des champs propres à la TSA (journal
/// d'audit, contreseing, traçabilité temporelle).
struct Config {
    listen: String,
    max_request_bytes: usize,
    pkcs11_module: String,
    token_label: String,
    key_label: String,
    key_bits: u64,
    pin: String,
    cert_file: String,
    chain_file: String,
    enroll_endpoint: String,
    enroll_ca_file: String,
    enroll_insecure: bool,
    enroll_timeout: Duration,
    enroll_hmac_key: String,
    enroll_profile: String,
    subject_cn: String,
    pki_internal_url: String,
    pki_insecure: bool,
    pki_ca_file: String,
    crl_refresh: Duration,
}

fn env_str(key: &str, fallback: &str) -> String {
    std::env::var(key)
        .ok()
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| fallback.to_string())
}

fn env_bool(key: &str, fallback: bool) -> bool {
    std::env::var(key)
        .ok()
        .filter(|v| !v.is_empty())
        .and_then(|v| v.parse().ok())
        .unwrap_or(fallback)
}

fn env_u64(key: &str, fallback: u64) -> u64 {
    std::env::var(key)
        .ok()
        .filter(|v| !v.is_empty())
        .and_then(|v| v.parse().ok())
        .unwrap_or(fallback)
}

fn env_duration_secs(key: &str, fallback: Duration) -> Duration {
    std::env::var(key)
        .ok()
        .filter(|v| !v.is_empty())
        .and_then(|v| oe_config_duration(&v))
        .unwrap_or(fallback)
}

/// Sous-ensemble de `time.ParseDuration` (Go) suffisant ici : "5m", "30s", "24h".
fn oe_config_duration(s: &str) -> Option<Duration> {
    let s = s.trim();
    let (num, unit) = s.split_at(s.find(|c: char| !c.is_ascii_digit() && c != '.')?);
    let value: f64 = num.parse().ok()?;
    let secs = match unit {
        "ns" => value / 1e9,
        "us" | "µs" => value / 1e6,
        "ms" => value / 1e3,
        "s" => value,
        "m" => value * 60.0,
        "h" => value * 3600.0,
        _ => return None,
    };
    Some(Duration::from_secs_f64(secs))
}

impl Config {
    fn load() -> Result<Config, String> {
        let key_bits = env_u64("OPENEIDAS_KEY_BITS", 3072);
        if key_bits < 3072 {
            return Err(format!(
                "OPENEIDAS_KEY_BITS={key_bits}: ETSI TS 119 312 impose au moins 3072 bits pour RSA"
            ));
        }
        let pin = std::env::var("OPENEIDAS_PIN").unwrap_or_default();
        if pin.is_empty() {
            return Err("OPENEIDAS_PIN est obligatoire (code PIN du token PKCS#11)".to_string());
        }
        let pki_internal_url = env_str("OPENEIDAS_PKI_INTERNAL_URL", "");
        if pki_internal_url.is_empty() {
            return Err("OPENEIDAS_PKI_INTERNAL_URL est obligatoire (URL, interne au déploiement, à laquelle interroger la CRL)".to_string());
        }

        Ok(Config {
            listen: env_str("OPENEIDAS_LISTEN", ":8319"),
            max_request_bytes: env_u64("OPENEIDAS_MAX_REQUEST_BYTES", 16 * 1024) as usize,
            pkcs11_module: env_str("OPENEIDAS_PKCS11_MODULE", "/usr/lib/softhsm/libsofthsm2.so"),
            token_label: env_str("OPENEIDAS_TOKEN_LABEL", "open-eidas-ocsp"),
            key_label: env_str("OPENEIDAS_KEY_LABEL", "ocsp-signing-key"),
            key_bits,
            pin,
            cert_file: env_str("OPENEIDAS_CERT_FILE", "/var/lib/open-eidas/ocsp.pem"),
            chain_file: env_str("OPENEIDAS_CHAIN_FILE", "/var/lib/open-eidas/chain.pem"),
            enroll_endpoint: env_str("OPENEIDAS_ENROLL_ENDPOINT", ""),
            enroll_ca_file: env_str("OPENEIDAS_ENROLL_CA_FILE", ""),
            enroll_insecure: env_bool("OPENEIDAS_ENROLL_INSECURE", false),
            enroll_timeout: env_duration_secs("OPENEIDAS_ENROLL_TIMEOUT", Duration::from_secs(300)),
            enroll_hmac_key: std::env::var("OPENEIDAS_ENROLL_HMAC_KEY").unwrap_or_default(),
            enroll_profile: env_str("OPENEIDAS_ENROLL_PROFILE", "ocsp_responder"),
            subject_cn: env_str("OPENEIDAS_SUBJECT_CN", "Open eIDAS OCSP Responder 1"),
            pki_internal_url,
            pki_insecure: env_bool("OPENEIDAS_PKI_INSECURE", false),
            pki_ca_file: env_str("OPENEIDAS_PKI_CA_FILE", ""),
            crl_refresh: env_duration_secs("OPENEIDAS_OCSP_CRL_REFRESH", Duration::from_secs(300)),
        })
    }
}

/// Construit le client HTTP utilisé pour interroger la CRL de la PKI,
/// reprenant l'ancre de confiance ou la tolérance TLS configurée —
/// reproduit `newCRLHTTPClient` (Go).
fn build_crl_http_client(cfg: &Config) -> Result<reqwest::Client, String> {
    let mut builder = reqwest::Client::builder().timeout(Duration::from_secs(30));
    if !cfg.pki_ca_file.is_empty() {
        let pem = std::fs::read(&cfg.pki_ca_file).map_err(|e| e.to_string())?;
        let cert = reqwest::Certificate::from_pem(&pem).map_err(|e| e.to_string())?;
        builder = builder.add_root_certificate(cert);
    } else if cfg.pki_insecure {
        builder = builder.danger_accept_invalid_certs(true);
    }
    builder.build().map_err(|e| e.to_string())
}

async fn run_serve() {
    tracing_subscriber::fmt::init();
    let cfg = Config::load().unwrap_or_else(|e| die("configuration invalide", &e));

    let token = oe_hsm::Pkcs11Token::open(&oe_hsm::Options {
        module_path: cfg.pkcs11_module.clone(),
        token_label: cfg.token_label.clone(),
        key_label: cfg.key_label.clone(),
        pin: cfg.pin.clone(),
    })
    .unwrap_or_else(|e| die("ouverture du token PKCS#11", e));
    let signer: Arc<dyn SigningToken + Send + Sync> = Arc::new(oe_hsm::SyncToken::new(token));

    let mut leaf = oe_certs::load_file(&cfg.cert_file)
        .unwrap_or_else(|e| die("certificat de signature OCSP", e));
    if leaf.is_empty() {
        die("certificat de signature OCSP", "aucun certificat trouvé");
    }
    let certificate = leaf.remove(0);
    let chain =
        oe_certs::load_file(&cfg.chain_file).unwrap_or_else(|e| die("chaîne d'émission", e));
    if chain.is_empty() {
        die(
            "chaîne d'émission",
            format!(
                "absente de {} : émetteur requis pour répondre aux requêtes OCSP",
                cfg.chain_file
            ),
        );
    }
    let issuer = chain[0].clone();

    let crl_url = oe_ocsp_core::crl_url(&cfg.pki_internal_url, &issuer);
    let http_client =
        build_crl_http_client(&cfg).unwrap_or_else(|e| die("client HTTP de la CRL", e));
    let responder = Arc::new(
        oe_ocsp_core::Responder::new(oe_ocsp_core::Options {
            signer,
            certificate,
            issuer,
            crl_url,
            crl_refresh: cfg.crl_refresh,
            max_request_bytes: cfg.max_request_bytes,
            http_client: Some(http_client),
        })
        .unwrap_or_else(|e| die("construction du répondeur", e)),
    );
    responder
        .refresh()
        .await
        .unwrap_or_else(|e| die("chargement initial de la CRL", e));

    {
        let responder = responder.clone();
        let interval = cfg.crl_refresh;
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            ticker.tick().await;
            loop {
                ticker.tick().await;
                if let Err(e) = responder.refresh().await {
                    tracing::error!(erreur = %e, "rafraîchissement de la CRL impossible, conservation du dernier instantané");
                }
            }
        });
    }

    let app = axum::Router::new()
        .route(
            "/ocsp",
            axum::routing::post({
                let responder = responder.clone();
                move |body: axum::body::Bytes| {
                    let responder = responder.clone();
                    async move {
                        let der = responder.handle(&body).await;
                        (
                            [(
                                axum::http::header::CONTENT_TYPE,
                                "application/ocsp-response",
                            )],
                            der,
                        )
                    }
                }
            }),
        )
        .route("/healthz", axum::routing::get(|| async { "ok" }));

    let listener = tokio::net::TcpListener::bind(bind_addr(&cfg.listen))
        .await
        .unwrap_or_else(|e| die(&format!("écoute sur {}", cfg.listen), e));
    eprintln!("ocsp-responder: écoute sur {}", cfg.listen);
    if let Err(e) = axum::serve(listener, app).await {
        die("serveur HTTP", e);
    }
}

async fn run_enroll() {
    tracing_subscriber::fmt::init();
    let cfg = Config::load().unwrap_or_else(|e| die("configuration invalide", &e));

    let token = oe_hsm::Pkcs11Token::open(&oe_hsm::Options {
        module_path: cfg.pkcs11_module.clone(),
        token_label: cfg.token_label.clone(),
        key_label: cfg.key_label.clone(),
        pin: cfg.pin.clone(),
    })
    .unwrap_or_else(|e| die("ouverture du token PKCS#11", e));

    if token.public_key_der().is_err() {
        eprintln!(
            "ocsp-responder: génération de la clé de signature dans le HSM ({} bits, label {:?})",
            cfg.key_bits, cfg.key_label
        );
        token
            .generate_rsa_key(cfg.key_bits)
            .unwrap_or_else(|e| die("génération de la bi-clé", e));
    }

    if let Ok(existing) = oe_certs::load_file_optional(&cfg.cert_file) {
        if let Some(cert) = existing.first() {
            let cert_spki = cert.tbs_certificate().subject_public_key_info().to_der();
            let signer_spki = token.public_key_der();
            if let (Ok(a), Ok(b)) = (cert_spki, signer_spki) {
                if a == b {
                    eprintln!("ocsp-responder: certificat de signature OCSP déjà en place, enrôlement ignoré");
                    return;
                }
            }
        }
    }

    let client = oe_enroll::Client::new(oe_enroll::Options {
        endpoint: cfg.enroll_endpoint.clone(),
        profile: cfg.enroll_profile.clone(),
        hmac_secret: cfg.enroll_hmac_key.clone(),
        ca_file: (!cfg.enroll_ca_file.is_empty()).then(|| cfg.enroll_ca_file.clone()),
        insecure: cfg.enroll_insecure,
        timeout: cfg.enroll_timeout,
        user_agent: Some(format!("open-eidas-ocsp/{}", env!("CARGO_PKG_VERSION"))),
    })
    .unwrap_or_else(|e| die("client d'enrôlement", e));

    let result = client
        .request(
            &token,
            oe_enroll::Subject {
                common_name: cfg.subject_cn.clone(),
            },
        )
        .await
        .unwrap_or_else(|e| die("enrôlement", e));

    oe_certs::write_file(&cfg.cert_file, &[result.certificate])
        .unwrap_or_else(|e| die("écriture du certificat", e));
    if !result.chain.is_empty() {
        oe_certs::write_file(&cfg.chain_file, &result.chain)
            .unwrap_or_else(|e| die("écriture de la chaîne d'émission", e));
    }
    eprintln!(
        "ocsp-responder: enrôlement terminé, certificat écrit dans {}",
        cfg.cert_file
    );
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    match cli.command {
        Command::Serve => run_serve().await,
        Command::Enroll => run_enroll().await,
        Command::Conformance { markdown } => {
            let matrix = oe_conformance::system_matrix();
            if markdown {
                print!("{}", oe_conformance::render_markdown(&matrix));
            } else {
                for e in &matrix.0 {
                    println!(
                        "{} — {} : {}",
                        e.requirement,
                        e.requirement.title,
                        e.status.label()
                    );
                }
            }
            if let Err(msg) = matrix.validate() {
                eprintln!("{msg}");
                std::process::exit(1);
            }
        }
        Command::Version => println!("{}", env!("CARGO_PKG_VERSION")),
    }
}
