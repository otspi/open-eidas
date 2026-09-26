//! `ra-console` : la console d'exploitation RA/CA (docs/WEBUI.md).
//!
//! Sous-commandes : `serve`, `internal-cert`, `version`.

use std::sync::Arc;

use clap::{Parser, Subcommand};
use ra_console::audit::AuditRecorder;
use ra_console::ca_link::CaLink;
use ra_console::config::Config;
use ra_console::login::LoginService;
use ra_console::session::Sessions;
use ra_console::{db_guard, http, purge, webauthn_models};
use sqlx::postgres::PgPoolOptions;

#[derive(Parser)]
#[command(
    name = "ra-console",
    version,
    about = "Console d'exploitation RA/CA (open-eidas)"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Sert la console.
    Serve,
    /// Demande le certificat client `internal_client` de la console à la CA (Jour 0,
    /// docs/WEBUI.md §14). Crée la clé (0600) si besoin. La demande passe par la file
    /// RA de la CA : un opérateur nommé l'approuve (`ca-server ra approve`), jamais
    /// la console elle-même.
    InternalCert,
}

fn die(context: &str, err: impl std::fmt::Display) -> ! {
    eprintln!("ra-console: {context}: {err}");
    std::process::exit(1);
}

/// Construit le journal (local, et S3 best-effort si configuré, docs/WEBUI.md
/// §7, §15 étape 2b-C).
fn open_recorder(cfg: &Config) -> AuditRecorder {
    let log = Arc::new(
        oe_audit::Log::open(&cfg.audit_file).unwrap_or_else(|e| die("journal d'audit", e)),
    );
    let s3 = cfg.s3.as_ref().map(|c| {
        let client = oe_s3::Client::new(oe_s3::Options {
            endpoint: c.endpoint.clone(),
            bucket: c.bucket.clone(),
            region: c.region.clone(),
            access_key: c.access_key.clone(),
            secret_key: c.secret_key.clone(),
            timeout: std::time::Duration::from_secs(30),
        })
        .unwrap_or_else(|e| die("client S3 du journal", e));
        (Arc::new(client), c.key.clone())
    });
    AuditRecorder::new(log, cfg.audit_file.clone(), s3)
}

fn bind_addr(listen: &str) -> String {
    match listen.strip_prefix(':') {
        Some(port) => format!("0.0.0.0:{port}"),
        None => listen.to_string(),
    }
}

async fn run_serve() {
    tracing_subscriber::fmt::init();
    let cfg = Config::load().unwrap_or_else(|e| die("configuration invalide", e));

    let pool = PgPoolOptions::new()
        .max_connections(8)
        .connect(&cfg.database_url)
        .await
        .unwrap_or_else(|e| die("connexion à la base", e));
    // Avant de servir quoi que ce soit : le rôle de la base doit être en lecture
    // seule sur les tables de ca-server (docs/WEBUI.md §16).
    db_guard::check_read_only(&pool)
        .await
        .unwrap_or_else(|e| die("rôle PostgreSQL refusé", e));

    let link = CaLink::new(&cfg.link).unwrap_or_else(|e| die("lien vers ca-server", e));
    // ca-server peut démarrer après la console : un lien injoignable n'est pas fatal,
    // il rend /healthz dégradé.
    match link.ping().await {
        Ok(()) => tracing::info!("lien mTLS vers ca-server opérationnel"),
        Err(e) => tracing::warn!(erreur = %e, "lien vers ca-server indisponible au démarrage"),
    }

    // Vérification des connexions (docs/WEBUI.md §15, étape 1c) : le même format
    // de liste blanche que `ca-server`, mais un exemplaire propre à la console
    // (§16, elle ne dépend d'aucun code de ca-server).
    let models = webauthn_models::load(&cfg.webauthn.models_file)
        .unwrap_or_else(|e| die("liste blanche de modèles WebAuthn", e));
    let origin = oe_webauthn::Url::parse(&cfg.webauthn.origin)
        .unwrap_or_else(|e| die("OPENEIDAS_WEBAUTHN_ORIGIN", e));
    let verifier =
        oe_webauthn::Verifier::new(&cfg.webauthn.rp_id, &origin, &cfg.webauthn.rp_name, models)
            .unwrap_or_else(|e| die("configuration WebAuthn", e));

    // Son propre journal chaîné (docs/WEBUI.md §7, §15 étape 2b-A/2b-C) : jamais
    // celui de ca-server, une chaîne distincte, copiée best-effort sur S3 si configuré.
    let journal: Arc<dyn ra_console::audit::Recorder> = Arc::new(open_recorder(&cfg));

    let login = LoginService::new(
        oe_actions::Registry::new(pool.clone()),
        verifier,
        cfg.webauthn.login_decoy_secret.into_bytes(),
        journal.clone(),
    );
    let sessions = Sessions::new(oe_actions::Registry::new(pool.clone()), journal);

    // Purge périodique des sessions et challenges expirés (§15 étape 1c-2b) :
    // aucune opération manuelle, arrêtée par le même signal que le serveur.
    purge::spawn_periodic(pool.clone(), cfg.purge_interval);

    let app = http::router(Arc::new(http::AppState {
        pool,
        link,
        login,
        sessions,
        s3: cfg.s3.clone(),
    }));
    let listener = tokio::net::TcpListener::bind(bind_addr(&cfg.listen))
        .await
        .unwrap_or_else(|e| die(&format!("écoute sur {}", cfg.listen), e));
    tracing::info!(adresse = %cfg.listen, "console en écoute");
    let shutdown = async {
        tokio::signal::ctrl_c().await.ok();
        tracing::info!("arrêt demandé");
    };
    if let Err(e) = axum::serve(listener, app)
        .with_graceful_shutdown(shutdown)
        .await
    {
        die("serveur HTTP", e);
    }
}

async fn run_internal_cert() {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .init();
    let (link, enroll) =
        Config::load_for_enrollment().unwrap_or_else(|e| die("configuration invalide", e));

    let key = oe_enroll::software_key::load_or_create_key(std::path::Path::new(&link.key_file))
        .unwrap_or_else(|e| die("clé du lien interne", e));
    let client = oe_enroll::Client::new(oe_enroll::Options {
        endpoint: enroll.url,
        profile: "internal_client".to_string(),
        hmac_secret: enroll.hmac_key,
        timeout: enroll.timeout,
        ..Default::default()
    })
    .unwrap_or_else(|e| die("client d'enrôlement", e));

    eprintln!("Demande du certificat client (profil internal_client) : un opérateur doit l'approuver sur la CA (`ca-server ra approve`).");
    let result = client
        .request(
            &key,
            oe_enroll::Subject {
                common_name: oe_conformance::INTERNAL_CLIENT_CN.to_string(),
            },
        )
        .await
        .unwrap_or_else(|e| die("enrôlement", e));

    use der::EncodePem;
    let pem = result
        .certificate
        .to_pem(der::pem::LineEnding::LF)
        .unwrap_or_else(|e| die("encodage du certificat", e));
    oe_enroll::software_key::write_certificate(std::path::Path::new(&link.cert_file), &pem)
        .unwrap_or_else(|e| die("écriture du certificat", e));
    eprintln!("Certificat client écrit dans {}.", link.cert_file);
}

#[tokio::main]
async fn main() {
    match Cli::parse().command {
        Command::Serve => run_serve().await,
        Command::InternalCert => run_internal_cert().await,
    }
}
