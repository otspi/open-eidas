//! Portage Rust de `cmd/ca-server` : l'autorité de certification et
//! d'enregistrement d'Open eIDAS. Elle remplace OpenXPKI (voir
//! `INDEPENDANCE.md`) : elle émet les certificats de l'unité d'horodatage et
//! du répondeur OCSP depuis une CSR, publie l'état de révocation, et porte
//! le point d'approbation RA. Rang 3 de l'ordre de portage
//! (`/home/philippe/.claude/plans/witty-hopping-nest.md`), dernier binaire
//! du « big bang ».
//!
//! Sous-commandes : `ceremony`, `serve`, `ra list|approve|reject`, `revoke`,
//! `operators bootstrap-admin|recover-admin|audit|reconcile`, `internal-cert server`, `conformance`,
//! `healthcheck`, `verify-audit`.

use std::sync::Arc;

use ca_server::{config, http, internal, internal_tls, registry_check, revoker, webauthn_models};
use clap::{Parser, Subcommand};
use config::Config;
use oe_hsm::SigningToken;

#[derive(Parser)]
#[command(
    name = "ca-server",
    version,
    about = "Autorité de certification et d'enregistrement (open-eidas)"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Crée la hiérarchie de CA (idempotent).
    Ceremony,
    /// Expose l'API d'enrôlement et publie la CRL.
    Serve,
    /// Interface de l'opérateur d'enregistrement.
    Ra {
        #[command(subcommand)]
        action: RaAction,
    },
    /// Révoque un certificat émis et republie la CRL.
    Revoke {
        /// Numéro de série en hexadécimal (voir `ra list`, le journal d'audit).
        serial_hex: String,
        /// Code motif RFC 5280 §5.3.1 (1=keyCompromise, 4=superseded, 5=cessationOfOperation, ...).
        reason: i32,
        operator: String,
        #[arg(trailing_var_arg = true)]
        comment: Vec<String>,
    },
    /// Registre des opérateurs de la console d'exploitation (docs/WEBUI.md §10).
    Operators {
        #[command(subcommand)]
        action: OperatorsAction,
    },
    /// Certificat du serveur du lien interne (docs/WEBUI.md §14, §16).
    InternalCert {
        #[command(subcommand)]
        action: InternalCertAction,
    },
    /// Matrice de conformité ETSI.
    Conformance {
        #[arg(long)]
        markdown: bool,
    },
    /// Interroge /healthz de cette instance.
    Healthcheck,
    /// Vérifie l'intégrité de la chaîne du journal d'audit.
    VerifyAudit { path: Option<String> },
    /// Affiche la version (identique à `--version`, sous forme de
    /// sous-commande — reproduit `cmd/ca-server` (Go), qui n'a que celle-ci).
    Version,
}

#[derive(Subcommand)]
enum InternalCertAction {
    /// Demande (ou récupère) le certificat `internal_server` de ce service.
    /// Crée la clé si elle n'existe pas, dépose la demande, et écrit le
    /// certificat dès qu'elle est approuvée (`ra approve`). Relancer la
    /// commande après approbation. Code de sortie 3 : demande en attente.
    Server {
        /// Nom DNS du service, celui que `ra-console` utilisera pour s'y
        /// connecter (ex. `ca.open-eidas.svc`). Minuscules, sans joker.
        dns: String,
    },
}

#[derive(Subcommand)]
enum OperatorsAction {
    /// Jour 0 : crée le premier administrateur et son invitation à usage
    /// unique. Refuse s'il existe déjà un administrateur actif. Le jeton est
    /// affiché une seule fois, sur la sortie standard.
    BootstrapAdmin {
        /// Nom de l'administrateur (1 à 100 caractères).
        name: String,
        /// Durée de validité de l'invitation, en minutes (1 à 1440).
        #[arg(long, default_value_t = 15)]
        ttl_minutes: i64,
    },
    /// Résout les divergences entre le registre et le journal chaîné
    /// (docs/WEBUI.md §21), par exemple après une restauration de la base : le
    /// journal fait foi. Une révocation ou un rôle du journal absent de la base est
    /// ré-appliqué ; une clé perdue ne peut pas être recréée, et n'est acquittée
    /// que sur demande explicite. Chaque résolution est consignée au journal.
    /// Code de sortie 0 : tout est résolu ; 1 : reste des divergences ; 2 : journal
    /// illisible ou rompu.
    Reconcile {
        /// Motif écrit (consigné au journal).
        #[arg(long)]
        reason: String,
        /// Prend acte de la perte de cette clé (à ré-enrôler). Répétable.
        #[arg(long = "acknowledge-missing")]
        acknowledge_missing: Vec<String>,
        /// Montre ce qui serait fait, sans rien modifier ni écrire au journal.
        #[arg(long)]
        dry_run: bool,
        /// Journal à lire (défaut : `OPENEIDAS_AUDIT_FILE`).
        #[arg(long)]
        journal: Option<String>,
    },
    /// Audite la chaîne du registre (docs/WEBUI.md §21) : chaque clé active se
    /// remonte, signatures re-vérifiées, jusqu'à une ancre attestée par le journal
    /// chaîné. Code de sortie 0 : registre sain ; 1 : constats ; 2 : journal
    /// illisible ou rompu (on ne juge pas le registre contre un journal douteux).
    Audit {
        /// Journal à lire (défaut : `OPENEIDAS_AUDIT_FILE`), par exemple la copie
        /// répliquée hors de l'hôte.
        #[arg(long)]
        journal: Option<String>,
    },
    /// Récupération d'un système verrouillé (docs/WEBUI.md §21) : crée une
    /// invitation d'administrateur alors que les administrateurs « actifs » ont
    /// perdu leurs clés, sans rien désactiver du registre existant. Exige le PIN
    /// du token PKCS#11 (garde de l'hôte), un motif écrit et un drapeau explicite ;
    /// écrit l'événement `operators.admin_recovery` au journal. Le jeton est
    /// affiché une seule fois, sur la sortie standard.
    RecoverAdmin {
        /// Nom de l'administrateur : nouveau, ou un administrateur existant qui a
        /// perdu sa clé.
        name: String,
        /// Motif écrit (consigné au journal).
        #[arg(long)]
        reason: String,
        /// Confirmation explicite : cette commande contourne le refus de
        /// `bootstrap-admin` face à des administrateurs actifs.
        #[arg(long)]
        confirm_recovery: bool,
        /// Le PIN du token de la CA émettrice est lu sur l'entrée standard (une
        /// ligne), jamais en argument ni en variable d'environnement :
        /// `read -rs PIN; printf %s "$PIN" | ca-server operators recover-admin … --pin-stdin`.
        #[arg(long, required = true)]
        pin_stdin: bool,
        /// Durée de validité de l'invitation, en minutes (1 à 1440).
        #[arg(long, default_value_t = 15)]
        ttl_minutes: i64,
    },
}

#[derive(Subcommand)]
enum RaAction {
    /// Liste les demandes d'enrôlement.
    List { state: Option<String> },
    /// Approuve une demande, sous l'identité d'un opérateur.
    Approve {
        transaction_id: String,
        operator: String,
        #[arg(trailing_var_arg = true)]
        comment: Vec<String>,
    },
    /// Rejette une demande, sous l'identité d'un opérateur.
    Reject {
        transaction_id: String,
        operator: String,
        #[arg(trailing_var_arg = true)]
        comment: Vec<String>,
    },
}

fn die(context: &str, err: impl std::fmt::Display) -> ! {
    eprintln!("ca-server: {context}: {err}");
    std::process::exit(1);
}

/// `":8320"` (forme conventionnelle de `net.Listen`, Go, pour « toutes les
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

/// Relie le journal d'audit aux deux points d'injection qui en dépendent
/// (`oe-ca-core` et `oe-raflow`) — mêmes noms d'événement que le binaire Go,
/// qui partage lui aussi un seul journal chaîné entre ces deux sources.
///
/// Le fichier local reste la source de vérité (verrou, relecture, chaînage) ;
/// s'il est configuré, un stockage S3-compatible auto-hébergé (docs/WEBUI.md
/// §7, §15 étape 2b) en reçoit une copie à chaque écriture — le journal
/// entier, S3 ne connaissant pas d'ajout partiel. Bloquant, comme
/// `oe_ca_core::Recorder`/`oe_raflow::Recorder` : un échec de l'envoi propage
/// une erreur, rien n'est considéré journalisé tant qu'il n'a pas atteint S3.
#[derive(Clone)]
struct AuditRecorder {
    log: Arc<oe_audit::Log>,
    /// Chemin du fichier local : relu en entier après chaque écriture pour
    /// l'envoi S3 (le contenu exact qui vient d'être scellé, verrou compris).
    path: String,
    s3: Option<(Arc<oe_s3::Client>, String)>,
}

/// Construit le journal (local, et S3 si configuré) pour une commande.
fn open_recorder(cfg: &Config) -> AuditRecorder {
    let log = Arc::new(open_journal(cfg));
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
    AuditRecorder {
        log,
        path: cfg.audit_file.clone(),
        s3,
    }
}

fn json_to_audit_data(data: serde_json::Value) -> Option<oe_audit::Data> {
    match data {
        serde_json::Value::Object(map) => Some(map.into_iter().collect()),
        serde_json::Value::Null => None,
        other => {
            let mut m = oe_audit::Data::new();
            m.insert("value".to_string(), other);
            Some(m)
        }
    }
}

impl AuditRecorder {
    async fn append_and_replicate(
        &self,
        event: &str,
        data: serde_json::Value,
    ) -> Result<(), String> {
        self.log
            .append(event, json_to_audit_data(data))
            .map_err(|e| e.to_string())?;
        if let Some((client, key)) = &self.s3 {
            let bytes = std::fs::read(&self.path)
                .map_err(|e| format!("relecture du journal pour l'envoi S3 : {e}"))?;
            client
                .put(key, bytes)
                .await
                .map_err(|e| format!("envoi S3 du journal : {e}"))?;
        }
        Ok(())
    }
}

#[async_trait::async_trait]
impl oe_ca_core::Recorder for AuditRecorder {
    async fn append(&self, event: &str, data: serde_json::Value) -> Result<(), String> {
        self.append_and_replicate(event, data).await
    }
}

#[async_trait::async_trait]
impl oe_raflow::Recorder for AuditRecorder {
    async fn append(&self, event: &str, data: serde_json::Value) -> Result<(), String> {
        self.append_and_replicate(event, data).await
    }
}

async fn open_store(cfg: &Config) -> oe_castore::Postgres {
    oe_castore::Postgres::open(&cfg.dsn)
        .await
        .unwrap_or_else(|e| die("ouverture du registre PostgreSQL", e))
}

fn open_journal(cfg: &Config) -> oe_audit::Log {
    oe_audit::Log::open(&cfg.audit_file).unwrap_or_else(|e| die("journal d'audit", e))
}

/// Ouvre le token de la CA émettrice. La clé est générée au premier appel :
/// la cérémonie est ainsi reproductible sans manipulation préalable, tout
/// en restant confinée au module cryptographique.
fn open_key(
    cfg: &Config,
    token_label: &str,
    key_label: &str,
    pin: &str,
    role: &str,
) -> oe_hsm::Pkcs11Token {
    let token = oe_hsm::Pkcs11Token::open(&oe_hsm::Options {
        module_path: cfg.pkcs11_module.clone(),
        token_label: token_label.to_string(),
        key_label: key_label.to_string(),
        pin: pin.to_string(),
    })
    .unwrap_or_else(|e| die(&format!("ouverture du token PKCS#11 ({role})"), e));
    if token.public_key_der().is_err() {
        tracing::info!(
            role,
            bits = cfg.key_bits,
            token = token_label,
            label = key_label,
            "génération de la clé d'autorité dans le HSM"
        );
        token
            .generate_rsa_key(cfg.key_bits)
            .unwrap_or_else(|e| die(&format!("génération de la bi-clé ({role})"), e));
    }
    token
}

fn open_issuing_key(cfg: &Config) -> oe_hsm::Pkcs11Token {
    open_key(
        cfg,
        &cfg.issuing_token_label,
        &cfg.issuing_key_label,
        &cfg.issuing_pin,
        "CA émettrice",
    )
}

fn open_root_key(cfg: &Config) -> oe_hsm::Pkcs11Token {
    open_key(
        cfg,
        &cfg.root_token_label,
        &cfg.root_key_label,
        &cfg.root_pin,
        "racine",
    )
}

async fn run_ceremony() {
    tracing_subscriber::fmt::init();
    let cfg = Config::load().unwrap_or_else(|e| die("configuration invalide", &e));
    if cfg.ceremony_operator.is_empty() {
        die("configuration invalide", "OPENEIDAS_CEREMONY_OPERATOR est obligatoire : la cérémonie de clé doit être imputable (ETSI EN 319 411-1 §6.5.1)");
    }

    let store = open_store(&cfg).await;

    let root_token = open_root_key(&cfg);
    let root_signer: Arc<dyn SigningToken + Send + Sync> =
        Arc::new(oe_hsm::SyncToken::new(root_token));
    let issuing_token = open_issuing_key(&cfg);
    let issuing_signer: Arc<dyn SigningToken + Send + Sync> =
        Arc::new(oe_hsm::SyncToken::new(issuing_token));

    let recorder: Arc<dyn oe_ca_core::Recorder> = Arc::new(open_recorder(&cfg));
    let h = oe_ca_core::ceremony::run_ceremony(oe_ca_core::ceremony::CeremonyOptions {
        root_signer,
        issuing_signer,
        root_cn: cfg.root_cn.clone(),
        issuing_cn: cfg.issuing_cn.clone(),
        organization: cfg.organization.clone(),
        country: cfg.country.clone(),
        root_validity: cfg.root_validity,
        issuing_validity: cfg.issuing_validity,
        root_token_label: cfg.root_token_label.clone(),
        root_key_label: cfg.root_key_label.clone(),
        issuing_token_label: cfg.issuing_token_label.clone(),
        issuing_key_label: cfg.issuing_key_label.clone(),
        store: Arc::new(store),
        operator: cfg.ceremony_operator.clone(),
        recorder: Some(recorder),
    })
    .await
    .unwrap_or_else(|e| die("cérémonie de clé", e));

    tracing::info!(
        creee = h.created,
        racine = %h.root.tbs_certificate().subject(),
        emettrice = %h.issuing.tbs_certificate().subject(),
        emettrice_expiration = %h.issuing.tbs_certificate().validity().not_after.to_date_time(),
        "hiérarchie de CA en place"
    );
}

/// Relit la hiérarchie enregistrée et construit l'autorité émettrice. Ne
/// crée jamais d'autorité : `ceremony` est le seul chemin par lequel une
/// hiérarchie apparaît.
async fn build_issuer(
    cfg: &Config,
    store: Arc<dyn oe_castore::Store>,
    recorder: Arc<dyn oe_ca_core::Recorder>,
) -> oe_ca_core::Issuer {
    let hierarchy = oe_ca_core::ceremony::load_hierarchy(store.as_ref())
        .await
        .unwrap_or_else(|e| die("lecture de la hiérarchie de CA", e))
        .unwrap_or_else(|| {
            die(
                "lecture de la hiérarchie de CA",
                "aucune hiérarchie enregistrée : exécutez d'abord `ca-server ceremony`",
            )
        });

    let issuing_token = open_issuing_key(cfg);
    let signer: Arc<dyn SigningToken + Send + Sync> =
        Arc::new(oe_hsm::SyncToken::new(issuing_token));

    oe_ca_core::Issuer::new(oe_ca_core::Options {
        signer,
        certificate: hierarchy.issuing,
        chain: vec![hierarchy.root],
        store,
        public_url: cfg.public_url.clone(),
        ocsp_url: (!cfg.ocsp_url.is_empty()).then(|| cfg.ocsp_url.clone()),
        crl_validity: cfg.crl_validity,
        crl_grace: cfg.crl_grace,
        recorder: Some(recorder),
    })
    .unwrap_or_else(|e| die("construction de l'autorité émettrice", e))
}

/// Le service d'actions d'opérateur, derrière le lien interne. Toute lacune de
/// configuration est fatale : un lien interne à moitié configuré n'est pas
/// ouvert (« échec fermé »).
async fn build_actions_service(
    cfg: &Config,
    store: Arc<dyn oe_castore::Store>,
    recorder: Arc<dyn oe_raflow::Recorder>,
    issuer: Arc<oe_ca_core::Issuer>,
) -> (
    Arc<oe_actions::Service>,
    Arc<oe_actions::RegistryGuard>,
    oe_actions::Registry,
) {
    for (name, value) in [
        ("OPENEIDAS_WEBAUTHN_RP_ID", &cfg.webauthn_rp_id),
        ("OPENEIDAS_WEBAUTHN_ORIGIN", &cfg.webauthn_origin),
        ("OPENEIDAS_WEBAUTHN_MODELS_FILE", &cfg.webauthn_models_file),
    ] {
        if value.is_empty() {
            die(
                "lien interne",
                format!("{name} est obligatoire quand OPENEIDAS_INTERNAL_LISTEN est défini"),
            );
        }
    }
    let models = webauthn_models::load(&cfg.webauthn_models_file)
        .unwrap_or_else(|e| die("liste blanche de modèles de clés", e));
    let origin = oe_webauthn::Url::parse(&cfg.webauthn_origin)
        .unwrap_or_else(|e| die("OPENEIDAS_WEBAUTHN_ORIGIN", e));
    let verifier =
        oe_webauthn::Verifier::new(&cfg.webauthn_rp_id, &origin, &cfg.webauthn_rp_name, models)
            .unwrap_or_else(|e| die("configuration WebAuthn", e));
    let registry = oe_actions::Registry::connect(&cfg.dsn)
        .await
        .unwrap_or_else(|e| die("ouverture du registre des opérateurs", e));
    let decider = oe_raflow::Decider::new(oe_raflow::DeciderOptions {
        store: store.clone(),
        recorder: Some(recorder.clone()),
        clock: None,
    });
    // Fermée tant que le contrôle du registre contre le journal n'a pas dit
    // qu'il est sain : le service ne sert rien avant.
    let guard = oe_actions::RegistryGuard::new();
    guard.block(vec!["contrôle du registre en cours".to_string()]);
    let service = Arc::new(
        oe_actions::Service::new(
            registry.clone(),
            verifier,
            store,
            decider,
            recorder,
            Arc::new(time::OffsetDateTime::now_utc),
        )
        .with_revoker(Arc::new(revoker::IssuerRevoker(issuer)))
        .with_guard(guard.clone()),
    );
    (service, guard, registry)
}

fn build_flow(
    cfg: &Config,
    store: Arc<dyn oe_castore::Store>,
    issuer: Arc<oe_ca_core::Issuer>,
    recorder: Arc<dyn oe_raflow::Recorder>,
) -> Arc<oe_raflow::Flow> {
    Arc::new(
        oe_raflow::Flow::new(oe_raflow::Options {
            store,
            issuer,
            hmac_secret: cfg.enroll_hmac_key.clone(),
            recorder: Some(recorder),
            retry_after: time::Duration::seconds(5),
            clock: None,
        })
        .unwrap_or_else(|e| die("construction de la machine à états RA", e.to_string())),
    )
}

/// TLS du lien interne : les deux fichiers ou aucun. Sans TLS, le lien reste
/// réservé à la boucle locale ; avec, il exige le certificat client de
/// `ra-console` (docs/WEBUI.md §16).
fn internal_link_tls(
    cfg: &Config,
    issuer: &x509_cert::Certificate,
) -> Option<rustls::ServerConfig> {
    if cfg.internal_listen.is_empty() {
        if !cfg.internal_tls_cert_file.is_empty() || !cfg.internal_tls_key_file.is_empty() {
            die(
                "lien interne",
                "OPENEIDAS_INTERNAL_TLS_* sans OPENEIDAS_INTERNAL_LISTEN : rien à protéger",
            );
        }
        return None;
    }
    match (
        cfg.internal_tls_cert_file.is_empty(),
        cfg.internal_tls_key_file.is_empty(),
    ) {
        (true, true) => {
            internal::check_loopback(&cfg.internal_listen)
                .unwrap_or_else(|e| die("lien interne", e));
            tracing::warn!("lien interne sans TLS : boucle locale seulement");
            None
        }
        (false, false) => {
            let cert = std::fs::read(&cfg.internal_tls_cert_file)
                .unwrap_or_else(|e| die("certificat du lien interne", e));
            let key = std::fs::read(&cfg.internal_tls_key_file)
                .unwrap_or_else(|e| die("clé du lien interne", e));
            Some(
                internal_tls::server_config(issuer, &cert, &key, time::OffsetDateTime::now_utc())
                    .unwrap_or_else(|e| die("TLS du lien interne", e)),
            )
        }
        _ => die(
            "lien interne",
            "OPENEIDAS_INTERNAL_TLS_CERT_FILE et OPENEIDAS_INTERNAL_TLS_KEY_FILE vont ensemble",
        ),
    }
}

async fn run_serve() {
    tracing_subscriber::fmt::init();
    let cfg = Config::load().unwrap_or_else(|e| die("configuration invalide", &e));

    let store: Arc<dyn oe_castore::Store> = Arc::new(open_store(&cfg).await);
    let audit = open_recorder(&cfg);
    let recorder: Arc<dyn oe_ca_core::Recorder> = Arc::new(audit.clone());

    let issuer = Arc::new(build_issuer(&cfg, store.clone(), recorder).await);

    let flow_recorder: Arc<dyn oe_raflow::Recorder> = Arc::new(audit.clone());
    let internal_service = if cfg.internal_listen.is_empty() {
        None
    } else {
        let (service, guard, registry) =
            build_actions_service(&cfg, store.clone(), flow_recorder.clone(), issuer.clone()).await;
        // Avant d'ouvrir quoi que ce soit : le registre est-il conforme au journal ?
        registry_check::refresh(
            &registry,
            &cfg.audit_file,
            &guard,
            std::time::Duration::ZERO,
        )
        .await;
        Some((service, guard, registry))
    };
    let internal_tls = internal_link_tls(&cfg, issuer.certificate());
    let internal_store = store.clone();
    let flow = build_flow(&cfg, store.clone(), issuer.clone(), flow_recorder);

    let _ = audit
        .append_and_replicate(
            oe_audit::EVENT_OPENED,
            serde_json::json!({
                "version": env!("CARGO_PKG_VERSION"),
                "role": "ca-server",
                "emettrice": issuer.certificate().tbs_certificate().subject().to_string(),
                "public_url": cfg.public_url.clone(),
            }),
        )
        .await;

    let mut server = http::Server::new(issuer.clone(), flow, env!("CARGO_PKG_VERSION").to_string());
    if let Some((_, guard, _)) = &internal_service {
        server = server.with_registry_guard(guard.clone());
    }
    let server = Arc::new(server);

    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    if let Some((_, guard, registry)) = &internal_service {
        registry_check::spawn_periodic(
            registry.clone(),
            cfg.audit_file.clone(),
            guard.clone(),
            cfg.registry_check_interval,
            shutdown_rx.clone(),
        );
    }
    server
        .start_crl_publication(cfg.crl_refresh, shutdown_rx.clone())
        .await
        .unwrap_or_else(|e| die("publication initiale de la CRL", e));

    let app = http::router(server.clone(), cfg.max_request_bytes);
    let listener = tokio::net::TcpListener::bind(bind_addr(&cfg.listen))
        .await
        .unwrap_or_else(|e| die(&format!("écoute sur {}", cfg.listen), e));
    tracing::info!(adresse = %cfg.listen, emettrice = %server.issuer().certificate().tbs_certificate().subject(), "autorité de certification en écoute");

    if let Some((service, _, _)) = internal_service {
        let tcp = tokio::net::TcpListener::bind(bind_addr(&cfg.internal_listen))
            .await
            .unwrap_or_else(|e| die(&format!("écoute sur {}", cfg.internal_listen), e));
        tracing::info!(adresse = %cfg.internal_listen, mtls = internal_tls.is_some(), "lien interne en écoute");
        let app = internal::router(service, cfg.max_request_bytes);
        let mut stop = shutdown_rx.clone();
        let done = async move {
            let _ = stop.changed().await;
        };
        match internal_tls {
            Some(tls) => {
                let listener = internal_tls::TlsListener::new(tcp, tls, internal_store);
                tokio::spawn(async move {
                    if let Err(e) = axum::serve(listener, app)
                        .with_graceful_shutdown(done)
                        .await
                    {
                        die("serveur HTTP interne", e);
                    }
                });
            }
            None => {
                tokio::spawn(async move {
                    if let Err(e) = axum::serve(tcp, app).with_graceful_shutdown(done).await {
                        die("serveur HTTP interne", e);
                    }
                });
            }
        }
    }

    let shutdown_timeout = cfg.shutdown_timeout;
    let graceful = async move {
        tokio::signal::ctrl_c().await.ok();
        tracing::info!("arrêt demandé, fermeture en cours");
        let _ = shutdown_tx.send(true);
        // Filet de sécurité : si le drainage des requêtes en cours ne se
        // termine pas dans le délai imparti, on force l'arrêt plutôt que de
        // rester bloqué indéfiniment (reproduit `httpSrv.Shutdown(shutdownCtx)`).
        tokio::spawn(async move {
            tokio::time::sleep(shutdown_timeout).await;
            tracing::error!(delai = ?shutdown_timeout, "arrêt non terminé, requêtes en cours abandonnées");
            std::process::exit(1);
        });
    };
    if let Err(e) = axum::serve(listener, app)
        .with_graceful_shutdown(graceful)
        .await
    {
        die("serveur HTTP", e);
    }
}

fn join_comment(parts: &[String]) -> String {
    parts.join(" ")
}

async fn run_ra_list(state: Option<String>) {
    tracing_subscriber::fmt::init();
    let cfg = Config::load_without_hsm().unwrap_or_else(|e| die("configuration invalide", &e));
    let store: Arc<dyn oe_castore::Store> = Arc::new(open_store(&cfg).await);

    let filter = match state.as_deref() {
        None | Some("") => None,
        Some("PENDING") => Some(oe_castore::RequestState::Pending),
        Some("APPROVED") => Some(oe_castore::RequestState::Approved),
        Some("ISSUED") => Some(oe_castore::RequestState::Issued),
        Some("REJECTED") => Some(oe_castore::RequestState::Rejected),
        Some(other) => die(
            "liste des demandes",
            format!("état inconnu: {other} (attendu PENDING|APPROVED|ISSUED|REJECTED)"),
        ),
    };
    let requests = store
        .requests(filter)
        .await
        .unwrap_or_else(|e| die("liste des demandes", e));
    println!("TRANSACTION\tPROFIL\tSUJET (CN)\tÉTAT\tOPÉRATEUR\tREÇUE LE");
    for r in &requests {
        let operator = if r.operator.is_empty() {
            "—"
        } else {
            &r.operator
        };
        println!(
            "{}\t{}\t{}\t{}\t{}\t{}",
            r.transaction_id, r.profile, r.subject_cn, r.state, operator, r.created_at
        );
    }
    if requests.is_empty() {
        println!("(aucune demande)");
    }
}

async fn run_decide(
    action_name: &str,
    transaction_id: String,
    operator: String,
    comment: Vec<String>,
) {
    tracing_subscriber::fmt::init();
    let cfg = Config::load_without_hsm().unwrap_or_else(|e| die("configuration invalide", &e));
    let store: Arc<dyn oe_castore::Store> = Arc::new(open_store(&cfg).await);
    let recorder: Arc<dyn oe_raflow::Recorder> = Arc::new(open_recorder(&cfg));
    let decider = oe_raflow::Decider::new(oe_raflow::DeciderOptions {
        store,
        recorder: Some(recorder),
        clock: None,
    });

    let comment = join_comment(&comment);
    let r = if action_name == "approve" {
        decider.approve(&transaction_id, &operator, &comment).await
    } else {
        decider.reject(&transaction_id, &operator, &comment).await
    };
    let r = r.unwrap_or_else(|e| die("décision RA", e));
    tracing::info!(action = action_name, transaction = %r.transaction_id, profil = %r.profile, sujet_cn = %r.subject_cn, operateur = %operator, "décision enregistrée");
}

async fn run_revoke(serial_hex: String, reason: i32, operator: String, comment: Vec<String>) {
    tracing_subscriber::fmt::init();
    let cfg = Config::load().unwrap_or_else(|e| die("configuration invalide", &e));
    let serial = hex::decode(serial_hex.trim_start_matches("0x"))
        .unwrap_or_else(|e| die("numéro de série illisible", e));

    let store: Arc<dyn oe_castore::Store> = Arc::new(open_store(&cfg).await);
    let recorder: Arc<dyn oe_ca_core::Recorder> = Arc::new(open_recorder(&cfg));
    let issuer = build_issuer(&cfg, store, recorder).await;

    let comment = join_comment(&comment);
    issuer
        .revoke(&serial, reason, &operator, &comment)
        .await
        .unwrap_or_else(|e| die("révocation", e));
    // La CRL est republiée immédiatement : une révocation qui n'est pas
    // publiée ne protège personne.
    let crl = issuer
        .publish_crl()
        .await
        .unwrap_or_else(|e| die("publication de la CRL", e));
    tracing::info!(serie = %hex::encode(&serial), motif = reason, operateur = %operator, crl = crl.number, "certificat révoqué et CRL republiée");
}

async fn run_operators_bootstrap_admin(name: String, ttl_minutes: i64) {
    // Journaux sur la sortie d'erreur : la sortie standard ne porte que le
    // jeton, que l'opérateur capture (`TOKEN=$(ca-server operators ...)`). Une
    // ligne de journal devant lui serait capturée avec.
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .init();
    let cfg = Config::load_without_hsm().unwrap_or_else(|e| die("configuration invalide", &e));
    // Ouvre le magasin de la CA pour appliquer les migrations, comme `serve`.
    let _ = open_store(&cfg).await;
    let registry = oe_actions::Registry::connect(&cfg.dsn)
        .await
        .unwrap_or_else(|e| die("ouverture du registre des opérateurs", e));
    let recorder = open_recorder(&cfg);

    let invite = oe_actions::bootstrap_admin(
        &registry,
        &recorder,
        &name,
        time::Duration::minutes(ttl_minutes),
        time::OffsetDateTime::now_utc(),
    )
    .await
    .unwrap_or_else(|e| die("amorçage du premier administrateur", e));

    let expires = invite
        .expires_at
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default();
    eprintln!("Invitation créée pour l'administrateur {name:?}, valable jusqu'à {expires}.");
    eprintln!(
        "Le jeton ci-dessous n'est affiché qu'une seule fois : il n'est conservé nulle part."
    );
    println!("{}", invite.token);
}

async fn run_internal_cert_server(dns: String) {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .init();
    let cfg = Config::load().unwrap_or_else(|e| die("configuration invalide", &e));
    if cfg.internal_tls_cert_file.is_empty() || cfg.internal_tls_key_file.is_empty() {
        die(
            "configuration invalide",
            "OPENEIDAS_INTERNAL_TLS_CERT_FILE et OPENEIDAS_INTERNAL_TLS_KEY_FILE sont obligatoires",
        );
    }
    let profile = oe_ca_core::profile::internal_server();
    if let Err(e) = profile.validate_cn(&dns) {
        die("nom DNS", e);
    }

    let key = oe_enroll::software_key::load_or_create_key(std::path::Path::new(
        &cfg.internal_tls_key_file,
    ))
    .unwrap_or_else(|e| die("clé du serveur interne", e));
    let (csr_der, _) = oe_enroll::build_csr(&key, &oe_enroll::Subject { common_name: dns })
        .unwrap_or_else(|e| die("demande de certificat", e));

    let store: Arc<dyn oe_castore::Store> = Arc::new(open_store(&cfg).await);
    let audit = open_recorder(&cfg);
    let issuer = Arc::new(build_issuer(&cfg, store.clone(), Arc::new(audit.clone())).await);
    let flow = build_flow(&cfg, store, issuer, Arc::new(audit));
    let result = flow
        .submit(
            &csr_der,
            oe_ca_core::profile::PROFILE_INTERNAL_SERVER,
            &oe_raflow::signature(&csr_der, &cfg.enroll_hmac_key),
        )
        .await
        .unwrap_or_else(|e| die("dépôt de la demande", e));

    match result.certificate {
        Some(cert) => {
            use der::EncodePem;
            let pem = cert
                .to_pem(der::pem::LineEnding::LF)
                .unwrap_or_else(|e| die("encodage du certificat", e));
            oe_enroll::software_key::write_certificate(
                std::path::Path::new(&cfg.internal_tls_cert_file),
                &pem,
            )
            .unwrap_or_else(|e| die("écriture du certificat", e));
            // Rien de `result` n'est affiché : c'est une valeur qui porte le certificat,
            // et l'analyse de flux de données la traite comme sensible même pour un
            // champ public (l'identifiant de demande). Le chemin, lui, vient de la
            // configuration.
            eprintln!(
                "Certificat émis, écrit dans {}.",
                cfg.internal_tls_cert_file
            );
        }
        None => {
            eprintln!(
                "Demande déposée, en attente d'approbation. Un opérateur la retrouve avec \
                 `ca-server ra list PENDING` et l'approuve avec `ca-server ra approve`, \
                 puis relancez cette commande."
            );
            std::process::exit(3);
        }
    }
}

async fn run_operators_reconcile(
    reason: String,
    acknowledge_missing: Vec<String>,
    dry_run: bool,
    journal: Option<String>,
) {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .init();
    let cfg = Config::load_without_hsm().unwrap_or_else(|e| die("configuration invalide", &e));
    let _ = open_store(&cfg).await;
    let registry = oe_actions::Registry::connect(&cfg.dsn)
        .await
        .unwrap_or_else(|e| die("ouverture du registre des opérateurs", e));
    let path = journal.unwrap_or_else(|| cfg.audit_file.clone());
    let events = registry_check::journal_events(&path).unwrap_or_else(|e| {
        eprintln!("{e}");
        eprintln!("Rien n'est résolu contre un journal dont l'intégrité n'est pas garantie.");
        std::process::exit(2);
    });
    // Les résolutions s'écrivent dans le même journal que celui qu'on a relu.
    let recorder = open_recorder(&cfg);

    let outcome = oe_actions::reconcile(
        &registry,
        &recorder,
        &oe_actions::Replay::from_events(events),
        &reason,
        &acknowledge_missing,
        dry_run,
        time::OffsetDateTime::now_utc(),
    )
    .await
    .unwrap_or_else(|e| die("résolution des divergences", e));

    for line in &outcome.resolved {
        println!("OK\t{line}");
    }
    for d in &outcome.unresolved {
        println!("KO\t{d}");
    }
    eprintln!(
        "{} résolue(s), {} en suspens.{}",
        outcome.resolved.len(),
        outcome.unresolved.len(),
        if dry_run {
            " (essai à blanc : rien n'a été modifié)"
        } else {
            ""
        }
    );
    if !outcome.unresolved.is_empty() {
        eprintln!(
            "Une clé perdue se ré-enrôle (invitation) ; `--acknowledge-missing <clé> --reason …` \
             en prend acte au journal."
        );
        std::process::exit(1);
    }
    if !dry_run {
        eprintln!("Les actions reprennent au prochain contrôle du registre (OPENEIDAS_REGISTRY_CHECK_INTERVAL) ou au redémarrage.");
    }
}

async fn run_operators_audit(journal: Option<String>) {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .init();
    let cfg = Config::load_without_hsm().unwrap_or_else(|e| die("configuration invalide", &e));
    let _ = open_store(&cfg).await;
    let registry = oe_actions::Registry::connect(&cfg.dsn)
        .await
        .unwrap_or_else(|e| die("ouverture du registre des opérateurs", e));

    let path = journal.unwrap_or_else(|| cfg.audit_file.clone());
    let records = match oe_audit::read(&path) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("journal illisible ou rompu ({path}) : {e}");
            eprintln!(
                "Le registre n'est pas jugé contre un journal dont l'intégrité n'est pas garantie."
            );
            std::process::exit(2);
        }
    };
    let view = oe_actions::JournalView::from_events(records.into_iter().filter_map(|r| {
        r.data
            .map(|d| (r.event, serde_json::Value::Object(d.into_iter().collect())))
    }));
    let report = oe_actions::audit_registry(&registry, &view)
        .await
        .unwrap_or_else(|e| die("audit du registre", e));

    for k in &report.keys {
        let short: String = k.credential_id.chars().take(16).collect();
        match &k.verdict {
            Ok(oe_actions::Verdict::Anchor) => {
                println!("OK\t{}\t{short}\tancre (journal)", k.operator)
            }
            Ok(oe_actions::Verdict::Chained { depth }) => {
                println!(
                    "OK\t{}\t{short}\tchaîne signée, profondeur {depth}",
                    k.operator
                )
            }
            Err(why) => println!("KO\t{}\t{short}\t{why}", k.operator),
        }
    }
    let findings = report.findings().len();
    eprintln!(
        "{} clé(s) active(s) auditée(s), {findings} constat(s).",
        report.keys.len()
    );
    if findings > 0 {
        std::process::exit(1);
    }
}

/// Preuve de garde de l'hôte : le PIN présenté doit ouvrir le token de la CA
/// émettrice. La valeur de `OPENEIDAS_ISSUING_PIN` du service n'est volontairement
/// pas comparée : elle est lisible de tout accès shell, alors que le PIN est ce que
/// détiennent les personnes habilitées.
fn verify_token_pin(cfg: &Config, pin: &str) -> Result<(), String> {
    oe_hsm::Pkcs11Token::open(&oe_hsm::Options {
        module_path: cfg.pkcs11_module.clone(),
        token_label: cfg.issuing_token_label.clone(),
        key_label: cfg.issuing_key_label.clone(),
        pin: pin.to_string(),
    })
    .map(|_| ())
    .map_err(|e| e.to_string())
}

async fn run_operators_recover_admin(
    name: String,
    reason: String,
    confirm_recovery: bool,
    ttl_minutes: i64,
) {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .init();
    if !confirm_recovery {
        die(
            "récupération",
            "confirmation absente : ajoutez --confirm-recovery pour indiquer que vous savez \
             que cette commande contourne le refus de `bootstrap-admin`",
        );
    }
    if reason.trim().is_empty() {
        die("récupération", "un motif écrit (--reason) est obligatoire");
    }
    // Le PIN vient de l'entrée standard, avant toute autre chose : une commande
    // lancée sans lui n'ouvre ni la base ni le journal.
    let mut pin = String::new();
    std::io::stdin()
        .read_line(&mut pin)
        .unwrap_or_else(|e| die("lecture du PIN sur l'entrée standard", e));
    let pin = pin.trim_end_matches(['\r', '\n']).to_string();
    if pin.is_empty() {
        die("récupération", "aucun PIN reçu sur l'entrée standard");
    }

    let cfg = Config::load_without_hsm().unwrap_or_else(|e| die("configuration invalide", &e));
    let _ = open_store(&cfg).await;
    let registry = oe_actions::Registry::connect(&cfg.dsn)
        .await
        .unwrap_or_else(|e| die("ouverture du registre des opérateurs", e));
    let recorder = open_recorder(&cfg);

    if let Err(e) = verify_token_pin(&cfg, &pin) {
        // Un refus est aussi un événement : quelqu'un a essayé. Best-effort :
        // le refus lui-même (et le processus se termine juste après) n'attend
        // pas le journal.
        let _ = oe_raflow::Recorder::append(
            &recorder,
            "operators.admin_recovery_refused",
            serde_json::json!({ "nom": name, "motif_du_refus": "PIN du token refusé" }),
        )
        .await;
        // Le détail de l'erreur PKCS#11 ne va pas à l'écran : il n'apprend rien
        // à celui qui a la garde du PIN, et beaucoup à celui qui l'essaie.
        tracing::debug!(erreur = %e, "PIN refusé");
        die(
            "récupération",
            "le PIN présenté n'ouvre pas le token de la CA émettrice",
        );
    }

    let invite = oe_actions::recover_admin(
        &registry,
        &recorder,
        &name,
        &reason,
        time::Duration::minutes(ttl_minutes),
        time::OffsetDateTime::now_utc(),
    )
    .await
    .unwrap_or_else(|e| die("récupération de l'administrateur", e));

    let expires = invite
        .expires_at
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default();
    eprintln!("Invitation de récupération créée pour l'administrateur {name:?}, valable jusqu'à {expires}.");
    eprintln!(
        "Le jeton ci-dessous n'est affiché qu'une seule fois : il n'est conservé nulle part."
    );
    eprintln!("Événement consigné au journal : operators.admin_recovery.");
    println!("{}", invite.token);
}

async fn run_healthcheck() {
    let listen = std::env::var("OPENEIDAS_LISTEN")
        .ok()
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| ":8320".to_string());
    let addr = if let Some(port) = listen.strip_prefix(':') {
        format!("127.0.0.1:{port}")
    } else {
        listen
    };
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .unwrap_or_else(|e| die("client HTTP", e));
    let resp = client
        .get(format!("http://{addr}/healthz"))
        .send()
        .await
        .unwrap_or_else(|e| die("requête", e));
    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();
    if !status.is_success() {
        die(
            "service non disponible",
            format!("({status}): {}", body.trim()),
        );
    }
    println!("{}", body.trim());
}

async fn run_verify_audit(path: Option<String>) {
    let path = path
        .or_else(|| std::env::var("OPENEIDAS_AUDIT_FILE").ok())
        .filter(|p| !p.is_empty())
        .unwrap_or_else(|| "/var/lib/open-eidas/state/ca-audit.log".to_string());
    let report = oe_audit::verify(&path).unwrap_or_else(|e| die("journal d'audit", e));
    println!("journal          : {path}");
    println!(
        "enregistrements  : {} (n° {} à {})",
        report.records, report.first, report.last
    );
    println!("scellements      : {}", report.seals);
    println!("tête de chaîne   : {}", report.head);
    println!("chaîne de hachage continue et intègre");
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    match cli.command {
        Command::Ceremony => run_ceremony().await,
        Command::Serve => run_serve().await,
        Command::Ra { action } => match action {
            RaAction::List { state } => run_ra_list(state).await,
            RaAction::Approve {
                transaction_id,
                operator,
                comment,
            } => run_decide("approve", transaction_id, operator, comment).await,
            RaAction::Reject {
                transaction_id,
                operator,
                comment,
            } => run_decide("reject", transaction_id, operator, comment).await,
        },
        Command::Revoke {
            serial_hex,
            reason,
            operator,
            comment,
        } => run_revoke(serial_hex, reason, operator, comment).await,
        Command::Operators { action } => match action {
            OperatorsAction::BootstrapAdmin { name, ttl_minutes } => {
                run_operators_bootstrap_admin(name, ttl_minutes).await
            }
            OperatorsAction::Audit { journal } => run_operators_audit(journal).await,
            OperatorsAction::Reconcile {
                reason,
                acknowledge_missing,
                dry_run,
                journal,
            } => run_operators_reconcile(reason, acknowledge_missing, dry_run, journal).await,
            OperatorsAction::RecoverAdmin {
                name,
                reason,
                confirm_recovery,
                pin_stdin: _,
                ttl_minutes,
            } => run_operators_recover_admin(name, reason, confirm_recovery, ttl_minutes).await,
        },
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
        Command::Healthcheck => run_healthcheck().await,
        Command::Version => println!("{}", env!("CARGO_PKG_VERSION")),
        Command::InternalCert {
            action: InternalCertAction::Server { dns },
        } => run_internal_cert_server(dns).await,
        Command::VerifyAudit { path } => run_verify_audit(path).await,
    }
}
