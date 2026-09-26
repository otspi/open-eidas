//! Portage Rust de `cmd/tsa-server/main.go`. Les cinq sous-commandes
//! (`serve`, `enroll`, `verify-audit`, `conformance`, `version`, cette
//! dernière fournie par clap) sont opérationnelles depuis le jalon J9 du
//! plan de migration (voir /home/philippe/.claude/plans/witty-hopping-nest.md).

use std::sync::Arc;

use clap::{Parser, Subcommand};
use der::Encode;
use oe_hsm::SigningToken;

#[derive(Parser)]
#[command(
    name = "tsa-server",
    version,
    about = "Time-Stamping Authority RFC 3161 (open-eidas)"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Démarre le service HTTP d'horodatage.
    Serve,
    /// Obtient ou renouvelle le certificat de la TSU auprès de la CA.
    Enroll,
    /// Vérifie l'intégrité de la chaîne du journal d'audit.
    VerifyAudit {
        /// Chemin du journal (défaut : OPENEIDAS_AUDIT_FILE ou /var/lib/open-eidas/audit.log).
        path: Option<String>,
    },
    /// Affiche la matrice de conformité ETSI.
    Conformance {
        #[arg(long)]
        markdown: bool,
    },
    /// Affiche la version (identique à `--version`, sous forme de
    /// sous-commande — reproduit `cmd/tsa-server` (Go), qui n'a que celle-ci).
    Version,
}

fn die(context: &str, err: impl std::fmt::Display) -> ! {
    eprintln!("tsa-server: {context}: {err}");
    std::process::exit(1);
}

/// `":8318"` (forme conventionnelle de `net.Listen`, Go, pour « toutes les
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
/// (`oe-tsa-core` et `oe-timesource`) — mêmes événements que le service Go,
/// qui partage lui aussi un seul journal chaîné entre ces deux sources.
struct AuditRecorder(Arc<oe_audit::Log>);

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

impl oe_timesource::Recorder for AuditRecorder {
    fn append(&self, event: &str, data: serde_json::Value) -> Result<(), String> {
        self.0
            .append(event, json_to_audit_data(data))
            .map_err(|e| e.to_string())
    }
}

/// Résume l'état de traçabilité de l'heure au moment de l'appel, pour
/// enrichir le journal de `oe-tsa-core` (constat J-3 de l'audit du
/// 2026-09-25, recommandation « état de l'horloge — écart, sources — au
/// moment de l'émission »).
fn describe_clock_status(status: &oe_timesource::Status) -> serde_json::Value {
    let format_time = |t: time::OffsetDateTime| {
        t.format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_default()
    };
    serde_json::json!({
        "politique": status.policy.to_string(),
        "tracable": status.traceable,
        "raison": status.reason,
        "ecart_secondes": status.offset.as_seconds_f64(),
        "etendue_secondes": status.spread.as_seconds_f64(),
        "derniere_synchro": status.last_sync.map(format_time),
        "sources": status.sources.iter().map(|s| serde_json::json!({
            "serveur": s.server,
            "ecart_secondes": s.offset.as_seconds_f64(),
            "aller_retour_secondes": s.rtt.as_seconds_f64(),
            "stratum": s.stratum,
            "a": format_time(s.at),
            "erreur": s.err,
        })).collect::<Vec<_>>(),
    })
}

/// Relie le journal d'`oe-tsa-core` au moniteur NTP : `oe_tsa_core::Recorder`
/// reste délibérément découplé d'`oe-timesource` (voir `MonitorClock`
/// ci-dessous) — c'est ici, où `tsa-server` connaît déjà les deux, que
/// l'état de l'horloge courant est ajouté à chaque événement journalisé,
/// sans que le cœur métier de l'horodatage ait à en savoir quoi que ce soit.
struct TsaAuditRecorder {
    log: Arc<oe_audit::Log>,
    monitor: Arc<oe_timesource::Monitor>,
}

impl oe_tsa_core::Recorder for TsaAuditRecorder {
    fn append(&self, event: &str, data: serde_json::Value) -> Result<(), String> {
        let mut data = data;
        if let serde_json::Value::Object(map) = &mut data {
            map.insert(
                "horloge".to_string(),
                describe_clock_status(&self.monitor.status()),
            );
        }
        self.log
            .append(event, json_to_audit_data(data))
            .map_err(|e| e.to_string())
    }
}

/// Adapte le moniteur NTP au trait `Clock` d'`oe-tsa-core` — ce dernier reste
/// délibérément découplé d'`oe-timesource`, à l'identique du code Go de
/// référence (voir la note de module d'`oe_tsa_core`).
struct MonitorClock(Arc<oe_timesource::Monitor>);

impl oe_tsa_core::Clock for MonitorClock {
    fn now(&self) -> Result<time::OffsetDateTime, String> {
        self.0.now().map_err(|e| e.to_string())
    }
}

fn digest_alg_from_config(d: oe_config::SigningDigest) -> oe_hsm::DigestAlg {
    match d {
        oe_config::SigningDigest::Sha256 => oe_hsm::DigestAlg::Sha256,
        oe_config::SigningDigest::Sha384 => oe_hsm::DigestAlg::Sha384,
        oe_config::SigningDigest::Sha512 => oe_hsm::DigestAlg::Sha512,
    }
}

fn to_time_duration(d: std::time::Duration, fallback: time::Duration) -> time::Duration {
    time::Duration::try_from(d).unwrap_or(fallback)
}

async fn run_serve() {
    tracing_subscriber::fmt::init();

    let cfg = oe_config::Config::load().unwrap_or_else(|e| die("configuration invalide", e));

    let token = oe_hsm::Pkcs11Token::open(&oe_hsm::Options {
        module_path: cfg.pkcs11_module.clone(),
        token_label: cfg.token_label.clone(),
        key_label: cfg.key_label.clone(),
        pin: cfg.pin.clone(),
    })
    .unwrap_or_else(|e| die("ouverture du token PKCS#11", e));
    let signer: Arc<dyn SigningToken + Send + Sync> = Arc::new(oe_hsm::SyncToken::new(token));

    let mut certs =
        oe_certs::load_file(&cfg.cert_file).unwrap_or_else(|e| die("certificat TSU", e));
    if certs.is_empty() {
        die("certificat TSU", "aucun certificat trouvé");
    }
    let certificate = certs.remove(0);
    let chain = oe_certs::load_file_optional(&cfg.chain_file)
        .unwrap_or_else(|e| die("chaîne d'émission", e));

    let log = Arc::new(
        oe_audit::Log::open(&cfg.audit_file).unwrap_or_else(|e| die("journal d'audit", e)),
    );
    let _ = log.append(oe_audit::EVENT_OPENED, None);

    let policy_arcs: Vec<u32> = cfg.policy_oid.iter().map(|&n| n as u32).collect();
    let policy = der::asn1::ObjectIdentifier::from_arcs(policy_arcs)
        .unwrap_or_else(|e| die("OID de politique", e));

    let ts_recorder: Arc<dyn oe_timesource::Recorder> = Arc::new(AuditRecorder(log.clone()));
    let monitor = oe_timesource::Monitor::new(oe_timesource::Options {
        servers: cfg.time_sources.clone(),
        policy: cfg.time_policy,
        max_offset: to_time_duration(cfg.time_max_offset, time::Duration::milliseconds(500)),
        max_age: to_time_duration(cfg.time_max_age, time::Duration::HOUR),
        min_sources: cfg.time_min_sources.max(1) as usize,
        poll_interval: cfg.time_poll,
        timeout: cfg.time_timeout,
        recorder: Some(ts_recorder),
    })
    .unwrap_or_else(|e| die("surveillance de l'heure", e));
    // Conservés pour la durée du process : le thread de sondage s'arrête à l'abandon du drapeau.
    let (_poll_handle, _poll_stop) = monitor.start_background();

    let tsa_recorder: Arc<dyn oe_tsa_core::Recorder> = Arc::new(TsaAuditRecorder {
        log: log.clone(),
        monitor: monitor.clone(),
    });
    let authority = Arc::new(
        oe_tsa_core::Authority::new(oe_tsa_core::Options {
            signer,
            certificate,
            chain,
            policy,
            accuracy: cfg.accuracy,
            signing_digest: digest_alg_from_config(cfg.signing_digest),
            clock: Arc::new(MonitorClock(monitor.clone())),
            recorder: Some(tsa_recorder),
        })
        .unwrap_or_else(|e| die("construction de l'autorité", e)),
    );

    let app = oe_httpapi::router(oe_httpapi::Options {
        authority,
        time_source: monitor,
        max_request_bytes: cfg.max_request_bytes.max(0) as usize,
        version: env!("CARGO_PKG_VERSION").to_string(),
        cors_allowed_origin: cfg.cors_allowed_origin.clone(),
    });

    let listener = tokio::net::TcpListener::bind(bind_addr(&cfg.listen))
        .await
        .unwrap_or_else(|e| die(&format!("écoute sur {}", cfg.listen), e));
    eprintln!("tsa-server: écoute sur {}", cfg.listen);
    if let Err(e) = axum::serve(listener, app).await {
        die("serveur HTTP", e);
    }
}

/// `true` si le certificat en cache correspond déjà à la clé du HSM et n'est
/// pas trop proche de son expiration — reproduit `currentCertUsable` (Go),
/// idempotent : ré-exécuter `enroll` sans besoin ne fait rien.
fn current_cert_usable(cfg: &oe_config::Config, signer: &dyn SigningToken) -> (bool, String) {
    let existing = match oe_certs::load_file_optional(&cfg.cert_file) {
        Ok(certs) if !certs.is_empty() => certs,
        _ => {
            return (
                false,
                "aucun certificat TSU exploitable en cache".to_string(),
            )
        }
    };
    let cert = &existing[0];
    let cert_spki = match cert.tbs_certificate().subject_public_key_info().to_der() {
        Ok(v) => v,
        Err(_) => return (false, "certificat en cache illisible".to_string()),
    };
    let signer_spki = match signer.public_key_der() {
        Ok(v) => v,
        Err(_) => return (false, "clé du HSM illisible".to_string()),
    };
    if cert_spki != signer_spki {
        return (
            false,
            "le certificat en cache ne correspond pas à la clé du HSM".to_string(),
        );
    }
    let not_after = cert.tbs_certificate().validity().not_after.to_date_time();
    let not_after =
        time::OffsetDateTime::from_unix_timestamp(not_after.unix_duration().as_secs() as i64)
            .unwrap_or(time::OffsetDateTime::UNIX_EPOCH);
    let remaining = not_after - time::OffsetDateTime::now_utc();
    let renew_before = to_time_duration(cfg.renew_before, time::Duration::days(30));
    if remaining < renew_before {
        return (false, format!("certificat expirant dans {remaining}"));
    }
    (true, format!("valide jusqu'au {not_after}"))
}

async fn run_enroll() {
    tracing_subscriber::fmt::init();
    let cfg = oe_config::Config::load().unwrap_or_else(|e| die("configuration invalide", e));

    let token = oe_hsm::Pkcs11Token::open(&oe_hsm::Options {
        module_path: cfg.pkcs11_module.clone(),
        token_label: cfg.token_label.clone(),
        key_label: cfg.key_label.clone(),
        pin: cfg.pin.clone(),
    })
    .unwrap_or_else(|e| die("ouverture du token PKCS#11", e));

    if token.public_key_der().is_err() {
        eprintln!(
            "tsa-server: génération de la clé de signature dans le HSM ({} bits, label {:?})",
            cfg.key_bits, cfg.key_label
        );
        token
            .generate_rsa_key(cfg.key_bits.max(0) as u64)
            .unwrap_or_else(|e| die("génération de la bi-clé", e));
    }

    let (usable, reason) = current_cert_usable(&cfg, &token);
    if usable {
        eprintln!("tsa-server: certificat TSU déjà en place, enrôlement ignoré ({reason})");
        return;
    }
    eprintln!("tsa-server: enrôlement nécessaire ({reason})");

    let client = oe_enroll::Client::new(oe_enroll::Options {
        endpoint: cfg.enroll_endpoint.clone(),
        profile: cfg.enroll_profile.clone(),
        hmac_secret: cfg.enroll_hmac_key.clone(),
        ca_file: (!cfg.enroll_ca_file.is_empty()).then(|| cfg.enroll_ca_file.clone()),
        insecure: cfg.enroll_insecure,
        timeout: cfg.enroll_timeout,
        user_agent: Some(format!("open-eidas-tsa/{}", env!("CARGO_PKG_VERSION"))),
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
        .unwrap_or_else(|e| die("écriture du certificat TSU", e));
    if !result.chain.is_empty() {
        oe_certs::write_file(&cfg.chain_file, &result.chain)
            .unwrap_or_else(|e| die("écriture de la chaîne d'émission", e));
    }
    eprintln!(
        "tsa-server: enrôlement terminé, certificat écrit dans {}",
        cfg.cert_file
    );
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    match cli.command {
        Command::Serve => run_serve().await,
        Command::Enroll => run_enroll().await,
        Command::VerifyAudit { path } => {
            let path = path
                .or_else(|| std::env::var("OPENEIDAS_AUDIT_FILE").ok())
                .filter(|p| !p.is_empty())
                .unwrap_or_else(|| "/var/lib/open-eidas/audit.log".to_string());

            let report = oe_audit::verify(&path).unwrap_or_else(|e| die("journal d'audit", e));
            println!("journal      : {path}");
            println!(
                "enregistrements : {} (n° {} à {})",
                report.records, report.first, report.last
            );
            println!("scellements  : {}", report.seals);
            println!("tête de chaîne : {}", report.head);
            println!("chaîne de hachage continue et intègre");
        }
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
            let counts = matrix.counts();
            eprintln!(
                "\n{} exigences : {} couvertes, {} écarts documentés, {} hors périmètre logiciel.",
                matrix.0.len(),
                counts[&oe_conformance::Status::Covered],
                counts[&oe_conformance::Status::Gap],
                counts[&oe_conformance::Status::OutOfScope],
            );
        }
        Command::Version => println!("{}", env!("CARGO_PKG_VERSION")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn describe_clock_status_reports_offset_traceability_and_sources() {
        let status = oe_timesource::Status {
            policy: oe_timesource::Policy::Enforce,
            traceable: true,
            reason: String::new(),
            offset: time::Duration::milliseconds(120),
            spread: time::Duration::milliseconds(5),
            last_sync: None,
            sources: Vec::new(),
        };
        let json = describe_clock_status(&status);
        assert_eq!(json["politique"], "enforce");
        assert_eq!(json["tracable"], true);
        assert!((json["ecart_secondes"].as_f64().unwrap() - 0.12).abs() < 1e-9);
    }

    /// Constat J-3 de l'audit du 2026-09-25 : le journal d'`oe-tsa-core` doit
    /// aussi porter l'état de l'horloge au moment de l'émission — preuve que
    /// le `Recorder` englobant de `tsa-server` l'ajoute réellement, sans que
    /// `oe-tsa-core` ait eu à connaître `oe-timesource` (voir la note de
    /// `TsaAuditRecorder`).
    #[test]
    fn tsa_audit_recorder_journals_the_clock_state_at_the_moment_of_issuance() {
        let dir = std::env::temp_dir().join(format!(
            "tsa-audit-recorder-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("audit.log");
        let log = Arc::new(oe_audit::Log::open(&path).unwrap());
        // Politique désactivée, aucun serveur : l'état est fixé
        // immédiatement, sans sonder de vrai serveur NTP (voir
        // `Monitor::new`).
        let monitor = oe_timesource::Monitor::new(oe_timesource::Options {
            servers: Vec::new(),
            policy: oe_timesource::Policy::Disabled,
            max_offset: time::Duration::milliseconds(500),
            max_age: time::Duration::HOUR,
            min_sources: 1,
            poll_interval: std::time::Duration::from_secs(60),
            timeout: std::time::Duration::from_secs(1),
            recorder: None,
        })
        .unwrap();
        let recorder = TsaAuditRecorder { log, monitor };

        oe_tsa_core::Recorder::append(
            &recorder,
            "timestamp.granted",
            serde_json::json!({ "serial_number": "abcd" }),
        )
        .unwrap();

        let records = oe_audit::read(&path).unwrap();
        assert_eq!(records.len(), 1);
        let horloge = records[0]
            .data
            .as_ref()
            .and_then(|d| d.get("horloge"))
            .expect("le champ horloge est absent du journal");
        assert_eq!(horloge["politique"], "disabled");
        assert_eq!(horloge["tracable"], true);
    }
}
