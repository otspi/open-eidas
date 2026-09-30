//! API HTTP de la CA — portage de `cmd/ca-server/server.go`.
//!
//! Les chemins de publication (`/download/<CN>.cer` et `.crl`) sont
//! exactement ceux qu'OpenXPKI servait auparavant : les URL déjà gravées
//! dans les extensions CDP/AIA des certificats émis restent valables, et le
//! répondeur OCSP retrouve la CRL au même endroit.
//!
//! Constat C-1 : le certificat de la racine et son ARL sont servis de la même
//! façon (`/download/<CN racine>.cer` et `.arl`), aux adresses que gravent
//! l'AIA et le CDP de l'émettrice. L'ARL est publiée hors ligne
//! (`ca-server ceremony`, `ca-server authority`) : ce service ne fait que la
//! relire, il n'a jamais la clé de la racine.

use std::sync::{Arc, RwLock};

use axum::extract::{DefaultBodyLimit, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use der::Encode;
use serde::{Deserialize, Serialize};

struct CrlCache {
    crl: Option<oe_castore::Crl>,
    err: Option<String>,
}

struct RootPublication {
    der: Vec<u8>,
    cer_path: String,
    arl_path: String,
}

pub struct Server {
    issuer: Arc<oe_ca_core::Issuer>,
    flow: Arc<oe_raflow::Flow>,
    version: String,
    ca_der: Vec<u8>,
    ca_pem: String,
    crl_path: String,
    ca_path: String,
    /// Certificat (DER) de la racine et chemins de son `.cer`/`.arl` — absents
    /// si l'émettrice est construite sans sa chaîne.
    root: Option<RootPublication>,
    cache: RwLock<CrlCache>,
    /// Page HTML publique du dépôt (subjects, validités, empreintes des
    /// certificats réellement chargés) : générée une fois au démarrage,
    /// jamais reconstruite par requête — son contenu ne change qu'au
    /// redémarrage du service.
    repository_html: String,
    /// Fermée quand le registre des opérateurs diverge du journal (§21).
    registry_guard: Option<Arc<oe_actions::RegistryGuard>>,
    /// Voir `Config::ra_auto_approve`.
    ra_auto_approve: bool,
}

impl Server {
    pub fn new(
        issuer: Arc<oe_ca_core::Issuer>,
        flow: Arc<oe_raflow::Flow>,
        version: String,
    ) -> Server {
        let name = oe_certs::file_name(&common_name(issuer.certificate()));
        let ca_der = issuer.certificate().to_der().unwrap_or_default();
        let mut ca_pem = String::new();
        for c in issuer.full_chain() {
            if let Ok(der) = c.to_der() {
                ca_pem.push_str(&pem_block("CERTIFICATE", &der));
            }
        }
        let ca_path = format!("/download/{name}.cer");
        let crl_path = format!("/download/{name}.crl");
        let repository_html = render_repository_html(&issuer, &ca_path, &crl_path);
        let root = issuer.chain().last().map(|root| {
            let name = oe_certs::file_name(&common_name(root));
            RootPublication {
                der: root.to_der().unwrap_or_default(),
                cer_path: format!("/download/{name}.cer"),
                arl_path: format!("/download/{name}.arl"),
            }
        });
        Server {
            issuer,
            flow,
            version,
            ca_der,
            ca_pem,
            crl_path,
            ca_path,
            root,
            cache: RwLock::new(CrlCache {
                crl: None,
                err: None,
            }),
            repository_html,
            registry_guard: None,
            ra_auto_approve: false,
        }
    }

    /// Fait dépendre `/healthz` de la garde du registre : un registre qui diverge
    /// du journal met le service en 503, avec le détail.
    pub fn with_registry_guard(mut self, guard: Arc<oe_actions::RegistryGuard>) -> Server {
        self.registry_guard = Some(guard);
        self
    }

    /// Déclare, dans `/healthz`, que les demandes sont approuvées par un
    /// conteneur technique (constat R-2) : un auditeur le voit sans avoir à
    /// relire les valeurs du déploiement. N'en dégrade pas le statut : c'est
    /// un mode de démonstration assumé, pas une panne.
    pub fn with_ra_auto_approve(mut self, enabled: bool) -> Server {
        self.ra_auto_approve = enabled;
        self
    }

    pub fn issuer(&self) -> &oe_ca_core::Issuer {
        &self.issuer
    }

    /// Publie une CRL immédiatement puis à intervalle régulier, jusqu'à
    /// annulation du token. La première publication est bloquante : le
    /// service ne doit pas se déclarer prêt sans état de révocation
    /// servable.
    pub async fn start_crl_publication(
        self: &Arc<Self>,
        every: std::time::Duration,
        mut shutdown: tokio::sync::watch::Receiver<bool>,
    ) -> Result<(), String> {
        self.publish_crl()
            .await
            .map_err(|e| format!("publication initiale de la CRL: {e}"))?;
        let server = self.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(every);
            ticker.tick().await;
            loop {
                tokio::select! {
                    _ = ticker.tick() => {
                        if let Err(e) = server.publish_crl().await {
                            // L'ancienne CRL reste servie : elle est encore
                            // valide jusqu'à son nextUpdate, et /healthz
                            // bascule en dégradé dès qu'elle ne l'est plus.
                            tracing::error!(erreur = %e, "publication de la CRL impossible, conservation de la précédente");
                        }
                    }
                    _ = shutdown.changed() => return,
                }
            }
        });
        Ok(())
    }

    async fn publish_crl(&self) -> Result<(), String> {
        match self.issuer.publish_crl().await {
            Ok(crl) => {
                tracing::info!(numero = crl.number, next_update = %crl.next_update, "CRL publiée");
                let mut cache = self.cache.write().unwrap();
                cache.crl = Some(crl);
                cache.err = None;
                Ok(())
            }
            Err(e) => {
                self.cache.write().unwrap().err = Some(e.to_string());
                Err(e.to_string())
            }
        }
    }

    /// Relit le registre plutôt que le seul cache mémoire : une révocation
    /// décidée par une commande d'exploitation (`ca-server revoke`) publie
    /// une nouvelle CRL depuis un AUTRE processus, et une révocation qui
    /// n'est pas servie ne protège personne. Le cache ne sert que de repli
    /// si le registre est momentanément injoignable.
    async fn current_crl(&self) -> Result<oe_castore::Crl, String> {
        match self.issuer.current_crl().await {
            Ok(latest) => {
                let mut cache = self.cache.write().unwrap();
                if cache.crl.as_ref().is_none_or(|c| latest.number > c.number) {
                    cache.crl = Some(latest.clone());
                }
                Ok(latest)
            }
            Err(e) => {
                let cached = self.cache.read().unwrap().crl.clone();
                match cached {
                    Some(c) => {
                        tracing::warn!(erreur = %e, numero = c.number, "registre injoignable, CRL servie depuis le cache");
                        Ok(c)
                    }
                    None => Err(e.to_string()),
                }
            }
        }
    }
}

fn sha256_fingerprint(der: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(der)
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(":")
}

fn x509_time_to_offset(t: &x509_cert::time::Time) -> time::OffsetDateTime {
    let secs = t.to_date_time().unix_duration().as_secs();
    time::OffsetDateTime::from_unix_timestamp(secs as i64)
        .unwrap_or(time::OffsetDateTime::UNIX_EPOCH)
}

fn format_time(t: &x509_cert::time::Time) -> String {
    x509_time_to_offset(t)
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default()
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// Page HTML publique du dépôt de l'autorité : subject, validité et
/// empreinte SHA-256 de chaque certificat de `full_chain()` (l'autorité
/// émettrice, celle qui a réellement produit les certificats servis, puis
/// sa racine), sans rien affirmer de plus que ce que ces certificats
/// contiennent déjà — aucune mention de statut « staging » codée en dur
/// ici : c'est le Subject réel des certificats chargés qui en fait foi.
fn render_repository_html(issuer: &oe_ca_core::Issuer, ca_path: &str, crl_path: &str) -> String {
    let mut certs_html = String::new();
    for (i, cert) in issuer.full_chain().iter().enumerate() {
        let role = if i == 0 {
            "Autorité émettrice (signe les certificats publiés par ce service)"
        } else {
            "Autorité racine"
        };
        let der = cert.to_der().unwrap_or_default();
        certs_html.push_str(&format!(
            r#"<section class="cert">
  <h2>{role}</h2>
  <dl>
    <dt>Sujet</dt><dd>{subject}</dd>
    <dt>Émetteur</dt><dd>{issuer_dn}</dd>
    <dt>Numéro de série</dt><dd><code>{serial}</code></dd>
    <dt>Validité</dt><dd>{not_before} → {not_after}</dd>
    <dt>Empreinte SHA-256</dt><dd><code>{fingerprint}</code></dd>
  </dl>
</section>
"#,
            role = role,
            subject = html_escape(&cert.tbs_certificate().subject().to_string()),
            issuer_dn = html_escape(&cert.tbs_certificate().issuer().to_string()),
            serial = hex::encode_upper(cert.tbs_certificate().serial_number().as_bytes()),
            not_before = format_time(&cert.tbs_certificate().validity().not_before),
            not_after = format_time(&cert.tbs_certificate().validity().not_after),
            fingerprint = sha256_fingerprint(&der),
        ));
    }

    format!(
        r#"<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Dépôt de l'autorité de certification</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
          max-width: 720px; margin: 2rem auto; padding: 0 1.25rem; line-height: 1.5; color: #0f172a; }}
  h1 {{ font-size: 1.4rem; }}
  section.cert {{ border: 1px solid #e2e8f0; border-radius: 8px; padding: 1rem 1.25rem; margin: 1rem 0; }}
  dl {{ display: grid; grid-template-columns: auto 1fr; gap: 0.35rem 1rem; margin: 0; }}
  dt {{ color: #64748b; }}
  dd {{ margin: 0; word-break: break-all; }}
  code {{ background: #f8fafc; padding: 0.1rem 0.35rem; border-radius: 4px; }}
  ul {{ padding-left: 1.25rem; }}
  .warn {{ background: #fffbeb; border-left: 4px solid #b45309; padding: 0.75rem 1rem; border-radius: 6px; font-size: 0.9rem; }}
</style>
</head>
<body>
  <h1>Dépôt public de l'autorité de certification</h1>
  <p class="warn">
    Vérifiez le <strong>Sujet</strong> de chaque certificat ci-dessous avant de lui
    faire confiance : son nom identifie sans ambiguïté l'environnement qui l'a émis
    (production certifiée, ou un environnement de test/démonstration).
  </p>
  {certs_html}
  <h2>Téléchargements</h2>
  <ul>
    <li><a href="{ca_path}">Certificat de l'autorité émettrice (DER)</a></li>
    <li><a href="{crl_path}">Liste de révocation (CRL)</a></li>
    <li><a href="/api/v1/ca.pem">Chaîne complète (PEM)</a></li>
    <li><a href="/api/v1/conformance">Matrice de conformité ETSI</a></li>
  </ul>
</body>
</html>
"#,
        certs_html = certs_html,
        ca_path = ca_path,
        crl_path = crl_path,
    )
}

fn common_name(cert: &x509_cert::Certificate) -> String {
    const OID_CN: &str = "2.5.4.3";
    let cn_oid = der::asn1::ObjectIdentifier::new(OID_CN).expect("OID constant invalide");
    cert.tbs_certificate()
        .subject()
        .iter()
        .find(|atv| atv.oid == cn_oid)
        .map(|atv| String::from_utf8_lossy(atv.value.value()).into_owned())
        .unwrap_or_default()
}

fn pem_block(label: &str, der: &[u8]) -> String {
    use base64::Engine;
    let b64 = base64::engine::general_purpose::STANDARD.encode(der);
    let mut out = format!("-----BEGIN {label}-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).unwrap());
        out.push('\n');
    }
    out.push_str(&format!("-----END {label}-----\n"));
    out
}

pub fn router(server: Arc<Server>, max_request_bytes: usize) -> Router {
    let ca_path = server.ca_path.clone();
    let crl_path = server.crl_path.clone();
    let root_paths = server
        .root
        .as_ref()
        .map(|r| (r.cer_path.clone(), r.arl_path.clone()));
    let mut router = Router::new()
        .route("/", get(handle_repository))
        .route("/api/v1/enroll", axum::routing::post(handle_enroll))
        .route("/api/v1/ca.pem", get(handle_ca_pem))
        .route("/api/v1/conformance", get(handle_conformance))
        .route(&ca_path, get(handle_ca_der))
        .route(&crl_path, get(handle_crl))
        .route("/healthz", get(handle_health));
    if let Some((cer_path, arl_path)) = root_paths {
        router = router
            .route(&cer_path, get(handle_root_der))
            .route(&arl_path, get(handle_arl));
    }
    router
        .layer(DefaultBodyLimit::max(max_request_bytes))
        .with_state(server)
}

/// Le protocole est défini par ce dépôt : la CSR est transmise en PEM, la
/// signature est le HMAC-SHA256 hexadécimal de ses octets DER (voir
/// `oe_raflow::signature`).
#[derive(Deserialize)]
struct EnrollRequest {
    profile: String,
    pkcs10: String,
    signature: String,
}

#[derive(Serialize)]
struct EnrollResponse {
    state: String,
    transaction_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    retry_after: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    certificate: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    chain: Vec<String>,
}

fn error_response(status: StatusCode, message: impl Into<String>) -> Response {
    (status, Json(serde_json::json!({ "error": message.into() }))).into_response()
}

/// Accepte la CSR en PEM ou en base64 de son DER : le premier est ce que
/// produisent les outils courants, le second évite aux clients JSON de
/// transporter des sauts de ligne.
fn decode_csr(raw: &str) -> Result<Vec<u8>, String> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Err("champ pkcs10 vide".to_string());
    }
    if raw.starts_with("-----BEGIN") {
        let (label, doc) =
            der::Document::from_pem(raw).map_err(|e| format!("bloc PEM illisible: {e}"))?;
        if label != "CERTIFICATE REQUEST" {
            return Err(format!(
                "bloc PEM de type {label:?}, attendu CERTIFICATE REQUEST"
            ));
        }
        return Ok(doc.into_vec());
    }
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(raw)
        .map_err(|_| "champ pkcs10 : ni PEM ni base64 exploitable".to_string())
}

async fn handle_enroll(
    State(server): State<Arc<Server>>,
    Json(req): Json<EnrollRequest>,
) -> Response {
    let csr_der = match decode_csr(&req.pkcs10) {
        Ok(der) => der,
        Err(e) => return error_response(StatusCode::BAD_REQUEST, e),
    };

    let result = match server
        .flow
        .submit(&csr_der, &req.profile, &req.signature)
        .await
    {
        Ok(r) => r,
        // Volontairement laconique : distinguer « secret faux » de « CSR
        // invalide » renseignerait un attaquant sur ce qu'il doit corriger.
        Err(oe_raflow::RaflowError::Unauthenticated) => {
            return error_response(StatusCode::UNAUTHORIZED, "demande non authentifiée")
        }
        Err(e @ oe_raflow::RaflowError::Rejected { .. }) => {
            return error_response(StatusCode::FORBIDDEN, e.to_string())
        }
        Err(e) => {
            tracing::warn!(erreur = %e, "enrôlement refusé");
            return error_response(StatusCode::BAD_REQUEST, e.to_string());
        }
    };

    let mut resp = EnrollResponse {
        state: request_state_str(result.state).to_string(),
        transaction_id: result.transaction_id,
        retry_after: None,
        certificate: None,
        chain: vec![],
    };
    let status = if result.state == oe_castore::RequestState::Pending {
        // 202 Accepted : la demande est enregistrée, la décision appartient
        // à un opérateur RA. Le client reviendra.
        resp.retry_after = result.retry_after.map(|d| d.whole_seconds());
        StatusCode::ACCEPTED
    } else {
        if let Some(cert) = &result.certificate {
            resp.certificate = cert.to_der().ok().map(|der| pem_block("CERTIFICATE", &der));
        }
        resp.chain = result
            .chain
            .iter()
            .filter_map(|c| c.to_der().ok())
            .map(|der| pem_block("CERTIFICATE", &der))
            .collect();
        StatusCode::OK
    };
    (status, Json(resp)).into_response()
}

fn request_state_str(s: oe_castore::RequestState) -> &'static str {
    match s {
        oe_castore::RequestState::Pending => "PENDING",
        oe_castore::RequestState::Approved => "APPROVED",
        oe_castore::RequestState::Issued => "ISSUED",
        oe_castore::RequestState::Rejected => "REJECTED",
    }
}

/// Dépôt public, lisible par un humain : subject/validité/empreinte de
/// chaque certificat de la hiérarchie, et les liens vers les mêmes
/// ressources que les autres routes servent déjà en brut.
async fn handle_repository(State(server): State<Arc<Server>>) -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        server.repository_html.clone(),
    )
}

async fn handle_ca_pem(State(server): State<Arc<Server>>) -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "application/x-pem-file")],
        server.ca_pem.clone(),
    )
}

/// Sert le certificat de la CA émettrice au format DER, à l'adresse exacte
/// que porte l'extension AIA `ca_issuers` des certificats émis.
async fn handle_ca_der(State(server): State<Arc<Server>>) -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "application/pkix-cert")],
        server.ca_der.clone(),
    )
}

/// Certificat de la racine, à l'adresse que porte l'AIA `caIssuers` de
/// l'émettrice (constat C-1).
async fn handle_root_der(State(server): State<Arc<Server>>) -> Response {
    match &server.root {
        Some(root) => (
            [(header::CONTENT_TYPE, "application/pkix-cert")],
            root.der.clone(),
        )
            .into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

/// ARL de la racine, à l'adresse que porte le CDP de l'émettrice (constat
/// C-1). Relue en base à chaque requête : elle est publiée par un autre
/// processus, hors ligne, et une révocation d'autorité qui n'est pas servie
/// ne protège personne.
async fn handle_arl(State(server): State<Arc<Server>>) -> Response {
    match server.issuer.current_arl().await {
        Ok(arl) => ([(header::CONTENT_TYPE, "application/pkix-crl")], arl.der).into_response(),
        Err(e) => {
            tracing::error!(erreur = %e, "ARL indisponible");
            (StatusCode::SERVICE_UNAVAILABLE, "aucune ARL publiée").into_response()
        }
    }
}

async fn handle_crl(State(server): State<Arc<Server>>) -> Response {
    match server.current_crl().await {
        Ok(crl) => ([(header::CONTENT_TYPE, "application/pkix-crl")], crl.der).into_response(),
        Err(e) => {
            tracing::error!(erreur = %e, "CRL indisponible");
            (StatusCode::SERVICE_UNAVAILABLE, "aucune CRL publiée").into_response()
        }
    }
}

/// Sert la matrice ETSI telle que l'instance qui tourne l'applique : un
/// auditeur peut ainsi comparer le document du dépôt à ce que le service
/// déclare réellement.
async fn handle_conformance(State(server): State<Arc<Server>>) -> impl IntoResponse {
    let matrix = oe_conformance::system_matrix();
    let entries: Vec<_> = matrix
        .0
        .iter()
        .map(|e| {
            serde_json::json!({
                "norme": e.requirement.standard,
                "clause": e.requirement.clause,
                "exigence": e.requirement.title,
                "statut": e.status.label(),
                "mecanisme": e.mechanism,
                "test": e.test,
                "cible": e.target,
            })
        })
        .collect();
    let comptes: serde_json::Map<String, serde_json::Value> = matrix
        .counts()
        .into_iter()
        .map(|(status, n)| (status.label().to_string(), serde_json::Value::from(n)))
        .collect();
    let (coherente, incoherence) = match matrix.validate() {
        Ok(()) => (true, None),
        Err(msg) => (false, Some(msg)),
    };
    Json(serde_json::json!({
        "version": server.version,
        "comptes": comptes,
        "normes": matrix.standards(),
        "exigences": entries,
        "matrice_coherente": coherente,
        "incoherence": incoherence,
    }))
}

/// Bascule en dégradé dès que l'état de révocation n'est plus servable : un
/// service qui ne peut plus dire ce qui est révoqué ne doit pas se déclarer
/// sain (ETSI EN 319 411-1 §6.3.10).
async fn handle_health(State(server): State<Arc<Server>>) -> Response {
    let crl_result = server.current_crl().await;
    let cached_err = server.cache.read().unwrap().err.clone();

    let mut status = StatusCode::OK;
    let mut statut = "ok";
    let mut detail = String::new();
    let mut crl_numero = None;
    let mut crl_next_update = None;

    match &crl_result {
        Err(_) => {
            statut = "degrade";
            detail = "aucune CRL publiée".to_string();
            status = StatusCode::SERVICE_UNAVAILABLE;
        }
        Ok(crl) => {
            if time::OffsetDateTime::now_utc() > crl.next_update {
                statut = "degrade";
                detail = format!("la CRL publiée est périmée depuis le {}", crl.next_update);
                status = StatusCode::SERVICE_UNAVAILABLE;
            }
            crl_numero = Some(crl.number);
            crl_next_update = Some(crl.next_update.to_string());
        }
    }
    if detail.is_empty() {
        if let Some(err) = cached_err {
            detail = format!("dernière publication en échec : {err}");
        }
    }
    // Un registre qui diverge du journal n'exécute aucune action : c'est visible ici.
    let registry_blocked = server.registry_guard.as_ref().and_then(|g| g.blocked());
    if let Some(reasons) = &registry_blocked {
        statut = "degrade";
        status = StatusCode::SERVICE_UNAVAILABLE;
        let text = format!("registre des opérateurs bloqué : {}", reasons.join(" ; "));
        detail = if detail.is_empty() {
            text
        } else {
            format!("{detail} ; {text}")
        };
    }

    let body = serde_json::json!({
        "statut": statut,
        "version": server.version,
        "emettrice": server.issuer.certificate().tbs_certificate().subject().to_string(),
        "crl_numero": crl_numero,
        "crl_next_update": crl_next_update,
        "detail": if detail.is_empty() { None } else { Some(detail) },
        "registre_bloque": registry_blocked,
        "approbation_automatique": server.ra_auto_approve,
    });
    (status, Json(body)).into_response()
}
