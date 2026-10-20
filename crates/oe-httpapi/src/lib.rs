//! Portage de `internal/httpapi` : expose l'autorité d'horodatage en HTTP
//! (`axum`) — jalon J7 du plan de migration
//! (`/home/philippe/.claude/plans/witty-hopping-nest.md`).
//!
//! Endpoints, à l'identique du service Go : `POST /tsa` (RFC 3161 binaire),
//! `POST /api/v1/timestamp` (façade JSON de confort), `GET /api/v1/policy`,
//! `GET /api/v1/certificate`, `GET /healthz`.
//!
//! **Nuance importante reproduite du code Go** : un refus protocolaire RFC
//! 3161 (`TsaError::Rejection`) sur `POST /tsa` répond **200 OK** avec une
//! `TimeStampResp` de statut « rejection » — ce n'est pas une erreur de
//! transport, c'est une réponse RFC 3161 valide que le client doit savoir
//! interpréter. Seule une défaillance interne répond 500.

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use der::Encode;
use serde::Serialize;

use oe_hsm::DigestAlg;
use oe_tsa_core::{Authority, FailureInfo, TsaError};

const MIME_QUERY: &str = "application/timestamp-query";
const MIME_REPLY: &str = "application/timestamp-reply";

pub struct Options {
    pub authority: Arc<Authority>,
    pub time_source: Arc<oe_timesource::Monitor>,
    pub max_request_bytes: usize,
    pub version: String,
    /// Origine autorisée en cross-origin (Access-Control-Allow-Origin) pour
    /// les routes de lecture/soumission destinées à un navigateur
    /// (`/api/v1/timestamp`, `/api/v1/certificate`, `/api/v1/policy`).
    /// `None` = pas de couche CORS, comportement par défaut.
    pub cors_allowed_origin: Option<String>,
    /// L'état du scellement et de la copie hors site du journal d'audit,
    /// rendu par `/healthz`. `None` : le service ne scelle pas (tests).
    pub journal: Option<Arc<dyn JournalHealth>>,
}

pub use oe_audit::{JournalHealth, JournalReport};

#[derive(Clone)]
struct AppState {
    authority: Arc<Authority>,
    time_source: Arc<oe_timesource::Monitor>,
    version: Arc<str>,
    journal: Option<Arc<dyn JournalHealth>>,
}

pub fn router(opts: Options) -> Router {
    let state = AppState {
        authority: opts.authority,
        time_source: opts.time_source,
        version: Arc::from(opts.version.as_str()),
        journal: opts.journal,
    };
    let mut router = Router::new()
        .route("/tsa", post(handle_rfc3161))
        .route("/api/v1/timestamp", post(handle_json))
        .route("/api/v1/policy", get(handle_policy))
        .route("/api/v1/certificate", get(handle_certificate))
        .route("/healthz", get(handle_health))
        .layer(DefaultBodyLimit::max(opts.max_request_bytes))
        .layer(tower_http::trace::TraceLayer::new_for_http());
    if let Some(origin) = opts.cors_allowed_origin.as_deref() {
        if let Ok(origin) = axum::http::HeaderValue::from_str(origin) {
            // `allow_origin(HeaderValue)` (AllowOrigin::exact) renverrait cette
            // valeur sur TOUTE requête, quelle que soit son origine réelle —
            // AllowOrigin::list ne la reflète que si l'en-tête Origin de la
            // requête correspond exactement, et l'omet sinon.
            router = router.layer(
                tower_http::cors::CorsLayer::new()
                    .allow_origin(tower_http::cors::AllowOrigin::list([origin]))
                    .allow_methods([axum::http::Method::GET, axum::http::Method::POST])
                    .allow_headers([axum::http::header::CONTENT_TYPE]),
            );
        }
    }
    router.with_state(state)
}

async fn handle_rfc3161(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if let Some(ct) = content_type(&headers) {
        if ct != MIME_QUERY && ct != "application/octet-stream" {
            return timestamp_rejection_response(FailureInfo::BadRequest, StatusCode::OK);
        }
    }
    if body.is_empty() {
        return timestamp_rejection_response(FailureInfo::BadDataFormat, StatusCode::OK);
    }

    match state.authority.timestamp(&body) {
        Ok(resp_der) => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, MIME_REPLY)],
            resp_der,
        )
            .into_response(),
        Err(TsaError::Rejection(r)) => timestamp_rejection_response(r.failure, StatusCode::OK),
        Err(_) => timestamp_rejection_response(
            FailureInfo::SystemFailure,
            StatusCode::INTERNAL_SERVER_ERROR,
        ),
    }
}

fn timestamp_rejection_response(failure: FailureInfo, code: StatusCode) -> Response {
    match oe_tsa_core::error_response(failure) {
        Ok(der) => (code, [(header::CONTENT_TYPE, MIME_REPLY)], der).into_response(),
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response(),
    }
}

fn content_type(headers: &HeaderMap) -> Option<String> {
    let raw = headers.get(header::CONTENT_TYPE)?.to_str().ok()?;
    let ct = raw.split(';').next().unwrap_or(raw).trim().to_lowercase();
    if ct.is_empty() {
        None
    } else {
        Some(ct)
    }
}

#[derive(serde::Deserialize)]
struct JsonRequest {
    hash: String,
    #[serde(default)]
    algorithm: String,
    #[serde(default, rename = "cert_req")]
    cert_req: Option<bool>,
    #[serde(default)]
    nonce: bool,
}

#[derive(Serialize)]
struct JsonResponse {
    granted: bool,
    token: String,
    gen_time: String,
    hash_algorithm: String,
}

#[derive(Serialize)]
struct JsonErrorBody {
    error: String,
}

/// Chemin d'appel testable en une commande curl, sans avoir à fabriquer une
/// requête ASN.1 : le service construit lui-même la `TimeStampReq` à partir
/// de l'empreinte fournie.
async fn handle_json(State(state): State<AppState>, body: Bytes) -> Response {
    let in_: JsonRequest = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(_) => return json_error(StatusCode::BAD_REQUEST, "corps JSON invalide"),
    };
    let alg = match parse_digest_alg(&in_.algorithm) {
        Some(a) => a,
        None => {
            return json_error(
                StatusCode::BAD_REQUEST,
                "algorithme non supporté (sha256, sha384, sha512)",
            )
        }
    };
    let digest = match decode_digest(&in_.hash) {
        Ok(d) => d,
        Err(msg) => return json_error(StatusCode::BAD_REQUEST, &msg),
    };
    if digest.len() != alg.expected_len() {
        return json_error(
            StatusCode::BAD_REQUEST,
            "longueur d'empreinte incohérente avec l'algorithme demandé",
        );
    }

    let req = oe_rfc3161_asn1::TimeStampReq {
        version: 1,
        message_imprint: oe_rfc3161_asn1::MessageImprint {
            hash_algorithm: digest_alg_id(alg),
            hashed_message: match der::asn1::OctetString::new(digest) {
                Ok(v) => v,
                Err(_) => {
                    return json_error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "encodage de la requête impossible",
                    )
                }
            },
        },
        req_policy: None,
        nonce: if in_.nonce {
            Some(random_nonce())
        } else {
            None
        },
        cert_req: in_.cert_req.unwrap_or(true),
        extensions: None,
    };
    let req_der = match req.to_der() {
        Ok(v) => v,
        Err(_) => {
            return json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "encodage de la requête impossible",
            )
        }
    };

    match state.authority.timestamp(&req_der) {
        Ok(resp_der) => {
            use base64::Engine;
            let token = base64::engine::general_purpose::STANDARD.encode(&resp_der);
            let gen_time = time::OffsetDateTime::now_utc()
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_default();
            Json(JsonResponse {
                granted: true,
                token,
                gen_time,
                hash_algorithm: digest_alg_name(alg).to_string(),
            })
            .into_response()
        }
        Err(TsaError::Rejection(r)) => json_error(StatusCode::BAD_REQUEST, &r.reason),
        Err(_) => json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "défaillance interne de la TSA",
        ),
    }
}

fn json_error(code: StatusCode, message: &str) -> Response {
    (
        code,
        Json(JsonErrorBody {
            error: message.to_string(),
        }),
    )
        .into_response()
}

async fn handle_policy(State(state): State<AppState>) -> Response {
    let cert = state.authority.certificate();
    let hashes: Vec<&str> = Authority::accepted_hashes()
        .iter()
        .map(|a| digest_alg_name(*a))
        .collect();
    let payload = serde_json::json!({
        "policy_oid": state.authority.policy().to_string(),
        "accuracy": format!("{:?}", state.authority.accuracy()),
        "accepted_hashes": hashes,
        "tsu_subject": cert.tbs_certificate().subject().to_string(),
        "tsu_issuer": cert.tbs_certificate().issuer().to_string(),
        "rfc3161_endpoint": "/tsa",
        "time_source": time_source_json(&state.time_source),
        "version": state.version.as_ref(),
    });
    Json(payload).into_response()
}

async fn handle_certificate(State(state): State<AppState>) -> Response {
    let mut out = String::new();
    for cert in std::iter::once(state.authority.certificate()).chain(state.authority.chain()) {
        if let Ok(der) = cert.to_der() {
            let block = pem::Pem::new("CERTIFICATE", der);
            out.push_str(&pem::encode(&block));
        }
    }
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/x-pem-file")],
        out,
    )
        .into_response()
}

async fn handle_health(State(state): State<AppState>) -> Response {
    let time_status = state.time_source.status();
    let (code, state_str) =
        if !time_status.traceable && time_status.policy == oe_timesource::Policy::Enforce {
            (
                StatusCode::SERVICE_UNAVAILABLE,
                format!("heure non traçable : {}", time_status.reason),
            )
        } else if !time_status.traceable {
            (
                StatusCode::OK,
                format!("dégradé — heure non traçable : {}", time_status.reason),
            )
        } else {
            (StatusCode::OK, "ok".to_string())
        };
    let journal = state.journal.as_ref().map(|j| j.report());
    // Un journal qui n'est plus scellé ou copié ne suspend pas l'émission :
    // `/healthz` sert aussi de sonde de vivacité, un 503 ferait redémarrer le
    // service. Il le dit, pour que la supervision alerte. L'heure non
    // traçable, plus grave, garde la priorité dans le libellé.
    let state_str = match journal.as_ref().and_then(|j| j.degraded.as_deref()) {
        Some(reason) if state_str == "ok" => format!("dégradé — journal d'audit : {reason}"),
        _ => state_str,
    };
    let mut payload = serde_json::json!({
        "status": state_str,
        "time_source": time_source_json(&state.time_source),
        "version": state.version.as_ref(),
    });
    if let Some(journal) = journal {
        payload["journal"] = journal.detail;
    }
    (code, Json(payload)).into_response()
}

fn time_source_json(monitor: &oe_timesource::Monitor) -> serde_json::Value {
    let status = monitor.status();
    serde_json::json!({
        "policy": status.policy.to_string(),
        "traceable": status.traceable,
        "reason": status.reason,
    })
}

fn digest_alg_name(alg: DigestAlg) -> &'static str {
    match alg {
        DigestAlg::Sha256 => "sha256",
        DigestAlg::Sha384 => "sha384",
        DigestAlg::Sha512 => "sha512",
    }
}

fn parse_digest_alg(name: &str) -> Option<DigestAlg> {
    match name.trim().to_lowercase().as_str() {
        "" | "sha256" => Some(DigestAlg::Sha256),
        "sha384" => Some(DigestAlg::Sha384),
        "sha512" => Some(DigestAlg::Sha512),
        _ => None,
    }
}

fn digest_alg_id(alg: DigestAlg) -> spki::AlgorithmIdentifierOwned {
    let oid = match alg {
        DigestAlg::Sha256 => "2.16.840.1.101.3.4.2.1",
        DigestAlg::Sha384 => "2.16.840.1.101.3.4.2.2",
        DigestAlg::Sha512 => "2.16.840.1.101.3.4.2.3",
    };
    spki::AlgorithmIdentifierOwned {
        oid: der::asn1::ObjectIdentifier::new(oid).expect("OID constant invalide"),
        parameters: None,
    }
}

fn decode_digest(s: &str) -> Result<Vec<u8>, String> {
    let s = s.trim();
    if s.is_empty() {
        return Err("champ hash manquant".to_string());
    }
    if let Ok(b) = hex::decode(s) {
        return Ok(b);
    }
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(s)
        .map_err(|_| "champ hash: encodage hexadécimal ou base64 attendu".to_string())
}

fn random_nonce() -> der::asn1::Int {
    use rand::RngCore;
    let mut bytes = [0u8; 8];
    rand::thread_rng().fill_bytes(&mut bytes);
    bytes[0] &= 0x7f; // garde un entier positif
    der::asn1::Int::new(&bytes).unwrap_or_else(|_| der::asn1::Int::new(&[1]).unwrap())
}
