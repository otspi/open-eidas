//! Routes internes de `ca-server` (docs/WEBUI.md §4, §16, §17) : le challenge,
//! puis l'exécution d'une action d'opérateur signée.
//!
//! Elles écoutent sur un **second port**, jamais mélangé avec le port public :
//! une `NetworkPolicy` ne voit que les ports. Le pare-feu réseau et le mTLS
//! (tranche suivante) prouvent seulement que l'appelant est `ra-console` ; ils
//! ne donnent aucun pouvoir. Le pouvoir vient de la signature de l'opérateur,
//! que [`oe_actions::Service`] vérifie contre son propre registre.
//!
//! Les routes sont génériques : une action de plus dans `oe_actions::Action`
//! hérite de tout ce qui suit sans qu'il y ait une route à ajouter.

use std::net::IpAddr;
use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use oe_actions::{Action, Error, Service};
use oe_webauthn::{PublicKeyCredential, RegisterPublicKeyCredential, Uuid};
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ChallengeRequest {
    /// Une action nouvelle, que `ca-server` fige...
    #[serde(default)]
    body: Option<Action>,
    /// ...ou une action déjà figée, pour un signataire de plus (double contrôle).
    /// L'un ou l'autre, jamais les deux : on ne signe pas un corps qu'on choisit
    /// par-dessus une action existante.
    #[serde(default)]
    action_id: Option<Uuid>,
    /// Sert seulement à choisir les clés à proposer, jamais une décision de
    /// confiance (§4).
    operator_hint: Uuid,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ExecuteRequest {
    challenge_id: Uuid,
    /// Sortie brute de `navigator.credentials.get`. Aucun corps d'action :
    /// c'est celui figé à l'émission du challenge qui s'exécute.
    assertion: PublicKeyCredential,
    /// Ce que l'appelant croit faire exécuter (type et cible), comparé au corps
    /// figé avant toute vérification : ne peut que faire refuser, jamais changer
    /// ce qui s'exécute.
    #[serde(default)]
    expect: Option<oe_actions::Expect>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RegisterBegin {
    /// Jeton d'invitation : c'est lui qui authentifie l'appelant, pas une
    /// signature d'opérateur (aucune clé n'existe encore).
    token: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RegisterFinish {
    ceremony_id: Uuid,
    /// Sortie brute de `navigator.credentials.create`.
    credential: RegisterPublicKeyCredential,
}

pub fn router(service: Arc<Service>, max_request_bytes: usize) -> Router {
    Router::new()
        .route("/internal/v1/ping", get(handle_ping))
        .route("/internal/v1/challenge", post(handle_challenge))
        .route("/internal/v1/actions", post(handle_actions))
        .route("/internal/v1/register/begin", post(handle_register_begin))
        .route("/internal/v1/register/finish", post(handle_register_finish))
        .layer(DefaultBodyLimit::max(max_request_bytes))
        .with_state(service)
}

/// `{"error": "<code>", "message": "..."}`, sans trace interne (§5).
fn error(status: StatusCode, code: &str, message: impl Into<String>) -> Response {
    (
        status,
        Json(serde_json::json!({ "error": code, "message": message.into() })),
    )
        .into_response()
}

fn bad_json(e: serde_json::Error) -> Response {
    error(StatusCode::BAD_REQUEST, "bad_request", e.to_string())
}

/// Le message d'une erreur d'infrastructure (base, effet) peut contenir un
/// détail interne : il va au journal de service, pas au client.
fn failure(e: Error) -> Response {
    let (status, code) = match &e {
        Error::Denied(_) => (StatusCode::FORBIDDEN, "denied"),
        Error::BadRequest(_) => (StatusCode::BAD_REQUEST, "bad_request"),
        Error::NotFound => (StatusCode::NOT_FOUND, "unknown_challenge"),
        Error::Expired => (StatusCode::GONE, "expired"),
        Error::AlreadyUsed => (StatusCode::CONFLICT, "already_used"),
        Error::StateLost => (StatusCode::CONFLICT, "ceremony_lost"),
        Error::Verification(_) => (StatusCode::UNAUTHORIZED, "signature_rejected"),
        Error::Journal(_) => (StatusCode::SERVICE_UNAVAILABLE, "journal_unavailable"),
        Error::Blocked(_) => (StatusCode::SERVICE_UNAVAILABLE, "registry_blocked"),
        Error::Mismatch(_) => (StatusCode::CONFLICT, "action_mismatch"),
        Error::Db(_) | Error::Effect(_) => {
            tracing::error!(erreur = %e, "action interne en échec");
            return error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal",
                "erreur interne",
            );
        }
    };
    if matches!(e, Error::Journal(_)) {
        tracing::error!(erreur = %e, "journal indisponible, action refusée");
        return error(status, code, "journal indisponible, action non émise");
    }
    error(status, code, e.to_string())
}

/// Ne fait rien, et ne dit rien de plus que « je suis là » : `ra-console` s'en
/// sert pour savoir si le lien interne (mTLS compris) fonctionne, sans avoir à
/// forger une action.
async fn handle_ping() -> Response {
    Json(serde_json::json!({ "ok": true })).into_response()
}

async fn handle_challenge(State(service): State<Arc<Service>>, body: Bytes) -> Response {
    let req: ChallengeRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => return bad_json(e),
    };
    let issued = match (req.body, req.action_id) {
        (Some(action), None) => service.issue_challenge(action, req.operator_hint).await,
        (None, Some(id)) => service.issue_challenge_for(id, req.operator_hint).await,
        _ => {
            return error(
                StatusCode::BAD_REQUEST,
                "bad_request",
                "exactement un des champs body ou action_id est attendu",
            )
        }
    };
    match issued {
        Ok(issued) => Json(serde_json::json!({
            "challenge_id": issued.challenge_id,
            "action_id": issued.action_id,
            "body": issued.body,
            "body_hash": issued.body_hash,
            "required_signatures": issued.required_signatures,
            "signatures": issued.signatures,
            "webauthn": issued.options.public_key,
        }))
        .into_response(),
        Err(e) => failure(e),
    }
}

async fn handle_actions(State(service): State<Arc<Service>>, body: Bytes) -> Response {
    let req: ExecuteRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => return bad_json(e),
    };
    let done = match &req.expect {
        Some(expect) => {
            service
                .execute_expecting(req.challenge_id, &req.assertion, expect)
                .await
        }
        None => service.execute(req.challenge_id, &req.assertion).await,
    };
    match done {
        // L'identité vient du registre de `ca-server`, jamais de l'appelant.
        Ok(done) => Json(serde_json::json!({
            "action_id": done.action_id,
            "challenge_id": done.challenge_id,
            "status": if done.executed { "executed" } else { "awaiting_quorum" },
            "signatures": done.signatures,
            "required": done.required,
            "operator": done.operator,
            "role": done.role.as_str(),
            // Propre à l'action (ex. le jeton d'une invitation) ; `null` sinon.
            "result": done.result,
        }))
        .into_response(),
        Err(e) => failure(e),
    }
}

async fn handle_register_begin(State(service): State<Arc<Service>>, body: Bytes) -> Response {
    let req: RegisterBegin = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => return bad_json(e),
    };
    match service.begin_registration(&req.token).await {
        Ok(begun) => Json(serde_json::json!({
            "ceremony_id": begun.ceremony_id,
            "operator": begun.operator,
            "webauthn": begun.options.public_key,
        }))
        .into_response(),
        Err(e) => failure(e),
    }
}

async fn handle_register_finish(State(service): State<Arc<Service>>, body: Bytes) -> Response {
    let req: RegisterFinish = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => return bad_json(e),
    };
    match service
        .finish_registration(req.ceremony_id, &req.credential)
        .await
    {
        Ok(done) => Json(serde_json::json!({
            "operator": done.operator,
            "credential_id": done.credential_id,
            "status": done.status.as_str(),
            "key_fingerprint": done.key_fingerprint,
            "aaguid": done.aaguid,
        }))
        .into_response(),
        Err(e) => failure(e),
    }
}

/// Le lien interne n'est pas encore protégé par mTLS : tant qu'il ne l'est pas,
/// il ne s'ouvre que sur la boucle locale. Refuser de démarrer vaut mieux
/// qu'exposer, sans le dire, un port qui accepte n'importe quel appelant du
/// réseau.
pub fn check_loopback(listen: &str) -> Result<(), String> {
    let host = listen
        .rsplit_once(':')
        .map(|(h, _)| h)
        .unwrap_or(listen)
        .trim_matches(|c| c == '[' || c == ']');
    let loopback = host == "localhost"
        || host
            .parse::<IpAddr>()
            .map(|ip| ip.is_loopback())
            .unwrap_or(false);
    if loopback {
        Ok(())
    } else {
        Err(format!(
            "OPENEIDAS_INTERNAL_LISTEN={listen:?} : le lien interne n'est pas encore protégé par mTLS, \
             il ne peut écouter que sur la boucle locale (127.0.0.1, [::1], localhost)"
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_loopback_addresses_are_accepted() {
        for ok in ["127.0.0.1:8321", "localhost:8321", "[::1]:8321"] {
            assert!(check_loopback(ok).is_ok(), "{ok}");
        }
        for bad in [
            "0.0.0.0:8321",
            ":8321",
            "10.0.0.5:8321",
            "[::]:8321",
            "ca:8321",
        ] {
            assert!(check_loopback(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn infrastructure_failures_do_not_leak_their_detail() {
        let r = failure(Error::Effect("connexion à 10.1.2.3 refusée".to_string()));
        assert_eq!(r.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }
}
