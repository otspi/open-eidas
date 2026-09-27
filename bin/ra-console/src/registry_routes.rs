//! Gestion du registre des opérateurs depuis la console (docs/WEBUI.md §5,
//! §10) : inviter un opérateur, confirmer ou révoquer une clé, changer un rôle.
//! Même schéma que les décisions et la révocation (§4) : le challenge est
//! préparé par `POST /api/v1/webauthn/challenge` avec l'action voulue, puis
//! l'assertion est relayée ici, **sans corps** ; `ca-server` exécute celui
//! qu'il a figé, après avoir comparé la cible de la route (`expect`) au corps
//! figé. Seul un `admin` signe ces actions, et deux pour créer un
//! administrateur ou changer le rôle de l'un d'eux : c'est la politique de
//! `ca-server`, jamais une décision de la console.

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};

use crate::http::{error, looks_like_a_name, quorum_status, relay_assertion, AppState};

pub(crate) fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/v1/operators", post(handle_invite))
        .route(
            "/api/v1/credentials/{credential_id}/confirm",
            post(handle_confirm_key),
        )
        .route(
            "/api/v1/credentials/{credential_id}/revoke",
            post(handle_revoke_key),
        )
        .route("/api/v1/operators/{name}/role", post(handle_set_role))
}

/// Un identifiant de clé WebAuthn tel que le registre le range : base64url,
/// borné. Il n'est qu'une attente : `ca-server` le compare au corps figé.
fn looks_like_a_credential_id(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 1024
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

async fn relay(
    state: &AppState,
    headers: &HeaderMap,
    body: &[u8],
    expect: serde_json::Value,
) -> Response {
    match relay_assertion(state, headers, body, expect).await {
        Ok(r) => Json(quorum_status(&r.body)).into_response(),
        Err(resp) => resp,
    }
}

/// `POST /api/v1/operators` : exécute l'invitation figée
/// (`{"action": "invite_operator", "name", "role"}`). Le jeton d'invitation
/// n'existe que dans `result.invite_token` de la réponse d'exécution : ni
/// `ca-server` ni la console ne le journalisent ni ne le conservent. Une
/// invitation n'a pas de cible dans la route : seul le type est contrôlé.
async fn handle_invite(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    relay(
        &state,
        &headers,
        &body,
        serde_json::json!({ "action": "invite_operator" }),
    )
    .await
}

/// `POST /api/v1/credentials/{credential_id}/confirm` : active une clé en
/// attente. L'empreinte, transmise hors bande par l'invité (§10), fait partie
/// du corps signé ; `ca-server` la recompare à la clé en attente.
async fn handle_confirm_key(
    State(state): State<Arc<AppState>>,
    Path(credential_id): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if !looks_like_a_credential_id(&credential_id) {
        return error(StatusCode::BAD_REQUEST, "bad_request", "clé invalide");
    }
    relay(
        &state,
        &headers,
        &body,
        serde_json::json!({ "action": "confirm_key", "credential_id": credential_id }),
    )
    .await
}

/// `POST /api/v1/credentials/{credential_id}/revoke` (perte de clé, départ,
/// §14). `ca-server` refuse de révoquer la dernière clé d'administrateur active.
async fn handle_revoke_key(
    State(state): State<Arc<AppState>>,
    Path(credential_id): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if !looks_like_a_credential_id(&credential_id) {
        return error(StatusCode::BAD_REQUEST, "bad_request", "clé invalide");
    }
    relay(
        &state,
        &headers,
        &body,
        serde_json::json!({ "action": "revoke_key", "credential_id": credential_id }),
    )
    .await
}

/// `POST /api/v1/operators/{name}/role` : l'opérateur est désigné par son
/// **nom**, comme dans le corps signé (`set_role`), pas par un identifiant
/// technique. Élever un opérateur au rôle `admin`, ou changer celui d'un
/// administrateur, exige deux administrateurs : la première signature rend
/// `AWAITING_QUORUM`, la seconde passe par `/api/v1/quorum/{id}/sign`.
async fn handle_set_role(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if !looks_like_a_name(&name) {
        return error(StatusCode::BAD_REQUEST, "bad_request", "opérateur invalide");
    }
    relay(
        &state,
        &headers,
        &body,
        serde_json::json!({ "action": "set_role", "operator": name }),
    )
    .await
}
