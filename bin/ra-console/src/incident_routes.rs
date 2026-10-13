//! Routes des dossiers d'incident (docs/WEBUI.md §5, §6, §15 étape 5) : ouvrir,
//! lister, lire, consigner, clore. Rien n'est relayé à `ca-server` : un dossier
//! n'appartient qu'à la console, qui juge donc elle-même du rôle
//! ([`crate::incidents::may_write`]) et vérifie elle-même l'assertion de
//! clôture.

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use oe_webauthn::Uuid;
use serde::Deserialize;

use crate::http::{authenticate, error, is_json, unsupported_media_type, AppState};
use crate::incidents;
use crate::session::Authenticated;

pub(crate) fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/v1/incidents", get(handle_list).post(handle_open))
        .route("/api/v1/incidents/{id}", get(handle_get))
        .route("/api/v1/incidents/{id}/actions", post(handle_add))
        .route(
            "/api/v1/incidents/{id}/close/challenge",
            post(handle_close_challenge),
        )
        .route("/api/v1/incidents/{id}/close", post(handle_close))
}

fn unavailable() -> Response {
    error(
        StatusCode::SERVICE_UNAVAILABLE,
        "unavailable",
        "service indisponible",
    )
}

fn unknown_incident() -> Response {
    error(StatusCode::NOT_FOUND, "unknown_incident", "dossier inconnu")
}

/// Un refus du module, dans la forme du §5. Une panne (journal, base) ne fuit
/// aucun détail ; une assertion refusée non plus, sa raison est au journal.
fn refusal(e: incidents::Error) -> Response {
    use incidents::Error;
    match e {
        Error::Forbidden => error(
            StatusCode::FORBIDDEN,
            "forbidden",
            "rôle insuffisant pour écrire dans un dossier d'incident",
        ),
        Error::InvalidTitle => error(StatusCode::BAD_REQUEST, "bad_request", "titre invalide"),
        Error::InvalidText => error(StatusCode::BAD_REQUEST, "bad_request", "texte invalide"),
        Error::UnknownIncident => unknown_incident(),
        Error::Closed => error(
            StatusCode::CONFLICT,
            "incident_closed",
            "ce dossier est clos",
        ),
        Error::UnknownAction => error(StatusCode::NOT_FOUND, "unknown_action", "action inconnue"),
        Error::AlreadyLinked => error(
            StatusCode::CONFLICT,
            "already_linked",
            "cette action est déjà rattachée à ce dossier",
        ),
        Error::NoKey => error(
            StatusCode::CONFLICT,
            "no_active_key",
            "aucune clé active pour signer",
        ),
        Error::InvalidAssertion => error(
            StatusCode::FORBIDDEN,
            "invalid_assertion",
            "signature refusée",
        ),
        Error::ChallengeMismatch => error(
            StatusCode::CONFLICT,
            "challenge_mismatch",
            "ce challenge a été émis pour un autre dossier",
        ),
        Error::Journal(e) => {
            tracing::error!(erreur = %e, "incidents : journal indisponible, rien n'est écrit");
            unavailable()
        }
        Error::Database(e) => {
            tracing::error!(erreur = %e, "incidents : base indisponible");
            unavailable()
        }
    }
}

/// Session, type de contenu et identifiant du dossier d'une route d'écriture.
/// L'`Err` est la réponse à rendre telle quelle (voir [`authenticate`]).
#[allow(clippy::result_large_err)]
async fn writer(
    state: &AppState,
    headers: &HeaderMap,
    id: &str,
) -> Result<(Authenticated, Uuid), Response> {
    if !is_json(headers) {
        return Err(unsupported_media_type());
    }
    let who = authenticate(state, headers).await?;
    let id = id.parse().map_err(|_| unknown_incident())?;
    Ok((who, id))
}

fn bad_body() -> Response {
    error(StatusCode::BAD_REQUEST, "bad_request", "corps invalide")
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Open {
    title: String,
}

/// `POST /api/v1/incidents` (`{"title": "…"}`) : ouvre un dossier au nom de
/// l'opérateur de la session. Réservé à `ra_operateur` et `ca_operateur` ;
/// consigné au journal de la console avant d'exister en base, et refusé si le
/// journal ne peut pas l'écrire.
async fn handle_open(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if !is_json(&headers) {
        return unsupported_media_type();
    }
    let who = match authenticate(&state, &headers).await {
        Ok(a) => a,
        Err(resp) => return resp,
    };
    let Ok(req) = serde_json::from_slice::<Open>(&body) else {
        return bad_body();
    };
    let now = time::OffsetDateTime::now_utc();
    match incidents::open(&state.pool, state.journal.as_ref(), &who, &req.title, now).await {
        Ok(incident) => (StatusCode::CREATED, Json(incident)).into_response(),
        Err(e) => refusal(e),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ListQuery {
    state: Option<String>,
}

/// `GET /api/v1/incidents?state=OUVERT|CLOS` : les dossiers, les plus récents
/// d'abord. Comme les autres lectures de la console, toute session
/// authentifiée suffit.
async fn handle_list(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(q): Query<ListQuery>,
) -> Response {
    if let Err(resp) = authenticate(&state, &headers).await {
        return resp;
    }
    if let Some(s) = &q.state {
        if !incidents::STATES.contains(&s.as_str()) {
            return error(StatusCode::BAD_REQUEST, "bad_request", "état invalide");
        }
    }
    match incidents::list(&state.pool, q.state.as_deref()).await {
        Ok(list) => Json(list).into_response(),
        Err(e) => refusal(e.into()),
    }
}

/// `GET /api/v1/incidents/{id}` : un dossier, ce qu'on y a consigné dans
/// l'ordre, et la preuve de sa clôture s'il est clos.
async fn handle_get(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Response {
    if let Err(resp) = authenticate(&state, &headers).await {
        return resp;
    }
    let Ok(id) = id.parse::<Uuid>() else {
        return unknown_incident();
    };
    match incidents::detail(&state.pool, id).await {
        Ok(Some(detail)) => Json(detail).into_response(),
        Ok(None) => unknown_incident(),
        Err(e) => refusal(e.into()),
    }
}

#[derive(Deserialize)]
#[serde(tag = "kind", deny_unknown_fields)]
enum Add {
    #[serde(rename = "note")]
    Note { detail: String },
    #[serde(rename = "action_liee")]
    LinkedAction {
        action_id: String,
        #[serde(default)]
        detail: String,
    },
}

/// `POST /api/v1/incidents/{id}/actions` : consigne dans un dossier ouvert une
/// note (`{"kind": "note", "detail"}`) ou la référence d'une action figée par
/// `ca-server` (`{"kind": "action_liee", "action_id", "detail"?}`). La
/// référence est vérifiée : l'action doit exister, et c'est l'empreinte de son
/// corps, lue chez `ca-server`, qui est recopiée. Rien n'est exécuté.
async fn handle_add(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let (who, id) = match writer(&state, &headers, &id).await {
        Ok(w) => w,
        Err(resp) => return resp,
    };
    let Ok(req) = serde_json::from_slice::<Add>(&body) else {
        return bad_body();
    };
    let now = time::OffsetDateTime::now_utc();
    let journal = state.journal.as_ref();
    let added = match req {
        Add::Note { detail } => {
            incidents::add_note(&state.pool, journal, &who, id, &detail, now).await
        }
        Add::LinkedAction { action_id, detail } => {
            let Ok(action_id) = action_id.parse::<Uuid>() else {
                return refusal(incidents::Error::UnknownAction);
            };
            incidents::link_action(&state.pool, journal, &who, id, action_id, &detail, now).await
        }
    };
    match added {
        Ok(entry) => (StatusCode::CREATED, Json(entry)).into_response(),
        Err(e) => refusal(e),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CloseChallenge {
    closing_note: String,
}

/// `POST /api/v1/incidents/{id}/close/challenge` (`{"closing_note": "…"}`) :
/// fige la clôture demandée et rend le challenge WebAuthn que l'opérateur de
/// la session signera, avec le corps exact à lui montrer et son empreinte.
/// Rien n'est clos à ce stade.
async fn handle_close_challenge(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let (who, id) = match writer(&state, &headers, &id).await {
        Ok(w) => w,
        Err(resp) => return resp,
    };
    let Ok(req) = serde_json::from_slice::<CloseChallenge>(&body) else {
        return bad_body();
    };
    match incidents::begin_close(&state.pool, &state.login, &who, id, &req.closing_note).await {
        Ok(c) => Json(serde_json::json!({
            "challenge_id": c.challenge_id,
            "webauthn": c.options.public_key,
            "body": c.body,
            "body_hash": c.body_hash,
        }))
        .into_response(),
        Err(e) => refusal(e),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Close {
    challenge_id: String,
    /// La sortie brute de `navigator.credentials.get` : vérifiée par
    /// `ra-console` elle-même, puis conservée avec le dossier.
    assertion: serde_json::Value,
}

/// `POST /api/v1/incidents/{id}/close` (`{"challenge_id", "assertion"}`) : clôt
/// le dossier sur l'assertion de l'opérateur de la session. Aucune note dans
/// cette requête : celle qui est enregistrée est celle du corps figé, que
/// l'assertion couvre. Un challenge émis pour un autre dossier est refusé sans
/// être consommé.
async fn handle_close(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let (who, id) = match writer(&state, &headers, &id).await {
        Ok(w) => w,
        Err(resp) => return resp,
    };
    let Ok(req) = serde_json::from_slice::<Close>(&body) else {
        return bad_body();
    };
    let (Ok(challenge_id), Ok(credential)) = (
        req.challenge_id.parse::<Uuid>(),
        serde_json::from_value(req.assertion),
    ) else {
        return refusal(incidents::Error::InvalidAssertion);
    };
    match incidents::close(
        &state.pool,
        &state.login,
        state.journal.as_ref(),
        &who,
        id,
        challenge_id,
        &credential,
    )
    .await
    {
        Ok(detail) => Json(detail).into_response(),
        Err(e) => refusal(e),
    }
}
