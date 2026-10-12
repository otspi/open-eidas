//! Routes des dossiers d'incident (docs/WEBUI.md §5, §6, §15 étape 5a) :
//! ouvrir, lister, lire. Rien n'est relayé à `ca-server` : un dossier
//! n'appartient qu'à la console, qui juge donc elle-même du rôle
//! ([`crate::incidents::may_write`]).

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use serde::Deserialize;

use crate::http::{authenticate, error, is_json, unsupported_media_type, AppState};
use crate::incidents;

pub(crate) fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/v1/incidents", get(handle_list).post(handle_open))
        .route("/api/v1/incidents/{id}", get(handle_get))
}

fn unavailable() -> Response {
    error(
        StatusCode::SERVICE_UNAVAILABLE,
        "unavailable",
        "service indisponible",
    )
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
    let req: Open = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(_) => return error(StatusCode::BAD_REQUEST, "bad_request", "corps invalide"),
    };
    let now = time::OffsetDateTime::now_utc();
    match incidents::open(&state.pool, state.journal.as_ref(), &who, &req.title, now).await {
        Ok(incident) => (StatusCode::CREATED, Json(incident)).into_response(),
        Err(incidents::Error::Forbidden) => error(
            StatusCode::FORBIDDEN,
            "forbidden",
            "rôle insuffisant pour ouvrir un dossier d'incident",
        ),
        Err(incidents::Error::InvalidTitle) => {
            error(StatusCode::BAD_REQUEST, "bad_request", "titre invalide")
        }
        Err(incidents::Error::Journal(e)) => {
            tracing::error!(erreur = %e, "incidents : journal indisponible, dossier non ouvert");
            unavailable()
        }
        Err(incidents::Error::Database(e)) => {
            tracing::error!(erreur = %e, "incidents : base indisponible");
            unavailable()
        }
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
        Err(e) => {
            tracing::error!(erreur = %e, "incidents : base indisponible");
            unavailable()
        }
    }
}

/// `GET /api/v1/incidents/{id}` : un dossier.
async fn handle_get(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Response {
    if let Err(resp) = authenticate(&state, &headers).await {
        return resp;
    }
    let unknown = || error(StatusCode::NOT_FOUND, "unknown_incident", "dossier inconnu");
    let Ok(id) = id.parse::<oe_webauthn::Uuid>() else {
        return unknown();
    };
    match incidents::get(&state.pool, id).await {
        Ok(Some(incident)) => Json(incident).into_response(),
        Ok(None) => unknown(),
        Err(e) => {
            tracing::error!(erreur = %e, "incidents : base indisponible");
            unavailable()
        }
    }
}
