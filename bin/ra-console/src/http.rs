//! Routes de `ra-console` (docs/WEBUI.md §5, §15) : `/healthz`, l'enregistrement
//! et la connexion WebAuthn, les sessions, et la première route de lecture
//! seule (`/api/v1/requests`, étape 2a).

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, Query, State};
use axum::http::header::{COOKIE, SET_COOKIE};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use sqlx::PgPool;

use crate::audit::{self, Recorder};
use crate::ca_link::{CaLink, Relayed};
use crate::login::{LoginError, LoginService};
use crate::requests;
use crate::session::{Authenticated, SessionError, Sessions, COOKIE_NAME, SESSION_TTL};

/// Assez pour un objet d'attestation, pas pour bourrer la mémoire.
const MAX_BODY_BYTES: usize = 64 * 1024;

pub struct AppState {
    pub pool: PgPool,
    pub link: CaLink,
    pub login: LoginService,
    pub sessions: Sessions,
    pub journal: Arc<dyn Recorder>,
}

pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/healthz", get(handle_health))
        .route(
            "/api/v1/webauthn/register/begin",
            post(handle_register_begin),
        )
        .route(
            "/api/v1/webauthn/register/finish",
            post(handle_register_finish),
        )
        .route("/api/v1/webauthn/login/begin", post(handle_login_begin))
        .route("/api/v1/webauthn/login/finish", post(handle_login_finish))
        .route("/api/v1/me", get(handle_me))
        .route("/api/v1/logout", post(handle_logout))
        .route("/api/v1/requests", get(handle_requests))
        .route("/api/v1/webauthn/challenge", post(handle_action_challenge))
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .with_state(state)
}

/// Sain seulement si la base répond ET si le lien vers `ca-server` fonctionne :
/// une console qui ne peut pas relayer d'action ne doit pas se déclarer prête.
async fn handle_health(State(state): State<Arc<AppState>>) -> Response {
    let base = sqlx::query_scalar::<_, i32>("SELECT 1")
        .fetch_one(&state.pool)
        .await
        .map(|_| ())
        .map_err(|e| e.to_string());
    let lien = state.link.ping().await.map_err(|e| e.to_string());

    let ok = base.is_ok() && lien.is_ok();
    let describe = |r: &Result<(), String>| match r {
        Ok(()) => "ok".to_string(),
        Err(e) => format!("ko : {e}"),
    };
    let body = serde_json::json!({
        "statut": if ok { "ok" } else { "degrade" },
        "version": env!("CARGO_PKG_VERSION"),
        "base": describe(&base),
        "lien_ca": describe(&lien),
        "certificat_client_expire_le": state
            .link
            .client_certificate_expires()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_default(),
    });
    let status = if ok {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (status, Json(body)).into_response()
}

/// `{"error": "<code>", "message": "..."}` (docs/WEBUI.md §5), sans trace interne.
fn error(status: StatusCode, code: &str, message: &str) -> Response {
    (
        status,
        Json(serde_json::json!({ "error": code, "message": message })),
    )
        .into_response()
}

/// Une route qui relaie des JSON n'accepte que du JSON déclaré : un navigateur ne
/// peut pas envoyer `application/json` d'un autre site sans pré-requête CORS, ce qui
/// ferme les envois « aveugles » d'un formulaire piégé.
fn is_json(headers: &HeaderMap) -> bool {
    headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.split(';').next().unwrap_or("").trim() == "application/json")
}

fn unsupported_media_type() -> Response {
    error(
        StatusCode::UNSUPPORTED_MEDIA_TYPE,
        "unsupported_media_type",
        "Content-Type: application/json attendu",
    )
}

/// Ce que `ca-server` a répondu, rendu tel quel pour un refus de sa part (le code
/// et le message sont faits pour cela) ; une panne, elle, ne fuit aucun détail.
fn relayed(result: Result<Relayed, crate::ca_link::LinkError>) -> Response {
    match result {
        Ok(r) if r.status < 500 => (
            StatusCode::from_u16(r.status).unwrap_or(StatusCode::BAD_GATEWAY),
            Json(r.body),
        )
            .into_response(),
        Ok(r) => {
            tracing::error!(statut = r.status, "ca-server a refusé de servir");
            error(
                StatusCode::BAD_GATEWAY,
                "ca_unavailable",
                "ca-server est indisponible",
            )
        }
        Err(e) => {
            tracing::error!(erreur = %e, "lien vers ca-server en échec");
            error(
                StatusCode::BAD_GATEWAY,
                "ca_unavailable",
                "ca-server est injoignable",
            )
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RegisterBegin {
    token: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RegisterFinish {
    ceremony_id: String,
    /// La sortie brute de `navigator.credentials.create` : la console ne la lit
    /// pas, elle ne la comprend pas, elle la relaie. C'est `ca-server` qui vérifie
    /// l'attestation.
    credential: serde_json::Value,
}

/// Une valeur d'identifiant de cérémonie : un UUID, rien d'autre.
fn looks_like_uuid(s: &str) -> bool {
    s.len() == 36
        && s.char_indices().all(|(i, c)| match i {
            8 | 13 | 18 | 23 => c == '-',
            _ => c.is_ascii_hexdigit(),
        })
}

/// `POST /api/v1/webauthn/register/begin` : l'invité présente son jeton
/// d'invitation, `ca-server` rend les options WebAuthn (docs/WEBUI.md §5, §10). Le
/// jeton est le seul secret de cette route : il n'est ni journalisé ni renvoyé.
async fn handle_register_begin(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if !is_json(&headers) {
        return unsupported_media_type();
    }
    let req: RegisterBegin = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(_) => return error(StatusCode::BAD_REQUEST, "bad_request", "corps invalide"),
    };
    if req.token.is_empty() || req.token.len() > 256 {
        return error(StatusCode::BAD_REQUEST, "bad_request", "jeton invalide");
    }
    relayed(
        state
            .link
            .post(
                "/internal/v1/register/begin",
                &serde_json::json!({ "token": req.token }),
            )
            .await,
    )
}

/// `POST /api/v1/webauthn/register/finish` : l'attestation est relayée telle
/// quelle. `ca-server` la vérifie contre la liste blanche de modèles et range la
/// clé ; la console n'en garde rien.
async fn handle_register_finish(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if !is_json(&headers) {
        return unsupported_media_type();
    }
    let req: RegisterFinish = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(_) => return error(StatusCode::BAD_REQUEST, "bad_request", "corps invalide"),
    };
    if !looks_like_uuid(&req.ceremony_id) || !req.credential.is_object() {
        return error(StatusCode::BAD_REQUEST, "bad_request", "corps invalide");
    }
    relayed(
        state
            .link
            .post(
                "/internal/v1/register/finish",
                &serde_json::json!({
                    "ceremony_id": req.ceremony_id,
                    "credential": req.credential,
                }),
            )
            .await,
    )
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LoginBegin {
    name: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LoginFinish {
    challenge_id: String,
    /// La sortie brute de `navigator.credentials.get` : vérifiée par
    /// `ra-console` elle-même (§16), jamais relayée à `ca-server`.
    credential: serde_json::Value,
}

/// Un nom d'opérateur : ce qu'un humain saisit, pas un identifiant technique.
/// Une longueur bornée suffit à écarter un corps abusif avant toute requête ;
/// le reste (existe ou non) ne se voit jamais dans la réponse (§16).
fn looks_like_a_name(s: &str) -> bool {
    !s.is_empty() && s.chars().count() <= 256
}

/// `POST /api/v1/webauthn/login/begin` : options WebAuthn de même forme que le
/// nom existe ou non (docs/WEBUI.md §16). Ni `ca-server` ni son lien interne ne
/// sont sollicités : le registre en lecture seule suffit.
async fn handle_login_begin(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if !is_json(&headers) {
        return unsupported_media_type();
    }
    let req: LoginBegin = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(_) => return error(StatusCode::BAD_REQUEST, "bad_request", "corps invalide"),
    };
    if !looks_like_a_name(&req.name) {
        return error(StatusCode::BAD_REQUEST, "bad_request", "nom invalide");
    }
    match state.login.begin(&req.name).await {
        Ok(begun) => Json(serde_json::json!({
            "challenge_id": begun.challenge_id,
            "webauthn": begun.options.public_key,
        }))
        .into_response(),
        Err(e) => {
            tracing::error!(erreur = %e, "login/begin : base indisponible");
            error(
                StatusCode::SERVICE_UNAVAILABLE,
                "unavailable",
                "service indisponible",
            )
        }
    }
}

/// `POST /api/v1/webauthn/login/finish` : assertion vérifiée contre le
/// registre en lecture seule, puis session ouverte (docs/WEBUI.md §15 étape
/// 1c-2) — cookie `HttpOnly; Secure; SameSite=Strict` qui ne porte que
/// `sessions.id`.
async fn handle_login_finish(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if !is_json(&headers) {
        return unsupported_media_type();
    }
    let req: LoginFinish = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(_) => return error(StatusCode::BAD_REQUEST, "bad_request", "corps invalide"),
    };
    let Ok(challenge_id) = req.challenge_id.parse() else {
        return invalid_credential();
    };
    let credential = match serde_json::from_value(req.credential) {
        Ok(c) => c,
        Err(_) => return invalid_credential(),
    };
    let verified = match state.login.finish(challenge_id, &credential).await {
        Ok(v) => v,
        Err(LoginError::Invalid) => return invalid_credential(),
    };
    let session_id = match state
        .sessions
        .create(verified.operator_id, &verified.credential_id)
        .await
    {
        Ok(id) => id,
        Err(e) => {
            tracing::error!(erreur = %e, "login/finish : ouverture de la session");
            return error(
                StatusCode::SERVICE_UNAVAILABLE,
                "unavailable",
                "service indisponible",
            );
        }
    };
    (
        [(SET_COOKIE, set_session_cookie(&session_id))],
        Json(serde_json::json!({
            "operator": verified.operator,
            "role": verified.role.as_str(),
        })),
    )
        .into_response()
}

/// Une seule forme pour tout refus de `login/finish` (§16) : nom inconnu,
/// leurre, challenge périmé ou déjà consommé, clé révoquée, opérateur
/// désactivé, signature refusée, compteur en régression ne se distinguent
/// jamais de l'extérieur.
fn invalid_credential() -> Response {
    error(
        StatusCode::UNAUTHORIZED,
        "invalid_credential",
        "identifiants invalides",
    )
}

/// `Set-Cookie` d'une session ouverte : `HttpOnly` (jamais lu par un script),
/// `Secure` (jamais en clair), `SameSite=Strict` (jamais envoyé par un site
/// tiers, y compris une navigation entrante) — docs/WEBUI.md §15 étape 1c-2.
fn set_session_cookie(id: &str) -> String {
    format!(
        "{COOKIE_NAME}={id}; Path=/; Max-Age={}; HttpOnly; Secure; SameSite=Strict",
        SESSION_TTL.whole_seconds()
    )
}

/// Efface le cookie côté navigateur (déconnexion) : même forme, âge nul.
fn clear_session_cookie() -> String {
    format!("{COOKIE_NAME}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Strict")
}

/// Lit l'identifiant de session dans l'en-tête `Cookie`. Un seul cookie
/// nous intéresse : pas besoin d'une bibliothèque dédiée pour ce format.
fn session_id_from(headers: &HeaderMap) -> Option<String> {
    let raw = headers.get(COOKIE)?.to_str().ok()?;
    raw.split(';').find_map(|kv| {
        let (k, v) = kv.trim().split_once('=')?;
        (k == COOKIE_NAME).then(|| v.to_string())
    })
}

/// Authentifie la requête par son cookie de session, ou rend directement la
/// réponse 401 uniforme à retourner (§16 : absente, expirée, révoquée,
/// opérateur désactivé ne se distinguent jamais).
///
/// `Response` est volontairement l'`Err`, malgré sa taille (`clippy::result_large_err`,
/// visible seulement sur la toolchain 1.98 de la CI) : c'est justement la réponse à
/// renvoyer telle quelle à l'appelant, la boxer n'apporterait rien ici.
#[allow(clippy::result_large_err)]
async fn authenticate(state: &AppState, headers: &HeaderMap) -> Result<Authenticated, Response> {
    let id = session_id_from(headers).ok_or_else(unauthenticated)?;
    state
        .sessions
        .authenticate(&id)
        .await
        .map_err(|SessionError::Invalid| unauthenticated())
}

/// `GET /api/v1/me` : identité et rôle relus en base à l'instant de l'appel
/// (§16, une session ne porte qu'un identifiant, jamais une décision mise en
/// cache).
async fn handle_me(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    match authenticate(&state, &headers).await {
        Ok(a) => Json(serde_json::json!({
            "operator": a.operator,
            "role": a.role.as_str(),
        }))
        .into_response(),
        Err(resp) => resp,
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RequestsQuery {
    state: Option<String>,
}

/// `GET /api/v1/requests?state=PENDING` : la file d'enrôlement, en lecture
/// seule (docs/WEBUI.md §5, §15 étape 2a). Le rôle minimal documenté
/// (`auditeur`) n'est, comme tout contrôle de rôle de `ra-console`, qu'un
/// affichage (§3) : toute session authentifiée peut lire cette route, la
/// vraie barrière reste côté `ca-server` pour l'écriture.
async fn handle_requests(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(q): Query<RequestsQuery>,
) -> Response {
    if let Err(resp) = authenticate(&state, &headers).await {
        return resp;
    }
    if let Some(s) = &q.state {
        if !requests::STATES.contains(&s.as_str()) {
            return error(StatusCode::BAD_REQUEST, "bad_request", "état invalide");
        }
    }
    match requests::list(&state.pool, q.state.as_deref()).await {
        Ok(list) => Json(list).into_response(),
        Err(e) => {
            tracing::error!(erreur = %e, "requests : base indisponible");
            error(
                StatusCode::SERVICE_UNAVAILABLE,
                "unavailable",
                "service indisponible",
            )
        }
    }
}

/// Les actions que la console relaie à ce stade (docs/WEBUI.md §15, étape 3) :
/// décider d'une demande d'enrôlement. La révocation (étape 4) et la gestion
/// du registre suivront ; d'ici là, la console refuse de les préparer, même si
/// `ca-server` saurait les exécuter.
fn relayed_at_this_stage(action: &oe_actions::Action) -> bool {
    matches!(
        action,
        oe_actions::Action::ApproveRequest { .. } | oe_actions::Action::RejectRequest { .. }
    )
}

/// `POST /api/v1/webauthn/challenge` (docs/WEBUI.md §4 étapes 1 à 3, §5) :
/// l'opérateur connecté demande à `ca-server` de figer une action et d'émettre
/// le challenge qu'il signera. Le corps rendu est celui que `ca-server`
/// exécutera, à afficher tel quel.
///
/// Ce que la console décide : que la session est valide, et **pour qui** le
/// challenge est émis — l'opérateur de la session, jamais une valeur du
/// navigateur. Ce qu'elle ne décide pas : le rôle suffisant, l'état de la
/// demande, le corps final. `ca-server` en juge.
async fn handle_action_challenge(
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
    // Relue dans l'énumération fermée d'`oe_actions`, puis resérialisée : un
    // champ en trop (un `operator_hint` glissé par le navigateur, par exemple)
    // ne franchit jamais la console.
    let action: oe_actions::Action = match serde_json::from_slice(&body) {
        Ok(a) => a,
        Err(_) => return error(StatusCode::BAD_REQUEST, "bad_request", "action invalide"),
    };
    if !relayed_at_this_stage(&action) {
        return error(
            StatusCode::FORBIDDEN,
            "action_not_available",
            "cette action n'est pas encore proposée par la console",
        );
    }
    let result = state
        .link
        .post(
            "/internal/v1/challenge",
            &serde_json::json!({ "body": action, "operator_hint": who.operator_id }),
        )
        .await;
    if let Ok(r) = &result {
        state.journal.append(
            audit::EVENT_ACTION_CHALLENGE,
            serde_json::json!({
                "operator": who.operator,
                "action": r.body.get("body").and_then(|b| b.get("action")),
                "action_id": r.body.get("action_id"),
                "body_hash": r.body.get("body_hash"),
                "status": r.status,
                "error": r.body.get("error"),
            }),
        );
    }
    relayed(result)
}

/// `POST /api/v1/logout` : révoque la session sans attendre son expiration.
/// Idempotent, sans cookie ou avec un cookie déjà invalide compris : dans
/// tous les cas, plus aucune session valide n'existe ensuite.
async fn handle_logout(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if let Some(id) = session_id_from(&headers) {
        if let Err(e) = state.sessions.revoke(&id).await {
            tracing::error!(erreur = %e, "logout : révocation de la session");
            return error(
                StatusCode::SERVICE_UNAVAILABLE,
                "unavailable",
                "service indisponible",
            );
        }
    }
    (
        StatusCode::NO_CONTENT,
        [(SET_COOKIE, clear_session_cookie())],
    )
        .into_response()
}

fn unauthenticated() -> Response {
    error(
        StatusCode::UNAUTHORIZED,
        "unauthenticated",
        "connexion requise",
    )
}
