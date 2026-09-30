//! Le frontend de `ra-console` (docs/WEBUI.md §15 étape 6, docs/UI-UX.md) :
//! des assets statiques **embarqués dans le binaire** (UI-UX §7 : un
//! déploiement est un binaire unique autonome, sans serveur web ni
//! répertoire d'assets à côté), et les en-têtes de sécurité posés sur
//! **toutes** les réponses, API comprise (UI-UX §6.3).
//!
//! Les assets sont construits depuis `bin/ra-console/web/` (TypeScript,
//! esbuild) et versionnés dans `web/dist/` : la compilation Rust n'exige pas
//! Node, et la CI vérifie que `dist/` correspond aux sources.

use axum::extract::State;
use axum::http::{header, HeaderValue, Request};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};

static INDEX_HTML: &[u8] = include_bytes!("../web/dist/index.html");
static CONSOLE_JS: &[u8] = include_bytes!("../web/dist/console.js");
static CONSOLE_CSS: &[u8] = include_bytes!("../web/dist/console.css");

/// Environnement annoncé en tête de chaque écran (UI-UX §1, principe 4) :
/// **PRODUCTION** en rouge, les autres en teinte discrète. Déclaré par le
/// déploiement (`OPENEIDAS_RA_ENVIRONMENT`) ; non déclaré, la console le dit
/// plutôt que de laisser croire à un environnement sans risque.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Environment {
    Production,
    Staging,
    Demo,
    Undeclared,
}

impl Environment {
    pub fn parse(value: &str) -> Result<Environment, String> {
        match value {
            "" => Ok(Environment::Undeclared),
            "production" => Ok(Environment::Production),
            "staging" => Ok(Environment::Staging),
            "demo" => Ok(Environment::Demo),
            other => Err(format!(
                "OPENEIDAS_RA_ENVIRONMENT={other:?} : production, staging ou demo"
            )),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Environment::Production => "production",
            Environment::Staging => "staging",
            Environment::Demo => "demo",
            Environment::Undeclared => "undeclared",
        }
    }
}

/// Ce que le frontend doit savoir avant toute connexion.
#[derive(Debug, Clone)]
pub struct Console {
    pub environment: Environment,
}

/// Politique de contenu d'UI-UX §6.3, à l'identique : aucun script ni style
/// en ligne, rien hors de l'origine, pas d'intégration dans un cadre.
pub const CONTENT_SECURITY_POLICY: &str = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; object-src 'none'; base-uri 'self'; form-action 'self'";

pub fn router(console: Console) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/assets/console.js", get(script))
        .route("/assets/console.css", get(style))
        .route("/api/v1/console", get(describe))
        .with_state(console)
}

/// Les en-têtes de sécurité, sur toutes les réponses (UI-UX §6.3).
pub async fn security_headers(req: Request<axum::body::Body>, next: Next) -> Response {
    let mut res = next.run(req).await;
    let h = res.headers_mut();
    h.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(CONTENT_SECURITY_POLICY),
    );
    h.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    h.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    h.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    h.insert(
        "cross-origin-opener-policy",
        HeaderValue::from_static("same-origin"),
    );
    h.insert(
        "permissions-policy",
        HeaderValue::from_static("camera=(), microphone=(), geolocation=(), payment=()"),
    );
    // Rien de ce que sert la console ne doit rester dans un cache partagé
    // (réponses d'API comprises : identité, files, corps à signer).
    h.entry(header::CACHE_CONTROL)
        .or_insert(HeaderValue::from_static("no-store"));
    res
}

async fn index() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        INDEX_HTML,
    )
}

async fn script() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/javascript; charset=utf-8")],
        CONSOLE_JS,
    )
}

async fn style() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/css; charset=utf-8")],
        CONSOLE_CSS,
    )
}

/// `GET /api/v1/console` : l'environnement et la version, sans session — la
/// bannière doit s'afficher dès l'écran de connexion.
async fn describe(State(console): State<Console>) -> impl IntoResponse {
    Json(serde_json::json!({
        "environment": console.environment.as_str(),
        "version": env!("CARGO_PKG_VERSION"),
    }))
}
