//! Dossiers d'incident (docs/WEBUI.md §6, §15 étape 5a) : ouverture et lecture.
//!
//! Un dossier est une structure d'imputabilité, pas un pouvoir : il regroupe
//! et justifie, il ne décide de rien sur la PKI. C'est pourquoi `ca-server`
//! n'en voit rien passer, et pourquoi **ce module contrôle lui-même le rôle**
//! de qui écrit — à la différence des autres contrôles de rôle de la console,
//! qui ne sont qu'un affichage (§3).
//!
//! Le journal d'abord : l'ouverture est consignée dans la chaîne de la console
//! avant que le dossier n'existe en base, et n'a pas lieu si le journal refuse.

use oe_actions::Role;
use oe_webauthn::Uuid;
use serde::Serialize;
use sqlx::{PgPool, Row};
use time::OffsetDateTime;

use crate::audit::{self, JournalError, Recorder};
use crate::session::Authenticated;

/// Les deux états d'un dossier (contrainte `CHECK` de la table).
pub const STATES: &[&str] = &["OUVERT", "CLOS"];

/// Assez pour nommer un incident, pas pour y ranger son récit.
pub const MAX_TITLE_CHARS: usize = 200;

#[derive(Debug, Serialize)]
pub struct Incident {
    pub id: Uuid,
    pub title: String,
    pub state: String,
    pub opened_by: String,
    #[serde(with = "time::serde::rfc3339")]
    pub opened_at: OffsetDateTime,
    pub closed_by: Option<String>,
    #[serde(with = "time::serde::rfc3339::option")]
    pub closed_at: Option<OffsetDateTime>,
    pub closing_note: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Le rôle de la session ne permet pas d'écrire dans un dossier.
    #[error("rôle insuffisant")]
    Forbidden,
    #[error("titre invalide")]
    InvalidTitle,
    #[error(transparent)]
    Journal(#[from] JournalError),
    #[error(transparent)]
    Database(#[from] sqlx::Error),
}

/// Qui ouvre et fait évoluer un dossier (§3) : `ra_operateur`, et
/// `ca_operateur` qui fait tout ce que fait `ra_operateur`. Ni `auditeur`
/// (lecture seule), ni `admin` (qui gère le registre, rien d'autre).
pub fn may_write(role: Role) -> bool {
    matches!(role, Role::RaOperateur | Role::CaOperateur)
}

/// Le titre tel qu'il sera rangé : sans blancs autour, non vide, borné, sans
/// caractère de contrôle.
fn clean_title(raw: &str) -> Option<&str> {
    let title = raw.trim();
    let ok = !title.is_empty()
        && title.chars().count() <= MAX_TITLE_CHARS
        && !title.chars().any(char::is_control);
    ok.then_some(title)
}

fn from_row(r: &sqlx::postgres::PgRow) -> Incident {
    Incident {
        id: r.get("id"),
        title: r.get("title"),
        state: r.get("state"),
        opened_by: r.get("opened_by"),
        opened_at: r.get("opened_at"),
        closed_by: r.get("closed_by"),
        closed_at: r.get("closed_at"),
        closing_note: r.get("closing_note"),
    }
}

const COLUMNS: &str = "id, title, state, opened_by, opened_at, closed_by, closed_at, closing_note";

/// Ouvre un dossier au nom de l'opérateur de la session — jamais d'un nom venu
/// du navigateur.
pub async fn open(
    pool: &PgPool,
    journal: &dyn Recorder,
    who: &Authenticated,
    title: &str,
    now: OffsetDateTime,
) -> Result<Incident, Error> {
    if !may_write(who.role) {
        return Err(Error::Forbidden);
    }
    let title = clean_title(title).ok_or(Error::InvalidTitle)?;
    let id = Uuid::new_v4();
    journal.record(
        audit::EVENT_INCIDENT_OPENED,
        serde_json::json!({
            "incident_id": id,
            "title": title,
            "operator": who.operator,
        }),
    )?;
    let row = sqlx::query(&format!(
        "INSERT INTO incidents (id, title, opened_by, opened_at)
         VALUES ($1, $2, $3, $4)
         RETURNING {COLUMNS}"
    ))
    .bind(id)
    .bind(title)
    .bind(&who.operator)
    .bind(now)
    .fetch_one(pool)
    .await?;
    Ok(from_row(&row))
}

/// Les dossiers, les plus récents d'abord ; filtrés par état si demandé. À
/// l'appelant de confronter `state` à [`STATES`].
pub async fn list(pool: &PgPool, state: Option<&str>) -> Result<Vec<Incident>, sqlx::Error> {
    let rows = match state {
        Some(s) => {
            sqlx::query(&format!(
                "SELECT {COLUMNS} FROM incidents \
                 WHERE state = $1 ORDER BY opened_at DESC, id"
            ))
            .bind(s)
            .fetch_all(pool)
            .await?
        }
        None => {
            sqlx::query(&format!(
                "SELECT {COLUMNS} FROM incidents ORDER BY opened_at DESC, id"
            ))
            .fetch_all(pool)
            .await?
        }
    };
    Ok(rows.iter().map(from_row).collect())
}

pub async fn get(pool: &PgPool, id: Uuid) -> Result<Option<Incident>, sqlx::Error> {
    let row = sqlx::query(&format!("SELECT {COLUMNS} FROM incidents WHERE id = $1"))
        .bind(id)
        .fetch_optional(pool)
        .await?;
    Ok(row.as_ref().map(from_row))
}
