//! Dossiers d'incident (docs/WEBUI.md §6, §15 étape 5) : ouverture, lecture,
//! notes et références d'actions, clôture.
//!
//! Un dossier est une structure d'imputabilité, pas un pouvoir : il regroupe
//! et justifie, il ne décide de rien sur la PKI. C'est pourquoi `ca-server`
//! n'en voit rien passer, et pourquoi **ce module contrôle lui-même le rôle**
//! de qui écrit — à la différence des autres contrôles de rôle de la console,
//! qui ne sont qu'un affichage (§3).
//!
//! Le journal d'abord : chaque écriture est consignée dans la chaîne de la
//! console avant d'exister en base, et n'a pas lieu si le journal refuse.
//!
//! Un dossier **désigne** des actions, il n'en déclenche aucune : une
//! révocation passe par sa propre route, que `ca-server` juge ; le dossier en
//! garde ensuite l'identifiant et l'empreinte du corps figé, relus dans la
//! table `actions`.
//!
//! La clôture est signée : l'opérateur réaffirme, avec sa clé, le corps exact
//! qui lui est montré (dossier, note de clôture, son nom). La console vérifie
//! elle-même cette assertion et la conserve avec le dossier
//! (`incident_closures`).

use oe_actions::Role;
use oe_webauthn::{PublicKeyCredential, RequestChallengeResponse, Uuid};
use serde::Serialize;
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Row};
use time::OffsetDateTime;

use crate::audit::{self, JournalError, Recorder};
use crate::login::{LoginService, ReassertError, KIND_INCIDENT_CLOSE};
use crate::session::Authenticated;

/// Les deux états d'un dossier (contrainte `CHECK` de la table).
pub const STATES: &[&str] = &["OUVERT", "CLOS"];

/// Assez pour nommer un incident, pas pour y ranger son récit.
pub const MAX_TITLE_CHARS: usize = 200;

/// Une note, un commentaire de rattachement ou une note de clôture.
pub const MAX_TEXT_CHARS: usize = 2000;

/// Les deux sortes d'entrées d'un dossier (contrainte `CHECK` de la table).
pub const KIND_NOTE: &str = "note";
pub const KIND_LINKED_ACTION: &str = "action_liee";

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
    #[error("texte invalide")]
    InvalidText,
    #[error("dossier inconnu")]
    UnknownIncident,
    /// Rien ne s'ajoute à un dossier clos, et il ne se clôt qu'une fois.
    #[error("dossier clos")]
    Closed,
    #[error("action inconnue")]
    UnknownAction,
    #[error("action déjà rattachée à ce dossier")]
    AlreadyLinked,
    #[error("aucune clé active")]
    NoKey,
    /// L'assertion de clôture est refusée (raison au journal).
    #[error("assertion refusée")]
    InvalidAssertion,
    /// Le challenge présenté a été émis pour un autre dossier.
    #[error("challenge émis pour un autre dossier")]
    ChallengeMismatch,
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

/// Un texte libre tel qu'il sera rangé : sans blancs autour, borné, sans
/// caractère de contrôle autre que le saut de ligne et la tabulation.
fn clean_text(raw: &str) -> Option<&str> {
    let text = raw.trim();
    let ok = text.chars().count() <= MAX_TEXT_CHARS
        && !text
            .chars()
            .any(|c| c.is_control() && c != '\n' && c != '\t');
    ok.then_some(text)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Vrai si l'erreur vient de la contrainte nommée (contrainte ou déclencheur).
fn violates(e: &sqlx::Error, constraint: &str) -> bool {
    e.as_database_error()
        .and_then(|d| d.constraint())
        .is_some_and(|c| c == constraint)
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

/// Une entrée d'un dossier : une note, ou la référence d'une action figée.
#[derive(Debug, Serialize)]
pub struct Entry {
    pub id: Uuid,
    #[serde(with = "time::serde::rfc3339")]
    pub at: OffsetDateTime,
    pub operator: String,
    pub kind: String,
    pub detail: String,
    /// Pour une action rattachée : son identifiant et l'empreinte de son corps
    /// figé, recopiée de `actions` au moment du rattachement.
    pub action_id: Option<Uuid>,
    pub body_hash: Option<String>,
    /// Son nom (`revoke_certificate`…) et son état, relus chez `ca-server`.
    pub action: Option<String>,
    pub executed: Option<bool>,
}

/// La preuve d'une clôture, telle qu'elle est conservée.
#[derive(Debug, Serialize)]
pub struct Closure {
    pub credential_id: String,
    /// Le corps exact que l'assertion couvre, et son empreinte.
    pub body: String,
    pub body_hash: String,
    #[serde(with = "time::serde::rfc3339")]
    pub verified_at: OffsetDateTime,
}

/// Un dossier complet : ce qu'il est, ce qu'on y a consigné, et sa clôture.
#[derive(Debug, Serialize)]
pub struct Detail {
    #[serde(flatten)]
    pub incident: Incident,
    pub actions: Vec<Entry>,
    pub closure: Option<Closure>,
}

pub async fn detail(pool: &PgPool, id: Uuid) -> Result<Option<Detail>, sqlx::Error> {
    let Some(incident) = get(pool, id).await? else {
        return Ok(None);
    };
    let rows = sqlx::query(
        "SELECT e.id, e.at, e.operator, e.kind, e.detail, e.action_id, e.body_hash,
                a.body->>'action' AS action, a.executed_at
         FROM incident_actions e
         LEFT JOIN actions a ON a.id = e.action_id
         WHERE e.incident_id = $1
         ORDER BY e.at, e.id",
    )
    .bind(id)
    .fetch_all(pool)
    .await?;
    let actions = rows
        .iter()
        .map(|r| {
            let action_id: Option<Uuid> = r.get("action_id");
            let body_hash: Option<Vec<u8>> = r.get("body_hash");
            let executed_at: Option<OffsetDateTime> = r.get("executed_at");
            Entry {
                id: r.get("id"),
                at: r.get("at"),
                operator: r.get("operator"),
                kind: r.get("kind"),
                detail: r.get("detail"),
                action_id,
                body_hash: body_hash.as_deref().map(hex),
                action: r.get("action"),
                executed: action_id.map(|_| executed_at.is_some()),
            }
        })
        .collect();
    let closure = sqlx::query(
        "SELECT credential_id, body, body_hash, verified_at
         FROM incident_closures WHERE incident_id = $1",
    )
    .bind(id)
    .fetch_optional(pool)
    .await?
    .map(|r| Closure {
        credential_id: r.get("credential_id"),
        body: r.get("body"),
        body_hash: hex(&r.get::<Vec<u8>, _>("body_hash")),
        verified_at: r.get("verified_at"),
    });
    Ok(Some(Detail {
        incident,
        actions,
        closure,
    }))
}

/// Le dossier, pour y écrire : il existe et il est ouvert, et le rôle de la
/// session le permet.
async fn writable(pool: &PgPool, who: &Authenticated, id: Uuid) -> Result<Incident, Error> {
    if !may_write(who.role) {
        return Err(Error::Forbidden);
    }
    let incident = get(pool, id).await?.ok_or(Error::UnknownIncident)?;
    if incident.state != "OUVERT" {
        return Err(Error::Closed);
    }
    Ok(incident)
}

/// Une écriture refusée par la base parce que le dossier s'est clos entre
/// temps (déclencheur `incident_actions_only_while_open`).
fn closed_meanwhile(e: sqlx::Error) -> Error {
    if violates(&e, "incident_open") {
        Error::Closed
    } else {
        Error::Database(e)
    }
}

/// Consigne une note dans un dossier ouvert.
pub async fn add_note(
    pool: &PgPool,
    journal: &dyn Recorder,
    who: &Authenticated,
    incident_id: Uuid,
    text: &str,
    now: OffsetDateTime,
) -> Result<Entry, Error> {
    writable(pool, who, incident_id).await?;
    let text = clean_text(text)
        .filter(|t| !t.is_empty())
        .ok_or(Error::InvalidText)?;
    let id = Uuid::new_v4();
    journal.record(
        audit::EVENT_INCIDENT_ACTION,
        serde_json::json!({
            "incident_id": incident_id,
            "entry_id": id,
            "kind": KIND_NOTE,
            "operator": who.operator,
            "detail": text,
        }),
    )?;
    sqlx::query(
        "INSERT INTO incident_actions (id, incident_id, at, operator, kind, detail)
         VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(id)
    .bind(incident_id)
    .bind(now)
    .bind(&who.operator)
    .bind(KIND_NOTE)
    .bind(text)
    .execute(pool)
    .await
    .map_err(closed_meanwhile)?;
    Ok(Entry {
        id,
        at: now,
        operator: who.operator.clone(),
        kind: KIND_NOTE.to_string(),
        detail: text.to_string(),
        action_id: None,
        body_hash: None,
        action: None,
        executed: None,
    })
}

/// Rattache à un dossier ouvert une action que `ca-server` a figée : elle doit
/// exister, et c'est l'empreinte de **son** corps qui est recopiée — jamais
/// une valeur de l'appelant. Le dossier n'exécute rien.
pub async fn link_action(
    pool: &PgPool,
    journal: &dyn Recorder,
    who: &Authenticated,
    incident_id: Uuid,
    action_id: Uuid,
    comment: &str,
    now: OffsetDateTime,
) -> Result<Entry, Error> {
    writable(pool, who, incident_id).await?;
    let comment = clean_text(comment).ok_or(Error::InvalidText)?;
    let action = sqlx::query(
        "SELECT body->>'action' AS action, body_hash, executed_at FROM actions WHERE id = $1",
    )
    .bind(action_id)
    .fetch_optional(pool)
    .await?
    .ok_or(Error::UnknownAction)?;
    let name: Option<String> = action.get("action");
    let body_hash: Vec<u8> = action.get("body_hash");
    let executed_at: Option<OffsetDateTime> = action.get("executed_at");

    let id = Uuid::new_v4();
    journal.record(
        audit::EVENT_INCIDENT_ACTION,
        serde_json::json!({
            "incident_id": incident_id,
            "entry_id": id,
            "kind": KIND_LINKED_ACTION,
            "operator": who.operator,
            "action_id": action_id,
            "action": name,
            "body_hash": hex(&body_hash),
            "detail": comment,
        }),
    )?;
    sqlx::query(
        "INSERT INTO incident_actions
           (id, incident_id, at, operator, kind, action_id, body_hash, detail)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
    )
    .bind(id)
    .bind(incident_id)
    .bind(now)
    .bind(&who.operator)
    .bind(KIND_LINKED_ACTION)
    .bind(action_id)
    .bind(&body_hash)
    .bind(comment)
    .execute(pool)
    .await
    .map_err(|e| {
        if violates(&e, "incident_actions_incident_id_action_id_key") {
            Error::AlreadyLinked
        } else {
            closed_meanwhile(e)
        }
    })?;
    Ok(Entry {
        id,
        at: now,
        operator: who.operator.clone(),
        kind: KIND_LINKED_ACTION.to_string(),
        detail: comment.to_string(),
        action_id: Some(action_id),
        body_hash: Some(hex(&body_hash)),
        action: name,
        executed: Some(executed_at.is_some()),
    })
}

/// Ce que l'opérateur va signer pour clore un dossier.
pub struct CloseChallenge {
    pub challenge_id: Uuid,
    pub options: RequestChallengeResponse,
    /// Le corps figé, à afficher tel quel (WYSIWYS), et son empreinte.
    pub body: String,
    pub body_hash: String,
}

/// Fige la clôture demandée et émet le challenge que l'opérateur de la session
/// signera avec sa clé. Rien n'est clos ici.
pub async fn begin_close(
    pool: &PgPool,
    login: &LoginService,
    who: &Authenticated,
    incident_id: Uuid,
    note: &str,
) -> Result<CloseChallenge, Error> {
    writable(pool, who, incident_id).await?;
    let note = clean_text(note)
        .filter(|n| !n.is_empty())
        .ok_or(Error::InvalidText)?;
    let body = serde_json::json!({
        "action": "close_incident",
        "incident_id": incident_id,
        "closing_note": note,
        "operator": who.operator,
    })
    .to_string();
    let begun = login
        .begin_reassertion(
            who.operator_id,
            KIND_INCIDENT_CLOSE,
            serde_json::json!({ "incident_id": incident_id, "body": body }),
        )
        .await
        .map_err(|e| match e {
            ReassertError::NoKey => Error::NoKey,
            ReassertError::Database(e) => Error::Database(e),
            ReassertError::Invalid | ReassertError::Mismatch => Error::InvalidAssertion,
        })?;
    Ok(CloseChallenge {
        challenge_id: begun.challenge_id,
        options: begun.options,
        body_hash: hex(&Sha256::digest(body.as_bytes())),
        body,
    })
}

/// Clôt un dossier sur l'assertion de l'opérateur de la session. Ce qui est
/// clos, et avec quelle note, vient du corps figé à l'émission du challenge —
/// jamais de la requête qui porte l'assertion. La preuve et la clôture sont
/// écrites ensemble, après le journal.
pub async fn close(
    pool: &PgPool,
    login: &LoginService,
    journal: &dyn Recorder,
    who: &Authenticated,
    incident_id: Uuid,
    challenge_id: Uuid,
    credential: &PublicKeyCredential,
) -> Result<Detail, Error> {
    writable(pool, who, incident_id).await?;
    let wanted = serde_json::json!(incident_id);
    let proof = login
        .finish_reassertion(
            challenge_id,
            who.operator_id,
            KIND_INCIDENT_CLOSE,
            credential,
            |frozen| frozen.get("incident_id") == Some(&wanted),
        )
        .await
        .map_err(|e| match e {
            ReassertError::Mismatch => Error::ChallengeMismatch,
            ReassertError::Database(e) => Error::Database(e),
            ReassertError::Invalid | ReassertError::NoKey => Error::InvalidAssertion,
        })?;
    let body = proof
        .frozen
        .get("body")
        .and_then(|b| b.as_str())
        .ok_or(Error::InvalidAssertion)?;
    let note = serde_json::from_str::<serde_json::Value>(body)
        .ok()
        .and_then(|b| b.get("closing_note")?.as_str().map(str::to_string))
        .ok_or(Error::InvalidAssertion)?;
    let body_hash = Sha256::digest(body.as_bytes()).to_vec();

    journal.record(
        audit::EVENT_INCIDENT_CLOSED,
        serde_json::json!({
            "incident_id": incident_id,
            "operator": who.operator,
            "credential_id": proof.credential_id,
            "closing_note": note,
            "body_hash": hex(&body_hash),
        }),
    )?;

    let now = OffsetDateTime::now_utc();
    let mut tx = pool.begin().await?;
    sqlx::query(
        "INSERT INTO incident_closures
           (incident_id, operator_id, credential_id, body, body_hash, challenge,
            authenticator_data, client_data_json, signature, verified_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
    )
    .bind(incident_id)
    .bind(who.operator_id)
    .bind(&proof.credential_id)
    .bind(body)
    .bind(&body_hash)
    .bind(&proof.challenge)
    .bind(&proof.authenticator_data)
    .bind(&proof.client_data_json)
    .bind(&proof.signature)
    .bind(now)
    .execute(&mut *tx)
    .await
    .map_err(|e| {
        if violates(&e, "incident_closures_pkey") {
            Error::Closed
        } else {
            Error::Database(e)
        }
    })?;
    let closed = sqlx::query(
        "UPDATE incidents
         SET state = 'CLOS', closed_by = $2, closed_at = $3, closing_note = $4
         WHERE id = $1 AND state = 'OUVERT'",
    )
    .bind(incident_id)
    .bind(&who.operator)
    .bind(now)
    .bind(&note)
    .execute(&mut *tx)
    .await?;
    if closed.rows_affected() != 1 {
        return Err(Error::Closed);
    }
    tx.commit().await?;
    detail(pool, incident_id)
        .await?
        .ok_or(Error::UnknownIncident)
}
