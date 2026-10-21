//! Lecture seule de la file d'enrôlement (docs/WEBUI.md §5, §15 étape 2a) :
//! `GET /api/v1/requests`, aucun aller-retour vers `ca-server`. `ra-console`
//! lit directement `enrollment_requests`, table dont elle n'a que la lecture
//! (`ra_console_grants.sql`) — décider (`approve`/`reject`) restera une
//! écriture relayée à `ca-server` (étape 3, pas encore faite).

use serde::Serialize;
use sqlx::{PgPool, Row};
use time::OffsetDateTime;

/// Les quatre états possibles d'une demande (`oe_castore::RequestState`,
/// dupliqué ici en chaîne plutôt qu'en dépendance : `ra-console` ne lit que
/// des colonnes, elle n'a besoin d'aucun type de `ca-server`).
pub const STATES: &[&str] = &["PENDING", "APPROVED", "ISSUED", "REJECTED"];

#[derive(Debug, Serialize)]
pub struct EnrollmentRequest {
    pub transaction_id: String,
    /// Empreinte de la CSR, que l'opérateur compare avec le demandeur avant
    /// d'approuver (constat A-1, WEBUI §11).
    pub csr_fingerprint: String,
    pub profile: String,
    pub subject_cn: String,
    pub state: String,
    /// Vide tant que la demande est `PENDING` (contrainte
    /// `decision_imputable` de `ca-server`) : `None` plutôt qu'une chaîne
    /// vide, plus honnête pour un client JSON.
    pub operator: Option<String>,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339::option")]
    pub decided_at: Option<OffsetDateTime>,
    pub certificate_serial_hex: Option<String>,
}

fn from_row(r: &sqlx::postgres::PgRow) -> EnrollmentRequest {
    let operator: String = r.get("operator");
    EnrollmentRequest {
        transaction_id: r.get("transaction_id"),
        csr_fingerprint: r.get("csr_fingerprint"),
        profile: r.get("profile"),
        subject_cn: r.get("subject_cn"),
        state: r.get("state"),
        operator: (!operator.is_empty()).then_some(operator),
        created_at: r.get("created_at"),
        decided_at: r.get("decided_at"),
        certificate_serial_hex: r.get("certificate_serial_hex"),
    }
}

const COLUMNS: &str =
    "transaction_id, csr_fingerprint, profile, subject_cn, state, operator, created_at, decided_at, certificate_serial_hex";

/// Les demandes, les plus récentes d'abord ; filtrées par état si demandé.
/// `state` n'est pas revalidé ici : à l'appelant de le confronter à
/// [`STATES`] avant d'appeler (une valeur inconnue ne rendrait de toute
/// façon aucune ligne, la colonne porte sa propre contrainte `CHECK`).
pub async fn list(
    pool: &PgPool,
    state: Option<&str>,
) -> Result<Vec<EnrollmentRequest>, sqlx::Error> {
    let rows = match state {
        Some(s) => {
            sqlx::query(&format!(
                "SELECT {COLUMNS} FROM enrollment_requests \
                 WHERE state = $1 ORDER BY created_at DESC, transaction_id"
            ))
            .bind(s)
            .fetch_all(pool)
            .await?
        }
        None => {
            sqlx::query(&format!(
                "SELECT {COLUMNS} FROM enrollment_requests \
                 ORDER BY created_at DESC, transaction_id"
            ))
            .fetch_all(pool)
            .await?
        }
    };
    Ok(rows.iter().map(from_row).collect())
}
