//! `GET /api/v1/certificates` (docs/WEBUI.md §5, §15 étape 6c) : les
//! certificats émis, en lecture seule sur la table de `ca-server`, pour que
//! l'opérateur choisisse ce qu'il révoque. Les certificats réservés (numéro
//! tiré, émission non aboutie) n'y figurent pas.

use serde::Serialize;
use sqlx::{PgPool, Row};
use time::OffsetDateTime;

/// Les états qu'un filtre peut demander.
pub const STATUSES: &[&str] = &["issued", "revoked"];

#[derive(Debug, Serialize)]
pub struct IssuedCertificate {
    /// Hexadécimal minuscule : la forme canonique qu'attend la révocation.
    pub serial_hex: String,
    pub profile: String,
    pub subject_dn: String,
    #[serde(with = "time::serde::rfc3339::option")]
    pub not_before: Option<OffsetDateTime>,
    #[serde(with = "time::serde::rfc3339::option")]
    pub not_after: Option<OffsetDateTime>,
    pub status: String,
    #[serde(with = "time::serde::rfc3339::option")]
    pub revoked_at: Option<OffsetDateTime>,
    pub revocation_reason: i32,
    pub request_transaction_id: String,
}

/// Les certificats émis ou révoqués, les plus récents d'abord ; filtrés par
/// état si demandé. `status` n'est pas revalidé ici : à l'appelant de le
/// confronter à [`STATUSES`].
pub async fn list(
    pool: &PgPool,
    status: Option<&str>,
) -> Result<Vec<IssuedCertificate>, sqlx::Error> {
    let rows = sqlx::query(
        "SELECT serial_hex, profile, subject_dn, not_before, not_after, status, revoked_at,
                revocation_reason, request_transaction_id
         FROM certificates
         WHERE status <> 'reserved' AND ($1::text IS NULL OR status = $1)
         ORDER BY not_before DESC NULLS LAST, serial_hex
         LIMIT 1000",
    )
    .bind(status)
    .fetch_all(pool)
    .await?;
    Ok(rows
        .iter()
        .map(|r| IssuedCertificate {
            serial_hex: r.get("serial_hex"),
            profile: r.get("profile"),
            subject_dn: r.get("subject_dn"),
            not_before: r.get("not_before"),
            not_after: r.get("not_after"),
            status: r.get("status"),
            revoked_at: r.get("revoked_at"),
            revocation_reason: r.get("revocation_reason"),
            request_transaction_id: r.get("request_transaction_id"),
        })
        .collect())
}
