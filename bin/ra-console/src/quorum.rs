//! Salle d'attente des actions à plusieurs signatures (docs/WEBUI.md §8, §15
//! étape 4b), en lecture seule sur les tables de `ca-server`.
//!
//! Le §8 prévoyait des tables de collecte propres à la console, qui auraient
//! conservé les assertions jusqu'au seuil. Ce n'est pas ce qui est construit :
//! `ca-server` enregistre chaque signature au fil de l'eau (`decision_evidence`)
//! et n'exécute qu'au seuil. La console lit donc l'état qui fait foi, sans en
//! tenir de copie qui pourrait diverger, et ne garde jamais d'assertion.

use oe_webauthn::Uuid;
use serde::Serialize;
use sqlx::{PgPool, Row};
use time::OffsetDateTime;

/// Une action figée par `ca-server`, telle que la route de signature en a
/// besoin pour dire ce qu'elle attend (`expect`).
pub struct Frozen {
    pub body: serde_json::Value,
    pub executed: bool,
}

/// Une action en attente de signatures, pour l'affichage (« 1 signature sur
/// 2 »). Le seuil qui fait foi reste celui de la politique de `ca-server`,
/// relu à l'exécution.
#[derive(Serialize)]
pub struct Pending {
    pub action_id: Uuid,
    pub action: String,
    /// Le corps figé, à afficher tel quel à qui va co-signer (WYSIWYS).
    pub body: serde_json::Value,
    pub body_hash: String,
    pub required: i32,
    pub signatures: usize,
    /// Qui a déjà signé, lu dans le registre de `ca-server`.
    pub signed_by: Vec<String>,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub expires_at: OffsetDateTime,
}

pub async fn frozen(pool: &PgPool, id: Uuid) -> Result<Option<Frozen>, sqlx::Error> {
    let row = sqlx::query("SELECT body, executed_at FROM actions WHERE id = $1")
        .bind(id)
        .fetch_optional(pool)
        .await?;
    Ok(row.map(|r| Frozen {
        body: r.get("body"),
        executed: r.get::<Option<OffsetDateTime>, _>("executed_at").is_some(),
    }))
}

/// Les actions à plusieurs signatures ni exécutées ni expirées, des plus
/// anciennes aux plus récentes.
pub async fn pending(pool: &PgPool, now: OffsetDateTime) -> Result<Vec<Pending>, sqlx::Error> {
    let rows = sqlx::query(
        "SELECT a.id, a.body, a.body_hash, a.required_signatures, a.created_at, a.expires_at,
                COALESCE(array_agg(o.name ORDER BY e.verified_at)
                         FILTER (WHERE o.name IS NOT NULL), '{}') AS signed_by
         FROM actions a
         LEFT JOIN decision_evidence e ON e.action_id = a.id
         LEFT JOIN operators o ON o.id = e.operator_id
         WHERE a.executed_at IS NULL AND a.expires_at > $1 AND a.required_signatures > 1
         GROUP BY a.id
         ORDER BY a.created_at",
    )
    .bind(now)
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|r| {
            let body: serde_json::Value = r.get("body");
            let signed_by: Vec<String> = r.get("signed_by");
            let hash: Vec<u8> = r.get("body_hash");
            Pending {
                action_id: r.get("id"),
                action: body
                    .get("action")
                    .and_then(|a| a.as_str())
                    .unwrap_or_default()
                    .to_string(),
                body,
                body_hash: hash.iter().map(|b| format!("{b:02x}")).collect(),
                required: r.get("required_signatures"),
                signatures: signed_by.len(),
                signed_by,
                created_at: r.get("created_at"),
                expires_at: r.get("expires_at"),
            }
        })
        .collect())
}
