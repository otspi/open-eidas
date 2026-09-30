//! `GET /api/v1/operators` (docs/WEBUI.md §10, §15 étape 6e) : le registre des
//! opérateurs, leurs clés et les clés en attente de confirmation, en lecture
//! seule sur les tables de `ca-server`. Toute écriture passe par une action
//! signée (`registry_routes`).
//!
//! L'empreinte d'une clé en attente est recalculée ici avec la fonction même
//! de `ca-server` (`oe_actions::key_fingerprint`) : l'administrateur la compare
//! hors bande à celle que l'invité a reçue à l'enregistrement (§10), puis la
//! signe ; `ca-server` la recompare à la clé stockée. Une console qui
//! afficherait une autre empreinte ferait échouer la confirmation, pas passer
//! une autre clé.

use oe_webauthn::Uuid;
use serde::Serialize;
use sqlx::{PgPool, Row};
use time::OffsetDateTime;

#[derive(Debug, Serialize)]
pub struct Credential {
    pub credential_id: String,
    pub label: String,
    #[serde(with = "time::serde::rfc3339")]
    pub initiated_at: OffsetDateTime,
    pub confirmed_by: Option<String>,
    #[serde(with = "time::serde::rfc3339::option")]
    pub last_used_at: Option<OffsetDateTime>,
    #[serde(with = "time::serde::rfc3339::option")]
    pub revoked_at: Option<OffsetDateTime>,
}

#[derive(Debug, Serialize)]
pub struct Operator {
    pub name: String,
    pub role: String,
    pub disabled: bool,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    pub credentials: Vec<Credential>,
}

#[derive(Debug, Serialize)]
pub struct PendingKey {
    pub credential_id: String,
    pub operator: String,
    /// `None` si la clé stockée ne se relit pas : rien à confirmer alors.
    pub key_fingerprint: Option<String>,
    #[serde(with = "time::serde::rfc3339")]
    pub registered_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub expires_at: OffsetDateTime,
}

#[derive(Debug, Serialize)]
pub struct Registry {
    pub operators: Vec<Operator>,
    pub pending: Vec<PendingKey>,
}

pub async fn list(pool: &PgPool, now: OffsetDateTime) -> Result<Registry, sqlx::Error> {
    let ops =
        sqlx::query("SELECT id, name, role, created_at, disabled_at FROM operators ORDER BY name")
            .fetch_all(pool)
            .await?;
    let creds = sqlx::query(
        "SELECT credential_id, operator_id, label, initiated_at, confirmed_by, last_used_at, revoked_at
         FROM webauthn_credentials ORDER BY initiated_at",
    )
    .fetch_all(pool)
    .await?;
    let operators = ops
        .iter()
        .map(|o| {
            let id: Uuid = o.get("id");
            Operator {
                name: o.get("name"),
                role: o.get("role"),
                disabled: o.get::<Option<OffsetDateTime>, _>("disabled_at").is_some(),
                created_at: o.get("created_at"),
                credentials: creds
                    .iter()
                    .filter(|c| c.get::<Uuid, _>("operator_id") == id)
                    .map(|c| Credential {
                        credential_id: c.get("credential_id"),
                        label: c.get("label"),
                        initiated_at: c.get("initiated_at"),
                        confirmed_by: c.get("confirmed_by"),
                        last_used_at: c.get("last_used_at"),
                        revoked_at: c.get("revoked_at"),
                    })
                    .collect(),
            }
        })
        .collect();

    let pending = sqlx::query(
        "SELECT p.credential_id, o.name, p.passkey, p.registered_at, p.expires_at
         FROM pending_credentials p JOIN operators o ON o.id = p.operator_id
         WHERE p.expires_at > $1
         ORDER BY p.registered_at",
    )
    .bind(now)
    .fetch_all(pool)
    .await?
    .iter()
    .map(|p| {
        let passkey: serde_json::Value = p.get("passkey");
        PendingKey {
            credential_id: p.get("credential_id"),
            operator: p.get("name"),
            key_fingerprint: serde_json::from_value::<oe_webauthn::AttestedPasskey>(passkey)
                .ok()
                .and_then(|k| oe_actions::key_fingerprint(&k).ok()),
            registered_at: p.get("registered_at"),
            expires_at: p.get("expires_at"),
        }
    })
    .collect();
    Ok(Registry { operators, pending })
}
