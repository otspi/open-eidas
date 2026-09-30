//! Sessions HTTP de `ra-console` (docs/WEBUI.md §15 étape 1c-2, §16).
//!
//! Le cookie ne porte que `sessions.id` (256 bits, tirés du système) : ce
//! n'est pas un jeton auto-porteur, il ne prouve rien par lui-même — l'identité
//! et le rôle sont relus dans le registre à **chaque** requête, jamais mis en
//! cache dans la session. Une session n'est pas une ancre de confiance : elle
//! authentifie qui parle à la console, `ca-server` re-vérifie lui-même chaque
//! action signée (§16).
//!
//! Durée **fixe** de 8 heures, jamais prolongée (pas de fenêtre glissante) :
//! une session active depuis 8 heures se termine, un nouveau login est
//! nécessaire. Révocable côté serveur (`revoked_at`), contrairement à un JWT
//! auto-porteur qu'on ne peut pas rappeler.

use std::sync::Arc;

use oe_actions::{Registry, Role};
use oe_webauthn::Uuid;
use rand::RngCore;
use sqlx::Row;
use time::OffsetDateTime;

use crate::audit::{self, Recorder};

pub const SESSION_TTL: time::Duration = time::Duration::hours(8);

/// Nom du cookie et du champ qu'il porte : rien d'autre que cet identifiant
/// opaque n'y est jamais placé.
pub const COOKIE_NAME: &str = "session";

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SessionError {
    /// Absente, expirée, révoquée, ou l'opérateur qu'elle désigne est
    /// désactivé depuis : une seule forme, pour ne rien laisser deviner.
    #[error("session invalide")]
    Invalid,
}

/// Une session authentifiée, relue en base à l'instant de l'appel.
pub struct Authenticated {
    /// Identifiant de l'opérateur dans le registre : ce qu'une route relaie à
    /// `ca-server` (`operator_hint`), jamais une valeur venue du navigateur.
    pub operator_id: Uuid,
    pub operator: String,
    pub role: Role,
}

pub struct Sessions {
    registry: Registry,
    journal: Arc<dyn Recorder>,
}

impl Sessions {
    pub fn new(registry: Registry, journal: Arc<dyn Recorder>) -> Sessions {
        Sessions { registry, journal }
    }

    /// Ouvre une session pour l'identité que `login::LoginService::finish` (ou
    /// un premier enregistrement de clé) vient de vérifier. Rend l'identifiant
    /// à poser en cookie — jamais journalisé, jamais renvoyé au delà de ce
    /// cookie.
    pub async fn create(
        &self,
        operator_id: Uuid,
        credential_id: &str,
    ) -> Result<String, sqlx::Error> {
        let mut raw = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut raw);
        let id = oe_actions::credential_id(&raw);
        let now = OffsetDateTime::now_utc();
        sqlx::query(
            "INSERT INTO sessions
               (id, operator_id, credential_id, created_at, last_seen_at, expires_at)
             VALUES ($1, $2, $3, $4, $4, $5)",
        )
        .bind(&id)
        .bind(operator_id)
        .bind(credential_id)
        .bind(now)
        .bind(now + SESSION_TTL)
        .execute(self.registry.pool())
        .await?;
        self.journal.append(
            audit::EVENT_SESSION_OPENED,
            serde_json::json!({ "credential_id": credential_id }),
        );
        Ok(id)
    }

    /// Authentifie une requête par son cookie de session. Relit l'identité et
    /// le rôle en base à chaque appel (§16) : un rôle retiré ou un opérateur
    /// désactivé après l'ouverture de la session ferme l'accès sans attendre
    /// son expiration.
    pub async fn authenticate(&self, session_id: &str) -> Result<Authenticated, SessionError> {
        let now = OffsetDateTime::now_utc();
        let row = sqlx::query(
            "SELECT operator_id FROM sessions
             WHERE id = $1 AND revoked_at IS NULL AND expires_at > $2",
        )
        .bind(session_id)
        .bind(now)
        .fetch_optional(self.registry.pool())
        .await
        .map_err(|_| SessionError::Invalid)?
        .ok_or(SessionError::Invalid)?;
        let operator_id: Uuid = row.get("operator_id");
        let operator = self
            .registry
            .operator(operator_id)
            .await
            .map_err(|_| SessionError::Invalid)?
            .ok_or(SessionError::Invalid)?;
        if operator.disabled {
            return Err(SessionError::Invalid);
        }
        // Best-effort : une écriture manquée ici ne remet pas en cause
        // l'authentification qu'on vient d'établir.
        let _ = sqlx::query("UPDATE sessions SET last_seen_at = $2 WHERE id = $1")
            .bind(session_id)
            .bind(now)
            .execute(self.registry.pool())
            .await;
        Ok(Authenticated {
            operator_id: operator.id,
            operator: operator.name,
            role: operator.role,
        })
    }

    /// Déconnexion : révoque la session sans attendre son expiration.
    /// Idempotent (une session déjà révoquée ou inconnue ne fait pas échouer
    /// la déconnexion : le résultat visible, absence de session, est le même).
    pub async fn revoke(&self, session_id: &str) -> Result<(), sqlx::Error> {
        let done =
            sqlx::query("UPDATE sessions SET revoked_at = $2 WHERE id = $1 AND revoked_at IS NULL")
                .bind(session_id)
                .bind(OffsetDateTime::now_utc())
                .execute(self.registry.pool())
                .await?;
        // Seulement si cet appel a réellement clos une session : sinon, une
        // déconnexion rejouée ou d'un cookie déjà expiré grossirait le
        // journal sans qu'il ne se soit rien passé.
        if done.rows_affected() > 0 {
            self.journal
                .append(audit::EVENT_SESSION_CLOSED, serde_json::json!({}));
        }
        Ok(())
    }
}
