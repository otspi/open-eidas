//! Connexion par nom (docs/WEBUI.md §15 étape 1c, §16 « connexion par nom,
//! réponses uniformes »).
//!
//! `ra-console` vérifie elle-même l'assertion contre le registre en lecture
//! seule : une session n'est jamais une ancre de confiance, `ca-server`
//! re-vérifie chaque action (§16), mais la connexion elle-même n'a besoin
//! d'aucun aller-retour vers `ca-server`. `finish` prouve l'identité et met à
//! jour le compteur anti-clonage ; l'ouverture de la session elle-même (cookie,
//! `/api/v1/me`, déconnexion) est l'affaire de `crate::session`, à partir de
//! l'identité que ce module rend.
//!
//! Une seule erreur, `LoginError::Invalid`, sort de tout ce qui peut échouer
//! après `begin` : nom inconnu, clé factice, challenge périmé ou déjà
//! consommé, clé révoquée, opérateur désactivé, signature refusée, compteur en
//! régression. Les distinguer laisserait deviner lequel s'est produit.

use std::sync::Arc;

use hmac::{Hmac, Mac};
use oe_actions::{Registry, Role};
use oe_webauthn::{
    decoy_authentication_challenge, AttestedPasskeyAuthentication, PublicKeyCredential,
    RequestChallengeResponse, Uuid, Verifier,
};
use sha2::Sha256;
use sqlx::Row;
use time::OffsetDateTime;

use crate::audit::{self, Recorder};

/// Aligné sur la contrainte SQL `challenge_short_lived` (migration 0006) : un
/// challenge de connexion ne vit pas plus longtemps qu'un challenge d'action.
pub const CHALLENGE_TTL: time::Duration = time::Duration::minutes(5);

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum LoginError {
    /// Toute défaillance après `begin` : voir la documentation du module.
    #[error("identifiants invalides")]
    Invalid,
}

/// Une assertion refusée, déjà consignée au journal avec sa raison.
struct Refused;

/// Type de challenge d'une clôture de dossier d'incident (contrainte `CHECK`
/// de `webauthn_challenges.kind`, migration 0009).
pub const KIND_INCIDENT_CLOSE: &str = "incident_close";

#[derive(Debug, thiserror::Error)]
pub enum ReassertError {
    /// L'opérateur n'a aucune clé active avec laquelle signer.
    #[error("aucune clé active")]
    NoKey,
    /// Challenge inconnu, périmé, déjà consommé, d'un autre opérateur, ou
    /// assertion refusée : consigné au journal, jamais détaillé à l'appelant.
    #[error("assertion refusée")]
    Invalid,
    /// Le challenge existe mais porte sur autre chose que ce que l'appelant
    /// attend : il n'est pas consommé.
    #[error("le challenge ne porte pas sur cet objet")]
    Mismatch,
    #[error(transparent)]
    Database(#[from] sqlx::Error),
}

/// Une réassertion vérifiée : ce qui a été figé à l'émission du challenge, et
/// la preuve brute, à conserver telle quelle.
pub struct Reasserted {
    pub credential_id: String,
    pub frozen: serde_json::Value,
    pub challenge: Vec<u8>,
    pub authenticator_data: Vec<u8>,
    pub client_data_json: Vec<u8>,
    pub signature: Vec<u8>,
}

/// Ce que `login/begin` rend au navigateur.
pub struct Begun {
    pub challenge_id: Uuid,
    pub options: RequestChallengeResponse,
}

/// Identité vérifiée par `login/finish`. `operator_id` et `credential_id` :
/// de quoi ouvrir une session (1c-2, `crate::session`), sans que ce module
/// n'ait à connaître les sessions.
pub struct Verified {
    pub operator_id: Uuid,
    pub operator: String,
    pub role: Role,
    pub credential_id: String,
}

pub struct LoginService {
    registry: Registry,
    verifier: Verifier,
    decoy_secret: Vec<u8>,
    journal: Arc<dyn Recorder>,
}

impl LoginService {
    pub fn new(
        registry: Registry,
        verifier: Verifier,
        decoy_secret: Vec<u8>,
        journal: Arc<dyn Recorder>,
    ) -> LoginService {
        LoginService {
            registry,
            verifier,
            decoy_secret,
            journal,
        }
    }

    /// Consigne un refus dans le journal propre à `ra-console` (§7) avec sa
    /// vraie raison — jamais dans la réponse HTTP, uniforme (§16) — puis rend
    /// l'erreur à propager.
    fn refuse(&self, challenge_id: Uuid, reason: &str) -> LoginError {
        self.note_refusal(audit::EVENT_LOGIN_REFUSED, challenge_id, reason);
        LoginError::Invalid
    }

    fn note_refusal(&self, event: &str, challenge_id: Uuid, reason: &str) {
        self.journal.append(
            event,
            serde_json::json!({ "challenge_id": challenge_id.to_string(), "raison": reason }),
        );
    }

    /// Dérivé du nom et du secret du service : stable pour un même nom (une
    /// même requête reçoit toujours la même forme de réponse), imprévisible
    /// sans le secret. `HMAC-SHA256`, pas un simple hachage : le secret ne
    /// doit jouer aucun autre rôle qu'ici (pas de risque de confusion de
    /// domaine à défendre, mais c'est la construction de référence pour un
    /// MAC à clé).
    fn decoy_credential_id(&self, name: &str) -> Vec<u8> {
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.decoy_secret)
            .expect("HMAC-SHA256 accepte une clé de taille arbitraire");
        mac.update(name.as_bytes());
        mac.finalize().into_bytes().to_vec()
    }

    /// `login/begin {name}` : options WebAuthn de même forme que le nom
    /// existe ou non (docs/WEBUI.md §16). Un opérateur désactivé ou sans clé
    /// active reçoit lui aussi le leurre : il ne pourrait de toute façon pas
    /// se connecter, autant ne pas le distinguer d'un nom inconnu.
    pub async fn begin(&self, name: &str) -> Result<Begun, sqlx::Error> {
        let real = match self.registry.operator_by_name(name).await? {
            Some(op) if !op.disabled => {
                let keys = self.registry.active_keys(op.id).await?;
                if keys.is_empty() {
                    None
                } else {
                    Some((op.id, keys))
                }
            }
            _ => None,
        };

        let operator_id = real.as_ref().map(|(id, _)| *id);
        let (options, state) = match real {
            Some((_, keys)) => {
                let passkeys = keys.into_iter().map(|k| k.passkey).collect::<Vec<_>>();
                let (options, ast) = self
                    .verifier
                    .start_authentication(&passkeys)
                    .map_err(|e| sqlx::Error::Protocol(e.to_string()))?;
                (options, Some(ast))
            }
            None => {
                let decoy_id = self.decoy_credential_id(name);
                let options = decoy_authentication_challenge(self.verifier.rp_id(), &decoy_id);
                (options, None)
            }
        };

        let challenge_id = Uuid::new_v4();
        let now = OffsetDateTime::now_utc();
        let request_body = state
            .as_ref()
            .map(serde_json::to_value)
            .transpose()
            .map_err(|e| sqlx::Error::Encode(e.into()))?;
        sqlx::query(
            "INSERT INTO webauthn_challenges
               (id, kind, challenge, operator_id, request_body, created_at, expires_at)
             VALUES ($1, 'login', $2, $3, $4, $5, $6)",
        )
        .bind(challenge_id)
        .bind(options.public_key.challenge.as_ref())
        .bind(operator_id)
        .bind(request_body)
        .bind(now)
        .bind(now + CHALLENGE_TTL)
        .execute(self.registry.pool())
        .await?;

        Ok(Begun {
            challenge_id,
            options,
        })
    }

    /// `login/finish {challenge_id, credential}` : consomme le challenge
    /// (usage unique), vérifie l'assertion et met à jour le compteur
    /// anti-clonage (`login_counters`, jamais en régression une fois positif).
    pub async fn finish(
        &self,
        challenge_id: Uuid,
        credential: &PublicKeyCredential,
    ) -> Result<Verified, LoginError> {
        let row = sqlx::query(
            "UPDATE webauthn_challenges
             SET consumed_at = $2
             WHERE id = $1 AND kind = 'login' AND consumed_at IS NULL AND expires_at > $2
             RETURNING operator_id, request_body",
        )
        .bind(challenge_id)
        .bind(OffsetDateTime::now_utc())
        .fetch_optional(self.registry.pool())
        .await
        .map_err(|_| self.refuse(challenge_id, "base indisponible"))?
        .ok_or_else(|| self.refuse(challenge_id, "challenge inconnu, expiré ou déjà consommé"))?;

        // Un leurre n'a rien à vérifier : aucune assertion ne peut réussir.
        let operator_id: Option<Uuid> = row.get("operator_id");
        let operator_id =
            operator_id.ok_or_else(|| self.refuse(challenge_id, "leurre (nom inconnu)"))?;
        let request_body: Option<serde_json::Value> = row.get("request_body");
        let state: AttestedPasskeyAuthentication = request_body
            .and_then(|v| serde_json::from_value(v).ok())
            .ok_or_else(|| self.refuse(challenge_id, "état de la cérémonie illisible"))?;

        let (operator, credential_id) = self
            .verify_assertion(
                audit::EVENT_LOGIN_REFUSED,
                challenge_id,
                operator_id,
                &state,
                credential,
            )
            .await
            .map_err(|Refused| LoginError::Invalid)?;

        self.journal.append(
            audit::EVENT_LOGIN_SUCCEEDED,
            serde_json::json!({ "operateur": operator.name, "credential_id": credential_id }),
        );

        Ok(Verified {
            operator_id: operator.id,
            operator: operator.name,
            role: operator.role,
            credential_id,
        })
    }

    /// Vérifie une assertion pour un challenge déjà consommé : la clé est lue
    /// dans le registre, elle appartient à l'opérateur attendu, ni elle ni lui
    /// ne sont écartés, et le compteur de la console ne recule pas. Chaque
    /// refus est consigné sous `event` avec sa vraie raison.
    async fn verify_assertion(
        &self,
        event: &'static str,
        challenge_id: Uuid,
        operator_id: Uuid,
        state: &AttestedPasskeyAuthentication,
        credential: &PublicKeyCredential,
    ) -> Result<(oe_actions::Operator, String), Refused> {
        let refuse = |reason: &str| {
            self.note_refusal(event, challenge_id, reason);
            Refused
        };
        // La clé qui a signé, lue dans le registre — jamais déclarée par
        // l'appelant (§16).
        let credential_id = oe_actions::credential_id(credential.raw_id.as_ref());
        let key = self
            .registry
            .key(&credential_id)
            .await
            .map_err(|_| refuse("base indisponible"))?
            .ok_or_else(|| refuse("clé inconnue du registre"))?;
        if key.revoked {
            return Err(refuse("clé révoquée"));
        }
        if key.operator_id != operator_id {
            return Err(refuse("clé d'un autre opérateur"));
        }
        let operator = self
            .registry
            .operator(operator_id)
            .await
            .map_err(|_| refuse("base indisponible"))?
            .ok_or_else(|| refuse("opérateur inconnu"))?;
        if operator.disabled {
            return Err(refuse("opérateur désactivé"));
        }

        // Son propre compteur, jamais `webauthn_credentials.sign_count` : ce
        // dernier n'est écrit que par `ca-server` (migration 0006), et
        // `ra-console` n'a que la lecture sur cette table (§16).
        let last_sign_count: Option<i64> = sqlx::query_scalar(
            "SELECT last_sign_count FROM login_counters WHERE credential_id = $1",
        )
        .bind(&credential_id)
        .fetch_optional(self.registry.pool())
        .await
        .map_err(|_| refuse("base indisponible"))?;
        let last_sign_count = u32::try_from(last_sign_count.unwrap_or(0)).unwrap_or(u32::MAX);

        let assertion = self
            .verifier
            .finish_authentication(credential, state, last_sign_count)
            .map_err(|e| {
                let reason = if matches!(e, oe_webauthn::Error::CounterRegression { .. }) {
                    "compteur en régression : clonage présumé"
                } else {
                    "assertion refusée"
                };
                tracing::debug!(erreur = %e, "assertion refusée");
                refuse(reason)
            })?;

        sqlx::query(
            "INSERT INTO login_counters (credential_id, last_sign_count)
             VALUES ($1, $2)
             ON CONFLICT (credential_id) DO UPDATE SET last_sign_count = excluded.last_sign_count",
        )
        .bind(&credential_id)
        .bind(i64::from(assertion.counter))
        .execute(self.registry.pool())
        .await
        .map_err(|_| refuse("base indisponible"))?;

        Ok((operator, credential_id))
    }

    /// Émet un challenge pour qu'un opérateur **déjà connecté** signe, avec
    /// l'une de ses clés actives, ce que `frozen` décrit. `frozen` est rangé
    /// avec le challenge : c'est lui, et rien de ce que le navigateur renverra,
    /// que [`LoginService::finish_reassertion`] rendra à l'appelant.
    pub async fn begin_reassertion(
        &self,
        operator_id: Uuid,
        kind: &'static str,
        frozen: serde_json::Value,
    ) -> Result<Begun, ReassertError> {
        let keys = self.registry.active_keys(operator_id).await?;
        if keys.is_empty() {
            return Err(ReassertError::NoKey);
        }
        let passkeys = keys.into_iter().map(|k| k.passkey).collect::<Vec<_>>();
        let (options, state) = self
            .verifier
            .start_authentication(&passkeys)
            .map_err(|e| sqlx::Error::Protocol(e.to_string()))?;
        let state = serde_json::to_value(&state).map_err(|e| sqlx::Error::Encode(e.into()))?;

        let challenge_id = Uuid::new_v4();
        let now = OffsetDateTime::now_utc();
        sqlx::query(
            "INSERT INTO webauthn_challenges
               (id, kind, challenge, operator_id, request_body, created_at, expires_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7)",
        )
        .bind(challenge_id)
        .bind(kind)
        .bind(options.public_key.challenge.as_ref())
        .bind(operator_id)
        .bind(serde_json::json!({ "state": state, "frozen": frozen }))
        .bind(now)
        .bind(now + CHALLENGE_TTL)
        .execute(self.registry.pool())
        .await?;
        Ok(Begun {
            challenge_id,
            options,
        })
    }

    /// Vérifie la réassertion d'un opérateur connecté. `expected` juge ce qui
    /// a été figé **avant** que le challenge ne soit consommé : une assertion
    /// présentée sur la mauvaise route reste utilisable sur la bonne. Le
    /// challenge est à usage unique, lié à l'opérateur et au type demandés.
    pub async fn finish_reassertion(
        &self,
        challenge_id: Uuid,
        operator_id: Uuid,
        kind: &'static str,
        credential: &PublicKeyCredential,
        expected: impl FnOnce(&serde_json::Value) -> bool,
    ) -> Result<Reasserted, ReassertError> {
        let event = audit::EVENT_REASSERTION_REFUSED;
        let invalid = |reason: &str| {
            self.note_refusal(event, challenge_id, reason);
            ReassertError::Invalid
        };
        let now = OffsetDateTime::now_utc();
        let row = sqlx::query(
            "SELECT challenge, request_body FROM webauthn_challenges
             WHERE id = $1 AND kind = $2 AND operator_id = $3
               AND consumed_at IS NULL AND expires_at > $4",
        )
        .bind(challenge_id)
        .bind(kind)
        .bind(operator_id)
        .bind(now)
        .fetch_optional(self.registry.pool())
        .await?
        .ok_or_else(|| {
            invalid("challenge inconnu, expiré, déjà consommé ou d'un autre opérateur")
        })?;
        let challenge: Vec<u8> = row.get("challenge");
        let body: Option<serde_json::Value> = row.get("request_body");
        let (state, frozen) = body
            .and_then(|mut b| {
                let state = serde_json::from_value(b.get_mut("state")?.take()).ok()?;
                Some((state, b.get_mut("frozen")?.take()))
            })
            .ok_or_else(|| invalid("état de la cérémonie illisible"))?;
        let state: AttestedPasskeyAuthentication = state;
        if !expected(&frozen) {
            self.note_refusal(event, challenge_id, "challenge émis pour un autre objet");
            return Err(ReassertError::Mismatch);
        }

        let consumed = sqlx::query(
            "UPDATE webauthn_challenges SET consumed_at = $2
             WHERE id = $1 AND consumed_at IS NULL",
        )
        .bind(challenge_id)
        .bind(now)
        .execute(self.registry.pool())
        .await?;
        if consumed.rows_affected() != 1 {
            return Err(invalid("challenge déjà consommé"));
        }

        let (_, credential_id) = self
            .verify_assertion(event, challenge_id, operator_id, &state, credential)
            .await
            .map_err(|Refused| ReassertError::Invalid)?;
        Ok(Reasserted {
            credential_id,
            frozen,
            challenge,
            authenticator_data: credential.response.authenticator_data.as_ref().to_vec(),
            client_data_json: credential.response.client_data_json.as_ref().to_vec(),
            signature: credential.response.signature.as_ref().to_vec(),
        })
    }
}
