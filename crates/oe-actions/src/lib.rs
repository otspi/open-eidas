//! Actions d'opérateur signées, vérifiées et exécutées par `ca-server`
//! (docs/WEBUI.md §4, §16).
//!
//! Le principe : `ra-console` n'est jamais une ancre de confiance. Elle relaie
//! une demande et une assertion WebAuthn ; c'est ce module, dans `ca-server`,
//! qui vérifie la signature contre son propre registre, lit le rôle dans ce
//! registre, exécute, et consigne. Approuver une demande déclenche l'émission
//! du certificat (`oe_raflow::Flow::resume`) : une console qui pouvait écrire
//! une approbation pouvait faire émettre n'importe quoi.
//!
//! Déroulement :
//!
//!   1. [`Service::issue_challenge`] fige le corps de l'action, l'écrit au
//!      journal chaîné **avant** de répondre, et émet un challenge ;
//!   2. l'opérateur signe le challenge avec sa clé ;
//!   3. [`Service::execute`] reçoit l'identifiant du challenge et l'assertion,
//!      **et aucun corps** : il exécute le corps figé à l'étape 1.
//!
//! Le challenge est tiré par la bibliothèque WebAuthn, il ne dérive pas du
//! corps (décision O7). Le lien challenge → corps est donc établi par le
//! journal et par la table `actions`, pas par la signature seule.

mod assertion;
mod audit;
mod enrollment;
mod guard;
mod onboarding;
mod quorum;
mod registry;
mod registry_actions;
mod replay;
mod revocation;

pub use enrollment::{key_fingerprint, KeyStatus, Registered, RegistrationBegun, PENDING_TTL};
pub use onboarding::{bootstrap_admin, recover_admin, Invite, MAX_INVITE_TTL, MIN_INVITE_TTL};

pub use audit::{audit_registry, AuditReport, JournalView, KeyReport, Verdict};
pub use guard::RegistryGuard;
pub use quorum::{QUORUM, QUORUM_WINDOW};
pub use registry::{credential_id, Key, NewCredential, Operator, Registry, Role};
pub use replay::{find_divergences, reconcile, Divergence, ReconcileOutcome, Replay};
pub use revocation::Revoker;

use oe_castore::{RequestState, Store, StoreError};
use oe_raflow::Decider;
use oe_raflow::Recorder;
use oe_webauthn::{PublicKeyCredential, RequestChallengeResponse, Uuid, Verifier};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use time::OffsetDateTime;

/// Durée de validité d'une action et de son challenge.
pub const CHALLENGE_TTL: time::Duration = time::Duration::minutes(5);

pub type Clock = Arc<dyn Fn() -> OffsetDateTime + Send + Sync>;

/// Ce que l'opérateur demande. L'énumération est fermée : une action qui n'y
/// figure pas ne peut pas être signée, donc pas exécutée.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum Action {
    ApproveRequest {
        transaction_id: String,
        /// Empreinte de la CSR que l'opérateur a vérifiée avec le demandeur
        /// (§11). Si présente, elle doit correspondre à la demande.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        csr_fingerprint: Option<String>,
        comment: String,
    },
    RejectRequest {
        transaction_id: String,
        comment: String,
    },
    /// Invite un nouvel opérateur (§10). Le jeton d'invitation n'est renvoyé
    /// que dans le résultat de l'exécution : la base n'en garde que le haché.
    InviteOperator {
        name: String,
        role: Role,
        #[serde(default = "default_invite_ttl_minutes")]
        ttl_minutes: i64,
    },
    /// Active une clé en attente. L'empreinte fait partie du corps signé :
    /// l'administrateur s'engage sur *cette* clé, pas sur « la clé en attente »
    /// de quelqu'un, quelle qu'elle soit.
    ConfirmKey {
        credential_id: String,
        key_fingerprint: String,
    },
    RevokeKey {
        credential_id: String,
        reason: String,
    },
    SetRole {
        operator: String,
        role: Role,
    },
    /// Révoque un certificat émis et republie la CRL. `serial` est le numéro
    /// de série en hexadécimal minuscule, sans préfixe : la forme canonique
    /// est exigée pour que le corps signé n'ait qu'une écriture.
    RevokeCertificate {
        serial: String,
        /// Code RFC 5280 §5.3.1. « unspecified » (0) est refusé : il ne
        /// justifie pas une décision devant un auditeur.
        reason: i32,
        comment: String,
    },
}

fn default_invite_ttl_minutes() -> i64 {
    60
}

impl Action {
    fn kind(&self) -> &'static str {
        match self {
            Action::ApproveRequest { .. } => "approve_request",
            Action::RejectRequest { .. } => "reject_request",
            Action::InviteOperator { .. } => "invite_operator",
            Action::ConfirmKey { .. } => "confirm_key",
            Action::RevokeKey { .. } => "revoke_key",
            Action::SetRole { .. } => "set_role",
            Action::RevokeCertificate { .. } => "revoke_certificate",
        }
    }

    /// Rôles habilités à signer cette action (§3). `admin` n'y figure pas :
    /// il gère les opérateurs, aucun droit sur les certificats.
    fn allowed_roles(&self) -> &'static [Role] {
        match self {
            Action::ApproveRequest { .. } | Action::RejectRequest { .. } => {
                &[Role::RaOperateur, Role::CaOperateur]
            }
            // Seul l'administrateur modifie le registre, et il n'a aucun droit
            // sur les certificats : les deux périmètres ne se mélangent pas.
            Action::InviteOperator { .. }
            | Action::ConfirmKey { .. }
            | Action::RevokeKey { .. }
            | Action::SetRole { .. } => &[Role::Admin],
            // Décider de la fin de vie d'un certificat est un acte de la CA.
            Action::RevokeCertificate { .. } => &[Role::CaOperateur],
        }
    }

    fn transaction_id(&self) -> Option<&str> {
        match self {
            Action::ApproveRequest { transaction_id, .. }
            | Action::RejectRequest { transaction_id, .. } => Some(transaction_id),
            _ => None,
        }
    }
}

/// Le corps figé : l'action et son échéance. Les octets de cette
/// sérialisation, dans cet ordre de champs, sont ce que couvre `body_hash`.
#[derive(Serialize, Deserialize)]
struct Body {
    #[serde(flatten)]
    action: Action,
    expires_at: String,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("action refusée : {0}")]
    Denied(String),
    #[error("requête invalide : {0}")]
    BadRequest(String),
    #[error("challenge inconnu")]
    NotFound,
    #[error("challenge expiré")]
    Expired,
    #[error("challenge déjà utilisé")]
    AlreadyUsed,
    #[error("cérémonie perdue (redémarrage) : demander un nouveau challenge")]
    StateLost,
    #[error("journal indisponible, action non émise : {0}")]
    Journal(String),
    #[error("signature refusée : {0}")]
    Verification(#[from] oe_webauthn::Error),
    #[error("base de données : {0}")]
    Db(#[from] sqlx::Error),
    #[error("exécution : {0}")]
    Effect(String),
    #[error("registre bloqué, aucune action n'est exécutée : {0}")]
    Blocked(String),
    #[error("l'action figée n'est pas celle attendue : {0}")]
    Mismatch(String),
}

/// Ce que l'appelant croit faire exécuter (docs/WEBUI.md §5,
/// `/requests/{id}/approve`) : le type d'action et sa cible. Comparé au corps
/// figé **avant** toute vérification ou consommation, et refusé s'il diffère :
/// une assertion obtenue pour la demande A ne peut pas être présentée pour la
/// demande B. Ne peut que restreindre : ce qui s'exécute reste le corps figé.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Expect {
    pub action: String,
    #[serde(default)]
    pub transaction_id: Option<String>,
}

impl Expect {
    fn check(&self, action: &Action) -> Result<(), Error> {
        if self.action != action.kind() {
            return Err(Error::Mismatch(format!(
                "attendu {}, figé {}",
                self.action,
                action.kind()
            )));
        }
        let target = match action {
            Action::ApproveRequest { transaction_id, .. }
            | Action::RejectRequest { transaction_id, .. } => Some(transaction_id),
            _ => None,
        };
        match (target, &self.transaction_id) {
            (Some(frozen), Some(expected)) if frozen == expected => Ok(()),
            (Some(_), None) => Err(Error::BadRequest(
                "la demande visée doit être précisée".to_string(),
            )),
            (Some(frozen), Some(expected)) => Err(Error::Mismatch(format!(
                "demande attendue {expected}, figée {frozen}"
            ))),
            (None, _) => Ok(()),
        }
    }
}

/// Un challenge émis, à présenter à l'opérateur.
#[derive(Debug)]
pub struct Issued {
    pub challenge_id: Uuid,
    pub action_id: Uuid,
    /// Le corps que `ca-server` exécutera, à afficher tel quel (WYSIWYS).
    pub body: serde_json::Value,
    /// SHA-256 hexadécimal de la sérialisation canonique du corps.
    pub body_hash: String,
    /// Signatures exigées (politique de `ca-server`) et déjà recueillies.
    pub required_signatures: u32,
    pub signatures: u32,
    pub options: RequestChallengeResponse,
}

/// Une action exécutée.
#[derive(Debug)]
pub struct Executed {
    pub action_id: Uuid,
    pub challenge_id: Uuid,
    /// Identité lue dans le registre, jamais transmise par l'appelant.
    pub operator: String,
    pub role: Role,
    /// Ce que l'action produit pour l'appelant (ex. le jeton d'une invitation).
    /// Jamais journalisé ni conservé.
    pub result: Option<serde_json::Value>,
    /// `false` tant que le seuil de signatures n'est pas atteint : la signature
    /// est enregistrée, rien n'est encore exécuté.
    pub executed: bool,
    pub signatures: u32,
    pub required: u32,
}

struct Pending {
    state: oe_webauthn::AttestedPasskeyAuthentication,
}

pub struct Service {
    registry: Registry,
    verifier: Verifier,
    store: Arc<dyn Store>,
    decider: Decider,
    journal: Arc<dyn Recorder>,
    clock: Clock,
    // L'état d'une cérémonie reste en mémoire : `ca-server` n'a qu'un
    // réplica (il détient un token PKCS#11). Une cérémonie perdue à un
    // redémarrage est simplement refaite.
    pending: Mutex<HashMap<Uuid, Pending>>,
    // Idem pour les cérémonies d'enregistrement de clé.
    registrations: Mutex<HashMap<Uuid, enrollment::PendingRegistration>>,
    // Sans lui, la révocation de certificat est refusée : un service qui ne
    // sait pas révoquer ne doit pas faire signer une révocation.
    revoker: Option<Arc<dyn Revoker>>,
    // Fermée tant que le registre diverge du journal (§21) ; ouverte si absente.
    guard: Option<Arc<RegistryGuard>>,
}

impl Service {
    pub fn new(
        registry: Registry,
        verifier: Verifier,
        store: Arc<dyn Store>,
        decider: Decider,
        journal: Arc<dyn Recorder>,
        clock: Clock,
    ) -> Service {
        Service {
            registry,
            verifier,
            store,
            decider,
            journal,
            clock,
            pending: Mutex::new(HashMap::new()),
            registrations: Mutex::new(HashMap::new()),
            revoker: None,
            guard: None,
        }
    }

    /// Branche la garde du registre : tant qu'elle est fermée, ce service
    /// n'émet aucun challenge, n'exécute aucune action et n'enregistre aucune clé.
    pub fn with_guard(mut self, guard: Arc<RegistryGuard>) -> Service {
        self.guard = Some(guard);
        self
    }

    /// Échec fermé si le registre est bloqué.
    pub(crate) fn ensure_open(&self) -> Result<(), Error> {
        match self.guard.as_ref().and_then(|g| g.blocked()) {
            Some(reasons) => Err(Error::Blocked(reasons.join(" ; "))),
            None => Ok(()),
        }
    }

    /// Branche la CA qui exécute les révocations de certificats.
    pub fn with_revoker(mut self, revoker: Arc<dyn Revoker>) -> Service {
        self.revoker = Some(revoker);
        self
    }

    fn now(&self) -> OffsetDateTime {
        (self.clock)()
    }

    /// Contrôles communs à l'émission et à l'exécution, sur l'état *actuel*
    /// de la demande visée : elle existe, est en attente, et l'empreinte de
    /// CSR annoncée est bien la sienne.
    async fn check_target(&self, action: &Action) -> Result<(), Error> {
        let Some(transaction_id) = action.transaction_id() else {
            return Ok(());
        };
        let request = match self.store.request_by_transaction_id(transaction_id).await {
            Ok(r) => r,
            Err(StoreError::NotFound) => return Err(Error::Denied("demande inconnue".to_string())),
            Err(e) => return Err(Error::Effect(e.to_string())),
        };
        if request.state != RequestState::Pending {
            return Err(Error::Denied(format!(
                "la demande n'est pas en attente ({})",
                request.state
            )));
        }
        if let Action::ApproveRequest {
            csr_fingerprint: Some(fp),
            ..
        } = action
        {
            if *fp != request.csr_fingerprint {
                return Err(Error::Denied(
                    "l'empreinte de CSR annoncée n'est pas celle de la demande".to_string(),
                ));
            }
        }
        if let Action::RejectRequest { comment, .. } = action {
            if comment.trim().is_empty() {
                return Err(Error::BadRequest(
                    "un rejet exige un motif écrit".to_string(),
                ));
            }
        }
        Ok(())
    }

    /// Contrôles sur l'état *actuel* de la cible. Pour le registre, c'est
    /// l'exécution elle-même, jouée à blanc puis annulée : un seul chemin de
    /// code, donc ce qui est contrôlé à l'émission est ce qui sera fait.
    /// `required` est le nombre de signatures figé sur l'action.
    async fn check_action(
        &self,
        action: &Action,
        actor: &Operator,
        required: u32,
    ) -> Result<(), Error> {
        match action {
            Action::ApproveRequest { .. } | Action::RejectRequest { .. } => {
                self.check_target(action).await
            }
            Action::RevokeCertificate { .. } => self.check_revocation(action).await,
            _ => self
                .run_registry_action(action, actor, self.now(), false, required)
                .await
                .map(|_| ()),
        }
    }

    /// L'opérateur dont on propose les clés, s'il est habilité à signer.
    async fn eligible_signer(&self, hint: Uuid, action: &Action) -> Result<Operator, Error> {
        let operator = self
            .registry
            .operator(hint)
            .await?
            .ok_or_else(|| Error::Denied("opérateur inconnu".to_string()))?;
        if operator.disabled || !action.allowed_roles().contains(&operator.role) {
            return Err(Error::Denied(format!(
                "le rôle {} ne peut pas signer {}",
                operator.role.as_str(),
                action.kind()
            )));
        }
        Ok(operator)
    }

    /// Ouvre une cérémonie d'authentification sur les clés actives de l'opérateur.
    async fn start_ceremony(
        &self,
        operator_hint: Uuid,
    ) -> Result<
        (
            RequestChallengeResponse,
            oe_webauthn::AttestedPasskeyAuthentication,
        ),
        Error,
    > {
        let keys = self.registry.active_keys(operator_hint).await?;
        if keys.is_empty() {
            return Err(Error::Denied("aucune clé active".to_string()));
        }
        let passkeys: Vec<_> = keys.iter().map(|k| k.passkey.clone()).collect();
        Ok(self.verifier.start_authentication(&passkeys)?)
    }

    async fn count_signatures(&self, action_id: Uuid) -> Result<u32, Error> {
        let n: i64 =
            sqlx::query_scalar("SELECT count(*) FROM decision_evidence WHERE action_id = $1")
                .bind(action_id)
                .fetch_one(self.registry.pool())
                .await?;
        Ok(n as u32)
    }

    /// Fige l'action et émet un challenge pour les clés de `operator_hint`.
    ///
    /// `operator_hint` sert seulement à choisir les clés à proposer : ce n'est
    /// jamais une décision de confiance. L'opérateur qui agit est celui dont la
    /// clé signe, lu dans le registre par [`Service::execute`].
    ///
    /// Le nombre de signatures exigé vient de la politique de `ca-server`. Au-delà
    /// d'une, l'action reste signable pendant [`QUORUM_WINDOW`] ; les signataires
    /// suivants demandent leur challenge par [`Service::issue_challenge_for`].
    pub async fn issue_challenge(
        &self,
        action: Action,
        operator_hint: Uuid,
    ) -> Result<Issued, Error> {
        self.ensure_open()?;
        let operator = self.eligible_signer(operator_hint, &action).await?;
        let required = self.required_signatures(&action).await?;
        if required > 1 {
            self.ensure_enough_holders(&action, required).await?;
        }
        self.check_action(&action, &operator, required).await?;
        let (options, state) = self.start_ceremony(operator_hint).await?;

        let now = self.now();
        let action_expires_at = now
            + if required > 1 {
                QUORUM_WINDOW
            } else {
                CHALLENGE_TTL
            };
        let body = Body {
            action,
            expires_at: action_expires_at
                .format(&time::format_description::well_known::Rfc3339)
                .map_err(|e| Error::BadRequest(e.to_string()))?,
        };
        // Les octets qui font foi. JSONB réordonne les clés : c'est cette
        // chaîne, écrite au journal, qu'un auditeur re-hache.
        let canonical =
            serde_json::to_string(&body).map_err(|e| Error::BadRequest(e.to_string()))?;
        let body_hash = hex::encode(Sha256::digest(canonical.as_bytes()));
        let body_json: serde_json::Value =
            serde_json::from_str(&canonical).map_err(|e| Error::BadRequest(e.to_string()))?;

        let action_id = Uuid::new_v4();
        let challenge_id = Uuid::new_v4();
        let challenge_expires_at = (now + CHALLENGE_TTL).min(action_expires_at);

        // Le journal d'abord : si l'écriture échoue, aucun challenge n'est émis.
        // Un système qui ferait signer sans pouvoir consigner perdrait la
        // propriété qui donne son sens à tout ce module (§21).
        self.journal
            .append(
                "operators.action_challenge_issued",
                serde_json::json!({
                    "action_id": action_id.to_string(),
                    "challenge_id": challenge_id.to_string(),
                    "action": body_json["action"],
                    "body": canonical,
                    "body_hash": body_hash,
                    "signatures_exigees": required,
                    "operator_hint": operator.name,
                }),
            )
            .await
            .map_err(Error::Journal)?;

        let challenge = options.public_key.challenge.as_ref().to_vec();
        let mut tx = self.registry.pool().begin().await?;
        sqlx::query(
            "INSERT INTO actions (id, body, body_hash, created_at, expires_at, required_signatures)
             VALUES ($1, $2, $3, $4, $5, $6)",
        )
        .bind(action_id)
        .bind(&body_json)
        .bind(Sha256::digest(canonical.as_bytes()).to_vec())
        .bind(now)
        .bind(action_expires_at)
        .bind(required as i32)
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "INSERT INTO action_challenges
               (challenge_id, action_id, challenge, operator_hint, issued_at, expires_at)
             VALUES ($1, $2, $3, $4, $5, $6)",
        )
        .bind(challenge_id)
        .bind(action_id)
        .bind(challenge)
        .bind(operator_hint)
        .bind(now)
        .bind(challenge_expires_at)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;

        self.pending
            .lock()
            .expect("verrou des cérémonies")
            .insert(challenge_id, Pending { state });

        Ok(Issued {
            challenge_id,
            action_id,
            body: body_json,
            body_hash,
            required_signatures: required,
            signatures: 0,
            options,
        })
    }

    /// Émet un challenge pour un signataire de plus sur une action **déjà
    /// figée** : il signe exactement le corps du premier, jamais un autre.
    pub async fn issue_challenge_for(
        &self,
        action_id: Uuid,
        operator_hint: Uuid,
    ) -> Result<Issued, Error> {
        use sqlx::Row;
        self.ensure_open()?;
        let now = self.now();
        let row = sqlx::query(
            "SELECT body, body_hash, expires_at, executed_at, required_signatures
             FROM actions WHERE id = $1",
        )
        .bind(action_id)
        .fetch_optional(self.registry.pool())
        .await?
        .ok_or(Error::NotFound)?;
        let executed: Option<OffsetDateTime> = row.get("executed_at");
        let expires_at: OffsetDateTime = row.get("expires_at");
        let required = row.get::<i32, _>("required_signatures") as u32;
        let body_json: serde_json::Value = row.get("body");
        let body_hash = hex::encode(row.get::<Vec<u8>, _>("body_hash"));
        if executed.is_some() {
            return Err(Error::AlreadyUsed);
        }
        if now > expires_at {
            return Err(Error::Expired);
        }
        let stored: Body = serde_json::from_value(body_json.clone())
            .map_err(|e| Error::BadRequest(e.to_string()))?;

        let operator = self.eligible_signer(operator_hint, &stored.action).await?;
        let already: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM decision_evidence WHERE action_id = $1 AND operator_id = $2)",
        )
        .bind(action_id)
        .bind(operator.id)
        .fetch_one(self.registry.pool())
        .await?;
        if already {
            return Err(Error::Denied(
                "cet opérateur a déjà signé cette action".to_string(),
            ));
        }
        self.check_action(&stored.action, &operator, required)
            .await?;
        let (options, state) = self.start_ceremony(operator_hint).await?;

        let challenge_id = Uuid::new_v4();
        self.journal
            .append(
                "operators.action_challenge_issued",
                serde_json::json!({
                    "action_id": action_id.to_string(),
                    "challenge_id": challenge_id.to_string(),
                    "action": body_json["action"],
                    "body_hash": body_hash,
                    "signatures_exigees": required,
                    "operator_hint": operator.name,
                }),
            )
            .await
            .map_err(Error::Journal)?;
        sqlx::query(
            "INSERT INTO action_challenges
               (challenge_id, action_id, challenge, operator_hint, issued_at, expires_at)
             VALUES ($1, $2, $3, $4, $5, $6)",
        )
        .bind(challenge_id)
        .bind(action_id)
        .bind(options.public_key.challenge.as_ref().to_vec())
        .bind(operator_hint)
        .bind(now)
        .bind((now + CHALLENGE_TTL).min(expires_at))
        .execute(self.registry.pool())
        .await?;
        self.pending
            .lock()
            .expect("verrou des cérémonies")
            .insert(challenge_id, Pending { state });

        Ok(Issued {
            challenge_id,
            action_id,
            body: body_json,
            body_hash,
            required_signatures: required,
            signatures: self.count_signatures(action_id).await?,
            options,
        })
    }

    /// Vérifie l'assertion, l'enregistre, et exécute **le corps figé à
    /// l'émission** dès que le nombre de signatures exigé est atteint.
    ///
    /// La signature est consommée dès qu'elle est reconnue valide, avant
    /// l'effet : si l'effet échoue ensuite, les opérateurs devront signer de
    /// nouveau. On préfère ne jamais exécuter deux fois, et ne jamais exécuter
    /// sans des signatures valides et neuves, à « réessayer » sur une signature
    /// déjà utilisée.
    ///
    /// Tant que le seuil n'est pas atteint, la signature est enregistrée et
    /// [`Executed::executed`] vaut `false`.
    pub async fn execute(
        &self,
        challenge_id: Uuid,
        assertion: &PublicKeyCredential,
    ) -> Result<Executed, Error> {
        self.execute_inner(challenge_id, assertion, None).await
    }

    /// Comme [`Service::execute`], mais refuse, avant de rien vérifier ni
    /// consommer, si le corps figé n'est pas celui que l'appelant attend
    /// (voir [`Expect`]).
    pub async fn execute_expecting(
        &self,
        challenge_id: Uuid,
        assertion: &PublicKeyCredential,
        expect: &Expect,
    ) -> Result<Executed, Error> {
        self.execute_inner(challenge_id, assertion, Some(expect))
            .await
    }

    async fn execute_inner(
        &self,
        challenge_id: Uuid,
        assertion: &PublicKeyCredential,
        expect: Option<&Expect>,
    ) -> Result<Executed, Error> {
        self.ensure_open()?;
        let now = self.now();

        let row = sqlx::query(
            "SELECT c.action_id, c.consumed_at, c.expires_at, a.body, a.body_hash,
                    a.executed_at, a.expires_at AS action_expires_at, a.required_signatures
             FROM action_challenges c JOIN actions a ON a.id = c.action_id
             WHERE c.challenge_id = $1",
        )
        .bind(challenge_id)
        .fetch_optional(self.registry.pool())
        .await?
        .ok_or(Error::NotFound)?;
        use sqlx::Row;
        let action_id: Uuid = row.get("action_id");
        let consumed: Option<OffsetDateTime> = row.get("consumed_at");
        let executed: Option<OffsetDateTime> = row.get("executed_at");
        let expires_at: OffsetDateTime = row.get("expires_at");
        let action_expires_at: OffsetDateTime = row.get("action_expires_at");
        let required = row.get::<i32, _>("required_signatures") as u32;
        let body: serde_json::Value = row.get("body");
        let body_hash: Vec<u8> = row.get("body_hash");
        if consumed.is_some() || executed.is_some() {
            return Err(Error::AlreadyUsed);
        }
        if now > expires_at || now > action_expires_at {
            return Err(Error::Expired);
        }
        let stored: Body =
            serde_json::from_value(body).map_err(|e| Error::BadRequest(e.to_string()))?;
        // Avant de retirer l'état de la cérémonie : une assertion présentée pour
        // une autre cible ne consomme rien, le bon appel reste possible.
        if let Some(expect) = expect {
            expect.check(&stored.action)?;
        }

        // Une seule tentative par cérémonie : l'état sort de la mémoire quoi
        // qu'il arrive ensuite.
        let pending = self
            .pending
            .lock()
            .expect("verrou des cérémonies")
            .remove(&challenge_id)
            .ok_or(Error::StateLost)?;

        // L'opérateur est celui dont la clé a signé, lu dans le registre.
        let key = self
            .registry
            .key(&credential_id(assertion.raw_id.as_ref()))
            .await?
            .ok_or_else(|| Error::Denied("clé inconnue du registre".to_string()))?;
        if key.revoked {
            return Err(Error::Denied("clé révoquée".to_string()));
        }
        let operator = self
            .registry
            .operator(key.operator_id)
            .await?
            .ok_or_else(|| Error::Denied("opérateur inconnu".to_string()))?;
        if operator.disabled || !stored.action.allowed_roles().contains(&operator.role) {
            return Err(Error::Denied(format!(
                "le rôle {} ne peut pas signer {}",
                operator.role.as_str(),
                stored.action.kind()
            )));
        }

        let verified =
            self.verifier
                .finish_authentication(assertion, &pending.state, key.sign_count)?;

        // Le corps figé peut avoir vieilli depuis l'émission (demande décidée
        // entre-temps) : on le recontrôle avant d'engager la signature.
        self.check_action(&stored.action, &operator, required)
            .await?;

        let mut tx = self.registry.pool().begin().await?;
        // Serialise les signatures d'une même action : deux dernières signatures
        // simultanées n'exécutent qu'une fois.
        let locked = sqlx::query("SELECT executed_at FROM actions WHERE id = $1 FOR UPDATE")
            .bind(action_id)
            .fetch_one(&mut *tx)
            .await?;
        if locked
            .get::<Option<OffsetDateTime>, _>("executed_at")
            .is_some()
        {
            return Err(Error::AlreadyUsed);
        }
        // Consommation : conditionnelle, donc sûre sous concurrence.
        let consumed_now = sqlx::query(
            "UPDATE action_challenges SET consumed_at = $2
             WHERE challenge_id = $1 AND consumed_at IS NULL",
        )
        .bind(challenge_id)
        .bind(now)
        .execute(&mut *tx)
        .await?;
        if consumed_now.rows_affected() != 1 {
            return Err(Error::AlreadyUsed);
        }
        sqlx::query(
            "UPDATE webauthn_credentials SET sign_count = $2, last_used_at = $3
             WHERE credential_id = $1",
        )
        .bind(&key.credential_id)
        .bind(i64::from(verified.counter))
        .bind(now)
        .execute(&mut *tx)
        .await?;
        let evidence = sqlx::query(
            "INSERT INTO decision_evidence
               (id, challenge_id, action_id, operator_id, credential_id,
                authenticator_data, client_data_json, signature, verified_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
        )
        .bind(Uuid::new_v4())
        .bind(challenge_id)
        .bind(action_id)
        .bind(operator.id)
        .bind(&key.credential_id)
        .bind(assertion.response.authenticator_data.as_ref())
        .bind(assertion.response.client_data_json.as_ref())
        .bind(assertion.response.signature.as_ref())
        .bind(now)
        .execute(&mut *tx)
        .await;
        if let Err(e) = evidence {
            // UNIQUE (action_id, operator_id) : un opérateur ne compte qu'une fois.
            return Err(
                if e.as_database_error()
                    .and_then(|d| d.code())
                    .is_some_and(|c| c == "23505")
                {
                    Error::Denied("cet opérateur a déjà signé cette action".to_string())
                } else {
                    e.into()
                },
            );
        }

        let signers = sqlx::query(
            "SELECT o.name, o.role, o.disabled_at, c.revoked_at
             FROM decision_evidence e
             JOIN operators o ON o.id = e.operator_id
             JOIN webauthn_credentials c ON c.credential_id = e.credential_id
             WHERE e.action_id = $1
             ORDER BY e.verified_at, o.name",
        )
        .bind(action_id)
        .fetch_all(&mut *tx)
        .await?;
        let signatures = signers.len() as u32;

        if signatures < required {
            // Le journal avant la validation : s'il échoue, la signature n'est pas prise.
            self.journal
                .append(
                    "operators.action_signed",
                    serde_json::json!({
                        "action_id": action_id.to_string(),
                        "challenge_id": challenge_id.to_string(),
                        "action": stored.action.kind(),
                        "body_hash": hex::encode(&body_hash),
                        "operateur": operator.name,
                        "role": operator.role.as_str(),
                        "credential_id": key.credential_id,
                        "signatures": signatures,
                        "signatures_exigees": required,
                    }),
                )
                .await
                .map_err(Error::Journal)?;
            tx.commit().await?;
            return Ok(Executed {
                action_id,
                challenge_id,
                operator: operator.name,
                role: operator.role,
                result: None,
                executed: false,
                signatures,
                required,
            });
        }

        // Seuil atteint. Les premiers signataires ont pu perdre leur habilitation
        // depuis (jusqu'à 24 h) : chacun doit encore l'être.
        let mut names = Vec::new();
        for s in &signers {
            let name: String = s.get("name");
            let role: String = s.get("role");
            let disabled: Option<OffsetDateTime> = s.get("disabled_at");
            let revoked: Option<OffsetDateTime> = s.get("revoked_at");
            let allowed = stored
                .action
                .allowed_roles()
                .iter()
                .any(|r| r.as_str() == role);
            if disabled.is_some() || revoked.is_some() || !allowed {
                return Err(Error::Denied(format!(
                    "le signataire {name:?} n'est plus habilité à signer cette action"
                )));
            }
            names.push(name);
        }
        let marked = sqlx::query(
            "UPDATE actions SET executed_at = $2 WHERE id = $1 AND executed_at IS NULL",
        )
        .bind(action_id)
        .bind(now)
        .execute(&mut *tx)
        .await?;
        if marked.rows_affected() != 1 {
            return Err(Error::AlreadyUsed);
        }
        tx.commit().await?;

        // Journal avant l'effet : s'il échoue, rien n'est appliqué et les
        // signatures restent consommées (échec fermé).
        self.journal
            .append(
                "operators.action_executed",
                serde_json::json!({
                    "action_id": action_id.to_string(),
                    "challenge_id": challenge_id.to_string(),
                    "action": stored.action.kind(),
                    "body_hash": hex::encode(&body_hash),
                    "operateur": operator.name,
                    "role": operator.role.as_str(),
                    "credential_id": key.credential_id,
                    "signataires": names,
                }),
            )
            .await
            .map_err(Error::Journal)?;

        let result = match &stored.action {
            Action::ApproveRequest {
                transaction_id,
                comment,
                ..
            } => self
                .decider
                .approve(transaction_id, &operator.name, comment)
                .await
                .map(|_| None)
                .map_err(|e| Error::Effect(e.to_string()))?,
            Action::RejectRequest {
                transaction_id,
                comment,
            } => self
                .decider
                .reject(transaction_id, &operator.name, comment)
                .await
                .map(|_| None)
                .map_err(|e| Error::Effect(e.to_string()))?,
            // Tous les signataires sont imputés à la révocation, pas le seul dernier.
            Action::RevokeCertificate {
                serial,
                reason,
                comment,
            } => Some(
                self.revoke_certificate(serial, *reason, &names.join(", "), comment)
                    .await?,
            ),
            registry_action => Some(
                self.run_registry_action(registry_action, &operator, now, true, required)
                    .await?,
            ),
        };

        Ok(Executed {
            action_id,
            challenge_id,
            operator: operator.name,
            role: operator.role,
            result,
            executed: true,
            signatures,
            required,
        })
    }
}

#[cfg(test)]
mod expect_tests {
    use super::*;

    fn approve(tx: &str) -> Action {
        Action::ApproveRequest {
            transaction_id: tx.to_string(),
            csr_fingerprint: None,
            comment: "ok".to_string(),
        }
    }

    fn expect(action: &str, tx: Option<&str>) -> Expect {
        Expect {
            action: action.to_string(),
            transaction_id: tx.map(str::to_string),
        }
    }

    #[test]
    fn only_the_frozen_action_and_target_pass() {
        assert!(expect("approve_request", Some("tx-a"))
            .check(&approve("tx-a"))
            .is_ok());
        assert!(matches!(
            expect("approve_request", Some("tx-b")).check(&approve("tx-a")),
            Err(Error::Mismatch(_))
        ));
        assert!(matches!(
            expect("reject_request", Some("tx-a")).check(&approve("tx-a")),
            Err(Error::Mismatch(_))
        ));
        // Une décision sans cible précisée n'est pas une attente : refusée.
        assert!(matches!(
            expect("approve_request", None).check(&approve("tx-a")),
            Err(Error::BadRequest(_))
        ));
        // Une action sans demande visée : seul le type compte.
        let role = Action::SetRole {
            operator: "alice".to_string(),
            role: Role::Auditeur,
        };
        assert!(expect("set_role", None).check(&role).is_ok());
    }
}
