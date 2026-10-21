//! Vérification WebAuthn des opérateurs, pour `ca-server` (docs/WEBUI.md §2, §4).
//!
//! Enveloppe étroite autour de `webauthn-rs` : elle n'ajoute que les règles du
//! projet, pour qu'elles soient lisibles et testées à un seul endroit.
//!
//!   * une clé n'est admise qu'avec une attestation du fabricant, vérifiée
//!     contre une liste blanche de couples (racine, AAGUID) ;
//!   * une clé synchronisable (drapeau BE) est refusée, à l'enregistrement
//!     comme à l'usage ;
//!   * la vérification de l'utilisateur (PIN ou biométrie) est obligatoire ;
//!   * une régression du compteur de signatures est un clonage présumé ;
//!   * le RP ID doit être exactement le nom d'hôte de l'origine.
//!
//! Le challenge d'une action est lié à son corps : `SHA-256(domaine ‖
//! SHA-256(corps) ‖ aléa)`, l'aléa étant celui que tire la bibliothèque
//! ([`Verifier::start_bound_authentication`]). Une signature engage ainsi sur
//! *cette* action, et un tiers qui a le corps et l'aléa la vérifie sans croire
//! `ca-server` (décision O7 révisée, constat A-1).

pub use webauthn_rs::prelude::{
    AttestationCaList, AttestedPasskey, AttestedPasskeyAuthentication, AttestedPasskeyRegistration,
    CreationChallengeResponse, PublicKeyCredential, RegisterPublicKeyCredential,
    RequestChallengeResponse, Url, Uuid,
};
use webauthn_rs::prelude::{AttestationCaListBuilder, CredentialID};
use webauthn_rs::{Webauthn, WebauthnBuilder};

mod decoy;
pub use decoy::decoy_authentication_challenge;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("configuration WebAuthn : {0}")]
    Config(String),
    #[error("liste blanche de modèles vide : aucune clé ne pourrait être admise")]
    NoTrustedModel,
    #[error("racine d'attestation illisible ({model}) : {detail}")]
    BadRoot { model: String, detail: String },
    #[error("vérification WebAuthn refusée : {0}")]
    Rejected(#[from] webauthn_rs::prelude::WebauthnError),
    #[error("clé synchronisable (BE) refusée : elle peut exister en plusieurs exemplaires")]
    CopyableKey,
    #[error("vérification de l'utilisateur absente : PIN ou biométrie obligatoire")]
    UserNotVerified,
    #[error("compteur de signatures en régression ({seen} <= {last}) : clonage présumé")]
    CounterRegression { seen: u32, last: u32 },
}

/// Un modèle de clé de sécurité admis : la racine de sa chaîne d'attestation
/// et l'AAGUID qui l'identifie. La racine seule ne suffit pas : un même
/// fabricant signe des modèles que l'association n'a pas retenus.
pub struct TrustedModel<'a> {
    pub root_pem: &'a [u8],
    pub aaguid: Uuid,
    pub description: &'a str,
}

/// Construit la liste blanche. Les modèles viennent d'un fichier versionné
/// dans le dépôt, revu par PR : aucun appel réseau à l'exécution.
pub fn trusted_models(models: &[TrustedModel<'_>]) -> Result<AttestationCaList, Error> {
    if models.is_empty() {
        return Err(Error::NoTrustedModel);
    }
    let mut b = AttestationCaListBuilder::new();
    for m in models {
        b.insert_device_pem(
            m.root_pem,
            m.aaguid,
            m.description.to_string(),
            Default::default(),
        )
        .map_err(|e| Error::BadRoot {
            model: m.description.to_string(),
            detail: e.to_string(),
        })?;
    }
    Ok(b.build())
}

/// Ce que l'attestation d'une clé enregistrée dit du modèle. L'AAGUID a déjà
/// été confronté à la liste blanche par la bibliothèque ; on le lit ici pour
/// le conserver au registre, lisible sans elle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttestationSummary {
    pub aaguid: Uuid,
    /// Forme de l'attestation (`basic`, `attca`, `anonca`, `self`). Jamais
    /// `none` : une clé sans attestation est refusée.
    pub format: &'static str,
}

/// Refuse une clé dont on ne peut pas lire un AAGUID et une attestation
/// vérifiable : sans eux, la clé ne prouverait pas son modèle.
pub fn summarize_attestation(key: &AttestedPasskey) -> Result<AttestationSummary, Error> {
    use webauthn_rs::prelude::{AttestationMetadata, ParsedAttestationData};
    let attestation = key.attestation();
    let format = match attestation.data {
        ParsedAttestationData::Basic(_) => "basic",
        ParsedAttestationData::AttCa(_) => "attca",
        ParsedAttestationData::AnonCa(_) => "anonca",
        ParsedAttestationData::Self_ => "self",
        _ => {
            return Err(Error::Config(
                "attestation absente ou non vérifiable".into(),
            ))
        }
    };
    let aaguid = match attestation.metadata {
        AttestationMetadata::Packed { aaguid } | AttestationMetadata::Tpm { aaguid, .. } => aaguid,
        _ => return Err(Error::Config("AAGUID absent de l'attestation".into())),
    };
    Ok(AttestationSummary { aaguid, format })
}

/// Domaine du challenge lié au corps d'une action : sépare cette dérivation de
/// tout autre usage de SHA-256 sur les mêmes octets.
pub const BOUND_CHALLENGE_DOMAIN: &[u8] = b"open-eidas/action-challenge/v1";

/// Le challenge d'une action : `SHA-256(domaine ‖ SHA-256(corps) ‖ aléa)`. Un
/// auditeur qui a le corps figé et l'aléa le recalcule.
pub fn bound_challenge(body_hash: &[u8], nonce: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(BOUND_CHALLENGE_DOMAIN);
    h.update(body_hash);
    h.update(nonce);
    h.finalize().into()
}

pub struct Verifier {
    webauthn: Webauthn,
    models: AttestationCaList,
    rp_id: String,
}

/// Résultat d'une assertion vérifiée.
#[derive(Debug, PartialEq, Eq)]
pub struct Assertion {
    pub credential_id: Vec<u8>,
    pub counter: u32,
}

impl Verifier {
    /// `rp_id` doit être exactement le nom d'hôte de `origin` (§2) : un RP ID
    /// plus large (le domaine racine) ouvrirait la porte aux autres
    /// sous-domaines, et un RP ID différent produirait un service qui
    /// « fonctionne » avec des garanties plus faibles. Mieux vaut refuser de
    /// démarrer.
    pub fn new(
        rp_id: &str,
        origin: &Url,
        rp_name: &str,
        models: AttestationCaList,
    ) -> Result<Self, Error> {
        if models.is_empty() {
            return Err(Error::NoTrustedModel);
        }
        if origin.host_str() != Some(rp_id) {
            return Err(Error::Config(format!(
                "le RP ID {rp_id:?} doit être exactement le nom d'hôte de l'origine {origin}"
            )));
        }
        if origin.scheme() != "https" && rp_id != "localhost" {
            return Err(Error::Config(format!(
                "origine {origin} : https obligatoire"
            )));
        }
        let webauthn = WebauthnBuilder::new(rp_id, origin)
            .map_err(|e| Error::Config(e.to_string()))?
            .rp_name(rp_name)
            .build()
            .map_err(|e| Error::Config(e.to_string()))?;
        Ok(Verifier {
            webauthn,
            models,
            rp_id: rp_id.to_string(),
        })
    }

    /// Le RP ID de ce vérificateur, pour construire un défi de la même forme
    /// qu'une authentification réelle sans en être une (`decoy_authentication_challenge`).
    pub fn rp_id(&self) -> &str {
        &self.rp_id
    }

    pub fn start_registration(
        &self,
        user_id: Uuid,
        name: &str,
        already_registered: Option<Vec<CredentialID>>,
    ) -> Result<(CreationChallengeResponse, AttestedPasskeyRegistration), Error> {
        Ok(self.webauthn.start_attested_passkey_registration(
            user_id,
            name,
            name,
            already_registered,
            self.models.clone(),
            None,
        )?)
    }

    /// La bibliothèque vérifie l'attestation contre la liste blanche et
    /// l'AAGUID, et refuse une clé synchronisable (`start_attested_passkey_registration`
    /// passe `reject_synchronised_authenticators(true)`, vérifié dans son code).
    /// Le drapeau BE n'est pas lisible sur la clé enregistrée sans la feature
    /// `danger-credential-internals` : il est donc recontrôlé à chaque
    /// assertion (`finish_authentication`), où il est exposé.
    pub fn finish_registration(
        &self,
        reg: &RegisterPublicKeyCredential,
        state: &AttestedPasskeyRegistration,
    ) -> Result<AttestedPasskey, Error> {
        Ok(self
            .webauthn
            .finish_attested_passkey_registration(reg, state)?)
    }

    /// Comme [`Verifier::start_authentication`], mais le challenge est lié au corps
    /// d'une action : `SHA-256(BOUND_CHALLENGE_DOMAIN ‖ body_hash ‖ aléa)`. La
    /// bibliothèque tire l'aléa ; on le garde (3e élément rendu) pour pouvoir
    /// recalculer le challenge, et on le substitue dans les options **et** dans
    /// l'état de la cérémonie, que `finish_authentication` compare à la
    /// `clientDataJSON` de l'assertion.
    ///
    /// Passe par la sérialisation de l'état (feature `danger-allow-state-serialisation`)
    /// : si la bibliothèque en change la forme, on échoue ici plutôt que d'émettre
    /// un challenge que personne ne saurait vérifier.
    pub fn start_bound_authentication(
        &self,
        keys: &[AttestedPasskey],
        body_hash: &[u8],
    ) -> Result<
        (
            RequestChallengeResponse,
            AttestedPasskeyAuthentication,
            Vec<u8>,
        ),
        Error,
    > {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;
        let (mut options, state) = self.start_authentication(keys)?;
        let nonce = options.public_key.challenge.as_ref().to_vec();
        let bound = bound_challenge(body_hash, &nonce);

        let mut json = serde_json::to_value(&state)
            .map_err(|e| Error::Config(format!("état de cérémonie illisible : {e}")))?;
        let slot = json
            .pointer_mut("/ast/challenge")
            .ok_or_else(|| Error::Config("état de cérémonie sans challenge".into()))?;
        *slot = serde_json::Value::String(URL_SAFE_NO_PAD.encode(bound));
        let state: AttestedPasskeyAuthentication = serde_json::from_value(json)
            .map_err(|e| Error::Config(format!("état de cérémonie illisible : {e}")))?;

        options.public_key.challenge = bound.to_vec().into();
        Ok((options, state, nonce))
    }

    pub fn start_authentication(
        &self,
        keys: &[AttestedPasskey],
    ) -> Result<(RequestChallengeResponse, AttestedPasskeyAuthentication), Error> {
        Ok(self.webauthn.start_attested_passkey_authentication(keys)?)
    }

    /// `last_counter` est le dernier compteur vu par l'appelant pour cette clé.
    /// Un authentificateur sans compteur renvoie toujours 0 : c'est admis tant
    /// que le compteur n'a jamais été positif. Une fois positif, il ne doit
    /// plus reculer, ni même stagner.
    pub fn finish_authentication(
        &self,
        response: &PublicKeyCredential,
        state: &AttestedPasskeyAuthentication,
        last_counter: u32,
    ) -> Result<Assertion, Error> {
        let res = self
            .webauthn
            .finish_attested_passkey_authentication(response, state)?;
        if !res.user_verified() {
            return Err(Error::UserNotVerified);
        }
        if res.backup_eligible() || res.backup_state() {
            return Err(Error::CopyableKey);
        }
        let seen = res.counter();
        if last_counter > 0 && seen <= last_counter {
            return Err(Error::CounterRegression {
                seen,
                last: last_counter,
            });
        }
        Ok(Assertion {
            credential_id: res.cred_id().as_ref().to_vec(),
            counter: seen,
        })
    }
}
