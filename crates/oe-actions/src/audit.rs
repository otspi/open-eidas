//! Audit de la chaîne du registre (docs/WEBUI.md §21, `operators audit`).
//!
//! Toute clé du registre est entrée par une action signée avec une clé déjà
//! présente, et la remontée s'arrête à un premier administrateur amorcé
//! localement (§10). Ce module refait ce chemin pour chaque clé active, sans
//! croire la base sur parole :
//!
//!   * une clé **confirmée** doit avoir une action `confirm_key` exécutée, dont le
//!     corps n'a pas bougé (empreinte de `actions.body_hash`), qui engage bien
//!     *cette* clé (empreinte signée), signée par assez d'opérateurs distincts et
//!     **dont chaque signature se re-vérifie** contre la clé du signataire, qui a
//!     lui-même une chaîne valide. Qui insère une ligne en SQL ne peut pas
//!     fabriquer la signature d'une clé existante ;
//!   * une clé **d'ancre** (amorçage, récupération) ne se prouve pas dans la base :
//!     la contrainte du registre l'admet sans confirmation, donc n'importe qui
//!     pouvant écrire en base pourrait s'en donner une. Elle doit figurer au
//!     journal chaîné, que la base ne contrôle pas.
//!
//! La signature WebAuthn porte sur le challenge tiré par la bibliothèque, pas sur
//! le corps de l'action (décision O7) : le lien corps ↔ signature est celui que
//! `ca-server` a écrit au journal *avant* de faire signer. Un corps réécrit avec
//! son empreinte, cohérents entre eux, passerait la cryptographie : c'est le
//! journal, hors de portée de la base, qui le trahit.
//!
//! Le journal fait foi pour le registre, pas l'inverse : une confirmation absente
//! du journal est signalée même si sa signature est bonne.

use std::collections::{HashMap, HashSet};

use oe_webauthn::{AttestedPasskey, Uuid};
use sha2::{Digest, Sha256};
use sqlx::Row;

use crate::assertion::verify_assertion;
use crate::enrollment::key_fingerprint;
use crate::onboarding::RECOVERY;
use crate::{Action, Body, Error, Registry};

/// Marque des invitations d'amorçage (`created_by`, `initiated_by`).
const BOOTSTRAP: &str = "bootstrap-admin";

/// Ce que le journal chaîné atteste du registre.
#[derive(Debug, Default, Clone)]
pub struct JournalView {
    registered_active: HashSet<String>,
    confirmed: HashSet<String>,
    /// Empreinte du corps consignée à l'émission du challenge, par action.
    issued: HashMap<String, String>,
}

impl JournalView {
    /// Construit la vue à partir des événements `(nom, données)` du journal,
    /// dont l'appelant a déjà contrôlé la chaîne.
    pub fn from_events(events: impl IntoIterator<Item = (String, serde_json::Value)>) -> Self {
        let mut view = JournalView::default();
        for (event, data) in events {
            if event == "operators.action_challenge_issued" {
                if let (Some(action), Some(hash)) = (
                    data.get("action_id").and_then(|v| v.as_str()),
                    data.get("body_hash").and_then(|v| v.as_str()),
                ) {
                    // Le premier consigné fait foi : un signataire de plus sur la
                    // même action répète la même empreinte.
                    view.issued
                        .entry(action.to_string())
                        .or_insert_with(|| hash.to_string());
                }
                continue;
            }
            let Some(id) = data.get("credential_id").and_then(|v| v.as_str()) else {
                continue;
            };
            match event.as_str() {
                // Une clé entrée directement dans le registre : l'ancre.
                "operators.credential_registered"
                    if data.get("statut").and_then(|v| v.as_str()) == Some("active") =>
                {
                    view.registered_active.insert(id.to_string());
                }
                "operators.key_confirmed" => {
                    view.confirmed.insert(id.to_string());
                }
                _ => {}
            }
        }
        view
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Clé d'amorçage ou de récupération, attestée par le journal.
    Anchor,
    /// Clé confirmée par une chaîne de signatures valides ; `depth` est le
    /// nombre de confirmations jusqu'à l'ancre.
    Chained { depth: u32 },
}

#[derive(Debug)]
pub struct KeyReport {
    pub credential_id: String,
    pub operator: String,
    pub verdict: Result<Verdict, String>,
}

#[derive(Debug)]
pub struct AuditReport {
    pub keys: Vec<KeyReport>,
}

impl AuditReport {
    /// Les clés actives sans chaîne valide.
    pub fn findings(&self) -> Vec<&KeyReport> {
        self.keys.iter().filter(|k| k.verdict.is_err()).collect()
    }

    pub fn is_clean(&self) -> bool {
        self.findings().is_empty()
    }
}

struct Cred {
    operator_id: Uuid,
    operator: String,
    passkey: serde_json::Value,
    initiated_by: String,
    confirmed_by: Option<String>,
    revoked: bool,
}

struct Evidence {
    /// Aléa du challenge lié au corps (décision O7 révisée) ; `None` pour une preuve
    /// antérieure, dont le challenge était tiré au hasard.
    nonce: Option<Vec<u8>>,
    credential_id: String,
    operator_id: Uuid,
    authenticator_data: Vec<u8>,
    client_data_json: Vec<u8>,
    signature: Vec<u8>,
    challenge: Vec<u8>,
}

struct Confirmation {
    action_id: String,
    body: serde_json::Value,
    body_hash: Vec<u8>,
    required: u32,
    evidence: Vec<Evidence>,
}

struct Auditor<'a> {
    creds: HashMap<String, Cred>,
    confirmations: HashMap<String, Vec<Confirmation>>,
    journal: &'a JournalView,
}

/// Audite toutes les clés actives du registre.
pub async fn audit_registry(
    registry: &Registry,
    journal: &JournalView,
) -> Result<AuditReport, Error> {
    let pool = registry.pool();

    let mut creds = HashMap::new();
    let mut order = Vec::new();
    for r in sqlx::query(
        "SELECT c.credential_id, c.operator_id, o.name, c.passkey, c.initiated_by,
                c.confirmed_by, c.revoked_at
         FROM webauthn_credentials c JOIN operators o ON o.id = c.operator_id
         ORDER BY c.initiated_at, c.credential_id",
    )
    .fetch_all(pool)
    .await?
    {
        let id: String = r.get("credential_id");
        order.push(id.clone());
        creds.insert(
            id,
            Cred {
                operator_id: r.get("operator_id"),
                operator: r.get("name"),
                passkey: r.get("passkey"),
                initiated_by: r.get("initiated_by"),
                confirmed_by: r.get("confirmed_by"),
                revoked: r
                    .get::<Option<time::OffsetDateTime>, _>("revoked_at")
                    .is_some(),
            },
        );
    }

    // Toutes les confirmations exécutées, avec leurs signatures et le challenge
    // que `ca-server` avait émis pour chacune.
    let mut confirmations: HashMap<String, Vec<Confirmation>> = HashMap::new();
    for a in sqlx::query(
        "SELECT id, body, body_hash, required_signatures FROM actions
         WHERE executed_at IS NOT NULL AND body->>'action' = 'confirm_key'",
    )
    .fetch_all(pool)
    .await?
    {
        let action_id: Uuid = a.get("id");
        let body: serde_json::Value = a.get("body");
        let Some(target) = body
            .get("credential_id")
            .and_then(|v| v.as_str())
            .map(str::to_string)
        else {
            continue;
        };
        let evidence = sqlx::query(
            "SELECT e.credential_id, e.operator_id, e.authenticator_data, e.client_data_json,
                    e.signature, c.challenge, c.nonce
             FROM decision_evidence e JOIN action_challenges c ON c.challenge_id = e.challenge_id
             WHERE e.action_id = $1 ORDER BY e.verified_at, e.id",
        )
        .bind(action_id)
        .fetch_all(pool)
        .await?
        .into_iter()
        .map(|e| Evidence {
            credential_id: e.get("credential_id"),
            operator_id: e.get("operator_id"),
            authenticator_data: e.get("authenticator_data"),
            client_data_json: e.get("client_data_json"),
            signature: e.get("signature"),
            challenge: e.get("challenge"),
            nonce: e.get("nonce"),
        })
        .collect();
        confirmations.entry(target).or_default().push(Confirmation {
            action_id: action_id.to_string(),
            body,
            body_hash: a.get("body_hash"),
            required: a.get::<i32, _>("required_signatures") as u32,
            evidence,
        });
    }

    let auditor = Auditor {
        creds,
        confirmations,
        journal,
    };
    let mut memo = HashMap::new();
    let mut keys = Vec::new();
    for id in order {
        let cred = &auditor.creds[&id];
        if cred.revoked {
            continue;
        }
        let verdict = auditor.check(&id, &mut Vec::new(), &mut memo).map(|depth| {
            if depth == 0 {
                Verdict::Anchor
            } else {
                Verdict::Chained { depth }
            }
        });
        keys.push(KeyReport {
            credential_id: id,
            operator: cred.operator.clone(),
            verdict,
        });
    }
    Ok(AuditReport { keys })
}

impl Auditor<'_> {
    /// Profondeur de la chaîne de `id` (0 pour une ancre), ou la raison pour
    /// laquelle elle n'existe pas.
    fn check(
        &self,
        id: &str,
        visiting: &mut Vec<String>,
        memo: &mut HashMap<String, Result<u32, String>>,
    ) -> Result<u32, String> {
        if let Some(known) = memo.get(id) {
            return known.clone();
        }
        if visiting.iter().any(|v| v == id) {
            return Err("cycle de confirmations : aucune ancre n'est atteinte".to_string());
        }
        visiting.push(id.to_string());
        let result = self.check_uncached(id, visiting, memo);
        visiting.pop();
        memo.insert(id.to_string(), result.clone());
        result
    }

    fn check_uncached(
        &self,
        id: &str,
        visiting: &mut Vec<String>,
        memo: &mut HashMap<String, Result<u32, String>>,
    ) -> Result<u32, String> {
        let cred = self.creds.get(id).ok_or("clé inconnue du registre")?;

        if cred.initiated_by == BOOTSTRAP || cred.initiated_by == RECOVERY {
            return if self.journal.registered_active.contains(id) {
                Ok(0)
            } else {
                Err("clé d'amorçage ou de récupération absente du journal : \
                     elle n'est attestée que par la base"
                    .to_string())
            };
        }

        let candidates = self
            .confirmations
            .get(id)
            .ok_or("aucune confirmation signée pour cette clé")?;
        let mut last = String::new();
        for c in candidates {
            match self.check_confirmation(id, cred, c, visiting, memo) {
                Ok(depth) => return Ok(depth),
                Err(e) => last = e,
            }
        }
        Err(last)
    }

    fn check_confirmation(
        &self,
        id: &str,
        cred: &Cred,
        c: &Confirmation,
        visiting: &mut Vec<String>,
        memo: &mut HashMap<String, Result<u32, String>>,
    ) -> Result<u32, String> {
        // Le corps n'a pas bougé depuis l'émission des challenges.
        let body: Body = serde_json::from_value(c.body.clone())
            .map_err(|e| format!("corps de l'action illisible: {e}"))?;
        let canonical = serde_json::to_string(&body).map_err(|e| e.to_string())?;
        if Sha256::digest(canonical.as_bytes()).as_slice() != c.body_hash.as_slice() {
            return Err("le corps de l'action ne correspond plus à son empreinte".to_string());
        }
        // Et il engage bien cette clé, pas une autre.
        let Action::ConfirmKey {
            credential_id,
            key_fingerprint: signed,
        } = &body.action
        else {
            return Err("l'action n'est pas une confirmation de clé".to_string());
        };
        let passkey: AttestedPasskey = serde_json::from_value(cred.passkey.clone())
            .map_err(|e| format!("clé illisible: {e}"))?;
        let actual = key_fingerprint(&passkey).map_err(|e| e.to_string())?;
        if credential_id != id || *signed != actual {
            return Err("l'empreinte signée n'est pas celle de la clé du registre".to_string());
        }

        let distinct: HashSet<Uuid> = c.evidence.iter().map(|e| e.operator_id).collect();
        if distinct.is_empty() || (distinct.len() as u32) < c.required {
            return Err(format!(
                "{} signataire(s) distinct(s) sur {} exigés",
                distinct.len(),
                c.required
            ));
        }

        let mut depth = 0;
        let mut unbound: Option<String> = None;
        let mut signers = Vec::new();
        for ev in &c.evidence {
            let signer = self
                .creds
                .get(&ev.credential_id)
                .ok_or("clé du signataire inconnue du registre")?;
            if signer.operator_id != ev.operator_id {
                return Err("la clé du signataire n'appartient pas à l'opérateur inscrit".into());
            }
            if signer.operator_id == cred.operator_id {
                return Err("une clé ne se confirme pas elle-même".to_string());
            }
            verify_assertion(
                &signer.passkey["cred"]["cred"],
                &ev.authenticator_data,
                &ev.client_data_json,
                &ev.signature,
                &ev.challenge,
            )
            .map_err(|e| format!("signature de {} refusée: {e}", signer.operator))?;
            // Le challenge signé dérive du corps figé : un tiers qui a le corps
            // et l'aléa le recalcule, sans croire `ca-server`. Constaté ici, signalé
            // après le contrôle du journal (qui dit mieux ce qui a été réécrit).
            if let Some(nonce) = &ev.nonce {
                let bound = oe_webauthn::bound_challenge(&c.body_hash, nonce);
                if bound.as_slice() != ev.challenge.as_slice() && unbound.is_none() {
                    unbound = Some(format!(
                        "le challenge signé par {} ne dérive pas du corps de l'action",
                        signer.operator
                    ));
                }
            }
            let d = self.check(&ev.credential_id, visiting, memo).map_err(|e| {
                format!(
                    "le signataire {} n'a pas de chaîne valide: {e}",
                    signer.operator
                )
            })?;
            depth = depth.max(d);
            signers.push(signer.operator.as_str());
        }
        // Le corps que les signataires ont vu est celui que le journal a consigné
        // avant leur signature : la base seule ne peut pas le réécrire.
        match self.journal.issued.get(&c.action_id) {
            Some(logged) if *logged == hex::encode(&c.body_hash) => {}
            Some(_) => {
                return Err(
                    "le corps de l'action diffère de celui que le journal a consigné \
                     avant la signature"
                        .to_string(),
                )
            }
            None => return Err("action absente du journal chaîné".to_string()),
        }
        if let Some(reason) = unbound {
            return Err(reason);
        }
        match cred.confirmed_by.as_deref() {
            Some(by) if signers.contains(&by) => {}
            _ => return Err("« confirmé par » ne désigne aucun des signataires".to_string()),
        }
        if !self.journal.confirmed.contains(id) {
            return Err("confirmation absente du journal chaîné".to_string());
        }
        Ok(depth + 1)
    }
}
