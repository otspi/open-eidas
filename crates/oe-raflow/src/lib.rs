//! Portage de `internal/raflow` : la machine à états d'enrôlement et
//! d'approbation de l'autorité d'enregistrement (RA). Rang 3 de l'ordre de
//! portage (`/home/philippe/.claude/plans/witty-hopping-nest.md`), dernier
//! morceau majeur avant `bin/ca-server`.
//!
//! ```text
//!            (HMAC valide)      (approbation, opérateur)      (émission)
//! CSR ──────────────────► PENDING ──────────────────► APPROVED ─────────► ISSUED
//!                            │
//!                            └──── (rejet, opérateur) ────► REJECTED
//! ```
//!
//! Deux propriétés, chacune corrigeant un défaut constaté sur OpenXPKI (voir
//! `INDEPENDANCE.md`), sont le cœur de ce paquet :
//!
//!   - aucune fonction ne fait passer une demande de PENDING à ISSUED sans
//!     passer par [`Decider::approve`] : pas de règle d'éligibilité
//!     automatique, pas d'auto-approbation, pas de chemin dérobé ;
//!   - [`Decider::approve`]/[`Decider::reject`] exigent l'identité de
//!     l'opérateur, consignée en base et au journal d'audit (ETSI EN
//!     319 411-1 §6.3.2, §6.4.5).
//!
//! **Écart assumé** : `Decider` ne détient jamais la clé de l'autorité —
//! approuver, c'est décider, pas signer (à l'identique du Go : la commande
//! `ca-server ra approve` n'ouvre aucun token PKCS#11).

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use x509_cert::request::CertReq;

/// Voie par laquelle l'opérateur d'une décision a été identifié (constat R-1).
pub use oe_ca_core::{SystemIdentity, Via};
use oe_castore::{Request, RequestState, Store, StoreError};

#[derive(Debug, thiserror::Error)]
pub enum RaflowError {
    #[error("raflow: demande non authentifiée")]
    Unauthenticated,
    #[error(
        "raflow: demande rejetée par l'autorité d'enregistrement (opérateur {operator}{})",
        comment_suffix(comment)
    )]
    Rejected { operator: String, comment: String },
    #[error("raflow: demande inconnue")]
    NotFound,
    #[error("raflow: la demande n'est plus en attente de décision (état actuel: {0})")]
    NotPending(String),
    #[error("raflow: {0}")]
    Der(#[from] der::Error),
    #[error("raflow: {0}")]
    Ca(#[from] oe_ca_core::CaError),
    #[error("raflow: {0}")]
    Store(#[from] StoreError),
    #[error("raflow: {0}")]
    Other(String),
}

fn comment_suffix(c: &str) -> String {
    if c.is_empty() {
        String::new()
    } else {
        format!(" : {c}")
    }
}

/// Consigne les décisions au journal d'audit — reproduit `raflow.Recorder`
/// (Go), découplé de `oe-audit` par la même convention que
/// `oe_ca_core::Recorder`.
///
/// Async et bloquant, comme `oe_ca_core::Recorder` (docs/WEBUI.md §15 étape
/// 2b) : son échec propage une erreur plutôt que d'être ignoré. `Flow::open`
/// journalise *avant* d'enregistrer la demande (rien d'irréversible n'a
/// encore eu lieu si le journal échoue). `Decider::decide` est l'exception
/// documentée : l'écriture optimiste (`update_request`, CAS sur l'état
/// `Pending`) doit rester *avant* le journal, car c'est elle qui départage
/// deux décisions concurrentes sur la même demande — journaliser avant
/// risquerait de consigner une décision qui perd la course et n'a jamais eu
/// lieu.
#[async_trait::async_trait]
pub trait Recorder: Send + Sync {
    async fn append(&self, event: &str, data: serde_json::Value) -> Result<(), String>;
}

/// Authentifiant HMAC-SHA256 attendu sur les octets DER bruts d'une CSR. Le
/// client ([`oe_enroll`]) et le serveur calculent la même fonction : le
/// protocole est défini par ce dépôt, pas déduit du comportement d'un tiers.
pub fn signature(csr_der: &[u8], secret: &str) -> String {
    let mut mac =
        Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("clé HMAC de taille arbitraire");
    mac.update(csr_der);
    hex::encode(mac.finalize().into_bytes())
}

/// Empreinte SHA-256 hexadécimale de la CSR — clé d'idempotence : re-soumettre
/// la même CSR retrouve la même demande.
pub fn fingerprint(csr_der: &[u8]) -> String {
    hex::encode(Sha256::digest(csr_der))
}

/// Identifiant public d'une demande, dérivé déterministiquement de sa CSR :
/// un demandeur qui l'a perdu peut le recalculer sans état côté client.
pub fn transaction_id(csr_der: &[u8]) -> String {
    fingerprint(csr_der)[..32].to_string()
}

fn verify_hmac(csr_der: &[u8], secret: &str, signature_hex: &str) -> Result<(), RaflowError> {
    let given = hex::decode(signature_hex).map_err(|_| RaflowError::Unauthenticated)?;
    let mut mac =
        Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("clé HMAC de taille arbitraire");
    mac.update(csr_der);
    mac.verify_slice(&given)
        .map_err(|_| RaflowError::Unauthenticated)
}

/// ETSI TS 119 312 §8.4 : longueur de clé RSA minimale, la même exigence
/// qu'`OPENEIDAS_CA_KEY_BITS`/`OPENEIDAS_KEY_BITS` imposent déjà à la
/// configuration des autorités elles-mêmes — appliquée ici à la clé
/// publique portée par la demande d'un tiers, que la configuration ne
/// contrôle pas.
const MIN_RSA_KEY_BITS: usize = 3072;

/// Sujet CN et clé publique (SPKI DER) d'une CSR PKCS#10, après vérification
/// qu'elle est bien signée par la clé privée correspondant à cette même clé
/// publique — reproduit `x509.CertificateRequest.CheckSignature` (Go).
/// Seul RSA/SHA-256 est accepté : c'est le seul algorithme que `oe-hsm`
/// sait produire à ce stade (`Pkcs11Token::generate_rsa_key`), et SHA-1
/// n'est jamais une option (ETSI TS 119 312).
fn parse_and_verify_csr(csr_der: &[u8]) -> Result<(String, Vec<u8>), RaflowError> {
    use der::{Decode, Encode};
    use rsa::pkcs8::DecodePublicKey;
    use rsa::traits::PublicKeyParts;
    use rsa::RsaPublicKey;

    let csr = CertReq::from_der(csr_der)?;
    let spki_der = csr.info.public_key.to_der()?;
    let public_key = RsaPublicKey::from_public_key_der(&spki_der)
        .map_err(|e| RaflowError::Other(format!("clé publique de la demande illisible: {e}")))?;

    let key_bits = public_key.n().bits();
    if key_bits < MIN_RSA_KEY_BITS {
        return Err(RaflowError::Other(format!(
            "clé RSA de {key_bits} bits: ETSI TS 119 312 impose au moins {MIN_RSA_KEY_BITS} bits"
        )));
    }

    let tbs_der = csr.info.to_der()?;
    // Schéma et condensé déclarés par la demande, s'ils sont admis (PKCS#1 v1.5
    // ou RSASSA-PSS, SHA-2) ; SHA-1 n'est jamais une option (ETSI TS 119 312).
    let (scheme, alg) = oe_hsm::scheme_of(&csr.algorithm).ok_or_else(|| {
        RaflowError::Other(format!(
            "algorithme de signature de la demande non admis : {}",
            csr.algorithm.oid
        ))
    })?;
    oe_hsm::verify_signature_with(
        &public_key,
        scheme,
        alg,
        &alg.hash(&tbs_der),
        csr.signature.raw_bytes(),
    )
    .map_err(|_| {
        RaflowError::Other("la demande n'est pas signée par la clé qu'elle présente".to_string())
    })?;

    let cn = common_name(&csr.info.subject);
    if cn.is_empty() {
        return Err(RaflowError::Other(
            "la demande ne porte pas de nom courant (CN)".to_string(),
        ));
    }
    Ok((cn, spki_der))
}

fn common_name(name: &x509_cert::name::Name) -> String {
    const OID_CN: &str = "2.5.4.3";
    let cn_oid = der::asn1::ObjectIdentifier::new(OID_CN).expect("OID constant invalide");
    name.iter()
        .find(|atv| atv.oid == cn_oid)
        .map(|atv| String::from_utf8_lossy(atv.value.value()).into_owned())
        .unwrap_or_default()
}

/// Configure la partie « décision » de la machine à états.
///
/// Séparée du reste parce qu'un opérateur RA n'a aucune raison de détenir
/// la clé de l'autorité.
pub struct DeciderOptions {
    pub store: std::sync::Arc<dyn Store>,
    pub recorder: Option<std::sync::Arc<dyn Recorder>>,
    pub clock: Option<std::sync::Arc<dyn Fn() -> time::OffsetDateTime + Send + Sync>>,
}

/// Porte les transitions PENDING → APPROVED et PENDING → REJECTED.
pub struct Decider {
    opts: DeciderOptions,
}

impl Decider {
    pub fn new(opts: DeciderOptions) -> Decider {
        Decider { opts }
    }

    fn now(&self) -> time::OffsetDateTime {
        match &self.opts.clock {
            Some(clock) => clock(),
            None => time::OffsetDateTime::now_utc(),
        }
    }

    async fn record(&self, event: &str, data: serde_json::Value) -> Result<(), RaflowError> {
        if let Some(recorder) = &self.opts.recorder {
            recorder
                .append(event, data)
                .await
                .map_err(|e| RaflowError::Other(format!("journal : {e}")))?;
        }
        Ok(())
    }

    /// Fait passer une demande de PENDING à APPROVED. C'est la SEULE
    /// transition qui y mène, et elle exige l'identité de l'opérateur :
    /// c'est ce qui rend la décision imputable (ETSI EN 319 411-1 §6.4.5, REG-6.4.5-04).
    pub async fn approve(
        &self,
        transaction_id: &str,
        operator: &str,
        comment: &str,
        via: &Via,
    ) -> Result<Request, RaflowError> {
        self.decide(
            transaction_id,
            operator,
            comment,
            via,
            RequestState::Approved,
        )
        .await
    }

    /// Refuse définitivement une demande. Le demandeur en est informé lors
    /// de sa prochaine soumission, avec le nom de l'opérateur et son motif.
    pub async fn reject(
        &self,
        transaction_id: &str,
        operator: &str,
        comment: &str,
        via: &Via,
    ) -> Result<Request, RaflowError> {
        self.decide(
            transaction_id,
            operator,
            comment,
            via,
            RequestState::Rejected,
        )
        .await
    }

    async fn decide(
        &self,
        transaction_id: &str,
        operator: &str,
        comment: &str,
        via: &Via,
        target: RequestState,
    ) -> Result<Request, RaflowError> {
        if operator.is_empty() {
            return Err(RaflowError::Other(
                "la décision exige l'identité de l'opérateur qui la prend".to_string(),
            ));
        }
        via.check_comment(comment).map_err(RaflowError::Other)?;
        let r = match self
            .opts
            .store
            .request_by_transaction_id(transaction_id)
            .await
        {
            Ok(r) => r,
            Err(StoreError::NotFound) => return Err(RaflowError::NotFound),
            Err(e) => return Err(e.into()),
        };
        if r.state != RequestState::Pending {
            return Err(RaflowError::NotPending(r.state.to_string()));
        }

        let mut updated = r.clone();
        updated.state = target;
        updated.operator = operator.to_string();
        updated.comment = comment.to_string();
        updated.decided_at = Some(self.now());
        match self
            .opts
            .store
            .update_request(updated.clone(), RequestState::Pending)
            .await
        {
            Ok(()) => {}
            Err(StoreError::Conflict) => {
                return Err(RaflowError::NotPending(RequestState::Pending.to_string()))
            }
            Err(e) => return Err(e.into()),
        }

        let event = if target == RequestState::Rejected {
            "ca.request_rejected"
        } else {
            "ca.request_approved"
        };
        // Exception documentée (voir `Recorder`) : l'écriture optimiste
        // ci-dessus, qui départage deux décisions concurrentes, reste avant
        // le journal — pas après, comme partout ailleurs.
        let mut data = serde_json::json!({
            "transaction": updated.transaction_id,
            "profil": updated.profile,
            "sujet_cn": updated.subject_cn,
            "operateur": operator,
            "commentaire": comment,
        });
        via.annotate(&mut data);
        self.record(event, data).await?;
        Ok(updated)
    }

    /// Liste les demandes dans l'état donné (toutes si `None`), pour
    /// l'interface d'exploitation de l'opérateur RA.
    pub async fn requests(&self, state: Option<RequestState>) -> Result<Vec<Request>, RaflowError> {
        Ok(self.opts.store.requests(state).await?)
    }
}

/// Nom du demandeur qui s'authentifie avec l'unique secret historique.
pub const LEGACY_REQUESTER: &str = "legacy";

/// Un demandeur d'enrôlement : son secret HMAC, les profils qu'il peut demander
/// et, optionnellement, le CN unique qu'il peut porter (constat R-3, EN 319
/// 411-1 `REG-6.3.2-01`).
#[derive(Clone, Default)]
pub struct Requester {
    pub name: String,
    /// Secret HMAC. Vide pour un demandeur qui ne s'authentifie que par son
    /// certificat client (`client_cn`).
    pub secret: String,
    /// Fin de validité du secret (amorçage à durée limitée) ; passé ce terme, il
    /// n'authentifie plus.
    pub secret_expires_at: Option<time::OffsetDateTime>,
    /// Nom courant du certificat client (profil `enroll_client`) qui identifie ce
    /// demandeur sur le port d'enrôlement en TLS mutuel (docs/R3-MTLS-DEMANDEURS.md).
    pub client_cn: Option<String>,
    /// Noms de profils autorisés ; `*` pour tous.
    pub profiles: Vec<String>,
    /// CN imposé, `None` pour laisser la validation du profil seule juge.
    pub subject_cn: Option<String>,
}

impl Requester {
    fn allows(&self, profile: &str) -> bool {
        self.profiles.iter().any(|p| p == "*" || p == profile)
    }
}

/// Un demandeur vide (demande antérieure à R-3) est le demandeur historique.
fn requester_key(name: &str) -> &str {
    if name.is_empty() {
        LEGACY_REQUESTER
    } else {
        name
    }
}

/// Configure la machine à états complète (décision et émission).
pub struct Options {
    pub store: std::sync::Arc<dyn Store>,
    pub issuer: std::sync::Arc<oe_ca_core::Issuer>,
    /// Authentifie le demandeur. Vide, l'enrôlement deviendrait anonyme :
    /// refusé explicitement à la construction plutôt que toléré par défaut.
    ///
    /// Secret historique, partagé : il identifie le demandeur [`LEGACY_REQUESTER`],
    /// autorisé pour tous les profils. Remplacé par `requesters` (constat R-3).
    pub hmac_secret: String,
    /// Un secret par demandeur, lié aux profils qu'il peut demander (constat R-3).
    pub requesters: Vec<Requester>,
    pub recorder: Option<std::sync::Arc<dyn Recorder>>,
    /// Délai suggéré au client tant que sa demande attend une décision.
    pub retry_after: time::Duration,
    pub clock: Option<std::sync::Arc<dyn Fn() -> time::OffsetDateTime + Send + Sync>>,
}

/// Issue d'une soumission.
#[derive(Debug)]
pub struct SubmitResult {
    pub state: RequestState,
    pub transaction_id: String,
    /// Renseigné tant que la demande attend une décision.
    pub retry_after: Option<time::Duration>,
    /// Renseignés seulement à l'état `Issued`.
    pub certificate: Option<x509_cert::Certificate>,
    pub chain: Vec<x509_cert::Certificate>,
}

/// La machine à états complète : décision (par composition d'un
/// [`Decider`]) et émission.
pub struct Flow {
    decider: Decider,
    opts: Options,
    /// Demandeurs reconnus : ceux d'`Options::requesters`, puis le demandeur
    /// historique si son secret est configuré.
    requesters: Vec<Requester>,
}

impl Flow {
    pub fn new(opts: Options) -> Result<Flow, RaflowError> {
        let mut requesters = opts.requesters.clone();
        if !opts.hmac_secret.is_empty() {
            requesters.push(Requester {
                name: LEGACY_REQUESTER.to_string(),
                secret: opts.hmac_secret.clone(),
                profiles: vec!["*".to_string()],
                subject_cn: None,
                ..Default::default()
            });
        }
        // Une PKI qui délivre à quiconque le demande n'a pas de valeur : un
        // secret partagé n'est pas une identité, mais il est le minimum.
        // Un demandeur s'authentifie par un secret, un certificat client, ou les deux.
        if requesters.is_empty()
            || requesters
                .iter()
                .any(|r| r.secret.is_empty() && r.client_cn.as_deref().unwrap_or("").is_empty())
        {
            return Err(RaflowError::Other(
                "secret HMAC d'enrôlement non configuré (enrôlement anonyme refusé)".to_string(),
            ));
        }
        let mut cns = std::collections::HashSet::new();
        for cn in requesters.iter().filter_map(|r| r.client_cn.as_deref()) {
            if !cns.insert(cn) {
                return Err(RaflowError::Other(format!(
                    "le certificat client {cn:?} identifie deux demandeurs"
                )));
            }
        }
        if requesters.iter().any(|r| r.name.is_empty()) {
            return Err(RaflowError::Other(
                "un demandeur d'enrôlement sans nom".to_string(),
            ));
        }
        let retry_after = if opts.retry_after.is_zero() {
            time::Duration::seconds(5)
        } else {
            opts.retry_after
        };
        let decider = Decider::new(DeciderOptions {
            store: opts.store.clone(),
            recorder: opts.recorder.clone(),
            clock: opts.clock.clone(),
        });
        Ok(Flow {
            decider,
            opts: Options {
                retry_after,
                ..opts
            },
            requesters,
        })
    }

    pub fn decider(&self) -> &Decider {
        &self.decider
    }

    fn now(&self) -> time::OffsetDateTime {
        match &self.opts.clock {
            Some(clock) => clock(),
            None => time::OffsetDateTime::now_utc(),
        }
    }

    async fn record(&self, event: &str, data: serde_json::Value) -> Result<(), RaflowError> {
        if let Some(recorder) = &self.opts.recorder {
            recorder
                .append(event, data)
                .await
                .map_err(|e| RaflowError::Other(format!("journal : {e}")))?;
        }
        Ok(())
    }

    /// Reçoit une demande d'enrôlement, ou reprend celle qui correspond
    /// déjà à cette CSR.
    ///
    /// C'est aussi le point où une demande approuvée devient un certificat :
    /// l'émission a lieu ici, dans le processus qui détient la clé de
    /// l'autorité, et non au moment de l'approbation — l'opérateur RA
    /// décide, il ne signe pas.
    pub async fn submit(
        &self,
        csr_der: &[u8],
        profile_name: &str,
        signature_hex: &str,
    ) -> Result<SubmitResult, RaflowError> {
        let now = self.now();
        let requester = self
            .requesters
            .iter()
            .find(|r| {
                !r.secret.is_empty()
                    && r.secret_expires_at.is_none_or(|end| now <= end)
                    && verify_hmac(csr_der, &r.secret, signature_hex).is_ok()
            })
            .ok_or(RaflowError::Unauthenticated)?;
        // Amorçage (docs/R3-MTLS-DEMANDEURS.md §3) : le secret ne vaut qu'une fois
        // pour un certificat client ; ensuite, le demandeur s'identifie par lui.
        if profile_name == oe_ca_core::profile::PROFILE_ENROLL_CLIENT {
            self.ensure_bootstrap_unused(requester, csr_der).await?;
        }
        self.submit_as(requester, csr_der, profile_name).await
    }

    /// Soumission d'un demandeur authentifié par son **certificat client** (port
    /// d'enrôlement en TLS mutuel) : `client_cn` est le nom courant d'un certificat
    /// que la couche TLS a déjà vérifié (chaîne, validité, statut). Aucun HMAC.
    pub async fn submit_mtls(
        &self,
        csr_der: &[u8],
        profile_name: &str,
        client_cn: &str,
    ) -> Result<SubmitResult, RaflowError> {
        let requester = self
            .requesters
            .iter()
            .find(|r| r.client_cn.as_deref() == Some(client_cn))
            .ok_or(RaflowError::Unauthenticated)?;
        self.submit_as(requester, csr_der, profile_name).await
    }

    /// Un secret d'amorçage n'ouvre qu'une demande de certificat client : une
    /// autre CSR `enroll_client` du même demandeur est refusée (la même CSR, elle,
    /// se reprend, pour que le demandeur puisse attendre la décision).
    async fn ensure_bootstrap_unused(
        &self,
        requester: &Requester,
        csr_der: &[u8],
    ) -> Result<(), RaflowError> {
        let fp = fingerprint(csr_der);
        let others = self.opts.store.requests(None).await?.into_iter().any(|r| {
            r.profile == oe_ca_core::profile::PROFILE_ENROLL_CLIENT
                && requester_key(&r.requester) == requester.name
                && r.csr_fingerprint != fp
                && r.state != RequestState::Rejected
        });
        if others {
            return Err(RaflowError::Other(
                "le secret d'amorçage a déjà servi à une demande de certificat client".to_string(),
            ));
        }
        Ok(())
    }

    async fn submit_as(
        &self,
        requester: &Requester,
        csr_der: &[u8],
        profile_name: &str,
    ) -> Result<SubmitResult, RaflowError> {
        let profile = oe_ca_core::profile_by_name(profile_name).map_err(RaflowError::Other)?;
        // Constat R-3 : un demandeur n'obtient que les profils qui lui sont liés.
        if !requester.allows(profile_name) {
            return Err(RaflowError::Other(format!(
                "le demandeur {:?} n'est pas autorisé pour le profil {profile_name:?}",
                requester.name
            )));
        }
        let (cn, spki_der) = parse_and_verify_csr(csr_der)?;
        // Son certificat client porte son nom ; les autres profils, le CN fixé
        // pour lui, s'il y en a un.
        let expected_cn = if profile_name == oe_ca_core::profile::PROFILE_ENROLL_CLIENT {
            Some(requester.client_cn.as_ref().ok_or_else(|| {
                RaflowError::Other(format!(
                    "le demandeur {:?} n'a pas de nom de certificat client",
                    requester.name
                ))
            })?)
        } else {
            requester.subject_cn.as_ref()
        };
        if let Some(expected) = expected_cn {
            if *expected != cn {
                return Err(RaflowError::Other(format!(
                    "le demandeur {:?} ne peut demander que le CN {expected:?}",
                    requester.name
                )));
            }
        }
        // Refusé dès le dépôt : une demande vouée à l'échec à l'émission ne
        // doit pas occuper un opérateur RA.
        profile.validate_cn(&cn).map_err(RaflowError::Other)?;

        let fp = fingerprint(csr_der);
        let existing = match self.opts.store.request_by_fingerprint(&fp).await {
            Ok(r) => Some(r),
            Err(StoreError::NotFound) => None,
            Err(e) => return Err(e.into()),
        };

        match existing {
            None => {
                self.open(csr_der, &cn, &spki_der, &profile, &fp, &requester.name)
                    .await
            }
            Some(r) if requester_key(&r.requester) != requester.name => Err(RaflowError::Other(
                "cette demande a été soumise par un autre demandeur".to_string(),
            )),
            Some(r) if r.profile != profile_name => Err(RaflowError::Other(format!(
                "cette demande a été soumise pour le profil {:?}, pas {:?}",
                r.profile, profile_name
            ))),
            Some(r) => self.resume(r, &spki_der, &cn, &profile).await,
        }
    }

    async fn open(
        &self,
        csr_der: &[u8],
        cn: &str,
        _spki_der: &[u8],
        profile: &oe_ca_core::Profile,
        fp: &str,
        requester: &str,
    ) -> Result<SubmitResult, RaflowError> {
        let tx = transaction_id(csr_der);
        let r = Request {
            transaction_id: tx.clone(),
            csr_fingerprint: fp.to_string(),
            csr_der: csr_der.to_vec(),
            profile: profile.name.to_string(),
            subject_cn: cn.to_string(),
            state: RequestState::Pending,
            created_at: self.now(),
            decided_at: None,
            operator: String::new(),
            comment: String::new(),
            issued_at: None,
            certificate_serial: None,
            requester: requester.to_string(),
        };
        // Le journal *avant* l'enregistrement durable (§15 étape 2b) : si
        // l'écriture échoue, aucune demande n'est créée — rejouable sans
        // laisser de trace à moitié écrite. (Deux soumissions strictement
        // simultanées de la même CSR pourraient, plus rarement encore,
        // journaliser deux fois la même réception si l'une des deux échoue
        // ensuite à `create_request` : imprécision mineure d'audit, pas une
        // décision faussée, contrairement au cas de `Decider::decide`.)
        self.record(
            "ca.request_received",
            serde_json::json!({
                "transaction": tx,
                "profil": profile.name,
                "sujet_cn": cn,
                "empreinte": fp,
                "demandeur": requester,
            }),
        )
        .await?;
        self.opts.store.create_request(r).await?;
        Ok(SubmitResult {
            state: RequestState::Pending,
            transaction_id: tx,
            retry_after: Some(self.opts.retry_after),
            certificate: None,
            chain: vec![],
        })
    }

    async fn resume(
        &self,
        r: Request,
        spki_der: &[u8],
        cn: &str,
        profile: &oe_ca_core::Profile,
    ) -> Result<SubmitResult, RaflowError> {
        match r.state {
            RequestState::Pending => Ok(SubmitResult {
                state: RequestState::Pending,
                transaction_id: r.transaction_id,
                retry_after: Some(self.opts.retry_after),
                certificate: None,
                chain: vec![],
            }),
            RequestState::Rejected => Err(RaflowError::Rejected {
                operator: r.operator,
                comment: r.comment,
            }),
            RequestState::Approved => self.issue(r, spki_der, cn, profile).await,
            RequestState::Issued => {
                let cert = self.issued_certificate(&r).await?;
                Ok(SubmitResult {
                    state: RequestState::Issued,
                    transaction_id: r.transaction_id,
                    retry_after: None,
                    certificate: Some(cert),
                    chain: self.opts.issuer.full_chain(),
                })
            }
        }
    }

    async fn issued_certificate(&self, r: &Request) -> Result<x509_cert::Certificate, RaflowError> {
        use der::Decode;
        let serial = r.certificate_serial.as_ref().ok_or_else(|| {
            RaflowError::Other(format!(
                "demande {} marquée émise sans certificat associé",
                r.transaction_id
            ))
        })?;
        let rec = self.opts.store.certificate(serial).await?;
        Ok(x509_cert::Certificate::from_der(&rec.der)?)
    }

    /// Transforme une demande approuvée en certificat, puis applique la
    /// politique « une seule unité active par sujet » en révoquant les
    /// certificats précédents du même sujet.
    async fn issue(
        &self,
        r: Request,
        spki_der: &[u8],
        cn: &str,
        profile: &oe_ca_core::Profile,
    ) -> Result<SubmitResult, RaflowError> {
        // Les certificats actifs du sujet sont relevés AVANT l'émission :
        // après, le nouveau certificat en ferait partie et se révoquerait
        // lui-même.
        let subject = oe_ca_core::build_subject(
            cn,
            profile.organizational_unit,
            profile.organization,
            profile.country,
        )?;
        let subject_dn = subject.to_string();
        let now = self.now();
        let previous = self.opts.store.active_by_subject(&subject_dn, now).await?;

        let cert = self
            .opts
            .issuer
            .issue(spki_der, cn, profile, &r.transaction_id)
            .await?;
        let serial = oe_ca_core::canonical_serial(cert.tbs_certificate().serial_number());

        let mut updated = r.clone();
        updated.state = RequestState::Issued;
        updated.issued_at = Some(now);
        updated.certificate_serial = Some(serial.clone());
        self.opts
            .store
            .update_request(updated, RequestState::Approved)
            .await?;

        // reasonCode 4 = superseded (RFC 5280 §5.3.1) : le motif exact
        // compte, « unspecified » ne justifierait rien devant un auditeur.
        const SUPERSEDED: i32 = 4;
        // Constat R-3 : un renouvellement ne révoque que les certificats du même
        // demandeur. Celui d'un autre demandeur, même de même DN, reste actif :
        // un secret volé ne permet pas de faire révoquer la TSU légitime.
        for old in &previous {
            let owner = match self
                .opts
                .store
                .request_by_transaction_id(&old.request_transaction_id)
                .await
            {
                Ok(prev) => prev.requester,
                Err(StoreError::NotFound) => String::new(),
                Err(e) => return Err(e.into()),
            };
            if requester_key(&owner) != requester_key(&r.requester) {
                self.record(
                    "ca.renewal_revocation_skipped",
                    serde_json::json!({
                        "serie_ancienne": hex::encode(&old.serial),
                        "serie_nouvelle": hex::encode(&serial),
                        "demandeur_ancien": requester_key(&owner),
                        "demandeur_nouveau": requester_key(&r.requester),
                    }),
                )
                .await?;
                continue;
            }
            self.opts
                .issuer
                .revoke(
                    &old.serial,
                    SUPERSEDED,
                    "raflow:renouvellement",
                    &format!("remplacé par {}", hex::encode(&serial)),
                    &Via::Automatic,
                )
                .await?;
        }

        // Republie la CRL immédiatement : elle porte, depuis le constat O-1
        // de l'audit du 2026-09-25, la liste des numéros émis
        // (`oe_conformance::OID_CRL_ISSUED_SERIALS`) que consulte le
        // répondeur OCSP pour distinguer un numéro jamais émis d'un numéro
        // émis mais non révoqué. Sans cette republication immédiate, le
        // certificat qui vient d'être émis répondrait `unknown` en OCSP
        // jusqu'à la prochaine republication périodique — aussi grave qu'une
        // révocation non publiée (même raison que la CLI `revoke`, qui
        // republie elle aussi tout de suite).
        self.opts.issuer.publish_crl().await?;

        Ok(SubmitResult {
            state: RequestState::Issued,
            transaction_id: r.transaction_id,
            retry_after: None,
            certificate: Some(cert),
            chain: self.opts.issuer.full_chain(),
        })
    }
}
