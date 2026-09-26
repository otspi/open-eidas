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
//!     319 411-1 §6.2.1).
//!
//! **Écart assumé** : `Decider` ne détient jamais la clé de l'autorité —
//! approuver, c'est décider, pas signer (à l'identique du Go : la commande
//! `ca-server ra approve` n'ouvre aucun token PKCS#11).

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use x509_cert::request::CertReq;

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

/// ETSI TS 119 312 §6.2 : longueur de clé RSA minimale, la même exigence
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
    use rsa::pkcs1v15::Pkcs1v15Sign;
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
    let digest = Sha256::digest(&tbs_der);
    public_key
        .verify(
            Pkcs1v15Sign::new::<Sha256>(),
            &digest,
            csr.signature.raw_bytes(),
        )
        .map_err(|_| {
            RaflowError::Other(
                "la demande n'est pas signée par la clé qu'elle présente".to_string(),
            )
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
    /// c'est ce qui rend la décision imputable (ETSI EN 319 411-1 §6.2.1).
    pub async fn approve(
        &self,
        transaction_id: &str,
        operator: &str,
        comment: &str,
    ) -> Result<Request, RaflowError> {
        self.decide(transaction_id, operator, comment, RequestState::Approved)
            .await
    }

    /// Refuse définitivement une demande. Le demandeur en est informé lors
    /// de sa prochaine soumission, avec le nom de l'opérateur et son motif.
    pub async fn reject(
        &self,
        transaction_id: &str,
        operator: &str,
        comment: &str,
    ) -> Result<Request, RaflowError> {
        self.decide(transaction_id, operator, comment, RequestState::Rejected)
            .await
    }

    async fn decide(
        &self,
        transaction_id: &str,
        operator: &str,
        comment: &str,
        target: RequestState,
    ) -> Result<Request, RaflowError> {
        if operator.is_empty() {
            return Err(RaflowError::Other(
                "la décision exige l'identité de l'opérateur qui la prend".to_string(),
            ));
        }
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
        self.record(
            event,
            serde_json::json!({
                "transaction": updated.transaction_id,
                "profil": updated.profile,
                "sujet_cn": updated.subject_cn,
                "operateur": operator,
                "commentaire": comment,
            }),
        )
        .await?;
        Ok(updated)
    }

    /// Liste les demandes dans l'état donné (toutes si `None`), pour
    /// l'interface d'exploitation de l'opérateur RA.
    pub async fn requests(&self, state: Option<RequestState>) -> Result<Vec<Request>, RaflowError> {
        Ok(self.opts.store.requests(state).await?)
    }
}

/// Configure la machine à états complète (décision et émission).
pub struct Options {
    pub store: std::sync::Arc<dyn Store>,
    pub issuer: std::sync::Arc<oe_ca_core::Issuer>,
    /// Authentifie le demandeur. Vide, l'enrôlement deviendrait anonyme :
    /// refusé explicitement à la construction plutôt que toléré par défaut.
    pub hmac_secret: String,
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
}

impl Flow {
    pub fn new(opts: Options) -> Result<Flow, RaflowError> {
        if opts.hmac_secret.is_empty() {
            // Une PKI qui délivre à quiconque le demande n'a pas de valeur :
            // le secret partagé n'est pas une identité, mais il est le minimum.
            return Err(RaflowError::Other(
                "secret HMAC d'enrôlement non configuré (enrôlement anonyme refusé)".to_string(),
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
        verify_hmac(csr_der, &self.opts.hmac_secret, signature_hex)?;
        let profile = oe_ca_core::profile_by_name(profile_name).map_err(RaflowError::Other)?;
        let (cn, spki_der) = parse_and_verify_csr(csr_der)?;
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
            None => self.open(csr_der, &cn, &spki_der, &profile, &fp).await,
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
        for old in &previous {
            self.opts
                .issuer
                .revoke(
                    &old.serial,
                    SUPERSEDED,
                    "raflow:renouvellement",
                    &format!("remplacé par {}", hex::encode(&serial)),
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
