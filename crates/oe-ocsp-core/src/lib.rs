//! Portage de `internal/ocspresponder` : répondeur OCSP (RFC 6960)
//! autonome pour la CA émettrice de la TSU — rang 2 de l'ordre de portage
//! post-`tsa-server` (`/home/philippe/.claude/plans/witty-hopping-nest.md`).
//!
//! S'appuie sur la CRL publiée par l'autorité plutôt que sur un accès direct
//! à son registre : le répondeur ne voit donc que ce qu'un tiers pourrait
//! voir lui-même, et ne peut pas attester d'un statut que la CA n'a pas
//! publié.

pub mod asn1;

use std::collections::HashMap;
use std::sync::RwLock;
use std::time::Duration;

use der::{Decode, Encode};
use rsa::pkcs1v15::Pkcs1v15Sign;
use rsa::pkcs8::DecodePublicKey;
use rsa::RsaPublicKey;
use sha2::{Digest as _, Sha256};
use spki::AlgorithmIdentifierOwned;
use x509_cert::Certificate;

use oe_hsm::{DigestAlg, SigningToken};

use der::oid::AssociatedOid;

use crate::asn1::{
    BasicOcspResponse, CertStatus, OcspRequest, OcspResponse, OcspResponseStatus, ResponderId,
    ResponseBytes, ResponseData, RevokedInfo, SingleResponse,
};

const OID_SHA256_WITH_RSA: &str = "1.2.840.113549.1.1.11";

#[derive(Debug, thiserror::Error)]
pub enum OcspError {
    #[error("ocspresponder: signataire, certificat et émetteur requis")]
    MissingMaterial,
    #[error("ocspresponder: URL de CRL requise")]
    MissingCrlUrl,
    #[error("ocspresponder: chargement de la CRL: {0}")]
    Fetch(#[from] reqwest::Error),
    #[error("ocspresponder: la PKI a répondu {0}")]
    UnexpectedStatus(reqwest::StatusCode),
    #[error("ocspresponder: CRL illisible: {0}")]
    InvalidCrl(der::Error),
    #[error("ocspresponder: signature de la CRL invalide: {0}")]
    InvalidCrlSignature(String),
    #[error("ocspresponder: {0}")]
    Der(#[from] der::Error),
    #[error("ocspresponder: signature de la réponse: {0}")]
    Signing(#[from] oe_hsm::HsmError),
}

#[derive(Clone)]
struct Revoked {
    at: time::OffsetDateTime,
    reason: Option<x509_cert::ext::pkix::crl::CrlReason>,
}

struct CrlSnapshot {
    revoked: HashMap<Vec<u8>, Revoked>,
    /// Constat O-1 : tous les numéros émis, tirés de l'extension privée de
    /// la CRL (`oe_conformance::OID_CRL_ISSUED_SERIALS`). Un numéro absent
    /// d'ici est `unknown`, jamais `good` par défaut.
    issued: std::collections::HashSet<Vec<u8>>,
    this_update: time::OffsetDateTime,
    next_update: time::OffsetDateTime,
    last_fetch: Option<std::time::Instant>,
}

impl Default for CrlSnapshot {
    fn default() -> Self {
        CrlSnapshot {
            revoked: HashMap::new(),
            issued: std::collections::HashSet::new(),
            this_update: time::OffsetDateTime::UNIX_EPOCH,
            next_update: time::OffsetDateTime::UNIX_EPOCH,
            last_fetch: None,
        }
    }
}

pub struct Options {
    /// Clé et certificat de signature OCSP, émis par la PKI avec
    /// l'extension `id-pkix-ocsp-nocheck`.
    pub signer: std::sync::Arc<dyn SigningToken + Send + Sync>,
    pub certificate: Certificate,
    /// Certificat de la CA émettrice dont ce répondeur atteste le statut de
    /// révocation des certificats délivrés.
    pub issuer: Certificate,
    pub crl_url: String,
    pub crl_refresh: Duration,
    pub max_request_bytes: usize,
    /// Client HTTP à utiliser pour interroger la CRL — permet à l'appelant
    /// de configurer une ancre de confiance ou de tolérer un certificat TLS
    /// non vérifiable en démonstration locale (`newCRLHTTPClient`, Go).
    /// `None` construit un client par défaut.
    pub http_client: Option<reqwest::Client>,
}

/// Répond aux requêtes OCSP en consultant un instantané de CRL rafraîchi
/// périodiquement en arrière-plan.
pub struct Responder {
    opts: Options,
    http: reqwest::Client,
    snapshot: RwLock<CrlSnapshot>,
    /// Constat O-1 : un certificat tout juste émis peut légitimement être
    /// absent de l'instantané courant (la CA a republié une CRL plus
    /// récente que le dernier rafraîchissement périodique). Sur un
    /// `unknown`, un rafraîchissement à la volée est tenté — mais borné par
    /// [`ON_DEMAND_REFRESH_COOLDOWN`], sinon quiconque interroge des séries
    /// au hasard déclencherait un fetch HTTP et une vérification de
    /// signature à chaque requête (déni de service).
    last_on_demand_refresh: std::sync::Mutex<Option<std::time::Instant>>,
}

/// Délai minimal entre deux rafraîchissements à la volée, quel que soit le
/// volume de requêtes OCSP reçues entre-temps.
const ON_DEMAND_REFRESH_COOLDOWN: Duration = Duration::from_secs(2);

/// Déduit l'URL de la CRL de la CA émettrice à partir de l'adresse à
/// laquelle ce service joint la PKI et du nom courant de l'émetteur. La
/// dérivation du nom de fichier est celle d'`oe_certs::file_name`, la même
/// qu'emploient l'autorité qui grave l'URL dans les extensions CDP et le
/// serveur qui publie le fichier : définie une seule fois, elle ne peut pas
/// diverger entre les trois.
pub fn crl_url(pki_internal_url: &str, issuer: &Certificate) -> String {
    const OID_COMMON_NAME: &str = "2.5.4.3";
    let cn_oid = der::asn1::ObjectIdentifier::new(OID_COMMON_NAME).expect("OID constant invalide");
    let cn = issuer
        .tbs_certificate()
        .subject()
        .iter()
        .find(|atv| atv.oid == cn_oid)
        .map(|atv| String::from_utf8_lossy(atv.value.value()).into_owned())
        .unwrap_or_default();
    format!(
        "{}/download/{}.crl",
        pki_internal_url.trim_end_matches('/'),
        oe_certs::file_name(&cn)
    )
}

impl Responder {
    pub fn new(opts: Options) -> Result<Responder, OcspError> {
        if opts.crl_url.is_empty() {
            return Err(OcspError::MissingCrlUrl);
        }
        let http = match opts.http_client.clone() {
            Some(client) => client,
            None => reqwest::Client::builder()
                .timeout(Duration::from_secs(30))
                .build()?,
        };
        Ok(Responder {
            opts,
            http,
            snapshot: RwLock::new(CrlSnapshot::default()),
            last_on_demand_refresh: std::sync::Mutex::new(None),
        })
    }

    /// Tente un rafraîchissement à la volée, borné par
    /// [`ON_DEMAND_REFRESH_COOLDOWN`] : rend `true` s'il a eu lieu (que la
    /// requête HTTP réussisse ou non — l'appelant relit simplement
    /// l'instantané, qui n'a alors changé qu'en cas de succès), `false` s'il
    /// a été sauté faute de délai écoulé.
    async fn try_on_demand_refresh(&self) -> bool {
        {
            let mut last = self
                .last_on_demand_refresh
                .lock()
                .expect("verrou empoisonné");
            match *last {
                Some(t) if t.elapsed() < ON_DEMAND_REFRESH_COOLDOWN => return false,
                _ => *last = Some(std::time::Instant::now()),
            }
        }
        if let Err(e) = self.refresh().await {
            tracing::warn!(erreur = %e, "rafraîchissement à la volée de la CRL impossible");
        }
        true
    }

    /// Charge la CRL une première fois (bloquant), à appeler avant de
    /// servir des requêtes.
    pub async fn refresh(&self) -> Result<(), OcspError> {
        let resp = self.http.get(&self.opts.crl_url).send().await?;
        if !resp.status().is_success() {
            return Err(OcspError::UnexpectedStatus(resp.status()));
        }
        let der = resp.bytes().await?;

        let crl = x509_cert::crl::CertificateList::from_der(&der).map_err(OcspError::InvalidCrl)?;
        verify_crl_signature(&crl, &self.opts.issuer).map_err(OcspError::InvalidCrlSignature)?;

        let mut revoked = HashMap::new();
        if let Some(entries) = &crl.tbs_cert_list.revoked_certificates {
            for entry in entries {
                let reason = entry.crl_entry_extensions.as_ref().and_then(|exts| {
                    exts.iter()
                        .find(|e| e.extn_id == x509_cert::ext::pkix::crl::CrlReason::OID)
                        .and_then(|e| {
                            x509_cert::ext::pkix::crl::CrlReason::from_der(e.extn_value.as_bytes())
                                .ok()
                        })
                });
                let at = x509_time_to_offset(&entry.revocation_date);
                revoked.insert(
                    entry.serial_number.as_bytes().to_vec(),
                    Revoked { at, reason },
                );
            }
        }

        // Constat O-1 : sans cette extension, impossible de distinguer un
        // numéro jamais émis d'un numéro émis mais non révoqué — une CRL qui
        // ne la porte pas est donc refusée, comme une CRL illisible (aucune
        // CRL produite par cette CA n'en manque, voir
        // `oe_ca_core::extensions::crl_issued_serials`).
        let issued_oid = der::asn1::ObjectIdentifier::new(oe_conformance::OID_CRL_ISSUED_SERIALS)
            .expect("OID constant invalide");
        let issued_ext = crl
            .tbs_cert_list
            .crl_extensions
            .as_ref()
            .and_then(|exts| exts.iter().find(|e| e.extn_id == issued_oid))
            .ok_or_else(|| {
                OcspError::InvalidCrl(der::Error::new(der::ErrorKind::Failed, der::Length::ZERO))
            })?;
        let issued_serials: Vec<x509_cert::serial_number::SerialNumber> =
            der::Decode::from_der(issued_ext.extn_value.as_bytes())?;
        let issued: std::collections::HashSet<Vec<u8>> = issued_serials
            .iter()
            .map(|s| s.as_bytes().to_vec())
            .collect();

        let mut snap = self.snapshot.write().expect("verrou de CRL empoisonné");
        snap.revoked = revoked;
        snap.issued = issued;
        snap.this_update = x509_time_to_offset(&crl.tbs_cert_list.this_update);
        snap.next_update = crl
            .tbs_cert_list
            .next_update
            .as_ref()
            .map(x509_time_to_offset)
            .unwrap_or(time::OffsetDateTime::UNIX_EPOCH);
        snap.last_fetch = Some(std::time::Instant::now());
        drop(snap);

        tracing::info!(revoques = ?self.snapshot.read().unwrap().revoked.len(), "CRL rafraîchie");
        Ok(())
    }

    /// Traite une requête OCSP encodée en DER (RFC 6960 §4.1) et retourne
    /// une `OCSPResponse` DER, toujours — un refus protocolaire est une
    /// réponse OCSP valide de statut non `successful`, jamais une erreur de
    /// transport.
    pub async fn handle(&self, req_der: &[u8]) -> Vec<u8> {
        match self.handle_inner(req_der).await {
            Ok(der) => der,
            Err(_) => error_response(OcspResponseStatus::InternalError),
        }
    }

    /// `None` si la CRL en cache est trop ancienne (`stale`, à traiter par
    /// l'appelant comme `tryLater`) ; sinon le statut, `thisUpdate` et
    /// `nextUpdate` de l'instantané courant.
    fn lookup(
        &self,
        serial: &[u8],
    ) -> Option<(CertStatus, time::OffsetDateTime, time::OffsetDateTime)> {
        let snap = self.snapshot.read().expect("verrou de CRL empoisonné");
        let stale = match snap.last_fetch {
            Some(t) => t.elapsed() > self.opts.crl_refresh * 2,
            None => true,
        };
        if stale {
            return None;
        }
        let status = match snap.revoked.get(serial) {
            Some(rev) => CertStatus::Revoked(RevokedInfo {
                revocation_time: der::asn1::GeneralizedTime::from_date_time(
                    offset_to_der_datetime(rev.at).ok()?,
                ),
                revocation_reason: rev.reason,
            }),
            // Constat O-1 : un numéro absent des deux listes n'a jamais été
            // émis par cette CA — `unknown`, jamais `good` par défaut.
            None if snap.issued.contains(serial) => CertStatus::Good(der::asn1::Null),
            None => CertStatus::Unknown(der::asn1::Null),
        };
        Some((status, snap.this_update, snap.next_update))
    }

    async fn handle_inner(&self, req_der: &[u8]) -> Result<Vec<u8>, OcspError> {
        let req = match OcspRequest::from_der(req_der) {
            Ok(r) => r,
            Err(_) => return Ok(error_response(OcspResponseStatus::MalformedRequest)),
        };
        let Some(single) = req.tbs_request.request_list.first() else {
            return Ok(error_response(OcspResponseStatus::MalformedRequest));
        };
        let cert_id = &single.req_cert;

        let Some((issuer_name_hash, issuer_key_hash)) =
            compute_issuer_hashes(&self.opts.issuer, &cert_id.hash_algorithm)
        else {
            return Ok(error_response(OcspResponseStatus::MalformedRequest));
        };
        if cert_id.issuer_name_hash.as_bytes() != issuer_name_hash
            || cert_id.issuer_key_hash.as_bytes() != issuer_key_hash
        {
            return Ok(error_response(OcspResponseStatus::Unauthorized));
        }

        let serial = cert_id.serial_number.as_bytes().to_vec();
        let Some((mut status, mut this_update, mut next_update)) = self.lookup(&serial) else {
            return Ok(error_response(OcspResponseStatus::TryLater));
        };

        // Constat O-1 : un certificat tout juste émis peut être absent de
        // l'instantané courant — un rafraîchissement à la volée (borné,
        // `try_on_demand_refresh`) lui laisse une chance avant de répondre
        // `unknown` pour de bon.
        if matches!(status, CertStatus::Unknown(_)) && self.try_on_demand_refresh().await {
            if let Some((s, tu, nu)) = self.lookup(&serial) {
                status = s;
                this_update = tu;
                next_update = nu;
            }
        }

        let single_response = SingleResponse {
            cert_id: cert_id.clone(),
            cert_status: status,
            this_update: der::asn1::GeneralizedTime::from_date_time(offset_to_der_datetime(
                this_update,
            )?),
            next_update: Some(der::asn1::GeneralizedTime::from_date_time(
                offset_to_der_datetime(next_update)?,
            )),
            single_extensions: None,
        };

        self.sign_response(single_response)
    }

    fn sign_response(&self, single: SingleResponse) -> Result<Vec<u8>, OcspError> {
        let responder_id =
            ResponderId::ByName(self.opts.certificate.tbs_certificate().subject().clone());
        let produced_at = der::asn1::GeneralizedTime::from_date_time(offset_to_der_datetime(
            time::OffsetDateTime::now_utc(),
        )?);

        let tbs = ResponseData {
            version: None,
            responder_id,
            produced_at,
            responses: vec![single],
            response_extensions: None,
        };
        let tbs_der = tbs.to_der()?;
        let digest = Sha256::digest(&tbs_der);
        let signature = self.opts.signer.sign_digest(DigestAlg::Sha256, &digest)?;

        let basic = BasicOcspResponse {
            tbs_response_data: tbs,
            signature_algorithm: AlgorithmIdentifierOwned {
                oid: der::asn1::ObjectIdentifier::new(OID_SHA256_WITH_RSA)
                    .expect("OID constant invalide"),
                parameters: None,
            },
            signature: der::asn1::BitString::from_bytes(&signature)?,
            certs: Some(vec![self.opts.certificate.clone()]),
        };
        let basic_der = basic.to_der()?;

        let resp = OcspResponse {
            response_status: OcspResponseStatus::Successful,
            response_bytes: Some(ResponseBytes {
                response_type: der::asn1::ObjectIdentifier::new(asn1::OID_PKIX_OCSP_BASIC)
                    .expect("OID constant invalide"),
                response: der::asn1::OctetString::new(basic_der)?,
            }),
        };
        Ok(resp.to_der()?)
    }
}

fn error_response(status: OcspResponseStatus) -> Vec<u8> {
    let resp = OcspResponse {
        response_status: status,
        response_bytes: None,
    };
    resp.to_der().unwrap_or_default()
}

fn x509_time_to_offset(t: &x509_cert::time::Time) -> time::OffsetDateTime {
    let dt = t.to_date_time();
    time::OffsetDateTime::from_unix_timestamp(dt.unix_duration().as_secs() as i64)
        .unwrap_or(time::OffsetDateTime::UNIX_EPOCH)
}

fn offset_to_der_datetime(t: time::OffsetDateTime) -> Result<der::DateTime, der::Error> {
    der::DateTime::new(
        t.year() as u16,
        t.month() as u8,
        t.day(),
        t.hour(),
        t.minute(),
        t.second(),
    )
}

/// Vérifie la signature de la CRL avec la clé publique de l'émetteur
/// (RSA PKCS#1 v1.5, seul schéma utilisé par ce dépôt).
fn verify_crl_signature(
    crl: &x509_cert::crl::CertificateList,
    issuer: &Certificate,
) -> Result<(), String> {
    let spki_der = issuer
        .tbs_certificate()
        .subject_public_key_info()
        .to_der()
        .map_err(|e| e.to_string())?;
    let public_key = RsaPublicKey::from_public_key_der(&spki_der).map_err(|e| e.to_string())?;
    let tbs_der = crl.tbs_cert_list.to_der().map_err(|e| e.to_string())?;
    let digest = Sha256::digest(&tbs_der);
    public_key
        .verify(
            Pkcs1v15Sign::new::<Sha256>(),
            &digest,
            crl.signature.raw_bytes(),
        )
        .map_err(|e| e.to_string())
}

/// Empreintes du nom et de la clé publique de l'émetteur, avec l'algorithme
/// de hachage demandé par le client — RFC 6960 exige le hash de la seule
/// BIT STRING de clé publique, sans l'identifiant d'algorithme qui l'accompagne.
fn compute_issuer_hashes(
    issuer: &Certificate,
    hash_alg: &AlgorithmIdentifierOwned,
) -> Option<(Vec<u8>, Vec<u8>)> {
    let oid = hash_alg.oid.to_string();
    let spki = issuer.tbs_certificate().subject_public_key_info();
    let name_der = issuer.tbs_certificate().subject().to_der().ok()?;
    let key_bits = spki.subject_public_key.raw_bytes();

    match oid.as_str() {
        "1.3.14.3.2.26" => Some((sha1_of(&name_der), sha1_of(key_bits))),
        "2.16.840.1.101.3.4.2.1" => Some((sha256_of(&name_der), sha256_of(key_bits))),
        _ => None,
    }
}

fn sha1_of(data: &[u8]) -> Vec<u8> {
    use sha1::Digest as _;
    sha1::Sha1::digest(data).to_vec()
}

fn sha256_of(data: &[u8]) -> Vec<u8> {
    Sha256::digest(data).to_vec()
}
