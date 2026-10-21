//! Assemblage du `TimeStampToken` : une enveloppe CMS `SignedData` (RFC 5652)
//! encapsulant un `TSTInfo`, avec un attribut signé `signingCertificateV2`
//! (RFC 5035) liant le jeton au certificat de la TSU.
//!
//! Jalon J6 du plan de migration
//! (`/home/philippe/.claude/plans/witty-hopping-nest.md`) : ce module ne
//! signe rien lui-même — il prépare les octets à signer
//! ([`signed_attrs_der`]) et assemble le jeton final à partir d'une
//! signature déjà produite ([`assemble`]), pour que la clé privée reste
//! entièrement du ressort d'`oe-hsm` (jamais manipulée ici).
//!
//! **Écart assumé face au binaire Go** : `github.com/digitorus/timestamp`
//! inclut le champ optionnel `issuerSerial` dans chaque `ESSCertIDv2`
//! (RFC 5035 §5) ; ce module l'omet (également valide : le champ est
//! `OPTIONAL`). Le construire à l'identique demanderait de retagger les
//! octets bruts du `Name` de l'émetteur en `[4] IMPLICIT` au sein d'un
//! `GeneralName`, une subtilité de balisage ASN.1 sans bénéfice fonctionnel
//! ici — seul `certHash` est requis pour qu'un vérificateur (`openssl ts
//! -verify` notamment) accepte le jeton.

use der::asn1::{ObjectIdentifier, OctetString, SetOfVec};
use der::{Any, Decode, Encode};
use spki::AlgorithmIdentifierOwned;
use x509_cert::attr::{Attribute, Attributes};

use cms::cert::IssuerAndSerialNumber;
use cms::content_info::{CmsVersion, ContentInfo};
use cms::signed_data::{
    CertificateSet, DigestAlgorithmIdentifiers, EncapsulatedContentInfo, SignedData,
    SignerIdentifier, SignerInfo, SignerInfos,
};

use crate::{PkiStatusInfo, TimeStampResp};

/// OID `id-data` (1.2.840.113549.1.7.1).
pub const OID_DATA: &str = "1.2.840.113549.1.7.1";
/// OID `id-signedData` (1.2.840.113549.1.7.2).
pub const OID_SIGNED_DATA: &str = "1.2.840.113549.1.7.2";
/// OID `id-ct-TSTInfo` (1.2.840.113549.1.9.16.1.4).
pub const OID_CT_TST_INFO: &str = "1.2.840.113549.1.9.16.1.4";
/// OID `id-contentType` (1.2.840.113549.1.9.3).
pub const OID_CONTENT_TYPE: &str = "1.2.840.113549.1.9.3";
/// OID `id-messageDigest` (1.2.840.113549.1.9.4).
pub const OID_MESSAGE_DIGEST: &str = "1.2.840.113549.1.9.4";
/// OID `id-aa-signingCertificateV2` (1.2.840.113549.1.9.16.2.47, RFC 5035).
pub const OID_SIGNING_CERTIFICATE_V2: &str = "1.2.840.113549.1.9.16.2.47";
/// OID `rsaEncryption` (1.2.840.113549.1.1.1) — utilisé comme
/// `signatureAlgorithm` de `SignerInfo` : la signature est une simple
/// signature PKCS#1 v1.5 sur l'empreinte des attributs signés, l'algorithme
/// de hachage étant porté séparément par `digestAlgorithm`.
pub const OID_RSA_ENCRYPTION: &str = "1.2.840.113549.1.1.1";
/// OID `id-sha256` (2.16.840.1.101.3.4.2.1).
pub const OID_SHA256: &str = "2.16.840.1.101.3.4.2.1";

#[derive(Debug, thiserror::Error)]
pub enum TokenError {
    #[error("oe-rfc3161-asn1: erreur ASN.1: {0}")]
    Der(#[from] der::Error),
}

fn oid(s: &str) -> ObjectIdentifier {
    ObjectIdentifier::new(s).expect("OID constant invalide")
}

/// `AlgorithmIdentifier` pour SHA-256 avec paramètres `NULL` explicites —
/// reproduit `getMessageImprint` (Go, `github.com/digitorus/timestamp`), qui
/// pose `Parameters: asn1.NullRawValue` plutôt que d'omettre le champ.
pub fn sha256_algorithm_identifier() -> Result<AlgorithmIdentifierOwned, TokenError> {
    Ok(AlgorithmIdentifierOwned {
        oid: oid(OID_SHA256),
        parameters: Some(Any::from_der(&der::asn1::Null.to_der()?)?),
    })
}

fn any_of<T: Encode>(value: &T) -> Result<Any, TokenError> {
    Ok(Any::from_der(&value.to_der()?)?)
}

/// Composants nécessaires à l'assemblage du jeton, précalculés par
/// l'appelant (`oe-tsa-core`) : ce module ne fait ni hachage ni signature.
pub struct TokenParts<'a> {
    /// `TSTInfo` déjà encodé en DER (le contenu encapsulé du jeton).
    pub tst_info_der: &'a [u8],
    /// Empreinte de `tst_info_der`, avec l'algorithme de `digest_alg`.
    pub tst_info_digest: &'a [u8],
    /// Empreinte du certificat TSU (DER complet), même algorithme.
    pub signing_cert_digest: &'a [u8],
    /// Identifiant de l'algorithme de hachage (typiquement SHA-256).
    pub digest_alg: AlgorithmIdentifierOwned,
    /// Émetteur et numéro de série du certificat TSU, pour `SignerIdentifier`.
    pub issuer: x509_cert::name::Name,
    pub serial_number: x509_cert::serial_number::SerialNumber,
    /// Certificat TSU et chaîne, déjà en DER, à embarquer si `include_certs`.
    pub certs_der: &'a [Vec<u8>],
    pub include_certs: bool,
    /// `signatureAlgorithm` de `SignerInfo`, choisi par l'appelant selon le
    /// schéma de la signature : [`rsa_encryption_algorithm_identifier`] pour
    /// PKCS#1 v1.5, `id-RSASSA-PSS` avec ses paramètres (RFC 4056) pour PSS.
    pub signature_algorithm: AlgorithmIdentifierOwned,
}

/// `rsaEncryption` avec paramètres `NULL` : le `signatureAlgorithm` d'un
/// `SignerInfo` signé en PKCS#1 v1.5 (l'empreinte est portée par `digestAlgorithm`).
pub fn rsa_encryption_algorithm_identifier() -> Result<AlgorithmIdentifierOwned, TokenError> {
    Ok(AlgorithmIdentifierOwned {
        oid: oid(OID_RSA_ENCRYPTION),
        parameters: Some(Any::from_der(&der::asn1::Null.to_der()?)?),
    })
}

/// Construit l'ensemble `SignedAttributes` (contentType, messageDigest,
/// signingCertificateV2) et retourne son encodage DER en `SET OF` — les
/// octets exacts dont l'empreinte doit être signée (RFC 5652 §5.4). Le même
/// ensemble, une fois signé, est réintégré tel quel par [`assemble`].
pub fn signed_attrs_der(parts: &TokenParts) -> Result<Vec<u8>, TokenError> {
    let content_type_attr = Attribute {
        oid: oid(OID_CONTENT_TYPE),
        values: SetOfVec::from_iter([any_of(&oid(OID_CT_TST_INFO))?])?,
    };
    let message_digest_attr = Attribute {
        oid: oid(OID_MESSAGE_DIGEST),
        values: SetOfVec::from_iter([any_of(&OctetString::new(parts.tst_info_digest.to_vec())?)?])?,
    };

    let ess_cert_id_v2 = EssCertIdV2 {
        // Omis pour SHA-256 (valeur par défaut, RFC 5035 §3) : reproduit le
        // comportement du binaire Go, qui n'inclut ce champ que pour un
        // algorithme différent de SHA-256.
        hash_algorithm: if parts.digest_alg.oid == oid(OID_SHA256) {
            None
        } else {
            Some(parts.digest_alg.clone())
        },
        cert_hash: OctetString::new(parts.signing_cert_digest.to_vec())?,
    };
    let signing_certificate_v2 = SigningCertificateV2 {
        certs: vec![ess_cert_id_v2],
    };
    let signing_certificate_v2_attr = Attribute {
        oid: oid(OID_SIGNING_CERTIFICATE_V2),
        values: SetOfVec::from_iter([any_of(&signing_certificate_v2)?])?,
    };

    let attrs: Attributes = SetOfVec::from_iter([
        content_type_attr,
        message_digest_attr,
        signing_certificate_v2_attr,
    ])?;
    Ok(attrs.to_der()?)
}

/// Assemble le `TimeStampToken` final (un `ContentInfo` `SignedData` DER) à
/// partir des `signedAttrs` déjà construits par [`signed_attrs_der`] et
/// d'une signature déjà produite (selon `parts.signature_algorithm`, sur l'empreinte de ces
/// `signedAttrs`, calculée par l'appelant via `oe-hsm`).
pub fn assemble(
    parts: &TokenParts,
    signed_attrs_der: &[u8],
    signature: Vec<u8>,
) -> Result<Vec<u8>, TokenError> {
    let signed_attrs: Attributes = Attributes::from_der(signed_attrs_der)?;

    let signer_info = SignerInfo {
        version: CmsVersion::V1,
        sid: SignerIdentifier::IssuerAndSerialNumber(IssuerAndSerialNumber {
            issuer: parts.issuer.clone(),
            serial_number: parts.serial_number.clone(),
        }),
        digest_alg: parts.digest_alg.clone(),
        signed_attrs: Some(signed_attrs),
        signature_algorithm: parts.signature_algorithm.clone(),
        signature: OctetString::new(signature)?,
        unsigned_attrs: None,
    };

    let certificates = if parts.include_certs && !parts.certs_der.is_empty() {
        let mut set = SetOfVec::new();
        for cert_der in parts.certs_der {
            let cert = x509_cert::Certificate::from_der(cert_der)?;
            set.insert(cms::cert::CertificateChoices::Certificate(cert))?;
        }
        Some(CertificateSet(set))
    } else {
        None
    };

    let signed_data = SignedData {
        // version 3 : eContentType (id-ct-TSTInfo) diffère de id-data (RFC 5652 §5.1).
        version: CmsVersion::V3,
        digest_algorithms: DigestAlgorithmIdentifiers::from_iter([parts.digest_alg.clone()])?,
        encap_content_info: EncapsulatedContentInfo {
            econtent_type: oid(OID_CT_TST_INFO),
            econtent: Some(any_of(&OctetString::new(parts.tst_info_der.to_vec())?)?),
        },
        certificates,
        crls: None,
        signer_infos: SignerInfos(SetOfVec::from_iter([signer_info])?),
    };

    let content_info = ContentInfo {
        content_type: oid(OID_SIGNED_DATA),
        content: any_of(&signed_data)?,
    };
    Ok(content_info.to_der()?)
}

/// Le `TSTInfo` encapsulé dans une `TimeStampResp` accordée : ce qui fait foi
/// (heure, série, empreinte), lu dans le jeton lui-même.
pub fn tst_info_of_response(resp_der: &[u8]) -> Result<crate::TstInfo, TokenError> {
    let resp = TimeStampResp::from_der(resp_der)?;
    let token = resp
        .time_stamp_token
        .ok_or_else(|| der::Error::from(der::ErrorKind::Failed))?;
    let content_info = ContentInfo::from_der(&token.to_der()?)?;
    let signed_data = SignedData::from_der(&content_info.content.to_der()?)?;
    let econtent = signed_data
        .encap_content_info
        .econtent
        .ok_or_else(|| der::Error::from(der::ErrorKind::Failed))?;
    let octets = OctetString::from_der(&econtent.to_der()?)?;
    Ok(crate::TstInfo::from_der(octets.as_bytes())?)
}

/// Encode la réponse RFC 3161 complète (statut « granted » + jeton).
pub fn granted_response(token_der: Vec<u8>) -> Result<TimeStampResp, TokenError> {
    Ok(TimeStampResp {
        status: PkiStatusInfo {
            status: der::asn1::Int::new(&[0])?, // PKIStatus granted(0)
            status_string: None,
            fail_info: None,
        },
        time_stamp_token: Some(Any::from_der(&token_der)?),
    })
}

/// `ESSCertIDv2 ::= SEQUENCE { hashAlgorithm AlgorithmIdentifier DEFAULT
/// {algorithm id-sha256}, certHash Hash, issuerSerial IssuerSerial OPTIONAL }`
/// (RFC 5035 §3) — `issuerSerial` toujours omis ici, voir la note de module.
#[derive(der::Sequence)]
struct EssCertIdV2 {
    #[asn1(optional = "true")]
    hash_algorithm: Option<AlgorithmIdentifierOwned>,
    cert_hash: OctetString,
}

/// `SigningCertificateV2 ::= SEQUENCE { certs SEQUENCE OF ESSCertIDv2,
/// policies SEQUENCE OF PolicyInformation OPTIONAL }` (RFC 5035 §3).
#[derive(der::Sequence)]
struct SigningCertificateV2 {
    certs: Vec<EssCertIdV2>,
}
