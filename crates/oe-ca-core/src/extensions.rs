//! Construction manuelle des extensions X.509 employées par les profils —
//! critical flags explicites, à l'identique du code Go (`internal/ca.go`),
//! plutôt que déduits d'une règle fixe par type comme le permettrait le
//! trait `ToExtension` de `x509-cert`.

use der::asn1::{Ia5String, ObjectIdentifier, OctetString};
use der::Encode;
use x509_cert::ext::pkix::name::GeneralName;
use x509_cert::ext::pkix::{AuthorityKeyIdentifier, BasicConstraints, KeyUsage, KeyUsages};
use x509_cert::ext::Extension;

use crate::CaError;

fn oid(s: &str) -> ObjectIdentifier {
    ObjectIdentifier::new(s).expect("OID constant invalide")
}

fn build<T: Encode>(oid_str: &str, critical: bool, value: &T) -> Result<Extension, CaError> {
    Ok(Extension {
        extn_id: oid(oid_str),
        critical,
        extn_value: OctetString::new(value.to_der()?)?,
    })
}

/// Reproduit la criticité que `crypto/x509` (Go) applique inconditionnellement
/// à `basicConstraints` et `keyUsage` dès qu'ils sont présents.
const OID_BASIC_CONSTRAINTS: &str = "2.5.29.19";
const OID_KEY_USAGE: &str = "2.5.29.15";
const OID_SUBJECT_KEY_ID: &str = "2.5.29.14";
const OID_AUTHORITY_KEY_ID: &str = "2.5.29.35";
const OID_EXT_KEY_USAGE: &str = "2.5.29.37";
const OID_CRL_DISTRIBUTION_POINTS: &str = "2.5.29.31";
const OID_AUTHORITY_INFO_ACCESS: &str = "1.3.6.1.5.5.7.1.1";
pub const OID_OCSP_NO_CHECK: &str = "1.3.6.1.5.5.7.48.1.5";
const OID_AD_CA_ISSUERS: &str = "1.3.6.1.5.5.7.48.2";
const OID_AD_OCSP: &str = "1.3.6.1.5.5.7.48.1";
const OID_CRL_NUMBER: &str = "2.5.29.20";
const OID_CERTIFICATE_POLICIES: &str = "2.5.29.32";
const OID_SUBJECT_ALT_NAME: &str = "2.5.29.17";

pub(crate) fn basic_constraints(ca: bool, path_len: Option<u8>) -> Result<Extension, CaError> {
    build(
        OID_BASIC_CONSTRAINTS,
        true,
        &BasicConstraints {
            ca,
            path_len_constraint: path_len,
        },
    )
}

pub(crate) fn key_usage(usages: der::flagset::FlagSet<KeyUsages>) -> Result<Extension, CaError> {
    build(OID_KEY_USAGE, true, &KeyUsage(usages))
}

pub(crate) fn subject_key_identifier(ski: &[u8]) -> Result<Extension, CaError> {
    build(OID_SUBJECT_KEY_ID, false, &OctetString::new(ski.to_vec())?)
}

/// `cRLNumber` (RFC 5280 §5.2.3) : entier monotone propre à la CRL, distinct
/// du numéro de série des certificats.
pub(crate) fn crl_number(number: i64) -> Result<Extension, CaError> {
    let value = der::asn1::Int::new(&(number as u64).to_be_bytes())?;
    build(OID_CRL_NUMBER, false, &value)
}

/// L'AKI d'une CRL doit identifier la clé de SON signataire — ici toujours
/// l'autorité elle-même, jamais l'AKI (qui pointe vers le parent de
/// l'autorité) qu'un appel naïf à `CrlBuilder::new_with_this_update`
/// recopierait par erreur depuis le certificat d'autorité s'il en possède
/// une (constaté par vérification croisée `openssl verify -crl_check`, qui
/// échoue avec « unable to get certificate CRL » sur cet AKI erroné).
pub(crate) fn authority_key_identifier(parent_ski: &[u8]) -> Result<Extension, CaError> {
    build(
        OID_AUTHORITY_KEY_ID,
        false,
        &AuthorityKeyIdentifier {
            key_identifier: Some(OctetString::new(parent_ski.to_vec())?),
            authority_cert_issuer: None,
            authority_cert_serial_number: None,
        },
    )
}

/// `extendedKeyUsage` est posé à la main plutôt que via un type générique :
/// ETSI EN 319 421 §7.7.2 exige de pouvoir le marquer critique, comme le
/// fait `internal/ca.go` (Go) en construisant l'extension lui-même plutôt
/// qu'en passant par `x509.Certificate.ExtKeyUsage`.
pub(crate) fn extended_key_usage(
    oids: &[ObjectIdentifier],
    critical: bool,
) -> Result<Extension, CaError> {
    build(OID_EXT_KEY_USAGE, critical, &oids.to_vec())
}

/// Constat O-1 de l'audit du 2026-09-25 (EN 319 411-1 `OVR-6.6.3-02`) : le
/// répondeur OCSP ne connaît que la CRL, où un certificat jamais émis est
/// indiscernable d'un certificat émis mais non révoqué — les deux sont
/// simplement absents. Cette extension de la **CRL** (pas d'un certificat)
/// porte tous les numéros de série jamais émis, pour que le répondeur
/// réponde `unknown` à une série absente d'ici, jamais `good`. Non critique :
/// un vérificateur RFC 5280 qui l'ignore lit une CRL par ailleurs valide.
pub(crate) fn crl_issued_serials(serials: &[Vec<u8>]) -> Result<Extension, CaError> {
    let values: Result<Vec<x509_cert::serial_number::SerialNumber>, _> = serials
        .iter()
        .map(|s| x509_cert::serial_number::SerialNumber::new(s))
        .collect();
    build(oe_conformance::OID_CRL_ISSUED_SERIALS, false, &values?)
}

pub(crate) fn ocsp_no_check() -> Extension {
    // La valeur est un NULL DER : l'extension vaut par sa seule présence.
    Extension {
        extn_id: oid(OID_OCSP_NO_CHECK),
        critical: false,
        extn_value: OctetString::new(vec![0x05, 0x00]).expect("NULL DER valide"),
    }
}

pub(crate) fn crl_distribution_point(url: &str) -> Result<Extension, CaError> {
    use x509_cert::ext::pkix::crl::dp::DistributionPoint;
    use x509_cert::ext::pkix::name::DistributionPointName;
    let name = Ia5String::new(url)?;
    let dp = DistributionPoint {
        distribution_point: Some(DistributionPointName::FullName(vec![
            GeneralName::UniformResourceIdentifier(name),
        ])),
        reasons: None,
        crl_issuer: None,
    };
    build(OID_CRL_DISTRIBUTION_POINTS, false, &vec![dp])
}

pub(crate) fn authority_info_access(
    ca_issuers_url: Option<&str>,
    ocsp_url: Option<&str>,
) -> Result<Extension, CaError> {
    use x509_cert::ext::pkix::AccessDescription;
    let mut descriptions = Vec::new();
    if let Some(url) = ca_issuers_url {
        descriptions.push(AccessDescription {
            access_method: oid(OID_AD_CA_ISSUERS),
            access_location: GeneralName::UniformResourceIdentifier(Ia5String::new(url)?),
        });
    }
    if let Some(url) = ocsp_url {
        descriptions.push(AccessDescription {
            access_method: oid(OID_AD_OCSP),
            access_location: GeneralName::UniformResourceIdentifier(Ia5String::new(url)?),
        });
    }
    build(OID_AUTHORITY_INFO_ACCESS, false, &descriptions)
}

/// `certificatePolicies` (RFC 5280 §4.2.1.4) avec une seule politique, sans
/// qualificateur.
pub(crate) fn certificate_policy(policy_oid: &str) -> Result<Extension, CaError> {
    use x509_cert::ext::pkix::certpolicy::PolicyInformation;
    let info = PolicyInformation {
        policy_identifier: oid(policy_oid),
        policy_qualifiers: None,
    };
    build(OID_CERTIFICATE_POLICIES, false, &vec![info])
}

/// `subjectAltName` réduit à un `dNSName`. Non critique (RFC 5280 §4.2.1.6 ne
/// l'exige que pour un sujet vide) : un vérificateur TLS identifie le serveur
/// par ce nom, jamais par le CN.
pub(crate) fn subject_alt_name_dns(name: &str) -> Result<Extension, CaError> {
    build(
        OID_SUBJECT_ALT_NAME,
        false,
        &vec![GeneralName::DnsName(Ia5String::new(name)?)],
    )
}
