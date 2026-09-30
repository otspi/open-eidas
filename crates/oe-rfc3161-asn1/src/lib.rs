//! Structures ASN.1 RFC 3161 (`TimeStampReq`, `TimeStampResp`, `TSTInfo`,
//! `MessageImprint`) — portage de la grammaire implémentée côté Go par
//! `github.com/digitorus/timestamp`, plus ([`token`]) l'assemblage du
//! `TimeStampToken` (enveloppe CMS `SignedData`, RFC 5652/5035).
//!
//! Jalon J1 du plan de migration
//! (`/home/philippe/.claude/plans/witty-hopping-nest.md`) : les structures
//! de ce fichier sont définies directement sur les primitives DER de
//! RustCrypto (`der`, `spki`, `x509-cert`) — validées par un round-trip DER
//! octet-à-octet parfait sur le corpus `tests/fixtures/rfc3161/`. Le module
//! [`token`] (jalon J6) construit un `TimeStampToken` réel ; il s'appuie sur
//! la crate `cms`, ce qui a entraîné la migration de tout ce stack ASN.1 de
//! der 0.7 vers der 0.8 (voir l'historique du plan).
//!
//! Grammaire de référence : RFC 3161 §2.4.1-2.4.2.

use der::asn1::{BitString, Int, ObjectIdentifier, OctetString};
use der::{Any, Sequence, ValueOrd};
use spki::AlgorithmIdentifierOwned;
use x509_cert::ext::Extensions;

pub mod gen_time;
pub mod token;

/// `MessageImprint ::= SEQUENCE { hashAlgorithm AlgorithmIdentifier, hashedMessage OCTET STRING }`
#[derive(Clone, Debug, Eq, PartialEq, Sequence, ValueOrd)]
pub struct MessageImprint {
    pub hash_algorithm: AlgorithmIdentifierOwned,
    pub hashed_message: OctetString,
}

/// `TimeStampReq ::= SEQUENCE { version INTEGER, messageImprint MessageImprint,
/// reqPolicy TSAPolicyId OPTIONAL, nonce INTEGER OPTIONAL,
/// certReq BOOLEAN DEFAULT FALSE, extensions [0] IMPLICIT Extensions OPTIONAL }`
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct TimeStampReq {
    pub version: u8,
    pub message_imprint: MessageImprint,
    #[asn1(optional = "true")]
    pub req_policy: Option<ObjectIdentifier>,
    #[asn1(optional = "true")]
    pub nonce: Option<Int>,
    #[asn1(default = "bool_false")]
    pub cert_req: bool,
    #[asn1(context_specific = "0", tag_mode = "IMPLICIT", optional = "true")]
    pub extensions: Option<Extensions>,
}

fn bool_false() -> bool {
    false
}

/// `PKIStatusInfo ::= SEQUENCE { status INTEGER, statusString PKIFreeText
/// OPTIONAL, failInfo PKIFailureInfo OPTIONAL }` (`PKIFreeText ::= SEQUENCE
/// OF UTF8String`, `PKIFailureInfo ::= BIT STRING`).
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct PkiStatusInfo {
    pub status: Int,
    #[asn1(optional = "true")]
    pub status_string: Option<Vec<String>>,
    #[asn1(optional = "true")]
    pub fail_info: Option<BitString>,
}

/// `TimeStampResp ::= SEQUENCE { status PKIStatusInfo, timeStampToken
/// TimeStampToken OPTIONAL }`. `TimeStampToken` (un `ContentInfo` CMS signé)
/// est conservé opaque — voir la note de module.
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct TimeStampResp {
    pub status: PkiStatusInfo,
    #[asn1(optional = "true")]
    pub time_stamp_token: Option<Any>,
}

/// `Accuracy ::= SEQUENCE { seconds INTEGER OPTIONAL, millis [0] INTEGER
/// (1..999) OPTIONAL, micros [1] INTEGER (1..999) OPTIONAL }`
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct Accuracy {
    #[asn1(optional = "true")]
    pub seconds: Option<Int>,
    #[asn1(context_specific = "0", tag_mode = "IMPLICIT", optional = "true")]
    pub millis: Option<u16>,
    #[asn1(context_specific = "1", tag_mode = "IMPLICIT", optional = "true")]
    pub micros: Option<u16>,
}

/// `TSTInfo ::= SEQUENCE { version INTEGER, policy TSAPolicyId,
/// messageImprint MessageImprint, serialNumber INTEGER, genTime
/// GeneralizedTime, accuracy Accuracy OPTIONAL, ordering BOOLEAN DEFAULT
/// FALSE, nonce INTEGER OPTIONAL, tsa [0] GeneralName OPTIONAL, extensions
/// [1] IMPLICIT Extensions OPTIONAL }`.
///
/// `tsa` est un `GeneralName` (type CHOICE) : X.680 interdit le taggage
/// implicite d'un CHOICE, le tag `[0]` est donc EXPLICIT même sans mot-clé —
/// conservé opaque ici pour la même raison que `TimeStampToken`.
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct TstInfo {
    pub version: u8,
    pub policy: ObjectIdentifier,
    pub message_imprint: MessageImprint,
    pub serial_number: Int,
    /// `Any`, pas `der::asn1::GeneralizedTime` : ce dernier suit le profil
    /// RFC 5280 (certificats), qui **interdit** les fractions de seconde —
    /// RFC 3161 ne reprend pas cette restriction pour `TSTInfo.genTime`, et
    /// EN 319 422 §5.2.2 exige justement la fraction nécessaire à
    /// l'exactitude déclarée (constat T-1 de l'audit du 2026-09-25). Voir
    /// [`gen_time`].
    pub gen_time: Any,
    #[asn1(optional = "true")]
    pub accuracy: Option<Accuracy>,
    #[asn1(default = "bool_false")]
    pub ordering: bool,
    #[asn1(optional = "true")]
    pub nonce: Option<Int>,
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT", optional = "true")]
    pub tsa: Option<Any>,
    #[asn1(context_specific = "1", tag_mode = "IMPLICIT", optional = "true")]
    pub extensions: Option<Extensions>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use der::{Decode, Encode};
    use std::fs;
    use std::path::Path;

    fn fixtures_dir() -> &'static Path {
        Path::new(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../tests/fixtures/rfc3161"
        ))
    }

    fn case_dirs() -> Vec<std::path::PathBuf> {
        fs::read_dir(fixtures_dir())
            .expect("corpus de fixtures introuvable (tests/fixtures/rfc3161, généré une fois pour toutes par le binaire Go de référence avant sa dépréciation)")
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| p.is_dir() && p.file_name().is_some_and(|n| n != "keys"))
            .collect()
    }

    #[test]
    fn round_trips_every_request_in_the_corpus() {
        let dirs = case_dirs();
        assert!(!dirs.is_empty(), "corpus de fixtures vide");
        for dir in dirs {
            let path = dir.join("request.der");
            let raw = fs::read(&path).unwrap_or_else(|e| panic!("{path:?}: {e}"));
            let req = TimeStampReq::from_der(&raw)
                .unwrap_or_else(|e| panic!("décodage de {path:?}: {e}"));
            let reencoded = req
                .to_der()
                .unwrap_or_else(|e| panic!("réencodage de {path:?}: {e}"));
            assert_eq!(reencoded, raw, "round-trip DER non fidèle pour {path:?}");
        }
    }

    #[test]
    fn round_trips_every_response_in_the_corpus() {
        let dirs: Vec<_> = case_dirs()
            .into_iter()
            .filter(|d| d.join("response.der").exists())
            .collect();
        assert!(!dirs.is_empty(), "aucune réponse accordée dans le corpus");
        for dir in dirs {
            let path = dir.join("response.der");
            let raw = fs::read(&path).unwrap();
            let resp = TimeStampResp::from_der(&raw)
                .unwrap_or_else(|e| panic!("décodage de {path:?}: {e}"));
            assert!(
                resp.time_stamp_token.is_some(),
                "{path:?}: jeton absent d'une réponse accordée"
            );
            let reencoded = resp
                .to_der()
                .unwrap_or_else(|e| panic!("réencodage de {path:?}: {e}"));
            assert_eq!(reencoded, raw, "round-trip DER non fidèle pour {path:?}");
        }
    }
}
