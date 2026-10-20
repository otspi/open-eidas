//! Adapte [`oe_hsm::SigningToken`] à l'API de signature externe de
//! `x509_cert::builder` : `Builder::finalize`/`assemble` n'exigent qu'un
//! type sachant produire sa clé publique et son identifiant d'algorithme
//! (`signature::Keypair` + `spki::DynSignatureAlgorithmIdentifier`), jamais
//! la clé privée elle-même — exactement le découpage qu'il fallait pour
//! signer avec une clé qui ne quitte jamais le token PKCS#11, sans avoir à
//! réécrire à la main les structures `TbsCertificate`/`TbsCertList`.
//!
//! [`RawPublicKey`] enveloppe directement les octets DER
//! `SubjectPublicKeyInfo` déjà produits par
//! [`oe_hsm::SigningToken::public_key_der`], plutôt que de les redécoder en
//! `rsa::RsaPublicKey` : la crate `rsa` dépend d'une version de `spki`
//! antérieure à celle qu'exige `x509-cert` 0.3, et les deux traits
//! `EncodePublicKey` (l'un par version) sont incompatibles entre elles.

use der::asn1::BitString;
use der::Encode;
use sha2::{Digest, Sha256};
use spki::AlgorithmIdentifierOwned;
use x509_cert::builder::Builder;

use oe_hsm::{DigestAlg, SigningToken};

use crate::CaError;

const OID_SHA256_WITH_RSA: &str = "1.2.840.113549.1.1.11";

#[derive(Clone)]
pub(crate) struct RawPublicKey(Vec<u8>);

impl spki::EncodePublicKey for RawPublicKey {
    fn to_public_key_der(&self) -> spki::Result<der::Document> {
        der::Document::try_from(self.0.as_slice()).map_err(spki::Error::from)
    }
}

pub(crate) struct HsmKeypair {
    public_key_der: Vec<u8>,
}

impl HsmKeypair {
    pub(crate) fn from_public_key_der(der: &[u8]) -> Self {
        HsmKeypair {
            public_key_der: der.to_vec(),
        }
    }
}

impl signature::Keypair for HsmKeypair {
    type VerifyingKey = RawPublicKey;
    fn verifying_key(&self) -> Self::VerifyingKey {
        RawPublicKey(self.public_key_der.clone())
    }
}

impl spki::DynSignatureAlgorithmIdentifier for HsmKeypair {
    fn signature_algorithm_identifier(&self) -> spki::Result<AlgorithmIdentifierOwned> {
        Ok(AlgorithmIdentifierOwned {
            oid: der::asn1::ObjectIdentifier::new(OID_SHA256_WITH_RSA)
                .expect("OID constant invalide"),
            // RFC 4055 §5 : sha256WithRSAEncryption porte des paramètres NULL à
            // l\'émission (constat C-5) ; l\'absence reste tolérée à la lecture.
            parameters: Some(der::asn1::Null.into()),
        })
    }
}

/// Finalise un `Builder` x509-cert (certificat ou CRL) en signant avec le
/// token PKCS#11, sans jamais faire transiter la clé privée par ce
/// processus : `finalize` produit les octets à signer, le token les signe,
/// `assemble` reconstitue l'objet final avec la signature obtenue.
pub(crate) fn sign_with_token<B: Builder>(
    mut builder: B,
    signer: &dyn SigningToken,
    public_key_der: &[u8],
) -> Result<B::Output, CaError> {
    let keypair = HsmKeypair::from_public_key_der(public_key_der);
    let tbs_der = builder
        .finalize(&keypair)
        .map_err(|e| CaError::Other(e.to_string()))?;
    let digest = Sha256::digest(&tbs_der);
    let signature = signer.sign_digest(DigestAlg::Sha256, &digest)?;
    let bit_string = BitString::from_bytes(&signature)?;
    builder
        .assemble(bit_string, &keypair)
        .map_err(|e| CaError::Other(e.to_string()))
}

/// Signe une CRL construite à la main (voir `lib::publish_crl`), sans passer
/// par `x509_cert::builder::CrlBuilder` : celui-ci recopierait l'AKI du
/// certificat d'autorité lui-même dans la CRL, plutôt que d'identifier la
/// clé qui la signe réellement — cf. le commentaire de
/// `extensions::authority_key_identifier`. Reproduit la même séquence que
/// `Builder::finalize`/`assemble` (fixer l'algorithme, encoder, signer,
/// assembler), à la main.
pub(crate) fn sign_crl(
    mut tbs: x509_cert::crl::TbsCertList,
    signer: &dyn SigningToken,
    public_key_der: &[u8],
) -> Result<x509_cert::crl::CertificateList, CaError> {
    let keypair = HsmKeypair::from_public_key_der(public_key_der);
    let algorithm = spki::DynSignatureAlgorithmIdentifier::signature_algorithm_identifier(&keypair)
        .map_err(|e| CaError::Other(e.to_string()))?;
    tbs.signature = algorithm.clone();
    let tbs_der = tbs.to_der().map_err(CaError::Der)?;
    let digest = Sha256::digest(&tbs_der);
    let signature = signer.sign_digest(DigestAlg::Sha256, &digest)?;
    let bit_string = BitString::from_bytes(&signature)?;
    Ok(x509_cert::crl::CertificateList {
        tbs_cert_list: tbs,
        signature_algorithm: algorithm,
        signature: bit_string,
    })
}

/// SHA-1 de la BIT STRING de clé publique (méthode 1, RFC 5280 §4.2.1.2).
/// SHA-1 n'intervient ici que comme identifiant d'appariement, jamais comme
/// preuve d'intégrité.
pub(crate) fn subject_key_id(public_key_der: &[u8]) -> Result<Vec<u8>, CaError> {
    use der::Decode;
    use sha1::Digest as _;
    let spki = x509_cert::SubjectPublicKeyInfo::from_der(public_key_der).map_err(CaError::Der)?;
    let sum = sha1::Sha1::digest(spki.subject_public_key.raw_bytes());
    Ok(sum.to_vec())
}
