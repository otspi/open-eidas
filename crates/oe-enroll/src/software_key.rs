//! Clé logicielle du lien interne `ra-console` ↔ `ca-server` (docs/WEBUI.md
//! §14, §16), partagée par les deux services : la clé, et l'écriture des fichiers
//! qu'ils relisent.
//!
//! La clé est logicielle par conception : elle n'authentifie qu'un canal et ne
//! signe ni certificat, ni jeton, ni réponse OCSP. Elle reste sur le volume du
//! service, en 0600, et n'est jamais affichée ni journalisée.

use std::io::Write;
use std::path::Path;

use oe_hsm::{DigestAlg, HsmError, Scheme, SigningToken};
use rsa::pkcs1v15::Pkcs1v15Sign;
use rsa::pkcs8::{DecodePrivateKey, EncodePrivateKey, EncodePublicKey};
use rsa::RsaPrivateKey;
use sha2::{Sha256, Sha384, Sha512};

/// ETSI TS 119 312 : la CA refuse moins de 3072 bits (`oe_raflow`).
const KEY_BITS: usize = 3072;

pub struct SoftSigner(RsaPrivateKey);

impl SigningToken for SoftSigner {
    fn sign_digest(&self, alg: DigestAlg, digest: &[u8]) -> Result<Vec<u8>, HsmError> {
        if digest.len() != alg.expected_len() {
            return Err(HsmError::DigestLength {
                alg,
                expected: alg.expected_len(),
                actual: digest.len(),
            });
        }
        match alg {
            DigestAlg::Sha256 => self.0.sign(Pkcs1v15Sign::new::<Sha256>(), digest),
            DigestAlg::Sha384 => self.0.sign(Pkcs1v15Sign::new::<Sha384>(), digest),
            DigestAlg::Sha512 => self.0.sign(Pkcs1v15Sign::new::<Sha512>(), digest),
        }
        .map_err(HsmError::SoftwareSign)
    }

    fn sign_digest_with(
        &self,
        scheme: Scheme,
        alg: DigestAlg,
        digest: &[u8],
    ) -> Result<Vec<u8>, HsmError> {
        if scheme == Scheme::Pkcs1v15 {
            return self.sign_digest(alg, digest);
        }
        if digest.len() != alg.expected_len() {
            return Err(HsmError::DigestLength {
                alg,
                expected: alg.expected_len(),
                actual: digest.len(),
            });
        }
        let salt = alg.expected_len();
        match alg {
            DigestAlg::Sha256 => self.0.sign_with_rng(
                &mut rand::thread_rng(),
                rsa::pss::Pss::new_with_salt::<Sha256>(salt),
                digest,
            ),
            DigestAlg::Sha384 => self.0.sign_with_rng(
                &mut rand::thread_rng(),
                rsa::pss::Pss::new_with_salt::<Sha384>(salt),
                digest,
            ),
            DigestAlg::Sha512 => self.0.sign_with_rng(
                &mut rand::thread_rng(),
                rsa::pss::Pss::new_with_salt::<Sha512>(salt),
                digest,
            ),
        }
        .map_err(HsmError::SoftwareSign)
    }

    fn public_key_der(&self) -> Result<Vec<u8>, HsmError> {
        self.0
            .to_public_key()
            .to_public_key_der()
            .map(|d| d.as_bytes().to_vec())
            .map_err(HsmError::PublicKeyEncoding)
    }
}

/// Relit la clé si le fichier existe, la crée sinon. Réutiliser la clé rend la
/// commande idempotente : la même clé et le même nom redonnent la même CSR
/// (signature PKCS#1 v1.5 déterministe), donc retrouvent la même demande.
pub fn load_or_create_key(path: &Path) -> Result<SoftSigner, String> {
    if path.exists() {
        let pem = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
        return RsaPrivateKey::from_pkcs8_pem(&pem)
            .map(SoftSigner)
            .map_err(|e| format!("{}: clé illisible: {e}", path.display()));
    }
    let key = RsaPrivateKey::new(&mut rand::thread_rng(), KEY_BITS)
        .map_err(|e| format!("génération de la clé: {e}"))?;
    let pem = key
        .to_pkcs8_pem(Default::default())
        .map_err(|e| format!("encodage de la clé: {e}"))?;
    write_new(path, pem.as_bytes(), 0o600)?;
    Ok(SoftSigner(key))
}

/// Écrit un fichier qui n'existe pas encore, avec ses droits dès la création :
/// jamais un instant en lecture pour tous.
fn write_new(path: &Path, content: &[u8], mode: u32) -> Result<(), String> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(path)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    f.write_all(content)
        .map_err(|e| format!("{}: {e}", path.display()))
}

/// Écrit le certificat, en remplaçant l'ancien (renouvellement).
pub fn write_certificate(path: &Path, pem: &str) -> Result<(), String> {
    let tmp = path.with_extension("tmp");
    let _ = std::fs::remove_file(&tmp);
    write_new(&tmp, pem.as_bytes(), 0o644)?;
    std::fs::rename(&tmp, path).map_err(|e| format!("{}: {e}", path.display()))
}
