//! Portage de `internal/hsm` : accès à la clé de signature de l'unité
//! d'horodatage (TSU) via PKCS#11. La clé privée ne quitte jamais le token —
//! seule cette crate est autorisée à contenir du `unsafe` dans le workspace
//! (bindings PKCS#11 via la crate `cryptoki`).
//!
//! Le trait [`SigningToken`] joue le rôle de `crypto.Signer` côté Go : le
//! reste du workspace (`oe-tsa-core`, notamment) ne dépend que de ce trait,
//! jamais directement de `cryptoki`, ce qui permet de le tester avec
//! [`SoftwareToken`] sans matériel PKCS#11 réel (SoftHSM2 y compris).
//!
//! Feature `pkcs11` (activée par défaut) : le token PKCS#11 et `cryptoki`. Sans
//! elle, il ne reste que le trait et les types qui l'accompagnent. Un service qui
//! n'ouvre jamais de session PKCS#11 (`ra-console`, docs/WEBUI.md §16) désactive la
//! feature : `cryptoki` n'est alors pas même compilé, et son profil de dépendances
//! (donc de `cargo audit`) est celui promis.

#[cfg(feature = "pkcs11")]
use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
#[cfg(feature = "pkcs11")]
use cryptoki::mechanism::Mechanism;
#[cfg(feature = "pkcs11")]
use cryptoki::object::{Attribute, AttributeType, ObjectClass};
#[cfg(feature = "pkcs11")]
use cryptoki::session::{Session, UserType};
#[cfg(feature = "pkcs11")]
use cryptoki::types::AuthPin;
#[cfg(feature = "pkcs11")]
use sha2::{Digest, Sha256};

/// Paramètres d'ouverture du token (équivalent de `hsm.Options` en Go).
#[derive(Debug, Clone)]
pub struct Options {
    pub module_path: String,
    pub token_label: String,
    pub key_label: String,
    pub pin: String,
}

/// Algorithme de hachage pour lequel une signature RSA PKCS#1 v1.5 est
/// demandée. Le préfixe `DigestInfo` (RFC 3447 annexe B) est ajouté par cette
/// crate avant l'appel PKCS#11 `CKM_RSA_PKCS`, à l'identique de ce que fait
/// `crypto/rsa` côté Go pour un `crypto.Signer` RSA.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DigestAlg {
    Sha256,
    Sha384,
    Sha512,
}

impl DigestAlg {
    pub fn expected_len(self) -> usize {
        match self {
            DigestAlg::Sha256 => 32,
            DigestAlg::Sha384 => 48,
            DigestAlg::Sha512 => 64,
        }
    }

    /// Préfixe ASN.1 `DigestInfo` (RFC 3447 annexe B.1) pour cet algorithme.
    #[cfg(feature = "pkcs11")]
    fn digest_info_prefix(self) -> &'static [u8] {
        match self {
            DigestAlg::Sha256 => &[
                0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                0x01, 0x05, 0x00, 0x04, 0x20,
            ],
            DigestAlg::Sha384 => &[
                0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                0x02, 0x05, 0x00, 0x04, 0x30,
            ],
            DigestAlg::Sha512 => &[
                0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                0x03, 0x05, 0x00, 0x04, 0x40,
            ],
        }
    }

    #[cfg(feature = "pkcs11")]
    fn wrap(self, digest: &[u8]) -> Result<Vec<u8>, HsmError> {
        if digest.len() != self.expected_len() {
            return Err(HsmError::DigestLength {
                alg: self,
                expected: self.expected_len(),
                actual: digest.len(),
            });
        }
        let mut out = Vec::with_capacity(self.digest_info_prefix().len() + digest.len());
        out.extend_from_slice(self.digest_info_prefix());
        out.extend_from_slice(digest);
        Ok(out)
    }
}

/// Schéma de signature RSA (PKCS#1 v2.2). Constat H-2 de l'audit du
/// 2026-09-25 : RSASSA-PSS est l'orientation de l'ANSSI, PKCS#1 v1.5 reste
/// admis par TS 119 312. Décision de l'association du 2026-10-21 : PSS partout.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Scheme {
    /// RSASSA-PKCS1-v1_5 (RFC 8017 §8.2), `CKM_RSA_PKCS`.
    #[default]
    Pkcs1v15,
    /// RSASSA-PSS (RFC 8017 §8.1), `CKM_RSA_PKCS_PSS`, MGF1 du même condensé,
    /// sel de la longueur du condensé.
    Pss,
}

/// Variable d'environnement qui choisit le schéma de signature RSA de tous les
/// services (CA, OCSP, TSA) : `pss` ou `pkcs1v15` (défaut).
pub const ENV_RSA_SCHEME: &str = "OPENEIDAS_RSA_SCHEME";

impl std::str::FromStr for Scheme {
    type Err = String;

    fn from_str(s: &str) -> Result<Scheme, String> {
        match s.trim().to_lowercase().as_str() {
            "pkcs1v15" | "pkcs1" | "pkcs1-v1_5" => Ok(Scheme::Pkcs1v15),
            "pss" | "rsassa-pss" => Ok(Scheme::Pss),
            other => Err(format!(
                "{ENV_RSA_SCHEME}={other:?} : « pss » ou « pkcs1v15 » attendu"
            )),
        }
    }
}

impl Scheme {
    /// Lit [`ENV_RSA_SCHEME`] ; `pkcs1v15` quand elle est absente ou vide, le
    /// temps que PSS soit validé face aux vérificateurs de la production.
    pub fn from_env() -> Result<Scheme, String> {
        match std::env::var(ENV_RSA_SCHEME) {
            Ok(v) if !v.trim().is_empty() => v.parse(),
            _ => Ok(Scheme::Pkcs1v15),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum HsmError {
    #[error("hsm: schéma de signature {0:?} non pris en charge par ce signataire")]
    UnsupportedScheme(Scheme),
    #[cfg(feature = "pkcs11")]
    #[error("hsm: ouverture du token {token_label:?} via {module_path}: {source}")]
    Open {
        module_path: String,
        token_label: String,
        #[source]
        source: cryptoki::error::Error,
    },
    #[error("hsm: jeton introuvable pour le label {0:?}")]
    TokenNotFound(String),
    #[cfg(feature = "pkcs11")]
    #[error("hsm: recherche de la clé {key_label:?}: {source}")]
    FindKey {
        key_label: String,
        #[source]
        source: cryptoki::error::Error,
    },
    #[error("hsm: bi-clé introuvable sur le token")]
    KeyNotFound,
    #[error(
        "hsm: {0} objets répondent au label et au CKA_ID de la clé privée {1:?} (un seul attendu)"
    )]
    KeyAmbiguous(usize, String),
    #[error("hsm: la clé privée {key_label:?} n'a pas l'attribut {attribute} attendu (clé importée ou extractible ?)")]
    KeyAttribute {
        key_label: String,
        attribute: &'static str,
    },
    #[cfg(feature = "pkcs11")]
    #[error("hsm: génération de la bi-clé RSA-{bits}: {source}")]
    GenerateKey {
        bits: u64,
        #[source]
        source: cryptoki::error::Error,
    },
    #[error("hsm: digest {alg:?} de longueur invalide (attendu {expected}, reçu {actual})")]
    DigestLength {
        alg: DigestAlg,
        expected: usize,
        actual: usize,
    },
    #[cfg(feature = "pkcs11")]
    #[error("hsm: opération PKCS#11: {0}")]
    Pkcs11(#[from] cryptoki::error::Error),
    #[error("hsm: la signature produite ne se vérifie pas avec la clé publique (faute du module ou de la session ?)")]
    SignatureVerification,
    #[error("hsm: signature logicielle de test: {0}")]
    SoftwareSign(#[from] rsa::Error),
    #[error("hsm: encodage d'un identifiant d'algorithme: {0}")]
    Encoding(der::Error),
    #[error("hsm: encodage SubjectPublicKeyInfo: {0}")]
    PublicKeyEncoding(rsa::pkcs8::spki::Error),
}

/// Équivalent de `crypto.Signer` : signe un digest déjà calculé sans jamais
/// exposer la clé privée.
pub trait SigningToken {
    /// Signe en RSASSA-PKCS1-v1_5.
    fn sign_digest(&self, alg: DigestAlg, digest: &[u8]) -> Result<Vec<u8>, HsmError>;

    /// Signe selon le schéma demandé. Par défaut, seul PKCS#1 v1.5 est connu :
    /// un signataire qui sait faire PSS redéfinit cette méthode.
    fn sign_digest_with(
        &self,
        scheme: Scheme,
        alg: DigestAlg,
        digest: &[u8],
    ) -> Result<Vec<u8>, HsmError> {
        match scheme {
            Scheme::Pkcs1v15 => self.sign_digest(alg, digest),
            Scheme::Pss => Err(HsmError::UnsupportedScheme(scheme)),
        }
    }

    /// Clé publique correspondante, encodée SubjectPublicKeyInfo (DER).
    /// Sert à vérifier, avant de signer, que la clé du token correspond bien
    /// au certificat publié (reproduit la vérification faite par `tsa.New`
    /// côté Go via `x509.MarshalPKIXPublicKey`).
    fn public_key_der(&self) -> Result<Vec<u8>, HsmError>;
}

#[cfg(feature = "pkcs11")]
/// CKA_ID stable et non vide dérivé du label de clé — reproduit `hsm.Open`
/// (Go), qui s'en sert pour apparier clé privée et clé publique.
fn key_id(key_label: &str) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(key_label.as_bytes());
    hasher.finalize()[..8].to_vec()
}

/// OID `id-RSASSA-PSS` (RFC 4055 §3.1).
pub const OID_RSASSA_PSS: &str = "1.2.840.113549.1.1.10";
const OID_MGF1: &str = "1.2.840.113549.1.1.8";

impl DigestAlg {
    fn oid(self) -> &'static str {
        match self {
            DigestAlg::Sha256 => "2.16.840.1.101.3.4.2.1",
            DigestAlg::Sha384 => "2.16.840.1.101.3.4.2.2",
            DigestAlg::Sha512 => "2.16.840.1.101.3.4.2.3",
        }
    }

    /// OID `shaNWithRSAEncryption` (RFC 4055 §5).
    fn pkcs1_oid(self) -> &'static str {
        match self {
            DigestAlg::Sha256 => "1.2.840.113549.1.1.11",
            DigestAlg::Sha384 => "1.2.840.113549.1.1.12",
            DigestAlg::Sha512 => "1.2.840.113549.1.1.13",
        }
    }
}

/// L'`AlgorithmIdentifier` X.509 d'une signature RSA du schéma et du condensé
/// donnés, tel que RFC 4055 l'impose à l'émission :
///
/// - PKCS#1 v1.5 : `shaNWithRSAEncryption`, paramètres `NULL` ;
/// - PSS : `id-RSASSA-PSS` avec `RSASSA-PSS-params` — condensé (paramètres
///   `NULL`), MGF1 du même condensé, sel de la longueur du condensé,
///   `trailerField` par défaut omis —, l'encodage que produit openssl.
pub fn signature_algorithm(
    scheme: Scheme,
    alg: DigestAlg,
) -> Result<spki::AlgorithmIdentifierOwned, HsmError> {
    use der::{asn1::ObjectIdentifier, Any, Decode, Encode};
    let oid = |s: &str| ObjectIdentifier::new(s).expect("OID constant invalide");
    match scheme {
        Scheme::Pkcs1v15 => Ok(spki::AlgorithmIdentifierOwned {
            oid: oid(alg.pkcs1_oid()),
            parameters: Some(Any::from(der::asn1::Null)),
        }),
        Scheme::Pss => {
            let hash = spki::AlgorithmIdentifierOwned {
                oid: oid(alg.oid()),
                parameters: Some(Any::from(der::asn1::Null)),
            };
            let mgf = spki::AlgorithmIdentifierOwned {
                oid: oid(OID_MGF1),
                parameters: Some(
                    Any::from_der(&hash.to_der().map_err(HsmError::Encoding)?)
                        .map_err(HsmError::Encoding)?,
                ),
            };
            // [0] hash, [1] mgf, [2] saltLength — étiquettes explicites.
            let explicit = |tag: u8, inner: Vec<u8>| -> Vec<u8> {
                let mut out = vec![0xa0 | tag];
                out.extend(der_len(inner.len()));
                out.extend(inner);
                out
            };
            let mut body = Vec::new();
            body.extend(explicit(0, hash.to_der().map_err(HsmError::Encoding)?));
            body.extend(explicit(1, mgf.to_der().map_err(HsmError::Encoding)?));
            let salt = (alg.expected_len() as u64).to_be_bytes();
            let first = salt.iter().position(|&b| b != 0).unwrap_or(salt.len() - 1);
            let mut int = vec![0x02];
            let mut digits = salt[first..].to_vec();
            if digits[0] & 0x80 != 0 {
                digits.insert(0, 0);
            }
            int.extend(der_len(digits.len()));
            int.extend(digits);
            body.extend(explicit(2, int));
            let mut seq = vec![0x30];
            seq.extend(der_len(body.len()));
            seq.extend(body);
            Ok(spki::AlgorithmIdentifierOwned {
                oid: oid(OID_RSASSA_PSS),
                parameters: Some(Any::from_der(&seq).map_err(HsmError::Encoding)?),
            })
        }
    }
}

/// Le schéma et le condensé que désigne un `AlgorithmIdentifier` de signature
/// RSA — `shaNWithRSAEncryption` (paramètres NULL ou absents) ou `id-RSASSA-PSS`
/// avec exactement les paramètres de [`signature_algorithm`] —, ou `None` pour
/// tout autre (SHA-1, MD5, ECDSA, PSS à paramètres atypiques, …).
pub fn scheme_of(algorithm: &spki::AlgorithmIdentifierOwned) -> Option<(Scheme, DigestAlg)> {
    use der::Encode;
    let digests = [DigestAlg::Sha256, DigestAlg::Sha384, DigestAlg::Sha512];
    if algorithm.oid.to_string() == OID_RSASSA_PSS {
        let given = algorithm.to_der().ok()?;
        return digests
            .into_iter()
            .find(|d| {
                signature_algorithm(Scheme::Pss, *d)
                    .and_then(|a| a.to_der().map_err(HsmError::Encoding))
                    .is_ok_and(|expected| expected == given)
            })
            .map(|d| (Scheme::Pss, d));
    }
    let null_or_absent = match &algorithm.parameters {
        None => true,
        Some(p) => *p == der::Any::from(der::asn1::Null),
    };
    if !null_or_absent {
        return None;
    }
    digests
        .into_iter()
        .find(|d| d.pkcs1_oid() == algorithm.oid.to_string())
        .map(|d| (Scheme::Pkcs1v15, d))
}

impl DigestAlg {
    /// Condensé de `data`.
    pub fn hash(self, data: &[u8]) -> Vec<u8> {
        use sha2::Digest as _;
        match self {
            DigestAlg::Sha256 => sha2::Sha256::digest(data).to_vec(),
            DigestAlg::Sha384 => sha2::Sha384::digest(data).to_vec(),
            DigestAlg::Sha512 => sha2::Sha512::digest(data).to_vec(),
        }
    }
}

/// Longueur DER (courte ou longue).
fn der_len(n: usize) -> Vec<u8> {
    if n < 0x80 {
        vec![n as u8]
    } else if n < 0x100 {
        vec![0x81, n as u8]
    } else {
        vec![0x82, (n >> 8) as u8, n as u8]
    }
}

/// Vérifie une signature RSA PKCS#1 v1.5 de `digest` avec la clé publique
/// correspondante (constat H-2 de l'audit du 2026-09-25 : vérification après
/// signature). Une seule opération publique ; protège contre les fautes de
/// calcul du module (attaque de Bellcore sur RSA-CRT) et contre une erreur de
/// token ou de configuration, avant qu'une signature fautive ne sorte du
/// service.
pub fn verify_signature(
    public_key: &rsa::RsaPublicKey,
    alg: DigestAlg,
    digest: &[u8],
    signature: &[u8],
) -> Result<(), HsmError> {
    verify_signature_with(public_key, Scheme::Pkcs1v15, alg, digest, signature)
}

/// Comme [`verify_signature`], pour le schéma donné (PKCS#1 v1.5 ou PSS).
pub fn verify_signature_with(
    public_key: &rsa::RsaPublicKey,
    scheme: Scheme,
    alg: DigestAlg,
    digest: &[u8],
    signature: &[u8],
) -> Result<(), HsmError> {
    use rsa::pkcs1v15::Pkcs1v15Sign;
    use rsa::pss::Pss;
    let result = match (scheme, alg) {
        (Scheme::Pkcs1v15, DigestAlg::Sha256) => {
            public_key.verify(Pkcs1v15Sign::new::<sha2::Sha256>(), digest, signature)
        }
        (Scheme::Pkcs1v15, DigestAlg::Sha384) => {
            public_key.verify(Pkcs1v15Sign::new::<sha2::Sha384>(), digest, signature)
        }
        (Scheme::Pkcs1v15, DigestAlg::Sha512) => {
            public_key.verify(Pkcs1v15Sign::new::<sha2::Sha512>(), digest, signature)
        }
        (Scheme::Pss, DigestAlg::Sha256) => public_key.verify(
            Pss::new_with_salt::<sha2::Sha256>(alg.expected_len()),
            digest,
            signature,
        ),
        (Scheme::Pss, DigestAlg::Sha384) => public_key.verify(
            Pss::new_with_salt::<sha2::Sha384>(alg.expected_len()),
            digest,
            signature,
        ),
        (Scheme::Pss, DigestAlg::Sha512) => public_key.verify(
            Pss::new_with_salt::<sha2::Sha512>(alg.expected_len()),
            digest,
            signature,
        ),
    };
    result.map_err(|_| HsmError::SignatureVerification)
}

/// Le module signale-t-il une session perdue ou un appareil réinitialisé ?
/// (`CKR_USER_NOT_LOGGED_IN`, session fermée ou invalide, appareil retiré ou en
/// erreur, token absent, ou clé privée devenue invisible faute de connexion.)
#[cfg(feature = "pkcs11")]
fn is_session_lost(err: &HsmError) -> bool {
    use cryptoki::error::{Error, RvError};
    // Un module dont l'utilisateur est déconnecté ne montre plus les objets
    // privés : la clé semble absente. Une seule reconnexion lève le doute (si
    // la clé manque vraiment, l'erreur revient telle quelle).
    if matches!(err, HsmError::KeyNotFound) {
        return true;
    }
    let source = match err {
        HsmError::Pkcs11(e) => e,
        HsmError::FindKey { source, .. } => source,
        _ => return false,
    };
    matches!(
        source,
        Error::Pkcs11(
            RvError::UserNotLoggedIn
                | RvError::SessionClosed
                | RvError::SessionHandleInvalid
                | RvError::DeviceRemoved
                | RvError::DeviceError
                | RvError::TokenNotPresent,
            _
        )
    )
}

/// Implémentation réelle : token PKCS#11 (SoftHSM2 en dev/CI, HSM FIPS en prod).
#[cfg(feature = "pkcs11")]
pub struct Pkcs11Token {
    /// Session courante, remplacée par [`Pkcs11Token::reconnect`] quand le
    /// module la perd (constat H-2 : redémarrage du HSM, session fermée,
    /// utilisateur déconnecté).
    session: std::sync::Mutex<Session>,
    pkcs11: Pkcs11,
    token_label: String,
    /// Gardé pour rouvrir la session ; effacé de la mémoire à l'abandon du
    /// token (constat H-3 : le PIN n'était pas zéroïsé).
    pin: zeroize::Zeroizing<String>,
    key_id: Vec<u8>,
    key_label: String,
    /// Constat H-1 : la provenance de la clé n'est contrôlée qu'une fois par
    /// ouverture, avant la première utilisation.
    provenance_verified: std::sync::atomic::AtomicBool,
    /// Clé publique, lue une fois pour vérifier chaque signature (constat H-2).
    public_key: std::sync::OnceLock<rsa::RsaPublicKey>,
}

/// Attributs PKCS#11 de la clé privée qui prouvent qu'elle est née dans le
/// module et n'en sort pas (constat H-1 de l'audit du 2026-09-25 ;
/// EN 319 421 `TIS-7.6.2-03`, `TIS-7.6.2-06`, `TIS-7.6.3-02` ; EN 319 401
/// `REQ-7.5-01`).
#[cfg(feature = "pkcs11")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyProvenance {
    /// `CKA_LOCAL` : générée par le module (faux pour une clé importée).
    pub local: bool,
    /// `CKA_NEVER_EXTRACTABLE`.
    pub never_extractable: bool,
    /// `CKA_ALWAYS_SENSITIVE`.
    pub always_sensitive: bool,
    /// `CKA_SIGN`.
    pub sign: bool,
    /// `CKA_DECRYPT`, `CKA_UNWRAP`, `CKA_DERIVE` : faux pour une clé générée
    /// avec le gabarit actuel (constat H-3), à journaliser mais non exigé.
    pub decrypt: bool,
    pub unwrap: bool,
    pub derive: bool,
}

/// `C_Initialize` est un appel PROCESSUS entier, pas par instance de
/// contexte : un second appel sans `C_Finalize` entre les deux échoue avec
/// `CKR_CRYPTOKI_ALREADY_INITIALIZED` — constaté en pratique dès qu'un
/// même processus ouvre deux tokens PKCS#11 distincts (la cérémonie de
/// `ca-server` ouvre la racine ET l'émettrice). Ce cache, tenu pour la
/// durée du processus et indexé par chemin de module, garantit qu'un seul
/// contexte `Pkcs11` initialisé existe par bibliothèque chargée, partagé
/// entre tous les tokens ouverts sur ce module — reproduit le comportement
/// de `crypto11.Configure` (Go), qui réutilise de même un contexte partagé.
#[cfg(feature = "pkcs11")]
fn shared_context(module_path: &str) -> Result<Pkcs11, cryptoki::error::Error> {
    use std::collections::HashMap;
    use std::sync::{Mutex, OnceLock};
    static CONTEXTS: OnceLock<Mutex<HashMap<String, Pkcs11>>> = OnceLock::new();
    let contexts = CONTEXTS.get_or_init(|| Mutex::new(HashMap::new()));
    let mut contexts = contexts.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(existing) = contexts.get(module_path) {
        return Ok(existing.clone());
    }
    let pkcs11 = Pkcs11::new(module_path)?;
    pkcs11.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))?;
    contexts.insert(module_path.to_string(), pkcs11.clone());
    Ok(pkcs11)
}

#[cfg(feature = "pkcs11")]
impl Pkcs11Token {
    pub fn open(o: &Options) -> Result<Self, HsmError> {
        let pkcs11 = shared_context(&o.module_path).map_err(|source| HsmError::Open {
            module_path: o.module_path.clone(),
            token_label: o.token_label.clone(),
            source,
        })?;

        let session = Self::connect(&pkcs11, &o.token_label, &o.pin)?;

        Ok(Self {
            session: std::sync::Mutex::new(session),
            pkcs11,
            token_label: o.token_label.clone(),
            pin: zeroize::Zeroizing::new(o.pin.clone()),
            key_id: key_id(&o.key_label),
            key_label: o.key_label.clone(),
            provenance_verified: std::sync::atomic::AtomicBool::new(false),
            public_key: std::sync::OnceLock::new(),
        })
    }

    /// Ouvre une session en lecture/écriture sur le token de ce label et y
    /// authentifie l'utilisateur. Le slot est cherché à chaque appel : après
    /// un redémarrage du module, il peut avoir changé de numéro.
    fn connect(pkcs11: &Pkcs11, token_label: &str, pin: &str) -> Result<Session, HsmError> {
        let slot = pkcs11
            .get_slots_with_token()?
            .into_iter()
            .find(|slot| {
                pkcs11
                    .get_token_info(*slot)
                    .map(|info| info.label() == token_label)
                    .unwrap_or(false)
            })
            .ok_or_else(|| HsmError::TokenNotFound(token_label.to_string()))?;
        let session = pkcs11.open_rw_session(slot)?;
        session.login(UserType::User, Some(&AuthPin::from(pin.to_string())))?;
        Ok(session)
    }

    /// Simule la perte de la session (le module déconnecte l'utilisateur) pour
    /// vérifier la reconnexion. Réservé aux tests.
    #[cfg(any(test, feature = "testing"))]
    pub fn lose_session_for_test(&self) {
        let _ = self.session().logout();
    }

    fn session(&self) -> std::sync::MutexGuard<'_, Session> {
        self.session.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Remplace la session perdue par une neuve (constat H-2 : sans cela, une
    /// session PKCS#11 perdue met le service en panne jusqu'au redémarrage
    /// du processus).
    fn reconnect(&self) -> Result<(), HsmError> {
        let fresh = Self::connect(&self.pkcs11, &self.token_label, self.pin.as_str())?;
        *self.session.lock().unwrap_or_else(|e| e.into_inner()) = fresh;
        // La clé est cherchée de nouveau : ses attributs aussi sont revérifiés.
        self.provenance_verified
            .store(false, std::sync::atomic::Ordering::Release);
        Ok(())
    }

    /// Joue `op` ; si le module répond que la session est perdue, se
    /// reconnecte et rejoue **une fois**. Toute autre erreur est rendue telle
    /// quelle, et une seconde panne de session aussi.
    fn retrying<T>(&self, op: impl Fn() -> Result<T, HsmError>) -> Result<T, HsmError> {
        match op() {
            Err(e) if is_session_lost(&e) => {
                self.reconnect()?;
                op()
            }
            other => other,
        }
    }

    /// Lit les attributs de provenance de la clé privée (constat H-1), pour
    /// les journaliser au démarrage. Ne refuse rien : voir
    /// [`Pkcs11Token::verify_key_provenance`].
    pub fn key_provenance(&self) -> Result<KeyProvenance, HsmError> {
        let handle = self.retrying(|| self.find_unique_private_key())?;
        let wanted = [
            AttributeType::Local,
            AttributeType::NeverExtractable,
            AttributeType::AlwaysSensitive,
            AttributeType::Sign,
            AttributeType::Decrypt,
            AttributeType::Unwrap,
            AttributeType::Derive,
        ];
        let mut p = KeyProvenance {
            local: false,
            never_extractable: false,
            always_sensitive: false,
            sign: false,
            decrypt: true,
            unwrap: true,
            derive: true,
        };
        for attribute in self.session().get_attributes(handle, &wanted)? {
            match attribute {
                Attribute::Local(v) => p.local = v,
                Attribute::NeverExtractable(v) => p.never_extractable = v,
                Attribute::AlwaysSensitive(v) => p.always_sensitive = v,
                Attribute::Sign(v) => p.sign = v,
                Attribute::Decrypt(v) => p.decrypt = v,
                Attribute::Unwrap(v) => p.unwrap = v,
                Attribute::Derive(v) => p.derive = v,
                _ => {}
            }
        }
        Ok(p)
    }

    /// Exige la preuve que la clé privée est née dans le module et n'en sort
    /// pas (constat H-1) : `CKA_LOCAL`, `CKA_NEVER_EXTRACTABLE`,
    /// `CKA_ALWAYS_SENSITIVE` et `CKA_SIGN` vrais. Rend ce qu'elle a lu,
    /// `decrypt`/`unwrap`/`derive` compris (voir [`KeyProvenance`]).
    pub fn verify_key_provenance(&self) -> Result<KeyProvenance, HsmError> {
        let p = self.key_provenance()?;
        let fail = |attribute| HsmError::KeyAttribute {
            key_label: self.key_label.clone(),
            attribute,
        };
        if !p.local {
            return Err(fail("CKA_LOCAL"));
        }
        if !p.never_extractable {
            return Err(fail("CKA_NEVER_EXTRACTABLE"));
        }
        if !p.always_sensitive {
            return Err(fail("CKA_ALWAYS_SENSITIVE"));
        }
        if !p.sign {
            return Err(fail("CKA_SIGN"));
        }
        // `decrypt`, `unwrap` et `derive` sont rendus mais pas exigés : les clés
        // générées avant le gabarit restreint du constat H-3 les portent à
        // vrai (défaut du token) et ne doivent pas devenir inutilisables au
        // déploiement ; elles le sont jusqu'à leur renouvellement.
        Ok(p)
    }

    /// La clé privée, après contrôle (une fois par ouverture) de sa provenance.
    fn find_private_key(&self) -> Result<cryptoki::object::ObjectHandle, HsmError> {
        use std::sync::atomic::Ordering;
        if !self.provenance_verified.load(Ordering::Acquire) {
            self.verify_key_provenance()?;
            self.provenance_verified.store(true, Ordering::Release);
        }
        self.find_unique_private_key()
    }

    /// Le seul objet qui répond au label et au `CKA_ID` : plusieurs → refus
    /// (constat H-1, ambiguïté entre une clé générée et une clé importée).
    fn find_unique_private_key(&self) -> Result<cryptoki::object::ObjectHandle, HsmError> {
        let template = vec![
            Attribute::Class(ObjectClass::PRIVATE_KEY),
            Attribute::Id(self.key_id.clone()),
            Attribute::Label(self.key_label.clone().into_bytes()),
        ];
        let keys = self
            .session()
            .find_objects(&template)
            .map_err(|source| HsmError::FindKey {
                key_label: self.key_label.clone(),
                source,
            })?;
        match keys.len() {
            0 => Err(HsmError::KeyNotFound),
            1 => Ok(keys[0]),
            n => Err(HsmError::KeyAmbiguous(n, self.key_label.clone())),
        }
    }

    /// Génère une bi-clé RSA dans le token (équivalent de `Token.GenerateRSAKey`).
    pub fn generate_rsa_key(&self, bits: u64) -> Result<(), HsmError> {
        let public_exponent: Vec<u8> = vec![0x01, 0x00, 0x01]; // 65537
        let pub_template = vec![
            Attribute::Token(true),
            Attribute::Private(false),
            Attribute::Verify(true),
            Attribute::ModulusBits(bits.into()),
            Attribute::PublicExponent(public_exponent),
            Attribute::Id(self.key_id.clone()),
            Attribute::Label(self.key_label.clone().into_bytes()),
        ];
        let priv_template = vec![
            Attribute::Token(true),
            Attribute::Private(true),
            Attribute::Sensitive(true),
            Attribute::Extractable(false),
            Attribute::Sign(true),
            // Constat H-3 : une clé de signature n'est restreinte à la
            // signature que par construction, pas par le comportement par
            // défaut du token.
            Attribute::Decrypt(false),
            Attribute::Unwrap(false),
            Attribute::Derive(false),
            Attribute::Modifiable(false),
            Attribute::Id(self.key_id.clone()),
            Attribute::Label(self.key_label.clone().into_bytes()),
        ];
        self.session()
            .generate_key_pair(&Mechanism::RsaPkcsKeyPairGen, &pub_template, &priv_template)
            .map_err(|source| HsmError::GenerateKey { bits, source })?;
        Ok(())
    }

    /// Lit le module et l'exposant public de la bi-clé (RSA) sur le token.
    /// Utilisé pour vérifier après coup qu'une signature produite par
    /// [`SigningToken::sign_digest`] correspond bien à la clé publiée, sans
    /// jamais accéder à la clé privée.
    pub fn rsa_public_components(&self) -> Result<(Vec<u8>, Vec<u8>), HsmError> {
        let template = vec![
            Attribute::Class(ObjectClass::PUBLIC_KEY),
            Attribute::Id(self.key_id.clone()),
            Attribute::Label(self.key_label.clone().into_bytes()),
        ];
        let keys = self
            .session()
            .find_objects(&template)
            .map_err(|source| HsmError::FindKey {
                key_label: self.key_label.clone(),
                source,
            })?;
        let key = keys.into_iter().next().ok_or(HsmError::KeyNotFound)?;

        let attrs = self.session().get_attributes(
            key,
            &[
                cryptoki::object::AttributeType::Modulus,
                cryptoki::object::AttributeType::PublicExponent,
            ],
        )?;
        let mut modulus = None;
        let mut exponent = None;
        for attr in attrs {
            match attr {
                Attribute::Modulus(v) => modulus = Some(v),
                Attribute::PublicExponent(v) => exponent = Some(v),
                _ => {}
            }
        }
        Ok((
            modulus.ok_or(HsmError::KeyNotFound)?,
            exponent.ok_or(HsmError::KeyNotFound)?,
        ))
    }
}

#[cfg(feature = "pkcs11")]
impl Pkcs11Token {
    /// Une tentative de signature, sur la session courante.
    fn sign_once(
        &self,
        scheme: Scheme,
        alg: DigestAlg,
        digest: &[u8],
    ) -> Result<Vec<u8>, HsmError> {
        let key = self.find_private_key()?;
        let signature = match scheme {
            Scheme::Pkcs1v15 => {
                let digest_info = alg.wrap(digest)?;
                self.session()
                    .sign(&Mechanism::RsaPkcs, key, &digest_info)?
            }
            Scheme::Pss => {
                if digest.len() != alg.expected_len() {
                    return Err(HsmError::DigestLength {
                        alg,
                        expected: alg.expected_len(),
                        actual: digest.len(),
                    });
                }
                // CKM_RSA_PKCS_PSS signe un condensé déjà calculé : même
                // condensé pour le calcul, pour MGF1, sel de sa longueur.
                use cryptoki::mechanism::rsa::{PkcsMgfType, PkcsPssParams};
                use cryptoki::mechanism::MechanismType;
                let (hash_alg, mgf) = match alg {
                    DigestAlg::Sha256 => (MechanismType::SHA256, PkcsMgfType::MGF1_SHA256),
                    DigestAlg::Sha384 => (MechanismType::SHA384, PkcsMgfType::MGF1_SHA384),
                    DigestAlg::Sha512 => (MechanismType::SHA512, PkcsMgfType::MGF1_SHA512),
                };
                let params = PkcsPssParams {
                    hash_alg,
                    mgf,
                    s_len: (alg.expected_len() as u64).into(),
                };
                self.session()
                    .sign(&Mechanism::RsaPkcsPss(params), key, digest)?
            }
        };
        // Constat H-2 : jamais de signature qui ne se vérifie pas avec la clé
        // publique du token.
        if self.public_key.get().is_none() {
            let (modulus, exponent) = self.rsa_public_components()?;
            let public_key = rsa::RsaPublicKey::new(
                rsa::BigUint::from_bytes_be(&modulus),
                rsa::BigUint::from_bytes_be(&exponent),
            )
            .map_err(HsmError::SoftwareSign)?;
            let _ = self.public_key.set(public_key);
        }
        let public_key = self
            .public_key
            .get()
            .expect("clé publique tout juste posée");
        verify_signature_with(public_key, scheme, alg, digest, &signature)?;
        Ok(signature)
    }
}

#[cfg(feature = "pkcs11")]
impl SigningToken for Pkcs11Token {
    /// Signe, et se reconnecte une fois si le module a perdu la session
    /// (constat H-2).
    fn sign_digest(&self, alg: DigestAlg, digest: &[u8]) -> Result<Vec<u8>, HsmError> {
        self.sign_digest_with(Scheme::Pkcs1v15, alg, digest)
    }

    fn sign_digest_with(
        &self,
        scheme: Scheme,
        alg: DigestAlg,
        digest: &[u8],
    ) -> Result<Vec<u8>, HsmError> {
        self.retrying(|| self.sign_once(scheme, alg, digest))
    }

    fn public_key_der(&self) -> Result<Vec<u8>, HsmError> {
        let (modulus, exponent) = self.retrying(|| self.rsa_public_components())?;
        let public_key = rsa::RsaPublicKey::new(
            rsa::BigUint::from_bytes_be(&modulus),
            rsa::BigUint::from_bytes_be(&exponent),
        )
        .map_err(HsmError::SoftwareSign)?;
        use rsa::pkcs8::EncodePublicKey;
        public_key
            .to_public_key_der()
            .map(|doc| doc.as_bytes().to_vec())
            .map_err(HsmError::PublicKeyEncoding)
    }
}

/// Rend n'importe quel [`SigningToken`] utilisable depuis plusieurs threads
/// à la fois (`Sync`), en sérialisant les appels derrière un verrou.
/// Nécessaire pour `Pkcs11Token` : une session `cryptoki` est `Send` mais
/// pas `Sync` (un seul appel PKCS#11 à la fois par session), ce qui
/// empêcherait de la partager entre les gestionnaires concurrents d'un
/// serveur HTTP (jalon J7) sans ce wrapper.
pub struct SyncToken<T>(std::sync::Mutex<T>);

impl<T> SyncToken<T> {
    pub fn new(inner: T) -> Self {
        Self(std::sync::Mutex::new(inner))
    }
}

impl<T: SigningToken> SigningToken for SyncToken<T> {
    fn sign_digest(&self, alg: DigestAlg, digest: &[u8]) -> Result<Vec<u8>, HsmError> {
        self.0
            .lock()
            .expect("verrou de token empoisonné")
            .sign_digest(alg, digest)
    }

    fn sign_digest_with(
        &self,
        scheme: Scheme,
        alg: DigestAlg,
        digest: &[u8],
    ) -> Result<Vec<u8>, HsmError> {
        self.0
            .lock()
            .expect("verrou de token empoisonné")
            .sign_digest_with(scheme, alg, digest)
    }

    fn public_key_der(&self) -> Result<Vec<u8>, HsmError> {
        self.0
            .lock()
            .expect("verrou de token empoisonné")
            .public_key_der()
    }
}

/// Implémentation logicielle de [`SigningToken`], utilisée par les tests de
/// `oe-hsm` et des crates qui en dépendent (`oe-tsa-core`, notamment) pour
/// vérifier la logique métier sans matériel PKCS#11 réel. Ne doit jamais être
/// utilisée en production : la clé privée vit en mémoire du processus.
#[cfg(any(test, feature = "testing"))]
pub mod testing {
    use super::{DigestAlg, HsmError, Scheme, SigningToken};
    use rsa::pkcs1v15::Pkcs1v15Sign;
    use rsa::{RsaPrivateKey, RsaPublicKey};
    use sha2::{Sha256, Sha384, Sha512};

    pub struct SoftwareToken {
        key: RsaPrivateKey,
    }

    impl SoftwareToken {
        /// Génère une bi-clé RSA de test (jamais persistée).
        pub fn generate(bits: usize) -> Self {
            let mut rng = rand::thread_rng();
            let key = RsaPrivateKey::new(&mut rng, bits).expect("génération de clé RSA de test");
            Self { key }
        }

        pub fn public_key(&self) -> RsaPublicKey {
            RsaPublicKey::from(&self.key)
        }

        /// Charge une clé de test existante (PEM PKCS#8), pour les tests qui
        /// doivent faire correspondre la clé à un certificat déjà émis.
        pub fn from_pkcs8_pem(pem: &str) -> Result<Self, rsa::pkcs8::Error> {
            use rsa::pkcs8::DecodePrivateKey;
            Ok(Self {
                key: RsaPrivateKey::from_pkcs8_pem(pem)?,
            })
        }
    }

    impl SigningToken for SoftwareToken {
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
            let mut rng = rand::thread_rng();
            let salt = alg.expected_len();
            let signature = match alg {
                DigestAlg::Sha256 => self.key.sign_with_rng(
                    &mut rng,
                    rsa::pss::Pss::new_with_salt::<Sha256>(salt),
                    digest,
                ),
                DigestAlg::Sha384 => self.key.sign_with_rng(
                    &mut rng,
                    rsa::pss::Pss::new_with_salt::<Sha384>(salt),
                    digest,
                ),
                DigestAlg::Sha512 => self.key.sign_with_rng(
                    &mut rng,
                    rsa::pss::Pss::new_with_salt::<Sha512>(salt),
                    digest,
                ),
            };
            signature.map_err(HsmError::SoftwareSign)
        }

        fn sign_digest(&self, alg: DigestAlg, digest: &[u8]) -> Result<Vec<u8>, HsmError> {
            if digest.len() != alg.expected_len() {
                return Err(HsmError::DigestLength {
                    alg,
                    expected: alg.expected_len(),
                    actual: digest.len(),
                });
            }
            let signature = match alg {
                DigestAlg::Sha256 => self.key.sign(Pkcs1v15Sign::new::<Sha256>(), digest),
                DigestAlg::Sha384 => self.key.sign(Pkcs1v15Sign::new::<Sha384>(), digest),
                DigestAlg::Sha512 => self.key.sign(Pkcs1v15Sign::new::<Sha512>(), digest),
            };
            signature.map_err(HsmError::SoftwareSign)
        }

        fn public_key_der(&self) -> Result<Vec<u8>, HsmError> {
            use rsa::pkcs8::EncodePublicKey;
            self.public_key()
                .to_public_key_der()
                .map(|doc| doc.as_bytes().to_vec())
                .map_err(HsmError::PublicKeyEncoding)
        }
    }
}

#[cfg(all(test, feature = "pkcs11"))]
mod tests {
    use super::*;

    /// Constat H-2 : `verify_signature` accepte une signature correcte et
    /// refuse une signature altérée, un autre condensé ou une autre clé.
    #[test]
    fn verify_signature_accepts_only_a_genuine_signature() {
        use crate::testing::SoftwareToken;
        let token = SoftwareToken::generate(1024);
        let other = SoftwareToken::generate(1024);
        let digest = Sha256::digest(b"message");
        let signature = token.sign_digest(DigestAlg::Sha256, &digest).unwrap();
        let public = token.public_key();
        verify_signature(&public, DigestAlg::Sha256, &digest, &signature).unwrap();

        let mut faulty = signature.clone();
        faulty[10] ^= 0x01;
        assert!(matches!(
            verify_signature(&public, DigestAlg::Sha256, &digest, &faulty),
            Err(HsmError::SignatureVerification)
        ));
        let other_digest = Sha256::digest(b"autre");
        assert!(verify_signature(&public, DigestAlg::Sha256, &other_digest, &signature).is_err());
        assert!(
            verify_signature(&other.public_key(), DigestAlg::Sha256, &digest, &signature).is_err()
        );
    }

    /// Constat H-3 : le PIN que le token garde pour rouvrir sa session est
    /// effacé de la mémoire à son abandon. Garde de type : si le champ cessait
    /// d'être `Zeroizing`, ceci ne compilerait plus.
    #[cfg(feature = "pkcs11")]
    #[allow(dead_code)]
    fn the_stored_pin_is_zeroizing(t: &Pkcs11Token) -> &zeroize::Zeroizing<String> {
        &t.pin
    }

    #[test]
    fn the_scheme_names_are_parsed_and_unknown_ones_refused() {
        assert_eq!("pss".parse::<Scheme>().unwrap(), Scheme::Pss);
        assert_eq!(" PSS ".parse::<Scheme>().unwrap(), Scheme::Pss);
        assert_eq!("pkcs1v15".parse::<Scheme>().unwrap(), Scheme::Pkcs1v15);
        assert!("sha1".parse::<Scheme>().is_err());
        assert!("".parse::<Scheme>().is_err());
    }

    /// RSASSA-PSS : signature logicielle et vérification d'accord, pour les
    /// trois condensés ; une signature PSS n'est pas une signature PKCS#1 v1.5
    /// et inversement.
    #[test]
    fn pss_signatures_verify_as_pss_only() {
        use crate::testing::SoftwareToken;
        let token = SoftwareToken::generate(2048);
        let public = token.public_key();
        for (alg, digest) in [
            (DigestAlg::Sha256, Sha256::digest(b"m").to_vec()),
            (DigestAlg::Sha384, sha2::Sha384::digest(b"m").to_vec()),
            (DigestAlg::Sha512, sha2::Sha512::digest(b"m").to_vec()),
        ] {
            let pss = token.sign_digest_with(Scheme::Pss, alg, &digest).unwrap();
            let v15 = token
                .sign_digest_with(Scheme::Pkcs1v15, alg, &digest)
                .unwrap();
            verify_signature_with(&public, Scheme::Pss, alg, &digest, &pss).unwrap();
            verify_signature_with(&public, Scheme::Pkcs1v15, alg, &digest, &v15).unwrap();
            assert!(verify_signature_with(&public, Scheme::Pkcs1v15, alg, &digest, &pss).is_err());
            assert!(verify_signature_with(&public, Scheme::Pss, alg, &digest, &v15).is_err());
            // PSS est probabiliste : deux signatures du même condensé diffèrent.
            let again = token.sign_digest_with(Scheme::Pss, alg, &digest).unwrap();
            assert_ne!(pss, again);
        }
        // Un condensé de la mauvaise longueur est refusé avant toute signature.
        assert!(matches!(
            token.sign_digest_with(Scheme::Pss, DigestAlg::Sha256, &[0u8; 16]),
            Err(HsmError::DigestLength { .. })
        ));
    }

    /// L'`AlgorithmIdentifier` RSASSA-PSS est celui que produit openssl
    /// (`req -sigopt rsa_padding_mode:pss`), octet pour octet ; PKCS#1 v1.5
    /// porte des paramètres NULL.
    #[test]
    fn signature_algorithm_matches_the_openssl_encoding() {
        use der::Encode;
        let pss = signature_algorithm(Scheme::Pss, DigestAlg::Sha256).unwrap();
        // Relevé d'un certificat émis par openssl 3 en RSASSA-PSS/SHA-256, sel 32.
        let reference = hex::decode(
            "304106092a864886f70d01010a3034a00f300d06096086480165030402010500\
             a11c301a06092a864886f70d010108300d06096086480165030402010500a203020120",
        )
        .unwrap();
        assert_eq!(pss.to_der().unwrap(), reference);
        let v15 = signature_algorithm(Scheme::Pkcs1v15, DigestAlg::Sha256).unwrap();
        assert_eq!(v15.oid.to_string(), "1.2.840.113549.1.1.11");
        assert_eq!(v15.parameters, Some(der::Any::from(der::asn1::Null)));
        // Les trois condensés ont chacun leur identifiant PSS, distinct.
        let ids: Vec<_> = [DigestAlg::Sha256, DigestAlg::Sha384, DigestAlg::Sha512]
            .iter()
            .map(|a| {
                signature_algorithm(Scheme::Pss, *a)
                    .unwrap()
                    .to_der()
                    .unwrap()
            })
            .collect();
        assert!(ids[0] != ids[1] && ids[1] != ids[2] && ids[0] != ids[2]);
    }

    #[test]
    fn digest_info_prefix_rejects_wrong_length() {
        let err = DigestAlg::Sha256.wrap(&[0u8; 16]).unwrap_err();
        assert!(matches!(err, HsmError::DigestLength { .. }));
    }

    #[test]
    fn digest_info_wraps_expected_length() {
        let digest = [0x42u8; 32];
        let wrapped = DigestAlg::Sha256.wrap(&digest).unwrap();
        assert_eq!(wrapped.len(), 19 + 32);
        assert_eq!(&wrapped[19..], &digest[..]);
    }

    #[test]
    fn key_id_is_stable_for_same_label() {
        assert_eq!(key_id("tsu-signing-key"), key_id("tsu-signing-key"));
        assert_ne!(key_id("tsu-signing-key"), key_id("other-key"));
        assert_eq!(key_id("tsu-signing-key").len(), 8);
    }
}
