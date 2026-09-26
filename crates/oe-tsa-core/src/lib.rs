//! Portage de `internal/tsa` : le cœur métier de l'horodatage RFC 3161.
//! Jalon décisif J6 du plan de migration
//! (`/home/philippe/.claude/plans/witty-hopping-nest.md`) — assemble
//! `oe-rfc3161-asn1` (J1), `oe-hsm` (J2) et une politique de temps injectée
//! (`Clock`, équivalent du moniteur `oe-timesource`, jalon J4) pour produire
//! et signer un jeton d'horodatage réel.
//!
//! **Écart assumé face à `internal/conformance`** : la vérification du
//! profil du certificat TSU (`conformance.CheckTSUCertificate`, EN 319 421
//! §7.7.2) n'est pas encore portée (`oe-conformance` la déclare `Gap`,
//! jalon J3) — `Authority::new` ne la reproduit donc pas encore. Ce qui est
//! bien vérifié ici : la correspondance clé publique du token ↔ certificat,
//! et la fenêtre de validité temporelle du certificat, comme dans `tsa.New`
//! (Go).

use std::sync::Arc;

use der::asn1::{GeneralizedTime, Int, ObjectIdentifier};
use der::{Decode, Encode};
use sha2::{Digest, Sha256, Sha384, Sha512};
use spki::AlgorithmIdentifierOwned;
use x509_cert::Certificate;

use oe_hsm::{DigestAlg, SigningToken};
use oe_rfc3161_asn1::token::{self, TokenParts};
use oe_rfc3161_asn1::{Accuracy, MessageImprint, TimeStampReq, TimeStampResp, TstInfo};

/// Fournit l'heure à estampiller. Une erreur signifie que l'heure n'est pas
/// rattachable à UTC dans les limites annoncées : la TSA doit alors refuser
/// de signer plutôt que de produire un jeton non fiable. Équivalent de
/// `tsa.Clock` (Go) — délibérément découplé d'`oe-timesource`, à l'identique
/// du code Go de référence (`cmd/tsa-server` branche `timesource.Monitor`
/// dessus, `internal/tsa` ne le connaît pas).
pub trait Clock: Send + Sync {
    fn now(&self) -> Result<time::OffsetDateTime, String>;
}

/// Consigne les décisions de l'autorité dans le journal d'audit.
///
/// Reste synchrone, comme `oe_timesource::Recorder` et pour la même raison
/// (docs/WEBUI.md §15 étape 2b) : `Authority::timestamp` est déjà entièrement
/// synchrone (la signature HSM l'est), appelée directement depuis un
/// gestionnaire HTTP async sans `spawn_blocking` — un futur dos S3 y ferait un
/// appel HTTP bloquant, sans changer ce qui bloque déjà le thread. Son échec
/// est **bloquant** : `Authority::record` le propage, et chaque appelant
/// journalise avant la signature elle-même, l'acte irréversible.
pub trait Recorder: Send + Sync {
    fn append(&self, event: &str, data: serde_json::Value) -> Result<(), String>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureInfo {
    BadAlg,
    BadRequest,
    BadDataFormat,
    TimeNotAvailable,
    UnacceptedPolicy,
    UnacceptedExtension,
    SystemFailure,
}

/// Un refus protocolaire RFC 3161 : converti par la couche HTTP (jalon J7)
/// en une `TimeStampResp` de statut « rejection », qui reste une réponse
/// valide — jamais une erreur de transport.
#[derive(Debug, Clone)]
pub struct Rejection {
    pub failure: FailureInfo,
    pub reason: String,
}

impl std::fmt::Display for Rejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}: {}", self.failure, self.reason)
    }
}
impl std::error::Error for Rejection {}

#[derive(Debug, thiserror::Error)]
pub enum TsaError {
    #[error("tsa: {0}")]
    Rejection(#[from] Rejection),
    #[error("tsa: {0}")]
    Der(#[from] der::Error),
    #[error("tsa: {0}")]
    Token(#[from] token::TokenError),
    #[error("tsa: signature: {0}")]
    Signing(#[from] oe_hsm::HsmError),
    #[error("tsa: {0}")]
    Other(String),
}

fn reject(failure: FailureInfo, reason: impl Into<String>) -> TsaError {
    TsaError::Rejection(Rejection {
        failure,
        reason: reason.into(),
    })
}

pub struct Options {
    pub signer: Arc<dyn SigningToken + Send + Sync>,
    pub certificate: Certificate,
    pub chain: Vec<Certificate>,
    pub policy: ObjectIdentifier,
    pub accuracy: std::time::Duration,
    pub signing_digest: DigestAlg,
    pub clock: Arc<dyn Clock>,
    pub recorder: Option<Arc<dyn Recorder>>,
}

pub struct Authority {
    opts: Options,
}

impl Authority {
    /// Valide la cohérence du matériel cryptographique et construit
    /// l'autorité : la clé du token doit correspondre au certificat publié,
    /// et le certificat doit être temporellement valide (heure système, la
    /// surveillance n'a pas encore de mesure à ce stade).
    pub fn new(opts: Options) -> Result<Authority, String> {
        let cert_spki = opts
            .certificate
            .tbs_certificate()
            .subject_public_key_info()
            .to_der()
            .map_err(|e| format!("tsa: clé publique du certificat illisible: {e}"))?;
        let signer_spki = opts
            .signer
            .public_key_der()
            .map_err(|e| format!("tsa: clé publique du token illisible: {e}"))?;
        if cert_spki != signer_spki {
            return Err("tsa: la clé du token ne correspond pas au certificat TSU".to_string());
        }

        let now = time::OffsetDateTime::now_utc();
        let not_before = x509_time_to_offset_date_time(
            &opts.certificate.tbs_certificate().validity().not_before,
        );
        let not_after =
            x509_time_to_offset_date_time(&opts.certificate.tbs_certificate().validity().not_after);
        if now > not_after {
            return Err(format!("tsa: certificat TSU expiré depuis le {not_after}"));
        }
        if now < not_before {
            return Err(format!(
                "tsa: certificat TSU pas encore valide (à partir du {not_before})"
            ));
        }

        // Un certificat chargé depuis le disque peut venir d'ailleurs que de
        // cette PKI : le re-contrôler au démarrage, pas seulement lui faire
        // confiance parce qu'il a été émis un jour — reproduit
        // `CheckTSUCertificate` appelée par `cmd/tsa-server` (Go).
        oe_conformance::check_tsu_certificate("certificat TSU", &opts.certificate)?;

        Ok(Authority { opts })
    }

    pub fn certificate(&self) -> &Certificate {
        &self.opts.certificate
    }

    pub fn chain(&self) -> &[Certificate] {
        &self.opts.chain
    }

    pub fn policy(&self) -> ObjectIdentifier {
        self.opts.policy
    }

    pub fn accuracy(&self) -> std::time::Duration {
        self.opts.accuracy
    }

    /// Algorithmes de hachage admis pour l'empreinte soumise par le client
    /// (`messageImprint`) — indépendant de `signing_digest`, qui régit la
    /// signature de la TSA elle-même. Reproduit `conformance.AdmittedHashes`
    /// (Go) ; voir la note de module sur l'écart face à `internal/conformance`.
    pub fn accepted_hashes() -> &'static [DigestAlg] {
        &[DigestAlg::Sha256, DigestAlg::Sha384, DigestAlg::Sha512]
    }

    /// Consomme une `TimeStampReq` DER et retourne une `TimeStampResp` DER
    /// de statut « granted ». Un refus protocolaire est signalé par
    /// [`TsaError::Rejection`].
    pub fn timestamp(&self, req_der: &[u8]) -> Result<Vec<u8>, TsaError> {
        match self.timestamp_inner(req_der) {
            Ok(resp) => Ok(resp),
            Err(TsaError::Rejection(rejection)) => {
                // Rien d'irréversible ne dépend de ce journal (la requête est
                // déjà rejetée) : mais si lui-même échoue, c'est cette
                // raison-là qui prime (§15 étape 2b).
                self.record(
                    "timestamp.rejected",
                    serde_json::json!({"failure": format!("{:?}", rejection.failure), "reason": rejection.reason}),
                )?;
                Err(TsaError::Rejection(rejection))
            }
            Err(e) => Err(e),
        }
    }

    fn timestamp_inner(&self, req_der: &[u8]) -> Result<Vec<u8>, TsaError> {
        let req = TimeStampReq::from_der(req_der).map_err(|e| {
            reject(
                FailureInfo::BadDataFormat,
                format!("requête RFC 3161 illisible: {e}"),
            )
        })?;

        let expected_len =
            admitted_hash_len(&req.message_imprint.hash_algorithm.oid).ok_or_else(|| {
                reject(
                    FailureInfo::BadAlg,
                    "algorithme d'empreinte refusé par la politique",
                )
            })?;
        if req.message_imprint.hashed_message.as_bytes().len() != expected_len {
            return Err(reject(
                FailureInfo::BadDataFormat,
                "longueur d'empreinte incohérente avec l'algorithme annoncé",
            ));
        }
        if let Some(req_policy) = &req.req_policy {
            if *req_policy != self.opts.policy {
                return Err(reject(
                    FailureInfo::UnacceptedPolicy,
                    format!("politique demandée {req_policy} non servie par cette TSA"),
                ));
            }
        }
        if let Some(extensions) = &req.extensions {
            for ext in extensions.iter() {
                if ext.critical {
                    return Err(reject(
                        FailureInfo::UnacceptedExtension,
                        format!("extension critique non supportée: {}", ext.extn_id),
                    ));
                }
            }
        }

        let gen_time = self.opts.clock.now().map_err(|e| {
            reject(
                FailureInfo::TimeNotAvailable,
                format!("source de temps indisponible: {e}"),
            )
        })?;

        let tst_info = self.build_tst_info(&req, gen_time)?;
        let tst_info_der = tst_info.to_der()?;

        let cert_der = self.opts.certificate.to_der()?;
        let sign_alg_oid = digest_algorithm_identifier(self.opts.signing_digest);
        let tst_info_digest = hash_with(self.opts.signing_digest, &tst_info_der);
        let signing_cert_digest = hash_with(self.opts.signing_digest, &cert_der);

        let mut certs_der: Vec<Vec<u8>> = vec![cert_der];
        for c in &self.opts.chain {
            certs_der.push(c.to_der()?);
        }

        let parts = TokenParts {
            tst_info_der: &tst_info_der,
            tst_info_digest: &tst_info_digest,
            signing_cert_digest: &signing_cert_digest,
            digest_alg: sign_alg_oid,
            issuer: self.opts.certificate.tbs_certificate().issuer().clone(),
            serial_number: self
                .opts
                .certificate
                .tbs_certificate()
                .serial_number()
                .clone(),
            certs_der: &certs_der,
            include_certs: req.cert_req,
        };

        let signed_attrs = token::signed_attrs_der(&parts)?;
        let digest_to_sign = hash_with(self.opts.signing_digest, &signed_attrs);

        // Le journal *avant* la signature (§15 étape 2b) : l'acte
        // irréversible est la signature elle-même (la clé de la TSA ne
        // signe jamais deux fois la même chose, et rien n'annule une
        // signature déjà produite). Si le journal échoue, aucun jeton n'est
        // signé.
        //
        // `serial_number` est celui du **jeton** (`tst_info.serial_number`,
        // tiré à chaque appel), jamais celui, constant, du certificat de la
        // TSU : c'est ce qui permet, après incident, d'identifier quels
        // jetons ont été émis (EN 319 421 `OVR-7.13-05`, constat J-3 de
        // l'audit du 2026-09-25). `message_imprint` et `gen_time` (avec sa
        // fraction) viennent du jeton réellement construit, pas d'une valeur
        // reconstruite après coup.
        self.record(
            "timestamp.granted",
            serde_json::json!({
                "serial_number": bytes_to_hex(tst_info.serial_number.as_bytes()),
                "gen_time": gen_time
                    .format(&time::format_description::well_known::Rfc3339)
                    .unwrap_or_else(|_| gen_time.to_string()),
                "policy": self.opts.policy.to_string(),
                "nonce": req.nonce.is_some(),
                "message_imprint_alg": req.message_imprint.hash_algorithm.oid.to_string(),
                "message_imprint": bytes_to_hex(req.message_imprint.hashed_message.as_bytes()),
                "tsu_certificate_fingerprint": bytes_to_hex(&signing_cert_digest),
            }),
        )?;

        let signature = self
            .opts
            .signer
            .sign_digest(self.opts.signing_digest, &digest_to_sign)?;

        let token_der = token::assemble(&parts, &signed_attrs, signature)?;
        let resp = token::granted_response(token_der)?;
        let resp_der = resp.to_der()?;
        Ok(resp_der)
    }

    fn build_tst_info(
        &self,
        req: &TimeStampReq,
        gen_time: time::OffsetDateTime,
    ) -> Result<TstInfo, TsaError> {
        let serial = random_serial_number();
        Ok(TstInfo {
            version: 1,
            policy: self.opts.policy,
            message_imprint: MessageImprint {
                hash_algorithm: req.message_imprint.hash_algorithm.clone(),
                hashed_message: req.message_imprint.hashed_message.clone(),
            },
            serial_number: Int::new(&serial)?,
            gen_time: GeneralizedTime::from_date_time(der::DateTime::new(
                gen_time.year() as u16,
                gen_time.month() as u8,
                gen_time.day(),
                gen_time.hour(),
                gen_time.minute(),
                gen_time.second(),
            )?),
            accuracy: build_accuracy(self.opts.accuracy)?,
            ordering: false,
            nonce: req.nonce.clone(),
            tsa: None,
            extensions: None,
        })
    }

    fn record(&self, event: &str, data: serde_json::Value) -> Result<(), TsaError> {
        if let Some(recorder) = &self.opts.recorder {
            recorder
                .append(event, data)
                .map_err(|e| TsaError::Other(format!("journal : {e}")))?;
        }
        Ok(())
    }
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn x509_time_to_offset_date_time(t: &x509_cert::time::Time) -> time::OffsetDateTime {
    let dt = t.to_date_time();
    time::OffsetDateTime::from_unix_timestamp(dt.unix_duration().as_secs() as i64)
        .unwrap_or(time::OffsetDateTime::UNIX_EPOCH)
}

const OID_SHA256: &str = "2.16.840.1.101.3.4.2.1";
const OID_SHA384: &str = "2.16.840.1.101.3.4.2.2";
const OID_SHA512: &str = "2.16.840.1.101.3.4.2.3";

fn admitted_hash_len(oid: &ObjectIdentifier) -> Option<usize> {
    let s = oid.to_string();
    match s.as_str() {
        OID_SHA256 => Some(32),
        OID_SHA384 => Some(48),
        OID_SHA512 => Some(64),
        _ => None,
    }
}

fn hash_with(alg: DigestAlg, data: &[u8]) -> Vec<u8> {
    match alg {
        DigestAlg::Sha256 => Sha256::digest(data).to_vec(),
        DigestAlg::Sha384 => Sha384::digest(data).to_vec(),
        DigestAlg::Sha512 => Sha512::digest(data).to_vec(),
    }
}

fn digest_algorithm_identifier(alg: DigestAlg) -> AlgorithmIdentifierOwned {
    let oid_str = match alg {
        DigestAlg::Sha256 => OID_SHA256,
        DigestAlg::Sha384 => OID_SHA384,
        DigestAlg::Sha512 => OID_SHA512,
    };
    AlgorithmIdentifierOwned {
        oid: ObjectIdentifier::new(oid_str).expect("OID constant invalide"),
        parameters: None,
    }
}

/// 20 octets aléatoires réinterprétés comme un entier positif — reproduit
/// `generateTSASerialNumber` (Go, `digitorus/timestamp`).
fn random_serial_number() -> Vec<u8> {
    use rand::RngCore;
    let mut bytes = [0u8; 20];
    rand::thread_rng().fill_bytes(&mut bytes);
    minimal_positive_integer(&bytes)
}

/// Les octets de contenu d'un `INTEGER` DER **minimal** et positif pour cet
/// entier big-endian (X.690 §8.3.2) : aucun octet de tête superflu, et un `0x00`
/// devant seulement si le bit de poids fort est posé (sinon le nombre serait lu
/// négatif).
///
/// Le bug corrigé ici : le tirage de 20 octets commençait parfois par `0x00`
/// (1 fois sur 256), suivi d'un octet `< 0x80` (1 fois sur 2). Ce `0x00` était
/// gardé tel quel, l'`INTEGER` n'était plus minimal, et un vérificateur strict
/// (OpenSSL : « illegal padding », champ `serial`) rejetait le jeton, soit environ
/// **un jeton d'horodatage sur 512**.
fn minimal_positive_integer(bytes: &[u8; 20]) -> Vec<u8> {
    // Retire les zéros de tête ; s'il n'en reste rien, le nombre est 0, ce qui n'est
    // pas un numéro de série admissible : on prend 1. (Probabilité : 2⁻¹⁶⁰.)
    let significant = match bytes.iter().position(|b| *b != 0) {
        Some(i) => &bytes[i..],
        None => &[1u8][..],
    };
    let mut out = Vec::with_capacity(significant.len() + 1);
    if significant[0] & 0x80 != 0 {
        out.push(0);
    }
    out.extend_from_slice(significant);
    out
}

/// Convertit une durée en `Accuracy` (secondes/millis/micros), en reproduisant
/// la troncature successive de `populateTSTInfo` (Go).
fn build_accuracy(d: std::time::Duration) -> Result<Option<Accuracy>, der::Error> {
    if d.is_zero() {
        return Ok(None);
    }
    let total_micros = d.as_micros();
    if total_micros == 0 {
        // Moins d'une microseconde : arrondi à 1µs, comme le code Go.
        return Ok(Some(Accuracy {
            seconds: None,
            millis: None,
            micros: Some(1),
        }));
    }
    let seconds = total_micros / 1_000_000;
    let rem_micros = total_micros % 1_000_000;
    let millis = rem_micros / 1_000;
    let micros = rem_micros % 1_000;

    Ok(Some(Accuracy {
        seconds: if seconds > 0 {
            Some(minimal_positive_int(seconds as u64)?)
        } else {
            None
        },
        millis: if millis > 0 {
            Some(millis as u16)
        } else {
            None
        },
        micros: if micros > 0 {
            Some(micros as u16)
        } else {
            None
        },
    }))
}

/// Encode `v` comme `INTEGER` DER minimal et positif : `Int::new` n'élague
/// que les octets `0xFF` de tête (redondants pour un entier signé négatif),
/// pas les octets `0x00` de tête — un `to_be_bytes()` brut y laisse un
/// bourrage illégal en DER (`illegal padding`, détecté par `openssl ts
/// -reply -text` sur le champ `Accuracy.seconds`).
fn minimal_positive_int(v: u64) -> Result<Int, der::Error> {
    let full = v.to_be_bytes();
    let first_nonzero = full.iter().position(|&b| b != 0).unwrap_or(7);
    let mut bytes = full[first_nonzero..].to_vec();
    if bytes[0] & 0x80 != 0 {
        bytes.insert(0, 0);
    }
    Int::new(&bytes)
}

/// Encode une `TimeStampResp` de refus (statut `rejection`), exploitable par
/// un client. Séparé de [`Authority::timestamp`], à l'identique
/// d'`ErrorResponse` (Go) : la couche HTTP (jalon J7) décide quand
/// l'invoquer.
pub fn error_response(failure: FailureInfo) -> Result<Vec<u8>, der::Error> {
    let bit = failure_info_bit(failure);
    let mut bits = vec![0u8; (bit / 8) + 2];
    bits[0] = 7 - (bit % 8) as u8; // nombre de bits inutilisés dans le dernier octet
    bits[1 + bit / 8] = 0x80 >> (bit % 8);
    let resp = TimeStampResp {
        status: oe_rfc3161_asn1::PkiStatusInfo {
            status: Int::new(&[2])?, // PKIStatus rejection(2)
            status_string: None,
            fail_info: Some(der::asn1::BitString::from_bytes(&bits)?),
        },
        time_stamp_token: None,
    };
    resp.to_der()
}

fn failure_info_bit(f: FailureInfo) -> usize {
    match f {
        FailureInfo::BadAlg => 0,
        FailureInfo::BadRequest => 2,
        FailureInfo::BadDataFormat => 5,
        FailureInfo::TimeNotAvailable => 14,
        FailureInfo::UnacceptedPolicy => 15,
        FailureInfo::UnacceptedExtension => 16,
        FailureInfo::SystemFailure => 25,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use der::Decode;
    use oe_hsm::testing::SoftwareToken;
    use std::path::PathBuf;

    fn fixtures_dir() -> PathBuf {
        PathBuf::from(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../tests/fixtures/tsa"
        ))
    }

    fn test_certificate_serial() -> Vec<u8> {
        let dir = fixtures_dir();
        let cert_pem = std::fs::read_to_string(dir.join("tsu-cert.pem")).unwrap();
        let cert_block = pem::parse(cert_pem.as_bytes()).unwrap();
        let certificate = Certificate::from_der(cert_block.contents()).unwrap();
        certificate
            .tbs_certificate()
            .serial_number()
            .as_bytes()
            .to_vec()
    }

    fn corpus_dir() -> PathBuf {
        PathBuf::from(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../tests/fixtures/rfc3161"
        ))
    }

    struct TestClock;
    impl Clock for TestClock {
        fn now(&self) -> Result<time::OffsetDateTime, String> {
            Ok(time::OffsetDateTime::now_utc())
        }
    }

    struct BrokenClock;
    impl Clock for BrokenClock {
        fn now(&self) -> Result<time::OffsetDateTime, String> {
            Err("aucune source de temps jointe".to_string())
        }
    }

    fn new_test_authority(clock: Arc<dyn Clock>) -> Authority {
        new_test_authority_with(clock, None)
    }

    /// Capture les données de chaque événement journalisé, pour les tests qui
    /// vérifient *ce qui* est consigné, pas seulement que l'horodatage réussit.
    #[derive(Default)]
    struct CapturingRecorder {
        events: std::sync::Mutex<Vec<(String, serde_json::Value)>>,
    }

    impl Recorder for CapturingRecorder {
        fn append(&self, event: &str, data: serde_json::Value) -> Result<(), String> {
            self.events.lock().unwrap().push((event.to_string(), data));
            Ok(())
        }
    }

    fn new_test_authority_with(
        clock: Arc<dyn Clock>,
        recorder: Option<Arc<dyn Recorder>>,
    ) -> Authority {
        let dir = fixtures_dir();
        let key_pem = std::fs::read_to_string(dir.join("tsu-key.pem")).unwrap();
        let cert_pem = std::fs::read_to_string(dir.join("tsu-cert.pem")).unwrap();
        let signer = SoftwareToken::from_pkcs8_pem(&key_pem).unwrap();
        let cert_block = pem::parse(cert_pem.as_bytes()).unwrap();
        let certificate = Certificate::from_der(cert_block.contents()).unwrap();

        Authority::new(Options {
            signer: Arc::new(signer),
            certificate,
            chain: Vec::new(),
            policy: ObjectIdentifier::new("1.3.6.1.4.1.99999.1.1.1").unwrap(),
            accuracy: std::time::Duration::from_secs(1),
            signing_digest: DigestAlg::Sha256,
            clock,
            recorder,
        })
        .unwrap()
    }

    /// Constat J-3 de l'audit du 2026-09-25 : le journal doit tracer le
    /// **jeton** émis, pas seulement le certificat de la TSU (constant d'un
    /// appel à l'autre). Deux jetons distincts doivent produire deux séries
    /// distinctes au journal (recommandation explicite de l'audit).
    #[test]
    fn timestamp_granted_journals_the_tokens_own_serial_not_the_certificates() {
        let recorder = Arc::new(CapturingRecorder::default());
        let authority = new_test_authority_with(Arc::new(TestClock), Some(recorder.clone()));
        let req_der = read_corpus_request("granted-sha256-with-cert");

        authority.timestamp(&req_der).expect("horodatage refusé");
        authority.timestamp(&req_der).expect("horodatage refusé");

        let events = recorder.events.lock().unwrap();
        let granted: Vec<_> = events
            .iter()
            .filter(|(e, _)| e == "timestamp.granted")
            .collect();
        assert_eq!(granted.len(), 2, "{events:?}");

        let cert_serial = bytes_to_hex(&test_certificate_serial());
        let mut series = std::collections::HashSet::new();
        for (_, data) in &granted {
            let serial = data["serial_number"].as_str().unwrap();
            assert_ne!(
                serial, cert_serial,
                "la série journalisée est celle du certificat, pas celle du jeton"
            );
            assert!(!data["message_imprint"].as_str().unwrap().is_empty());
            assert!(!data["message_imprint_alg"].as_str().unwrap().is_empty());
            assert!(!data["tsu_certificate_fingerprint"]
                .as_str()
                .unwrap()
                .is_empty());
            series.insert(serial.to_string());
        }
        assert_eq!(
            series.len(),
            2,
            "deux jetons doivent produire deux séries distinctes au journal"
        );
    }

    fn read_corpus_request(case: &str) -> Vec<u8> {
        std::fs::read(corpus_dir().join(case).join("request.der"))
            .unwrap_or_else(|e| panic!("fixture {case}: {e}"))
    }

    #[test]
    fn test_timestamp_granted() {
        let authority = new_test_authority(Arc::new(TestClock));
        let req_der = read_corpus_request("granted-sha256-with-cert");

        let resp_der = authority.timestamp(&req_der).expect("horodatage refusé");
        let resp = TimeStampResp::from_der(&resp_der).expect("réponse illisible");
        assert!(
            resp.time_stamp_token.is_some(),
            "jeton absent d'une réponse accordée"
        );
    }

    #[test]
    fn test_timestamp_rejects_sha1() {
        let authority = new_test_authority(Arc::new(TestClock));
        let req_der = read_corpus_request("rejects-sha1");

        let err = authority.timestamp(&req_der).unwrap_err();
        match err {
            TsaError::Rejection(r) => assert_eq!(r.failure, FailureInfo::BadAlg),
            other => panic!("un refus était attendu, obtenu: {other}"),
        }
    }

    #[test]
    fn test_timestamp_rejects_foreign_policy() {
        let authority = new_test_authority(Arc::new(TestClock));
        let req_der = read_corpus_request("rejects-foreign-policy");

        let err = authority.timestamp(&req_der).unwrap_err();
        match err {
            TsaError::Rejection(r) => assert_eq!(r.failure, FailureInfo::UnacceptedPolicy),
            other => panic!("un refus était attendu, obtenu: {other}"),
        }
    }

    #[test]
    fn test_timestamp_refuses_when_time_is_not_traceable() {
        let authority = new_test_authority(Arc::new(BrokenClock));
        let req_der = read_corpus_request("rejects-time-not-traceable");

        let err = authority.timestamp(&req_der).unwrap_err();
        match err {
            TsaError::Rejection(r) => assert_eq!(r.failure, FailureInfo::TimeNotAvailable),
            other => panic!("un refus était attendu, obtenu: {other}"),
        }
    }

    #[test]
    fn minimal_positive_int_has_no_leading_zero_padding() {
        // Ce cas précis (1 seconde) a révélé le bug corrigé par
        // `minimal_positive_int` : `Int::new(&1u64.to_be_bytes())` produisait
        // un DER invalide (padding illégal), détecté par
        // `openssl ts -reply -text` dans le test bout-en-bout.
        let encoded = minimal_positive_int(1).unwrap();
        assert_eq!(encoded.as_bytes(), &[1]);
    }
}

#[cfg(test)]
mod serial_tests {
    use super::*;
    use der::{Decode, Encode};

    /// Ce qu'un vérificateur strict fait : décoder l'`INTEGER` en DER, qui refuse
    /// tout encodage non minimal.
    fn strictly_decodes(content: &[u8]) -> bool {
        let der = Int::new(content).and_then(|i| i.to_der());
        matches!(der, Ok(bytes) if Int::from_der(&bytes).is_ok()
            && bytes.len() == content.len() + 2)
    }

    fn padded(prefix: &[u8]) -> [u8; 20] {
        let mut b = [0x11u8; 20];
        b[..prefix.len()].copy_from_slice(prefix);
        b
    }

    #[test]
    fn the_serial_is_minimal_positive_der_for_every_shape_of_leading_bytes() {
        let cases: [(&[u8], &[u8]); 6] = [
            // Le cas fautif : 0x00 devant un octet < 0x80.
            (&[0x00, 0x01], &[0x01]),
            (&[0x00, 0x00, 0x7f], &[0x7f]),
            // Un zéro de tête que le bit de poids fort du suivant rend nécessaire.
            (&[0x00, 0x80], &[0x00, 0x80]),
            (&[0x00, 0x00, 0xff], &[0x00, 0xff]),
            // Aucun zéro de tête, bit de poids fort posé : un seul 0x00 est ajouté.
            (&[0x80], &[0x00, 0x80]),
            (&[0x7f], &[0x7f]),
        ];
        for (prefix, expected_start) in cases {
            let out = minimal_positive_integer(&padded(prefix));
            assert!(
                out.starts_with(expected_start),
                "{prefix:02x?} : {out:02x?} ne commence pas par {expected_start:02x?}"
            );
            assert!(strictly_decodes(&out), "{prefix:02x?} : {out:02x?}");
            // Jamais négatif ni superflu.
            assert!(
                out.len() < 2 || out[0] != 0 || out[1] & 0x80 != 0,
                "{out:02x?}"
            );
        }
    }

    #[test]
    fn an_all_zero_draw_becomes_one() {
        assert_eq!(minimal_positive_integer(&[0u8; 20]), vec![1]);
    }

    #[test]
    fn random_serials_always_decode_strictly() {
        // 1 tirage sur ~512 était fautif : 20 000 tirages l'auraient vu ~40 fois.
        for _ in 0..20_000 {
            assert!(strictly_decodes(&random_serial_number()));
        }
    }
}
