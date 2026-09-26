//! Test décisif du jalon J6 du plan de migration
//! (`/home/philippe/.claude/plans/witty-hopping-nest.md`) : `Authority`
//! produit un jeton RFC 3161 réel pour chaque cas du corpus
//! `tests/fixtures/rfc3161/`, et ce jeton est vérifié comme valide par
//! `openssl ts -verify` — un vérificateur tiers indépendant de ce dépôt,
//! exactement comme le fait `helm-kind-smoke-test` côté Go.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

use der::Decode;
use oe_hsm::{testing::SoftwareToken, DigestAlg};
use oe_tsa_core::{Authority, Clock, Options};
use x509_cert::Certificate;

fn fixtures_dir() -> PathBuf {
    PathBuf::from(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/fixtures/tsa"
    ))
}

fn rfc3161_corpus_dir() -> PathBuf {
    PathBuf::from(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/fixtures/rfc3161"
    ))
}

struct FixedClock;
impl Clock for FixedClock {
    fn now(&self) -> Result<time::OffsetDateTime, String> {
        Ok(time::OffsetDateTime::now_utc())
    }
}

fn load_authority() -> Authority {
    load_authority_with(None)
}

fn load_authority_with(recorder: Option<Arc<dyn oe_tsa_core::Recorder>>) -> Authority {
    let dir = fixtures_dir();
    let key_pem =
        std::fs::read_to_string(dir.join("tsu-key.pem")).expect("lecture de la clé de test");
    let cert_pem =
        std::fs::read_to_string(dir.join("tsu-cert.pem")).expect("lecture du certificat de test");

    let signer = SoftwareToken::from_pkcs8_pem(&key_pem).expect("chargement de la clé RSA de test");

    let cert_block = pem::parse(cert_pem.as_bytes()).expect("PEM invalide");
    let certificate =
        Certificate::from_der(cert_block.contents()).expect("certificat DER invalide");

    Authority::new(Options {
        signer: Arc::new(signer),
        certificate,
        chain: Vec::new(),
        policy: der::asn1::ObjectIdentifier::new("1.3.6.1.4.1.99999.1.1.1").unwrap(),
        accuracy: std::time::Duration::from_secs(1),
        signing_digest: DigestAlg::Sha256,
        clock: Arc::new(FixedClock),
        recorder,
    })
    .expect("construction de l'autorité")
}

/// Un premier `request.der` de granted dans le corpus, pour les tests qui
/// n'ont besoin que d'une requête RFC 3161 valide quelconque.
fn any_granted_request() -> Vec<u8> {
    for entry in std::fs::read_dir(rfc3161_corpus_dir()).expect("corpus introuvable") {
        let path = entry.unwrap().path();
        if path.is_dir() && path.join("response.der").exists() {
            return std::fs::read(path.join("request.der")).unwrap();
        }
    }
    panic!("aucun cas 'granted' dans le corpus");
}

fn openssl_verify_token(resp_der_path: &Path, query_path: &Path, cert_path: &Path) {
    // openssl ts -reply attend directement le TimeStampResp (ce que nous produisons) ;
    // -verify redemande la requête d'origine pour contrôler le nonce/imprint.
    let output = Command::new("openssl")
        .args([
            "ts",
            "-reply",
            "-in",
            resp_der_path.to_str().unwrap(),
            "-text",
        ])
        .output()
        .expect("exécution d'openssl");
    assert!(
        output.status.success(),
        "openssl ts -reply -text a échoué: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let output = Command::new("openssl")
        .args([
            "ts",
            "-verify",
            "-in",
            resp_der_path.to_str().unwrap(),
            "-queryfile",
            query_path.to_str().unwrap(),
            "-CAfile",
            cert_path.to_str().unwrap(),
            "-untrusted",
            cert_path.to_str().unwrap(),
        ])
        .output()
        .expect("exécution d'openssl ts -verify");
    assert!(
        output.status.success(),
        "openssl ts -verify a rejeté le jeton produit par oe-tsa-core:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn produces_tokens_accepted_by_openssl_for_every_granted_case_in_the_corpus() {
    let authority = load_authority();
    let cert_path = fixtures_dir().join("tsu-cert.pem");

    let mut checked = 0;
    for entry in std::fs::read_dir(rfc3161_corpus_dir()).expect("corpus introuvable") {
        let entry = entry.unwrap();
        let path = entry.path();
        if !path.is_dir() || path.file_name().is_some_and(|n| n == "keys") {
            continue;
        }
        let request_path = path.join("request.der");
        if !request_path.exists() {
            continue;
        }
        let has_response = path.join("response.der").exists();
        if !has_response {
            // Cas de rejet du corpus : couvert par les tests unitaires
            // d'oe-tsa-core, pas par ce test bout-en-bout.
            continue;
        }

        let req_der = std::fs::read(&request_path).unwrap();
        let resp_der = authority
            .timestamp(&req_der)
            .unwrap_or_else(|e| panic!("horodatage refusé pour {path:?}: {e}"));

        let out_path = std::env::temp_dir().join(format!(
            "oe-tsa-core-e2e-{}.der",
            path.file_name().unwrap().to_string_lossy()
        ));
        std::fs::write(&out_path, &resp_der).unwrap();

        openssl_verify_token(&out_path, &request_path, &cert_path);
        let _ = std::fs::remove_file(&out_path);
        checked += 1;
    }
    assert!(
        checked >= 3,
        "le corpus devrait fournir au moins 3 cas accordés, {checked} vérifiés"
    );
}

/// Un journal qui échoue systématiquement (docs/WEBUI.md §15 étape 2b) :
/// preuve que le journal, écrit *avant* la signature, bloque bien
/// l'horodatage — aucun jeton n'est signé quand il échoue.
struct FailingRecorder;
impl oe_tsa_core::Recorder for FailingRecorder {
    fn append(&self, _event: &str, _data: serde_json::Value) -> Result<(), String> {
        Err("stockage du journal injoignable (test)".to_string())
    }
}

/// Compte les appels à `sign_digest`, pour prouver qu'aucune signature n'a
/// lieu quand le journal échoue — pas seulement qu'une erreur est rendue
/// (une erreur rendue *après* avoir signé serait pire, pas mieux).
struct CountingSigner {
    inner: SoftwareToken,
    calls: std::sync::atomic::AtomicUsize,
}

impl oe_hsm::SigningToken for CountingSigner {
    fn sign_digest(&self, alg: DigestAlg, digest: &[u8]) -> Result<Vec<u8>, oe_hsm::HsmError> {
        self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.inner.sign_digest(alg, digest)
    }
    fn public_key_der(&self) -> Result<Vec<u8>, oe_hsm::HsmError> {
        self.inner.public_key_der()
    }
}

fn load_authority_with_signer(
    recorder: Option<Arc<dyn oe_tsa_core::Recorder>>,
) -> (Authority, Arc<CountingSigner>) {
    load_authority_with_signer_and_clock(recorder, Arc::new(FixedClock))
}

fn load_authority_with_signer_and_clock(
    recorder: Option<Arc<dyn oe_tsa_core::Recorder>>,
    clock: Arc<dyn Clock>,
) -> (Authority, Arc<CountingSigner>) {
    let dir = fixtures_dir();
    let key_pem =
        std::fs::read_to_string(dir.join("tsu-key.pem")).expect("lecture de la clé de test");
    let cert_pem =
        std::fs::read_to_string(dir.join("tsu-cert.pem")).expect("lecture du certificat de test");
    let inner = SoftwareToken::from_pkcs8_pem(&key_pem).expect("chargement de la clé RSA de test");
    let signer = Arc::new(CountingSigner {
        inner,
        calls: std::sync::atomic::AtomicUsize::new(0),
    });
    let cert_block = pem::parse(cert_pem.as_bytes()).expect("PEM invalide");
    let certificate =
        Certificate::from_der(cert_block.contents()).expect("certificat DER invalide");
    let authority = Authority::new(Options {
        signer: signer.clone(),
        certificate,
        chain: Vec::new(),
        policy: der::asn1::ObjectIdentifier::new("1.3.6.1.4.1.99999.1.1.1").unwrap(),
        accuracy: std::time::Duration::from_secs(1),
        signing_digest: DigestAlg::Sha256,
        clock,
        recorder,
    })
    .expect("construction de l'autorité");
    (authority, signer)
}

/// Après l'expiration de la clé de la fixture (`privateKeyUsagePeriod`,
/// notAfter `2028-09-26`, voir `tests/fixtures/tsa/README.md`), mais avant
/// celle du certificat lui-même (`2029-09-25`) : isole le seul cas qui
/// intéresse le constat T-3.
struct KeyExpiredClock;
impl Clock for KeyExpiredClock {
    fn now(&self) -> Result<time::OffsetDateTime, String> {
        let date = time::Date::from_calendar_date(2029, time::Month::January, 1)
            .map_err(|e| e.to_string())?;
        Ok(date
            .with_hms(0, 0, 0)
            .map_err(|e| e.to_string())?
            .assume_utc())
    }
}

/// Constat T-3 de l'audit du 2026-09-25 (EN 319 421 `TIS-7.7.1-09`) : passé
/// la date d'expiration de la **clé** (pas celle du certificat, encore
/// valide), l'horodatage doit être refusé — et surtout, aucune signature ne
/// doit avoir lieu (pas seulement une erreur rendue après coup).
#[test]
fn a_timestamp_is_refused_once_the_signing_key_has_expired() {
    let (authority, signer) = load_authority_with_signer_and_clock(None, Arc::new(KeyExpiredClock));
    let req_der = any_granted_request();
    let err = authority.timestamp(&req_der).unwrap_err();
    assert!(err.to_string().contains("expirée"), "{err}");
    assert_eq!(
        signer.calls.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "aucune signature ne doit avoir eu lieu : la clé a expiré avant"
    );
}

#[test]
fn a_journal_failure_blocks_the_timestamp_before_any_signature() {
    let (authority, signer) = load_authority_with_signer(Some(Arc::new(FailingRecorder)));
    let req_der = any_granted_request();
    let err = authority.timestamp(&req_der).unwrap_err();
    assert!(err.to_string().contains("journal"), "{err}");
    assert_eq!(
        signer.calls.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "aucune signature ne doit avoir eu lieu : le journal a échoué avant"
    );
}
