//! Vérifie `oe-crosstsa::Client` contre un vrai serveur RFC 3161 — notre
//! propre `oe-httpapi` en l'occurrence, un serveur externe RFC 3161 standard
//! du point de vue du client. Jalon J8 du plan de migration
//! (`/home/philippe/.claude/plans/witty-hopping-nest.md`).

use std::sync::Arc;

use der::Decode;
use oe_hsm::testing::SoftwareToken;
use oe_tsa_core::{Authority, Clock, Options as TsaOptions};
use x509_cert::Certificate;

struct FixedClock;
impl Clock for FixedClock {
    fn now(&self) -> Result<time::OffsetDateTime, String> {
        Ok(time::OffsetDateTime::now_utc())
    }
}

fn fixtures_dir() -> std::path::PathBuf {
    std::path::PathBuf::from(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/fixtures/tsa"
    ))
}

async fn start_local_tsa() -> String {
    let dir = fixtures_dir();
    let key_pem = std::fs::read_to_string(dir.join("tsu-key.pem")).unwrap();
    let cert_pem = std::fs::read_to_string(dir.join("tsu-cert.pem")).unwrap();
    let signer = SoftwareToken::from_pkcs8_pem(&key_pem).unwrap();
    let cert_block = pem::parse(cert_pem.as_bytes()).unwrap();
    let certificate = Certificate::from_der(cert_block.contents()).unwrap();

    let authority = Arc::new(
        Authority::new(TsaOptions {
            signer: Arc::new(signer),
            certificate,
            chain: Vec::new(),
            policy: der::asn1::ObjectIdentifier::new("1.3.6.1.4.1.67027.9.1.1.1").unwrap(),
            accuracy: std::time::Duration::from_secs(1),
            signing_digest: oe_hsm::DigestAlg::Sha256,
            signature_scheme: oe_hsm::Scheme::Pkcs1v15,
            clock: Arc::new(FixedClock),
            recorder: None,
        })
        .unwrap(),
    );
    let time_source = oe_timesource::Monitor::new(oe_timesource::Options {
        policy: oe_timesource::Policy::Disabled,
        ..Default::default()
    })
    .unwrap();
    let app = oe_httpapi::router(oe_httpapi::Options {
        authority,
        time_source,
        max_request_bytes: 64 * 1024,
        version: "test".to_string(),
        cors_allowed_origin: None,
        journal: None,
    });

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    format!("http://{addr}/tsa")
}

#[tokio::test]
async fn seals_a_digest_against_a_real_rfc3161_server() {
    let url = start_local_tsa().await;

    let client = oe_crosstsa::Client::new(oe_crosstsa::Options {
        urls: vec![url],
        timeout: std::time::Duration::from_secs(5),
    });

    use sha2::Digest;
    let digest = sha2::Sha256::digest(b"tete-de-chaine-du-journal-d-audit").to_vec();
    let sha256_alg = spki::AlgorithmIdentifierOwned {
        oid: der::asn1::ObjectIdentifier::new("2.16.840.1.101.3.4.2.1").unwrap(),
        parameters: None,
    };

    let attestations = client.seal(&digest, sha256_alg).await;
    assert_eq!(
        attestations.len(),
        1,
        "le contreseing contre le serveur local doit réussir"
    );
    let att = &attestations[0];
    assert!(!att.gen_time.is_empty());
    assert!(!att.serial.is_empty());
    assert!(
        att.tsa.contains("Time-Stamping Unit"),
        "nom de la TSA attendu depuis le certificat: {}",
        att.tsa
    );
    assert!(!att.token.is_empty());
}
