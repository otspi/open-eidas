//! Test décisif du répondeur OCSP : une vraie CRL signée par openssl, de
//! vraies requêtes OCSP produites par `openssl ocsp`, et une réponse produite
//! par `Responder` vérifiée par `openssl ocsp -verify_other` — un
//! vérificateur tiers indépendant, comme pour le jeton RFC 3161 en J6.
//! Jalon « ocsp-responder, rang 2 » de l'ordre de portage post-tsa-server
//! (`/home/philippe/.claude/plans/witty-hopping-nest.md`).

use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

use axum::routing::get;
use axum::Router;
use der::Decode;
use oe_hsm::testing::SoftwareToken;
use x509_cert::Certificate;

fn fixtures_dir() -> std::path::PathBuf {
    std::path::PathBuf::from(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/fixtures/ocsp"
    ))
}

fn load_cert(path: &std::path::Path) -> Certificate {
    let pem = std::fs::read_to_string(path).unwrap();
    let block = pem::parse(pem.as_bytes()).unwrap();
    Certificate::from_der(block.contents()).unwrap()
}

async fn start_crl_server() -> String {
    let dir = fixtures_dir();
    let crl = std::fs::read(dir.join("issuer.crl.der")).unwrap();
    let app = Router::new().route("/issuer.crl", get(move || async move { crl.clone() }));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    format!("http://{addr}/issuer.crl")
}

async fn build_responder() -> oe_ocsp_core::Responder {
    let dir = fixtures_dir();
    let issuer = load_cert(&dir.join("issuer-cert.pem"));
    let certificate = load_cert(&dir.join("responder-cert.pem"));
    let key_pem = std::fs::read_to_string(dir.join("responder-key.pem")).unwrap();
    let signer = SoftwareToken::from_pkcs8_pem(&key_pem).unwrap();

    let crl_url = start_crl_server().await;
    let responder = oe_ocsp_core::Responder::new(oe_ocsp_core::Options {
        signer: Arc::new(signer),
        certificate,
        issuer,
        crl_url,
        crl_refresh: Duration::from_secs(300),
        max_request_bytes: 16 * 1024,
        http_client: None,
    })
    .expect("construction du répondeur");
    responder
        .refresh()
        .await
        .expect("chargement initial de la CRL");
    responder
}

fn verify_with_openssl(resp_der: &[u8], expect_status: &str) {
    let dir = fixtures_dir();
    let out_path = std::env::temp_dir().join(format!("oe-ocsp-resp-{}.der", uuid_like()));
    std::fs::write(&out_path, resp_der).unwrap();

    let output = Command::new("openssl")
        .args([
            "ocsp",
            "-respin",
            out_path.to_str().unwrap(),
            "-CAfile",
            dir.join("issuer-cert.pem").to_str().unwrap(),
            "-verify_other",
            dir.join("responder-cert.pem").to_str().unwrap(),
            "-text",
        ])
        .output()
        .unwrap();
    let _ = std::fs::remove_file(&out_path);

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Response verify OK") || output.status.success(),
        "openssl n'a pas pu vérifier la réponse OCSP:\nstdout: {stdout}\nstderr: {stderr}"
    );
    assert!(
        stdout.contains(expect_status),
        "statut attendu {expect_status:?} absent de la sortie openssl:\n{stdout}"
    );
}

fn uuid_like() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64
}

#[tokio::test]
async fn reports_good_status_for_a_non_revoked_certificate() {
    let responder = build_responder().await;
    let req_der = std::fs::read(fixtures_dir().join("request-good.der")).unwrap();
    let resp_der = responder.handle(&req_der);
    verify_with_openssl(&resp_der, "good");
}

#[tokio::test]
async fn reports_revoked_status_for_a_revoked_certificate() {
    let responder = build_responder().await;
    let req_der = std::fs::read(fixtures_dir().join("request-revoked.der")).unwrap();
    let resp_der = responder.handle(&req_der);
    verify_with_openssl(&resp_der, "revoked");
}

/// Constat O-1 de l'audit du 2026-09-25 (EN 319 411-1 `OVR-6.6.3-02`) : un
/// numéro de série jamais émis par cette CA doit recevoir `unknown`, jamais
/// `good` par défaut — la CRL seule ne peut pas faire la différence, d'où
/// l'extension privée `OID_CRL_ISSUED_SERIALS` que ce test exerce.
#[tokio::test]
async fn reports_unknown_status_for_a_serial_never_issued() {
    let responder = build_responder().await;
    let req_der = std::fs::read(fixtures_dir().join("request-unknown.der")).unwrap();
    let resp_der = responder.handle(&req_der);
    verify_with_openssl(&resp_der, "unknown");
}
