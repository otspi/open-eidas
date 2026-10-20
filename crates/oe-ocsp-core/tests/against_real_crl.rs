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
    let (url, _counter) = start_counting_crl_server().await;
    url
}

/// Comme [`start_crl_server`], mais compte les requêtes reçues — pour
/// prouver que le rafraîchissement à la volée est borné (constat O-1).
async fn start_counting_crl_server() -> (String, std::sync::Arc<std::sync::atomic::AtomicUsize>) {
    let dir = fixtures_dir();
    let crl = std::fs::read(dir.join("issuer.crl.der")).unwrap();
    let counter = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let served = counter.clone();
    let app = Router::new().route(
        "/issuer.crl",
        get(move || {
            let crl = crl.clone();
            let served = served.clone();
            async move {
                served.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                crl
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (format!("http://{addr}/issuer.crl"), counter)
}

/// Comme [`start_crl_server`], mais sert un contenu qui peut changer entre
/// deux requêtes (`swap`) — pour simuler une CA qui republie une CRL plus
/// récente pendant que le répondeur tourne.
async fn start_swappable_crl_server(
    initial: Vec<u8>,
) -> (String, std::sync::Arc<std::sync::Mutex<Vec<u8>>>) {
    let crl = std::sync::Arc::new(std::sync::Mutex::new(initial));
    let served = crl.clone();
    let app = Router::new().route(
        "/issuer.crl",
        get(move || {
            let served = served.clone();
            async move { served.lock().unwrap().clone() }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (format!("http://{addr}/issuer.crl"), crl)
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
        clock: None,
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
    let resp_der = responder.handle(&req_der).await;
    verify_with_openssl(&resp_der, "good");
}

#[tokio::test]
async fn reports_revoked_status_for_a_revoked_certificate() {
    let responder = build_responder().await;
    let req_der = std::fs::read(fixtures_dir().join("request-revoked.der")).unwrap();
    let resp_der = responder.handle(&req_der).await;
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
    let resp_der = responder.handle(&req_der).await;
    verify_with_openssl(&resp_der, "unknown");
}

/// Constat O-1 : le rafraîchissement à la volée doit rester borné, sinon
/// quiconque interroge des séries jamais émises au hasard déclencherait un
/// fetch HTTP (et une vérification de signature) par requête — un déni de
/// service bon marché. Deux requêtes `unknown` rapprochées ne doivent
/// déclencher qu'un seul rafraîchissement supplémentaire.
#[tokio::test]
async fn on_demand_refresh_is_rate_limited() {
    let (crl_url, fetches) = start_counting_crl_server().await;
    let dir = fixtures_dir();
    let issuer = load_cert(&dir.join("issuer-cert.pem"));
    let certificate = load_cert(&dir.join("responder-cert.pem"));
    let key_pem = std::fs::read_to_string(dir.join("responder-key.pem")).unwrap();
    let signer = SoftwareToken::from_pkcs8_pem(&key_pem).unwrap();
    let responder = oe_ocsp_core::Responder::new(oe_ocsp_core::Options {
        signer: Arc::new(signer),
        certificate,
        issuer,
        crl_url,
        crl_refresh: Duration::from_secs(300),
        max_request_bytes: 16 * 1024,
        http_client: None,
        clock: None,
    })
    .expect("construction du répondeur");
    responder.refresh().await.expect("chargement initial");
    assert_eq!(fetches.load(std::sync::atomic::Ordering::SeqCst), 1);

    let req_der = std::fs::read(dir.join("request-unknown.der")).unwrap();
    let _ = responder.handle(&req_der).await;
    let _ = responder.handle(&req_der).await;
    let _ = responder.handle(&req_der).await;

    assert_eq!(
        fetches.load(std::sync::atomic::Ordering::SeqCst),
        2,
        "trois requêtes rapprochées ne doivent déclencher qu'un seul rafraîchissement à la volée"
    );
}

/// Constat O-1 : un certificat tout juste émis peut être absent de
/// l'instantané que le répondeur a en cache (la CA a republié une CRL plus
/// récente que son dernier rafraîchissement périodique). Sans rafraîchissement
/// à la volée, cette course répondrait `unknown` pour un certificat par
/// ailleurs parfaitement valide — ce test le prouve en réglant le cache sur
/// une CRL antérieure à l'émission de `0x1001`, puis en interrogeant ce
/// numéro sans jamais appeler `refresh()` explicitement.
#[tokio::test]
async fn an_unknown_status_triggers_an_on_demand_refresh_that_finds_a_freshly_issued_certificate() {
    let dir = fixtures_dir();
    let stale = std::fs::read(dir.join("issuer.crl.stale.der")).unwrap();
    let fresh = std::fs::read(dir.join("issuer.crl.der")).unwrap();
    let (crl_url, served) = start_swappable_crl_server(stale).await;

    let issuer = load_cert(&dir.join("issuer-cert.pem"));
    let certificate = load_cert(&dir.join("responder-cert.pem"));
    let key_pem = std::fs::read_to_string(dir.join("responder-key.pem")).unwrap();
    let signer = SoftwareToken::from_pkcs8_pem(&key_pem).unwrap();
    let responder = oe_ocsp_core::Responder::new(oe_ocsp_core::Options {
        signer: Arc::new(signer),
        certificate,
        issuer,
        crl_url,
        crl_refresh: Duration::from_secs(300),
        max_request_bytes: 16 * 1024,
        http_client: None,
        clock: None,
    })
    .expect("construction du répondeur");
    // Chargement initial : la CRL périmée, sans 0x1001.
    responder.refresh().await.expect("chargement initial");

    // La CA republie : le répondeur ne le sait pas encore.
    *served.lock().unwrap() = fresh;

    let req_der = std::fs::read(dir.join("request-good.der")).unwrap();
    let resp_der = responder.handle(&req_der).await;
    verify_with_openssl(&resp_der, "good");
}

/// Construit un répondeur sur une CRL interchangeable, avec une horloge
/// réglable (constat O-2).
async fn build_responder_on(
    initial: Vec<u8>,
    clock: Option<std::sync::Arc<dyn Fn() -> time::OffsetDateTime + Send + Sync>>,
) -> (
    oe_ocsp_core::Responder,
    std::sync::Arc<std::sync::Mutex<Vec<u8>>>,
) {
    let dir = fixtures_dir();
    let (crl_url, served) = start_swappable_crl_server(initial).await;
    let issuer = load_cert(&dir.join("issuer-cert.pem"));
    let certificate = load_cert(&dir.join("responder-cert.pem"));
    let key_pem = std::fs::read_to_string(dir.join("responder-key.pem")).unwrap();
    let signer = SoftwareToken::from_pkcs8_pem(&key_pem).unwrap();
    let responder = oe_ocsp_core::Responder::new(oe_ocsp_core::Options {
        signer: Arc::new(signer),
        certificate,
        issuer,
        crl_url,
        crl_refresh: Duration::from_secs(300),
        max_request_bytes: 16 * 1024,
        http_client: None,
        clock,
    })
    .expect("construction du répondeur");
    (responder, served)
}

/// Le statut protocolaire d'une réponse (RFC 6960 §4.2.1), sans la vérifier.
fn response_status(resp_der: &[u8]) -> oe_ocsp_core::asn1::OcspResponseStatus {
    oe_ocsp_core::asn1::OcspResponse::from_der(resp_der)
        .unwrap()
        .response_status
}

/// La `BasicOCSPResponse` d'une réponse réussie.
fn basic_response(resp_der: &[u8]) -> oe_ocsp_core::asn1::BasicOcspResponse {
    let resp = oe_ocsp_core::asn1::OcspResponse::from_der(resp_der).unwrap();
    assert_eq!(
        resp.response_status,
        oe_ocsp_core::asn1::OcspResponseStatus::Successful
    );
    oe_ocsp_core::asn1::BasicOcspResponse::from_der(
        resp.response_bytes.unwrap().response.as_bytes(),
    )
    .unwrap()
}

/// Une vraie requête OCSP produite par `openssl ocsp` pour les numéros
/// donnés ; `flag` vaut `-nonce` ou `-no_nonce`.
fn openssl_request(serials: &[&str], flag: &str) -> (Vec<u8>, std::path::PathBuf) {
    let dir = fixtures_dir();
    let path = std::env::temp_dir().join(format!("oe-ocsp-req-{}.der", uuid_like()));
    let mut cmd = Command::new("openssl");
    cmd.args([
        "ocsp",
        "-issuer",
        dir.join("issuer-cert.pem").to_str().unwrap(),
    ]);
    for serial in serials {
        cmd.args(["-serial", serial]);
    }
    cmd.arg(flag);
    cmd.args(["-reqout", path.to_str().unwrap()]);
    let out = cmd.output().unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    (std::fs::read(&path).unwrap(), path)
}

/// Constat O-2 : la péremption se juge sur le `nextUpdate` de la CRL, pas
/// sur l'heure de son téléchargement. Une CRL que la CA n'a pas republiée se
/// retélécharge très bien : passé son `nextUpdate`, le répondeur répond
/// `tryLater` plutôt que de signer un statut dont la validité est échue.
#[tokio::test]
async fn a_crl_past_its_next_update_yields_try_later() {
    let dir = fixtures_dir();
    let crl = std::fs::read(dir.join("issuer.crl.der")).unwrap();
    // La fixture expire en 2036 : une horloge en 2037 la voit périmée.
    let later = time::OffsetDateTime::from_unix_timestamp(2_114_380_800).unwrap(); // 2037-01-01
    let (responder, _) = build_responder_on(crl, Some(Arc::new(move || later))).await;
    responder
        .refresh()
        .await
        .expect("une CRL périmée se charge, elle n'est juste pas servie");

    let req_der = std::fs::read(dir.join("request-good.der")).unwrap();
    let resp_der = responder.handle(&req_der).await;
    assert_eq!(
        response_status(&resp_der),
        oe_ocsp_core::asn1::OcspResponseStatus::TryLater
    );
}

/// Constat O-2 : une CRL plus ancienne que celle en cache, même valablement
/// signée, est un rejeu qui ferait disparaître une révocation récente. Elle
/// est refusée et l'instantané courant conservé.
#[tokio::test]
async fn a_replayed_older_crl_is_refused_and_the_current_snapshot_kept() {
    let dir = fixtures_dir();
    let fresh = std::fs::read(dir.join("issuer.crl.der")).unwrap(); // cRLNumber 4096
    let stale = std::fs::read(dir.join("issuer.crl.stale.der")).unwrap(); // cRLNumber 4095
    let (responder, served) = build_responder_on(fresh.clone(), None).await;
    responder.refresh().await.expect("chargement initial");
    // La même CRL, resservie : ni rejeu ni erreur.
    responder
        .refresh()
        .await
        .expect("une CRL de même numéro n'est pas un rejeu");

    *served.lock().unwrap() = stale;
    let err = responder
        .refresh()
        .await
        .expect_err("une CRL plus ancienne doit être refusée");
    assert!(
        matches!(err, oe_ocsp_core::OcspError::CrlReplayed { .. }),
        "{err}"
    );
    assert!(
        err.to_string().contains("0FFF") && err.to_string().contains("1000"),
        "{err}"
    );

    // L'instantané courant (4096, où 0x1001 est émis) reste servi.
    let req_der = std::fs::read(dir.join("request-good.der")).unwrap();
    let resp_der = responder.handle(&req_der).await;
    verify_with_openssl(&resp_der, "good");

    // Et la CRL plus récente est de nouveau acceptée.
    *served.lock().unwrap() = fresh;
    responder.refresh().await.expect("la CRL courante repasse");
}

/// Constat O-2 : le nonce de la requête (RFC 8954) est repris tel quel dans
/// la réponse — openssl, qui l'exige quand il l'a envoyé, en témoigne.
#[tokio::test]
async fn the_request_nonce_is_echoed_in_the_response() {
    let responder = build_responder().await;
    let (req_der, req_path) = openssl_request(&["0x1001"], "-nonce");
    let resp_der = responder.handle(&req_der).await;

    let basic = basic_response(&resp_der);
    let nonce_oid = der::asn1::ObjectIdentifier::new(oe_ocsp_core::OID_PKIX_OCSP_NONCE).unwrap();
    let req = oe_ocsp_core::asn1::OcspRequest::from_der(&req_der).unwrap();
    let sent = req
        .tbs_request
        .request_extensions
        .unwrap()
        .into_iter()
        .find(|e| e.extn_id == nonce_oid)
        .expect("openssl a envoyé un nonce");
    let echoed = basic
        .tbs_response_data
        .response_extensions
        .expect("la réponse porte des extensions")
        .into_iter()
        .find(|e| e.extn_id == nonce_oid)
        .expect("la réponse porte le nonce");
    assert_eq!(echoed.extn_value, sent.extn_value);

    let dir = fixtures_dir();
    let resp_path = std::env::temp_dir().join(format!("oe-ocsp-resp-{}.der", uuid_like()));
    std::fs::write(&resp_path, &resp_der).unwrap();
    let out = Command::new("openssl")
        .args([
            "ocsp",
            "-reqin",
            req_path.to_str().unwrap(),
            "-respin",
            resp_path.to_str().unwrap(),
            "-CAfile",
            dir.join("issuer-cert.pem").to_str().unwrap(),
            "-verify_other",
            dir.join("responder-cert.pem").to_str().unwrap(),
        ])
        .output()
        .unwrap();
    let _ = std::fs::remove_file(&req_path);
    let _ = std::fs::remove_file(&resp_path);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("Response verify OK"), "{stderr}");
    assert!(
        !stderr.to_lowercase().contains("nonce"),
        "openssl se plaint du nonce : {stderr}"
    );

    // Sans nonce dans la requête, aucune extension n'est inventée.
    let (plain, plain_path) = openssl_request(&["0x1001"], "-no_nonce");
    let _ = std::fs::remove_file(&plain_path);
    let basic = basic_response(&responder.handle(&plain).await);
    assert!(basic.tbs_response_data.response_extensions.is_none());
}

/// RFC 8954 §2.1 : un nonce de plus de 32 octets est une requête malformée.
#[tokio::test]
async fn an_oversized_nonce_is_a_malformed_request() {
    use der::Encode;
    let responder = build_responder().await;
    let (req_der, req_path) = openssl_request(&["0x1001"], "-nonce");
    let _ = std::fs::remove_file(&req_path);
    let mut req = oe_ocsp_core::asn1::OcspRequest::from_der(&req_der).unwrap();
    let nonce_oid = der::asn1::ObjectIdentifier::new(oe_ocsp_core::OID_PKIX_OCSP_NONCE).unwrap();
    let oversized = der::asn1::OctetString::new(vec![0x42; oe_ocsp_core::MAX_NONCE_BYTES + 1])
        .unwrap()
        .to_der()
        .unwrap();
    for ext in req.tbs_request.request_extensions.as_mut().unwrap() {
        if ext.extn_id == nonce_oid {
            ext.extn_value = der::asn1::OctetString::new(oversized.clone()).unwrap();
        }
    }
    let resp_der = responder.handle(&req.to_der().unwrap()).await;
    assert_eq!(
        response_status(&resp_der),
        oe_ocsp_core::asn1::OcspResponseStatus::MalformedRequest
    );
}

/// Constat O-2 : chaque requête de la liste reçoit sa réponse — ici une
/// série révoquée et une série saine dans la même requête, que openssl
/// vérifie et dont il lit les deux statuts.
#[tokio::test]
async fn every_request_of_the_list_gets_its_own_single_response() {
    let responder = build_responder().await;
    let (req_der, req_path) = openssl_request(&["0x1000", "0x1001"], "-no_nonce");
    let _ = std::fs::remove_file(&req_path);
    let resp_der = responder.handle(&req_der).await;

    let basic = basic_response(&resp_der);
    assert_eq!(basic.tbs_response_data.responses.len(), 2);
    verify_with_openssl(&resp_der, "Cert Status: revoked");
    verify_with_openssl(&resp_der, "Cert Status: good");
}

/// Au-delà de [`oe_ocsp_core::MAX_REQUESTS`] requêtes, la liste est refusée
/// plutôt que de faire signer une réponse arbitrairement grande.
#[tokio::test]
async fn an_oversized_request_list_is_a_malformed_request() {
    let responder = build_responder().await;
    let serials: Vec<String> = (0..=oe_ocsp_core::MAX_REQUESTS)
        .map(|i| format!("0x{:x}", 0x2000 + i))
        .collect();
    let refs: Vec<&str> = serials.iter().map(String::as_str).collect();
    let (req_der, req_path) = openssl_request(&refs, "-no_nonce");
    let _ = std::fs::remove_file(&req_path);
    let resp_der = responder.handle(&req_der).await;
    assert_eq!(
        response_status(&resp_der),
        oe_ocsp_core::asn1::OcspResponseStatus::MalformedRequest
    );
}
