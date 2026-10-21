//! Port d'enrôlement en TLS mutuel (constat R-3, docs/R3-MTLS-DEMANDEURS.md), de
//! bout en bout : un vrai client TLS présente un vrai certificat `enroll_client`
//! émis par une vraie `Issuer`, et poste une vraie CSR à la vraie route.
//!
//! Chaque refus est prouvé par un certificat que la chaîne et l'EKU laissent
//! passer : ce que ces tests exercent, c'est le contrôle de `ca-server`.

use std::sync::Arc;

use ca_server::enroll_tls::{EnrollListener, EnrollPeer};
use ca_server::http;
use ca_server::internal_tls::server_config;
use der::Encode;
use oe_ca_core::ceremony::{run_ceremony, CeremonyOptions};
use oe_ca_core::{profile, Issuer, Options, Profile};
use oe_castore::{Memory, Store};
use oe_hsm::testing::SoftwareToken;
use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey};
use rsa::RsaPrivateKey;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use x509_cert::Certificate;

const SERVER_NAME: &str = "localhost";

struct Key {
    private: RsaPrivateKey,
}

impl Key {
    fn new() -> Key {
        Key {
            private: RsaPrivateKey::new(&mut rand::thread_rng(), 2048).unwrap(),
        }
    }
    fn spki(&self) -> Vec<u8> {
        self.private
            .to_public_key()
            .to_public_key_der()
            .unwrap()
            .as_bytes()
            .to_vec()
    }
    fn pkcs8_der(&self) -> Vec<u8> {
        self.private.to_pkcs8_der().unwrap().as_bytes().to_vec()
    }
    fn pkcs8_pem(&self) -> String {
        self.private
            .to_pkcs8_pem(Default::default())
            .unwrap()
            .to_string()
    }
}

struct Pki {
    issuer: Arc<Issuer>,
    /// Même autorité, autre magasin : ses certificats sont bien signés par la CA
    /// mais absents de la table `certificates` du serveur.
    other_issuer: Issuer,
    store: Arc<Memory>,
}

async fn pki() -> Pki {
    let store = Arc::new(Memory::new());
    let root = Arc::new(SoftwareToken::generate(2048));
    let issuing = Arc::new(SoftwareToken::generate(2048));
    let h = run_ceremony(CeremonyOptions {
        scheme: oe_hsm::Scheme::Pkcs1v15,
        root_signer: root,
        issuing_signer: issuing.clone(),
        root_cn: "Test Root CA".into(),
        issuing_cn: "Test Issuing CA".into(),
        organization: "Open eIDAS Test".into(),
        country: "FR".into(),
        root_validity: time::Duration::days(3650),
        issuing_validity: time::Duration::days(3650),
        root_token_label: "r".into(),
        root_key_label: "r".into(),
        issuing_token_label: "i".into(),
        issuing_key_label: "i".into(),
        store: store.clone(),
        operator: "test".into(),
        public_url: "https://ca.example.test".to_string(),
        recorder: None,
    })
    .await
    .unwrap();
    let make = |store: Arc<dyn Store>| {
        Issuer::new(Options {
            signer: issuing.clone(),
            certificate: h.issuing.clone(),
            chain: vec![],
            store,
            public_url: "https://ca.example.test".into(),
            ocsp_url: None,
            crl_validity: time::Duration::hours(24),
            recorder: None,
        })
        .unwrap()
    };
    Pki {
        issuer: Arc::new(make(store.clone())),
        other_issuer: make(Arc::new(Memory::new())),
        store,
    }
}

fn pem(cert: &Certificate) -> String {
    pem::encode(&pem::Pem::new("CERTIFICATE", cert.to_der().unwrap()))
}

/// Démarre le port d'enrôlement mTLS (même route et même flot que `ca-server
/// serve`) pour les demandeurs donnés, et rend son port.
async fn serve(pki: &Pki, requesters: Vec<oe_raflow::Requester>) -> u16 {
    let key = Key::new();
    let cert = pki
        .issuer
        .issue(&key.spki(), SERVER_NAME, &profile::internal_server(), "srv")
        .await
        .unwrap();
    let config = server_config(
        pki.issuer.certificate(),
        pem(&cert).as_bytes(),
        key.pkcs8_pem().as_bytes(),
        time::OffsetDateTime::now_utc(),
    )
    .unwrap();
    let flow = Arc::new(
        oe_raflow::Flow::new(oe_raflow::Options {
            store: pki.store.clone(),
            issuer: pki.issuer.clone(),
            hmac_secret: String::new(),
            requesters,
            recorder: None,
            retry_after: time::Duration::seconds(5),
            clock: None,
        })
        .unwrap(),
    );
    let server = Arc::new(http::Server::new(
        pki.issuer.clone(),
        flow,
        "test".to_string(),
    ));
    let tcp = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = tcp.local_addr().unwrap().port();
    let listener = EnrollListener::new(tcp, config, pki.store.clone());
    let app = http::enroll_mtls_router(server, 64 * 1024)
        .into_make_service_with_connect_info::<EnrollPeer>();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    port
}

/// POST de la CSR sur `/api/v1/enroll` avec ce certificat client : le statut HTTP,
/// ou `None` si la connexion a été coupée.
async fn post_enroll(
    pki: &Pki,
    port: u16,
    client: Option<(&Certificate, &Key)>,
    profile_name: &str,
    csr_pem: &str,
) -> Option<String> {
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(CertificateDer::from(
            pki.issuer.certificate().to_der().unwrap(),
        ))
        .unwrap();
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(roots);
    let config = match client {
        Some((cert, key)) => builder
            .with_client_auth_cert(
                vec![CertificateDer::from(cert.to_der().unwrap())],
                PrivateKeyDer::try_from(key.pkcs8_der()).unwrap(),
            )
            .unwrap(),
        None => builder.with_no_client_auth(),
    };
    let tcp = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .unwrap();
    let mut tls = tokio_rustls::TlsConnector::from(Arc::new(config))
        .connect(ServerName::try_from(SERVER_NAME).unwrap(), tcp)
        .await
        .ok()?;
    // Pas de champ `signature` : c'est le certificat client qui identifie.
    let body = serde_json::json!({ "profile": profile_name, "pkcs10": csr_pem }).to_string();
    let request = format!(
        "POST /api/v1/enroll HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    tls.write_all(request.as_bytes()).await.ok()?;
    let mut out = Vec::new();
    // Une coupure brutale (alerte, reset) est un refus, pas une erreur de test.
    let _ = tls.read_to_end(&mut out).await;
    String::from_utf8_lossy(&out)
        .lines()
        .next()
        .map(str::to_string)
}

async fn client_cert(issuer: &Issuer, profile: &Profile, cn: &str) -> (Certificate, Key) {
    let key = Key::new();
    let cert = issuer.issue(&key.spki(), cn, profile, "c").await.unwrap();
    (cert, key)
}

fn csr_pem(cn: &str) -> String {
    let token = SoftwareToken::generate(3072);
    let (_, pem) = oe_enroll::build_csr(
        &token,
        &oe_enroll::Subject {
            common_name: cn.to_string(),
        },
    )
    .unwrap();
    pem
}

fn tsa_requester() -> oe_raflow::Requester {
    oe_raflow::Requester {
        name: "tsa".into(),
        client_cn: Some("tsa-1".into()),
        profiles: vec!["tsa_signer".into()],
        subject_cn: Some("tsu.example.test".into()),
        ..Default::default()
    }
}

const ACCEPTED: &str = "HTTP/1.1 202 Accepted";

#[tokio::test]
async fn a_requester_enrolls_with_its_client_certificate_and_no_secret() {
    let pki = pki().await;
    let port = serve(&pki, vec![tsa_requester()]).await;
    let (cert, key) = client_cert(&pki.issuer, &profile::enroll_client(), "tsa-1").await;

    // Son profil et son CN : la demande est ouverte.
    let status = post_enroll(
        &pki,
        port,
        Some((&cert, &key)),
        "tsa_signer",
        &csr_pem("tsu.example.test"),
    )
    .await;
    assert_eq!(status.as_deref(), Some(ACCEPTED), "{status:?}");

    // Ses liens (profil, CN) tiennent encore par ce chemin.
    let status = post_enroll(
        &pki,
        port,
        Some((&cert, &key)),
        "ocsp_responder",
        &csr_pem("ocsp.example.test"),
    )
    .await;
    assert_eq!(
        status.as_deref(),
        Some("HTTP/1.1 400 Bad Request"),
        "{status:?}"
    );
    let status = post_enroll(
        &pki,
        port,
        Some((&cert, &key)),
        "tsa_signer",
        &csr_pem("autre.example.test"),
    )
    .await;
    assert_eq!(
        status.as_deref(),
        Some("HTTP/1.1 400 Bad Request"),
        "{status:?}"
    );
}

#[tokio::test]
async fn only_a_genuine_enroll_client_certificate_gets_through() {
    let pki = pki().await;
    let port = serve(&pki, vec![tsa_requester()]).await;
    let csr = csr_pem("tsu.example.test");

    // Sans certificat client.
    assert_eq!(
        post_enroll(&pki, port, None, "tsa_signer", &csr).await,
        None
    );

    // Un certificat de TSU : bonne CA, mauvais profil.
    let (tsu, tsu_key) = client_cert(&pki.issuer, &profile::tsa_signer(), "tsa-1").await;
    assert_eq!(
        post_enroll(&pki, port, Some((&tsu, &tsu_key)), "tsa_signer", &csr).await,
        None
    );

    // Le certificat du lien interne (clientAuth, politique voisine) ne passe pas.
    let (internal, internal_key) =
        client_cert(&pki.issuer, &profile::internal_client(), "ra-console").await;
    assert_eq!(
        post_enroll(
            &pki,
            port,
            Some((&internal, &internal_key)),
            "tsa_signer",
            &csr
        )
        .await,
        None
    );

    // Bon profil, mais le nom courant n'est celui d'aucun demandeur : la
    // connexion est admise, la requête est refusée comme non authentifiée.
    let (stranger, stranger_key) =
        client_cert(&pki.issuer, &profile::enroll_client(), "intrus").await;
    let status = post_enroll(
        &pki,
        port,
        Some((&stranger, &stranger_key)),
        "tsa_signer",
        &csr,
    )
    .await;
    assert_eq!(
        status.as_deref(),
        Some("HTTP/1.1 401 Unauthorized"),
        "{status:?}"
    );

    // Signé par la CA mais jamais inscrit dans la table du serveur.
    let (c, k) = client_cert(&pki.other_issuer, &profile::enroll_client(), "tsa-1").await;
    assert_eq!(
        post_enroll(&pki, port, Some((&c, &k)), "tsa_signer", &csr).await,
        None
    );
}

#[tokio::test]
async fn revoking_the_client_certificate_cuts_enrollment_at_the_next_connection() {
    let pki = pki().await;
    let port = serve(&pki, vec![tsa_requester()]).await;
    let (cert, key) = client_cert(&pki.issuer, &profile::enroll_client(), "tsa-1").await;
    let status = post_enroll(
        &pki,
        port,
        Some((&cert, &key)),
        "tsa_signer",
        &csr_pem("tsu.example.test"),
    )
    .await;
    assert_eq!(status.as_deref(), Some(ACCEPTED), "{status:?}");

    let serial = oe_ca_core::canonical_serial(cert.tbs_certificate().serial_number());
    pki.issuer
        .revoke(
            &serial,
            1,
            "operateur-test",
            "clé compromise",
            &oe_ca_core::Via::WebAuthn,
        )
        .await
        .unwrap();
    assert_eq!(
        post_enroll(
            &pki,
            port,
            Some((&cert, &key)),
            "tsa_signer",
            &csr_pem("tsu.example.test")
        )
        .await,
        None
    );
}

/// Le vrai client `oe_enroll::Client`, avec son certificat client et sans aucun
/// secret, contre le vrai port : la demande est acceptée (elle attend ensuite un
/// opérateur RA, d'où le délai dépassé qui porte l'identifiant de transaction).
/// Un certificat d'un demandeur inconnu est refusé par la CA.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_enroll_client_authenticates_with_its_certificate_alone() {
    let pki = pki().await;
    let port = serve(&pki, vec![tsa_requester()]).await;
    let dir = std::env::temp_dir().join(format!("enroll-mtls-{}-{port}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("ca.pem"), pem(pki.issuer.certificate())).unwrap();

    let identity = |cn: &str| {
        let (cert, key) =
            futures_lite_block(client_cert(&pki.issuer, &profile::enroll_client(), cn));
        let name = cn.to_string();
        std::fs::write(dir.join(format!("{name}.crt")), pem(&cert)).unwrap();
        std::fs::write(dir.join(format!("{name}.key")), key.pkcs8_pem()).unwrap();
        oe_enroll::ClientIdentity {
            cert_file: dir.join(format!("{name}.crt")).display().to_string(),
            key_file: dir.join(format!("{name}.key")).display().to_string(),
        }
    };
    let client = |cn: &str, profile: &str| {
        oe_enroll::Client::new(oe_enroll::Options {
            endpoint: format!("https://localhost:{port}/api/v1/enroll"),
            profile: profile.to_string(),
            client_identity: Some(identity(cn)),
            ca_file: Some(dir.join("ca.pem").display().to_string()),
            timeout: std::time::Duration::from_secs(2),
            ..Default::default()
        })
        .unwrap()
    };
    let token = SoftwareToken::generate(3072);

    let err = client("tsa-1", "tsa_signer")
        .request(
            &token,
            oe_enroll::Subject {
                common_name: "tsu.example.test".into(),
            },
        )
        .await
        .err()
        .expect("la demande attend un opérateur");
    assert!(
        matches!(err, oe_enroll::EnrollError::Timeout { .. }),
        "demande acceptée puis en attente, pas refusée : {err}"
    );

    let err = client("intrus", "tsa_signer")
        .request(
            &token,
            oe_enroll::Subject {
                common_name: "tsu.example.test".into(),
            },
        )
        .await
        .err()
        .expect("un demandeur inconnu est refusé");
    assert!(
        matches!(err, oe_enroll::EnrollError::Refused { .. }),
        "{err}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// Les fonctions de la PKI de test sont asynchrones ; le contexte d'un `identity`
/// synchrone les attend sur le runtime courant.
fn futures_lite_block<T>(f: impl std::future::Future<Output = T>) -> T {
    tokio::task::block_in_place(|| tokio::runtime::Handle::current().block_on(f))
}
