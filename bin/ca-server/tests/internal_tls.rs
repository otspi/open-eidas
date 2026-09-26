//! Le mTLS du lien interne (docs/WEBUI.md §16) contre de vrais certificats émis
//! par une vraie `Issuer`, et un vrai client TLS. Chaque refus est prouvé par un
//! certificat que la chaîne et l'EKU laissent passer : ce que ces tests
//! exercent, c'est le contrôle explicite de `ca-server`, pas celui de `rustls`.

use std::sync::Arc;

use axum::routing::get;
use axum::Router;
use ca_server::internal_tls::{server_config, TlsListener};
use der::Encode;
use oe_ca_core::ceremony::{run_ceremony, CeremonyOptions};
use oe_ca_core::{profile, Issuer, Options, Profile};
use oe_castore::{Memory, Store};
use oe_hsm::testing::SoftwareToken;
use oe_hsm::SigningToken;
use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey};
use rsa::RsaPrivateKey;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use x509_cert::Certificate;

const SERVER_NAME: &str = "ca.internal.svc";

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
    issuer: Issuer,
    /// Même autorité, autre magasin : ses certificats sont bien signés par la
    /// CA mais absents de la table `certificates` du serveur.
    other_issuer: Issuer,
    store: Arc<Memory>,
}

async fn pki() -> Pki {
    let store = Arc::new(Memory::new());
    let root = Arc::new(SoftwareToken::generate(2048));
    let issuing = Arc::new(SoftwareToken::generate(2048));
    let h = run_ceremony(CeremonyOptions {
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
            crl_grace: time::Duration::hours(1),
            recorder: None,
        })
        .unwrap()
    };
    Pki {
        issuer: make(store.clone()),
        other_issuer: make(Arc::new(Memory::new())),
        store,
    }
}

fn pem(cert: &Certificate) -> String {
    let b64 = {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode(cert.to_der().unwrap())
    };
    format!("-----BEGIN CERTIFICATE-----\n{b64}\n-----END CERTIFICATE-----\n")
}

/// Démarre le serveur TLS et rend son port.
async fn serve(pki: &Pki) -> u16 {
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
    let tcp = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = tcp.local_addr().unwrap().port();
    let listener = TlsListener::new(tcp, config, pki.store.clone());
    let app = Router::new().route("/ping", get(|| async { "pong" }));
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    port
}

/// Le statut HTTP obtenu, ou `None` si la connexion a été coupée.
async fn get_ping(pki: &Pki, port: u16, client: Option<(&Certificate, &Key)>) -> Option<String> {
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
    tls.write_all(b"GET /ping HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        .await
        .ok()?;
    let mut out = Vec::new();
    // Une coupure brutale (alerte, reset) est un refus, pas une erreur de test.
    let _ = tls.read_to_end(&mut out).await;
    let text = String::from_utf8_lossy(&out).to_string();
    text.lines().next().map(str::to_string)
}

async fn client_cert(issuer: &Issuer, profile: &Profile, cn: &str) -> (Certificate, Key) {
    let key = Key::new();
    let cert = issuer.issue(&key.spki(), cn, profile, "c").await.unwrap();
    (cert, key)
}

fn ok(status: &Option<String>) -> bool {
    status.as_deref() == Some("HTTP/1.1 200 OK")
}

#[tokio::test]
async fn only_the_genuine_ra_console_certificate_gets_through() {
    let pki = pki().await;
    let port = serve(&pki).await;

    // Le vrai certificat passe.
    let (cert, key) = client_cert(&pki.issuer, &profile::internal_client(), "ra-console").await;
    assert!(ok(&get_ping(&pki, port, Some((&cert, &key))).await));

    // Pas de certificat client.
    assert!(!ok(&get_ping(&pki, port, None).await));

    // Un certificat de TSU : bonne CA, mauvais EKU.
    let (tsu, tsu_key) = client_cert(&pki.issuer, &profile::tsa_signer(), "tsu.example.test").await;
    assert!(!ok(&get_ping(&pki, port, Some((&tsu, &tsu_key))).await));

    // Un certificat de serveur interne présenté comme client.
    let (srv, srv_key) =
        client_cert(&pki.issuer, &profile::internal_server(), "ca.other.svc").await;
    assert!(!ok(&get_ping(&pki, port, Some((&srv, &srv_key))).await));

    // Bonne CA, `clientAuth`, politique interne, mais un autre nom courant :
    // seul le contrôle explicite du sujet l'arrête.
    let wrong_cn = Profile {
        required_cn: None,
        ..profile::internal_client()
    };
    let (c, k) = client_cert(&pki.issuer, &wrong_cn, "intrus").await;
    assert!(!ok(&get_ping(&pki, port, Some((&c, &k))).await));

    // Bonne CA, `clientAuth`, bon CN, mais sans la politique dédiée : c'est ce
    // que serait un certificat d'identité qui porterait `clientAuth`.
    let no_policy = Profile {
        policy_oid: None,
        check: |_, _| Ok(()),
        ..profile::internal_client()
    };
    let (c, k) = client_cert(&pki.issuer, &no_policy, "ra-console").await;
    assert!(!ok(&get_ping(&pki, port, Some((&c, &k))).await));

    // Signé par la CA, mais jamais inscrit dans la table du serveur.
    let (c, k) = client_cert(&pki.other_issuer, &profile::internal_client(), "ra-console").await;
    assert!(!ok(&get_ping(&pki, port, Some((&c, &k))).await));
}

#[tokio::test]
async fn revoking_the_client_certificate_cuts_access_at_the_next_connection() {
    let pki = pki().await;
    let port = serve(&pki).await;
    let (cert, key) = client_cert(&pki.issuer, &profile::internal_client(), "ra-console").await;
    assert!(ok(&get_ping(&pki, port, Some((&cert, &key))).await));

    let serial = oe_ca_core::canonical_serial(cert.tbs_certificate().serial_number());
    pki.issuer
        .revoke(&serial, 1, "operateur-test", "clé compromise")
        .await
        .unwrap();
    assert!(!ok(&get_ping(&pki, port, Some((&cert, &key))).await));
}

#[tokio::test]
async fn the_server_refuses_to_start_with_a_certificate_of_another_profile() {
    let pki = pki().await;
    let key = Key::new();
    let now = time::OffsetDateTime::now_utc();
    let load = |cert: &Certificate, key: &Key| {
        server_config(
            pki.issuer.certificate(),
            pem(cert).as_bytes(),
            key.pkcs8_pem().as_bytes(),
            now,
        )
        .map(|_| ())
    };

    let tsu = pki
        .issuer
        .issue(&key.spki(), "tsu.example.test", &profile::tsa_signer(), "t")
        .await
        .unwrap();
    assert!(load(&tsu, &key).is_err());

    // La clé doit aller avec le certificat.
    let good = pki
        .issuer
        .issue(&key.spki(), SERVER_NAME, &profile::internal_server(), "s")
        .await
        .unwrap();
    assert!(load(&good, &key).is_ok());
    assert!(load(&good, &Key::new()).is_err());
}

// Évite un avertissement d'import inutilisé si `SigningToken` n'est plus requis.
#[allow(dead_code)]
fn _uses(_: &dyn SigningToken) {}
