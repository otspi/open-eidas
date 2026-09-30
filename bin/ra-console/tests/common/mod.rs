//! Outillage commun : une vraie PKI de test (cérémonie, émettrice), des
//! certificats du lien interne, et un vrai serveur TLS de `ca-server`.

#![allow(dead_code)]

use std::path::PathBuf;
use std::sync::Arc;

use axum::routing::get;
use axum::{Json, Router};
use ca_server::internal_tls::{server_config, TlsListener};
use der::{Encode, EncodePem};
use oe_ca_core::ceremony::{run_ceremony, CeremonyOptions};
use oe_ca_core::{profile, Issuer, Options, Profile};
use oe_castore::{Memory, Store};
use oe_hsm::testing::SoftwareToken;
use ra_console::config::LinkConfig;
use ra_console::login::LoginService;
use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey};
use rsa::RsaPrivateKey;
use webauthn_authenticator_rs::softtoken::{SoftToken, AAGUID};
use x509_cert::Certificate;

pub const HOST: &str = "localhost";

pub struct Key(RsaPrivateKey);

impl Key {
    pub fn new() -> Key {
        Key(RsaPrivateKey::new(&mut rand::thread_rng(), 2048).unwrap())
    }
    pub fn spki(&self) -> Vec<u8> {
        self.0
            .to_public_key()
            .to_public_key_der()
            .unwrap()
            .as_bytes()
            .to_vec()
    }
    pub fn pem(&self) -> String {
        self.0.to_pkcs8_pem(Default::default()).unwrap().to_string()
    }
}

pub fn cert_pem(cert: &Certificate) -> String {
    cert.to_pem(der::pem::LineEnding::LF).unwrap()
}

pub struct Pki {
    pub issuer: Issuer,
    pub store: Arc<Memory>,
}

pub async fn pki() -> Pki {
    let store = Arc::new(Memory::new());
    let issuing = Arc::new(SoftwareToken::generate(2048));
    let h = run_ceremony(CeremonyOptions {
        root_signer: Arc::new(SoftwareToken::generate(2048)),
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
    let issuer = Issuer::new(Options {
        signer: issuing,
        certificate: h.issuing,
        chain: vec![],
        store: store.clone() as Arc<dyn Store>,
        public_url: "https://ca.example.test".into(),
        ocsp_url: None,
        crl_validity: time::Duration::hours(24),
        crl_grace: time::Duration::hours(1),
        recorder: None,
    })
    .unwrap();
    Pki { issuer, store }
}

impl Pki {
    pub async fn cert(&self, profile: &Profile, cn: &str) -> (Certificate, Key) {
        let key = Key::new();
        let cert = self
            .issuer
            .issue(&key.spki(), cn, profile, "t")
            .await
            .unwrap();
        (cert, key)
    }

    /// Un serveur TLS de `ca-server` : mTLS, mêmes contrôles que le vrai, une route
    /// `/internal/v1/ping`. Rend son port.
    pub async fn serve(&self) -> u16 {
        let (cert, key) = self.cert(&profile::internal_server(), HOST).await;
        let config = server_config(
            self.issuer.certificate(),
            cert_pem(&cert).as_bytes(),
            key.pem().as_bytes(),
            time::OffsetDateTime::now_utc(),
        )
        .unwrap();
        self.serve_with(config).await
    }

    pub async fn serve_with(&self, config: rustls::ServerConfig) -> u16 {
        let app = Router::new().route(
            "/internal/v1/ping",
            get(|| async { Json(serde_json::json!({ "ok": true })) }),
        );
        self.serve_app(config, app).await
    }

    /// Le vrai serveur mTLS de `ca-server`, avec les routes qu'on lui donne (par
    /// exemple son vrai routeur interne).
    pub async fn serve_router(&self, app: Router) -> u16 {
        let (cert, key) = self.cert(&profile::internal_server(), HOST).await;
        let config = server_config(
            self.issuer.certificate(),
            cert_pem(&cert).as_bytes(),
            key.pem().as_bytes(),
            time::OffsetDateTime::now_utc(),
        )
        .unwrap();
        self.serve_app(config, app).await
    }

    async fn serve_app(&self, config: rustls::ServerConfig, app: Router) -> u16 {
        let tcp = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = tcp.local_addr().unwrap().port();
        let listener = TlsListener::new(tcp, config, self.store.clone());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        port
    }

    /// Les fichiers que lit la console : certificat client, clé, racine de confiance.
    pub fn files(&self, dir: &tempdir::Dir, client: &(Certificate, Key), port: u16) -> LinkConfig {
        let cert_file = dir.write("client.pem", &cert_pem(&client.0));
        let key_file = dir.write("client.key", &client.1.pem());
        let ca_file = dir.write("ca.pem", &cert_pem(self.issuer.certificate()));
        LinkConfig {
            ca_url: format!("https://{HOST}:{port}"),
            cert_file,
            key_file,
            ca_file,
        }
    }

    pub fn issuing_der(&self) -> Vec<u8> {
        self.issuer.certificate().to_der().unwrap()
    }
}

/// Une `LoginService` réelle (vrai `Verifier`, vraie liste blanche à un
/// modèle), pour les tests qui construisent un `AppState` complet — qu'ils
/// exercent la connexion ou seulement les autres routes.
pub fn login_service(pool: sqlx::PgPool) -> LoginService {
    let (_token, root) = SoftToken::new(true).unwrap();
    let models = oe_webauthn::trusted_models(&[oe_webauthn::TrustedModel {
        root_pem: &root.to_pem().unwrap(),
        aaguid: AAGUID,
        description: "SoftToken (test)",
    }])
    .unwrap();
    let verifier = oe_webauthn::Verifier::new(
        HOST,
        &oe_webauthn::Url::parse(&format!("https://{HOST}")).unwrap(),
        "Open eIDAS Console — test",
        models,
    )
    .unwrap();
    LoginService::new(
        oe_actions::Registry::new(pool),
        verifier,
        b"secret-de-test-au-moins-16-octets".to_vec(),
        std::sync::Arc::new(ra_console::audit::NullRecorder),
    )
}

pub fn sessions(pool: sqlx::PgPool) -> ra_console::session::Sessions {
    ra_console::session::Sessions::new(
        oe_actions::Registry::new(pool),
        std::sync::Arc::new(ra_console::audit::NullRecorder),
    )
}

pub mod tempdir {
    use super::PathBuf;

    pub struct Dir(PathBuf);

    impl Dir {
        pub fn new() -> Dir {
            let n = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let p = std::env::temp_dir().join(format!("raconsole_{n}_{}", std::process::id()));
            std::fs::create_dir_all(&p).unwrap();
            Dir(p)
        }
        pub fn write(&self, name: &str, content: &str) -> String {
            let p = self.0.join(name);
            std::fs::write(&p, content).unwrap();
            p.to_string_lossy().into_owned()
        }
    }

    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
}
