//! Le lien mTLS de `ra-console` vers `ca-server` (docs/WEBUI.md §16), contre de
//! vrais certificats émis par une vraie `Issuer` et un vrai serveur TLS. Chaque
//! refus est prouvé par un certificat que la chaîne laisse passer : ce que ces
//! tests exercent, ce sont les contrôles explicites de la console, pas ceux de la
//! bibliothèque TLS.

mod common;

use common::{cert_pem, pki, tempdir::Dir, Key, HOST};
use oe_ca_core::{profile, Profile};
use ra_console::ca_link::{CaLink, LinkError};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use std::sync::Arc;

#[tokio::test]
async fn the_genuine_link_works() {
    let pki = pki().await;
    let port = pki.serve().await;
    let dir = Dir::new();
    let client = pki.cert(&profile::internal_client(), "ra-console").await;
    let link = CaLink::new(&pki.files(&dir, &client, port)).unwrap();

    link.ping().await.expect("le lien authentique fonctionne");
    let left = link.client_certificate_expires() - time::OffsetDateTime::now_utc();
    assert!(left > time::Duration::days(80) && left < time::Duration::days(91));
}

#[tokio::test]
async fn the_console_refuses_to_start_with_a_certificate_that_is_not_its_own() {
    let pki = pki().await;
    let port = pki.serve().await;
    let dir = Dir::new();

    // Bonne CA, mauvais profil (un certificat de TSU) : refusé avant tout appel.
    let tsu = pki.cert(&profile::tsa_signer(), "tsu.example.test").await;
    let err = CaLink::new(&pki.files(&dir, &tsu, port))
        .err()
        .expect("certificat de TSU");
    assert!(matches!(err, LinkError::ClientCertificate(_)), "{err}");

    // Bon profil et politique, mais un autre nom courant.
    let wrong_cn = Profile {
        required_cn: None,
        ..profile::internal_client()
    };
    let other = pki.cert(&wrong_cn, "intrus").await;
    let err = CaLink::new(&pki.files(&dir, &other, port))
        .err()
        .expect("autre nom courant");
    assert!(matches!(err, LinkError::ClientCertificate(_)), "{err}");

    // Un certificat de serveur présenté comme client.
    let srv = pki.cert(&profile::internal_server(), "ca.autre.svc").await;
    assert!(CaLink::new(&pki.files(&dir, &srv, port)).is_err());
}

#[tokio::test]
async fn revoking_the_client_certificate_cuts_the_link() {
    let pki = pki().await;
    let port = pki.serve().await;
    let dir = Dir::new();
    let client = pki.cert(&profile::internal_client(), "ra-console").await;
    let link = CaLink::new(&pki.files(&dir, &client, port)).unwrap();
    link.ping().await.unwrap();

    let serial = oe_ca_core::canonical_serial(client.0.tbs_certificate().serial_number());
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
    let err = link.ping().await.expect_err("certificat révoqué");
    assert!(matches!(err, LinkError::Unreachable(_)), "{err}");
}

#[tokio::test]
async fn the_server_must_be_reached_under_the_name_of_its_certificate() {
    let pki = pki().await;
    let port = pki.serve().await;
    let dir = Dir::new();
    let client = pki.cert(&profile::internal_client(), "ra-console").await;

    // Le certificat porte `localhost` ; se connecter par l'adresse IP ne s'y
    // rattache à aucun SAN.
    let mut cfg = pki.files(&dir, &client, port);
    cfg.ca_url = format!("https://127.0.0.1:{port}");
    let err = CaLink::new(&cfg)
        .unwrap()
        .ping()
        .await
        .expect_err("nom non couvert par le SAN");
    assert!(matches!(err, LinkError::Unreachable(_)), "{err}");
}

#[tokio::test]
async fn a_server_certificate_without_the_dedicated_policy_is_refused() {
    let pki = pki().await;
    let dir = Dir::new();
    let client = pki.cert(&profile::internal_client(), "ra-console").await;

    // Un certificat `serverAuth`, bon SAN, chaîne valide, mais sans la politique
    // `internal_server` : ce que serait un certificat de TLS ordinaire de la CA.
    let plain_server = Profile {
        policy_oid: None,
        check: |_, _| Ok(()),
        ..profile::internal_server()
    };
    let (cert, key) = pki.cert(&plain_server, HOST).await;
    let mut roots = rustls::RootCertStore::empty();
    roots.add(CertificateDer::from(pki.issuing_der())).unwrap();
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let verifier = WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider.clone())
        .build()
        .unwrap();
    let config = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_client_cert_verifier(verifier)
        .with_single_cert(
            vec![CertificateDer::from(der::Encode::to_der(&cert).unwrap())],
            PrivateKeyDer::try_from(
                rsa::pkcs8::EncodePrivateKey::to_pkcs8_der(&key_private(&key))
                    .unwrap()
                    .as_bytes()
                    .to_vec(),
            )
            .unwrap(),
        )
        .unwrap();
    let port = pki.serve_with(config).await;

    let link = CaLink::new(&pki.files(&dir, &client, port)).unwrap();
    let err = link.ping().await.expect_err("politique absente");
    assert!(matches!(err, LinkError::ServerCertificate(_)), "{err}");
    assert!(err.to_string().contains("politique"), "{err}");
}

// `Key` n'expose pas sa clé privée brute : on la relit depuis son PEM.
fn key_private(key: &Key) -> rsa::RsaPrivateKey {
    use rsa::pkcs8::DecodePrivateKey;
    rsa::RsaPrivateKey::from_pkcs8_pem(&key.pem()).unwrap()
}

#[tokio::test]
async fn only_the_issuing_ca_is_trusted() {
    let pki = pki().await;
    let port = pki.serve().await;
    let dir = Dir::new();
    let client = pki.cert(&profile::internal_client(), "ra-console").await;
    let mut cfg = pki.files(&dir, &client, port);

    // La console ne fait confiance qu'à la racine qu'on lui donne : ici, celle d'une
    // autre PKI. Le serveur, signé par la nôtre, n'est pas reconnu.
    let other = common::pki().await;
    cfg.ca_file = dir.write("autre-ca.pem", &cert_pem(other.issuer.certificate()));
    let err = CaLink::new(&cfg)
        .unwrap()
        .ping()
        .await
        .expect_err("autre racine de confiance");
    assert!(matches!(err, LinkError::Unreachable(_)), "{err}");
}

#[tokio::test]
async fn an_unreachable_ca_is_reported_not_hidden() {
    let pki = pki().await;
    let dir = Dir::new();
    let client = pki.cert(&profile::internal_client(), "ra-console").await;
    // Un port où rien n'écoute.
    let port = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };
    let err = CaLink::new(&pki.files(&dir, &client, port))
        .unwrap()
        .ping()
        .await
        .expect_err("rien n'écoute");
    assert!(matches!(err, LinkError::Unreachable(_)), "{err}");
}

/// Les contrôles explicites, isolés : la bibliothèque TLS en fait une partie (nom,
/// chaîne), mais on ne s'en remet pas à elle, et certains ne sont pas les siens
/// (politique dédiée, fenêtre de validité relue sur le certificat lui-même).
#[tokio::test]
async fn the_explicit_certificate_checks_hold_on_their_own() {
    use ra_console::ca_link::{check_own_certificate, check_server_certificate};

    let pki = pki().await;
    let now = time::OffsetDateTime::now_utc();
    let (client, _) = pki.cert(&profile::internal_client(), "ra-console").await;
    let (server, _) = pki.cert(&profile::internal_server(), HOST).await;
    let server_der = der::Encode::to_der(&server).unwrap();

    // Certificat client : valable maintenant, plus valable dans un an, pas encore
    // valable il y a un an.
    check_own_certificate(&client, now).unwrap();
    assert!(matches!(
        check_own_certificate(&client, now + time::Duration::days(200)),
        Err(LinkError::ClientCertificate(_))
    ));
    assert!(matches!(
        check_own_certificate(&client, now - time::Duration::days(365)),
        Err(LinkError::ClientCertificate(_))
    ));

    // Certificat serveur : le bon nom, puis un autre nom, puis hors validité.
    check_server_certificate(&server_der, HOST, now).unwrap();
    check_server_certificate(&server_der, "LOCALHOST", now)
        .expect("le nom ne dépend pas de la casse");
    assert!(matches!(
        check_server_certificate(&server_der, "autre.svc", now),
        Err(LinkError::ServerCertificate(_))
    ));
    assert!(matches!(
        check_server_certificate(&server_der, HOST, now + time::Duration::days(200)),
        Err(LinkError::ServerCertificate(_))
    ));
    // Un certificat qui n'est pas celui d'un serveur interne (un client).
    let client_der = der::Encode::to_der(&client).unwrap();
    assert!(check_server_certificate(&client_der, HOST, now).is_err());
}
