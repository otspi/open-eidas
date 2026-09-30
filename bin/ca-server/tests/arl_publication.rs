//! Constat C-1 de l'audit du 2026-09-25 : l'ARL de la racine et son
//! certificat sont servis aux adresses exactes que gravent le CDP et l'AIA
//! `caIssuers` de l'émettrice — sans quoi ces extensions pointent dans le
//! vide. Requêtes envoyées en mémoire (`tower::ServiceExt::oneshot`), sans
//! lien réseau.

use std::sync::Arc;

use ca_server::http;
use der::{Decode, Encode};
use http_body_util::BodyExt;
use oe_ca_core::ceremony::{run_ceremony, CeremonyOptions, AUTHORITY_ISSUING};
use oe_ca_core::root::{RootAuthority, RootAuthorityOptions};
use oe_ca_core::{Issuer, Options as CaOptions};
use oe_castore::Memory;
use oe_hsm::testing::SoftwareToken;
use tower::ServiceExt;
use x509_cert::ext::pkix::name::{DistributionPointName, GeneralName};
use x509_cert::ext::pkix::{AuthorityInfoAccessSyntax, CrlDistributionPoints};
use x509_cert::Certificate;

const PUBLIC_URL: &str = "https://ca.example.test";

struct Fixture {
    server: Arc<http::Server>,
    root_authority: RootAuthority,
    root: Certificate,
    issuing: Certificate,
}

async fn fixture() -> Fixture {
    let store = Arc::new(Memory::new());
    let root_signer = Arc::new(SoftwareToken::generate(3072));
    let issuing_signer = Arc::new(SoftwareToken::generate(3072));
    let hierarchy = run_ceremony(CeremonyOptions {
        root_signer: root_signer.clone(),
        issuing_signer: issuing_signer.clone(),
        root_cn: "Test Root CA".to_string(),
        issuing_cn: "Test Issuing CA".to_string(),
        organization: "Open eIDAS Test".to_string(),
        country: "FR".to_string(),
        root_validity: time::Duration::days(20 * 365),
        issuing_validity: time::Duration::days(10 * 365),
        root_token_label: "root".to_string(),
        root_key_label: "root-key".to_string(),
        issuing_token_label: "issuing".to_string(),
        issuing_key_label: "issuing-key".to_string(),
        store: store.clone(),
        operator: "test-operator".to_string(),
        public_url: PUBLIC_URL.to_string(),
        recorder: None,
    })
    .await
    .unwrap();

    let issuer = Arc::new(
        Issuer::new(CaOptions {
            signer: issuing_signer,
            certificate: hierarchy.issuing.clone(),
            chain: vec![hierarchy.root.clone()],
            store: store.clone(),
            public_url: PUBLIC_URL.to_string(),
            ocsp_url: None,
            crl_validity: time::Duration::hours(24),
            crl_grace: time::Duration::hours(1),
            recorder: None,
        })
        .unwrap(),
    );
    let flow = Arc::new(
        oe_raflow::Flow::new(oe_raflow::Options {
            store: store.clone(),
            issuer: issuer.clone(),
            hmac_secret: "test-secret".to_string(),
            recorder: None,
            retry_after: time::Duration::seconds(5),
            clock: None,
        })
        .unwrap(),
    );
    let root_authority = RootAuthority::new(RootAuthorityOptions {
        signer: root_signer,
        certificate: hierarchy.root.clone(),
        store,
        arl_validity: time::Duration::days(365),
        recorder: None,
    });

    Fixture {
        server: Arc::new(http::Server::new(issuer, flow, "test".to_string())),
        root_authority,
        root: hierarchy.root,
        issuing: hierarchy.issuing,
    }
}

async fn get(server: &Arc<http::Server>, path: &str) -> (axum::http::StatusCode, Vec<u8>) {
    let app = http::router(server.clone(), 64 * 1024);
    let request = axum::http::Request::builder()
        .uri(path)
        .body(axum::body::Body::empty())
        .unwrap();
    let response = app.oneshot(request).await.unwrap();
    let status = response.status();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    (status, body.to_vec())
}

/// Chemin local d'une URI gravée dans un certificat : ce que ce service doit
/// servir pour que l'extension ne pointe pas dans le vide.
fn local_path(uri: &str) -> String {
    uri.strip_prefix(PUBLIC_URL)
        .unwrap_or_else(|| panic!("URI hors de l'adresse publique : {uri}"))
        .to_string()
}

fn cdp_uri(cert: &Certificate) -> String {
    let (_, cdp) = cert
        .tbs_certificate()
        .get_extension::<CrlDistributionPoints>()
        .unwrap()
        .expect("l'émettrice doit porter un CDP");
    match &cdp.0[0].distribution_point {
        Some(DistributionPointName::FullName(names)) => match &names[0] {
            GeneralName::UniformResourceIdentifier(uri) => uri.to_string(),
            other => panic!("CDP inattendu : {other:?}"),
        },
        other => panic!("CDP inattendu : {other:?}"),
    }
}

fn ca_issuers_uri(cert: &Certificate) -> String {
    let (_, aia) = cert
        .tbs_certificate()
        .get_extension::<AuthorityInfoAccessSyntax>()
        .unwrap()
        .expect("l'émettrice doit porter une AIA");
    let ca_issuers = der::asn1::ObjectIdentifier::new("1.3.6.1.5.5.7.48.2").unwrap();
    let desc = aia
        .0
        .iter()
        .find(|d| d.access_method == ca_issuers)
        .expect("l'AIA doit porter caIssuers");
    match &desc.access_location {
        GeneralName::UniformResourceIdentifier(uri) => uri.to_string(),
        other => panic!("AIA inattendue : {other:?}"),
    }
}

#[tokio::test]
async fn the_root_certificate_is_served_where_the_issuing_aia_points() {
    let f = fixture().await;
    let path = local_path(&ca_issuers_uri(&f.issuing));
    let (status, body) = get(&f.server, &path).await;
    assert_eq!(status, axum::http::StatusCode::OK, "{path}");
    assert_eq!(body, f.root.to_der().unwrap());
}

#[tokio::test]
async fn the_arl_is_served_where_the_issuing_cdp_points_and_reflects_revocation() {
    let f = fixture().await;
    let path = local_path(&cdp_uri(&f.issuing));

    let (status, _) = get(&f.server, &path).await;
    assert_eq!(
        status,
        axum::http::StatusCode::SERVICE_UNAVAILABLE,
        "aucune ARL publiée : le service le dit, sans inventer de contenu"
    );

    let empty = f.root_authority.publish_arl().await.unwrap();
    let (status, body) = get(&f.server, &path).await;
    assert_eq!(status, axum::http::StatusCode::OK, "{path}");
    assert_eq!(body, empty.der);

    // Publiée par un autre acteur (la racine, hors ligne) : le service la
    // relit en base, sans redémarrage.
    let revoked = f
        .root_authority
        .revoke_authority(AUTHORITY_ISSUING, 2, "test-operator", "compromission")
        .await
        .unwrap();
    let (status, body) = get(&f.server, &path).await;
    assert_eq!(status, axum::http::StatusCode::OK);
    assert_eq!(body, revoked.der);
    let arl = x509_cert::crl::CertificateList::from_der(&body).unwrap();
    let entries = arl
        .tbs_cert_list
        .revoked_certificates
        .expect("l'ARL servie doit lister l'émettrice révoquée");
    assert_eq!(
        entries[0].serial_number,
        *f.issuing.tbs_certificate().serial_number()
    );
}
