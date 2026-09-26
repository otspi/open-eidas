//! Vérifie `check_tsu_certificate` contre de vrais certificats produits par
//! `oe-ca-core` — pas de DER construit à la main : les champs de
//! `x509_cert::Certificate` sont privés hors de cette crate, la seule façon
//! honnête d'obtenir un certificat à tester est d'en émettre un.

use std::sync::Arc;

use oe_ca_core::ceremony::{run_ceremony, CeremonyOptions};
use oe_ca_core::{profile, Issuer, Options};
use oe_castore::Memory;
use oe_hsm::testing::SoftwareToken;
use oe_hsm::SigningToken;

async fn build_issuer() -> Issuer {
    let store = Arc::new(Memory::new());
    let root_signer = Arc::new(SoftwareToken::generate(3072));
    let issuing_signer = Arc::new(SoftwareToken::generate(3072));
    let hierarchy = run_ceremony(CeremonyOptions {
        root_signer,
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
        public_url: "https://ca.example.test".to_string(),
        recorder: None,
    })
    .await
    .unwrap();

    Issuer::new(Options {
        signer: issuing_signer,
        certificate: hierarchy.issuing,
        chain: vec![],
        store,
        public_url: "https://ca.example.test".to_string(),
        ocsp_url: None,
        crl_validity: time::Duration::hours(24),
        crl_grace: time::Duration::hours(1),
        recorder: None,
    })
    .unwrap()
}

async fn issue_with_profile(p: oe_ca_core::Profile) -> x509_cert::Certificate {
    let issuer = build_issuer().await;
    try_issue(&issuer, &p).await.unwrap()
}

async fn try_issue(
    issuer: &Issuer,
    p: &oe_ca_core::Profile,
) -> Result<x509_cert::Certificate, oe_ca_core::CaError> {
    let end_entity = SoftwareToken::generate(3072);
    let public_key_der = end_entity.public_key_der().unwrap();
    issuer
        .issue(&public_key_der, "entity.example.test", p, "txn-conformance")
        .await
}

#[tokio::test]
async fn accepts_a_certificate_issued_with_the_tsa_signer_profile() {
    let cert = issue_with_profile(profile::tsa_signer()).await;
    oe_conformance::check_tsu_certificate("test", &cert)
        .expect("un certificat émis avec le profil tsa_signer doit être accepté");
}

/// Constat T-3 de l'audit du 2026-09-25 : sans `privateKeyUsagePeriod`, rien
/// ne borne la durée de vie de la clé — le certificat seul ne suffit pas.
/// `check_tsu_certificate` est aussi le `Profile::check` de `tsa_signer` :
/// l'émission elle-même doit être refusée, pas seulement l'affichage après
/// coup (même discipline que le reste du profil, voir `Issuer::issue`).
#[tokio::test]
async fn issuance_is_refused_without_a_private_key_usage_period() {
    let issuer = build_issuer().await;
    let profile = oe_ca_core::Profile {
        private_key_validity: None,
        ..profile::tsa_signer()
    };
    let err = try_issue(&issuer, &profile).await.unwrap_err();
    assert!(err.to_string().contains("privateKeyUsagePeriod"), "{err}");
}

/// La clé ne doit jamais valoir plus longtemps que le certificat qui la
/// porte (EN 319 421 `TIS-7.6.7-02/-04`).
#[tokio::test]
async fn issuance_is_refused_when_the_key_outlives_the_certificate() {
    let issuer = build_issuer().await;
    let profile = oe_ca_core::Profile {
        // La clé (10 ans) dépasse largement la validité du certificat (2 ans).
        private_key_validity: Some(time::Duration::days(10 * 365)),
        ..profile::tsa_signer()
    };
    let err = try_issue(&issuer, &profile).await.unwrap_err();
    assert!(
        err.to_string().contains("expire après le certificat"),
        "{err}"
    );
}

#[tokio::test]
async fn rejects_a_certificate_issued_with_the_ocsp_responder_profile() {
    // Bon profil de PKI, mauvais usage : sert à vérifier que la fonction
    // contrôle vraiment le contenu du certificat, pas seulement qu'il vient
    // de cette autorité.
    let cert = issue_with_profile(profile::ocsp_responder()).await;
    let err = oe_conformance::check_tsu_certificate("test", &cert);
    assert!(
        err.is_err(),
        "un certificat émis pour le répondeur OCSP ne doit pas passer pour un certificat TSU"
    );
}
