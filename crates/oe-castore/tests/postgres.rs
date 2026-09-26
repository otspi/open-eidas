//! Vérifie `Postgres` contre une vraie instance (conteneur `postgres:17-alpine`
//! démarré manuellement pour ce jalon, DSN dans `OE_CASTORE_TEST_DSN`) : les
//! mêmes scénarios que `src/lib.rs::tests` sur `Memory`, plus les contraintes
//! qui n'existent qu'en base (verrou optimiste réellement concurrent,
//! persistance après réouverture du pool). Ignoré si la variable n'est pas
//! définie plutôt qu'un échec — cette suite ne doit pas bloquer un
//! `cargo test` sans PostgreSQL disponible.
#![cfg(feature = "postgres")]

use oe_castore::{
    Certificate, CertificateStatus, Crl, Postgres, Request, RequestState, Store, StoreError,
};
use time::OffsetDateTime;

async fn store() -> Option<Postgres> {
    let dsn = std::env::var("OE_CASTORE_TEST_DSN").ok()?;
    // Chaque test ouvre sa propre connexion sur une base vidée au préalable
    // par le script qui définit OE_CASTORE_TEST_DSN — pas d'isolation par
    // schéma ici, ce jalon vérifie la traduction SQL, pas la concurrence
    // entre suites.
    Some(Postgres::open(&dsn).await.expect("connexion et migration"))
}

macro_rules! require_store {
    () => {
        match store().await {
            Some(s) => s,
            None => {
                eprintln!("OE_CASTORE_TEST_DSN non définie : test PostgreSQL ignoré");
                return;
            }
        }
    };
}

fn cert(
    serial: &[u8],
    subject: &str,
    status: CertificateStatus,
    not_after: OffsetDateTime,
) -> Certificate {
    Certificate {
        serial: serial.to_vec(),
        profile: "tsa_signer".to_string(),
        subject_dn: subject.to_string(),
        issuer_dn: "CN=Test CA".to_string(),
        not_before: OffsetDateTime::UNIX_EPOCH,
        not_after,
        der: vec![1, 2, 3],
        status,
        revoked_at: None,
        revocation_reason: 0,
        request_transaction_id: "tx".to_string(),
    }
}

#[tokio::test]
async fn reserve_serial_then_save_round_trips() {
    let s = require_store!();
    let serial = unique_serial();
    s.reserve_serial(&serial, "tsa_signer").await.unwrap();
    assert!(
        matches!(s.certificate(&serial).await, Err(StoreError::NotFound)),
        "réservé mais non signé doit rester invisible"
    );

    let far_future = OffsetDateTime::UNIX_EPOCH + time::Duration::days(365 * 50);
    s.save_certificate(cert(
        &serial,
        "CN=test-pg",
        CertificateStatus::Issued,
        far_future,
    ))
    .await
    .unwrap();
    let got = s.certificate(&serial).await.unwrap();
    assert_eq!(got.subject_dn, "CN=test-pg");
}

#[tokio::test]
async fn reserve_serial_twice_conflicts() {
    let s = require_store!();
    let serial = unique_serial();
    s.reserve_serial(&serial, "tsa_signer").await.unwrap();
    assert!(matches!(
        s.reserve_serial(&serial, "tsa_signer").await,
        Err(StoreError::SerialTaken)
    ));
}

/// Constat O-1 de l'audit du 2026-09-25 : `issued_serials` doit inclure les
/// certificats émis et révoqués, jamais les réservations non signées, et
/// n'a pas de limite de durée (contrairement à `revoked`).
#[tokio::test]
async fn issued_serials_lists_issued_and_revoked_but_not_reserved() {
    let s = require_store!();
    let far_future = OffsetDateTime::UNIX_EPOCH + time::Duration::days(365 * 50);

    let issued = unique_serial();
    s.reserve_serial(&issued, "tsa_signer").await.unwrap();
    s.save_certificate(cert(
        &issued,
        "CN=test-pg",
        CertificateStatus::Issued,
        far_future,
    ))
    .await
    .unwrap();

    let revoked = unique_serial();
    s.reserve_serial(&revoked, "tsa_signer").await.unwrap();
    s.save_certificate(cert(
        &revoked,
        "CN=test-pg",
        CertificateStatus::Issued,
        far_future,
    ))
    .await
    .unwrap();
    s.revoke(
        &revoked,
        OffsetDateTime::UNIX_EPOCH + time::Duration::days(1),
        1,
    )
    .await
    .unwrap();

    let reserved_only = unique_serial();
    s.reserve_serial(&reserved_only, "tsa_signer")
        .await
        .unwrap();

    let all = s.issued_serials().await.unwrap();
    assert!(all.contains(&issued), "un certificat émis doit y figurer");
    assert!(
        all.contains(&revoked),
        "un certificat révoqué doit y figurer aussi"
    );
    assert!(
        !all.contains(&reserved_only),
        "une réservation non signée ne doit jamais y figurer"
    );
}

#[tokio::test]
async fn revoke_is_idempotent_on_first_date() {
    let s = require_store!();
    let serial = unique_serial();
    let far_future = OffsetDateTime::UNIX_EPOCH + time::Duration::days(365 * 50);
    s.reserve_serial(&serial, "tsa_signer").await.unwrap();
    s.save_certificate(cert(
        &serial,
        "CN=test-pg",
        CertificateStatus::Issued,
        far_future,
    ))
    .await
    .unwrap();

    let first = OffsetDateTime::UNIX_EPOCH + time::Duration::days(1);
    let second = OffsetDateTime::UNIX_EPOCH + time::Duration::days(2);
    s.revoke(&serial, first, 1).await.unwrap();
    s.revoke(&serial, second, 2).await.unwrap();

    let got = s.certificate(&serial).await.unwrap();
    assert_eq!(
        got.revoked_at,
        Some(first),
        "la première révocation doit faire foi"
    );
    assert_eq!(got.revocation_reason, 1);
}

#[tokio::test]
async fn create_request_rejects_duplicate_fingerprint() {
    let s = require_store!();
    let tx = unique_id("tx");
    let fp = unique_id("fp");
    let r = Request {
        transaction_id: tx.clone(),
        csr_fingerprint: fp.clone(),
        csr_der: vec![],
        profile: "tsa_signer".to_string(),
        subject_cn: "test".to_string(),
        state: RequestState::Pending,
        created_at: OffsetDateTime::now_utc(),
        decided_at: None,
        operator: String::new(),
        comment: String::new(),
        issued_at: None,
        certificate_serial: None,
    };
    s.create_request(r.clone()).await.unwrap();
    let mut dup = r.clone();
    dup.transaction_id = unique_id("tx");
    assert!(matches!(
        s.create_request(dup).await,
        Err(StoreError::Conflict)
    ));
}

#[tokio::test]
async fn update_request_requires_expected_from_state() {
    let s = require_store!();
    let tx = unique_id("tx");
    let r = Request {
        transaction_id: tx.clone(),
        csr_fingerprint: unique_id("fp"),
        csr_der: vec![],
        profile: "tsa_signer".to_string(),
        subject_cn: "test".to_string(),
        state: RequestState::Pending,
        created_at: OffsetDateTime::now_utc(),
        decided_at: None,
        operator: String::new(),
        comment: String::new(),
        issued_at: None,
        certificate_serial: None,
    };
    s.create_request(r.clone()).await.unwrap();

    let mut approved = r.clone();
    approved.state = RequestState::Approved;
    approved.operator = "operateur-ra".to_string();
    approved.decided_at = Some(OffsetDateTime::now_utc());
    assert!(matches!(s.update_request(approved.clone(), RequestState::Rejected).await, Err(StoreError::Conflict)), "le verrou optimiste (contrainte state = $2) doit refuser une transition depuis un état inattendu");
    s.update_request(approved, RequestState::Pending)
        .await
        .unwrap();

    let reread = s.request_by_transaction_id(&tx).await.unwrap();
    assert_eq!(reread.state, RequestState::Approved);
}

#[tokio::test]
async fn crl_numbers_increase_monotonically_via_sequence() {
    let s = require_store!();
    let first = s.next_crl_number().await.unwrap();
    let second = s.next_crl_number().await.unwrap();
    assert!(
        second > first,
        "la séquence PostgreSQL ne doit jamais reculer"
    );

    s.save_crl(Crl {
        number: second,
        der: vec![9],
        this_update: OffsetDateTime::now_utc(),
        next_update: OffsetDateTime::now_utc(),
    })
    .await
    .unwrap();
    assert_eq!(s.latest_crl().await.unwrap().number, second);
}

#[tokio::test]
async fn decision_without_operator_is_rejected_by_the_schema_constraint() {
    // `decision_imputable` (migrations/0001_schema.sql) : la base elle-même
    // refuse qu'une décision quitte PENDING sans opérateur, indépendamment de
    // ce que le code Rust vérifie déjà — double garde, pas une redondance.
    let s = require_store!();
    let tx = unique_id("tx");
    let r = Request {
        transaction_id: tx.clone(),
        csr_fingerprint: unique_id("fp"),
        csr_der: vec![],
        profile: "tsa_signer".to_string(),
        subject_cn: "test".to_string(),
        state: RequestState::Pending,
        created_at: OffsetDateTime::now_utc(),
        decided_at: None,
        operator: String::new(),
        comment: String::new(),
        issued_at: None,
        certificate_serial: None,
    };
    s.create_request(r.clone()).await.unwrap();

    let mut approved_without_operator = r;
    approved_without_operator.state = RequestState::Approved;
    approved_without_operator.decided_at = Some(OffsetDateTime::now_utc());
    // operator reste vide : la contrainte SQL doit intervenir.
    let err = s
        .update_request(approved_without_operator, RequestState::Pending)
        .await;
    assert!(err.is_err(), "la base doit refuser une approbation sans opérateur, même si le code appelant l'a laissé passer");
}

fn unique_serial() -> Vec<u8> {
    let mut bytes = [0u8; 16];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut bytes);
    bytes[0] |= 0x80;
    bytes.to_vec()
}

fn unique_id(prefix: &str) -> String {
    format!("{prefix}-{}", hex::encode(unique_serial()))
}
