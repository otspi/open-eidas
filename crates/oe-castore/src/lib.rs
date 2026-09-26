//! Portage de `internal/castore` : l'état persistant de l'autorité de
//! certification — les autorités elles-mêmes, le registre des certificats
//! émis, les demandes d'enrôlement en cours et l'historique des CRL. Rang 3
//! de l'ordre de portage post-`tsa-server`/`ocsp-responder`
//! (`/home/philippe/.claude/plans/witty-hopping-nest.md`).
//!
//! Le trait [`Store`] est délibérément étroit et explicite : chaque méthode
//! correspond à une opération que le moteur de CA doit pouvoir défendre
//! devant un auditeur.
//!
//! Deux implémentations : [`Memory`], pour les tests unitaires d'`oe-raflow`
//! et `oe-ca-core` (qui ne dépendent que du trait `Store`) ; et, derrière la
//! feature Cargo `postgres`, [`postgres::Postgres`] — celle
//! d'exploitation, portage de `internal/castore/postgres.go` sur le même
//! schéma SQL (`migrations/0001_schema.sql`, repris tel quel du binaire Go).

use std::collections::BTreeMap;
use std::sync::Mutex;

use time::OffsetDateTime;

#[cfg(feature = "postgres")]
pub mod postgres;
#[cfg(feature = "postgres")]
pub use postgres::Postgres;

/// Numéro de série, en octets big-endian canoniques (nos tirages font 128
/// bits, bit de poids fort forcé : la comparaison lexicographique d'octets
/// coïncide donc avec l'ordre numérique, sans dépendance à une bibliothèque
/// de grands entiers).
pub type Serial = Vec<u8>;

fn serial_key(s: &[u8]) -> String {
    hex::encode(s)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertificateStatus {
    /// Numéro de série réservé mais certificat pas encore signé — ne doit
    /// jamais apparaître dans une CRL ni dans une réponse d'enrôlement.
    Reserved,
    Issued,
    Revoked,
}

#[derive(Debug, Clone)]
pub struct Certificate {
    pub serial: Serial,
    pub profile: String,
    pub subject_dn: String,
    pub issuer_dn: String,
    pub not_before: OffsetDateTime,
    pub not_after: OffsetDateTime,
    pub der: Vec<u8>,
    pub status: CertificateStatus,
    pub revoked_at: Option<OffsetDateTime>,
    /// Codes RFC 5280 §5.3.1. `0` (unspecified) est accepté mais signalé par
    /// `oe-conformance` : il ne justifie pas une décision devant un auditeur.
    pub revocation_reason: i32,
    /// Relie le certificat à la demande d'enrôlement qui l'a produit, donc à
    /// l'opérateur qui l'a approuvée.
    pub request_transaction_id: String,
}

/// L'état d'une demande d'enrôlement. Ces quatre valeurs sont les seules :
/// la machine à états d'`oe-raflow` n'en connaît pas d'autre, et aucune ne
/// mène à `Issued` sans passer par `Approved`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestState {
    Pending,
    Approved,
    Issued,
    Rejected,
}

impl std::fmt::Display for RequestState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            RequestState::Pending => "PENDING",
            RequestState::Approved => "APPROVED",
            RequestState::Issued => "ISSUED",
            RequestState::Rejected => "REJECTED",
        })
    }
}

#[derive(Debug, Clone)]
pub struct Request {
    pub transaction_id: String,
    /// Empreinte SHA-256 hexadécimale de la CSR DER — porte la contrainte
    /// d'unicité qui rend l'enrôlement idempotent.
    pub csr_fingerprint: String,
    pub csr_der: Vec<u8>,
    pub profile: String,
    pub subject_cn: String,
    pub state: RequestState,
    pub created_at: OffsetDateTime,
    pub decided_at: Option<OffsetDateTime>,
    pub operator: String,
    pub comment: String,
    pub issued_at: Option<OffsetDateTime>,
    pub certificate_serial: Option<Serial>,
}

/// Une autorité de la hiérarchie. La clé privée n'y figure pas : elle ne
/// quitte jamais le token PKCS#11, seuls ses labels d'accès sont conservés.
#[derive(Debug, Clone)]
pub struct Authority {
    pub name: String,
    pub subject_dn: String,
    pub der: Vec<u8>,
    pub token_label: String,
    pub key_label: String,
    pub created_at: OffsetDateTime,
}

#[derive(Debug, Clone)]
pub struct Crl {
    pub number: i64,
    pub der: Vec<u8>,
    pub this_update: OffsetDateTime,
    pub next_update: OffsetDateTime,
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum StoreError {
    #[error("castore: introuvable")]
    NotFound,
    #[error("castore: numéro de série déjà réservé")]
    SerialTaken,
    #[error("castore: état modifié entre-temps")]
    Conflict,
    #[error("castore: {0}")]
    Other(String),
}

#[async_trait::async_trait]
pub trait Store: Send + Sync {
    async fn save_authority(&self, a: Authority) -> Result<(), StoreError>;
    async fn authority(&self, name: &str) -> Result<Authority, StoreError>;

    async fn reserve_serial(&self, serial: &Serial, profile: &str) -> Result<(), StoreError>;
    async fn save_certificate(&self, c: Certificate) -> Result<(), StoreError>;
    async fn certificate(&self, serial: &Serial) -> Result<Certificate, StoreError>;
    async fn active_by_subject(
        &self,
        subject_dn: &str,
        now: OffsetDateTime,
    ) -> Result<Vec<Certificate>, StoreError>;
    async fn revoke(
        &self,
        serial: &Serial,
        at: OffsetDateTime,
        reason: i32,
    ) -> Result<(), StoreError>;
    /// Certificats révoqués à porter dans la CRL. Un certificat expiré
    /// depuis plus de `grace` en est retiré (RFC 5280 §5).
    async fn revoked(
        &self,
        now: OffsetDateTime,
        grace: time::Duration,
    ) -> Result<Vec<Certificate>, StoreError>;

    /// Tous les numéros de série émis (`issued` ou `revoked`, jamais
    /// `reserved`), sans limite de durée — jamais purgé, à la différence de
    /// [`Store::revoked`] (constat O-1 de l'audit du 2026-09-25) : le
    /// répondeur OCSP en a besoin pour distinguer un certificat jamais émis
    /// (`unknown`) d'un certificat émis, même expiré depuis longtemps ou
    /// révoqué puis retiré de la CRL (`good`/`revoked`, jamais `unknown`).
    async fn issued_serials(&self) -> Result<Vec<Serial>, StoreError>;

    async fn create_request(&self, r: Request) -> Result<(), StoreError>;
    async fn request_by_fingerprint(&self, fingerprint: &str) -> Result<Request, StoreError>;
    async fn request_by_transaction_id(&self, transaction_id: &str) -> Result<Request, StoreError>;
    /// Les demandes dans l'état donné, les plus anciennes d'abord. `None`
    /// les liste toutes.
    async fn requests(&self, state: Option<RequestState>) -> Result<Vec<Request>, StoreError>;
    /// Applique une transition d'état. `from` est l'état attendu avant la
    /// transition : sinon, `StoreError::Conflict` et rien n'est écrit.
    async fn update_request(&self, r: Request, from: RequestState) -> Result<(), StoreError>;

    async fn next_crl_number(&self) -> Result<i64, StoreError>;
    async fn save_crl(&self, c: Crl) -> Result<(), StoreError>;
    async fn latest_crl(&self) -> Result<Crl, StoreError>;
}

/// Implémentation en mémoire de [`Store`], destinée aux tests unitaires du
/// moteur de CA et de la machine à états d'enrôlement — reproduit les mêmes
/// contraintes que la base (unicité de série, unicité d'empreinte de CSR,
/// transition conditionnée par l'état de départ) pour que ce qui passe ici
/// passe aussi en PostgreSQL le jour venu.
#[derive(Default)]
pub struct Memory {
    inner: Mutex<MemoryState>,
}

#[derive(Default)]
struct MemoryState {
    authorities: BTreeMap<String, Authority>,
    certificates: BTreeMap<String, Certificate>,
    requests: BTreeMap<String, Request>,
    by_fingerprint: BTreeMap<String, String>,
    crls: Vec<Crl>,
    next_crl: i64,
}

impl Memory {
    pub fn new() -> Memory {
        Memory::default()
    }
}

#[async_trait::async_trait]
impl Store for Memory {
    async fn save_authority(&self, a: Authority) -> Result<(), StoreError> {
        self.inner
            .lock()
            .unwrap()
            .authorities
            .insert(a.name.clone(), a);
        Ok(())
    }

    async fn authority(&self, name: &str) -> Result<Authority, StoreError> {
        self.inner
            .lock()
            .unwrap()
            .authorities
            .get(name)
            .cloned()
            .ok_or(StoreError::NotFound)
    }

    async fn reserve_serial(&self, serial: &Serial, profile: &str) -> Result<(), StoreError> {
        let mut state = self.inner.lock().unwrap();
        let key = serial_key(serial);
        if state.certificates.contains_key(&key) {
            return Err(StoreError::SerialTaken);
        }
        state.certificates.insert(
            key,
            Certificate {
                serial: serial.clone(),
                profile: profile.to_string(),
                subject_dn: String::new(),
                issuer_dn: String::new(),
                not_before: OffsetDateTime::UNIX_EPOCH,
                not_after: OffsetDateTime::UNIX_EPOCH,
                der: Vec::new(),
                status: CertificateStatus::Reserved,
                revoked_at: None,
                revocation_reason: 0,
                request_transaction_id: String::new(),
            },
        );
        Ok(())
    }

    async fn save_certificate(&self, c: Certificate) -> Result<(), StoreError> {
        let mut state = self.inner.lock().unwrap();
        let key = serial_key(&c.serial);
        match state.certificates.get(&key) {
            None => return Err(StoreError::NotFound),
            Some(existing) if existing.status != CertificateStatus::Reserved => {
                return Err(StoreError::Conflict)
            }
            _ => {}
        }
        state.certificates.insert(key, c);
        Ok(())
    }

    async fn certificate(&self, serial: &Serial) -> Result<Certificate, StoreError> {
        let state = self.inner.lock().unwrap();
        match state.certificates.get(&serial_key(serial)) {
            Some(c) if c.status != CertificateStatus::Reserved => Ok(c.clone()),
            _ => Err(StoreError::NotFound),
        }
    }

    async fn active_by_subject(
        &self,
        subject_dn: &str,
        now: OffsetDateTime,
    ) -> Result<Vec<Certificate>, StoreError> {
        let state = self.inner.lock().unwrap();
        let mut out: Vec<Certificate> = state
            .certificates
            .values()
            .filter(|c| {
                c.status == CertificateStatus::Issued
                    && c.subject_dn == subject_dn
                    && now < c.not_after
            })
            .cloned()
            .collect();
        out.sort_by(|a, b| a.serial.cmp(&b.serial));
        Ok(out)
    }

    async fn revoke(
        &self,
        serial: &Serial,
        at: OffsetDateTime,
        reason: i32,
    ) -> Result<(), StoreError> {
        let mut state = self.inner.lock().unwrap();
        let key = serial_key(serial);
        let cert = state
            .certificates
            .get_mut(&key)
            .ok_or(StoreError::NotFound)?;
        if cert.status == CertificateStatus::Reserved {
            return Err(StoreError::NotFound);
        }
        if cert.status == CertificateStatus::Revoked {
            // Première révocation faisant foi.
            return Ok(());
        }
        cert.status = CertificateStatus::Revoked;
        cert.revoked_at = Some(at);
        cert.revocation_reason = reason;
        Ok(())
    }

    async fn revoked(
        &self,
        now: OffsetDateTime,
        grace: time::Duration,
    ) -> Result<Vec<Certificate>, StoreError> {
        let state = self.inner.lock().unwrap();
        let mut out: Vec<Certificate> = state
            .certificates
            .values()
            .filter(|c| c.status == CertificateStatus::Revoked && now <= c.not_after + grace)
            .cloned()
            .collect();
        out.sort_by(|a, b| a.serial.cmp(&b.serial));
        Ok(out)
    }

    async fn issued_serials(&self) -> Result<Vec<Serial>, StoreError> {
        let state = self.inner.lock().unwrap();
        let mut out: Vec<Serial> = state
            .certificates
            .values()
            .filter(|c| c.status != CertificateStatus::Reserved)
            .map(|c| c.serial.clone())
            .collect();
        out.sort();
        Ok(out)
    }

    async fn create_request(&self, r: Request) -> Result<(), StoreError> {
        let mut state = self.inner.lock().unwrap();
        if state.by_fingerprint.contains_key(&r.csr_fingerprint)
            || state.requests.contains_key(&r.transaction_id)
        {
            return Err(StoreError::Conflict);
        }
        state
            .by_fingerprint
            .insert(r.csr_fingerprint.clone(), r.transaction_id.clone());
        state.requests.insert(r.transaction_id.clone(), r);
        Ok(())
    }

    async fn request_by_fingerprint(&self, fingerprint: &str) -> Result<Request, StoreError> {
        let state = self.inner.lock().unwrap();
        let id = state
            .by_fingerprint
            .get(fingerprint)
            .ok_or(StoreError::NotFound)?;
        state.requests.get(id).cloned().ok_or(StoreError::NotFound)
    }

    async fn request_by_transaction_id(&self, transaction_id: &str) -> Result<Request, StoreError> {
        self.inner
            .lock()
            .unwrap()
            .requests
            .get(transaction_id)
            .cloned()
            .ok_or(StoreError::NotFound)
    }

    async fn requests(
        &self,
        state_filter: Option<RequestState>,
    ) -> Result<Vec<Request>, StoreError> {
        let state = self.inner.lock().unwrap();
        let mut out: Vec<Request> = state
            .requests
            .values()
            .filter(|r| state_filter.is_none_or(|s| r.state == s))
            .cloned()
            .collect();
        out.sort_by(|a, b| {
            a.created_at
                .cmp(&b.created_at)
                .then_with(|| a.transaction_id.cmp(&b.transaction_id))
        });
        Ok(out)
    }

    async fn update_request(&self, r: Request, from: RequestState) -> Result<(), StoreError> {
        let mut state = self.inner.lock().unwrap();
        let existing = state
            .requests
            .get(&r.transaction_id)
            .ok_or(StoreError::NotFound)?;
        if existing.state != from {
            return Err(StoreError::Conflict);
        }
        state.requests.insert(r.transaction_id.clone(), r);
        Ok(())
    }

    async fn next_crl_number(&self) -> Result<i64, StoreError> {
        let mut state = self.inner.lock().unwrap();
        state.next_crl += 1;
        Ok(state.next_crl)
    }

    async fn save_crl(&self, c: Crl) -> Result<(), StoreError> {
        self.inner.lock().unwrap().crls.push(c);
        Ok(())
    }

    async fn latest_crl(&self) -> Result<Crl, StoreError> {
        let state = self.inner.lock().unwrap();
        state
            .crls
            .iter()
            .max_by_key(|c| c.number)
            .cloned()
            .ok_or(StoreError::NotFound)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let store = Memory::new();
        let serial = vec![1u8; 16];
        store.reserve_serial(&serial, "tsa_signer").await.unwrap();
        assert!(
            matches!(store.certificate(&serial).await, Err(StoreError::NotFound)),
            "réservé mais non signé doit rester invisible"
        );

        let far_future = OffsetDateTime::UNIX_EPOCH + time::Duration::days(365 * 50);
        store
            .save_certificate(cert(
                &serial,
                "CN=test",
                CertificateStatus::Issued,
                far_future,
            ))
            .await
            .unwrap();
        let got = store.certificate(&serial).await.unwrap();
        assert_eq!(got.subject_dn, "CN=test");
    }

    #[tokio::test]
    async fn reserve_serial_twice_conflicts() {
        let store = Memory::new();
        let serial = vec![2u8; 16];
        store.reserve_serial(&serial, "tsa_signer").await.unwrap();
        assert!(matches!(
            store.reserve_serial(&serial, "tsa_signer").await,
            Err(StoreError::SerialTaken)
        ));
    }

    #[tokio::test]
    async fn revoke_is_idempotent_on_first_date() {
        let store = Memory::new();
        let serial = vec![3u8; 16];
        let far_future = OffsetDateTime::UNIX_EPOCH + time::Duration::days(365 * 50);
        store.reserve_serial(&serial, "tsa_signer").await.unwrap();
        store
            .save_certificate(cert(
                &serial,
                "CN=test",
                CertificateStatus::Issued,
                far_future,
            ))
            .await
            .unwrap();

        let first = OffsetDateTime::UNIX_EPOCH + time::Duration::days(1);
        let second = OffsetDateTime::UNIX_EPOCH + time::Duration::days(2);
        store.revoke(&serial, first, 1).await.unwrap();
        store.revoke(&serial, second, 2).await.unwrap();

        let got = store.certificate(&serial).await.unwrap();
        assert_eq!(
            got.revoked_at,
            Some(first),
            "la première révocation doit faire foi"
        );
        assert_eq!(got.revocation_reason, 1);
    }

    #[tokio::test]
    async fn create_request_rejects_duplicate_fingerprint() {
        let store = Memory::new();
        let r = Request {
            transaction_id: "tx1".to_string(),
            csr_fingerprint: "fp1".to_string(),
            csr_der: vec![],
            profile: "tsa_signer".to_string(),
            subject_cn: "test".to_string(),
            state: RequestState::Pending,
            created_at: OffsetDateTime::UNIX_EPOCH,
            decided_at: None,
            operator: String::new(),
            comment: String::new(),
            issued_at: None,
            certificate_serial: None,
        };
        store.create_request(r.clone()).await.unwrap();
        let mut dup = r.clone();
        dup.transaction_id = "tx2".to_string();
        assert!(matches!(
            store.create_request(dup).await,
            Err(StoreError::Conflict)
        ));
    }

    #[tokio::test]
    async fn update_request_requires_expected_from_state() {
        let store = Memory::new();
        let r = Request {
            transaction_id: "tx1".to_string(),
            csr_fingerprint: "fp1".to_string(),
            csr_der: vec![],
            profile: "tsa_signer".to_string(),
            subject_cn: "test".to_string(),
            state: RequestState::Pending,
            created_at: OffsetDateTime::UNIX_EPOCH,
            decided_at: None,
            operator: String::new(),
            comment: String::new(),
            issued_at: None,
            certificate_serial: None,
        };
        store.create_request(r.clone()).await.unwrap();

        let mut approved = r.clone();
        approved.state = RequestState::Approved;
        assert!(matches!(
            store
                .update_request(approved.clone(), RequestState::Rejected)
                .await,
            Err(StoreError::Conflict)
        ));
        store
            .update_request(approved, RequestState::Pending)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn crl_numbers_increase_and_latest_wins() {
        let store = Memory::new();
        assert_eq!(store.next_crl_number().await.unwrap(), 1);
        assert_eq!(store.next_crl_number().await.unwrap(), 2);

        store
            .save_crl(Crl {
                number: 1,
                der: vec![],
                this_update: OffsetDateTime::UNIX_EPOCH,
                next_update: OffsetDateTime::UNIX_EPOCH,
            })
            .await
            .unwrap();
        store
            .save_crl(Crl {
                number: 2,
                der: vec![9],
                this_update: OffsetDateTime::UNIX_EPOCH,
                next_update: OffsetDateTime::UNIX_EPOCH,
            })
            .await
            .unwrap();
        assert_eq!(store.latest_crl().await.unwrap().number, 2);
    }
}
