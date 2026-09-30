//! Implémentation de [`Store`] adossée à PostgreSQL — portage de
//! `internal/castore/postgres.go`, utilisée en exploitation. Les contraintes
//! d'intégrité (unicité du numéro de série, unicité de l'empreinte de CSR,
//! imputabilité de la décision d'approbation) sont portées par le schéma
//! (`migrations/0001_schema.sql`, repris tel quel du binaire Go) et non
//! seulement par le code : une écriture fautive est refusée par la base, y
//! compris si elle vient d'ailleurs.
//!
//! Derrière la feature Cargo `postgres` : `oe-raflow`/`oe-ca-core` ne
//! dépendent que du trait [`Store`], jamais de cette implémentation, et
//! n'ont donc aucune raison de tirer `sqlx`.

use sqlx::postgres::PgPoolOptions;
use sqlx::{PgPool, Row};
use time::OffsetDateTime;

use crate::{
    serial_key, Authority, Certificate, CertificateStatus, Crl, Request, RequestState, Serial,
    Store, StoreError,
};

fn map_err(e: sqlx::Error) -> StoreError {
    StoreError::Other(e.to_string())
}

/// SQLSTATE 23505 : seul moyen fiable de distinguer une collision de clé
/// d'une véritable panne.
fn is_unique_violation(e: &sqlx::Error) -> bool {
    matches!(e, sqlx::Error::Database(db) if db.code().as_deref() == Some("23505"))
}

fn status_str(s: CertificateStatus) -> &'static str {
    match s {
        CertificateStatus::Reserved => "reserved",
        CertificateStatus::Issued => "issued",
        CertificateStatus::Revoked => "revoked",
    }
}

fn status_from_str(s: &str) -> Result<CertificateStatus, StoreError> {
    match s {
        "reserved" => Ok(CertificateStatus::Reserved),
        "issued" => Ok(CertificateStatus::Issued),
        "revoked" => Ok(CertificateStatus::Revoked),
        other => Err(StoreError::Other(format!(
            "castore: statut de certificat illisible en base: {other:?}"
        ))),
    }
}

fn state_from_str(s: &str) -> Result<RequestState, StoreError> {
    match s {
        "PENDING" => Ok(RequestState::Pending),
        "APPROVED" => Ok(RequestState::Approved),
        "ISSUED" => Ok(RequestState::Issued),
        "REJECTED" => Ok(RequestState::Rejected),
        other => Err(StoreError::Other(format!(
            "castore: état de demande illisible en base: {other:?}"
        ))),
    }
}

fn serial_from_hex(s: &str) -> Result<Serial, StoreError> {
    hex::decode(s)
        .map_err(|e| StoreError::Other(format!("castore: numéro de série illisible en base: {e}")))
}

/// Implémentation de [`Store`] adossée à PostgreSQL, utilisée en
/// exploitation.
pub struct Postgres {
    pool: PgPool,
}

impl Postgres {
    /// Établit le pool de connexions et applique les migrations
    /// (`migrations/0001_schema.sql`, embarquée dans le binaire).
    pub async fn open(dsn: &str) -> Result<Postgres, StoreError> {
        let pool = PgPoolOptions::new()
            .connect(dsn)
            .await
            .map_err(|e| StoreError::Other(format!("castore: connexion à PostgreSQL: {e}")))?;
        sqlx::migrate!("./migrations")
            .run(&pool)
            .await
            .map_err(|e| StoreError::Other(format!("castore: migration: {e}")))?;
        Ok(Postgres { pool })
    }

    fn certificate_from_row(row: sqlx::postgres::PgRow) -> Result<Certificate, StoreError> {
        let status: String = row.try_get("status").map_err(map_err)?;
        Ok(Certificate {
            serial: serial_from_hex(
                row.try_get::<String, _>("serial_hex")
                    .map_err(map_err)?
                    .as_str(),
            )?,
            profile: row.try_get("profile").map_err(map_err)?,
            subject_dn: row.try_get("subject_dn").map_err(map_err)?,
            issuer_dn: row.try_get("issuer_dn").map_err(map_err)?,
            not_before: row
                .try_get::<Option<OffsetDateTime>, _>("not_before")
                .map_err(map_err)?
                .unwrap_or(OffsetDateTime::UNIX_EPOCH),
            not_after: row
                .try_get::<Option<OffsetDateTime>, _>("not_after")
                .map_err(map_err)?
                .unwrap_or(OffsetDateTime::UNIX_EPOCH),
            der: row
                .try_get::<Option<Vec<u8>>, _>("der")
                .map_err(map_err)?
                .unwrap_or_default(),
            status: status_from_str(&status)?,
            revoked_at: row.try_get("revoked_at").map_err(map_err)?,
            revocation_reason: row.try_get("revocation_reason").map_err(map_err)?,
            request_transaction_id: row.try_get("request_transaction_id").map_err(map_err)?,
        })
    }

    fn request_from_row(row: sqlx::postgres::PgRow) -> Result<Request, StoreError> {
        let state: String = row.try_get("state").map_err(map_err)?;
        let serial_hex: Option<String> = row.try_get("certificate_serial_hex").map_err(map_err)?;
        let certificate_serial = match serial_hex {
            Some(s) if !s.is_empty() => Some(serial_from_hex(&s)?),
            _ => None,
        };
        Ok(Request {
            transaction_id: row.try_get("transaction_id").map_err(map_err)?,
            csr_fingerprint: row.try_get("csr_fingerprint").map_err(map_err)?,
            csr_der: row.try_get("csr_der").map_err(map_err)?,
            profile: row.try_get("profile").map_err(map_err)?,
            subject_cn: row.try_get("subject_cn").map_err(map_err)?,
            state: state_from_str(&state)?,
            created_at: row.try_get("created_at").map_err(map_err)?,
            decided_at: row.try_get("decided_at").map_err(map_err)?,
            operator: row.try_get("operator").map_err(map_err)?,
            comment: row.try_get("comment").map_err(map_err)?,
            issued_at: row.try_get("issued_at").map_err(map_err)?,
            certificate_serial,
        })
    }
}

const CERTIFICATE_COLUMNS: &str = "serial_hex, profile, subject_dn, issuer_dn, \
    not_before, not_after, der, status, revoked_at, revocation_reason, \
    request_transaction_id";

const REQUEST_COLUMNS: &str = "transaction_id, csr_fingerprint, csr_der, profile, \
    subject_cn, state, created_at, decided_at, operator, comment, issued_at, \
    certificate_serial_hex";

#[async_trait::async_trait]
impl Store for Postgres {
    async fn save_authority(&self, a: Authority) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO authorities (name, subject_dn, der, token_label, key_label, created_at)
             VALUES ($1, $2, $3, $4, $5, $6)
             ON CONFLICT (name) DO UPDATE SET
                 subject_dn = EXCLUDED.subject_dn,
                 der        = EXCLUDED.der,
                 token_label = EXCLUDED.token_label,
                 key_label   = EXCLUDED.key_label",
        )
        .bind(&a.name)
        .bind(&a.subject_dn)
        .bind(&a.der)
        .bind(&a.token_label)
        .bind(&a.key_label)
        .bind(a.created_at)
        .execute(&self.pool)
        .await
        .map_err(map_err)?;
        Ok(())
    }

    async fn authority(&self, name: &str) -> Result<Authority, StoreError> {
        let row = sqlx::query("SELECT name, subject_dn, der, token_label, key_label, created_at FROM authorities WHERE name = $1")
            .bind(name)
            .fetch_optional(&self.pool)
            .await
            .map_err(map_err)?
            .ok_or(StoreError::NotFound)?;
        Ok(Authority {
            name: row.try_get("name").map_err(map_err)?,
            subject_dn: row.try_get("subject_dn").map_err(map_err)?,
            der: row.try_get("der").map_err(map_err)?,
            token_label: row.try_get("token_label").map_err(map_err)?,
            key_label: row.try_get("key_label").map_err(map_err)?,
            created_at: row.try_get("created_at").map_err(map_err)?,
        })
    }

    async fn reserve_serial(&self, serial: &Serial, profile: &str) -> Result<(), StoreError> {
        let result = sqlx::query(
            "INSERT INTO certificates (serial_hex, profile, status) VALUES ($1, $2, 'reserved')",
        )
        .bind(serial_key(serial))
        .bind(profile)
        .execute(&self.pool)
        .await;
        match result {
            Ok(_) => Ok(()),
            Err(e) if is_unique_violation(&e) => Err(StoreError::SerialTaken),
            Err(e) => Err(map_err(e)),
        }
    }

    async fn save_certificate(&self, c: Certificate) -> Result<(), StoreError> {
        let tag = sqlx::query(
            "UPDATE certificates SET
                 profile = $2, subject_dn = $3, issuer_dn = $4,
                 not_before = $5, not_after = $6, der = $7, status = $8,
                 request_transaction_id = $9
             WHERE serial_hex = $1 AND status = 'reserved'",
        )
        .bind(serial_key(&c.serial))
        .bind(&c.profile)
        .bind(&c.subject_dn)
        .bind(&c.issuer_dn)
        .bind(c.not_before)
        .bind(c.not_after)
        .bind(&c.der)
        .bind(status_str(c.status))
        .bind(&c.request_transaction_id)
        .execute(&self.pool)
        .await
        .map_err(map_err)?;
        if tag.rows_affected() == 0 {
            // Soit la réservation n'existe pas, soit elle a déjà été
            // complétée : dans les deux cas, écraser serait pire que refuser.
            return Err(StoreError::Conflict);
        }
        Ok(())
    }

    async fn certificate(&self, serial: &Serial) -> Result<Certificate, StoreError> {
        let row = sqlx::query(&format!("SELECT {CERTIFICATE_COLUMNS} FROM certificates WHERE serial_hex = $1 AND status <> 'reserved'"))
            .bind(serial_key(serial))
            .fetch_optional(&self.pool)
            .await
            .map_err(map_err)?
            .ok_or(StoreError::NotFound)?;
        Self::certificate_from_row(row)
    }

    async fn active_by_subject(
        &self,
        subject_dn: &str,
        now: OffsetDateTime,
    ) -> Result<Vec<Certificate>, StoreError> {
        let rows = sqlx::query(&format!(
            "SELECT {CERTIFICATE_COLUMNS} FROM certificates
             WHERE status = 'issued' AND subject_dn = $1 AND not_after > $2
             ORDER BY serial_hex"
        ))
        .bind(subject_dn)
        .bind(now)
        .fetch_all(&self.pool)
        .await
        .map_err(map_err)?;
        rows.into_iter().map(Self::certificate_from_row).collect()
    }

    async fn revoke(
        &self,
        serial: &Serial,
        at: OffsetDateTime,
        reason: i32,
    ) -> Result<(), StoreError> {
        let key = serial_key(serial);
        // La clause status = 'issued' rend l'opération idempotente ET
        // protège la date de première révocation : une seconde révocation
        // ne la repousse pas.
        let tag = sqlx::query("UPDATE certificates SET status = 'revoked', revoked_at = $2, revocation_reason = $3 WHERE serial_hex = $1 AND status = 'issued'")
            .bind(&key)
            .bind(at)
            .bind(reason)
            .execute(&self.pool)
            .await
            .map_err(map_err)?;
        if tag.rows_affected() == 1 {
            return Ok(());
        }
        // Aucune ligne modifiée : soit le certificat est déjà révoqué (sans
        // erreur), soit il n'existe pas (NotFound).
        let status: Option<String> =
            sqlx::query_scalar("SELECT status FROM certificates WHERE serial_hex = $1")
                .bind(&key)
                .fetch_optional(&self.pool)
                .await
                .map_err(map_err)?;
        match status.as_deref() {
            None | Some("reserved") => Err(StoreError::NotFound),
            _ => Ok(()),
        }
    }

    async fn revoked(
        &self,
        now: OffsetDateTime,
        grace: time::Duration,
    ) -> Result<Vec<Certificate>, StoreError> {
        let rows = sqlx::query(&format!(
            "SELECT {CERTIFICATE_COLUMNS} FROM certificates
             WHERE status = 'revoked' AND not_after + $2::interval >= $1
             ORDER BY serial_hex"
        ))
        .bind(now)
        .bind(format!("{} seconds", grace.whole_seconds()))
        .fetch_all(&self.pool)
        .await
        .map_err(map_err)?;
        rows.into_iter().map(Self::certificate_from_row).collect()
    }

    async fn issued_serials(&self) -> Result<Vec<Serial>, StoreError> {
        let rows: Vec<(String,)> = sqlx::query_as(
            "SELECT serial_hex FROM certificates WHERE status <> 'reserved' ORDER BY serial_hex",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(map_err)?;
        rows.into_iter()
            .map(|(hex_str,)| hex::decode(hex_str).map_err(|e| StoreError::Other(e.to_string())))
            .collect()
    }

    async fn create_request(&self, r: Request) -> Result<(), StoreError> {
        let result = sqlx::query(
            "INSERT INTO enrollment_requests
                 (transaction_id, csr_fingerprint, csr_der, profile, subject_cn, state, created_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7)",
        )
        .bind(&r.transaction_id)
        .bind(&r.csr_fingerprint)
        .bind(&r.csr_der)
        .bind(&r.profile)
        .bind(&r.subject_cn)
        .bind(r.state.to_string())
        .bind(r.created_at)
        .execute(&self.pool)
        .await;
        match result {
            Ok(_) => Ok(()),
            Err(e) if is_unique_violation(&e) => Err(StoreError::Conflict),
            Err(e) => Err(map_err(e)),
        }
    }

    async fn request_by_fingerprint(&self, fingerprint: &str) -> Result<Request, StoreError> {
        let row = sqlx::query(&format!(
            "SELECT {REQUEST_COLUMNS} FROM enrollment_requests WHERE csr_fingerprint = $1"
        ))
        .bind(fingerprint)
        .fetch_optional(&self.pool)
        .await
        .map_err(map_err)?
        .ok_or(StoreError::NotFound)?;
        Self::request_from_row(row)
    }

    async fn request_by_transaction_id(&self, transaction_id: &str) -> Result<Request, StoreError> {
        let row = sqlx::query(&format!(
            "SELECT {REQUEST_COLUMNS} FROM enrollment_requests WHERE transaction_id = $1"
        ))
        .bind(transaction_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(map_err)?
        .ok_or(StoreError::NotFound)?;
        Self::request_from_row(row)
    }

    async fn requests(&self, state: Option<RequestState>) -> Result<Vec<Request>, StoreError> {
        let rows = match state {
            Some(s) => {
                sqlx::query(&format!("SELECT {REQUEST_COLUMNS} FROM enrollment_requests WHERE state = $1 ORDER BY created_at, transaction_id")).bind(s.to_string()).fetch_all(&self.pool).await
            }
            None => sqlx::query(&format!("SELECT {REQUEST_COLUMNS} FROM enrollment_requests ORDER BY created_at, transaction_id")).fetch_all(&self.pool).await,
        }
        .map_err(map_err)?;
        rows.into_iter().map(Self::request_from_row).collect()
    }

    async fn update_request(&self, r: Request, from: RequestState) -> Result<(), StoreError> {
        let serial_hex = r.certificate_serial.as_deref().map(serial_key);
        // La clause state = $2 est le verrou optimiste : deux opérateurs qui
        // décident simultanément ne peuvent pas appliquer deux transitions à
        // la même demande, le second obtient StoreError::Conflict.
        let tag = sqlx::query(
            "UPDATE enrollment_requests SET
                 state = $3, decided_at = $4, operator = $5, comment = $6,
                 issued_at = $7, certificate_serial_hex = $8
             WHERE transaction_id = $1 AND state = $2",
        )
        .bind(&r.transaction_id)
        .bind(from.to_string())
        .bind(r.state.to_string())
        .bind(r.decided_at)
        .bind(&r.operator)
        .bind(&r.comment)
        .bind(r.issued_at)
        .bind(serial_hex)
        .execute(&self.pool)
        .await
        .map_err(map_err)?;
        if tag.rows_affected() == 0 {
            let exists: bool = sqlx::query_scalar(
                "SELECT EXISTS (SELECT 1 FROM enrollment_requests WHERE transaction_id = $1)",
            )
            .bind(&r.transaction_id)
            .fetch_one(&self.pool)
            .await
            .map_err(map_err)?;
            return Err(if exists {
                StoreError::Conflict
            } else {
                StoreError::NotFound
            });
        }
        Ok(())
    }

    async fn next_crl_number(&self) -> Result<i64, StoreError> {
        let n: i64 = sqlx::query_scalar("SELECT nextval('crl_number_seq')")
            .fetch_one(&self.pool)
            .await
            .map_err(map_err)?;
        Ok(n)
    }

    async fn save_crl(&self, c: Crl) -> Result<(), StoreError> {
        let result = sqlx::query(
            "INSERT INTO crls (number, der, this_update, next_update) VALUES ($1, $2, $3, $4)",
        )
        .bind(c.number)
        .bind(&c.der)
        .bind(c.this_update)
        .bind(c.next_update)
        .execute(&self.pool)
        .await;
        match result {
            Ok(_) => Ok(()),
            Err(e) if is_unique_violation(&e) => Err(StoreError::Conflict),
            Err(e) => Err(map_err(e)),
        }
    }

    async fn latest_crl(&self) -> Result<Crl, StoreError> {
        let row = sqlx::query(
            "SELECT number, der, this_update, next_update FROM crls ORDER BY number DESC LIMIT 1",
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_err)?
        .ok_or(StoreError::NotFound)?;
        Ok(Crl {
            number: row.try_get("number").map_err(map_err)?,
            der: row.try_get("der").map_err(map_err)?,
            this_update: row.try_get("this_update").map_err(map_err)?,
            next_update: row.try_get("next_update").map_err(map_err)?,
        })
    }
}
