//! Vérifie contre une vraie instance PostgreSQL les invariants du registre des
//! opérateurs (migration 0002, docs/WEBUI.md §2, §16). Ils sont portés par la
//! base, pas par le code appelant : ces tests attaquent donc la base
//! directement, en SQL, sans passer par une API applicative qui pourrait les
//! respecter par politesse.
//!
//! Même mécanique que `postgres.rs` : DSN dans `OE_CASTORE_TEST_DSN`, test
//! ignoré si elle n'est pas définie.
#![cfg(feature = "postgres")]

use oe_castore::Postgres;
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use std::sync::atomic::{AtomicU64, Ordering};

static SEQ: AtomicU64 = AtomicU64::new(0);

fn unique(prefix: &str) -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!("{prefix}-{nanos}-{}", SEQ.fetch_add(1, Ordering::Relaxed))
}

async fn pool() -> Option<PgPool> {
    let dsn = std::env::var("OE_CASTORE_TEST_DSN").ok()?;
    // Ouvre le magasin pour appliquer les migrations, comme en production.
    Postgres::open(&dsn).await.expect("connexion et migration");
    Some(
        PgPoolOptions::new()
            .max_connections(4)
            .connect(&dsn)
            .await
            .expect("pool de test"),
    )
}

macro_rules! require_pool {
    () => {
        match pool().await {
            Some(p) => p,
            None => {
                eprintln!("OE_CASTORE_TEST_DSN non définie : test PostgreSQL ignoré");
                return;
            }
        }
    };
}

fn sqlstate(e: &sqlx::Error) -> Option<String> {
    match e {
        sqlx::Error::Database(db) => db.code().map(|c| c.to_string()),
        _ => None,
    }
}

fn constraint(e: &sqlx::Error) -> Option<String> {
    match e {
        sqlx::Error::Database(db) => db.constraint().map(str::to_string),
        _ => None,
    }
}

async fn insert_operator(pool: &PgPool, role: &str) -> String {
    sqlx::query_scalar(
        "INSERT INTO operators (id, name, role, created_at, created_by)
         VALUES (gen_random_uuid(), $1, $2, now(), 'test') RETURNING id::text",
    )
    .bind(unique("op"))
    .bind(role)
    .fetch_one(pool)
    .await
    .expect("opérateur")
}

struct Cred<'a> {
    operator: &'a str,
    id: String,
    attestation_format: &'a str,
    backup_eligible: bool,
    initiated_by: &'a str,
    confirmed: bool,
}

impl<'a> Cred<'a> {
    /// Une clé valide : attestée, non copiable, confirmée.
    fn valid(operator: &'a str) -> Self {
        Cred {
            operator,
            id: unique("cred"),
            attestation_format: "packed",
            backup_eligible: false,
            initiated_by: "admin-test",
            confirmed: true,
        }
    }

    async fn insert(&self, pool: &PgPool) -> Result<(), sqlx::Error> {
        sqlx::query(
            "INSERT INTO webauthn_credentials
               (credential_id, operator_id, public_key, aaguid, attestation_format,
                attestation_object, backup_eligible, initiated_by, initiated_at,
                confirmed_by, confirmed_at, passkey)
             VALUES ($1, $2::uuid, '\\x00', gen_random_uuid(), $3, '\\x00', $4, $5, now(),
                     CASE WHEN $6 THEN 'admin-test' END,
                     CASE WHEN $6 THEN now() END, '{}'::jsonb)",
        )
        .bind(&self.id)
        .bind(self.operator)
        .bind(self.attestation_format)
        .bind(self.backup_eligible)
        .bind(self.initiated_by)
        .bind(self.confirmed)
        .execute(pool)
        .await
        .map(|_| ())
    }
}

#[tokio::test]
async fn a_key_without_attestation_never_enters_the_registry() {
    let pool = require_pool!();
    let op = insert_operator(&pool, "admin").await;
    let mut c = Cred::valid(&op);
    c.attestation_format = "none";
    let err = c
        .insert(&pool)
        .await
        .expect_err("attestation « none » refusée");
    assert_eq!(constraint(&err).as_deref(), Some("attestation_required"));
}

#[tokio::test]
async fn a_copyable_key_never_enters_the_registry() {
    let pool = require_pool!();
    let op = insert_operator(&pool, "admin").await;
    let mut c = Cred::valid(&op);
    c.backup_eligible = true;
    let err = c
        .insert(&pool)
        .await
        .expect_err("clé synchronisable refusée");
    assert_eq!(constraint(&err).as_deref(), Some("not_backup_eligible"));
}

#[tokio::test]
async fn a_key_is_active_only_once_confirmed_except_for_the_first_admin() {
    let pool = require_pool!();
    let op = insert_operator(&pool, "admin").await;

    let mut unconfirmed = Cred::valid(&op);
    unconfirmed.confirmed = false;
    let err = unconfirmed
        .insert(&pool)
        .await
        .expect_err("une clé non confirmée ne peut pas être dans le registre");
    assert_eq!(
        constraint(&err).as_deref(),
        Some("credential_confirmed_before_active")
    );

    Cred::valid(&op).insert(&pool).await.expect("clé confirmée");

    // Le tout premier administrateur est amorcé localement, sans confirmant.
    let mut bootstrap = Cred::valid(&op);
    bootstrap.confirmed = false;
    bootstrap.initiated_by = "bootstrap-admin";
    bootstrap.insert(&pool).await.expect("amorçage local");
}

/// Prépare une action avec `n` challenges distincts et renvoie leurs
/// identifiants (texte) avec celui de l'action.
async fn action_with_challenges(pool: &PgPool, n: usize) -> (String, Vec<String>) {
    let action: String = sqlx::query_scalar(
        "INSERT INTO actions (id, body, body_hash, created_at, expires_at)
         VALUES (gen_random_uuid(), '{\"action\":\"test\"}', '\\x00', now(), now() + interval '5 minutes')
         RETURNING id::text",
    )
    .fetch_one(pool)
    .await
    .expect("action");
    let mut challenges = Vec::new();
    for _ in 0..n {
        let id: String = sqlx::query_scalar(
            "INSERT INTO action_challenges (challenge_id, action_id, challenge, issued_at, expires_at)
             VALUES (gen_random_uuid(), $1::uuid, sha256(uuid_send(gen_random_uuid())), now(), now() + interval '5 minutes')
             RETURNING challenge_id::text",
        )
        .bind(&action)
        .fetch_one(pool)
        .await
        .expect("challenge");
        challenges.push(id);
    }
    (action, challenges)
}

async fn insert_evidence(
    pool: &PgPool,
    challenge: &str,
    action: &str,
    operator: &str,
    credential: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO decision_evidence
           (id, challenge_id, action_id, operator_id, credential_id,
            authenticator_data, client_data_json, signature, verified_at)
         VALUES (gen_random_uuid(), $1::uuid, $2::uuid, $3::uuid, $4, '\\x00', '\\x00', '\\x00', now())",
    )
    .bind(challenge)
    .bind(action)
    .bind(operator)
    .bind(credential)
    .execute(pool)
    .await
    .map(|_| ())
}

#[tokio::test]
async fn an_operator_counts_only_once_per_action() {
    let pool = require_pool!();
    let a = insert_operator(&pool, "ca_operateur").await;
    let b = insert_operator(&pool, "ca_operateur").await;
    let cred_a = Cred::valid(&a);
    let cred_a2 = Cred::valid(&a); // même opérateur, seconde clé
    let cred_b = Cred::valid(&b);
    cred_a.insert(&pool).await.unwrap();
    cred_a2.insert(&pool).await.unwrap();
    cred_b.insert(&pool).await.unwrap();

    let (action, ch) = action_with_challenges(&pool, 3).await;

    insert_evidence(&pool, &ch[0], &action, &a, &cred_a.id)
        .await
        .expect("première signature de A");

    // Deux clés à lui ne font pas deux personnes (WEBUI.md §8).
    let err = insert_evidence(&pool, &ch[1], &action, &a, &cred_a2.id)
        .await
        .expect_err("A ne peut pas signer deux fois la même action");
    assert_eq!(sqlstate(&err).as_deref(), Some("23505"));
    assert_eq!(
        constraint(&err).as_deref(),
        Some("decision_evidence_action_id_operator_id_key")
    );

    insert_evidence(&pool, &ch[2], &action, &b, &cred_b.id)
        .await
        .expect("B est un autre opérateur");
}

#[tokio::test]
async fn a_challenge_is_recorded_once_and_its_evidence_at_most_once() {
    let pool = require_pool!();
    let a = insert_operator(&pool, "admin").await;
    let cred = Cred::valid(&a);
    cred.insert(&pool).await.unwrap();
    let (action, ch) = action_with_challenges(&pool, 1).await;

    insert_evidence(&pool, &ch[0], &action, &a, &cred.id)
        .await
        .expect("preuve");

    // Une seconde preuve pour le même challenge est un rejeu.
    let b = insert_operator(&pool, "admin").await;
    let cred_b = Cred::valid(&b);
    cred_b.insert(&pool).await.unwrap();
    let err = insert_evidence(&pool, &ch[0], &action, &b, &cred_b.id)
        .await
        .expect_err("un challenge ne produit qu'une preuve");
    assert_eq!(sqlstate(&err).as_deref(), Some("23505"));
}

const GRANTS: &str = include_str!("../sql/ra_console_grants.sql");

/// Faille R2a (WEBUI.md §16) : sous le rôle de `ra-console`, aucune écriture
/// sur les tables de `ca-server`, et aucune lecture des hachés de jetons. Le
/// refus doit venir de PostgreSQL (42501), pas d'une convention de code.
#[tokio::test]
async fn ra_console_role_cannot_write_ca_tables() {
    let pool = require_pool!();
    sqlx::raw_sql(GRANTS)
        .execute(&pool)
        .await
        .expect("application des droits");

    let mut conn = pool.acquire().await.expect("connexion");
    sqlx::query("SET ROLE openeidas_ra_console")
        .execute(&mut *conn)
        .await
        .expect("SET ROLE");

    let writes = [
        // Écrire une approbation : le scénario de la faille.
        "UPDATE enrollment_requests SET state = 'APPROVED'",
        "DELETE FROM certificates",
        "UPDATE certificates SET status = 'revoked'",
        // S'inscrire une clé, ou une invitation, ou un rôle.
        "INSERT INTO webauthn_credentials (credential_id) VALUES ('x')",
        "INSERT INTO operators (id, name, role, created_at, created_by) \
         VALUES (gen_random_uuid(), 'pirate', 'admin', now(), 'x')",
        "UPDATE operators SET role = 'admin'",
        "INSERT INTO operator_invites (id) VALUES (gen_random_uuid())",
        "INSERT INTO decision_evidence (id) VALUES (gen_random_uuid())",
        "INSERT INTO actions (id) VALUES (gen_random_uuid())",
    ];
    for sql in writes {
        let err = sqlx::query(sql)
            .execute(&mut *conn)
            .await
            .expect_err(&format!("écriture autorisée à tort : {sql}"));
        assert_eq!(
            sqlstate(&err).as_deref(),
            Some("42501"),
            "{sql} : attendu « permission denied », obtenu {err}"
        );
    }

    // Aucune lecture des tables sans droit : hachés de jetons, challenges,
    // autorités, CRL.
    for table in [
        "operator_invites",
        "action_challenges",
        "authorities",
        "crls",
    ] {
        let err = sqlx::query(&format!("SELECT count(*) FROM {table}"))
            .fetch_one(&mut *conn)
            .await
            .expect_err(&format!("lecture autorisée à tort : {table}"));
        assert_eq!(sqlstate(&err).as_deref(), Some("42501"), "{table}");
    }

    // La lecture, elle, fonctionne : c'est ce dont la console a besoin.
    for table in [
        // La salle d'attente des actions à plusieurs signatures (§8).
        "actions",
        "enrollment_requests",
        "certificates",
        "operators",
        "webauthn_credentials",
        "pending_credentials",
        "decision_evidence",
    ] {
        sqlx::query(&format!("SELECT count(*) FROM {table}"))
            .fetch_one(&mut *conn)
            .await
            .unwrap_or_else(|e| panic!("lecture refusée à tort sur {table} : {e}"));
    }

    // Ses propres tables : lecture et écriture, sans quoi la console ne tient
    // ni session ni challenge. (Les clés étrangères vers le registre supposent le
    // droit REFERENCES, jamais un droit d'écriture.)
    for table in ["webauthn_challenges", "sessions", "login_counters"] {
        for privilege in ["SELECT", "INSERT", "UPDATE", "DELETE"] {
            let allowed: bool =
                sqlx::query_scalar("SELECT has_table_privilege(current_user, $1, $2)")
                    .bind(table)
                    .bind(privilege)
                    .fetch_one(&mut *conn)
                    .await
                    .unwrap();
            assert!(allowed, "{privilege} sur {table} devrait être accordé");
        }
    }
    // Et rien de plus : ni ses tables, ni celles de ca-server ne lui donnent le
    // droit de les redéfinir ou de les vider.
    for table in ["operators", "webauthn_credentials", "webauthn_challenges"] {
        for privilege in ["TRUNCATE", "TRIGGER"] {
            let allowed: bool =
                sqlx::query_scalar("SELECT has_table_privilege(current_user, $1, $2)")
                    .bind(table)
                    .bind(privilege)
                    .fetch_one(&mut *conn)
                    .await
                    .unwrap();
            assert!(
                !allowed,
                "{privilege} sur {table} ne devrait pas être accordé"
            );
        }
    }

    sqlx::query("RESET ROLE").execute(&mut *conn).await.unwrap();
}

/// Les invariants des tables de ra-console sont portés par la base, comme ceux du
/// registre : un challenge de plus de 5 minutes, ou une action sans opérateur,
/// sont refusés par PostgreSQL et non par une convention de code.
#[tokio::test]
async fn ra_console_tables_enforce_their_invariants() {
    let pool = require_pool!();
    let insert = |kind: &'static str, operator: Option<&'static str>, minutes: i32| {
        let pool = pool.clone();
        async move {
            sqlx::query(
                "INSERT INTO webauthn_challenges (id, kind, challenge, operator_id, created_at, expires_at)
                 VALUES (gen_random_uuid(), $1, '\\x01', $2::uuid, now(), now() + make_interval(mins => $3))",
            )
            .bind(kind)
            .bind(operator)
            .bind(minutes)
            .execute(&pool)
            .await
        }
    };

    // Un challenge de connexion, court, sans opérateur encore identifié.
    insert("login", None, 5)
        .await
        .expect("challenge de connexion");
    // Plus de 5 minutes : refusé.
    let err = insert("login", None, 6)
        .await
        .expect_err("challenge trop long");
    assert_eq!(sqlstate(&err).as_deref(), Some("23514"));
    // Un enregistrement ou une action sans opérateur : refusé.
    for kind in ["register", "action"] {
        let err = insert(kind, None, 5)
            .await
            .expect_err("opérateur obligatoire");
        assert_eq!(sqlstate(&err).as_deref(), Some("23514"), "{kind}");
    }
    // Un type inconnu : refusé.
    let err = insert("autre", None, 5).await.expect_err("type inconnu");
    assert_eq!(sqlstate(&err).as_deref(), Some("23514"));
}
