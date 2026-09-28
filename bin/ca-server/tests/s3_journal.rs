//! Câblage du journal d'audit sur un stockage S3-compatible auto-hébergé
//! (docs/WEBUI.md §7, §15 étape 2b) : exécute le vrai binaire `ca-server`
//! contre un PostgreSQL et un serveur HTTP qui se comporte comme un service
//! S3-compatible (même contrainte que `crates/oe-s3/tests/client.rs` : pas
//! d'image MinIO disponible dans cet environnement).
//!
//! Deux preuves :
//! - configuré, `OPENEIDAS_S3_*` fait recevoir au stockage objet une copie
//!   exacte du journal local à chaque écriture ;
//! - si l'envoi échoue, l'opération qui en dépend échoue aussi : rien n'est
//!   commité en base (pas seulement « une erreur est rendue »).
//!
//! DSN dans `OE_CASTORE_TEST_DSN` ; test ignoré si elle n'est pas définie.

use axum::extract::{Path, State};
use axum::http::{Method, StatusCode};
use axum::routing::any;
use axum::Router;
use sqlx::postgres::PgPoolOptions;
use std::collections::HashMap;
use std::process::Command;
use std::sync::{Arc, Mutex};

#[derive(Default)]
struct Objects(Mutex<HashMap<String, Vec<u8>>>);

async fn handle_ok(
    State(objects): State<Arc<Objects>>,
    method: Method,
    Path((bucket, key)): Path<(String, String)>,
    uri: axum::http::Uri,
    body: axum::body::Bytes,
) -> (StatusCode, Vec<u8>) {
    assert!(
        uri.query().unwrap_or("").contains("X-Amz-Signature"),
        "requête non signée : {uri}"
    );
    let full_key = format!("{bucket}/{key}");
    match method {
        Method::PUT => {
            objects.0.lock().unwrap().insert(full_key, body.to_vec());
            (StatusCode::OK, Vec::new())
        }
        Method::GET => match objects.0.lock().unwrap().get(&full_key) {
            Some(bytes) => (StatusCode::OK, bytes.clone()),
            None => (StatusCode::NOT_FOUND, Vec::new()),
        },
        _ => (StatusCode::METHOD_NOT_ALLOWED, Vec::new()),
    }
}

/// Un service S3 toujours en panne : exerce le chemin de blocage.
async fn handle_failing() -> StatusCode {
    StatusCode::INTERNAL_SERVER_ERROR
}

async fn serve(app: Router) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    format!("http://{addr}")
}

struct Fixture {
    dsn: String,
    audit: std::path::PathBuf,
}

async fn fixture(prefix: &str) -> Option<Fixture> {
    let base = std::env::var("OE_CASTORE_TEST_DSN").ok()?;
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let name = format!("{prefix}_{nanos}");
    let admin = PgPoolOptions::new().connect(&base).await.unwrap();
    sqlx::query(&format!("CREATE DATABASE {name}"))
        .execute(&admin)
        .await
        .unwrap();
    let dsn = format!("{}/{name}", base.rsplit_once('/').unwrap().0);
    Some(Fixture {
        audit: std::env::temp_dir().join(format!("{name}.audit.log")),
        dsn,
    })
}

impl Fixture {
    /// Lance `operators bootstrap-admin`, avec le stockage S3 donné en plus
    /// des variables déjà exigées par `bootstrap_cli.rs`.
    fn run_bootstrap(&self, name: &str, s3_endpoint: &str) -> std::process::Output {
        Command::new(env!("CARGO_BIN_EXE_ca-server"))
            .args(["operators", "bootstrap-admin", name])
            .env("OPENEIDAS_DB_DSN", &self.dsn)
            .env("OPENEIDAS_AUDIT_FILE", &self.audit)
            .env("OPENEIDAS_S3_ENDPOINT", s3_endpoint)
            .env("OPENEIDAS_S3_BUCKET", "audit")
            .env("OPENEIDAS_S3_ACCESS_KEY", "test")
            .env("OPENEIDAS_S3_SECRET_KEY", "test-secret-au-moins-16-octets")
            .env("OPENEIDAS_S3_KEY", "ca-server/audit.log")
            .output()
            .expect("lancement de ca-server")
    }

    async fn operator_exists(&self, name: &str) -> bool {
        let pool = PgPoolOptions::new().connect(&self.dsn).await.unwrap();
        sqlx::query_scalar::<_, bool>("SELECT EXISTS (SELECT 1 FROM operators WHERE name = $1)")
            .bind(name)
            .fetch_one(&pool)
            .await
            .unwrap()
    }
}

// Le serveur S3 est une tâche tokio ; `Command::output()` bloque le thread
// qui l'appelle. Un runtime mono-thread figerait cette tâche pendant l'appel
// (elle ne répondrait jamais, et le test « échec » passerait pour la
// mauvaise raison — un délai d'attente, pas un vrai refus du service).
#[tokio::test(flavor = "multi_thread")]
async fn a_configured_s3_receives_an_exact_copy_of_the_local_journal() {
    let Some(f) = fixture("s3_ok").await else {
        eprintln!("OE_CASTORE_TEST_DSN non définie : test PostgreSQL ignoré");
        return;
    };
    let objects = Arc::new(Objects::default());
    let app = Router::new()
        .route("/{bucket}/{*key}", any(handle_ok))
        .with_state(objects.clone());
    let endpoint = serve(app).await;

    let out = f.run_bootstrap("alice", &endpoint);
    assert!(
        out.status.success(),
        "bootstrap-admin avec S3 configuré : {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let local = std::fs::read(&f.audit).expect("journal local écrit");
    let remote = objects
        .0
        .lock()
        .unwrap()
        .get("audit/ca-server/audit.log")
        .cloned()
        .expect("le journal a été envoyé à S3");
    assert_eq!(
        local, remote,
        "le contenu envoyé à S3 doit être une copie exacte du journal local"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_failing_s3_blocks_the_operation_nothing_is_committed() {
    let Some(f) = fixture("s3_ko").await else {
        eprintln!("OE_CASTORE_TEST_DSN non définie : test PostgreSQL ignoré");
        return;
    };
    let app = Router::new().route("/{*path}", any(handle_failing));
    let endpoint = serve(app).await;

    let out = f.run_bootstrap("bob", &endpoint);
    assert!(
        !out.status.success(),
        "un envoi S3 en échec doit faire échouer la commande, pas seulement un avertissement"
    );
    assert!(
        out.stdout.is_empty(),
        "aucun jeton ne doit être émis quand le journal n'a pas pu être scellé sur S3 : {}",
        String::from_utf8_lossy(&out.stdout)
    );
    assert!(
        !f.operator_exists("bob").await,
        "rien ne doit être commité en base : le journal (avant le commit) a échoué"
    );
}
