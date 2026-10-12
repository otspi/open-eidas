//! `GET /api/v1/audit/search` (docs/WEBUI.md §7, §15 étape 2b-D) : relit et
//! vérifie **les deux** journaux chaînés — celui de `ca-server` (fait foi
//! pour la PKI) et celui de `ra-console` (§7) — depuis le stockage S3 commun,
//! avant de répondre. Jamais un index qui pourrait avoir divergé des fichiers
//! source : la vérification porte sur l'intégralité de chaque journal relu
//! pour cette requête, pas seulement sur les entrées retournées.
//!
//! `ra-console` n'a aucun accès local au journal de `ca-server` : seul S3 les
//! met en commun (`OPENEIDAS_S3_CA_KEY`), d'où la dépendance stricte au
//! stockage S3 — sans lui, cette route ne peut pas honorer sa propre
//! garantie et refuse plutôt que de ne montrer qu'une moitié de la vérité.

use crate::config::S3Config;
use serde::Serialize;
use std::sync::Arc;

/// Le journal d'origine d'une entrée : jamais mélangés silencieusement, un
/// constat identique à `docs/WEBUI.md §7` (« chaque résultat indique de quel
/// journal il provient »).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Source {
    CaServer,
    RaConsole,
}

#[derive(Debug, Clone, Serialize)]
pub struct Entry {
    pub source: Source,
    pub sequence: u64,
    pub at: String,
    pub event: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
    /// Empreinte de l'entrée précédente de **ce** journal (chaînage) et
    /// empreinte de celle-ci : de quoi recouper à la main, hors de la console,
    /// ce que `chain_verified` affirme (docs/UI-UX.md §3.3).
    pub prev: String,
    pub hash: String,
}

/// Nature d'une rupture, telle que `oe_audit` la constate à la relecture.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum BreakKind {
    /// L'empreinte précédente d'une entrée ne reprend pas celle de la précédente.
    Chain,
    /// La numérotation saute ou revient en arrière (entrée retirée ou insérée).
    Sequence,
    /// Le contenu d'une entrée ne correspond plus à son empreinte.
    Tampered,
    /// Une ligne n'est pas une entrée de journal.
    Unreadable,
}

/// Où et pourquoi un journal n'est pas intègre. Ne porte jamais d'empreinte
/// attendue ni de contenu : ce que l'opérateur doit savoir pour agir (quel
/// journal, quelle nature, quelle entrée), pas de quoi forger la suite.
#[derive(Debug, Clone, Serialize)]
pub struct Break {
    pub source: Source,
    pub kind: BreakKind,
    /// Numéro de l'entrée en cause, quand la rupture en désigne une.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sequence: Option<u64>,
    /// Numéro de ligne (à partir de 1) d'une ligne illisible.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<u64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Report {
    pub chain_verified: bool,
    pub entries_checked: u64,
    pub results: Vec<Entry>,
    /// Vide quand `chain_verified` est vrai ; sinon une rupture par journal
    /// rompu (les deux peuvent l'être).
    pub broken: Vec<Break>,
}

#[derive(Debug, Default, Clone)]
pub struct Query {
    /// Numéro de série hexadécimal (`data.serie`, insensible à la casse).
    pub serial: Option<String>,
    pub from: Option<time::OffsetDateTime>,
    pub to: Option<time::OffsetDateTime>,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("récupération du journal {0} sur S3 : {1}")]
    Fetch(&'static str, #[source] oe_s3::S3Error),
    /// Le journal a été reçu mais n'a pas pu être relu pour une raison locale
    /// (fichier temporaire) : ce n'est pas un constat d'intégrité et ne doit
    /// jamais s'afficher comme une rupture.
    #[error("relecture locale du journal {0} : {1}")]
    Read(&'static str, #[source] std::io::Error),
}

/// Relit `bytes` comme un journal `oe-audit` : `oe_audit::read` exige un
/// chemin, pas un tampon en mémoire, donc un fichier temporaire à usage
/// unique le porte le temps de l'appel.
fn read_journal(bytes: &[u8]) -> Result<Vec<oe_audit::Record>, oe_audit::AuditError> {
    let path = std::env::temp_dir().join(format!(
        "ra-console-audit-search-{}-{}.log",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));
    let result = std::fs::write(&path, bytes)
        .map_err(oe_audit::AuditError::from)
        .and_then(|()| oe_audit::read(&path));
    let _ = std::fs::remove_file(&path);
    result
}

fn matches(entry: &oe_audit::Record, q: &Query) -> bool {
    if let Some(serial) = &q.serial {
        let found = entry
            .data
            .as_ref()
            .and_then(|d| d.get("serie"))
            .and_then(|v| v.as_str())
            .is_some_and(|s| s.eq_ignore_ascii_case(serial));
        if !found {
            return false;
        }
    }
    if q.from.is_some() || q.to.is_some() {
        let Ok(at) = time::OffsetDateTime::parse(
            &entry.time,
            &time::format_description::well_known::Rfc3339,
        ) else {
            // Une date illisible n'est filtrée dans aucun sens : elle n'est
            // exclue que si elle échoue par ailleurs (elle ne le devrait
            // jamais, `oe-audit` l'écrit toujours au format RFC 3339).
            return true;
        };
        if let Some(from) = q.from {
            if at < from {
                return false;
            }
        }
        if let Some(to) = q.to {
            if at > to {
                return false;
            }
        }
    }
    true
}

/// Récupère et relit un journal depuis S3. `Ok(Err(rupture))` signale une
/// chaîne rompue ou illisible (jamais mélangée aux résultats, voir `search`) ;
/// `Err` signale que S3 ou la relecture locale n'a pas abouti
/// (indisponibilité, pas un constat d'intégrité).
async fn fetch_and_read(
    client: &oe_s3::Client,
    key: &str,
    source: Source,
) -> Result<Result<Vec<oe_audit::Record>, Break>, Error> {
    let name = match source {
        Source::CaServer => "ca-server",
        Source::RaConsole => "ra-console",
    };
    let bytes = client.get(key).await.map_err(|e| Error::Fetch(name, e))?;
    match read_journal(&bytes) {
        Ok(records) => Ok(Ok(records)),
        Err(oe_audit::AuditError::Io(e)) => Err(Error::Read(name, e)),
        Err(e) => Ok(Err(classify(source, &e))),
    }
}

fn classify(source: Source, error: &oe_audit::AuditError) -> Break {
    use oe_audit::AuditError::{BrokenChain, BrokenSequence, TamperedRecord, UnreadableLine};
    let (kind, sequence, line) = match error {
        BrokenChain { seq, .. } => (BreakKind::Chain, Some(*seq), None),
        BrokenSequence { found, .. } => (BreakKind::Sequence, Some(*found), None),
        TamperedRecord { seq, .. } => (BreakKind::Tampered, Some(*seq), None),
        UnreadableLine { line, .. } => (BreakKind::Unreadable, None, Some(*line)),
        _ => (BreakKind::Unreadable, None, None),
    };
    Break {
        source,
        kind,
        sequence,
        line,
    }
}

/// Relit et vérifie les deux journaux, filtre, et rend le tout trié
/// chronologiquement — jamais un tri qui masquerait de quel journal vient
/// quoi (`source` sur chaque entrée).
pub async fn search(s3: &S3Config, query: &Query) -> Result<Report, Error> {
    let client = Arc::new(
        oe_s3::Client::new(oe_s3::Options {
            endpoint: s3.endpoint.clone(),
            bucket: s3.bucket.clone(),
            region: s3.region.clone(),
            access_key: s3.access_key.clone(),
            secret_key: s3.secret_key.clone(),
            timeout: std::time::Duration::from_secs(30),
        })
        .map_err(|e| Error::Fetch("ca-server", e))?,
    );

    let ca = fetch_and_read(&client, &s3.ca_key, Source::CaServer).await?;
    let ra = fetch_and_read(&client, &s3.key, Source::RaConsole).await?;

    let mut broken = Vec::new();
    let mut journals = Vec::new();
    for (source, journal) in [(Source::CaServer, ca), (Source::RaConsole, ra)] {
        match journal {
            Ok(records) => journals.push((source, records)),
            Err(b) => broken.push(b),
        }
    }
    let chain_verified = broken.is_empty();
    let mut entries_checked = 0u64;
    let mut results = Vec::new();

    if chain_verified {
        for (source, records) in journals {
            entries_checked += records.len() as u64;
            for r in records.into_iter().filter(|r| matches(r, query)) {
                results.push(Entry {
                    source,
                    sequence: r.seq,
                    at: r.time,
                    event: r.event,
                    data: r
                        .data
                        .map(|d| serde_json::Value::Object(d.into_iter().collect())),
                    prev: r.prev,
                    hash: r.hash,
                });
            }
        }
        results.sort_by(|a, b| a.at.cmp(&b.at));
    }

    Ok(Report {
        chain_verified,
        entries_checked,
        // Un chaînage rompu bloque l'affichage plutôt que de montrer des
        // résultats à côté d'une alerte (docs/WEBUI.md §7) : personne ne
        // peut l'ignorer par inattention.
        results: if chain_verified { results } else { Vec::new() },
        broken,
    })
}
