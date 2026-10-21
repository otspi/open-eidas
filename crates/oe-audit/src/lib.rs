//! Portage de `internal/audit` : journal d'audit en JSON Lines chaîné par
//! hachage SHA-256 — jalon J5 du plan de migration
//! (`/home/philippe/.claude/plans/witty-hopping-nest.md`).
//!
//! Chaque enregistrement porte l'empreinte du précédent, si bien qu'aucune
//! ligne ne peut être modifiée, supprimée ou intercalée sans rompre la
//! chaîne. Le journal est synchronisé sur disque à chaque écriture, relu et
//! vérifié à l'ouverture, et verrouillé (`flock`) pendant chaque ajout pour
//! rester correct quand plusieurs processus y écrivent (le service et des
//! commandes d'exploitation lancées à côté).
//!
//! **Contrat de compatibilité avec le binaire Go** (jalon critique du plan) :
//! le format du journal est un contrat de données. `Payload` reproduit
//! l'ordre de champs et la sérialisation compacte de `encoding/json` (Go) —
//! `BTreeMap` pour trier les clés de `data` alphabétiquement, comme le fait
//! `json.Marshal` pour une `map[string]any` — afin qu'un journal produit par
//! l'un des deux binaires reste vérifiable par l'autre. Voir
//! `tests/cross_compat.rs` pour la preuve : ce test fait générer un journal
//! par le binaire Go de référence et le fait vérifier par ce module.

use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::sync::Mutex;

use fs2::FileExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Empreinte conventionnelle précédant le premier enregistrement d'un journal.
pub const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

// GENESIS_HASH doit faire 64 caractères ('0' * 64) : vérifié par un test unitaire.

pub const EVENT_OPENED: &str = "log.opened";
/// Démarrage dans un mode dégradé admis hors production (constat S-2 de
/// l'audit du 2026-09-25) : politique de temps autre qu'enforce, TLS non
/// vérifié vers la CA.
pub const EVENT_DEGRADED_START: &str = "service.degraded_start";
/// Génération d'une nouvelle clé de TSU, avant l'enrôlement de son certificat
/// (constat H-3, une clé par certificat).
pub const EVENT_TSU_KEY_GENERATED: &str = "tsu.key_generated";
/// Destruction d'une ancienne génération de la clé de TSU, à la demande d'un
/// opérateur (constat H-3, EN 319 421 `TIS-7.6.7-08`).
pub const EVENT_TSU_KEY_DESTROYED: &str = "tsu.key_destroyed";
/// Adoption à chaud d'un nouveau certificat de TSU (constat H-3), ou refus du
/// candidat qui a échoué aux contrôles du démarrage.
pub const EVENT_TSU_RELOADED: &str = "tsu.reloaded";
pub const EVENT_TSU_RELOAD_REFUSED: &str = "tsu.reload_refused";
pub const EVENT_SEALED: &str = "log.sealed";
pub const EVENT_CROSS_SEALED: &str = "log.cross_sealed";
pub const EVENT_REPLICATED: &str = "log.replicated";
pub const EVENT_TIMESTAMP_GRANTED: &str = "timestamp.granted";
pub const EVENT_TIMESTAMP_REJECTED: &str = "timestamp.rejected";
pub const EVENT_TIME_MEASUREMENT: &str = "time.measurement";
pub const EVENT_ENROLLMENT_ACCEPTED: &str = "enrollment.completed";

pub const EVENT_CA_CEREMONY: &str = "ca.ceremony";
pub const EVENT_CA_REQUEST_RECEIVED: &str = "ca.request_received";
pub const EVENT_CA_REQUEST_APPROVED: &str = "ca.request_approved";
pub const EVENT_CA_REQUEST_REJECTED: &str = "ca.request_rejected";
pub const EVENT_CA_CERTIFICATE_ISSUED: &str = "ca.certificate_issued";
pub const EVENT_CA_CERTIFICATE_REVOKED: &str = "ca.certificate_revoked";
pub const EVENT_CA_CRL_PUBLISHED: &str = "ca.crl_published";
pub const EVENT_CA_ISSUANCE_REFUSED: &str = "ca.issuance_refused";
pub const EVENT_CA_CONFORMANCE_REPORTED: &str = "ca.conformance_reported";

pub type Data = BTreeMap<String, serde_json::Value>;

/// Ce que `/healthz` d'un service dit de son journal d'audit (constat J-1 de
/// l'audit du 2026-09-25) : scellé, contresigné et copié hors site comme
/// prévu, ou non. Défini ici, à côté du journal, pour que chaque binaire
/// (`tsa-server`, `ca-server`, `ra-console`) l'expose de la même façon sans
/// dépendre de l'API HTTP d'un autre.
pub trait JournalHealth: Send + Sync {
    fn report(&self) -> JournalReport;
}

pub struct JournalReport {
    /// `Some(raison)` quand le journal n'est plus scellé ou copié comme prévu.
    pub degraded: Option<String>,
    /// Le détail rendu tel quel sous la clé `journal`.
    pub detail: serde_json::Value,
}

/// Une ligne du journal.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Record {
    pub seq: u64,
    pub time: String,
    pub event: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub data: Option<Data>,
    pub prev: String,
    pub hash: String,
}

/// La partie couverte par l'empreinte (tous les champs de `Record` sauf
/// `hash`). L'ordre de champs et la sérialisation compacte doivent rester
/// identiques à celles du `payload` Go pour que les empreintes concordent.
#[derive(Serialize)]
struct Payload<'a> {
    seq: u64,
    time: &'a str,
    event: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: &'a Option<Data>,
    prev: &'a str,
}

impl Record {
    fn compute_hash(&self) -> Result<String, AuditError> {
        let payload = Payload {
            seq: self.seq,
            time: &self.time,
            event: &self.event,
            data: &self.data,
            prev: &self.prev,
        };
        let raw = to_go_compatible_json(&payload)?;
        let sum = Sha256::digest(&raw);
        Ok(hex::encode(sum))
    }
}

/// Sérialise en JSON compact et applique l'échappement HTML-safe
/// qu'`encoding/json` (Go) applique par défaut à `json.Marshal` : les octets
/// `<`, `>` et `&` sont échappés en séquences d'échappement Unicode, de même
/// que les séparateurs de ligne/paragraphe U+2028 et U+2029 (valides en JSON
/// mais pas en JavaScript). Sans cela, un champ `data` contenant l'un de ces
/// caractères produirait une empreinte différente entre les deux binaires
/// pour un contenu identique — repéré par `tests/cross_compat.rs`, qui
/// vérifie un journal réellement produit par le binaire Go.
fn to_go_compatible_json<T: Serialize>(value: &T) -> Result<Vec<u8>, serde_json::Error> {
    let raw = serde_json::to_vec(value)?;
    Ok(html_escape_json(&raw))
}

fn html_escape_json(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    let mut i = 0;
    while i < input.len() {
        match input[i] {
            b'<' => out.extend_from_slice(b"\\u003c"),
            b'>' => out.extend_from_slice(b"\\u003e"),
            b'&' => out.extend_from_slice(b"\\u0026"),
            0xE2 if input.get(i + 1) == Some(&0x80)
                && matches!(input.get(i + 2), Some(&0xA8 | &0xA9)) =>
            {
                out.extend_from_slice(if input[i + 2] == 0xA8 {
                    b"\\u2028"
                } else {
                    b"\\u2029"
                });
                i += 3;
                continue;
            }
            b => out.push(b),
        }
        i += 1;
    }
    out
}

#[derive(Debug, thiserror::Error)]
pub enum AuditError {
    #[error("audit: erreur d'entrée/sortie: {0}")]
    Io(#[from] std::io::Error),
    #[error("audit: sérialisation: {0}")]
    Json(#[from] serde_json::Error),
    #[error("audit: ligne {line} illisible: {source}")]
    UnreadableLine {
        line: u64,
        #[source]
        source: serde_json::Error,
    },
    #[error("audit: chaîne rompue à l'enregistrement {seq}: empreinte précédente attendue {expected}, trouvée {found}")]
    BrokenChain {
        seq: u64,
        expected: String,
        found: String,
    },
    #[error("audit: numérotation rompue: enregistrement {expected} attendu, {found} trouvé")]
    BrokenSequence { expected: u64, found: u64 },
    #[error("audit: enregistrement {seq} altéré: empreinte {expected} attendue, {found} inscrite")]
    TamperedRecord {
        seq: u64,
        expected: String,
        found: String,
    },
}

/// Résume la relecture d'un journal.
#[derive(Debug, Clone, PartialEq)]
pub struct Report {
    pub records: u64,
    pub first: u64,
    pub last: u64,
    pub head: String,
    pub seals: u64,
}

impl Default for Report {
    fn default() -> Self {
        Report {
            records: 0,
            first: 0,
            last: 0,
            head: GENESIS_HASH.to_string(),
            seals: 0,
        }
    }
}

/// Relit des enregistrements depuis `r`, contrôle la continuité de la chaîne
/// et met à jour `report`. Retourne le nombre d'octets consommés, ce qui
/// permet à un journal ouvert en écriture de reprendre exactement là où il
/// s'était arrêté.
fn scan_chain<R: Read>(
    r: R,
    report: &mut Report,
    mut sink: Option<&mut Vec<Record>>,
) -> Result<u64, AuditError> {
    let mut reader = BufReader::with_capacity(64 * 1024, r);
    let mut line_no: u64 = 0;
    let mut read: u64 = 0;
    let mut buf = Vec::new();
    loop {
        buf.clear();
        let n = reader.read_until(b'\n', &mut buf)?;
        if n == 0 {
            break;
        }
        line_no += 1;
        read += n as u64;
        let has_newline = buf.last() == Some(&b'\n');
        let raw = if has_newline {
            &buf[..buf.len() - 1]
        } else {
            &buf[..]
        };
        if raw.is_empty() {
            if !has_newline {
                break;
            }
            continue;
        }
        let record: Record =
            serde_json::from_slice(raw).map_err(|source| AuditError::UnreadableLine {
                line: line_no,
                source,
            })?;
        if record.prev != report.head {
            return Err(AuditError::BrokenChain {
                seq: record.seq,
                expected: report.head.clone(),
                found: record.prev.clone(),
            });
        }
        let expected = if report.records == 0 {
            record.seq
        } else {
            report.last + 1
        };
        if record.seq != expected {
            return Err(AuditError::BrokenSequence {
                expected,
                found: record.seq,
            });
        }
        let hash = record.compute_hash()?;
        if hash != record.hash {
            return Err(AuditError::TamperedRecord {
                seq: record.seq,
                expected: hash,
                found: record.hash.clone(),
            });
        }

        if report.records == 0 {
            report.first = record.seq;
        }
        if record.event == EVENT_SEALED {
            report.seals += 1;
        }
        report.records += 1;
        report.last = record.seq;
        report.head = record.hash.clone();
        if let Some(out) = sink.as_deref_mut() {
            out.push(record);
        }

        if !has_newline {
            break;
        }
    }
    Ok(read)
}

/// Relit intégralement un journal et contrôle la continuité de la chaîne. Un
/// journal absent est considéré comme vide et valide.
pub fn verify(path: impl AsRef<Path>) -> Result<Report, AuditError> {
    let path = path.as_ref();
    let mut report = Report::default();
    let file = match File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(report),
        Err(e) => return Err(e.into()),
    };
    scan_chain(file, &mut report, None)?;
    Ok(report)
}

/// Relit le journal, en contrôle la chaîne, et en rend les enregistrements dans
/// l'ordre. Une chaîne rompue est une erreur : on ne lit pas un journal dont on
/// ne peut pas garantir l'intégrité. Un journal absent est vide.
pub fn read(path: impl AsRef<Path>) -> Result<Vec<Record>, AuditError> {
    let mut report = Report::default();
    let mut records = Vec::new();
    let file = match File::open(path.as_ref()) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(records),
        Err(e) => return Err(e.into()),
    };
    scan_chain(file, &mut report, Some(&mut records))?;
    Ok(records)
}

struct State {
    file: File,
    seq: u64,
    head: String,
    /// Position, en octets, jusqu'à laquelle le journal a été relu et
    /// vérifié par cette instance.
    offset: u64,
}

/// Un journal ouvert en écriture. Plusieurs processus peuvent légitimement
/// écrire dans le même journal : chaque ajout prend un verrou de fichier
/// exclusif et relit ce qui a pu être écrit entre-temps, de sorte que la
/// chaîne reste continue quel que soit l'ordre des écritures.
pub struct Log {
    state: Mutex<State>,
}

impl Log {
    /// Relit et vérifie le journal existant, puis l'ouvre en ajout.
    pub fn open(path: impl AsRef<Path>) -> Result<Log, AuditError> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let file = OpenOptions::new()
            .read(true)
            .create(true)
            .append(true)
            .open(path)?;

        FileExt::lock_exclusive(&file)?;
        let result = (|| -> Result<(u64, String, u64), AuditError> {
            let mut report = Report::default();
            let mut f = file.try_clone()?;
            f.seek(SeekFrom::Start(0))?;
            let read = scan_chain(&f, &mut report, None)?;
            Ok((report.last, report.head, read))
        })();
        let _ = FileExt::unlock(&file);
        let (seq, head, offset) = result?;

        Ok(Log {
            state: Mutex::new(State {
                file,
                seq,
                head,
                offset,
            }),
        })
    }

    /// Relit le journal à partir de l'offset déjà vérifié et met à jour la
    /// tête de chaîne. Appelé sous le verrou de fichier.
    fn catch_up(state: &mut State) -> Result<(), AuditError> {
        state.file.seek(SeekFrom::Start(state.offset))?;
        let mut report = Report {
            last: state.seq,
            head: state.head.clone(),
            records: state.seq,
            ..Report::default()
        };
        let mut f = state.file.try_clone()?;
        let read = scan_chain(&mut f, &mut report, None)?;
        state.offset += read;
        state.seq = report.last;
        state.head = report.head;
        Ok(())
    }

    /// Ajoute un enregistrement et le synchronise sur disque.
    pub fn append(&self, event: &str, data: Option<Data>) -> Result<(), AuditError> {
        let mut state = self.state.lock().expect("verrou de journal empoisonné");
        FileExt::lock_exclusive(&state.file)?;
        let result = (|| -> Result<(), AuditError> {
            Self::catch_up(&mut state)?;

            let time = now_rfc3339_nanos();
            let mut record = Record {
                seq: state.seq + 1,
                time,
                event: event.to_string(),
                data,
                prev: state.head.clone(),
                hash: String::new(),
            };
            record.hash = record.compute_hash()?;

            let mut line = to_go_compatible_json(&record)?;
            line.push(b'\n');
            state.file.seek(SeekFrom::End(0))?;
            state.file.write_all(&line)?;
            state.file.sync_all()?;

            state.seq = record.seq;
            state.head = record.hash;
            state.offset += line.len() as u64;
            Ok(())
        })();
        let _ = FileExt::unlock(&state.file);
        result
    }

    /// Le numéro et l'empreinte du dernier enregistrement, en tenant compte
    /// de ce qu'un autre processus aurait écrit entre-temps.
    pub fn head(&self) -> Result<(u64, String), AuditError> {
        let mut state = self.state.lock().expect("verrou de journal empoisonné");
        FileExt::lock_exclusive(&state.file)?;
        let result = Self::catch_up(&mut state);
        let _ = FileExt::unlock(&state.file);
        result?;
        Ok((state.seq, state.head.clone()))
    }
}

fn now_rfc3339_nanos() -> String {
    let now = time::OffsetDateTime::now_utc();
    now.format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| now.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn new_log() -> (Log, std::path::PathBuf, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.log");
        let log = Log::open(&path).unwrap();
        (log, path, dir)
    }

    fn append_some(log: &Log, n: u64) {
        for i in 0..n {
            let mut data = Data::new();
            data.insert("serial_number".to_string(), serde_json::json!(i));
            log.append(EVENT_TIMESTAMP_GRANTED, Some(data)).unwrap();
        }
    }

    fn read_lines(path: &Path) -> Vec<String> {
        let mut raw = String::new();
        File::open(path).unwrap().read_to_string(&mut raw).unwrap();
        raw.trim_end_matches('\n')
            .split('\n')
            .map(str::to_string)
            .collect()
    }

    fn write_lines(path: &Path, lines: &[String]) {
        std::fs::write(path, format!("{}\n", lines.join("\n"))).unwrap();
    }

    #[test]
    fn genesis_hash_is_64_hex_zeroes() {
        assert_eq!(GENESIS_HASH.len(), 64);
        assert!(GENESIS_HASH.chars().all(|c| c == '0'));
    }

    #[test]
    fn verify_accepts_intact_chain() {
        let (log, path, _dir) = new_log();
        append_some(&log, 3);

        let report = verify(&path).expect("un journal intact doit être accepté");
        assert_eq!(report.records, 3);
        assert_eq!(report.first, 1);
        assert_eq!(report.last, 3);

        let (_, head) = log.head().unwrap();
        assert_eq!(head, report.head);
    }

    #[test]
    fn read_returns_the_records_in_order() {
        let (log, path, _dir) = new_log();
        append_some(&log, 3);

        let records = read(&path).expect("un journal intact se relit");
        assert_eq!(
            records.iter().map(|r| r.seq).collect::<Vec<_>>(),
            vec![1, 2, 3]
        );
        let (_, head) = log.head().unwrap();
        assert_eq!(records.last().unwrap().hash, head);
    }

    #[test]
    fn read_refuses_a_broken_chain_and_treats_a_missing_log_as_empty() {
        let (log, path, dir) = new_log();
        append_some(&log, 3);
        let mut lines = read_lines(&path);
        lines[1] = lines[1].replace("\"serial_number\":1", "\"serial_number\":9");
        write_lines(&path, &lines);
        assert!(read(&path).is_err(), "on ne lit pas un journal altéré");

        assert!(read(dir.path().join("absent.log")).unwrap().is_empty());
    }

    #[test]
    fn verify_accepts_missing_log() {
        let dir = tempfile::tempdir().unwrap();
        let report = verify(dir.path().join("absent.log"))
            .expect("un journal absent doit être traité comme vide");
        assert_eq!(report.records, 0);
        assert_eq!(report.head, GENESIS_HASH);
    }

    #[test]
    fn verify_detects_modified_record() {
        let (log, path, _dir) = new_log();
        append_some(&log, 3);

        let mut lines = read_lines(&path);
        lines[1] = lines[1].replace("\"serial_number\":1", "\"serial_number\":9");
        write_lines(&path, &lines);

        assert!(
            verify(&path).is_err(),
            "la modification d'un enregistrement doit rompre la vérification"
        );
    }

    #[test]
    fn verify_detects_deleted_record() {
        let (log, path, _dir) = new_log();
        append_some(&log, 3);

        let lines = read_lines(&path);
        write_lines(&path, &[lines[0].clone(), lines[2].clone()]);

        assert!(
            verify(&path).is_err(),
            "la suppression d'un enregistrement doit rompre la chaîne"
        );
    }

    #[test]
    fn verify_detects_truncated_and_rewritten_tail() {
        let (log, path, _dir) = new_log();
        append_some(&log, 2);

        let lines = read_lines(&path);
        let mut forged = Record {
            seq: 3,
            time: "2026-09-06T00:00:00Z".to_string(),
            event: EVENT_TIMESTAMP_GRANTED.to_string(),
            data: None,
            prev: GENESIS_HASH.to_string(),
            hash: String::new(),
        };
        forged.hash = forged.compute_hash().unwrap();
        let line = serde_json::to_string(&forged).unwrap();

        let mut all = lines;
        all.push(line);
        write_lines(&path, &all);

        assert!(
            verify(&path).is_err(),
            "un enregistrement rattaché à la mauvaise empreinte doit être rejeté"
        );
    }

    #[test]
    fn open_resumes_existing_chain() {
        let (log, path, _dir) = new_log();
        append_some(&log, 2);
        let (_, head_before) = log.head().unwrap();
        drop(log);

        let reopened = Log::open(&path).expect("la réouverture d'un journal valide doit réussir");
        let (seq, head) = reopened.head().unwrap();
        assert_eq!(seq, 2);
        assert_eq!(head, head_before);

        reopened.append(EVENT_SEALED, None).unwrap();

        let report = verify(&path).expect("la chaîne doit rester valide après réouverture");
        assert_eq!(report.records, 3);
        assert_eq!(report.seals, 1);
    }

    #[test]
    fn open_refuses_tampered_log() {
        let (log, path, _dir) = new_log();
        append_some(&log, 2);
        drop(log);

        let lines = read_lines(&path);
        write_lines(&path, &lines[..1]);
        let mut lines = read_lines(&path);
        lines[0] = lines[0].replace("\"seq\":1", "\"seq\":2");
        write_lines(&path, &lines);

        assert!(
            Log::open(&path).is_err(),
            "un journal altéré ne doit pas pouvoir être rouvert en écriture"
        );
    }

    /// Deux processus écrivent légitimement dans le même journal : le
    /// service et des commandes d'exploitation lancées à côté. Chacun tenant
    /// sa propre idée de la tête de chaîne, les écritures se
    /// contrediraient sans verrou de fichier ni relecture.
    #[test]
    fn deux_ecrivains_partagent_la_meme_chaine() {
        let (premier, path, _dir) = new_log();
        let second = Log::open(&path).expect("ouverture du second écrivain");

        for i in 0..3 {
            let mut d1 = Data::new();
            d1.insert("ecrivain".to_string(), serde_json::json!("service"));
            d1.insert("n".to_string(), serde_json::json!(i));
            premier.append(EVENT_OPENED, Some(d1)).unwrap();

            let mut d2 = Data::new();
            d2.insert("ecrivain".to_string(), serde_json::json!("cli"));
            d2.insert("n".to_string(), serde_json::json!(i));
            second.append(EVENT_CA_REQUEST_APPROVED, Some(d2)).unwrap();
        }

        let report = verify(&path).expect("la chaîne doit rester continue malgré deux écrivains");
        assert_eq!(report.records, 6);
        assert_eq!(report.last, 6);

        for log in [&premier, &second] {
            let (seq, head) = log.head().unwrap();
            assert_eq!(seq, report.last);
            assert_eq!(head, report.head);
        }
    }
}
