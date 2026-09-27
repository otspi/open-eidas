//! Portage de `internal/timesource` (surveillance NTP multi-sources, ETSI EN
//! 319 421 §7.7.2) — jalon J4 du plan de migration
//! (`/home/philippe/.claude/plans/witty-hopping-nest.md`).
//!
//! ETSI EN 319 421 exige que l'heure d'un jeton soit traçable jusqu'à UTC et
//! que la TSA cesse d'émettre dès qu'elle ne peut plus garantir la précision
//! qu'elle annonce : [`evaluate`] est la règle de décision, isolée du réseau
//! pour rester testable sans mocker un serveur NTP, à l'identique de la
//! séparation `query`/`evaluate` du code Go de référence.

mod ntp;

use std::collections::HashMap;
use std::fmt;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use std::thread::JoinHandle;
use std::time::Duration as StdDuration;

use time::{Duration, OffsetDateTime};

pub use ntp::{NtpError, NtpSample};

/// Politique appliquée quand la traçabilité UTC ne peut pas être établie.
///
/// Équivalent de `timesource.Policy` (Go) : `PolicyEnforce` / `PolicyMonitor` /
/// `PolicyDisabled`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Policy {
    /// Refuse de signer tant que la traçabilité n'est pas établie.
    Enforce,
    /// Journalise l'écart mais laisse le service signer (dev uniquement).
    Monitor,
    /// Désactive toute surveillance.
    Disabled,
}

impl fmt::Display for Policy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Policy::Enforce => "enforce",
            Policy::Monitor => "monitor",
            Policy::Disabled => "disabled",
        })
    }
}

#[derive(Debug, thiserror::Error)]
#[error("politique de temps inconnue: {0:?} (enforce, monitor ou disabled)")]
pub struct ParsePolicyError(String);

impl FromStr for Policy {
    type Err = ParsePolicyError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_lowercase().as_str() {
            "enforce" => Ok(Policy::Enforce),
            "monitor" => Ok(Policy::Monitor),
            "disabled" => Ok(Policy::Disabled),
            _ => Err(ParsePolicyError(s.to_string())),
        }
    }
}

/// Consigne les mesures de temps dans le journal d'audit. La forme exacte du
/// payload sera revue au jalon J5 (`oe-audit`) pour correspondre au format
/// réel du journal ; `serde_json::Value` évite de figer une API provisoire.
/// Reste synchrone, à la différence d'`oe_ca_core::Recorder`/`oe_raflow::Recorder`
/// (docs/WEBUI.md §15 étape 2b) : `Monitor` s'exécute dans un thread dédié
/// bloquant (les requêtes NTP le sont déjà), jamais sur un exécuteur async —
/// un futur dos S3 y ferait un appel HTTP bloquant, sans avoir besoin de
/// `tokio`. Son échec ne fait échouer aucun appelant (voir `Monitor::record`) :
/// il retire la traçabilité de la mesure, `now()` s'en charge ensuite.
pub trait Recorder: Send + Sync {
    fn append(&self, event: &str, data: serde_json::Value) -> Result<(), String>;
}

pub const EVENT_TIME_MEASUREMENT: &str = "time.measurement";

/// Signale que l'heure locale n'est plus rattachable à UTC dans les limites
/// annoncées.
#[derive(Debug, Clone, thiserror::Error)]
#[error("heure non traçable jusqu'à UTC: {0}")]
pub struct TimeNotTraceable(pub String);

/// Une mesure ponctuelle face à une source de temps.
#[derive(Debug, Clone)]
pub struct Sample {
    pub server: String,
    pub offset: Duration,
    pub rtt: Duration,
    pub stratum: u8,
    pub at: OffsetDateTime,
    pub err: Option<String>,
}

impl Sample {
    fn ok(&self) -> bool {
        self.err.is_none()
    }

    fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "server": self.server,
            "offset": format_duration(self.offset),
            "rtt": format_duration(self.rtt),
            "stratum": self.stratum,
            "at": self.at.format(&time::format_description::well_known::Rfc3339).unwrap_or_default(),
            "error": self.err,
        })
    }
}

/// L'état de traçabilité publié par le service.
#[derive(Debug, Clone)]
pub struct Status {
    pub policy: Policy,
    pub traceable: bool,
    pub reason: String,
    pub offset: Duration,
    pub spread: Duration,
    pub last_sync: Option<OffsetDateTime>,
    pub sources: Vec<Sample>,
}

impl Default for Status {
    fn default() -> Self {
        Status {
            policy: Policy::Enforce,
            traceable: false,
            reason: String::new(),
            offset: Duration::ZERO,
            spread: Duration::ZERO,
            last_sync: None,
            sources: Vec::new(),
        }
    }
}

/// Paramètres de construction du moniteur.
pub struct Options {
    pub servers: Vec<String>,
    pub policy: Policy,
    pub max_offset: Duration,
    pub max_age: Duration,
    pub min_sources: usize,
    pub poll_interval: StdDuration,
    pub timeout: StdDuration,
    pub recorder: Option<Arc<dyn Recorder>>,
}

impl Default for Options {
    fn default() -> Self {
        Options {
            servers: Vec::new(),
            policy: Policy::Enforce,
            max_offset: Duration::milliseconds(500),
            max_age: Duration::HOUR,
            min_sources: 1,
            poll_interval: StdDuration::from_secs(5 * 60),
            timeout: StdDuration::from_secs(5),
            recorder: None,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum NewMonitorError {
    #[error("timesource: aucune source de temps configurée")]
    NoServers,
    #[error("timesource: {min_sources} source(s) exigée(s) mais {configured} configurée(s)")]
    QuorumExceedsServers {
        min_sources: usize,
        configured: usize,
    },
}

pub struct Monitor {
    opts: Options,
    status: RwLock<Status>,
}

impl fmt::Debug for Monitor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Monitor")
            .field("policy", &self.opts.policy)
            .field("servers", &self.opts.servers)
            .finish_non_exhaustive()
    }
}

impl Monitor {
    pub fn new(mut opts: Options) -> Result<Arc<Monitor>, NewMonitorError> {
        if opts.policy != Policy::Disabled && opts.servers.is_empty() {
            return Err(NewMonitorError::NoServers);
        }
        if opts.min_sources == 0 {
            opts.min_sources = 1;
        }
        if opts.policy != Policy::Disabled && opts.min_sources > opts.servers.len() {
            return Err(NewMonitorError::QuorumExceedsServers {
                min_sources: opts.min_sources,
                configured: opts.servers.len(),
            });
        }

        let status = if opts.policy == Policy::Disabled {
            Status {
                policy: Policy::Disabled,
                traceable: true,
                reason: "surveillance désactivée".to_string(),
                ..Status::default()
            }
        } else {
            Status {
                policy: opts.policy,
                reason: "aucune mesure effectuée".to_string(),
                ..Status::default()
            }
        };

        Ok(Arc::new(Monitor {
            opts,
            status: RwLock::new(status),
        }))
    }

    /// L'heure à estampiller, ou une erreur si la traçabilité n'est pas
    /// établie et que la politique impose le refus.
    pub fn now(&self) -> Result<OffsetDateTime, TimeNotTraceable> {
        let status = self.status();
        if !status.traceable && self.opts.policy == Policy::Enforce {
            return Err(TimeNotTraceable(status.reason));
        }
        Ok(OffsetDateTime::now_utc())
    }

    pub fn status(&self) -> Status {
        self.status
            .read()
            .expect("verrou de statut empoisonné")
            .clone()
    }

    /// Interroge toutes les sources configurées et met à jour le statut.
    /// Séparé de la boucle périodique pour rester appelable depuis un test
    /// ou un déclenchement manuel.
    pub fn poll_once(&self) {
        if self.opts.policy == Policy::Disabled {
            return;
        }
        let samples: Vec<Sample> = self
            .opts
            .servers
            .iter()
            .map(|server| query_one(server, self.opts.timeout))
            .collect();
        let mut status = evaluate(&samples, &self.opts, OffsetDateTime::now_utc());
        self.record(&mut status);
        *self.status.write().expect("verrou de statut empoisonné") = status;
    }

    /// Journalise la mesure — bloquant, comme `oe_ca_core::Recorder`/
    /// `oe_raflow::Recorder` (docs/WEBUI.md §15 étape 2b), mais différemment :
    /// il n'y a ici aucun appelant à faire échouer (une mesure périodique,
    /// pas une action). Un échec d'écriture retire donc la traçabilité de
    /// *cette* mesure (`traceable = false`) : c'est le mécanisme existant de
    /// `now()` (refus en politique `Enforce` si `!traceable`) qui bloque
    /// l'émission, pas un `Result` de plus à propager ici.
    fn record(&self, status: &mut Status) {
        let Some(recorder) = &self.opts.recorder else {
            return;
        };
        let sources: HashMap<&str, serde_json::Value> = status
            .sources
            .iter()
            .map(|s| (s.server.as_str(), s.to_json()))
            .collect();
        let payload = serde_json::json!({
            "traceable": status.traceable,
            "offset": format_duration(status.offset),
            "spread": format_duration(status.spread),
            "reason": status.reason,
            "sources": sources,
            "max_offset": format_duration(self.opts.max_offset),
        });
        if let Err(e) = recorder.append(EVENT_TIME_MEASUREMENT, payload) {
            status.traceable = false;
            status.reason = format!("journal indisponible, mesure non traçable : {e}");
        }
    }

    /// Lance la surveillance périodique dans un thread dédié. Le thread
    /// s'arrête dès que le `Monitor` (via l'`Arc` détenu par l'appelant) est
    /// abandonné et que le drapeau d'arrêt retourné est levé — équivalent de
    /// l'annulation par contexte côté Go.
    pub fn start_background(self: &Arc<Self>) -> (JoinHandle<()>, Arc<AtomicBool>) {
        let stop = Arc::new(AtomicBool::new(false));
        if self.opts.policy == Policy::Disabled {
            let handle = std::thread::spawn(|| {});
            return (handle, stop);
        }
        self.poll_once();
        let monitor = Arc::clone(self);
        let stop_flag = Arc::clone(&stop);
        let interval = self.opts.poll_interval;
        // Le thread se réveille plus souvent que l'intervalle de sondage pour
        // réagir vite à `stop`, sans pour autant interroger les serveurs NTP
        // plus fréquemment que configuré.
        let wake_every = interval
            .min(StdDuration::from_millis(200))
            .max(StdDuration::from_millis(1));
        let handle = std::thread::spawn(move || {
            let mut last_poll = std::time::Instant::now();
            while !stop_flag.load(Ordering::Relaxed) {
                std::thread::sleep(wake_every);
                if stop_flag.load(Ordering::Relaxed) {
                    break;
                }
                if last_poll.elapsed() >= interval {
                    monitor.poll_once();
                    last_poll = std::time::Instant::now();
                }
            }
        });
        (handle, stop)
    }
}

fn query_one(server: &str, timeout: StdDuration) -> Sample {
    let at = OffsetDateTime::now_utc();
    match ntp::query(server, timeout) {
        Ok(NtpSample {
            offset,
            rtt,
            stratum,
        }) => Sample {
            server: server.to_string(),
            offset,
            rtt,
            stratum,
            at,
            err: None,
        },
        Err(e) => Sample {
            server: server.to_string(),
            offset: Duration::ZERO,
            rtt: Duration::ZERO,
            stratum: 0,
            at,
            err: Some(e.to_string()),
        },
    }
}

/// La règle de décision : l'heure est jugée traçable lorsque le quorum de
/// sources est atteint, que l'écart mesuré et la dispersion entre sources
/// restent sous le seuil, et que la mesure n'est pas périmée.
pub fn evaluate(samples: &[Sample], opts: &Options, now: OffsetDateTime) -> Status {
    let mut status = Status {
        policy: opts.policy,
        sources: samples.to_vec(),
        ..Status::default()
    };

    let offsets: Vec<Duration> = samples
        .iter()
        .filter(|s| s.ok())
        .map(|s| s.offset)
        .collect();
    let newest = samples.iter().filter(|s| s.ok()).map(|s| s.at).max();

    if let Some(newest) = newest {
        status.last_sync = Some(newest);
        status.offset = max_abs(&offsets);
        status.spread = spread(&offsets);
    }

    status.reason = if offsets.len() < opts.min_sources {
        format!(
            "{} source(s) de temps jointe(s) sur les {} exigées",
            offsets.len(),
            opts.min_sources
        )
    } else if let Some(newest) = newest {
        let age = now - newest;
        if age > opts.max_age {
            format!(
                "dernière mesure datant de {} (limite {})",
                format_duration(age),
                format_duration(opts.max_age)
            )
        } else if status.offset > opts.max_offset {
            format!(
                "dérive de {} supérieure au seuil de {}",
                format_duration(status.offset),
                format_duration(opts.max_offset)
            )
        } else if status.spread > opts.max_offset {
            format!(
                "désaccord de {} entre les sources de temps (seuil {})",
                format_duration(status.spread),
                format_duration(opts.max_offset)
            )
        } else {
            status.traceable = true;
            String::new()
        }
    } else {
        String::new()
    };

    status
}

fn max_abs(durations: &[Duration]) -> Duration {
    durations
        .iter()
        .map(|d| d.abs())
        .max()
        .unwrap_or(Duration::ZERO)
}

fn spread(durations: &[Duration]) -> Duration {
    if durations.len() < 2 {
        return Duration::ZERO;
    }
    let min = *durations.iter().min().unwrap();
    let max = *durations.iter().max().unwrap();
    max - min
}

/// Formate une durée signée à la façon de `time.Duration.String()` (Go),
/// pour que les messages et le journal d'audit restent lisibles par un
/// humain habitué au format Go pendant la coexistence des deux binaires.
fn format_duration(d: Duration) -> String {
    if d == Duration::ZERO {
        return "0s".to_string();
    }
    let sign = if d.is_negative() { "-" } else { "" };
    let d = d.abs();
    if d < Duration::MICROSECOND {
        format!("{sign}{}ns", d.whole_nanoseconds())
    } else if d < Duration::MILLISECOND {
        format!("{sign}{:.3}µs", d.as_seconds_f64() * 1e6)
    } else if d < Duration::SECOND {
        format!("{sign}{:.3}ms", d.as_seconds_f64() * 1e3)
    } else {
        format!("{sign}{:.6}s", d.as_seconds_f64())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_options() -> Options {
        Options {
            policy: Policy::Enforce,
            min_sources: 2,
            max_offset: Duration::milliseconds(500),
            max_age: Duration::HOUR,
            ..Options::default()
        }
    }

    fn sample(server: &str, offset_ms: i64, at: OffsetDateTime) -> Sample {
        Sample {
            server: server.to_string(),
            offset: Duration::milliseconds(offset_ms),
            rtt: Duration::ZERO,
            stratum: 1,
            at,
            err: None,
        }
    }

    fn failed_sample(server: &str, at: OffsetDateTime, err: &str) -> Sample {
        Sample {
            server: server.to_string(),
            offset: Duration::ZERO,
            rtt: Duration::ZERO,
            stratum: 0,
            at,
            err: Some(err.to_string()),
        }
    }

    #[test]
    fn evaluate_matches_the_go_reference_cases() {
        let now = time::macros::datetime!(2026-09-06 12:00:00 UTC);
        let fresh = now - Duration::MINUTE;

        struct Case {
            name: &'static str,
            samples: Vec<Sample>,
            traceable: bool,
        }
        let cases = vec![
            Case {
                name: "deux sources concordantes",
                samples: vec![sample("a", 12, fresh), sample("b", -8, fresh)],
                traceable: true,
            },
            Case {
                name: "quorum non atteint",
                samples: vec![
                    sample("a", 5, fresh),
                    failed_sample("b", fresh, "i/o timeout"),
                ],
                traceable: false,
            },
            Case {
                name: "dérive supérieure au seuil",
                samples: vec![sample("a", 900, fresh), sample("b", 880, fresh)],
                traceable: false,
            },
            Case {
                name: "sources en désaccord",
                samples: vec![sample("a", 300, fresh), sample("b", -300, fresh)],
                traceable: false,
            },
            Case {
                name: "mesure périmée",
                samples: vec![
                    sample("a", 1, now - Duration::hours(3)),
                    sample("b", 1, now - Duration::hours(3)),
                ],
                traceable: false,
            },
            Case {
                name: "aucune source jointe",
                samples: vec![failed_sample("a", fresh, "unreachable")],
                traceable: false,
            },
        ];

        for case in cases {
            let status = evaluate(&case.samples, &test_options(), now);
            assert_eq!(status.traceable, case.traceable, "cas: {}", case.name);
            if !status.traceable {
                assert!(
                    !status.reason.is_empty(),
                    "cas {}: un refus doit être motivé",
                    case.name
                );
            }
        }
    }

    #[test]
    fn now_refuses_untraceable_time_in_enforce_mode() {
        let m = Monitor::new(Options {
            servers: vec!["a".into(), "b".into()],
            policy: Policy::Enforce,
            min_sources: 2,
            ..Options::default()
        })
        .unwrap();
        assert!(
            m.now().is_err(),
            "sans mesure, la politique enforce doit refuser de fournir l'heure"
        );
    }

    #[test]
    fn now_allows_untraceable_time_in_monitor_mode() {
        let m = Monitor::new(Options {
            servers: vec!["a".into()],
            policy: Policy::Monitor,
            min_sources: 1,
            ..Options::default()
        })
        .unwrap();
        assert!(
            m.now().is_ok(),
            "la politique monitor ne doit pas bloquer l'horodatage"
        );
    }

    #[test]
    fn new_rejects_quorum_larger_than_source_count() {
        let err = Monitor::new(Options {
            servers: vec!["a".into()],
            min_sources: 2,
            ..Options::default()
        })
        .unwrap_err();
        assert!(matches!(err, NewMonitorError::QuorumExceedsServers { .. }));
    }

    #[test]
    fn parses_known_policies_case_insensitively() {
        assert_eq!("enforce".parse::<Policy>().unwrap(), Policy::Enforce);
        assert_eq!("Monitor".parse::<Policy>().unwrap(), Policy::Monitor);
        assert_eq!(" DISABLED ".parse::<Policy>().unwrap(), Policy::Disabled);
    }

    #[test]
    fn rejects_unknown_policy() {
        assert!("bogus".parse::<Policy>().is_err());
    }

    /// Un journal qui échoue systématiquement (docs/WEBUI.md §15 étape 2b) :
    /// preuve que `Monitor::record` retire bien la traçabilité d'une mesure
    /// par ailleurs traçable, plutôt que d'ignorer l'échec en silence.
    struct FailingRecorder;
    impl Recorder for FailingRecorder {
        fn append(&self, _event: &str, _data: serde_json::Value) -> Result<(), String> {
            Err("stockage du journal injoignable (test)".to_string())
        }
    }

    #[test]
    fn a_journal_failure_makes_the_measurement_untraceable() {
        let opts = Options {
            servers: vec!["a".into()],
            min_sources: 1,
            recorder: Some(Arc::new(FailingRecorder)),
            ..test_options()
        };
        let monitor = Monitor::new(opts).unwrap();
        let mut status = Status {
            policy: Policy::Enforce,
            traceable: true,
            reason: "ok".to_string(),
            ..Status::default()
        };
        monitor.record(&mut status);
        assert!(!status.traceable, "{status:?}");
        assert!(status.reason.contains("journal"), "{}", status.reason);
    }

    #[test]
    fn a_working_journal_leaves_traceability_untouched() {
        struct NullRecorder;
        impl Recorder for NullRecorder {
            fn append(&self, _event: &str, _data: serde_json::Value) -> Result<(), String> {
                Ok(())
            }
        }
        let opts = Options {
            servers: vec!["a".into()],
            min_sources: 1,
            recorder: Some(Arc::new(NullRecorder)),
            ..test_options()
        };
        let monitor = Monitor::new(opts).unwrap();
        let mut status = Status {
            policy: Policy::Enforce,
            traceable: true,
            reason: "ok".to_string(),
            ..Status::default()
        };
        monitor.record(&mut status);
        assert!(status.traceable);
        assert_eq!(status.reason, "ok");
    }
}
