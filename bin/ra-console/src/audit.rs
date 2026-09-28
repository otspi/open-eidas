//! Journal d'audit propre à `ra-console` (docs/WEBUI.md §7, §15 étape 2b-A) :
//! connexions, refus de connexion (dont les régressions de compteur
//! détectées), déconnexions. Une chaîne distincte de celle de `ca-server`,
//! jamais partagée : un `ra-console` compromis ne peut ni écrire, ni même
//! ajouter de faux événements dans le journal qui fait foi sur la PKI (§7).
//!
//! `GET /api/v1/audit/search` (étape 2b-D, pas encore faite) relira les deux
//! chaînes ; ce module ne pose que l'écriture.

use std::sync::Arc;

pub const EVENT_LOGIN_SUCCEEDED: &str = "ra.login_succeeded";
/// `data.reason` distingue en interne ce que la réponse HTTP ne distingue
/// jamais (§16, « connexion par nom, réponses uniformes ») : ce journal n'est
/// lisible qu'authentifié (`auditeur`), la contrainte d'anti-énumération ne
/// s'y applique pas.
pub const EVENT_LOGIN_REFUSED: &str = "ra.login_refused";
pub const EVENT_SESSION_OPENED: &str = "ra.session_opened";
pub const EVENT_SESSION_CLOSED: &str = "ra.session_closed";

/// Même forme que `oe_ca_core::Recorder` / `oe_raflow::Recorder`, dupliquée
/// plutôt que partagée (ce sont des traits d'un seul étage, la duplication
/// coûte moins qu'une dépendance croisée entre crates qui ne se recoupent pas
/// autrement). Ne rend rien : un journal qui n'écrit pas ne doit pas faire
/// échouer une connexion par ailleurs valide, seulement se voir dans les logs
/// du service.
pub trait Recorder: Send + Sync {
    fn append(&self, event: &str, data: serde_json::Value);
}

/// Aucune écriture — pour les tests qui n'exercent pas le journal.
pub struct NullRecorder;

impl Recorder for NullRecorder {
    fn append(&self, _event: &str, _data: serde_json::Value) {}
}

/// Copie best-effort du journal sur un stockage objet compatible S3, auto-hébergé
/// (docs/WEBUI.md §7, §15 étape 2b-C) : `None` si `OPENEIDAS_S3_ENDPOINT` n'est pas
/// configuré. À la différence de `ca-server` (preuve légale de la PKI, bloquant), le
/// journal de `ra-console` reste best-effort par décision déjà prise ci-dessus —
/// l'envoi S3 suit la même règle, jamais de blocage de connexion/déconnexion pour lui.
pub struct AuditRecorder {
    log: Arc<oe_audit::Log>,
    path: String,
    s3: Option<(Arc<oe_s3::Client>, String)>,
}

impl AuditRecorder {
    pub fn new(
        log: Arc<oe_audit::Log>,
        path: String,
        s3: Option<(Arc<oe_s3::Client>, String)>,
    ) -> Self {
        Self { log, path, s3 }
    }
}

impl Recorder for AuditRecorder {
    fn append(&self, event: &str, data: serde_json::Value) {
        let data = match data {
            serde_json::Value::Object(map) => Some(map.into_iter().collect()),
            serde_json::Value::Null => None,
            other => {
                let mut m = oe_audit::Data::new();
                m.insert("value".to_string(), other);
                Some(m)
            }
        };
        if let Err(e) = self.log.append(event, data) {
            tracing::error!(erreur = %e, evenement = event, "journal d'audit : échec d'écriture locale");
            return;
        }
        // L'envoi S3 n'attend jamais l'appelant (connexion/déconnexion) : détaché,
        // son échec ne se voit que dans les logs du service, jamais dans la réponse.
        if let Some((client, key)) = self.s3.clone() {
            let path = self.path.clone();
            let event = event.to_string();
            tokio::spawn(async move {
                let bytes = match std::fs::read(&path) {
                    Ok(b) => b,
                    Err(e) => {
                        tracing::error!(erreur = %e, evenement = event, "journal d'audit : relecture pour l'envoi S3 impossible");
                        return;
                    }
                };
                if let Err(e) = client.put(&key, bytes).await {
                    tracing::error!(erreur = %e, evenement = event, "journal d'audit : échec de l'envoi S3");
                }
            });
        }
    }
}
