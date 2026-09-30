//! Constat R-1 de l'audit du 2026-09-25 (EN 319 411-1 `GEN-6.5.5-04`,
//! `CSS-6.5.5-06` ; EN 319 401 `REQ-7.4.1-11`, `-12`) et docs/WEBUI.md §20 :
//! une décision d'approbation, de rejet ou de révocation dit **par quelle
//! voie** son opérateur a été identifié. La voie est fixée par l'appelant au
//! moment de l'appel, jamais reconstruite après coup à partir du format du
//! champ `operateur`.
//!
//! La voie de secours (CLI sur l'hôte de `ca-server`) reste ouverte, par
//! décision (§20 : une panne de `ra-console` ne doit jamais rendre une
//! révocation d'urgence impossible), mais son identité n'est que déclarée :
//! elle est consignée avec l'identité système réelle du processus et marquée
//! non authentifiée, et elle exige un commentaire.

/// Par où l'identité de l'opérateur d'une décision a été établie.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Via {
    /// Action signée par une clé WebAuthn enregistrée, rôle lu dans le
    /// registre (`oe_actions`) : la voie primaire.
    WebAuthn,
    /// Voie de secours : commande `ca-server` lancée sur son hôte. L'opérateur
    /// est déclaré, pas authentifié ; le contrôle réel est l'accès à l'hôte
    /// (RBAC `kubectl exec`).
    Cli(SystemIdentity),
    /// Décision prise par le système lui-même, sans opérateur humain
    /// (révocation `superseded` au renouvellement).
    Automatic,
}

/// Identité du processus qui exécute une commande de secours, relevée par le
/// système et non déclarée par l'opérateur. Derrière un `kubectl exec`, elle
/// désigne le conteneur, pas la personne : celle-ci n'apparaît que dans le
/// journal d'audit de l'API Kubernetes, à recouper avec l'hôte consigné ici.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SystemIdentity {
    pub uid: Option<u32>,
    pub user: String,
    pub host: String,
}

impl SystemIdentity {
    /// Relève l'identité du processus courant (Linux : `/proc`, `/etc/passwd`).
    /// Ce qui ne peut être lu reste vide plutôt que d'être inventé.
    pub fn current() -> SystemIdentity {
        let uid = std::fs::read_to_string("/proc/self/status")
            .ok()
            .and_then(|s| parse_real_uid(&s));
        let user = uid
            .and_then(|uid| {
                std::fs::read_to_string("/etc/passwd")
                    .ok()
                    .and_then(|p| user_name(&p, uid))
            })
            .or_else(|| std::env::var("USER").ok().filter(|u| !u.is_empty()))
            .unwrap_or_default();
        let host = std::fs::read_to_string("/proc/sys/kernel/hostname")
            .ok()
            .map(|h| h.trim().to_string())
            .filter(|h| !h.is_empty())
            .or_else(|| std::env::var("HOSTNAME").ok())
            .unwrap_or_default();
        SystemIdentity { uid, user, host }
    }
}

/// UID réel (premier champ de la ligne `Uid:` de `/proc/<pid>/status`).
fn parse_real_uid(status: &str) -> Option<u32> {
    status
        .lines()
        .find_map(|l| l.strip_prefix("Uid:"))
        .and_then(|rest| rest.split_whitespace().next())
        .and_then(|uid| uid.parse().ok())
}

fn user_name(passwd: &str, uid: u32) -> Option<String> {
    passwd.lines().find_map(|line| {
        let mut fields = line.split(':');
        let name = fields.next()?;
        let _password = fields.next()?;
        let line_uid: u32 = fields.next()?.parse().ok()?;
        (line_uid == uid).then(|| name.to_string())
    })
}

impl Via {
    /// Valeur du champ `authenticated_via` du journal (docs/WEBUI.md §20).
    pub fn label(&self) -> &'static str {
        match self {
            Via::WebAuthn => "webauthn",
            Via::Cli(_) => "cli",
            Via::Automatic => "automatique",
        }
    }

    /// Une décision prise par la voie de secours doit se justifier : sans
    /// signature, le commentaire est la seule trace de son motif.
    pub fn check_comment(&self, comment: &str) -> Result<(), String> {
        if matches!(self, Via::Cli(_)) && comment.trim().is_empty() {
            return Err(
                "une décision prise par le CLI (voie de secours) exige un commentaire qui la motive"
                    .to_string(),
            );
        }
        Ok(())
    }

    /// Ajoute `authenticated_via` (et, pour le CLI, `identite_systeme`) aux
    /// données d'un événement du journal.
    pub fn annotate(&self, data: &mut serde_json::Value) {
        let Some(map) = data.as_object_mut() else {
            return;
        };
        map.insert(
            "authenticated_via".to_string(),
            serde_json::Value::from(self.label()),
        );
        if let Via::Cli(identity) = self {
            map.insert(
                "identite_systeme".to_string(),
                serde_json::json!({
                    "authentifiee": false,
                    "uid": identity.uid,
                    "utilisateur": identity.user,
                    "hote": identity.host,
                }),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_real_uid_is_read_from_proc_status() {
        let status = "Name:\tca-server\nUid:\t1000\t0\t0\t0\nGid:\t1000\t1000\t1000\t1000\n";
        assert_eq!(parse_real_uid(status), Some(1000));
        assert_eq!(parse_real_uid("Name:\tx\n"), None);
    }

    #[test]
    fn the_user_name_is_looked_up_by_uid() {
        let passwd =
            "root:x:0:0:root:/root:/bin/sh\nopeneidas:x:10001:10001::/home:/sbin/nologin\n";
        assert_eq!(user_name(passwd, 10001).as_deref(), Some("openeidas"));
        assert_eq!(user_name(passwd, 42), None);
    }

    #[test]
    fn a_cli_decision_requires_a_comment() {
        let cli = Via::Cli(SystemIdentity::current());
        assert!(cli.check_comment("  ").is_err());
        assert!(cli.check_comment("identité vérifiée").is_ok());
        assert!(Via::WebAuthn.check_comment("").is_ok());
        assert!(Via::Automatic.check_comment("").is_ok());
    }

    #[test]
    fn only_the_cli_carries_the_system_identity() {
        let mut data = serde_json::json!({"operateur": "prenom.nom"});
        Via::Cli(SystemIdentity {
            uid: Some(0),
            user: "root".to_string(),
            host: "ca-0".to_string(),
        })
        .annotate(&mut data);
        assert_eq!(data["authenticated_via"], "cli");
        assert_eq!(data["identite_systeme"]["authentifiee"], false);
        assert_eq!(data["identite_systeme"]["hote"], "ca-0");

        let mut data = serde_json::json!({});
        Via::WebAuthn.annotate(&mut data);
        assert_eq!(data["authenticated_via"], "webauthn");
        assert!(data.get("identite_systeme").is_none());
    }
}
