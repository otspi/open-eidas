//! Revue a posteriori des décisions prises par la voie de secours (constat
//! R-1 de l'audit du 2026-09-25, docs/WEBUI.md §20, décision O4) : le CLI
//! `ra approve|reject` et `revoke` reste ouvert, mais chacune de ses décisions
//! (`authenticated_via: "cli"`) doit être relue par une personne, et cette
//! relecture doit elle-même laisser une trace.
//!
//! Tout part du journal chaîné, qui fait foi : la revue lit ce qu'il atteste,
//! jamais la base. Un acquittement (`ra.cli_decisions_reviewed`) couvre les
//! enregistrements jusqu'à un numéro donné ; la revue suivante repart de là.

use oe_audit::Record;

/// Événement d'acquittement d'une revue.
pub const REVIEW_EVENT: &str = "ra.cli_decisions_reviewed";

/// Une décision prise par la voie de secours, telle que le journal l'atteste.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct CliDecision {
    pub seq: u64,
    pub time: String,
    pub event: String,
    pub operator: String,
    pub comment: String,
    /// Transaction (décision RA) ou numéro de série (révocation).
    pub subject: String,
    pub host: String,
    pub uid: Option<u64>,
}

/// Ce qu'une revue a devant elle.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct Review {
    /// Décisions CLI non encore couvertes par un acquittement (ou postérieures
    /// à `--since`).
    pub decisions: Vec<CliDecision>,
    /// Numéro du dernier enregistrement couvert par le dernier acquittement
    /// (0 : aucun).
    pub acknowledged_up_to: u64,
    /// Numéro du dernier enregistrement lu : ce qu'un acquittement couvrira.
    pub head: u64,
}

fn str_field(data: &oe_audit::Data, key: &str) -> String {
    data.get(key)
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string()
}

/// Relève les décisions CLI à revoir. Sans `since`, la fenêtre part du dernier
/// acquittement ; avec `since` (date de l'enregistrement, RFC 3339), elle part
/// de cette date, acquittements ou non — pour relire une période passée.
pub fn review(records: &[Record], since: Option<time::OffsetDateTime>) -> Result<Review, String> {
    let acknowledged_up_to = records
        .iter()
        .rev()
        .find(|r| r.event == REVIEW_EVENT)
        .and_then(|r| r.data.as_ref()?.get("jusqu_a")?.as_u64())
        .unwrap_or(0);
    let head = records.last().map(|r| r.seq).unwrap_or(0);

    let mut decisions = Vec::new();
    for r in records {
        // L'acquittement passe lui aussi par le CLI, mais ce n'est pas une
        // décision : le relister rendrait toute revue interminable.
        if r.event == REVIEW_EVENT {
            continue;
        }
        let Some(data) = &r.data else { continue };
        if data.get("authenticated_via").and_then(|v| v.as_str()) != Some("cli") {
            continue;
        }
        let in_window = match since {
            Some(since) => {
                let at = time::OffsetDateTime::parse(
                    &r.time,
                    &time::format_description::well_known::Rfc3339,
                )
                .map_err(|e| format!("enregistrement n° {} : date illisible : {e}", r.seq))?;
                at >= since
            }
            None => r.seq > acknowledged_up_to,
        };
        if !in_window {
            continue;
        }
        let identity = data.get("identite_systeme");
        let subject = [str_field(data, "transaction"), str_field(data, "serie")]
            .into_iter()
            .find(|s| !s.is_empty())
            .unwrap_or_default();
        decisions.push(CliDecision {
            seq: r.seq,
            time: r.time.clone(),
            event: r.event.clone(),
            operator: str_field(data, "operateur"),
            comment: str_field(data, "commentaire"),
            subject,
            host: identity
                .and_then(|i| i.get("hote"))
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string(),
            uid: identity.and_then(|i| i.get("uid")).and_then(|v| v.as_u64()),
        });
    }
    Ok(Review {
        decisions,
        acknowledged_up_to,
        head,
    })
}

/// Données de l'événement d'acquittement : qui a relu, jusqu'où, combien de
/// décisions, et pourquoi (le relecteur n'est que déclaré, comme toute
/// commande de secours : l'appelant y ajoute `authenticated_via`).
pub fn acknowledgement(review: &Review, reviewer: &str, comment: &str) -> serde_json::Value {
    serde_json::json!({
        "relecteur": reviewer,
        "commentaire": comment,
        "jusqu_a": review.head,
        "depuis": review.acknowledged_up_to,
        "decisions": review.decisions.len(),
        "sequences": review.decisions.iter().map(|d| d.seq).collect::<Vec<_>>(),
    })
}
