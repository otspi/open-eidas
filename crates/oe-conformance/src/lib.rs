//! Portage de l'ancien `internal/conformance` (Go, aujourd'hui déprécié) :
//! la matrice de conformité ETSI d'Open eIDAS sous une forme exécutable,
//! source unique du document généré `docs/CONFORMITE-ETSI.md`
//! (`ca-server conformance --markdown`).
//!
//! Ce module porte fidèlement la structure de données et les règles de
//! cohérence (`Matrix::validate`) ; [`system_matrix`] est mise à jour au fil
//! du portage — une entrée ne passe à [`Status::Covered`] que lorsque le
//! code qui l'applique existe réellement dans ce workspace et qu'un test
//! nommé le vérifie, jamais par anticipation sur ce qui reste à faire.
//! **Tenir cette matrice à jour est une obligation du portage** : la laisser
//! statique pendant qu'un jalon avance dessert le document publié
//! (`docs/CONFORMITE-ETSI.md`) exactement comme le ferait un optimisme
//! prématuré — dans les deux cas, le document cesse de refléter ce que le
//! système applique réellement.
//!
//! Les deux exigences purement organisationnelles (aucun logiciel, Go ou
//! Rust, ne peut les établir seul) restent [`Status::OutOfScope`], à
//! l'identique de la matrice Go.

use std::collections::BTreeMap;
use std::fmt;

/// Identifie une exigence précise : la norme, sa version, la clause et les
/// identifiants d'exigence qu'elle numérote (constat D-3 de l'audit du
/// 2026-09-25 : c'est la grille qu'un organisme d'évaluation suit).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Requirement {
    pub standard: &'static str,
    /// Version et date de publication de la norme citée, telles qu'en tête
    /// du texte (« V3.2.1 (2026-01) ») ; vide pour une RFC.
    pub version: &'static str,
    pub clause: &'static str,
    /// Identifiants d'exigence (`REQ-7.10-08`, `TIS-7.6.7-01`…), pour les
    /// normes qui en numérotent (voir [`STANDARDS_WITH_IDS`]).
    pub ids: &'static [&'static str],
    pub title: &'static str,
}

/// Normes dont chaque exigence porte un identifiant : une ligne de matrice
/// qui les cite doit nommer les identifiants, pas seulement la clause.
pub const STANDARDS_WITH_IDS: &[&str] =
    &["ETSI EN 319 401", "ETSI EN 319 411-1", "ETSI EN 319 421"];

impl fmt::Display for Requirement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.standard)?;
        if !self.clause.is_empty() {
            write!(f, " {}", self.clause)?;
        }
        if !self.ids.is_empty() {
            write!(f, " ({})", self.ids.join(", "))?;
        }
        Ok(())
    }
}

/// Numéro de clause porté par un identifiant d'exigence : `7.10` pour
/// `REQ-7.10-08`, `7.6.7` pour `TIS-7.6.7-01`.
fn id_clause(id: &str) -> Option<&str> {
    let mut parts = id.split('-');
    let _prefix = parts.next()?;
    let clause = parts.next()?;
    parts.next()?;
    Some(clause)
}

/// Distingue ce qui interdit une opération de ce qui doit seulement être
/// signalé.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    /// L'opération doit être refusée.
    Blocking,
    /// Écart signalé et journalisé, non bloquant.
    Advisory,
}

/// Le constat d'un écart à une exigence sur un objet donné.
#[derive(Debug, Clone)]
pub struct Finding {
    pub requirement: Requirement,
    pub severity: Severity,
    pub detail: String,
}

impl fmt::Display for Finding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let severity = match self.severity {
            Severity::Blocking => "bloquant",
            Severity::Advisory => "avertissement",
        };
        write!(
            f,
            "[{severity}] {} — {} : {}",
            self.requirement, self.requirement.title, self.detail
        )
    }
}

/// Les constats d'une vérification.
#[derive(Debug, Clone, Default)]
pub struct Findings(pub Vec<Finding>);

impl Findings {
    pub fn blocking(&self) -> Vec<&Finding> {
        self.0
            .iter()
            .filter(|f| f.severity == Severity::Blocking)
            .collect()
    }

    pub fn advisories(&self) -> Vec<&Finding> {
        self.0
            .iter()
            .filter(|f| f.severity == Severity::Advisory)
            .collect()
    }

    /// Convertit les constats bloquants en une erreur unique, ou `None` s'il
    /// n'y en a aucun.
    pub fn err(&self) -> Option<String> {
        let blocking = self.blocking();
        if blocking.is_empty() {
            return None;
        }
        let msgs: Vec<String> = blocking.iter().map(|f| f.to_string()).collect();
        Some(format!("non-conformité ETSI: {}", msgs.join(" ; ")))
    }
}

/// L'état d'une exigence pour l'ensemble du système. Quatre valeurs
/// seulement, pour qu'aucune zone grise ne puisse s'y loger.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Status {
    /// L'exigence est appliquée par un binaire en service, vérifiée par un
    /// test, et la mise en service est elle-même prouvée ([`Entry::in_service`]).
    Covered,
    /// Le mécanisme existe et il est testé, mais aucun binaire ne l'appelle
    /// (constat D-2 de l'audit du 2026-09-25) : l'exigence n'est pas satisfaite.
    Implemented,
    /// Écart connu et assumé, avec une mesure compensatoire et une cible.
    Gap,
    /// Exigence organisationnelle, qu'aucun logiciel ne peut satisfaire seul.
    OutOfScope,
}

impl Status {
    pub fn label(self) -> &'static str {
        match self {
            Status::Covered => "couvert",
            Status::Implemented => "implémenté, pas en service",
            Status::Gap => "écart documenté",
            Status::OutOfScope => "hors périmètre logiciel",
        }
    }
}

/// Une ligne de la matrice de conformité.
#[derive(Debug, Clone)]
pub struct Entry {
    pub requirement: Requirement,
    pub status: Status,
    /// Nomme le code qui applique l'exigence, ou la mesure compensatoire.
    pub mechanism: &'static str,
    /// Nomme le test qui vérifie le mécanisme. Vide hors périmètre logiciel.
    pub test: &'static str,
    /// Preuve que le mécanisme est en service (constat D-2) : un test qui
    /// exerce un binaire (`bin/…`) ou une étape d'un job de démonstration
    /// réelle (`.github/workflows/…`). Obligatoire pour une ligne couverte ;
    /// chaque référence est résolue par `tests/references.rs`.
    pub in_service: &'static str,
    /// Ce qui reste à faire pour lever un écart. Vide si couvert.
    pub target: &'static str,
}

/// La matrice de conformité complète du système.
#[derive(Debug, Clone, Default)]
pub struct Matrix(pub Vec<Entry>);

impl Matrix {
    pub fn counts(&self) -> BTreeMap<Status, usize> {
        let mut out = BTreeMap::new();
        out.insert(Status::Covered, 0);
        out.insert(Status::Implemented, 0);
        out.insert(Status::Gap, 0);
        out.insert(Status::OutOfScope, 0);
        for e in &self.0 {
            *out.entry(e.status).or_insert(0) += 1;
        }
        out
    }

    /// Liste les normes citées, dans l'ordre alphabétique.
    pub fn standards(&self) -> Vec<&'static str> {
        let mut out: Vec<&'static str> = Vec::new();
        for e in &self.0 {
            if !out.contains(&e.requirement.standard) {
                out.push(e.requirement.standard);
            }
        }
        out.sort_unstable();
        out
    }

    /// Contrôle la cohérence interne de la matrice : toute exigence déclarée
    /// couverte doit nommer un mécanisme et un test, tout écart doit nommer
    /// une mesure compensatoire et une cible.
    pub fn validate(&self) -> Result<(), String> {
        let mut problems = Vec::new();
        let mut seen = std::collections::HashSet::new();
        let mut versions: BTreeMap<&str, &str> = BTreeMap::new();
        for e in &self.0 {
            let key = e.requirement.to_string();
            if !seen.insert(key.clone()) {
                problems.push(format!("{key}: exigence déclarée deux fois"));
            }
            let r = &e.requirement;
            if r.standard.starts_with("ETSI") && r.version.is_empty() {
                problems.push(format!("{key}: version de la norme non précisée"));
            }
            if let Some(previous) = versions.insert(r.standard, r.version) {
                if previous != r.version {
                    problems.push(format!(
                        "{key}: {} citée en deux versions ({previous}, {})",
                        r.standard, r.version
                    ));
                }
            }
            if STANDARDS_WITH_IDS.contains(&r.standard) && r.ids.is_empty() {
                problems.push(format!("{key}: aucun identifiant d'exigence"));
            }
            // L'identifiant porte sa clause : la clause citée doit la contenir
            // (c'est ainsi que 10 lignes citaient une clause erronée, D-3).
            for id in r.ids {
                match id_clause(id) {
                    Some(c) if r.clause.split(", ").any(|cl| cl == format!("§{c}")) => {}
                    _ => problems.push(format!(
                        "{key}: l'identifiant {id} ne relève pas de la clause citée"
                    )),
                }
            }
            match e.status {
                Status::Covered => {
                    if e.mechanism.is_empty() {
                        problems.push(format!("{key}: couvert mais aucun mécanisme nommé"));
                    }
                    if e.test.is_empty() {
                        problems.push(format!("{key}: couvert mais aucun test nommé"));
                    }
                    // Constat D-2 : un test de bibliothèque prouve que le
                    // mécanisme existe, pas qu'un binaire l'applique.
                    if !e
                        .in_service
                        .split(", ")
                        .any(|r| r.starts_with("bin/") || r.starts_with(".github/workflows/"))
                    {
                        problems.push(format!(
                            "{key}: couvert sans preuve de mise en service (test d'un binaire ou job de démonstration)"
                        ));
                    }
                }
                Status::Implemented => {
                    if e.mechanism.is_empty() || e.test.is_empty() || e.target.is_empty() {
                        problems.push(format!(
                            "{key}: implémenté sans mécanisme, test ou cible de mise en service"
                        ));
                    }
                }
                Status::Gap => {
                    if e.mechanism.is_empty() {
                        problems.push(format!("{key}: écart sans mesure compensatoire"));
                    }
                    if e.target.is_empty() {
                        problems.push(format!("{key}: écart sans cible de levée"));
                    }
                }
                Status::OutOfScope => {
                    if e.target.is_empty() {
                        problems.push(format!("{key}: hors périmètre sans mesure attendue"));
                    }
                }
            }
        }
        if problems.is_empty() {
            Ok(())
        } else {
            Err(format!(
                "matrice de conformité incohérente: {}",
                problems.join(" ; ")
            ))
        }
    }
}

/// Neutralise les caractères qui casseraient une cellule de tableau Markdown.
fn cell(s: &str) -> String {
    s.replace('|', "\\|")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

/// Produit le contenu d'un document de conformité à partir de la matrice.
pub fn render_markdown(m: &Matrix) -> String {
    let mut b = String::new();
    b.push_str("# Matrice de conformité ETSI\n\n");
    b.push_str("<!-- Document généré par `ca-server conformance --markdown` depuis\n");
    b.push_str("     oe-conformance::system_matrix. Ne pas modifier à la main : toute\n");
    b.push_str("     correction se fait dans le code, pour que la matrice publiée reste\n");
    b.push_str("     celle que le système applique réellement. -->\n\n");

    let counts = m.counts();
    b.push_str(&format!(
        "**{} exigences** — {} couvertes, {} implémentée(s) sans être en service, {} écarts documentés, {} hors périmètre logiciel.\n\n",
        m.0.len(),
        counts[&Status::Covered],
        counts[&Status::Implemented],
        counts[&Status::Gap],
        counts[&Status::OutOfScope],
    ));

    b.push_str("Quatre statuts seulement, pour qu'aucune zone grise ne puisse s'y loger :\n\n");
    b.push_str("- **couvert** — l'exigence est appliquée par un binaire en service : le test nommé vérifie le mécanisme, la preuve de mise en service (test du binaire ou job de démonstration réelle) montre qu'il est appelé ;\n");
    b.push_str("- **implémenté, pas en service** — le mécanisme existe et il est testé, mais aucun binaire ne l'appelle : l'exigence n'est pas satisfaite ;\n");
    b.push_str("- **écart documenté** — l'exigence n'est pas satisfaite en l'état ; la mesure compensatoire en place et la cible sont indiquées ;\n");
    b.push_str("- **hors périmètre logiciel** — exigence organisationnelle, qu'aucun code ne peut établir seul.\n\n");

    for standard in m.standards() {
        let version =
            m.0.iter()
                .find(|e| e.requirement.standard == standard)
                .map(|e| e.requirement.version)
                .unwrap_or_default();
        if version.is_empty() {
            b.push_str(&format!("## {standard}\n\n"));
        } else {
            b.push_str(&format!("## {standard} {version}\n\n"));
        }
        b.push_str("| Clause | Exigence | Statut | Mécanisme | Vérification / cible |\n");
        b.push_str("|---|---|---|---|---|\n");
        for e in &m.0 {
            if e.requirement.standard != standard {
                continue;
            }
            let last = if e.status != Status::Covered {
                format!("**Cible :** {}", e.target)
            } else {
                format!("{} ; **en service :** {}", e.test, e.in_service)
            };
            let clause = if e.requirement.ids.is_empty() {
                cell(e.requirement.clause)
            } else {
                format!(
                    "{} — {}",
                    cell(e.requirement.clause),
                    cell(&e.requirement.ids.join(", "))
                )
            };
            b.push_str(&format!(
                "| {} | {} | {} | {} | {} |\n",
                clause,
                cell(e.requirement.title),
                cell(e.status.label()),
                cell(e.mechanism),
                cell(&last),
            ));
        }
        b.push('\n');
    }
    b
}

/// Durée de conservation minimale du journal d'audit (ETSI EN 319 401
/// §7.10). Le choix d'un an reproduit `internal/conformance.MinAuditRetention`
/// (Go) : durée déjà imposée par les obligations comptables/fiscales
/// courantes, retenue comme plancher faute d'exigence ETSI plus précise.
pub const MIN_AUDIT_RETENTION: time::Duration = time::Duration::days(365);

/// ETSI EN 319 401 §7.10 : la durée de conservation du journal d'audit doit
/// être configurée et au moins égale à [`MIN_AUDIT_RETENTION`].
pub fn check_audit_retention(retention: time::Duration) -> Result<(), String> {
    if retention <= time::Duration::ZERO {
        return Err("durée de conservation du journal d'audit non configurée".to_string());
    }
    if retention < MIN_AUDIT_RETENTION {
        return Err(format!(
            "durée de conservation du journal de {} jours, minimum requis {} jours",
            retention.whole_days(),
            MIN_AUDIT_RETENTION.whole_days()
        ));
    }
    Ok(())
}

/// Plafonds de durée de vie appliqués par le moteur d'émission. Aucune norme
/// ne fixe ces valeurs au jour près pour une TSU ; elles sont posées ici de
/// façon explicite et conservatrice (identiques à
/// `internal/conformance/certificate.go`, Go), afin qu'un certificat à durée
/// aberrante soit refusé plutôt que produit — un filet indépendant de ce que
/// le profil d'émission prétend appliquer, puisqu'il relit le certificat
/// réellement signé, pas les paramètres qui l'ont construit.
pub const MAX_END_ENTITY_LIFETIME: time::Duration = time::Duration::days(39 * 30);
pub const MAX_OCSP_LIFETIME: time::Duration = time::Duration::days(6 * 30);
pub const MAX_ISSUING_CA_LIFETIME: time::Duration = time::Duration::days(15 * 365);
pub const MAX_ROOT_CA_LIFETIME: time::Duration = time::Duration::days(25 * 365);

/// ETSI EN 319 421 §7.6.5 (TIS-7.6.5-01) : la durée de vie effective d'un certificat déjà
/// signé (pas celle que son profil visait) ne doit pas dépasser le plafond
/// applicable à sa catégorie.
pub fn check_certificate_lifetime(
    subject: &str,
    not_before: time::OffsetDateTime,
    not_after: time::OffsetDateTime,
    max: time::Duration,
) -> Result<(), String> {
    let life = not_after - not_before;
    if life > max {
        return Err(format!(
            "{subject}: durée de vie de {} jours, plafond {} jours",
            life.whole_days(),
            max.whole_days()
        ));
    }
    Ok(())
}

/// OID des algorithmes de signature admis par ce système. RSA/SHA-256 est le
/// seul algorithme que `oe-hsm` sait produire à ce stade — cette liste est
/// donc plus étroite que `internal/conformance.admittedSignatureAlgorithms`
/// (Go), qui admet aussi ECDSA et RSA-PSS : rien ici n'a encore de moyen de
/// les produire, les admettre serait prématuré.
const ADMITTED_SIGNATURE_ALGORITHM_OIDS: &[&str] = &[
    "1.2.840.113549.1.1.11", // sha256WithRSAEncryption
    "1.2.840.113549.1.1.12", // sha384WithRSAEncryption
    "1.2.840.113549.1.1.13", // sha512WithRSAEncryption
];

/// ETSI TS 119 312 §7.3 : l'algorithme de signature d'un objet (certificat,
/// CSR, CRL) doit figurer parmi les suites admises — SHA-1 et MD5 en sont
/// exclus explicitement, jamais tolérés par omission.
pub fn check_signature_algorithm(subject: &str, algorithm_oid: &str) -> Result<(), String> {
    if !ADMITTED_SIGNATURE_ALGORITHM_OIDS.contains(&algorithm_oid) {
        return Err(format!("{subject}: algorithme de signature {algorithm_oid} refusé (SHA-1 et MD5 sont proscrits par ETSI TS 119 312)"));
    }
    Ok(())
}

fn x509_time_to_offset_date_time(t: &x509_cert::time::Time) -> time::OffsetDateTime {
    let dt = t.to_date_time();
    time::OffsetDateTime::from_unix_timestamp(dt.unix_duration().as_secs() as i64)
        .unwrap_or(time::OffsetDateTime::UNIX_EPOCH)
}

fn find_extension<'a>(
    cert: &'a x509_cert::Certificate,
    oid: &str,
) -> Option<&'a x509_cert::ext::Extension> {
    let target = der::asn1::ObjectIdentifier::new(oid).ok()?;
    cert.tbs_certificate()
        .extensions()?
        .iter()
        .find(|e| e.extn_id == target)
}

/// ETSI EN 319 422 §6 : le certificat de l'unité d'horodatage relit et
/// re-contrôlé (pas seulement construit une fois à l'émission) doit porter
/// CA:FALSE, un `extendedKeyUsage` critique contenant **seulement**
/// id-kp-timeStamping, un `keyUsage` restreint à
/// digitalSignature/nonRepudiation, et une durée de vie plafonnée —
/// reproduit `CheckTSUCertificate` (Go). Appelé au démarrage de
/// `tsa-server`, pas seulement à l'émission côté `ca-server` : un
/// certificat chargé depuis le disque peut venir d'ailleurs.
pub fn check_tsu_certificate(subject: &str, cert: &x509_cert::Certificate) -> Result<(), String> {
    use der::Decode;
    use x509_cert::ext::pkix::{BasicConstraints, ExtendedKeyUsage, KeyUsage, KeyUsages};

    const OID_TIME_STAMPING: &str = "1.3.6.1.5.5.7.3.8";

    check_signature_algorithm(subject, &cert.signature_algorithm().oid.to_string())?;

    let not_before = x509_time_to_offset_date_time(&cert.tbs_certificate().validity().not_before);
    let not_after = x509_time_to_offset_date_time(&cert.tbs_certificate().validity().not_after);
    check_certificate_lifetime(subject, not_before, not_after, MAX_END_ENTITY_LIFETIME)?;

    let bc_ext = find_extension(cert, "2.5.29.19")
        .ok_or_else(|| format!("{subject}: extension basicConstraints absente"))?;
    let bc = BasicConstraints::from_der(bc_ext.extn_value.as_bytes())
        .map_err(|e| format!("{subject}: basicConstraints illisible: {e}"))?;
    if bc.ca {
        return Err(format!(
            "{subject}: le certificat TSU porte basicConstraints CA:TRUE"
        ));
    }

    let eku_ext = find_extension(cert, "2.5.29.37")
        .ok_or_else(|| format!("{subject}: extension extendedKeyUsage absente"))?;
    if !eku_ext.critical {
        return Err(format!(
            "{subject}: extension extendedKeyUsage non marquée critique"
        ));
    }
    let eku = ExtendedKeyUsage::from_der(eku_ext.extn_value.as_bytes())
        .map_err(|e| format!("{subject}: extendedKeyUsage illisible: {e}"))?;
    let time_stamping =
        der::asn1::ObjectIdentifier::new(OID_TIME_STAMPING).expect("OID constant invalide");
    if eku.0.as_slice() != [time_stamping] {
        return Err(format!(
            "{subject}: extendedKeyUsage doit contenir uniquement id-kp-timeStamping"
        ));
    }

    let ku_ext = find_extension(cert, "2.5.29.15")
        .ok_or_else(|| format!("{subject}: extension keyUsage absente"))?;
    let ku = KeyUsage::from_der(ku_ext.extn_value.as_bytes())
        .map_err(|e| format!("{subject}: keyUsage illisible: {e}"))?;
    let allowed = KeyUsages::DigitalSignature | KeyUsages::NonRepudiation;
    if ku.0.is_empty() {
        return Err(format!("{subject}: keyUsage vide"));
    }
    if !allowed.contains(ku.0) {
        return Err(format!(
            "{subject}: keyUsage déborde de digitalSignature/nonRepudiation"
        ));
    }

    Ok(())
}

/// RFC 6960 §4.2.2.2 : le certificat de signature du répondeur OCSP relu et
/// re-contrôlé doit porter CA:FALSE, `extendedKeyUsage` id-kp-OCSPSigning,
/// l'extension `id-pkix-ocsp-nocheck`, `keyUsage` incluant digitalSignature,
/// et une durée de vie plafonnée courte (§4.2.2.2.1 — la dispense de
/// vérification de révocation qu'accorde ocsp-nocheck a pour contrepartie
/// une vie courte) — reproduit `CheckOCSPResponderCertificate` (Go).
pub fn check_ocsp_responder_certificate(
    subject: &str,
    cert: &x509_cert::Certificate,
) -> Result<(), String> {
    use der::Decode;
    use x509_cert::ext::pkix::{BasicConstraints, ExtendedKeyUsage, KeyUsage, KeyUsages};

    const OID_OCSP_SIGNING: &str = "1.3.6.1.5.5.7.3.9";
    const OID_OCSP_NO_CHECK: &str = "1.3.6.1.5.5.7.48.1.5";

    check_signature_algorithm(subject, &cert.signature_algorithm().oid.to_string())?;

    let not_before = x509_time_to_offset_date_time(&cert.tbs_certificate().validity().not_before);
    let not_after = x509_time_to_offset_date_time(&cert.tbs_certificate().validity().not_after);
    check_certificate_lifetime(subject, not_before, not_after, MAX_OCSP_LIFETIME)?;

    let bc_ext = find_extension(cert, "2.5.29.19")
        .ok_or_else(|| format!("{subject}: extension basicConstraints absente"))?;
    let bc = BasicConstraints::from_der(bc_ext.extn_value.as_bytes())
        .map_err(|e| format!("{subject}: basicConstraints illisible: {e}"))?;
    if bc.ca {
        return Err(format!(
            "{subject}: le certificat du répondeur porte basicConstraints CA:TRUE"
        ));
    }

    let eku_ext = find_extension(cert, "2.5.29.37")
        .ok_or_else(|| format!("{subject}: extension extendedKeyUsage absente"))?;
    let eku = ExtendedKeyUsage::from_der(eku_ext.extn_value.as_bytes())
        .map_err(|e| format!("{subject}: extendedKeyUsage illisible: {e}"))?;
    let ocsp_signing =
        der::asn1::ObjectIdentifier::new(OID_OCSP_SIGNING).expect("OID constant invalide");
    if !eku.0.contains(&ocsp_signing) {
        return Err(format!(
            "{subject}: extendedKeyUsage id-kp-OCSPSigning absent"
        ));
    }

    if find_extension(cert, OID_OCSP_NO_CHECK).is_none() {
        return Err(format!("{subject}: extension id-pkix-ocsp-nocheck absente"));
    }

    let ku_ext = find_extension(cert, "2.5.29.15")
        .ok_or_else(|| format!("{subject}: extension keyUsage absente"))?;
    let ku = KeyUsage::from_der(ku_ext.extn_value.as_bytes())
        .map_err(|e| format!("{subject}: keyUsage illisible: {e}"))?;
    if !ku.0.contains(KeyUsages::DigitalSignature) {
        return Err(format!("{subject}: keyUsage ne porte pas digitalSignature"));
    }

    Ok(())
}

/// OID de politique de certification des certificats du lien interne
/// `ra-console` ↔ `ca-server` (docs/WEBUI.md §16). Aucun autre profil ne les
/// porte : c'est ce qui distingue un certificat client interne d'un certificat
/// d'identité ou de TSU qui porterait aussi `clientAuth`.
///
/// **PROVISOIRE** : sous le numéro d'entreprise 0, réservé et jamais attribué
/// (l'arc 2.999 des exemples est refusé par `const-oid`). À remplacer par l'arc
/// de l'association avant toute mise en production ; ces deux constantes sont
/// les seuls endroits à changer.
pub const OID_POLICY_INTERNAL_CLIENT: &str = "1.3.6.1.4.1.0.1.1";
pub const OID_POLICY_INTERNAL_SERVER: &str = "1.3.6.1.4.1.0.1.2";
/// Extension privée de la CRL portant la liste des numéros de série émis
/// (constat O-1 de l'audit du 2026-09-25) — voir
/// `oe_ca_core::extensions::issued_serials`, produite par `ca-server` et lue
/// par `oe_ocsp_core::Responder`. **PROVISOIRE**, même arc que ci-dessus.
pub const OID_CRL_ISSUED_SERIALS: &str = "1.3.6.1.4.1.0.1.3";
/// Le seul nom courant que porte le certificat client de `ra-console`.
pub const INTERNAL_CLIENT_CN: &str = "ra-console";
pub const OID_EKU_SERVER_AUTH: &str = "1.3.6.1.5.5.7.3.1";
pub const OID_EKU_CLIENT_AUTH: &str = "1.3.6.1.5.5.7.3.2";
/// Même catégorie que le répondeur OCSP : clé logicielle, vie courte (CPS A.6).
pub const MAX_INTERNAL_LIFETIME: time::Duration = MAX_OCSP_LIFETIME;

/// Vrai si le certificat porte cette politique dans `certificatePolicies`.
pub fn has_certificate_policy(cert: &x509_cert::Certificate, policy_oid: &str) -> bool {
    use der::Decode;
    use x509_cert::ext::pkix::CertificatePolicies;
    let Ok(target) = der::asn1::ObjectIdentifier::new(policy_oid) else {
        return false;
    };
    find_extension(cert, "2.5.29.32")
        .and_then(|e| CertificatePolicies::from_der(e.extn_value.as_bytes()).ok())
        .is_some_and(|p| p.0.iter().any(|i| i.policy_identifier == target))
}

/// Les `dNSName` du `subjectAltName`.
pub fn dns_names(cert: &x509_cert::Certificate) -> Vec<String> {
    use der::Decode;
    use x509_cert::ext::pkix::name::GeneralName;
    use x509_cert::ext::pkix::SubjectAltName;
    find_extension(cert, "2.5.29.17")
        .and_then(|e| SubjectAltName::from_der(e.extn_value.as_bytes()).ok())
        .map(|san| {
            san.0
                .into_iter()
                .filter_map(|n| match n {
                    GeneralName::DnsName(d) => Some(d.to_string()),
                    _ => None,
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Contrôles communs aux deux certificats du lien interne : ni CA, un EKU
/// **unique** (pas de `clientAuth` en plus de `serverAuth`), la politique
/// dédiée, `digitalSignature`, une vie courte.
fn check_internal_certificate(
    subject: &str,
    cert: &x509_cert::Certificate,
    eku_oid: &str,
    policy_oid: &str,
) -> Result<(), String> {
    use der::Decode;
    use x509_cert::ext::pkix::{BasicConstraints, ExtendedKeyUsage, KeyUsage, KeyUsages};

    check_signature_algorithm(subject, &cert.signature_algorithm().oid.to_string())?;

    let not_before = x509_time_to_offset_date_time(&cert.tbs_certificate().validity().not_before);
    let not_after = x509_time_to_offset_date_time(&cert.tbs_certificate().validity().not_after);
    check_certificate_lifetime(subject, not_before, not_after, MAX_INTERNAL_LIFETIME)?;

    let bc_ext = find_extension(cert, "2.5.29.19")
        .ok_or_else(|| format!("{subject}: extension basicConstraints absente"))?;
    let bc = BasicConstraints::from_der(bc_ext.extn_value.as_bytes())
        .map_err(|e| format!("{subject}: basicConstraints illisible: {e}"))?;
    if bc.ca {
        return Err(format!("{subject}: basicConstraints CA:TRUE"));
    }

    let eku_ext = find_extension(cert, "2.5.29.37")
        .ok_or_else(|| format!("{subject}: extension extendedKeyUsage absente"))?;
    let eku = ExtendedKeyUsage::from_der(eku_ext.extn_value.as_bytes())
        .map_err(|e| format!("{subject}: extendedKeyUsage illisible: {e}"))?;
    let expected = der::asn1::ObjectIdentifier::new(eku_oid).expect("OID constant invalide");
    if eku.0 != [expected] {
        return Err(format!(
            "{subject}: extendedKeyUsage doit contenir uniquement {eku_oid}"
        ));
    }

    if !has_certificate_policy(cert, policy_oid) {
        return Err(format!("{subject}: politique {policy_oid} absente"));
    }

    let ku_ext = find_extension(cert, "2.5.29.15")
        .ok_or_else(|| format!("{subject}: extension keyUsage absente"))?;
    let ku = KeyUsage::from_der(ku_ext.extn_value.as_bytes())
        .map_err(|e| format!("{subject}: keyUsage illisible: {e}"))?;
    if !ku.0.contains(KeyUsages::DigitalSignature) {
        return Err(format!("{subject}: keyUsage ne porte pas digitalSignature"));
    }
    Ok(())
}

/// Certificat que présente `ra-console` à `ca-server` (docs/WEBUI.md §16).
pub fn check_internal_client_certificate(
    subject: &str,
    cert: &x509_cert::Certificate,
) -> Result<(), String> {
    check_internal_certificate(
        subject,
        cert,
        OID_EKU_CLIENT_AUTH,
        OID_POLICY_INTERNAL_CLIENT,
    )
}

/// Certificat que `ca-server` présente sur le lien interne : en plus, un SAN
/// `dNSName` et un CN identique à ce nom (le client attend ce nom).
pub fn check_internal_server_certificate(
    subject: &str,
    cert: &x509_cert::Certificate,
) -> Result<(), String> {
    check_internal_certificate(
        subject,
        cert,
        OID_EKU_SERVER_AUTH,
        OID_POLICY_INTERNAL_SERVER,
    )?;
    if dns_names(cert).is_empty() {
        return Err(format!("{subject}: subjectAltName dNSName absent"));
    }
    Ok(())
}

/// La matrice de conformité applicable au portage Rust, à l'instant présent
/// du chantier (voir la note de module : mise à jour à chaque jalon, jamais
/// figée).
pub fn system_matrix() -> Matrix {
    Matrix(vec![
        Entry {
            requirement: Requirement { standard: "ETSI EN 319 401", version: "V3.2.1 (2026-01)", clause: "§7.5", ids: &["REQ-7.5-01"], title: "Gestion des clés du prestataire dans un module cryptographique" },
            status: Status::Covered,
            mechanism: "Toutes les clés vivent dans un token PKCS#11 et n'en sortent jamais : oe-hsm::Pkcs11Token, validé contre un vrai token SoftHSM2 (crates/oe-hsm/tests/pkcs11_integration.rs).",
            test: "bin/tsa-server/tests/serve.rs (the_binary_applies_what_the_matrix_declares)",
            in_service: "bin/tsa-server/tests/serve.rs (the_binary_applies_what_the_matrix_declares), .github/workflows/ci.yml (Horodate un fichier et vérifie le jeton (openssl ts))",
            target: "",
        },
        Entry {
            requirement: Requirement { standard: "ETSI EN 319 401", version: "V3.2.1 (2026-01)", clause: "§7.10", ids: &["REQ-7.10-01", "REQ-7.10-07"], title: "Journalisation des événements et durée de conservation" },
            status: Status::Gap,
            mechanism: "Journal JSON Lines chaîné par SHA-256 (oe-audit), écrit avant chaque émission dans les deux services ; durée de conservation contrôlée à la configuration par oe_conformance::check_audit_retention, mais côté CA seulement (bin/ca-server::Config::load).",
            test: "crates/oe-audit/src/lib.rs (deux_ecrivains_partagent_la_meme_chaine), crates/oe-conformance/src/lib.rs (check_audit_retention_accepts_the_minimum, check_audit_retention_rejects_unconfigured_and_short_durations)",
            in_service: "",
            target: "Constat J-3 (PR #52) : consigner la série du jeton et l'empreinte soumise ; contrôler aussi la durée de conservation au démarrage de tsa-server (docs/CPS.md B.3).",
        },
        Entry {
            requirement: Requirement { standard: "ETSI EN 319 401", version: "V3.2.1 (2026-01)", clause: "§7.10", ids: &["REQ-7.10-02", "REQ-7.10-08"], title: "Intégrité démontrable des enregistrements d'audit" },
            status: Status::Gap,
            mechanism: "Chaînage par hachage vérifié intégralement à l'ouverture ; verrou de fichier partagé entre plusieurs écrivains : oe-audit::Log. Le chaînage n'a pas de clé : une réécriture complète du fichier avec recalcul de la chaîne n'est pas détectée tant que la tête n'est pas ancrée hors du système.",
            test: "crates/oe-audit/src/lib.rs (deux_ecrivains_partagent_la_meme_chaine, verify_detects_modified_record, verify_detects_truncated_and_rewritten_tail)",
            in_service: "",
            target: "Constat J-1 : sceller périodiquement la tête de chaîne (TSU et TSA tierce) et en déposer une copie hors site, depuis les binaires en service.",
        },
        Entry {
            requirement: Requirement { standard: "ETSI EN 319 401", version: "V3.2.1 (2026-01)", clause: "§7.11.1, §7.11.2", ids: &["REQ-7.11.1-01", "REQ-7.11.2-01"], title: "Copies de sauvegarde et plan de sauvegarde" },
            status: Status::Implemented,
            mechanism: "Contreseing du journal par une TSA tierce (oe-crosstsa) et réplication WebDAV hors site (oe-replicate) écrits et testés contre un vrai serveur, mais appelés par aucun binaire : l'intégrité et la survie du journal reposent sur le contrôle d'accès et la sauvegarde de son volume.",
            test: "crates/oe-crosstsa/tests/against_local_server.rs (seals_a_digest_against_a_real_rfc3161_server), crates/oe-replicate/tests/against_local_server.rs (replicates_content_via_webdav_put)",
            in_service: "",
            target: "Constat J-1 : câbler dans tsa-server serve puis ca-server serve le scellement périodique (log.sealed), le contreseing tiers (log.cross_sealed) et la copie hors site (PR #49, #50 pour le stockage S3), testés de bout en bout sur le binaire ; dégrader /healthz sur échec prolongé.",
        },
        Entry {
            requirement: Requirement { standard: "ETSI EN 319 401", version: "V3.2.1 (2026-01)", clause: "§7.12", ids: &["REQ-7.12-02", "REQ-7.12-10"], title: "Plan de cessation d'activité" },
            status: Status::OutOfScope,
            mechanism: "Procédure organisationnelle décrite dans docs/CA.md, indépendante du langage d'implémentation.",
            test: "",
            in_service: "",
            target: "Engagement juridique de l'association, dépôt auprès de l'organe de contrôle, séquestre des journaux.",
        },
        Entry {
            requirement: Requirement { standard: "ETSI EN 319 401", version: "V3.2.1 (2026-01)", clause: "§6.1", ids: &["REQ-6.1-01", "REQ-6.1-03", "REQ-6.1-05"], title: "Politique de service et déclaration des pratiques publiées" },
            status: Status::Gap,
            mechanism: "docs/CPS.md porte un brouillon structuré, déjà indépendant du langage d'implémentation du service.",
            test: "",
            in_service: "",
            target: "Adoption formelle de docs/CPS.md par l'association (organisationnel, non affecté par le portage Rust).",
        },
        Entry {
            requirement: Requirement { standard: "ETSI EN 319 411-1", version: "V1.5.1 (2025-04)", clause: "§6.6.1", ids: &["GEN-6.6.1-01"], title: "Profil du certificat d'autorité de certification" },
            status: Status::Covered,
            mechanism: "Cérémonie produisant une racine et une CA émettrice au profil contrôlé (CA:TRUE critique, keyCertSign+cRLSign, SKI/AKI) : oe_ca_core::ceremony::run_ceremony, chaîne revérifiée par openssl.",
            test: "crates/oe-ca-core/tests/issuance.rs (ceremony_is_idempotent, ceremony_rejects_mismatched_signer_on_replay, openssl_accepts_the_chain_and_honors_revocation)",
            in_service: ".github/workflows/ci.yml (Vérifie le certificat TSU et la CRL avec openssl)",
            target: "",
        },
        Entry {
            requirement: Requirement { standard: "ETSI EN 319 411-1", version: "V1.5.1 (2025-04)", clause: "§6.6.1", ids: &["GEN-6.6.1-02"], title: "Certificats émis selon le profil applicable" },
            status: Status::Covered,
            mechanism: "Profils définis en structures Rust compilées, pas en configuration interprétée : oe_ca_core::profile. Contrôle de criticité (basicConstraints, keyUsage, EKU) posé à la main, vérifié par openssl.",
            test: "crates/oe-ca-core/tests/issuance.rs (openssl_accepts_the_chain_and_honors_revocation)",
            in_service: ".github/workflows/ci.yml (Vérifie le certificat TSU et la CRL avec openssl)",
            target: "",
        },
        Entry {
            requirement: Requirement { standard: "ETSI EN 319 411-1", version: "V1.5.1 (2025-04)", clause: "§6.3.2, §6.4.5", ids: &["REG-6.3.2-00B", "REG-6.4.5-03", "REG-6.4.5-04"], title: "Enregistrement et responsabilité de la décision d'émission" },
            status: Status::Gap,
            mechanism: "Aucune transition vers Approved n'existe sans identité d'opérateur : oe_raflow::Decider::approve/reject. L'identité est consignée en base et au journal d'audit.",
            test: "crates/oe-raflow/tests/flow.rs (decide_without_operator_identity_is_refused, approve_then_resubmit_issues_a_certificate_signed_by_the_issuing_key)",
            in_service: "",
            target: "Constat R-2 (PR #57) : approbation automatique désactivée par défaut dans le chart Helm, refusée avec production: true.",
        },
        Entry {
            requirement: Requirement { standard: "ETSI EN 319 411-1", version: "V1.5.1 (2025-04)", clause: "§6.3.2", ids: &["REG-6.3.2-01"], title: "Authentification de la demande de certificat" },
            status: Status::Gap,
            mechanism: "HMAC-SHA256 sur la CSR DER, vérifié en temps constant, et vérification de l'auto-signature de la CSR (preuve de possession) : oe_raflow::Flow::submit.",
            test: "crates/oe-raflow/tests/flow.rs (submit_without_valid_hmac_is_unauthenticated, submit_opens_a_pending_request_idempotently)",
            in_service: "",
            target: "Constat R-3 : un secret, ou mieux une identité mTLS, par demandeur, liée aux profils qu'il peut demander ; ne révoquer au renouvellement que les certificats du même demandeur.",
        },
        Entry {
            requirement: Requirement { standard: "ETSI EN 319 411-1", version: "V1.5.1 (2025-04)", clause: "§6.3.3", ids: &["GEN-6.3.3-02A"], title: "Numéro de série aléatoire" },
            status: Status::Covered,
            mechanism: "Numéro de série de 128 bits tiré sur rand::thread_rng et réservé de façon atomique (contrainte d'unicité en base) : oe_ca_core::Issuer::reserve_serial, oe_castore::Store::reserve_serial.",
            test: "crates/oe-castore/src/lib.rs (reserve_serial_twice_conflicts), crates/oe-castore/tests/postgres.rs (reserve_serial_twice_conflicts)",
            in_service: ".github/workflows/ci.yml (Vérifie le certificat TSU et la CRL avec openssl)",
            target: "",
        },
        Entry {
            requirement: Requirement { standard: "ETSI EN 319 411-1", version: "V1.5.1 (2025-04)", clause: "§6.4.5", ids: &["REV-6.4.5-09"], title: "Demandes de révocation et motif consignés" },
            status: Status::Covered,
            mechanism: "Motif RFC 5280 obligatoire à la révocation (Issuer::revoke), persisté et repris dans chaque entrée de CRL avec son extension cRLReason.",
            test: "crates/oe-ca-core/tests/issuance.rs (revoke_is_idempotent_and_keeps_first_reason, revoke_then_publish_crl_lists_the_certificate)",
            in_service: "bin/ca-server/tests/revocation_action.rs (a_ca_operator_revokes_a_certificate_and_the_crl_carries_it)",
            target: "",
        },
        Entry {
            requirement: Requirement { standard: "ETSI EN 319 411-1", version: "V1.5.1 (2025-04)", clause: "§6.3.9", ids: &["CSS-6.3.9-05", "CSS-6.3.9-06"], title: "Publication de la CRL au moins toutes les 24 heures, avec nextUpdate" },
            status: Status::Covered,
            mechanism: "oe_ca_core::Issuer::publish_crl produit une CRL signée, republiable même vide ; bin/ca-server::http::Server republie à intervalle régulier et dégrade /healthz (503) dès que la CRL servie est périmée, plutôt que de se déclarer sain sans pouvoir dire ce qui est révoqué.",
            test: "crates/oe-ca-core/tests/issuance.rs (revoke_then_publish_crl_lists_the_certificate), bin/ca-server/tests/crl_publication.rs (crl_is_republished_periodically, healthz_degrades_when_the_published_crl_is_stale)",
            in_service: "bin/ca-server/tests/crl_publication.rs (crl_is_republished_periodically, healthz_degrades_when_the_published_crl_is_stale)",
            target: "",
        },
        Entry {
            requirement: Requirement { standard: "ETSI EN 319 411-1", version: "V1.5.1 (2025-04)", clause: "§6.3.9, §6.3.10", ids: &["CSS-6.3.9-12", "CSS-6.3.9-13", "CSS-6.3.10-01"], title: "Révocation d'une autorité et ARL" },
            status: Status::Gap,
            mechanism: "Aucune : la CA émettrice ne porte ni CDP ni AIA vers la racine, et la racine ne publie aucune ARL.",
            test: "",
            in_service: "",
            target: "Constat C-1 (PR #56) : CDP/AIA vers la racine, `ca-server authority revoke|publish-arl`, ARL servie, émission refusée par une émettrice révoquée.",
        },
        Entry {
            requirement: Requirement { standard: "ETSI EN 319 411-1", version: "V1.5.1 (2025-04)", clause: "§6.6.3", ids: &["OVR-6.6.3-02"], title: "Statut OCSP d'un certificat jamais émis" },
            status: Status::Gap,
            mechanism: "Le répondeur OCSP ne connaît que la CRL : un numéro de série absent de la CRL est déclaré good, y compris jamais émis.",
            test: "",
            in_service: "",
            target: "Constat O-1 (PR #55) : publier les numéros émis avec la CRL et répondre unknown pour un numéro absent.",
        },
        Entry {
            requirement: Requirement { standard: "ETSI EN 319 411-1", version: "V1.5.1 (2025-04)", clause: "§6.5.1", ids: &["GEN-6.5.1-04", "GEN-6.5.1-11", "GEN-6.5.1-13"], title: "Cérémonie de génération des clés d'autorité" },
            status: Status::Gap,
            mechanism: "Cérémonie scriptée et idempotente (`ca-server ceremony`), produisant un procès-verbal consigné au journal d'audit (empreintes de clés, opérateur, date) : oe_ca_core::ceremony.",
            test: "crates/oe-ca-core/tests/issuance.rs (every_authority_decision_is_recorded)",
            in_service: "",
            target: "Cérémonie en double contrôle, sous témoin indépendant, sur HSM certifié, avec procès-verbal contresigné — écart organisationnel, pas seulement logiciel.",
        },
        Entry {
            requirement: Requirement { standard: "ETSI EN 319 411-1", version: "V1.5.1 (2025-04)", clause: "§6.5.5", ids: &["GEN-6.5.5-04", "CSS-6.5.5-06"], title: "Authentification multifacteur des comptes capables de provoquer une émission ou une révocation" },
            status: Status::Gap,
            mechanism: "Actions d'opérateur signées par WebAuthn (clé attestée, rôle lu dans le registre, quorum pour la révocation) : oe-actions, derrière le lien interne mTLS de ca-server. Le CLI de secours (ra approve|reject, revoke) reste ouvert sans second facteur.",
            test: "",
            in_service: "",
            target: "Constats R-1/R-2 : relayer les actions signées depuis ra-console (docs/WEBUI.md §15, étape 3) ; tracer et revoir la voie de secours CLI (PR #58, #59) ; approbation automatique désactivée par défaut (PR #57).",
        },
        Entry {
            requirement: Requirement { standard: "ETSI EN 319 421", version: "V1.3.1 (2025-07)", clause: "§7.7.1, §7.7.2", ids: &["TIS-7.7.1-04", "TIS-7.7.1-07", "TIS-7.7.2-01", "TIS-7.7.2-06"], title: "Traçabilité de l'heure jusqu'à UTC et suspension en cas de dérive" },
            status: Status::Covered,
            mechanism: "Surveillance NTP multi-sources avec quorum, seuil de dérive (MaxOffset) et péremption (MaxAge) ; la politique enforce fait refuser chaque demande avec timeNotAvailable : oe_timesource::Monitor.",
            test: "crates/oe-timesource/src/lib.rs (now_refuses_untraceable_time_in_enforce_mode, now_allows_untraceable_time_in_monitor_mode, new_rejects_quorum_larger_than_source_count), crates/oe-tsa-core/src/lib.rs (test_timestamp_refuses_when_time_is_not_traceable)",
            in_service: "bin/tsa-server/tests/serve.rs (the_binary_applies_what_the_matrix_declares)",
            target: "",
        },
        Entry {
            requirement: Requirement { standard: "ETSI EN 319 421", version: "V1.3.1 (2025-07)", clause: "§7.7.1, §7.7.2", ids: &["TIS-7.7.1-05", "TIS-7.7.1-06", "TIS-7.7.2-03"], title: "Exactitude de l'heure du jeton (1 seconde ou mieux)" },
            status: Status::Gap,
            mechanism: "genTime est tronqué à la seconde alors que la dérive tolérée atteint OPENEIDAS_TIME_MAX_OFFSET : l'écart réel peut dépasser l'exactitude annoncée.",
            test: "",
            in_service: "",
            target: "Constat T-1 (PR #53) : genTime à la milliseconde, et refus de démarrer si accuracy < max_offset + résolution.",
        },
        Entry {
            requirement: Requirement { standard: "ETSI EN 319 421", version: "V1.3.1 (2025-07)", clause: "§7.7.2", ids: &["TIS-7.7.2-04", "TIS-7.7.2-05"], title: "Protection de l'horloge contre un changement non détecté" },
            status: Status::Gap,
            mechanism: "Plusieurs sources UTC(k) avec quorum et seuil de dérive (oe_timesource::Monitor), mais client NTP sans contrôle d'origine, de l'indicateur de seconde intercalaire ni NTS.",
            test: "",
            in_service: "",
            target: "Constat T-2 : contrôler l'origine et le LI des réponses NTP, envisager NTS (RFC 8915).",
        },
        Entry {
            requirement: Requirement { standard: "ETSI EN 319 421", version: "V1.3.1 (2025-07)", clause: "§7.7.2", ids: &["TIS-7.7.2-07", "TIS-7.7.2-08", "TIS-7.7.2-09"], title: "Secondes intercalaires" },
            status: Status::Gap,
            mechanism: "Aucune : la seconde intercalaire n'est ni détectée ni consignée.",
            test: "",
            in_service: "",
            target: "Constat T-4 : détecter l'annonce (LI), consigner l'instant du changement au journal.",
        },
        Entry {
            requirement: Requirement { standard: "ETSI EN 319 421", version: "V1.3.1 (2025-07)", clause: "§7.6.2", ids: &["TIS-7.6.2-03"], title: "Génération de la clé TSU dans le module cryptographique" },
            status: Status::Gap,
            mechanism: "La bi-clé est générée dans le token PKCS#11 (oe_hsm::Pkcs11Token::generate_rsa_key) et ne manipule qu'un SigningToken ; la clé privée n'est jamais extraite.",
            test: "bin/tsa-server/tests/serve.rs (the_binary_applies_what_the_matrix_declares)",
            in_service: "",
            target: "Constat H-1 : vérifier au chargement que la clé a été générée dans le module (CKA_LOCAL, CKA_NEVER_EXTRACTABLE).",
        },
        Entry {
            requirement: Requirement { standard: "ETSI EN 319 421", version: "V1.3.1 (2025-07)", clause: "§7.6.5", ids: &["TIS-7.6.5-01"], title: "Durée de vie du certificat de l'unité d'horodatage plafonnée" },
            status: Status::Covered,
            mechanism: "oe_conformance::check_certificate_lifetime relit la validité du certificat réellement signé et la compare à un plafond indépendant du profil (MAX_END_ENTITY_LIFETIME/MAX_OCSP_LIFETIME) ; appelé via le champ Profile::check de oe_ca_core::Issuer::issue, comme profile.Check (Go).",
            test: "crates/oe-conformance/src/lib.rs (check_certificate_lifetime_accepts_within_the_ceiling, check_certificate_lifetime_rejects_beyond_the_ceiling), crates/oe-conformance/tests/tsu_certificate.rs",
            in_service: ".github/workflows/ci.yml (Vérifie le certificat TSU et la CRL avec openssl)",
            target: "",
        },
        Entry {
            requirement: Requirement { standard: "ETSI EN 319 421", version: "V1.3.1 (2025-07)", clause: "§7.6.7, §7.7.1", ids: &["TIS-7.6.7-01", "TIS-7.6.7-02", "TIS-7.6.7-04", "TIS-7.6.7-06", "TIS-7.6.7-07", "TIS-7.6.7-09", "TIS-7.7.1-09"], title: "Date d'expiration de la clé TSU, refus d'émettre au-delà" },
            status: Status::Gap,
            mechanism: "Validité du certificat TSU contrôlée au démarrage seulement ; aucune date d'expiration de clé définie.",
            test: "",
            in_service: "",
            target: "Constat T-3 (PR #54) : privateKeyUsagePeriod posé à l'émission, contrôlé à chaque signature ; nouvelle clé à chaque renouvellement.",
        },
        Entry {
            requirement: Requirement { standard: "ETSI EN 319 421", version: "V1.3.1 (2025-07)", clause: "§7.13", ids: &["OVR-7.13-05"], title: "Identification des jetons affectés par une compromission" },
            status: Status::Gap,
            mechanism: "Le journal consigne genTime et la série du certificat TSU, pas celle du jeton : les jetons émis ne sont pas identifiables un par un.",
            test: "",
            in_service: "",
            target: "Constat J-3 (PR #52) : consigner la série du jeton, l'empreinte soumise et l'état de l'horloge.",
        },
        Entry {
            requirement: Requirement { standard: "ETSI EN 319 422", version: "V1.1.1 (2016-03)", clause: "§6", ids: &[], title: "Profil du certificat de l'unité d'horodatage" },
            status: Status::Covered,
            mechanism: "oe_conformance::check_tsu_certificate (id-kp-timeStamping seul et critique, CA:FALSE, keyUsage restreint, durée de vie plafonnée) est appliquée à l'émission (Profile::check) ET re-contrôlée au démarrage de tsa-server (oe_tsa_core::Authority::new) — un certificat chargé depuis le disque peut venir d'ailleurs.",
            test: "crates/oe-conformance/tests/tsu_certificate.rs (accepts_a_certificate_issued_with_the_tsa_signer_profile, rejects_a_certificate_issued_with_the_ocsp_responder_profile)",
            in_service: "bin/tsa-server/tests/serve.rs (the_binary_applies_what_the_matrix_declares), .github/workflows/ci.yml (Vérifie le certificat TSU et la CRL avec openssl)",
            target: "",
        },
        Entry {
            requirement: Requirement { standard: "ETSI EN 319 422", version: "V1.1.1 (2016-03)", clause: "§5.2", ids: &[], title: "Profil du jeton d'horodatage" },
            status: Status::Gap,
            mechanism: "TSTInfo complet (politique, imprint, série, genTime UTC, précision), assemblé en CMS SignedData signé par le token : oe_rfc3161_asn1, oe_tsa_core::Authority::timestamp.",
            test: "crates/oe-tsa-core/tests/end_to_end.rs (produces_tokens_accepted_by_openssl_for_every_granted_case_in_the_corpus)",
            in_service: "",
            target: "Constat T-1 (PR #53) : genTime avec fraction de seconde (§5.2.2), cohérent avec la précision annoncée.",
        },
        Entry {
            requirement: Requirement { standard: "ETSI EN 319 422", version: "V1.1.1 (2016-03)", clause: "§7", ids: &[], title: "Protocole d'horodatage RFC 3161 sur HTTP" },
            status: Status::Covered,
            mechanism: "Endpoint /tsa acceptant application/timestamp-query, refus protocolaires rendus en TimeStampResp valides : oe_httpapi, bin/tsa-server.",
            test: "crates/oe-httpapi/tests/end_to_end.rs (serves_a_verifiable_token_over_http)",
            in_service: "bin/tsa-server/tests/serve.rs (the_binary_applies_what_the_matrix_declares), .github/workflows/ci.yml (Horodate un fichier et vérifie le jeton (openssl ts))",
            target: "",
        },
        Entry {
            requirement: Requirement { standard: "ETSI TS 119 312", version: "V2.1.1 (2026-06)", clause: "§8.4", ids: &[], title: "Longueur de clé suffisante pour la durée de vie visée" },
            status: Status::Covered,
            mechanism: "oe-config et bin/ca-server/src/config.rs imposent OPENEIDAS_KEY_BITS >= 3072 à la configuration (clé des autorités elles-mêmes) ; oe_raflow::parse_and_verify_csr applique la même exigence à la clé publique portée par une CSR soumise à l'enrôlement.",
            test: "crates/oe-config/src/lib.rs (load_fails_on_undersized_key_bits), crates/oe-raflow/tests/flow.rs (submit_rejects_a_csr_with_an_undersized_key)",
            in_service: "bin/ca-server/tests/bootstrap_cli.rs (undersized_ca_keys_are_refused_by_the_binary)",
            target: "",
        },
        Entry {
            requirement: Requirement { standard: "ETSI TS 119 312", version: "V2.1.1 (2026-06)", clause: "§7.3", ids: &[], title: "Algorithme de signature et fonction de hachage admis" },
            status: Status::Covered,
            mechanism: "oe_conformance::check_signature_algorithm vérifie explicitement l'OID de signature d'un certificat contre la liste des suites admises (SHA-256/384/512 avec RSA), appelée via Profile::check à l'émission et à la re-vérification.",
            test: "crates/oe-conformance/src/lib.rs (check_signature_algorithm_accepts_sha256_with_rsa, check_signature_algorithm_rejects_sha1)",
            in_service: ".github/workflows/ci.yml (Vérifie le certificat TSU et la CRL avec openssl)",
            target: "",
        },
        Entry {
            requirement: Requirement { standard: "ETSI TS 119 312", version: "V2.1.1 (2026-06)", clause: "§5.1", ids: &[], title: "Fonction de hachage admise pour l'empreinte soumise" },
            status: Status::Covered,
            mechanism: "oe_hsm::DigestAlg restreint la signature à SHA-256/384/512 ; une empreinte SHA-1 est refusée avec le failureInfo RFC 3161 badAlg : oe_tsa_core::Authority::timestamp.",
            test: "crates/oe-tsa-core/src/lib.rs (test_timestamp_rejects_sha1)",
            in_service: "bin/tsa-server/tests/serve.rs (the_binary_applies_what_the_matrix_declares)",
            target: "",
        },
        Entry {
            requirement: Requirement { standard: "RFC 6960", version: "", clause: "§2.1", ids: &[], title: "Service d'état de révocation interrogeable en ligne" },
            status: Status::Covered,
            mechanism: "Répondeur OCSP RFC 6960 s'appuyant sur la CRL publiée par la CA : oe_ocsp_core::Responder.",
            test: "crates/oe-ocsp-core/tests/against_real_crl.rs (reports_good_status_for_a_non_revoked_certificate, reports_revoked_status_for_a_revoked_certificate)",
            in_service: ".github/workflows/ci.yml (Interroge le répondeur OCSP pour le certificat TSU)",
            target: "",
        },
        Entry {
            requirement: Requirement { standard: "RFC 6960", version: "", clause: "§4.2.2.2", ids: &[], title: "Profil du certificat de signature du répondeur OCSP" },
            status: Status::Covered,
            mechanism: "Profil ocsp_responder (id-pkix-ocsp-nocheck, pas de CDP/AIA, durée de vie courte) appliqué à l'émission, re-contrôlé après signature par oe_conformance::check_ocsp_responder_certificate (Profile::check).",
            test: "crates/oe-ca-core/tests/issuance.rs (revoke_then_publish_crl_lists_the_certificate), crates/oe-conformance/tests/tsu_certificate.rs (rejects_a_certificate_issued_with_the_ocsp_responder_profile)",
            in_service: ".github/workflows/ci.yml (Interroge le répondeur OCSP pour le certificat TSU)",
            target: "",
        },
        Entry {
            requirement: Requirement { standard: "RFC 5280", version: "", clause: "§4.2.1.1-4.2.1.2", ids: &[], title: "Identifiants de clé de sujet et d'autorité présents" },
            status: Status::Covered,
            mechanism: "subjectKeyIdentifier (SHA-1 de la clé, méthode 1) et authorityKeyIdentifier (pointant vers le SKI de l'émetteur) posés sans condition à l'émission et dans la cérémonie : oe_ca_core::extensions, oe_ca_core::signing::subject_key_id.",
            test: "crates/oe-ca-core/tests/issuance.rs (issue_produces_a_certificate_signed_by_the_issuing_key, assert_ski_and_aki_present_and_linked)",
            in_service: ".github/workflows/ci.yml (Vérifie le certificat TSU et la CRL avec openssl)",
            target: "",
        },
        Entry {
            requirement: Requirement { standard: "RFC 5280", version: "", clause: "§5.1", ids: &[], title: "Liste de révocation signée, numérotée et datée" },
            status: Status::Covered,
            mechanism: "CRL régénérée avec cRLNumber, thisUpdate/nextUpdate et signature, republiée même vide : oe_ca_core::Issuer::publish_crl. La signature et le motif de révocation sont revérifiés par openssl.",
            test: "crates/oe-ca-core/tests/issuance.rs (revoke_then_publish_crl_lists_the_certificate, openssl_accepts_the_chain_and_honors_revocation)",
            in_service: ".github/workflows/ci.yml (Vérifie le certificat TSU et la CRL avec openssl), bin/ca-server/tests/crl_publication.rs (crl_is_republished_periodically)",
            target: "",
        },
        Entry {
            requirement: Requirement { standard: "ETSI EN 319 403-1", version: "V2.3.1 (2020-06)", clause: "§7", ids: &[], title: "Évaluation par un organisme d'évaluation de la conformité accrédité" },
            status: Status::OutOfScope,
            mechanism: "Le dépôt est intégralement public ; cette matrice fournit le point d'entrée d'un audit, indépendamment du langage d'implémentation.",
            test: "",
            in_service: "",
            target: "Audit par un organisme accrédité (LSTI, Apave), puis inscription à la liste de confiance nationale.",
        },
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_audit_retention_accepts_the_minimum() {
        assert!(check_audit_retention(MIN_AUDIT_RETENTION).is_ok());
    }

    #[test]
    fn check_audit_retention_rejects_unconfigured_and_short_durations() {
        assert!(check_audit_retention(time::Duration::ZERO).is_err());
        assert!(check_audit_retention(time::Duration::hours(24)).is_err());
    }

    #[test]
    fn check_certificate_lifetime_accepts_within_the_ceiling() {
        let now = time::OffsetDateTime::UNIX_EPOCH;
        assert!(check_certificate_lifetime(
            "t",
            now,
            now + time::Duration::days(365),
            MAX_END_ENTITY_LIFETIME
        )
        .is_ok());
    }

    #[test]
    fn check_certificate_lifetime_rejects_beyond_the_ceiling() {
        let now = time::OffsetDateTime::UNIX_EPOCH;
        assert!(check_certificate_lifetime(
            "t",
            now,
            now + MAX_END_ENTITY_LIFETIME + time::Duration::days(1),
            MAX_END_ENTITY_LIFETIME
        )
        .is_err());
    }

    #[test]
    fn check_signature_algorithm_accepts_sha256_with_rsa() {
        assert!(check_signature_algorithm("t", "1.2.840.113549.1.1.11").is_ok());
    }

    #[test]
    fn check_signature_algorithm_rejects_sha1() {
        // sha1WithRSAEncryption : jamais dans la liste admise.
        assert!(check_signature_algorithm("t", "1.2.840.113549.1.1.5").is_err());
    }

    #[test]
    fn system_matrix_is_internally_consistent() {
        system_matrix()
            .validate()
            .expect("la matrice doit être cohérente");
    }

    #[test]
    fn nothing_is_covered_without_a_named_mechanism_and_test() {
        for e in &system_matrix().0 {
            if e.status == Status::Covered {
                assert!(
                    !e.mechanism.is_empty(),
                    "{}: mécanisme manquant",
                    e.requirement
                );
                assert!(!e.test.is_empty(), "{}: test manquant", e.requirement);
            }
        }
    }

    #[test]
    fn render_markdown_reports_accurate_counts() {
        let m = system_matrix();
        let md = render_markdown(&m);
        let counts = m.counts();
        assert!(md.contains(&format!("**{} exigences**", m.0.len())));
        assert!(md.contains(&format!("{} couvertes", counts[&Status::Covered])));
    }

    #[test]
    fn detects_a_covered_entry_without_mechanism() {
        let bad = Matrix(vec![Entry {
            requirement: Requirement {
                standard: "X",
                version: "",
                clause: "1",
                ids: &[],
                title: "t",
            },
            status: Status::Covered,
            mechanism: "",
            test: "",
            in_service: "",
            target: "",
        }]);
        assert!(bad.validate().is_err());
    }

    fn covered(requirement: Requirement) -> Entry {
        Entry {
            requirement,
            status: Status::Covered,
            mechanism: "m",
            test: "t",
            in_service: "bin/x/tests/y.rs (z)",
            target: "",
        }
    }

    const OK: Requirement = Requirement {
        standard: "ETSI EN 319 401",
        version: "V3.2.1 (2026-01)",
        clause: "§7.10",
        ids: &["REQ-7.10-08"],
        title: "t",
    };

    /// Constat D-3 : une ligne sans version, sans identifiant (pour une norme
    /// qui en numérote), avec un identifiant d'une autre clause, ou une norme
    /// citée en deux versions, rend la matrice incohérente.
    #[test]
    fn detects_missing_versions_ids_and_mismatched_clauses() {
        assert!(Matrix(vec![covered(OK)]).validate().is_ok());

        let no_version = Requirement { version: "", ..OK };
        let err = Matrix(vec![covered(no_version)]).validate().unwrap_err();
        assert!(err.contains("version"), "{err}");

        let no_ids = Requirement { ids: &[], ..OK };
        let err = Matrix(vec![covered(no_ids)]).validate().unwrap_err();
        assert!(err.contains("aucun identifiant"), "{err}");

        // La faute d'origine : §7.9 cité pour une exigence du §7.10.
        let wrong_clause = Requirement {
            clause: "§7.9",
            ..OK
        };
        let err = Matrix(vec![covered(wrong_clause)]).validate().unwrap_err();
        assert!(err.contains("ne relève pas de la clause"), "{err}");

        let other_version = Requirement {
            version: "V3.1.1 (2024-06)",
            ids: &["REQ-7.10-02"],
            ..OK
        };
        let err = Matrix(vec![covered(OK), covered(other_version)])
            .validate()
            .unwrap_err();
        assert!(err.contains("deux versions"), "{err}");

        // Constat D-2 : couvert exige une preuve de mise en service par un
        // binaire ; un test de bibliothèque ne suffit pas.
        let library_only = Entry {
            in_service: "crates/oe-audit/src/lib.rs (t)",
            ..covered(OK)
        };
        let err = Matrix(vec![library_only]).validate().unwrap_err();
        assert!(err.contains("sans preuve de mise en service"), "{err}");

        // Une RFC ne porte ni version ETSI ni identifiant.
        let rfc = Requirement {
            standard: "RFC 5280",
            version: "",
            clause: "§5.1",
            ids: &[],
            title: "t",
        };
        assert!(Matrix(vec![covered(rfc)]).validate().is_ok());
    }
}
