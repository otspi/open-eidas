//! Portage de `internal/ca/profile.go` : ce que contient un certificat émis
//! par cette autorité, sous forme de structure Rust compilée et testée — et
//! non de configuration interprétée au démarrage (voir INDEPENDANCE.md).

use der::asn1::ObjectIdentifier;
use x509_cert::ext::pkix::KeyUsages;

pub const PROFILE_TSA_SIGNER: &str = "tsa_signer";
pub const PROFILE_OCSP_RESPONDER: &str = "ocsp_responder";
pub const PROFILE_INTERNAL_CLIENT: &str = "internal_client";
pub const PROFILE_INTERNAL_SERVER: &str = "internal_server";

/// Le seul nom courant que `internal_client` accepte (docs/WEBUI.md §16).
pub use oe_conformance::INTERNAL_CLIENT_CN;

pub use oe_conformance::{
    OID_EKU_CLIENT_AUTH, OID_EKU_SERVER_AUTH, OID_POLICY_INTERNAL_CLIENT,
    OID_POLICY_INTERNAL_SERVER,
};

fn oid(s: &str) -> ObjectIdentifier {
    ObjectIdentifier::new(s).expect("OID constant invalide")
}

/// Décrit ce qu'un certificat émis par cette autorité contient.
pub struct Profile {
    pub name: &'static str,
    pub label: &'static str,

    /// Parties fixes du sujet. Seul le CN provient de la CSR : le reste est
    /// imposé par l'autorité.
    pub organizational_unit: &'static str,
    pub organization: &'static str,
    pub country: &'static str,

    pub validity: time::Duration,

    pub key_usages: der::flagset::FlagSet<KeyUsages>,
    pub eku: &'static [&'static str],
    /// ETSI EN 319 421 §7.7.2 exige `extendedKeyUsage` critique pour un
    /// certificat de TSU : sans criticité, un vérificateur peut ignorer la
    /// restriction d'usage.
    pub eku_critical: bool,

    /// Ajoute `id-pkix-ocsp-nocheck` (RFC 6960 §4.2.2.2.1).
    pub ocsp_no_check: bool,

    pub include_crl_distribution_point: bool,
    pub include_ca_issuers: bool,
    pub include_ocsp_responder: bool,

    /// Nom courant imposé : la CSR qui en demande un autre est refusée.
    pub required_cn: Option<&'static str>,
    /// Le CN doit être un nom DNS, repris en `subjectAltName` : le client
    /// vérifie le serveur par ce nom (jamais par le CN).
    pub san_dns_from_cn: bool,
    /// Politique de certification gravée dans `certificatePolicies`.
    pub policy_oid: Option<&'static str>,
    /// Durée de vie de la **clé privée**, plus courte que `validity`
    /// (constat T-3 de l'audit du 2026-09-25, EN 319 421 `TIS-7.6.7-*`) :
    /// gravée dans l'extension `privateKeyUsagePeriod`. `None` pour un
    /// profil qui n'a pas cette exigence.
    pub private_key_validity: Option<time::Duration>,

    /// Applique les règles ETSI propres à ce profil au certificat
    /// réellement signé — reproduit le champ `Check` de `ca.Profile` (Go).
    /// Appelé juste après signature, avant tout enregistrement : émettre
    /// puis re-vérifier ce qui a été effectivement encodé, jamais se fier
    /// aux seuls paramètres qui l'ont construit.
    pub check: fn(&str, &x509_cert::Certificate) -> Result<(), String>,
}

pub const OID_EKU_TIME_STAMPING: &str = "1.3.6.1.5.5.7.3.8";
pub const OID_EKU_OCSP_SIGNING: &str = "1.3.6.1.5.5.7.3.9";
/// `id-pkix-ocsp-nocheck` (RFC 6960 §4.2.2.2.1).
pub const OID_OCSP_NO_CHECK: &str = "1.3.6.1.5.5.7.48.1.5";

pub fn eku_oids(p: &Profile) -> Vec<ObjectIdentifier> {
    p.eku.iter().map(|s| oid(s)).collect()
}

/// Reproduit le profil ETSI EN 319 422 / EN 319 421 §7.7.2 de l'unité
/// d'horodatage.
pub fn tsa_signer() -> Profile {
    Profile {
        name: PROFILE_TSA_SIGNER,
        label: "Open eIDAS Time-Stamping Unit",
        organizational_unit: "Time Stamping Authority",
        organization: "Open eIDAS",
        country: "FR",
        // 2 ans de certificat, 1 an de clé (constat T-3) : la clé expire
        // avant lui, imposant un renouvellement de bi-clé à mi-vie du
        // certificat plutôt qu'une clé unique reconduite indéfiniment.
        validity: time::Duration::days(2 * 365),
        // nonRepudiation (contentCommitment) accompagne digitalSignature :
        // un jeton d'horodatage engage l'autorité sur la date.
        key_usages: KeyUsages::DigitalSignature | KeyUsages::NonRepudiation,
        eku: &[OID_EKU_TIME_STAMPING],
        eku_critical: true,
        ocsp_no_check: false,
        include_crl_distribution_point: true,
        include_ca_issuers: true,
        include_ocsp_responder: true,
        required_cn: None,
        san_dns_from_cn: false,
        policy_oid: None,
        private_key_validity: Some(time::Duration::days(365)),
        check: oe_conformance::check_tsu_certificate,
    }
}

/// Reproduit le profil du répondeur OCSP. Ni CDP ni AIA : `ocsp-nocheck`
/// dispense de vérifier la révocation de ce certificat, la durée de vie
/// courte est la contrepartie de cette dispense.
pub fn ocsp_responder() -> Profile {
    Profile {
        name: PROFILE_OCSP_RESPONDER,
        label: "Open eIDAS OCSP Responder",
        organizational_unit: "OCSP Responder",
        organization: "Open eIDAS",
        country: "FR",
        validity: time::Duration::days(90),
        key_usages: KeyUsages::DigitalSignature.into(),
        eku: &[OID_EKU_OCSP_SIGNING],
        eku_critical: true,
        ocsp_no_check: true,
        include_crl_distribution_point: false,
        include_ca_issuers: false,
        include_ocsp_responder: false,
        required_cn: None,
        san_dns_from_cn: false,
        policy_oid: None,
        private_key_validity: None,
        check: oe_conformance::check_ocsp_responder_certificate,
    }
}

/// Certificat de `ra-console` sur le lien interne (docs/WEBUI.md §16) : EKU
/// `clientAuth` seul, politique dédiée, sujet imposé, vie de 3 mois. La clé
/// est logicielle : elle n'authentifie qu'un canal, aucun pouvoir de signature
/// n'en découle (la signature d'un opérateur reste exigée, §4).
pub fn internal_client() -> Profile {
    Profile {
        name: PROFILE_INTERNAL_CLIENT,
        label: "Open eIDAS internal link client",
        organizational_unit: "Internal Link",
        organization: "Open eIDAS",
        country: "FR",
        validity: time::Duration::days(90),
        key_usages: KeyUsages::DigitalSignature.into(),
        eku: &[OID_EKU_CLIENT_AUTH],
        eku_critical: true,
        ocsp_no_check: false,
        include_crl_distribution_point: true,
        include_ca_issuers: true,
        include_ocsp_responder: false,
        required_cn: Some(INTERNAL_CLIENT_CN),
        san_dns_from_cn: false,
        policy_oid: Some(OID_POLICY_INTERNAL_CLIENT),
        private_key_validity: None,
        check: oe_conformance::check_internal_client_certificate,
    }
}

/// Certificat de `ca-server` sur le lien interne : EKU `serverAuth` seul,
/// politique dédiée, SAN = le CN, qui doit être un nom DNS.
pub fn internal_server() -> Profile {
    Profile {
        name: PROFILE_INTERNAL_SERVER,
        label: "Open eIDAS internal link server",
        organizational_unit: "Internal Link",
        organization: "Open eIDAS",
        country: "FR",
        validity: time::Duration::days(90),
        key_usages: KeyUsages::DigitalSignature.into(),
        eku: &[OID_EKU_SERVER_AUTH],
        eku_critical: true,
        ocsp_no_check: false,
        include_crl_distribution_point: true,
        include_ca_issuers: true,
        include_ocsp_responder: false,
        required_cn: None,
        san_dns_from_cn: true,
        policy_oid: Some(OID_POLICY_INTERNAL_SERVER),
        private_key_validity: None,
        check: oe_conformance::check_internal_server_certificate,
    }
}

impl Profile {
    /// Contrôle le nom courant demandé, avant toute réservation de série.
    pub fn validate_cn(&self, cn: &str) -> Result<(), String> {
        if let Some(required) = self.required_cn {
            if cn != required {
                return Err(format!(
                    "le profil {} n'admet que le nom courant {required:?}, reçu {cn:?}",
                    self.name
                ));
            }
        }
        if self.san_dns_from_cn && !is_dns_name(cn) {
            return Err(format!(
                "le profil {} exige un nom DNS comme nom courant, reçu {cn:?}",
                self.name
            ));
        }
        Ok(())
    }
}

/// Nom d'hôte simple : étiquettes de lettres minuscules, chiffres et tirets,
/// séparées par des points. Pas de joker, pas de majuscule, pas d'adresse IP.
fn is_dns_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 253
        && !s.chars().all(|c| c.is_ascii_digit() || c == '.')
        && s.split('.').all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && !l.starts_with('-')
                && !l.ends_with('-')
                && l.chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        })
}

/// Nom inconnu : erreur explicite, aucun profil par défaut n'est appliqué
/// en silence — l'héritage implicite qui piégeait la configuration OpenXPKI.
pub fn profile_by_name(name: &str) -> Result<Profile, String> {
    match name {
        PROFILE_TSA_SIGNER => Ok(tsa_signer()),
        PROFILE_OCSP_RESPONDER => Ok(ocsp_responder()),
        PROFILE_INTERNAL_CLIENT => Ok(internal_client()),
        PROFILE_INTERNAL_SERVER => Ok(internal_server()),
        other => Err(format!("ca: profil de certificat inconnu: {other:?}")),
    }
}
