//! Portage de `internal/ca` : le moteur d'émission et de révocation de
//! l'autorité de certification — produit les certificats de l'unité
//! d'horodatage et du répondeur OCSP, et publie l'état de révocation. Rang
//! 3 de l'ordre de portage post-`tsa-server`/`ocsp-responder`
//! (`/home/philippe/.claude/plans/witty-hopping-nest.md`).
//!
//! **Re-vérification ETSI du certificat réellement signé** : chaque profil
//! porte un champ `check` (`oe_conformance::check_tsu_certificate`,
//! `check_ocsp_responder_certificate`) appelé juste après signature, avant
//! tout enregistrement — reproduit `Profile.Check` (Go). Un certificat non
//! conforme est refusé (`ca.issuance_refused` au journal) plutôt qu'émis. La
//! CRL n'a pas d'équivalent porté : la CA maîtrise entièrement sa
//! construction (`publish_crl`), contrairement au cas d'une CSR d'origine
//! externe.
//!
//! **Clé privée jamais en mémoire du processus** : la signature d'un
//! certificat ou d'une CRL passe par [`signing::sign_with_token`], qui
//! n'utilise que la clé publique et l'algorithme (`signature::Keypair` +
//! `spki::DynSignatureAlgorithmIdentifier`) pour construire l'objet avec
//! `x509_cert::builder`, puis fait signer les octets à signer par
//! `oe_hsm::SigningToken` — jamais par une clé en mémoire.

mod extensions;
pub mod profile;
mod signing;

use std::str::FromStr;
use std::sync::Arc;

use der::{Decode, Encode};
use x509_cert::builder::profile::BuilderProfile;
use x509_cert::builder::CertificateBuilder;
use x509_cert::ext::Extension;
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::time::{Time, Validity};
use x509_cert::{Certificate, SubjectPublicKeyInfo};

use oe_castore::{Store, StoreError};
use oe_hsm::SigningToken;

pub use profile::{profile_by_name, Profile};

/// Consigne les décisions de l'autorité au journal d'audit — reproduit
/// `ca.Recorder` (Go) ; comme `oe_tsa_core::Recorder`, découplé de
/// `oe-audit` par convention (mêmes noms d'événement en dur plutôt qu'une
/// dépendance de crate) pour ne pas lier ce moteur à un format de journal
/// particulier.
///
/// Async : l'écriture peut atteindre un stockage distant (docs/WEBUI.md §7,
/// §15 étape 2b). Son échec est **bloquant** — voir `Issuer::record` — donc
/// consigné *avant* toute mutation durable du store, jamais après : on ne
/// journalise en confiance que ce qui n'est pas encore irréversible.
#[async_trait::async_trait]
pub trait Recorder: Send + Sync {
    async fn append(&self, event: &str, data: serde_json::Value) -> Result<(), String>;
}

#[derive(Debug, thiserror::Error)]
pub enum CaError {
    #[error("ca: {0}")]
    Der(#[from] der::Error),
    #[error("ca: {0}")]
    Signing(#[from] oe_hsm::HsmError),
    #[error("ca: {0}")]
    Store(#[from] StoreError),
    #[error("ca: {0}")]
    Other(String),
}

/// Construit un sujet X.501, dans l'ordre `C, O, OU, CN` (convention de
/// `pkix.Name.ToRDNSequence`, Go) — seul le CN provient de la CSR, le reste
/// est imposé par l'autorité.
pub fn build_subject(cn: &str, ou: &str, o: &str, c: &str) -> Result<Name, CaError> {
    let mut parts = Vec::new();
    if !c.is_empty() {
        parts.push(format!("C={}", escape_rdn(c)));
    }
    if !o.is_empty() {
        parts.push(format!("O={}", escape_rdn(o)));
    }
    if !ou.is_empty() {
        parts.push(format!("OU={}", escape_rdn(ou)));
    }
    parts.push(format!("CN={}", escape_rdn(cn)));
    Name::from_str(&parts.join(",")).map_err(CaError::Der)
}

fn escape_rdn(s: &str) -> String {
    let mut out = String::new();
    for c in s.chars() {
        if matches!(c, ',' | '+' | '"' | '\\' | '<' | '>' | ';' | '=') {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

fn to_x509_time(t: time::OffsetDateTime) -> Result<Time, CaError> {
    Time::try_from(std::time::SystemTime::from(t)).map_err(CaError::Der)
}

/// Octets significatifs d'un numéro de série, sans l'éventuel `0x00` de tête
/// que le DER ajoute pour garder un entier positif (RFC 5280 impose un
/// INTEGER *signé*, donc un bit de poids fort à 1 exige ce remplissage) —
/// c'est cette forme, et non l'encodage DER brut, que tout outil tiers
/// affiche (`openssl x509 -serial`, `asn1parse`) et donc celle qu'un
/// opérateur colle dans `ca-server revoke`. Utilisée comme clé de
/// `castore`, jamais l'encodage DER intégral, pour que les deux
/// représentations coïncident.
pub fn canonical_serial(sn: &SerialNumber) -> Vec<u8> {
    match sn.as_bytes() {
        [0x00, rest @ ..] if !rest.is_empty() && rest[0] & 0x80 != 0 => rest.to_vec(),
        bytes => bytes.to_vec(),
    }
}

/// Vérifie que la clé publique d'un certificat correspond à celle du token
/// — reproduit `matchesSigner` (Go).
pub fn matches_signer(cert_spki_der: &[u8], signer: &dyn SigningToken) -> Result<(), CaError> {
    let signer_spki = signer.public_key_der()?;
    if cert_spki_der != signer_spki.as_slice() {
        return Err(CaError::Other(
            "la clé du token PKCS#11 ne correspond pas au certificat de l'autorité".to_string(),
        ));
    }
    Ok(())
}

/// Un profil de construction minimal pour `x509_cert::builder` : contrôle
/// total sur les extensions (critical flags explicites), à l'identique du
/// code Go, plutôt que dérivées d'une règle fixe par type.
struct RawProfile {
    subject: Name,
    issuer: Name,
    extensions: Vec<Extension>,
}

impl BuilderProfile for RawProfile {
    fn get_issuer(&self, _subject: &Name) -> Name {
        self.issuer.clone()
    }
    fn get_subject(&self) -> Name {
        self.subject.clone()
    }
    fn build_extensions(
        &self,
        _spk: spki::SubjectPublicKeyInfoRef<'_>,
        _issuer_spk: spki::SubjectPublicKeyInfoRef<'_>,
        _tbs: &x509_cert::TbsCertificate,
    ) -> x509_cert::builder::Result<Vec<Extension>> {
        Ok(self.extensions.clone())
    }
}

/// Configure l'autorité émettrice.
pub struct Options {
    pub signer: Arc<dyn SigningToken + Send + Sync>,
    pub certificate: Certificate,
    pub chain: Vec<Certificate>,
    pub store: Arc<dyn Store>,
    /// Adresse publique à laquelle cette CA est joignable par qui vérifie
    /// un certificat — gravée dans les extensions CDP et AIA.
    pub public_url: String,
    pub ocsp_url: Option<String>,
    pub crl_validity: time::Duration,
    pub crl_grace: time::Duration,
    pub recorder: Option<Arc<dyn Recorder>>,
}

pub struct Issuer {
    opts: Options,
}

impl Issuer {
    pub fn new(opts: Options) -> Result<Issuer, CaError> {
        let cert_spki_der = opts
            .certificate
            .tbs_certificate()
            .subject_public_key_info()
            .to_der()?;
        matches_signer(&cert_spki_der, opts.signer.as_ref())?;
        Ok(Issuer { opts })
    }

    /// Bloquant : un journal qui n'a pas pu être écrit (par ex. le stockage
    /// distant du §15 étape 2b est injoignable) doit empêcher l'opération en
    /// cours, pas seulement le signaler. C'est pourquoi chaque appelant
    /// journalise *avant* la mutation durable qui suit (`save_certificate`,
    /// `store.revoke`, `store.save_crl`) : si le journal échoue, rien
    /// d'irréversible n'a encore eu lieu.
    async fn record(&self, event: &str, data: serde_json::Value) -> Result<(), CaError> {
        if let Some(recorder) = &self.opts.recorder {
            recorder
                .append(event, data)
                .await
                .map_err(|e| CaError::Other(format!("journal : {e}")))?;
        }
        Ok(())
    }

    pub fn certificate(&self) -> &Certificate {
        &self.opts.certificate
    }

    pub fn chain(&self) -> &[Certificate] {
        &self.opts.chain
    }

    pub fn full_chain(&self) -> Vec<Certificate> {
        let mut out = vec![self.opts.certificate.clone()];
        out.extend(self.opts.chain.iter().cloned());
        out
    }

    pub fn crl_url(&self) -> String {
        format!(
            "{}/download/{}.crl",
            self.opts.public_url,
            oe_certs::file_name(&common_name(&self.opts.certificate))
        )
    }

    pub fn ca_certificate_url(&self) -> String {
        format!(
            "{}/download/{}.cer",
            self.opts.public_url,
            oe_certs::file_name(&common_name(&self.opts.certificate))
        )
    }

    /// Produit un certificat pour la CSR donnée selon le profil demandé.
    ///
    /// Séquence rigide, à l'identique du code Go : réserver le numéro de
    /// série AVANT de signer, signer, puis seulement alors inscrire au
    /// registre.
    pub async fn issue(
        &self,
        csr_public_key_der: &[u8],
        subject_cn: &str,
        profile: &Profile,
        transaction_id: &str,
    ) -> Result<Certificate, CaError> {
        profile.validate_cn(subject_cn).map_err(CaError::Other)?;
        let serial = self.reserve_serial(profile.name).await?;
        let serial_bytes = canonical_serial(&serial);

        let subject = build_subject(
            subject_cn,
            profile.organizational_unit,
            profile.organization,
            profile.country,
        )?;
        let issuer_name = self.opts.certificate.tbs_certificate().subject().clone();

        let now = time::OffsetDateTime::now_utc();
        let not_before = to_x509_time(now - time::Duration::minutes(5))?;
        let not_after = to_x509_time(now + profile.validity)?;

        let subject_spki = SubjectPublicKeyInfo::from_der(csr_public_key_der)?;
        let ski = signing::subject_key_id(csr_public_key_der)?;
        let issuer_spki_der = self
            .opts
            .certificate
            .tbs_certificate()
            .subject_public_key_info()
            .to_der()?;
        let parent_ski = signing::subject_key_id(&issuer_spki_der)?;

        let mut exts = vec![
            extensions::basic_constraints(false, None)?,
            extensions::key_usage(profile.key_usages)?,
            extensions::subject_key_identifier(&ski)?,
            extensions::authority_key_identifier(&parent_ski)?,
        ];
        let eku_oids = profile::eku_oids(profile);
        if !eku_oids.is_empty() {
            exts.push(extensions::extended_key_usage(
                &eku_oids,
                profile.eku_critical,
            )?);
        }
        if profile.ocsp_no_check {
            exts.push(extensions::ocsp_no_check());
        }
        if let Some(policy) = profile.policy_oid {
            exts.push(extensions::certificate_policy(policy)?);
        }
        if profile.san_dns_from_cn {
            exts.push(extensions::subject_alt_name_dns(subject_cn)?);
        }
        if profile.include_crl_distribution_point {
            exts.push(extensions::crl_distribution_point(&self.crl_url())?);
        }
        let ca_issuers = profile
            .include_ca_issuers
            .then(|| self.ca_certificate_url());
        let ocsp = if profile.include_ocsp_responder {
            self.opts.ocsp_url.clone()
        } else {
            None
        };
        if ca_issuers.is_some() || ocsp.is_some() {
            exts.push(extensions::authority_info_access(
                ca_issuers.as_deref(),
                ocsp.as_deref(),
            )?);
        }

        let raw_profile = RawProfile {
            subject,
            issuer: issuer_name,
            extensions: exts,
        };
        let builder = CertificateBuilder::new(
            raw_profile,
            serial,
            Validity::new(not_before, not_after),
            subject_spki,
        )
        .map_err(|e| CaError::Other(e.to_string()))?;
        let cert = signing::sign_with_token(builder, self.opts.signer.as_ref(), &issuer_spki_der)?;

        // Relit et re-contrôle le certificat réellement signé selon les
        // règles ETSI propres à son profil, avant tout enregistrement —
        // jamais se fier aux seuls paramètres qui l'ont construit.
        let check_subject = format!("certificat {} émis pour {}", profile.name, subject_cn);
        if let Err(reason) = (profile.check)(&check_subject, &cert) {
            // Rien d'irréversible ne dépend de ce journal : le rejet a déjà
            // lieu quoi qu'il arrive. Mais si le journal lui-même échoue,
            // c'est cette raison-là qui prime (§15 étape 2b : le journal fait
            // foi, on ne le contourne jamais en silence).
            self.record(
                "ca.issuance_refused",
                serde_json::json!({
                    "profil": profile.name,
                    "sujet": cert.tbs_certificate().subject().to_string(),
                    "motif": reason,
                    "demande": transaction_id,
                }),
            )
            .await?;
            return Err(CaError::Other(format!(
                "le certificat produit n'est pas conforme, émission annulée: {reason}"
            )));
        }

        // Le journal *avant* l'enregistrement durable : si l'écriture échoue
        // (par ex. le stockage distant du journal est injoignable), aucun
        // certificat n'est inscrit au store — seul le numéro de série réservé
        // est perdu (déjà toléré, comme pour un numéro de CRL, §15 étape 2b).
        self.record(
            "ca.certificate_issued",
            serde_json::json!({
                "profil": profile.name,
                "sujet": cert.tbs_certificate().subject().to_string(),
                "emetteur": cert.tbs_certificate().issuer().to_string(),
                "serie": hex::encode(&serial_bytes),
                "not_after": (now + profile.validity).format(&time::format_description::well_known::Rfc3339).unwrap_or_default(),
                "demande": transaction_id,
            }),
        )
        .await?;

        self.opts
            .store
            .save_certificate(oe_castore::Certificate {
                serial: serial_bytes.clone(),
                profile: profile.name.to_string(),
                subject_dn: cert.tbs_certificate().subject().to_string(),
                issuer_dn: cert.tbs_certificate().issuer().to_string(),
                not_before: now,
                not_after: now + profile.validity,
                der: cert.to_der()?,
                status: oe_castore::CertificateStatus::Issued,
                revoked_at: None,
                revocation_reason: 0,
                request_transaction_id: transaction_id.to_string(),
            })
            .await?;

        Ok(cert)
    }

    async fn reserve_serial(&self, profile: &str) -> Result<SerialNumber, CaError> {
        const SERIAL_BYTES: usize = 16; // 128 bits, ETSI EN 319 412-1 §4.1.
        const ATTEMPTS: u32 = 5;
        for _ in 0..ATTEMPTS {
            let mut bytes = [0u8; SERIAL_BYTES];
            rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut bytes);
            bytes[0] |= 0x80; // bit de poids fort forcé : strictement positif, entropie pleine.
            let serial = SerialNumber::new(&bytes)?;
            // Réserve la forme canonique (voir `canonical_serial`) : c'est
            // cette même clé que relira `issue` juste après, et celle que
            // tout outil tiers affichera pour ce certificat.
            match self
                .opts
                .store
                .reserve_serial(&canonical_serial(&serial), profile)
                .await
            {
                Ok(()) => return Ok(serial),
                Err(StoreError::SerialTaken) => continue,
                Err(e) => return Err(e.into()),
            }
        }
        Err(CaError::Other(format!("{ATTEMPTS} collisions successives de numéro de série sur {} bits — générateur d'aléa suspect", SERIAL_BYTES * 8)))
    }

    /// Révoque un certificat émis par cette autorité et consigne la
    /// décision. La CRL n'est pas republiée ici : `publish_crl` la reprend.
    pub async fn revoke(
        &self,
        serial: &[u8],
        reason: i32,
        operator: &str,
        comment: &str,
    ) -> Result<(), CaError> {
        if operator.is_empty() {
            return Err(CaError::Other(
                "la révocation exige l'identité de l'opérateur qui la décide".to_string(),
            ));
        }
        let cert = self.opts.store.certificate(&serial.to_vec()).await?;
        let at = time::OffsetDateTime::now_utc();

        // Le journal *avant* la révocation en base (§15 étape 2b) : si
        // l'écriture échoue, le certificat reste actif — pas de révocation
        // à moitié consignée.
        self.record(
            "ca.certificate_revoked",
            serde_json::json!({
                "serie": hex::encode(serial),
                "sujet": cert.subject_dn,
                "motif": reason,
                "operateur": operator,
                "commentaire": comment,
                "date": at.format(&time::format_description::well_known::Rfc3339).unwrap_or_default(),
            }),
        )
        .await?;
        self.opts.store.revoke(&serial.to_vec(), at, reason).await?;

        Ok(())
    }

    /// Produit et enregistre une nouvelle CRL — publiée même vide (ETSI EN
    /// 319 411-1 §6.3.10).
    pub async fn publish_crl(&self) -> Result<oe_castore::Crl, CaError> {
        let now = time::OffsetDateTime::now_utc();
        let revoked = self.opts.store.revoked(now, self.opts.crl_grace).await?;

        let number = self.opts.store.next_crl_number().await?;
        let this_update = to_x509_time(now - time::Duration::minutes(1))?;
        let next_update = to_x509_time(now + self.opts.crl_validity)?;

        let entries: Result<Vec<_>, CaError> = revoked
            .iter()
            .map(|c| -> Result<_, CaError> {
                let mut exts = x509_cert::ext::Extensions::new();
                if c.revocation_reason != 0 {
                    let reason_ext = extensions_crl_reason(c.revocation_reason)?;
                    exts.push(reason_ext);
                }
                Ok(x509_cert::crl::RevokedCert {
                    serial_number: SerialNumber::new(&c.serial)?,
                    revocation_date: to_x509_time(c.revoked_at.unwrap_or(now))?,
                    crl_entry_extensions: if exts.is_empty() { None } else { Some(exts) },
                })
            })
            .collect();
        // `None` plutôt qu'une séquence vide lorsqu'il n'y a rien à révoquer,
        // à l'identique du binaire Go.
        let entries = entries?;
        let revoked_certificates = if entries.is_empty() {
            None
        } else {
            Some(entries)
        };

        let issuer_spki_der = self
            .opts
            .certificate
            .tbs_certificate()
            .subject_public_key_info()
            .to_der()?;
        let ski = signing::subject_key_id(&issuer_spki_der)?;
        // Constat O-1 : la CRL seule ne distingue pas un numéro jamais émis
        // d'un numéro émis mais non révoqué. Cette extension porte tous les
        // numéros émis (jamais purgée, à la différence des entrées
        // révoquées ci-dessus) pour que le répondeur OCSP réponde `unknown`
        // à un numéro absent d'ici, jamais `good`.
        let issued = self.opts.store.issued_serials().await?;
        let crl_extensions: x509_cert::ext::Extensions = vec![
            extensions::crl_number(number)?,
            extensions::authority_key_identifier(&ski)?,
            extensions::crl_issued_serials(&issued)?,
        ];

        let tbs = x509_cert::crl::TbsCertList {
            version: x509_cert::Version::V2,
            // Remplacé par `signing::sign_crl` juste avant de signer, comme
            // le fait `x509_cert::builder::CrlBuilder` (placeholder "0.0.0").
            signature: spki::AlgorithmIdentifierOwned {
                oid: der::asn1::ObjectIdentifier::new("0.0.0").expect("OID constant invalide"),
                parameters: None,
            },
            issuer: self.opts.certificate.tbs_certificate().subject().clone(),
            this_update,
            next_update: Some(next_update),
            revoked_certificates,
            crl_extensions: Some(crl_extensions),
        };
        let crl = signing::sign_crl(tbs, self.opts.signer.as_ref(), &issuer_spki_der)?;
        let der = crl.to_der()?;

        let record = oe_castore::Crl {
            number,
            der,
            this_update: now,
            next_update: now + self.opts.crl_validity,
        };

        // Le journal *avant* l'enregistrement durable (§15 étape 2b) : si
        // l'écriture échoue, cette CRL n'est pas publiée — seul le numéro
        // réservé (`next_crl_number`) est perdu, déjà toléré (la séquence ne
        // recule jamais).
        self.record(
            "ca.crl_published",
            serde_json::json!({
                "numero": number,
                "entrees": revoked.len(),
                "prochaine_maj": record.next_update.format(&time::format_description::well_known::Rfc3339).unwrap_or_default(),
            }),
        )
        .await?;
        self.opts.store.save_crl(record.clone()).await?;

        Ok(record)
    }

    pub async fn current_crl(&self) -> Result<oe_castore::Crl, CaError> {
        Ok(self.opts.store.latest_crl().await?)
    }
}

fn extensions_crl_reason(code: i32) -> Result<Extension, CaError> {
    use x509_cert::ext::pkix::crl::CrlReason;
    let variant = match code {
        1 => CrlReason::KeyCompromise,
        2 => CrlReason::CaCompromise,
        3 => CrlReason::AffiliationChanged,
        4 => CrlReason::Superseded,
        5 => CrlReason::CessationOfOperation,
        6 => CrlReason::CertificateHold,
        8 => CrlReason::RemoveFromCRL,
        9 => CrlReason::PrivilegeWithdrawn,
        10 => CrlReason::AaCompromise,
        _ => CrlReason::Unspecified,
    };
    Ok(Extension {
        extn_id: der::asn1::ObjectIdentifier::new("2.5.29.21").expect("OID constant invalide"),
        critical: false,
        extn_value: der::asn1::OctetString::new(variant.to_der()?)?,
    })
}

fn common_name(cert: &Certificate) -> String {
    const OID_CN: &str = "2.5.4.3";
    let cn_oid = der::asn1::ObjectIdentifier::new(OID_CN).expect("OID constant invalide");
    cert.tbs_certificate()
        .subject()
        .iter()
        .find(|atv| atv.oid == cn_oid)
        .map(|atv| String::from_utf8_lossy(atv.value.value()).into_owned())
        .unwrap_or_default()
}

pub mod ceremony;
