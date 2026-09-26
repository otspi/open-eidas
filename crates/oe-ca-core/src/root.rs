//! Constat C-1 de l'audit du 2026-09-25 (EN 319 411-1 `CSS-6.3.9-12/-13`,
//! `CSS-6.3.10-01`) : jusqu'ici, rien ne permettait de révoquer une autorité
//! ni de publier l'ARL qui en informerait les tiers. Distinct d'[`crate::Issuer`],
//! qui signe avec la clé de l'émettrice : ici tout passe par la clé de la
//! **racine**, qui ne devrait être ouverte que pour cette opération — à
//! l'identique de [`crate::ceremony::run_ceremony`], jamais pendant le
//! service en ligne (`ca-server serve` n'ouvre que le token de l'émettrice).

use std::sync::Arc;

use der::{Decode, Encode};
use x509_cert::Certificate;

use oe_castore::{Arl, Store};
use oe_hsm::SigningToken;

use crate::{extensions, extensions_crl_reason, signing, to_x509_time, CaError, Recorder};

pub struct RootAuthorityOptions {
    pub signer: Arc<dyn SigningToken + Send + Sync>,
    pub certificate: Certificate,
    pub store: Arc<dyn Store>,
    pub arl_validity: time::Duration,
    pub recorder: Option<Arc<dyn Recorder>>,
}

/// Porte les deux seuls actes que la racine effectue après la cérémonie :
/// révoquer une autorité subordonnée, et publier l'ARL qui en atteste.
pub struct RootAuthority {
    opts: RootAuthorityOptions,
}

impl RootAuthority {
    pub fn new(opts: RootAuthorityOptions) -> RootAuthority {
        RootAuthority { opts }
    }

    async fn record(&self, event: &str, data: serde_json::Value) -> Result<(), CaError> {
        if let Some(recorder) = &self.opts.recorder {
            recorder
                .append(event, data)
                .await
                .map_err(|e| CaError::Other(format!("journal : {e}")))?;
        }
        Ok(())
    }

    /// Révoque une autorité subordonnée (jamais la racine elle-même, qui
    /// n'a pas d'émetteur à qui le signaler) et republie immédiatement
    /// l'ARL — même raisonnement que `Issuer::revoke`/`publish_crl` : une
    /// révocation qui n'est pas publiée ne protège personne.
    pub async fn revoke_authority(
        &self,
        name: &str,
        reason: i32,
        operator: &str,
        comment: &str,
    ) -> Result<Arl, CaError> {
        if operator.is_empty() {
            return Err(CaError::Other(
                "la révocation d'une autorité exige l'identité de l'opérateur qui la décide"
                    .to_string(),
            ));
        }
        if name == crate::ceremony::AUTHORITY_ROOT {
            return Err(CaError::Other(
                "la racine ne peut pas se révoquer elle-même".to_string(),
            ));
        }
        let authority = self.opts.store.authority(name).await?;
        let at = time::OffsetDateTime::now_utc();

        // Le journal *avant* la révocation en base (§15 étape 2b) : si
        // l'écriture échoue, l'autorité reste active — pas de révocation à
        // moitié consignée.
        self.record(
            "ca.authority_revoked",
            serde_json::json!({
                "autorite": name,
                "sujet": authority.subject_dn,
                "motif": reason,
                "operateur": operator,
                "commentaire": comment,
                "date": at.format(&time::format_description::well_known::Rfc3339).unwrap_or_default(),
            }),
        )
        .await?;
        self.opts.store.revoke_authority(name, at, reason).await?;

        self.publish_arl().await
    }

    /// Produit et enregistre une nouvelle ARL — publiée même vide (ETSI EN
    /// 319 411-1 `CSS-6.3.9-12` : au moins une fois par an).
    pub async fn publish_arl(&self) -> Result<Arl, CaError> {
        let now = time::OffsetDateTime::now_utc();
        let revoked = self.opts.store.revoked_authorities().await?;

        let number = self.opts.store.next_arl_number().await?;
        let this_update = to_x509_time(now - time::Duration::minutes(1))?;
        let next_update = to_x509_time(now + self.opts.arl_validity)?;

        let entries: Result<Vec<_>, CaError> = revoked
            .iter()
            .map(|a| -> Result<_, CaError> {
                let cert = Certificate::from_der(&a.der)?;
                let mut exts = x509_cert::ext::Extensions::new();
                if a.revocation_reason != 0 {
                    exts.push(extensions_crl_reason(a.revocation_reason)?);
                }
                Ok(x509_cert::crl::RevokedCert {
                    serial_number: cert.tbs_certificate().serial_number().clone(),
                    revocation_date: to_x509_time(a.revoked_at.unwrap_or(now))?,
                    crl_entry_extensions: if exts.is_empty() { None } else { Some(exts) },
                })
            })
            .collect();
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
        let arl_extensions: x509_cert::ext::Extensions = vec![
            extensions::crl_number(number)?,
            extensions::authority_key_identifier(&ski)?,
        ];

        let tbs = x509_cert::crl::TbsCertList {
            version: x509_cert::Version::V2,
            signature: spki::AlgorithmIdentifierOwned {
                oid: der::asn1::ObjectIdentifier::new("0.0.0").expect("OID constant invalide"),
                parameters: None,
            },
            issuer: self.opts.certificate.tbs_certificate().subject().clone(),
            this_update,
            next_update: Some(next_update),
            revoked_certificates,
            crl_extensions: Some(arl_extensions),
        };
        let arl = signing::sign_crl(tbs, self.opts.signer.as_ref(), &issuer_spki_der)?;
        let der = arl.to_der()?;

        let record = Arl {
            number,
            der,
            this_update: now,
            next_update: now + self.opts.arl_validity,
        };

        // Le journal *avant* l'enregistrement durable (§15 étape 2b).
        self.record(
            "ca.arl_published",
            serde_json::json!({
                "numero": number,
                "entrees": revoked.len(),
                "prochaine_maj": record.next_update.format(&time::format_description::well_known::Rfc3339).unwrap_or_default(),
            }),
        )
        .await?;
        self.opts.store.save_arl(record.clone()).await?;

        Ok(record)
    }

    pub async fn current_arl(&self) -> Result<Arl, CaError> {
        Ok(self.opts.store.latest_arl().await?)
    }
}
