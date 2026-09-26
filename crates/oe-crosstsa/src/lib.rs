//! Portage de `internal/crosstsa` : fait attester la tête du journal d'audit
//! par une ou plusieurs autorités d'horodatage tierces et publiques — jalon
//! J8 du plan de migration
//! (`/home/philippe/.claude/plans/witty-hopping-nest.md`).
//!
//! Le scellement du journal (`oe-audit`) est auto-référentiel : la TSU
//! horodate sa propre empreinte, ce qui ne prouve rien à qui ne fait pas
//! déjà confiance au service. En faisant compter le même hachage par une
//! autorité indépendante (RFC 3161 standard, comme n'importe quel client),
//! un auditeur peut vérifier après coup, avec des outils standards, que la
//! tête de chaîne existait à une date donnée.

use std::time::Duration;

use der::{Decode, Encode};
use x509_cert::Certificate;

const MIME_QUERY: &str = "application/timestamp-query";
/// Limite la réponse lue à 1 Mio, comme le code Go (`io.LimitReader`).
const MAX_RESPONSE_BYTES: usize = 1 << 20;

pub struct Options {
    /// URLs des TSA tierces interrogées. Chaque contreseing réussi est
    /// consigné séparément : la perte d'une source ne bloque pas les autres.
    pub urls: Vec<String>,
    pub timeout: Duration,
}

impl Default for Options {
    fn default() -> Self {
        Options {
            urls: Vec::new(),
            timeout: Duration::from_secs(15),
        }
    }
}

pub struct Client {
    http: reqwest::Client,
    urls: Vec<String>,
}

/// Le résultat d'un contreseing réussi.
#[derive(Debug, Clone)]
pub struct Attestation {
    pub tsa: String,
    pub gen_time: String,
    pub serial: String,
    /// `TimeStampResp` DER, encodée en base64.
    pub token: String,
}

#[derive(Debug, thiserror::Error)]
enum QueryError {
    #[error("encodage de la requête RFC 3161: {0}")]
    Encode(#[from] der::Error),
    #[error("requête HTTP: {0}")]
    Http(#[from] reqwest::Error),
    #[error("HTTP {0}")]
    Status(reqwest::StatusCode),
    #[error("réponse RFC 3161 illisible: {0}")]
    Decode(String),
    #[error("la TSA a retourné une empreinte différente de celle soumise")]
    ImprintMismatch,
}

impl Client {
    pub fn new(opts: Options) -> Client {
        let http = reqwest::Client::builder()
            .timeout(opts.timeout)
            .build()
            .unwrap_or_default();
        Client {
            http,
            urls: opts.urls,
        }
    }

    /// Soumet l'empreinte donnée à chaque TSA configurée et retourne les
    /// contreseings obtenus. Une TSA injoignable ou en erreur est
    /// journalisée (via `tracing`) et simplement absente du résultat.
    pub async fn seal(
        &self,
        digest: &[u8],
        hash_alg: spki::AlgorithmIdentifierOwned,
    ) -> Vec<Attestation> {
        let mut out = Vec::new();
        for url in &self.urls {
            match self.query(url, digest, hash_alg.clone()).await {
                Ok(att) => out.push(att),
                Err(e) => {
                    tracing::warn!(tsa = %url, erreur = %e, "contreseing par une TSA tierce impossible")
                }
            }
        }
        out
    }

    async fn query(
        &self,
        url: &str,
        digest: &[u8],
        hash_alg: spki::AlgorithmIdentifierOwned,
    ) -> Result<Attestation, QueryError> {
        let req = oe_rfc3161_asn1::TimeStampReq {
            version: 1,
            message_imprint: oe_rfc3161_asn1::MessageImprint {
                hash_algorithm: hash_alg,
                hashed_message: der::asn1::OctetString::new(digest.to_vec())?,
            },
            req_policy: None,
            nonce: None,
            cert_req: true,
            extensions: None,
        };
        let req_der = req.to_der()?;

        let resp = self
            .http
            .post(url)
            .header("Content-Type", MIME_QUERY)
            .body(req_der)
            .send()
            .await?;
        if !resp.status().is_success() {
            return Err(QueryError::Status(resp.status()));
        }
        let body = resp.bytes().await?;
        if body.len() > MAX_RESPONSE_BYTES {
            return Err(QueryError::Decode("réponse trop volumineuse".to_string()));
        }

        let parsed = ParsedToken::decode(&body).map_err(QueryError::Decode)?;
        if parsed.hashed_message != digest {
            return Err(QueryError::ImprintMismatch);
        }

        let name = parsed.signer_subject.unwrap_or_else(|| url.to_string());
        Ok(Attestation {
            tsa: name,
            gen_time: parsed.gen_time,
            serial: parsed.serial_hex,
            token: {
                use base64::Engine;
                base64::engine::general_purpose::STANDARD.encode(&body)
            },
        })
    }
}

/// Ce qu'on extrait d'une `TimeStampResp` reçue d'un tiers : décompose
/// l'enveloppe CMS (`ContentInfo` → `SignedData` → `TSTInfo` encapsulé) pour
/// vérifier l'empreinte et journaliser le nom de l'autorité tierce.
struct ParsedToken {
    hashed_message: Vec<u8>,
    gen_time: String,
    serial_hex: String,
    signer_subject: Option<String>,
}

impl ParsedToken {
    fn decode(resp_der: &[u8]) -> Result<ParsedToken, String> {
        let resp = oe_rfc3161_asn1::TimeStampResp::from_der(resp_der).map_err(|e| e.to_string())?;
        let token_any = resp.time_stamp_token.ok_or("jeton absent de la réponse")?;
        let token_der = token_any.to_der().map_err(|e| e.to_string())?;

        let content_info =
            cms::content_info::ContentInfo::from_der(&token_der).map_err(|e| e.to_string())?;
        let signed_data_der = content_info.content.to_der().map_err(|e| e.to_string())?;
        let signed_data =
            cms::signed_data::SignedData::from_der(&signed_data_der).map_err(|e| e.to_string())?;

        let econtent = signed_data
            .encap_content_info
            .econtent
            .ok_or("contenu encapsulé absent")?;
        let octets =
            der::asn1::OctetString::from_der(&econtent.to_der().map_err(|e| e.to_string())?)
                .map_err(|e| e.to_string())?;
        let tst_info =
            oe_rfc3161_asn1::TstInfo::from_der(octets.as_bytes()).map_err(|e| e.to_string())?;

        // `gen_time` est un `Any` (pas `der::asn1::GeneralizedTime`, qui
        // interdit les fractions de seconde — voir `oe_rfc3161_asn1::gen_time`) :
        // son contenu est déjà la chaîne ASCII `YYYYMMDDHHMMSS[.fff]Z`.
        let gen_time = String::from_utf8_lossy(tst_info.gen_time.value()).to_string();

        let signer_subject = signed_data.certificates.as_ref().and_then(|set| {
            set.0.iter().find_map(|choice| match choice {
                cms::cert::CertificateChoices::Certificate(cert) => Some(subject_string(cert)),
                _ => None,
            })
        });

        Ok(ParsedToken {
            hashed_message: tst_info.message_imprint.hashed_message.as_bytes().to_vec(),
            gen_time,
            serial_hex: hex::encode(tst_info.serial_number.as_bytes()),
            signer_subject,
        })
    }
}

fn subject_string(cert: &Certificate) -> String {
    cert.tbs_certificate().subject().to_string()
}
