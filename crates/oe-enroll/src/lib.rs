//! Portage de `internal/enroll` : obtient le certificat d'un service
//! (unité d'horodatage, répondeur OCSP) auprès de l'autorité de
//! certification (`ca-server`), via son API d'enrôlement — jalon J9 du plan
//! de migration (`/home/philippe/.claude/plans/witty-hopping-nest.md`).
//!
//! Le protocole est entièrement défini par ce dépôt : une CSR en PEM, un
//! authentifiant HMAC-SHA256 sur ses octets DER, une réponse JSON. Ce client
//! parle au `ca-server` Go existant (interopérabilité HTTP uniquement) tant
//! que celui-ci n'est pas porté — voir l'ordre de portage du plan.

pub mod software_key;

use std::time::Duration;

use der::asn1::{BitString, SetOfVec};
use der::{Decode, Encode};
use hmac::{Hmac, Mac};
use oe_hsm::{DigestAlg, SigningToken};
use sha2::{Digest, Sha256};
use spki::AlgorithmIdentifierOwned;
use x509_cert::name::Name;
use x509_cert::request::{CertReq, CertReqInfo};
use x509_cert::{Certificate, SubjectPublicKeyInfo};

/// OID `sha256WithRSAEncryption` (1.2.840.113549.1.1.11) — signature X.509
/// combinant hachage et padding en un seul identifiant, à la différence de
/// la convention CMS (`oe_rfc3161_asn1::token`, qui sépare les deux).
const OID_SHA256_WITH_RSA: &str = "1.2.840.113549.1.1.11";

pub struct Options {
    /// URL complète de l'API d'enrôlement de la CA, par ex.
    /// `http://ca:8320/api/v1/enroll`.
    pub endpoint: String,
    /// Nomme le profil de certificat demandé (voir `internal/ca`).
    pub profile: String,
    /// Authentifie le demandeur auprès de la CA. Sans lui, la demande est
    /// refusée avant même d'atteindre la machine à états.
    pub hmac_secret: String,
    pub ca_file: Option<String>,
    pub insecure: bool,
    pub timeout: Duration,
    pub user_agent: Option<String>,
}

impl Default for Options {
    fn default() -> Self {
        Options {
            endpoint: String::new(),
            profile: String::new(),
            hmac_secret: String::new(),
            ca_file: None,
            insecure: false,
            timeout: Duration::from_secs(5 * 60),
            user_agent: None,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum EnrollError {
    #[error("enroll: endpoint d'enrôlement non configuré")]
    MissingEndpoint,
    #[error("enroll: profil de certificat non configuré")]
    MissingProfile,
    #[error("enroll: secret d'enrôlement non configuré")]
    MissingSecret,
    #[error("enroll: lecture de l'ancre de confiance: {0}")]
    ReadCaFile(#[source] std::io::Error),
    #[error("enroll: ancre de confiance invalide: {0}")]
    InvalidCaFile(#[source] reqwest::Error),
    #[error("enroll: configuration du client HTTP: {0}")]
    HttpClient(#[source] reqwest::Error),
    #[error("enroll: génération de la CSR: {0}")]
    Csr(#[from] der::Error),
    #[error("enroll: signature de la CSR: {0}")]
    Signing(#[from] oe_hsm::HsmError),
    #[error("enroll: appel de {endpoint}: {source}")]
    Http {
        endpoint: String,
        #[source]
        source: reqwest::Error,
    },
    #[error("enroll: réponse illisible ({status}): {excerpt}")]
    UnreadableResponse {
        status: reqwest::StatusCode,
        excerpt: String,
    },
    #[error("enroll: la PKI a refusé la demande ({status}): {message}")]
    Refused {
        status: reqwest::StatusCode,
        message: String,
    },
    #[error(
        "enroll: demande {transaction_id} toujours en attente d'approbation après {timeout:?}"
    )]
    Timeout {
        transaction_id: String,
        timeout: Duration,
    },
    #[error("enroll: certificat émis illisible: {0}")]
    InvalidIssuedCertificate(String),
}

pub struct Client {
    opts: Options,
    http: reqwest::Client,
}

/// Le nom courant demandé pour le certificat. Le reste du sujet (unité,
/// organisation, pays) est imposé par le profil côté autorité : un
/// demandeur ne choisit pas l'organisation dont il se réclame.
pub struct Subject {
    pub common_name: String,
}

/// Le certificat émis et sa chaîne d'émission.
pub struct EnrollResult {
    pub certificate: Certificate,
    pub chain: Vec<Certificate>,
}

impl Client {
    pub fn new(opts: Options) -> Result<Client, EnrollError> {
        if opts.endpoint.is_empty() {
            return Err(EnrollError::MissingEndpoint);
        }
        if opts.profile.is_empty() {
            return Err(EnrollError::MissingProfile);
        }
        if opts.hmac_secret.is_empty() {
            return Err(EnrollError::MissingSecret);
        }

        let mut builder = reqwest::Client::builder().timeout(Duration::from_secs(30));
        if let Some(ca_file) = &opts.ca_file {
            let pem = std::fs::read(ca_file).map_err(EnrollError::ReadCaFile)?;
            let cert = reqwest::Certificate::from_pem(&pem).map_err(EnrollError::InvalidCaFile)?;
            builder = builder.add_root_certificate(cert);
        } else if opts.insecure {
            // Toléré uniquement pour la démonstration locale, où l'API de la
            // CA est jointe en HTTP interne ou derrière un certificat
            // auto-signé.
            builder = builder.danger_accept_invalid_certs(true);
        }
        let http = builder.build().map_err(EnrollError::HttpClient)?;

        Ok(Client { opts, http })
    }

    /// Génère une CSR signée par la clé du token puis la soumet à la CA.
    /// L'appel boucle tant que la demande attend la décision d'un opérateur
    /// RA, jusqu'à expiration du délai configuré.
    pub async fn request(
        &self,
        signer: &dyn SigningToken,
        subject: Subject,
    ) -> Result<EnrollResult, EnrollError> {
        let (csr_der, csr_pem) = build_csr(signer, &subject)?;
        let signature = hmac_signature(&csr_der, &self.opts.hmac_secret);

        let deadline = std::time::Instant::now() + self.opts.timeout;
        let mut attempt = 1u32;
        loop {
            let resp = self.post(&csr_pem, &signature).await?;
            if let Some(cert_pem) = &resp.certificate {
                if !cert_pem.is_empty() {
                    return parse_result(&resp);
                }
            }

            let retry_after = if resp.retry_after > 0 {
                Duration::from_secs(resp.retry_after as u64)
            } else {
                Duration::from_secs(5)
            };
            if std::time::Instant::now() + retry_after > deadline {
                return Err(EnrollError::Timeout {
                    transaction_id: resp.transaction_id,
                    timeout: self.opts.timeout,
                });
            }
            tracing::info!(
                transaction = %resp.transaction_id, tentative = attempt, nouvelle_tentative_dans = ?retry_after,
                "enrôlement en attente de l'approbation d'un opérateur RA"
            );
            tokio::time::sleep(retry_after).await;
            attempt += 1;
        }
    }

    async fn post(&self, csr_pem: &str, signature: &str) -> Result<EnrollResponse, EnrollError> {
        let body = EnrollRequest {
            profile: self.opts.profile.clone(),
            pkcs10: csr_pem.to_string(),
            signature: signature.to_string(),
            comment: "Open eIDAS service enrollment".to_string(),
        };
        let mut req = self
            .http
            .post(&self.opts.endpoint)
            .header("Accept", "application/json")
            .json(&body);
        if let Some(ua) = &self.opts.user_agent {
            req = req.header("User-Agent", ua);
        }
        let resp = req.send().await.map_err(|e| EnrollError::Http {
            endpoint: self.opts.endpoint.clone(),
            source: e,
        })?;
        let status = resp.status();
        let raw = resp.bytes().await.map_err(|e| EnrollError::Http {
            endpoint: self.opts.endpoint.clone(),
            source: e,
        })?;

        let parsed: EnrollResponse =
            serde_json::from_slice(&raw).map_err(|_| EnrollError::UnreadableResponse {
                status,
                excerpt: truncate(&String::from_utf8_lossy(&raw), 200),
            })?;

        // 202 accompagne une demande en attente : déroulement normal, pas une erreur.
        if status.as_u16() >= 300 {
            let message = if !parsed.error.is_empty() {
                parsed.error.clone()
            } else {
                truncate(&String::from_utf8_lossy(&raw), 200)
            };
            return Err(EnrollError::Refused { status, message });
        }
        Ok(parsed)
    }
}

#[derive(serde::Serialize)]
struct EnrollRequest {
    profile: String,
    pkcs10: String,
    signature: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    comment: String,
}

#[derive(serde::Deserialize, Default)]
struct EnrollResponse {
    #[serde(default)]
    transaction_id: String,
    #[serde(default)]
    retry_after: i64,
    #[serde(default)]
    certificate: Option<String>,
    #[serde(default)]
    chain: Vec<String>,
    #[serde(default)]
    error: String,
}

fn parse_result(resp: &EnrollResponse) -> Result<EnrollResult, EnrollError> {
    let cert_pem = resp.certificate.as_deref().unwrap_or_default();
    let leaf = oe_certs::parse_pem(cert_pem.as_bytes())
        .map_err(|e| EnrollError::InvalidIssuedCertificate(e.to_string()))?;
    let leaf_cert = leaf
        .into_iter()
        .next()
        .ok_or_else(|| EnrollError::InvalidIssuedCertificate("aucun certificat".to_string()))?;

    let mut chain = Vec::new();
    for item in &resp.chain {
        if item.trim().is_empty() {
            continue;
        }
        let parsed = oe_certs::parse_pem(item.as_bytes())
            .map_err(|e| EnrollError::InvalidIssuedCertificate(e.to_string()))?;
        chain.extend(parsed);
    }
    // Retire de la chaîne le certificat émis lui-même : selon la
    // configuration, la CA peut le renvoyer dans les deux champs.
    let leaf_der = leaf_cert.to_der()?;
    chain.retain(|c| c.to_der().map(|d| d != leaf_der).unwrap_or(true));

    Ok(EnrollResult {
        certificate: leaf_cert,
        chain,
    })
}

fn hmac_signature(csr_der: &[u8], secret: &str) -> String {
    let mut mac =
        Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("clé HMAC de taille arbitraire");
    mac.update(csr_der);
    hex::encode(mac.finalize().into_bytes())
}

/// Construit une CSR PKCS#10 signée par le token, avec l'algorithme
/// `sha256WithRSAEncryption` — SHA-1 n'est jamais une option : la CA
/// refuserait la CSR (ETSI TS 119 312), autant ne pas la produire.
pub fn build_csr(
    signer: &dyn SigningToken,
    subject: &Subject,
) -> Result<(Vec<u8>, String), EnrollError> {
    let name: Name = escape_common_name(&subject.common_name)
        .parse()
        .map_err(EnrollError::Csr)?;
    let spki_der = signer.public_key_der()?;
    let public_key = SubjectPublicKeyInfo::from_der(&spki_der)?;

    let info = CertReqInfo {
        version: Default::default(),
        subject: name,
        public_key,
        attributes: SetOfVec::new(),
    };
    let info_der = info.to_der()?;
    let digest = Sha256::digest(&info_der);
    let signature = signer.sign_digest(DigestAlg::Sha256, &digest)?;

    let req = CertReq {
        info,
        algorithm: AlgorithmIdentifierOwned {
            oid: der::asn1::ObjectIdentifier::new(OID_SHA256_WITH_RSA)
                .expect("OID constant invalide"),
            // RFC 4055 §5 : sha256WithRSAEncryption porte des paramètres NULL à
            // l\'émission (constat C-5) ; l\'absence reste tolérée à la lecture.
            parameters: Some(der::asn1::Null.into()),
        },
        signature: BitString::from_bytes(&signature)?,
    };
    let der = req.to_der()?;
    let pem = pem::encode(&pem::Pem::new("CERTIFICATE REQUEST", der.clone()));
    Ok((der, pem))
}

/// Échappe les caractères spéciaux RFC 4514 dans une valeur de CN destinée à
/// `Name::from_str` (`,+"\<>;` et espace/dièse en tête).
fn escape_common_name(cn: &str) -> String {
    let mut out = String::from("CN=");
    for (i, c) in cn.chars().enumerate() {
        match c {
            ',' | '+' | '"' | '\\' | '<' | '>' | ';' => {
                out.push('\\');
                out.push(c);
            }
            ' ' if i == 0 || i == cn.chars().count() - 1 => {
                out.push('\\');
                out.push(' ');
            }
            '#' if i == 0 => {
                out.push('\\');
                out.push('#');
            }
            other => out.push(other),
        }
    }
    out
}

fn truncate(s: &str, n: usize) -> String {
    let s = s.trim();
    if s.chars().count() <= n {
        s.to_string()
    } else {
        format!("{}…", s.chars().take(n).collect::<String>())
    }
}
