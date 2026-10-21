//! TLS mutuel du lien interne `ra-console` ↔ `ca-server` (docs/WEBUI.md §16
//! « Lien interne »), terminé par `ca-server` lui-même.
//!
//! Le mTLS ne prouve qu'une chose : l'appelant est bien `ra-console`. Il ne
//! donne aucun pouvoir, qui vient de la signature d'un opérateur (§4). Il doit
//! cependant être exact : les certificats de TSU, de répondeur OCSP et
//! d'identité remontent à la même CA, et certains peuvent porter `clientAuth`.
//! Vérifier la seule chaîne laisserait entrer n'importe quel porteur.
//!
//! Le vérificateur de `rustls` contrôle la chaîne vers la CA émettrice, la
//! validité et l'EKU `clientAuth`. Ce module y ajoute, **avant que la moindre
//! requête HTTP soit lue**, les contrôles que la bibliothèque ne connaît pas :
//!
//!   1. la structure du certificat (EKU `clientAuth` **seul**, politique dédiée) ;
//!   2. le nom courant exact `ra-console` ;
//!   3. l'inscription du certificat dans la table `certificates`, sous le profil
//!      `internal_client`, identique octet pour octet ;
//!   4. son statut : révoqué, la connexion est refusée dès la suivante.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use der::{Decode, Encode};
use oe_castore::{CertificateStatus, Store};
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig};
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::server::TlsStream;
use tokio_rustls::TlsAcceptor;
use x509_cert::Certificate;

/// Une poignée de main qui traîne ne doit pas retenir de ressources.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Contrôles propres à `ca-server`, appliqués au certificat client déjà
/// accepté par `rustls`. Séparés de la poignée de main pour être testés seuls.
pub async fn check_client_certificate(
    store: &dyn Store,
    der: &[u8],
    now: time::OffsetDateTime,
) -> Result<(), String> {
    let cert = Certificate::from_der(der).map_err(|e| format!("certificat illisible : {e}"))?;

    oe_conformance::check_internal_client_certificate("certificat client", &cert)?;

    let cn = common_name(&cert);
    if cn != oe_ca_core::profile::INTERNAL_CLIENT_CN {
        return Err(format!(
            "nom courant {cn:?}, attendu {:?}",
            oe_ca_core::profile::INTERNAL_CLIENT_CN
        ));
    }

    // Validité relue ici : ce contrôle ne dépend pas de la bibliothèque TLS.
    let validity = cert.tbs_certificate().validity();
    let unix = now.unix_timestamp() as u64;
    if unix < validity.not_before.to_unix_duration().as_secs()
        || unix > validity.not_after.to_unix_duration().as_secs()
    {
        return Err("certificat hors de sa période de validité".to_string());
    }

    let serial = oe_ca_core::canonical_serial(cert.tbs_certificate().serial_number());
    let stored = store
        .certificate(&serial)
        .await
        .map_err(|e| format!("certificat absent de la table certificates : {e}"))?;
    if stored.profile != oe_ca_core::profile::PROFILE_INTERNAL_CLIENT {
        return Err(format!(
            "certificat émis sous le profil {:?}, pas {:?}",
            stored.profile,
            oe_ca_core::profile::PROFILE_INTERNAL_CLIENT
        ));
    }
    if stored.der != der {
        return Err("le certificat présenté diffère de celui que la CA a émis".to_string());
    }
    match stored.status {
        CertificateStatus::Issued => Ok(()),
        CertificateStatus::Revoked => Err("certificat révoqué".to_string()),
        CertificateStatus::Reserved => Err("certificat jamais émis".to_string()),
    }
}

pub(crate) fn common_name(cert: &Certificate) -> String {
    let cn = der::asn1::ObjectIdentifier::new("2.5.4.3").expect("OID constant invalide");
    cert.tbs_certificate()
        .subject()
        .iter()
        .find(|atv| atv.oid == cn)
        .map(|atv| String::from_utf8_lossy(atv.value.value()).into_owned())
        .unwrap_or_default()
}

/// Configuration TLS du serveur : TLS 1.3 seul, certificat client obligatoire,
/// racine de confiance = la CA émettrice et elle seule.
///
/// Refuse de démarrer si le certificat du serveur n'est pas un certificat
/// `internal_server` valide : un certificat qui « fonctionne » mais qui n'est
/// pas celui que le profil décrit est une erreur de déploiement à voir tout de
/// suite.
pub fn server_config(
    issuer: &Certificate,
    cert_pem: &[u8],
    key_pem: &[u8],
    now: time::OffsetDateTime,
) -> Result<ServerConfig, String> {
    let chain: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(cert_pem)
        .collect::<Result<_, _>>()
        .map_err(|e| format!("certificat du serveur illisible : {e}"))?;
    let leaf_der = chain
        .first()
        .ok_or("aucun certificat dans le fichier du serveur")?;
    let leaf = Certificate::from_der(leaf_der)
        .map_err(|e| format!("certificat du serveur illisible : {e}"))?;
    oe_conformance::check_internal_server_certificate("certificat du serveur", &leaf)?;
    let validity = leaf.tbs_certificate().validity();
    let unix = now.unix_timestamp() as u64;
    if unix < validity.not_before.to_unix_duration().as_secs()
        || unix > validity.not_after.to_unix_duration().as_secs()
    {
        return Err("certificat du serveur hors de sa période de validité".to_string());
    }
    let key = PrivateKeyDer::from_pem_slice(key_pem)
        .map_err(|e| format!("clé privée du serveur illisible : {e}"))?;

    let issuer_der = issuer
        .to_der()
        .map_err(|e| format!("certificat de la CA : {e}"))?;
    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from(issuer_der))
        .map_err(|e| format!("racine de confiance : {e}"))?;

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let verifier = WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider.clone())
        .build()
        .map_err(|e| format!("vérificateur de certificats clients : {e}"))?;
    let mut config = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| e.to_string())?
        .with_client_cert_verifier(verifier)
        .with_single_cert(chain, key)
        .map_err(|e| format!("certificat et clé du serveur : {e}"))?;
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(config)
}

/// Écoute TLS pour `axum::serve` : ne rend que des connexions dont le
/// certificat client a passé tous les contrôles. Les poignées de main se
/// font en tâches séparées, pour qu'un client lent ne bloque pas les autres.
pub struct TlsListener {
    local: SocketAddr,
    accepted: tokio::sync::mpsc::Receiver<(TlsStream<TcpStream>, SocketAddr)>,
}

impl TlsListener {
    pub fn new(tcp: TcpListener, config: ServerConfig, store: Arc<dyn Store>) -> TlsListener {
        let local = tcp.local_addr().expect("adresse d'écoute");
        let acceptor = TlsAcceptor::from(Arc::new(config));
        let (tx, accepted) = tokio::sync::mpsc::channel(16);
        tokio::spawn(async move {
            loop {
                let (tcp, peer) = match tcp.accept().await {
                    Ok(c) => c,
                    Err(e) => {
                        tracing::warn!(erreur = %e, "accept() du lien interne");
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        continue;
                    }
                };
                let (acceptor, store, tx) = (acceptor.clone(), store.clone(), tx.clone());
                tokio::spawn(async move {
                    match tokio::time::timeout(
                        HANDSHAKE_TIMEOUT,
                        admit(&acceptor, tcp, store.as_ref()),
                    )
                    .await
                    {
                        Ok(Ok(tls)) => {
                            let _ = tx.send((tls, peer)).await;
                        }
                        Ok(Err(reason)) => {
                            tracing::warn!(pair = %peer, %reason, "connexion interne refusée");
                        }
                        Err(_) => {
                            tracing::warn!(pair = %peer, "connexion interne : poignée de main trop lente");
                        }
                    }
                });
            }
        });
        TlsListener { local, accepted }
    }
}

async fn admit(
    acceptor: &TlsAcceptor,
    tcp: TcpStream,
    store: &dyn Store,
) -> Result<TlsStream<TcpStream>, String> {
    let tls = acceptor
        .accept(tcp)
        .await
        .map_err(|e| format!("poignée de main TLS : {e}"))?;
    let leaf = tls
        .get_ref()
        .1
        .peer_certificates()
        .and_then(|c| c.first())
        .ok_or("aucun certificat client")?
        .to_vec();
    check_client_certificate(store, &leaf, time::OffsetDateTime::now_utc()).await?;
    Ok(tls)
}

impl axum::serve::Listener for TlsListener {
    type Io = TlsStream<TcpStream>;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        // L'émetteur vit autant que la tâche d'écoute : `None` ne se produit
        // qu'à l'arrêt du runtime.
        match self.accepted.recv().await {
            Some(c) => c,
            None => std::future::pending().await,
        }
    }

    fn local_addr(&self) -> std::io::Result<Self::Addr> {
        Ok(self.local)
    }
}
