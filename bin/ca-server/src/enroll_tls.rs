//! Port d'enrôlement en TLS mutuel (constat R-3, docs/R3-MTLS-DEMANDEURS.md) :
//! un demandeur (TSA, répondeur OCSP) s'identifie par son certificat client
//! `enroll_client`, plus par un secret partagé.
//!
//! Même discipline que le lien interne ([`crate::internal_tls`]) : la bibliothèque
//! TLS vérifie la chaîne vers la CA émettrice, la validité et `clientAuth` ; ce
//! module y ajoute, **avant toute requête HTTP**, la structure du certificat
//! (profil `enroll_client`), son inscription à l'identique dans la table
//! `certificates` et son statut. Le rattachement du nom courant à un demandeur,
//! lui, se fait à chaque requête (`Flow::submit_mtls`), pour qu'un changement du
//! fichier des demandeurs vaille tout de suite.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use der::Decode;
use oe_castore::{CertificateStatus, Store};
use rustls::ServerConfig;
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::server::TlsStream;
use tokio_rustls::TlsAcceptor;
use x509_cert::Certificate;

use crate::internal_tls::common_name;

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Qui est au bout de la connexion : son adresse et le nom courant de son
/// certificat client, déjà contrôlé.
#[derive(Clone, Debug)]
pub struct EnrollPeer {
    pub addr: SocketAddr,
    pub client_cn: String,
}

/// Contrôles de `ca-server` sur un certificat client déjà accepté par `rustls`.
/// Rend son nom courant.
pub async fn check_enroll_client_certificate(
    store: &dyn Store,
    der: &[u8],
    now: time::OffsetDateTime,
) -> Result<String, String> {
    let cert = Certificate::from_der(der).map_err(|e| format!("certificat illisible : {e}"))?;
    oe_conformance::check_enroll_client_certificate("certificat client", &cert)?;

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
    if stored.profile != oe_ca_core::profile::PROFILE_ENROLL_CLIENT {
        return Err(format!(
            "certificat émis sous le profil {:?}, pas {:?}",
            stored.profile,
            oe_ca_core::profile::PROFILE_ENROLL_CLIENT
        ));
    }
    if stored.der != der {
        return Err("le certificat présenté diffère de celui que la CA a émis".to_string());
    }
    match stored.status {
        CertificateStatus::Issued => Ok(common_name(&cert)),
        CertificateStatus::Revoked => Err("certificat révoqué".to_string()),
        CertificateStatus::Reserved => Err("certificat jamais émis".to_string()),
    }
}

/// Écoute TLS pour `axum::serve` : ne rend que des connexions dont le certificat
/// client a passé tous les contrôles, avec l'identité qu'il porte.
pub struct EnrollListener {
    local: SocketAddr,
    accepted: tokio::sync::mpsc::Receiver<(TlsStream<TcpStream>, EnrollPeer)>,
}

impl EnrollListener {
    pub fn new(tcp: TcpListener, config: ServerConfig, store: Arc<dyn Store>) -> EnrollListener {
        let local = tcp.local_addr().expect("adresse d'écoute");
        let acceptor = TlsAcceptor::from(Arc::new(config));
        let (tx, accepted) = tokio::sync::mpsc::channel(16);
        tokio::spawn(async move {
            loop {
                let (tcp, peer) = match tcp.accept().await {
                    Ok(c) => c,
                    Err(e) => {
                        tracing::warn!(erreur = %e, "accept() du port d'enrôlement");
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
                        Ok(Ok((tls, client_cn))) => {
                            let _ = tx
                                .send((
                                    tls,
                                    EnrollPeer {
                                        addr: peer,
                                        client_cn,
                                    },
                                ))
                                .await;
                        }
                        Ok(Err(reason)) => {
                            tracing::warn!(pair = %peer, %reason, "connexion d'enrôlement refusée");
                        }
                        Err(_) => {
                            tracing::warn!(pair = %peer, "enrôlement : poignée de main trop lente");
                        }
                    }
                });
            }
        });
        EnrollListener { local, accepted }
    }
}

async fn admit(
    acceptor: &TlsAcceptor,
    tcp: TcpStream,
    store: &dyn Store,
) -> Result<(TlsStream<TcpStream>, String), String> {
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
    let cn = check_enroll_client_certificate(store, &leaf, time::OffsetDateTime::now_utc()).await?;
    Ok((tls, cn))
}

impl axum::serve::Listener for EnrollListener {
    type Io = TlsStream<TcpStream>;
    type Addr = EnrollPeer;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        match self.accepted.recv().await {
            Some(c) => c,
            None => std::future::pending().await,
        }
    }

    fn local_addr(&self) -> std::io::Result<Self::Addr> {
        Ok(EnrollPeer {
            addr: self.local,
            client_cn: String::new(),
        })
    }
}

/// Permet à un handler d'extraire `ConnectInfo<EnrollPeer>` : l'identité du
/// certificat client, posée à l'acceptation de la connexion.
impl axum::extract::connect_info::Connected<axum::serve::IncomingStream<'_, EnrollListener>>
    for EnrollPeer
{
    fn connect_info(stream: axum::serve::IncomingStream<'_, EnrollListener>) -> Self {
        stream.remote_addr().clone()
    }
}
