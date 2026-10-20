//! Un serveur NTS complet en local, pour les tests de ce crate et ceux des
//! binaires qui l'emploient : NTS-KE en TLS 1.3 (certificat émis par une CA
//! de test fabriquée avec `openssl`) puis NTP authentifié en UDP, avec les
//! clés exportées de la même session TLS — même démarche
//! qu'`oe_hsm::testing::SoftwareToken`. Jamais utilisé par un service.

use std::io::{Read, Write};
use std::net::UdpSocket;
use std::process::Command;
use std::sync::Arc;

use time::{Duration, OffsetDateTime};

use crate::ntp;

/// Les clés (C2S, S2C) de chaque session négociée, partagées entre la
/// partie NTS-KE et le serveur NTP du test.
type SessionKeys = Arc<std::sync::Mutex<Vec<([u8; KEY_LEN], [u8; KEY_LEN])>>>;
use crate::nts::{
    authenticator, complete_records, extension_field, open_authenticator, record,
    AEAD_AES_SIV_CMAC_256, ALPN, CRITICAL, EF_NTS_AUTHENTICATOR, EF_NTS_COOKIE,
    EF_UNIQUE_IDENTIFIER, EXPORTER_LABEL, KEY_LEN, NEXT_PROTOCOL_NTPV4, REC_AEAD_ALGORITHM,
    REC_END_OF_MESSAGE, REC_NEW_COOKIE, REC_NEXT_PROTOCOL, REC_NTPV4_PORT,
};

/// Un serveur NTS complet en local : NTS-KE en TLS 1.3 (certificat émis
/// par une CA de test fabriquée avec openssl) puis NTP authentifié en
/// UDP, avec les clés exportées de la même session TLS. `tamper` fait
/// répondre le serveur avec un authentificateur forgé.
pub struct LocalNtsServer {
    pub ke_addr: String,
    pub roots: Arc<rustls::RootCertStore>,
    pub requests: Arc<std::sync::atomic::AtomicUsize>,
    /// Le certificat de la CA de test, en PEM : à donner comme ancre de
    /// confiance (`OPENEIDAS_TIME_NTS_CA_FILE`) à un service qui l'utilise.
    pub ca_pem: Vec<u8>,
}

/// Ce que le serveur de test sabote dans ses réponses.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Tamper {
    /// Réponses correctes.
    None,
    /// Authentificateur forgé sous une autre clé.
    Authenticator,
    /// Identifiant unique d'une autre requête, authentificateur valide.
    UniqueId,
}

pub fn local_nts_server(tamper: Tamper) -> LocalNtsServer {
    let dir = std::env::temp_dir().join(format!(
        "oe-nts-{}-{}",
        std::process::id(),
        rand::random::<u32>()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let run = |args: &[&str]| {
        let out = Command::new("openssl")
            .args(args)
            .current_dir(&dir)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
    };
    run(&[
        "req",
        "-x509",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-keyout",
        "ca.key",
        "-out",
        "ca.pem",
        "-subj",
        "/CN=Test NTS CA",
        "-days",
        "1",
        "-addext",
        "basicConstraints=critical,CA:TRUE",
    ]);
    run(&[
        "req",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-keyout",
        "srv.key",
        "-out",
        "srv.csr",
        "-subj",
        "/CN=localhost",
    ]);
    std::fs::write(
        dir.join("ext.cnf"),
        "subjectAltName=DNS:localhost,IP:127.0.0.1\n",
    )
    .unwrap();
    run(&[
        "x509",
        "-req",
        "-in",
        "srv.csr",
        "-CA",
        "ca.pem",
        "-CAkey",
        "ca.key",
        "-CAcreateserial",
        "-out",
        "srv.pem",
        "-days",
        "1",
        "-extfile",
        "ext.cnf",
    ]);
    let der = |name: &str| {
        pem::parse(std::fs::read(dir.join(name)).unwrap())
            .unwrap()
            .into_contents()
    };
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(rustls::pki_types::CertificateDer::from(der("ca.pem")))
        .unwrap();
    let chain = vec![rustls::pki_types::CertificateDer::from(der("srv.pem"))];
    let key = rustls::pki_types::PrivateKeyDer::Pkcs8(der("srv.key").into());
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .unwrap();
    config.alpn_protocols = vec![ALPN.to_vec()];
    let config = Arc::new(config);

    // Le serveur NTP authentifié : les clés de chaque session lui sont
    // transmises par la partie NTS-KE.
    let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
    let ntp_port = udp.local_addr().unwrap().port();
    let keys: SessionKeys = Default::default();
    let requests = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    {
        let keys = keys.clone();
        let requests = requests.clone();
        std::thread::spawn(move || {
            let mut buf = [0u8; 2048];
            while let Ok((n, peer)) = udp.recv_from(&mut buf) {
                let req = &buf[..n];
                requests.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                // Retrouve la session par essai de chaque clé C2S.
                let (auth_pos, body) = {
                    let mut pos = 48;
                    let mut found = None;
                    while pos + 4 <= req.len() {
                        let kind = u16::from_be_bytes([req[pos], req[pos + 1]]);
                        let len = u16::from_be_bytes([req[pos + 2], req[pos + 3]]) as usize;
                        if kind == EF_NTS_AUTHENTICATOR {
                            found = Some((pos, &req[pos + 4..pos + len]));
                            break;
                        }
                        pos += len;
                    }
                    found.expect("requête sans authentificateur")
                };
                let session = keys
                    .lock()
                    .unwrap()
                    .iter()
                    .find(|(c2s, _)| open_authenticator(c2s, &req[..auth_pos], body).is_ok())
                    .copied()
                    .expect("aucune session ne vérifie la requête");
                let unique_id = {
                    let mut pos = 48;
                    let mut id = None;
                    while pos + 4 <= req.len() {
                        let kind = u16::from_be_bytes([req[pos], req[pos + 1]]);
                        let len = u16::from_be_bytes([req[pos + 2], req[pos + 3]]) as usize;
                        if kind == EF_UNIQUE_IDENTIFIER {
                            id = Some(req[pos + 4..pos + len].to_vec());
                        }
                        pos += len;
                    }
                    id.unwrap()
                };
                let mut request48 = [0u8; 48];
                request48.copy_from_slice(&req[..48]);
                let mut reply =
                    ntp::server_reply(&request48, OffsetDateTime::now_utc(), Duration::ZERO)
                        .to_vec();
                reply[1] = 1;
                let echoed = if tamper == Tamper::UniqueId {
                    rand::random::<[u8; 32]>().to_vec()
                } else {
                    unique_id
                };
                reply.extend(extension_field(EF_UNIQUE_IDENTIFIER, &echoed));
                let fresh: Vec<u8> = [
                    extension_field(EF_NTS_COOKIE, &rand::random::<[u8; 32]>()),
                    extension_field(EF_NTS_COOKIE, &rand::random::<[u8; 32]>()),
                ]
                .concat();
                let s2c = if tamper == Tamper::Authenticator {
                    rand::random::<[u8; KEY_LEN]>()
                } else {
                    session.1
                };
                let auth = authenticator(&s2c, &rand::random(), &reply, &fresh).unwrap();
                reply.extend(auth);
                udp.send_to(&reply, peer).unwrap();
            }
        });
    }

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let ke_addr = listener.local_addr().unwrap().to_string();
    std::thread::spawn(move || {
        for tcp in listener.incoming().flatten() {
            let mut tcp = tcp;
            let mut conn = rustls::ServerConnection::new(config.clone()).unwrap();
            let mut tls = rustls::Stream::new(&mut conn, &mut tcp);
            let mut buf = Vec::new();
            let mut chunk = [0u8; 1024];
            // Un client qui refuse le certificat (test) fait échouer la lecture :
            // on passe au suivant plutôt que de paniquer.
            let mut failed = false;
            loop {
                let Ok(n) = tls.read(&mut chunk) else {
                    failed = true;
                    break;
                };
                buf.extend_from_slice(&chunk[..n]);
                if complete_records(&buf).ok().flatten().is_some() || n == 0 {
                    break;
                }
            }
            if failed {
                continue;
            }
            // Les clés de la session sont publiées au serveur NTP *avant* de
            // répondre au client : sinon sa première requête UDP peut arriver
            // avant elles et rester sans réponse.
            let export = |conn: &rustls::ServerConnection, direction: u8| {
                let context = [0, 0, 0, AEAD_AES_SIV_CMAC_256 as u8, direction];
                conn.export_keying_material([0u8; KEY_LEN], EXPORTER_LABEL, Some(&context))
                    .unwrap()
            };
            keys.lock()
                .unwrap()
                .push((export(tls.conn, 0), export(tls.conn, 1)));
            let mut response = vec![
                record(
                    REC_NEXT_PROTOCOL | CRITICAL,
                    &NEXT_PROTOCOL_NTPV4.to_be_bytes(),
                ),
                record(REC_AEAD_ALGORITHM, &AEAD_AES_SIV_CMAC_256.to_be_bytes()),
                record(REC_NTPV4_PORT, &ntp_port.to_be_bytes()),
            ];
            for _ in 0..3 {
                response.push(record(REC_NEW_COOKIE, &rand::random::<[u8; 32]>()));
            }
            response.push(record(REC_END_OF_MESSAGE | CRITICAL, &[]));
            let _ = tls.write_all(&response.concat());
            let _ = tls.flush();
            tls.conn.send_close_notify();
            let _ = tls.flush();
        }
    });
    let ca_pem = std::fs::read(dir.join("ca.pem")).unwrap();
    LocalNtsServer {
        ke_addr,
        roots: Arc::new(roots),
        requests,
        ca_pem,
    }
}
