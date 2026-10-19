//! Network Time Security (RFC 8915) : authentification des mesures NTP
//! (constat T-2 de l'audit du 2026-09-25, EN 319 421 `TIS-7.7.2-04`,
//! `TIS-7.7.2-05`), tranche T-c.
//!
//! Deux phases. **NTS-KE** : une session TLS 1.3 (ALPN `ntske/1`, port 4460)
//! avec le laboratoire, dans laquelle les deux parties négocient NTPv4 et
//! l'AEAD `AES-SIV-CMAC-256`, le serveur remet des *cookies* opaques, et les
//! clés C2S/S2C sont dérivées par l'exportateur TLS (RFC 5705) : jamais
//! transmises. **NTP authentifié** : chaque requête porte un identifiant
//! unique aléatoire, un cookie, et un champ d'authentification AES-SIV qui
//! couvre tout le paquet ; la réponse doit reprendre l'identifiant et être
//! authentifiée avec la clé S2C, sans quoi elle est écartée — un attaquant en
//! chemin ne peut plus ni forger ni modifier une réponse. Chaque réponse
//! rend de nouveaux cookies (chiffrés) ; à court de cookies, la session se
//! renégocie.
//!
//! Écrit dans le dépôt, comme le client SNTP, pour rester auditable : le
//! protocole côté client tient en quelques centaines de lignes et ne demande
//! que TLS (`rustls`) et l'AEAD (`aes-siv`).

use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs, UdpSocket};
use std::sync::Arc;
use std::time::Duration as StdDuration;

use aes_siv::aead::{Aead, KeyInit, Payload};
use aes_siv::Aes128SivAead;
use time::{Duration, OffsetDateTime};

use crate::ntp::{self, NtpError, NtpSample};

/// Port TCP de NTS-KE (RFC 8915 §4).
pub const NTS_KE_PORT: u16 = 4460;
pub(crate) const ALPN: &[u8] = b"ntske/1";
pub(crate) const EXPORTER_LABEL: &[u8] = b"EXPORTER-network-time-security";
/// Identifiant IANA d'`AEAD_AES_SIV_CMAC_256` (RFC 8915 §4.1.5).
pub(crate) const AEAD_AES_SIV_CMAC_256: u16 = 15;
pub(crate) const NEXT_PROTOCOL_NTPV4: u16 = 0;
/// Taille de clé d'`AEAD_AES_SIV_CMAC_256` (RFC 5297).
pub(crate) const KEY_LEN: usize = 32;
const NONCE_LEN: usize = 16;
/// Cookies gardés en réserve : à chaque requête, on en consomme un et on
/// demande au serveur de quoi revenir à ce nombre (RFC 8915 §5.7).
const COOKIE_TARGET: usize = 8;
/// Taille maximale d'une réponse NTS-KE acceptée.
const MAX_KE_BYTES: usize = 64 * 1024;

// Types d'enregistrement NTS-KE (RFC 8915 §4.1), bit « critique » à part.
pub(crate) const REC_END_OF_MESSAGE: u16 = 0;
pub(crate) const REC_NEXT_PROTOCOL: u16 = 1;
const REC_ERROR: u16 = 2;
const REC_WARNING: u16 = 3;
pub(crate) const REC_AEAD_ALGORITHM: u16 = 4;
pub(crate) const REC_NEW_COOKIE: u16 = 5;
const REC_NTPV4_SERVER: u16 = 6;
pub(crate) const REC_NTPV4_PORT: u16 = 7;
pub(crate) const CRITICAL: u16 = 0x8000;

// Champs d'extension NTP (RFC 8915 §5.3 à §5.6).
pub(crate) const EF_UNIQUE_IDENTIFIER: u16 = 0x0104;
pub(crate) const EF_NTS_COOKIE: u16 = 0x0204;
const EF_NTS_COOKIE_PLACEHOLDER: u16 = 0x0304;
pub(crate) const EF_NTS_AUTHENTICATOR: u16 = 0x0404;

#[derive(Debug, thiserror::Error)]
pub enum NtsError {
    #[error("NTS-KE: {0}")]
    Io(#[from] std::io::Error),
    #[error("NTS-KE: TLS: {0}")]
    Tls(#[from] rustls::Error),
    #[error("NTS-KE: nom de serveur invalide: {0}")]
    ServerName(String),
    #[error("NTS-KE: le serveur a répondu par une erreur (code {0})")]
    ServerError(u16),
    #[error("NTS-KE: réponse invalide: {0}")]
    InvalidKeyExchange(&'static str),
    #[error("NTS: {0}")]
    Ntp(#[from] NtpError),
    #[error("NTS: réponse non authentifiée: {0}")]
    Unauthenticated(&'static str),
    #[error("NTS: plus aucun cookie : renégociation nécessaire")]
    NoCookie,
}

/// Une session NTS établie : où joindre le serveur NTP, les clés dérivées
/// et les cookies restants.
pub struct Session {
    /// `hôte:port` du serveur NTP désigné par NTS-KE.
    pub ntp_server: String,
    c2s: [u8; KEY_LEN],
    s2c: [u8; KEY_LEN],
    cookies: Vec<Vec<u8>>,
}

impl Session {
    pub fn cookies_left(&self) -> usize {
        self.cookies.len()
    }
}

/// Sans les clés ni les cookies : rien de secret dans une trace.
impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session")
            .field("ntp_server", &self.ntp_server)
            .field("cookies", &self.cookies.len())
            .finish_non_exhaustive()
    }
}

/// Un identifiant de source NTS : `nts://hôte[:port]`, port 4460 par défaut.
pub fn parse_source(server: &str) -> Option<(String, u16)> {
    let rest = server.strip_prefix("nts://")?;
    let rest = rest.trim_end_matches('/');
    match rest.rsplit_once(':') {
        Some((host, port)) if !host.is_empty() => port.parse().ok().map(|p| (host.to_string(), p)),
        _ if !rest.is_empty() => Some((rest.to_string(), NTS_KE_PORT)),
        _ => None,
    }
}

/// Phase NTS-KE : négocie une session avec `host:port` en TLS 1.3 et en
/// dérive les clés. `roots` sont les ancres de confiance du certificat du
/// serveur.
pub fn key_exchange(
    host: &str,
    port: u16,
    roots: Arc<rustls::RootCertStore>,
    timeout: StdDuration,
) -> Result<Session, NtsError> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![ALPN.to_vec()];
    let server_name = rustls::pki_types::ServerName::try_from(host.to_string())
        .map_err(|e| NtsError::ServerName(e.to_string()))?;
    let mut conn = rustls::ClientConnection::new(Arc::new(config), server_name)?;

    let addr = (host, port)
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "adresse introuvable"))?;
    let mut tcp = TcpStream::connect_timeout(&addr, timeout)?;
    tcp.set_read_timeout(Some(timeout))?;
    tcp.set_write_timeout(Some(timeout))?;

    let request = [
        record(
            REC_NEXT_PROTOCOL | CRITICAL,
            &NEXT_PROTOCOL_NTPV4.to_be_bytes(),
        ),
        record(
            REC_AEAD_ALGORITHM | CRITICAL,
            &AEAD_AES_SIV_CMAC_256.to_be_bytes(),
        ),
        record(REC_END_OF_MESSAGE | CRITICAL, &[]),
    ]
    .concat();
    let mut tls = rustls::Stream::new(&mut conn, &mut tcp);
    tls.write_all(&request)?;
    tls.flush()?;

    let mut response = Vec::new();
    let mut chunk = [0u8; 4096];
    let records = loop {
        match tls.read(&mut chunk) {
            Ok(0) => break parse_records(&response)?,
            Ok(n) => {
                response.extend_from_slice(&chunk[..n]);
                if response.len() > MAX_KE_BYTES {
                    return Err(NtsError::InvalidKeyExchange("réponse trop volumineuse"));
                }
                if let Some(records) = complete_records(&response)? {
                    break records;
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                break parse_records(&response)?
            }
            Err(e) => return Err(e.into()),
        }
    };
    if conn.alpn_protocol() != Some(ALPN) {
        return Err(NtsError::InvalidKeyExchange("ALPN ntske/1 non négocié"));
    }

    let mut ntp_host = host.to_string();
    let mut ntp_port = 123u16;
    let mut cookies = Vec::new();
    let mut next_protocol_ok = false;
    let mut aead_ok = false;
    for (kind, critical, body) in records {
        match kind {
            REC_ERROR => {
                let code = body
                    .get(0..2)
                    .map(|b| u16::from_be_bytes([b[0], b[1]]))
                    .unwrap_or(0);
                return Err(NtsError::ServerError(code));
            }
            REC_WARNING => {}
            REC_NEXT_PROTOCOL => {
                next_protocol_ok = body
                    .chunks_exact(2)
                    .any(|c| u16::from_be_bytes([c[0], c[1]]) == NEXT_PROTOCOL_NTPV4);
            }
            REC_AEAD_ALGORITHM => {
                aead_ok = body.len() == 2
                    && u16::from_be_bytes([body[0], body[1]]) == AEAD_AES_SIV_CMAC_256;
            }
            REC_NEW_COOKIE => cookies.push(body.to_vec()),
            REC_NTPV4_SERVER => {
                ntp_host = String::from_utf8(body.to_vec())
                    .map_err(|_| NtsError::InvalidKeyExchange("nom de serveur NTP illisible"))?;
            }
            REC_NTPV4_PORT => {
                if body.len() != 2 {
                    return Err(NtsError::InvalidKeyExchange("port NTP mal formé"));
                }
                ntp_port = u16::from_be_bytes([body[0], body[1]]);
            }
            REC_END_OF_MESSAGE => break,
            _ if critical => {
                return Err(NtsError::InvalidKeyExchange(
                    "enregistrement critique inconnu",
                ))
            }
            _ => {}
        }
    }
    if !next_protocol_ok {
        return Err(NtsError::InvalidKeyExchange("NTPv4 non négocié"));
    }
    if !aead_ok {
        return Err(NtsError::InvalidKeyExchange(
            "AEAD_AES_SIV_CMAC_256 non négocié",
        ));
    }
    if cookies.is_empty() {
        return Err(NtsError::InvalidKeyExchange("aucun cookie remis"));
    }

    let c2s = export_key(&conn, 0x00)?;
    let s2c = export_key(&conn, 0x01)?;
    Ok(Session {
        ntp_server: format!("{ntp_host}:{ntp_port}"),
        c2s,
        s2c,
        cookies,
    })
}

/// Clé C2S (`0x00`) ou S2C (`0x01`) par l'exportateur TLS (RFC 8915 §4.3 :
/// contexte = protocole suivant, AEAD, sens).
fn export_key(conn: &rustls::ClientConnection, direction: u8) -> Result<[u8; KEY_LEN], NtsError> {
    let context = [0x00, 0x00, 0x00, AEAD_AES_SIV_CMAC_256 as u8, direction];
    let key = conn.export_keying_material([0u8; KEY_LEN], EXPORTER_LABEL, Some(&context))?;
    Ok(key)
}

pub(crate) fn record(kind: u16, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + body.len());
    out.extend_from_slice(&kind.to_be_bytes());
    out.extend_from_slice(&(body.len() as u16).to_be_bytes());
    out.extend_from_slice(body);
    out
}

type Record<'a> = (u16, bool, &'a [u8]);

/// Les enregistrements d'une réponse complète (jusqu'à « fin de message »),
/// ou `None` s'il en manque encore.
pub(crate) fn complete_records(buf: &[u8]) -> Result<Option<Vec<Record<'_>>>, NtsError> {
    let mut records = Vec::new();
    let mut pos = 0;
    while pos + 4 <= buf.len() {
        let kind = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
        let len = u16::from_be_bytes([buf[pos + 2], buf[pos + 3]]) as usize;
        if pos + 4 + len > buf.len() {
            return Ok(None);
        }
        let body = &buf[pos + 4..pos + 4 + len];
        records.push((kind & !CRITICAL, kind & CRITICAL != 0, body));
        pos += 4 + len;
        if kind & !CRITICAL == REC_END_OF_MESSAGE {
            return Ok(Some(records));
        }
    }
    Ok(None)
}

fn parse_records(buf: &[u8]) -> Result<Vec<Record<'_>>, NtsError> {
    complete_records(buf)?.ok_or(NtsError::InvalidKeyExchange(
        "réponse tronquée (pas de fin de message)",
    ))
}

/// Une mesure authentifiée : consomme un cookie, redemande de quoi revenir
/// à la réserve, et n'accepte la réponse que si elle reprend l'identifiant
/// unique et porte un authentificateur valide sous la clé S2C.
pub fn query(
    session: &mut Session,
    timeout: StdDuration,
    max_rtt: Duration,
) -> Result<NtpSample, NtsError> {
    let cookie = session.cookies.pop().ok_or(NtsError::NoCookie)?;
    let placeholders = COOKIE_TARGET.saturating_sub(session.cookies.len() + 1);

    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.set_read_timeout(Some(timeout))?;
    socket.set_write_timeout(Some(timeout))?;
    socket.connect(&session.ntp_server)?;

    let t1 = OffsetDateTime::now_utc();
    let header = ntp::build_request(t1);
    let unique_id: [u8; 32] = rand::random();
    let mut packet = header.to_vec();
    packet.extend(extension_field(EF_UNIQUE_IDENTIFIER, &unique_id));
    packet.extend(extension_field(EF_NTS_COOKIE, &cookie));
    for _ in 0..placeholders {
        packet.extend(extension_field(
            EF_NTS_COOKIE_PLACEHOLDER,
            &vec![0u8; cookie.len()],
        ));
    }
    let nonce: [u8; NONCE_LEN] = rand::random();
    let auth = authenticator(&session.c2s, &nonce, &packet, &[])?;
    packet.extend(auth);

    socket.send(&packet)?;
    let mut buf = [0u8; 2048];
    let n = socket.recv(&mut buf)?;
    let t4 = OffsetDateTime::now_utc();
    let reply = &buf[..n];

    let sample = ntp::parse_response(&header, reply, t1, t4, max_rtt)?;

    let mut id_echoed = false;
    let mut new_cookies = None;
    let mut pos = 48;
    while pos + 4 <= reply.len() {
        let kind = u16::from_be_bytes([reply[pos], reply[pos + 1]]);
        let len = u16::from_be_bytes([reply[pos + 2], reply[pos + 3]]) as usize;
        if len < 4 || !len.is_multiple_of(4) || pos + len > reply.len() {
            return Err(NtsError::Unauthenticated("champ d'extension mal formé"));
        }
        let body = &reply[pos + 4..pos + len];
        match kind {
            EF_UNIQUE_IDENTIFIER => id_echoed = body == unique_id,
            EF_NTS_AUTHENTICATOR => {
                let plaintext = open_authenticator(&session.s2c, &reply[..pos], body)?;
                new_cookies = Some(inner_cookies(&plaintext)?);
                // Rien de ce qui suit l'authentificateur n'est couvert par lui.
                break;
            }
            _ => {}
        }
        pos += len;
    }
    if !id_echoed {
        return Err(NtsError::Unauthenticated(
            "identifiant unique absent ou différent",
        ));
    }
    let Some(new_cookies) = new_cookies else {
        return Err(NtsError::Unauthenticated("authentificateur absent"));
    };
    session.cookies.extend(new_cookies);
    Ok(sample)
}

/// Encode un champ d'extension (RFC 7822) : type, longueur totale, corps
/// complété à un multiple de 4 octets.
pub(crate) fn extension_field(kind: u16, body: &[u8]) -> Vec<u8> {
    let padded = (body.len() + 3) & !3;
    let mut out = Vec::with_capacity(4 + padded);
    out.extend_from_slice(&kind.to_be_bytes());
    out.extend_from_slice(&((4 + padded) as u16).to_be_bytes());
    out.extend_from_slice(body);
    out.resize(4 + padded, 0);
    out
}

/// Le champ « NTS Authenticator and Encrypted Extension Fields » (RFC 8915
/// §5.6) : `aad` est le paquet jusqu'ici, `plaintext` les champs à chiffrer.
pub(crate) fn authenticator(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, NtsError> {
    let cipher = Aes128SivAead::new(key.into());
    let ciphertext = cipher
        .encrypt(
            nonce.into(),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| NtsError::Unauthenticated("chiffrement impossible"))?;
    let mut body = Vec::with_capacity(4 + NONCE_LEN + ciphertext.len() + 3);
    body.extend_from_slice(&(NONCE_LEN as u16).to_be_bytes());
    body.extend_from_slice(&(ciphertext.len() as u16).to_be_bytes());
    body.extend_from_slice(nonce);
    body.extend_from_slice(&ciphertext);
    Ok(extension_field(EF_NTS_AUTHENTICATOR, &body))
}

/// Vérifie et déchiffre un authentificateur reçu : `aad` est le paquet
/// jusqu'au champ, `body` le corps du champ.
pub(crate) fn open_authenticator(
    key: &[u8; KEY_LEN],
    aad: &[u8],
    body: &[u8],
) -> Result<Vec<u8>, NtsError> {
    if body.len() < 4 {
        return Err(NtsError::Unauthenticated("authentificateur tronqué"));
    }
    let nonce_len = u16::from_be_bytes([body[0], body[1]]) as usize;
    let ct_len = u16::from_be_bytes([body[2], body[3]]) as usize;
    let nonce_padded = (nonce_len + 3) & !3;
    if nonce_len != NONCE_LEN || body.len() < 4 + nonce_padded + ct_len {
        return Err(NtsError::Unauthenticated("authentificateur mal formé"));
    }
    let nonce = &body[4..4 + nonce_len];
    let ciphertext = &body[4 + nonce_padded..4 + nonce_padded + ct_len];
    let cipher = Aes128SivAead::new(key.into());
    cipher
        .decrypt(
            nonce.into(),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| NtsError::Unauthenticated("authentificateur invalide"))
}

/// Les cookies portés par les champs d'extension déchiffrés.
fn inner_cookies(plaintext: &[u8]) -> Result<Vec<Vec<u8>>, NtsError> {
    let mut cookies = Vec::new();
    let mut pos = 0;
    while pos + 4 <= plaintext.len() {
        let kind = u16::from_be_bytes([plaintext[pos], plaintext[pos + 1]]);
        let len = u16::from_be_bytes([plaintext[pos + 2], plaintext[pos + 3]]) as usize;
        if len < 4 || pos + len > plaintext.len() {
            return Err(NtsError::Unauthenticated("champ chiffré mal formé"));
        }
        if kind == EF_NTS_COOKIE {
            cookies.push(plaintext[pos + 4..pos + len].to_vec());
        }
        pos += len;
    }
    Ok(cookies)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{local_nts_server, Tamper};

    #[test]
    fn parses_nts_sources() {
        assert_eq!(
            parse_source("nts://ptbtime1.ptb.de"),
            Some(("ptbtime1.ptb.de".into(), 4460))
        );
        assert_eq!(
            parse_source("nts://localhost:4461/"),
            Some(("localhost".into(), 4461))
        );
        assert_eq!(parse_source("ptbtime1.ptb.de"), None);
        assert_eq!(parse_source("nts://"), None);
    }

    #[test]
    fn records_round_trip_and_stop_at_end_of_message() {
        let bytes = [
            record(REC_NEXT_PROTOCOL | CRITICAL, &[0, 0]),
            record(REC_NEW_COOKIE, &[9; 5]),
            record(REC_END_OF_MESSAGE | CRITICAL, &[]),
            record(REC_NEW_COOKIE, &[1; 3]), // au-delà de la fin : ignoré
        ]
        .concat();
        let records = complete_records(&bytes).unwrap().unwrap();
        assert_eq!(records.len(), 3);
        assert_eq!(records[0], (REC_NEXT_PROTOCOL, true, &[0u8, 0][..]));
        assert_eq!(records[1], (REC_NEW_COOKIE, false, &[9u8; 5][..]));
        assert!(complete_records(&bytes[..7]).unwrap().is_none());
    }

    /// L'authentificateur se vérifie avec la même clé sur le même paquet, et
    /// avec rien d'autre : une autre clé, un paquet modifié ou un nonce
    /// modifié sont refusés.
    #[test]
    fn the_authenticator_binds_key_packet_and_nonce() {
        let key = [7u8; KEY_LEN];
        let nonce = [3u8; NONCE_LEN];
        let packet = extension_field(EF_UNIQUE_IDENTIFIER, &[1u8; 32]);
        let ef = authenticator(
            &key,
            &nonce,
            &packet,
            &extension_field(EF_NTS_COOKIE, &[5u8; 8]),
        )
        .unwrap();
        let body = &ef[4..];
        let plaintext = open_authenticator(&key, &packet, body).unwrap();
        assert_eq!(inner_cookies(&plaintext).unwrap(), vec![vec![5u8; 8]]);

        assert!(open_authenticator(&[8u8; KEY_LEN], &packet, body).is_err());
        let mut tampered = packet.clone();
        tampered[10] ^= 1;
        assert!(open_authenticator(&key, &tampered, body).is_err());
        let mut bad_nonce = body.to_vec();
        bad_nonce[4] ^= 1;
        assert!(open_authenticator(&key, &packet, &bad_nonce).is_err());
    }

    /// Phase NTS-KE puis mesures authentifiées : la session rend des
    /// mesures tant qu'elle a des cookies, chaque réponse en rapporte, et
    /// les clés viennent bien de l'exportateur TLS (sinon le serveur, qui
    /// vérifie la requête, ne répondrait pas).
    #[test]
    fn key_exchange_then_authenticated_measurements_replenish_cookies() {
        let server = local_nts_server(Tamper::None);
        let (host, port) = server.ke_addr.rsplit_once(':').unwrap();
        let mut session = key_exchange(
            host,
            port.parse().unwrap(),
            server.roots.clone(),
            StdDuration::from_secs(5),
        )
        .unwrap();
        assert_eq!(session.cookies_left(), 3);
        for _ in 0..5 {
            let sample = query(&mut session, StdDuration::from_secs(2), Duration::SECOND).unwrap();
            assert_eq!(sample.stratum, 1);
            assert!(
                sample.offset.abs() < Duration::SECOND,
                "{:?}",
                sample.offset
            );
        }
        // Chaque réponse rapporte deux cookies pour un consommé.
        assert_eq!(session.cookies_left(), 3 + 5);
        assert_eq!(server.requests.load(std::sync::atomic::Ordering::SeqCst), 5);
    }

    /// Une réponse dont l'authentificateur ne vérifie pas sous la clé S2C
    /// — forgée, ou modifiée en chemin — n'est pas une mesure.
    #[test]
    fn a_reply_with_a_forged_authenticator_is_refused() {
        let server = local_nts_server(Tamper::Authenticator);
        let (host, port) = server.ke_addr.rsplit_once(':').unwrap();
        let mut session = key_exchange(
            host,
            port.parse().unwrap(),
            server.roots.clone(),
            StdDuration::from_secs(5),
        )
        .unwrap();
        let err = query(&mut session, StdDuration::from_secs(2), Duration::SECOND).unwrap_err();
        assert!(matches!(err, NtsError::Unauthenticated(_)), "{err}");
    }

    /// Une réponse authentifiée mais qui ne reprend pas l'identifiant unique
    /// de la requête répond à une autre requête : refusée aussi.
    #[test]
    fn an_authenticated_reply_to_another_request_is_refused() {
        let server = local_nts_server(Tamper::UniqueId);
        let (host, port) = server.ke_addr.rsplit_once(':').unwrap();
        let mut session = key_exchange(
            host,
            port.parse().unwrap(),
            server.roots.clone(),
            StdDuration::from_secs(5),
        )
        .unwrap();
        let err = query(&mut session, StdDuration::from_secs(2), Duration::SECOND).unwrap_err();
        assert!(err.to_string().contains("identifiant unique"), "{err}");
    }

    /// Sans ancre de confiance pour le certificat du serveur, pas de session.
    #[test]
    fn key_exchange_refuses_an_untrusted_server() {
        let server = local_nts_server(Tamper::None);
        let (host, port) = server.ke_addr.rsplit_once(':').unwrap();
        let err = key_exchange(
            host,
            port.parse().unwrap(),
            Arc::new(rustls::RootCertStore::empty()),
            StdDuration::from_secs(5),
        )
        .unwrap_err();
        assert!(matches!(err, NtsError::Tls(_) | NtsError::Io(_)), "{err}");
    }
}
