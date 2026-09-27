//! Client SNTP minimal (RFC 4330 / RFC 5905, mode client, sans authentification).
//!
//! Le plan de migration recommande d'écrire ce client plutôt que d'aligner une
//! dépendance tierce sur les exigences ETSI EN 319 421 §7.7.2 : le protocole
//! côté client est simple (une requête, une réponse, 48 octets), et l'écrire
//! ici réduit la surface de confiance et le rend directement auditable.

use std::net::UdpSocket;
use std::time::Duration as StdDuration;

use time::{Duration, OffsetDateTime};

/// Secondes entre l'epoch NTP (1900-01-01) et l'epoch Unix (1970-01-01).
const NTP_UNIX_EPOCH_OFFSET: i64 = 2_208_988_800;

#[derive(Debug, Clone, Copy)]
pub struct NtpSample {
    /// Écart entre l'horloge locale et la source, signé (positif = horloge
    /// locale en avance).
    pub offset: Duration,
    pub rtt: Duration,
    pub stratum: u8,
}

#[derive(Debug, thiserror::Error)]
pub enum NtpError {
    #[error("erreur réseau: {0}")]
    Io(#[from] std::io::Error),
    #[error("réponse NTP invalide: {0}")]
    InvalidResponse(&'static str),
    #[error("stratum non synchronisé (kiss-o'-death, stratum 0)")]
    Unsynchronized,
}

/// Interroge un serveur NTP et retourne l'écart d'horloge mesuré. `server`
/// peut être un nom d'hôte seul (port 123 par défaut) ou `hôte:port`.
pub fn query(server: &str, timeout: StdDuration) -> Result<NtpSample, NtpError> {
    let addr = if server.contains(':') {
        server.to_string()
    } else {
        format!("{server}:123")
    };

    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.set_read_timeout(Some(timeout))?;
    socket.set_write_timeout(Some(timeout))?;
    socket.connect(&addr)?;

    let mut packet = [0u8; 48];
    packet[0] = 0b00_100_011; // LI=0 (no warning), VN=4, Mode=3 (client)
    let t1 = OffsetDateTime::now_utc();
    write_ntp_timestamp(&mut packet[40..48], t1);

    socket.send(&packet)?;
    let mut buf = [0u8; 48];
    let n = socket.recv(&mut buf)?;
    let t4 = OffsetDateTime::now_utc();
    if n < 48 {
        return Err(NtpError::InvalidResponse("réponse tronquée (< 48 octets)"));
    }

    let stratum = buf[1];
    if stratum == 0 {
        return Err(NtpError::Unsynchronized);
    }
    let mode = buf[0] & 0b0000_0111;
    if mode != 4 {
        return Err(NtpError::InvalidResponse(
            "mode de réponse inattendu (attendu 4, serveur)",
        ));
    }

    let t2 = read_ntp_timestamp(&buf[32..40]);
    let t3 = read_ntp_timestamp(&buf[40..48]);

    // Formules RFC 5905 §8 : offset = ((T2-T1)+(T3-T4))/2, délai = (T4-T1)-(T3-T2).
    let offset = ((t2 - t1) + (t3 - t4)) / 2;
    let rtt = (t4 - t1) - (t3 - t2);

    Ok(NtpSample {
        offset,
        rtt,
        stratum,
    })
}

fn write_ntp_timestamp(buf: &mut [u8], t: OffsetDateTime) {
    let seconds = (t.unix_timestamp() + NTP_UNIX_EPOCH_OFFSET) as u32;
    let frac = ((t.nanosecond() as u64) << 32) / 1_000_000_000;
    buf[0..4].copy_from_slice(&seconds.to_be_bytes());
    buf[4..8].copy_from_slice(&(frac as u32).to_be_bytes());
}

fn read_ntp_timestamp(buf: &[u8]) -> OffsetDateTime {
    let seconds = u32::from_be_bytes(buf[0..4].try_into().unwrap()) as i64 - NTP_UNIX_EPOCH_OFFSET;
    let frac = u32::from_be_bytes(buf[4..8].try_into().unwrap()) as u64;
    let nanos = (frac * 1_000_000_000) >> 32;
    OffsetDateTime::from_unix_timestamp(seconds).unwrap_or(OffsetDateTime::UNIX_EPOCH)
        + Duration::nanoseconds(nanos as i64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ntp_timestamp_round_trips() {
        let t = OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap()
            + Duration::nanoseconds(123_456_789);
        let mut buf = [0u8; 8];
        write_ntp_timestamp(&mut buf, t);
        let back = read_ntp_timestamp(&buf);
        // La précision NTP (fraction sur 32 bits) est d'environ 233 picosecondes ;
        // la marge ci-dessous couvre l'arrondi de conversion.
        assert!((back - t).abs() < Duration::microseconds(1));
    }

    #[test]
    #[ignore = "nécessite un accès réseau UDP/123 sortant vers un serveur NTP public"]
    fn queries_a_real_public_ntp_server() {
        let sample = query("pool.ntp.org", StdDuration::from_secs(5)).expect("requête NTP");
        assert!(sample.stratum > 0);
        assert!(
            sample.offset.abs() < Duration::seconds(10),
            "écart déraisonnable: {:?}",
            sample.offset
        );
    }
}
