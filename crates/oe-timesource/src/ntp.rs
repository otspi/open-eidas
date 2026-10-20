//! Client SNTP minimal (RFC 4330 / RFC 5905, mode client, sans authentification).
//!
//! Le plan de migration recommande d'écrire ce client plutôt que d'aligner une
//! dépendance tierce sur les exigences ETSI EN 319 421 §7.7.2 : le protocole
//! côté client est simple (une requête, une réponse, 48 octets), et l'écrire
//! ici réduit la surface de confiance et le rend directement auditable.
//!
//! Constat T-2 de l'audit du 2026-09-25 (EN 319 421 `TIS-7.7.2-04`,
//! `TIS-7.7.2-05`) : une réponse n'est acceptée que si elle répond bien à la
//! requête envoyée — son *originate timestamp* doit reprendre, octet pour
//! octet, le *transmit timestamp* de la requête, dont les bits de poids
//! faible sont tirés au hasard (RFC 5905 §8 : « the client … should use a
//! random value for the low-order bits ») — et si elle est saine : version
//! 3 ou 4, mode serveur, indicateur de saut ≠ 3 (horloge non synchronisée),
//! strate 1 à 15, *transmit* non nul, aller-retour sous un seuil (au-delà,
//! l'écart mesuré ne vaut rien). Un attaquant hors chemin ne peut plus faire
//! passer une réponse forgée ; en chemin, seul NTS (RFC 8915) y pourvoit.

use std::net::UdpSocket;
use std::time::Duration as StdDuration;

use time::{Duration, OffsetDateTime};

/// Secondes entre l'epoch NTP (1900-01-01) et l'epoch Unix (1970-01-01).
const NTP_UNIX_EPOCH_OFFSET: i64 = 2_208_988_800;

/// Strate maximale d'une source utilisable (RFC 5905 §7.3 : 16 = non
/// synchronisée).
const MAX_STRATUM: u8 = 15;

#[derive(Debug, Clone, Copy)]
pub struct NtpSample {
    /// Écart entre l'horloge locale et la source, signé (positif = horloge
    /// locale en avance).
    pub offset: Duration,
    pub rtt: Duration,
    pub stratum: u8,
    /// Indicateur de saut (RFC 5905 §7.3) : 0 = aucun, 1 = une seconde
    /// ajoutée en fin de jour, 2 = une seconde retirée. Jamais 3 ici : une
    /// telle réponse est refusée.
    pub leap: u8,
}

#[derive(Debug, thiserror::Error)]
pub enum NtpError {
    #[error("erreur réseau: {0}")]
    Io(#[from] std::io::Error),
    #[error("réponse NTP invalide: {0}")]
    InvalidResponse(&'static str),
    #[error("source non synchronisée: {0}")]
    Unsynchronized(&'static str),
    #[error("aller-retour de {rtt:?} au-delà du seuil de {max:?}")]
    RoundTripTooLong { rtt: Duration, max: Duration },
}

/// Interroge un serveur NTP et retourne l'écart d'horloge mesuré. `server`
/// peut être un nom d'hôte seul (port 123 par défaut) ou `hôte:port`.
pub fn query(server: &str, timeout: StdDuration, max_rtt: Duration) -> Result<NtpSample, NtpError> {
    let addr = if server.contains(':') {
        server.to_string()
    } else {
        format!("{server}:123")
    };

    // Port source éphémère, tiré par le système : avec le *transmit*
    // aléatoire, c'est ce qu'un attaquant hors chemin devrait deviner.
    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.set_read_timeout(Some(timeout))?;
    socket.set_write_timeout(Some(timeout))?;
    socket.connect(&addr)?;

    let t1 = OffsetDateTime::now_utc();
    let packet = build_request(t1);
    socket.send(&packet)?;

    let mut buf = [0u8; 48];
    let n = socket.recv(&mut buf)?;
    let t4 = OffsetDateTime::now_utc();
    parse_response(&packet, &buf[..n], t1, t4, max_rtt)
}

/// La requête : LI = 0, version 4, mode client, *transmit* = `t1` dont les
/// bits de poids faible de la fraction sont aléatoires.
fn build_request(t1: OffsetDateTime) -> [u8; 48] {
    let mut packet = [0u8; 48];
    packet[0] = 0b00_100_011; // LI=0 (no warning), VN=4, Mode=3 (client)
    write_ntp_timestamp(&mut packet[40..48], t1);
    // La fraction NTP vaut 2^-32 s par unité : remplacer ses 16 bits de poids
    // faible (≈ 15 µs) ne change pas l'instant, mais rend le *transmit*
    // imprévisible — c'est le nonce que l'*originate* de la réponse doit
    // reprendre.
    let random: [u8; 2] = rand::random();
    packet[46..48].copy_from_slice(&random);
    packet
}

/// Contrôle et dépouille une réponse. `request` est le paquet envoyé (son
/// *transmit* est le nonce attendu), `t1` et `t4` les instants d'envoi et
/// de réception locaux.
fn parse_response(
    request: &[u8; 48],
    buf: &[u8],
    t1: OffsetDateTime,
    t4: OffsetDateTime,
    max_rtt: Duration,
) -> Result<NtpSample, NtpError> {
    if buf.len() < 48 {
        return Err(NtpError::InvalidResponse("réponse tronquée (< 48 octets)"));
    }
    // Anti-usurpation (RFC 5905 §8) : la réponse doit reprendre le
    // *transmit* de la requête. Contrôlé avant tout le reste : une réponse
    // non sollicitée ne mérite pas d'être interprétée.
    if buf[24..32] != request[40..48] {
        return Err(NtpError::InvalidResponse(
            "originate ≠ transmit envoyé : réponse non sollicitée",
        ));
    }
    let leap = buf[0] >> 6;
    let version = (buf[0] >> 3) & 0b111;
    let mode = buf[0] & 0b0000_0111;
    if leap == 3 {
        return Err(NtpError::Unsynchronized(
            "indicateur de saut 3 (horloge de la source non synchronisée)",
        ));
    }
    if version != 3 && version != 4 {
        return Err(NtpError::InvalidResponse(
            "version NTP inattendue (attendu 3 ou 4)",
        ));
    }
    if mode != 4 {
        return Err(NtpError::InvalidResponse(
            "mode de réponse inattendu (attendu 4, serveur)",
        ));
    }
    let stratum = buf[1];
    if stratum == 0 {
        return Err(NtpError::Unsynchronized("strate 0 (kiss-o'-death)"));
    }
    if stratum > MAX_STRATUM {
        return Err(NtpError::Unsynchronized("strate 16 ou plus"));
    }
    if buf[32..40].iter().all(|&b| b == 0) || buf[40..48].iter().all(|&b| b == 0) {
        return Err(NtpError::InvalidResponse(
            "horodatage de réception ou de transmission nul",
        ));
    }

    let t2 = read_ntp_timestamp(&buf[32..40]);
    let t3 = read_ntp_timestamp(&buf[40..48]);

    // Formules RFC 5905 §8 : offset = ((T2-T1)+(T3-T4))/2, délai = (T4-T1)-(T3-T2).
    let offset = ((t2 - t1) + (t3 - t4)) / 2;
    let rtt = (t4 - t1) - (t3 - t2);
    if rtt < Duration::ZERO {
        return Err(NtpError::InvalidResponse(
            "aller-retour négatif : horodatages de la source incohérents",
        ));
    }
    if rtt > max_rtt {
        return Err(NtpError::RoundTripTooLong { rtt, max: max_rtt });
    }

    Ok(NtpSample {
        offset,
        rtt,
        stratum,
        leap,
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

    /// Le *transmit* de la requête porte l'instant d'envoi, à 15 µs près,
    /// et deux requêtes au même instant ne se ressemblent pas.
    #[test]
    fn the_request_transmit_is_the_send_time_with_random_low_bits() {
        let t1 = OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap();
        let a = build_request(t1);
        let b = build_request(t1);
        assert_eq!(a[0], 0b00_100_011);
        assert!((read_ntp_timestamp(&a[40..48]) - t1).abs() < Duration::microseconds(20));
        assert_ne!(
            a[46..48],
            b[46..48],
            "les bits de poids faible doivent être aléatoires"
        );
    }

    /// Une réponse de serveur bien formée, qui reprend le *transmit* de la
    /// requête et date la réception et l'émission à `t1 + offset`.
    fn reply(request: &[u8; 48], t1: OffsetDateTime, offset: Duration) -> [u8; 48] {
        let mut r = [0u8; 48];
        r[0] = 0b00_100_100; // LI=0, VN=4, mode 4 (serveur)
        r[1] = 2; // strate 2
        r[24..32].copy_from_slice(&request[40..48]); // originate = notre transmit
        write_ntp_timestamp(&mut r[32..40], t1 + offset); // receive
        write_ntp_timestamp(&mut r[40..48], t1 + offset); // transmit
        r
    }

    fn t1() -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap()
    }

    #[test]
    fn a_genuine_reply_yields_offset_rtt_stratum_and_leap() {
        let t1 = t1();
        let request = build_request(t1);
        let reply = reply(&request, t1, Duration::milliseconds(40));
        let t4 = t1 + Duration::milliseconds(10);
        let sample = parse_response(&request, &reply, t1, t4, Duration::SECOND).unwrap();
        // offset = ((T2-T1)+(T3-T4))/2 = (40 + 30)/2 = 35 ms ; rtt = 10 ms - 0.
        assert!((sample.offset - Duration::milliseconds(35)).abs() < Duration::milliseconds(1));
        assert!((sample.rtt - Duration::milliseconds(10)).abs() < Duration::milliseconds(1));
        assert_eq!(sample.stratum, 2);
        assert_eq!(sample.leap, 0);
    }

    /// Constat T-2 : une réponse dont l'*originate* n'est pas le *transmit*
    /// envoyé est une réponse non sollicitée (usurpation hors chemin ou
    /// réponse tardive à une autre requête) : refusée avant toute lecture.
    #[test]
    fn a_reply_to_another_request_is_refused() {
        let t1 = t1();
        let request = build_request(t1);
        let other = build_request(t1);
        let reply = reply(&other, t1, Duration::ZERO);
        let err = parse_response(&request, &reply, t1, t1, Duration::SECOND).unwrap_err();
        assert!(err.to_string().contains("non sollicitée"), "{err}");
    }

    #[test]
    fn an_unsynchronized_source_is_refused() {
        let t1 = t1();
        let request = build_request(t1);
        let mut li3 = reply(&request, t1, Duration::ZERO);
        li3[0] |= 0b11_000_000;
        assert!(matches!(
            parse_response(&request, &li3, t1, t1, Duration::SECOND),
            Err(NtpError::Unsynchronized(_))
        ));
        let mut kod = reply(&request, t1, Duration::ZERO);
        kod[1] = 0;
        assert!(matches!(
            parse_response(&request, &kod, t1, t1, Duration::SECOND),
            Err(NtpError::Unsynchronized(_))
        ));
        let mut stratum16 = reply(&request, t1, Duration::ZERO);
        stratum16[1] = 16;
        assert!(matches!(
            parse_response(&request, &stratum16, t1, t1, Duration::SECOND),
            Err(NtpError::Unsynchronized(_))
        ));
    }

    #[test]
    fn a_malformed_reply_is_refused() {
        let t1 = t1();
        let request = build_request(t1);
        let good = reply(&request, t1, Duration::ZERO);

        let mut version2 = good;
        version2[0] = 0b00_010_100;
        assert!(parse_response(&request, &version2, t1, t1, Duration::SECOND).is_err());

        let mut client_mode = good;
        client_mode[0] = 0b00_100_011;
        assert!(parse_response(&request, &client_mode, t1, t1, Duration::SECOND).is_err());

        let mut no_transmit = good;
        no_transmit[40..48].fill(0);
        assert!(parse_response(&request, &no_transmit, t1, t1, Duration::SECOND).is_err());

        assert!(parse_response(&request, &good[..40], t1, t1, Duration::SECOND).is_err());

        // Une version 3 est acceptée (serveurs anciens, même format).
        let mut version3 = good;
        version3[0] = 0b00_011_100;
        assert!(parse_response(&request, &version3, t1, t1, Duration::SECOND).is_ok());
    }

    /// Un aller-retour trop long rend l'écart mesuré incertain d'autant :
    /// la mesure est écartée plutôt que de compter pour la traçabilité.
    #[test]
    fn a_slow_round_trip_is_refused() {
        let t1 = t1();
        let request = build_request(t1);
        let reply = reply(&request, t1, Duration::ZERO);
        let t4 = t1 + Duration::seconds(3);
        let err = parse_response(&request, &reply, t1, t4, Duration::SECOND).unwrap_err();
        assert!(matches!(err, NtpError::RoundTripTooLong { .. }), "{err}");
        assert!(parse_response(&request, &reply, t1, t4, Duration::seconds(5)).is_ok());
    }

    /// Un vrai échange UDP avec un serveur local qui répond correctement,
    /// puis avec un serveur qui répond sans reprendre l'*originate* (ce que
    /// ferait une réponse forgée) : seul le premier donne une mesure.
    #[test]
    fn queries_a_local_server_and_rejects_a_spoofing_one() {
        fn serve(spoof: bool) -> String {
            let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
            let addr = socket.local_addr().unwrap();
            std::thread::spawn(move || {
                let mut buf = [0u8; 48];
                let (n, peer) = socket.recv_from(&mut buf).unwrap();
                assert_eq!(n, 48);
                let mut request = [0u8; 48];
                request.copy_from_slice(&buf);
                if spoof {
                    request[40..48].copy_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
                }
                let now = OffsetDateTime::now_utc();
                let r = reply(&request, now, Duration::ZERO);
                socket.send_to(&r, peer).unwrap();
            });
            addr.to_string()
        }
        let sample = query(&serve(false), StdDuration::from_secs(2), Duration::SECOND).unwrap();
        assert_eq!(sample.stratum, 2);
        assert!(
            sample.offset.abs() < Duration::SECOND,
            "{:?}",
            sample.offset
        );

        let err = query(&serve(true), StdDuration::from_secs(2), Duration::SECOND).unwrap_err();
        assert!(err.to_string().contains("non sollicitée"), "{err}");
    }

    #[test]
    #[ignore = "nécessite un accès réseau UDP/123 sortant vers un serveur NTP public"]
    fn queries_a_real_public_ntp_server() {
        let sample = query(
            "pool.ntp.org",
            StdDuration::from_secs(5),
            Duration::seconds(2),
        )
        .expect("requête NTP");
        assert!(sample.stratum > 0);
        assert!(
            sample.offset.abs() < Duration::seconds(10),
            "écart déraisonnable: {:?}",
            sample.offset
        );
    }
}
