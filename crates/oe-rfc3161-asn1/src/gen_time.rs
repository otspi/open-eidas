//! `GeneralizedTime` avec fraction de seconde, pour `TSTInfo.genTime`
//! (RFC 3161 §2.4.2 ; EN 319 422 §5.2.2).
//!
//! `der::asn1::GeneralizedTime` suit délibérément le profil RFC 5280
//! (certificats X.509), qui **interdit** les fractions de seconde. RFC 3161
//! ne reprend pas cette restriction pour `genTime`, et EN 319 422 §5.2.2
//! exige que `genTime` porte la précision nécessaire à l'exactitude
//! déclarée — d'où ce module, qui encode/décode le DER à la main plutôt que
//! de réutiliser ce type.
//!
//! Forme canonique DER (X.690 §11.7) respectée par [`encode`] : la fraction
//! ne se termine jamais par un zéro, et est absente si elle est nulle
//! (`20260115100000Z`, pas `20260115100000.000Z`) — ce qui rend [`encode`]
//! compatible octet pour octet avec les fixtures historiques du corpus
//! (`tests/fixtures/rfc3161/`), produites sans fraction.

use der::asn1::Any;
use der::{Error, Tag};

/// Composants d'un instant UTC. Ce crate ne dépend d'aucune bibliothèque de
/// date (voir la note de module de `lib.rs`) : l'appelant convertit depuis
/// son propre type d'horodatage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Parts {
    /// 0000-9999 : `GeneralizedTime` code l'année sur 4 chiffres.
    pub year: u16,
    pub month: u8,
    pub day: u8,
    pub hour: u8,
    pub minute: u8,
    pub second: u8,
    /// Nanosecondes dans la seconde (0..1_000_000_000).
    pub nanosecond: u32,
}

fn value_error() -> Error {
    Tag::GeneralizedTime.value_error().into()
}

/// Encode `p` en `GeneralizedTime` DER, la fraction tronquée à `digits`
/// chiffres décimaux (0..=9 ; EN 319 422 §5.2.2 demande au moins la
/// précision de l'exactitude déclarée — la milliseconde, `digits = 3`, la
/// couvre pour l'exactitude à la seconde qu'annonce ce dépôt).
pub fn encode(p: &Parts, digits: u8) -> Result<Any, Error> {
    if p.year > 9999 || p.month == 0 || p.month > 12 || p.day == 0 || p.day > 31 {
        return Err(value_error());
    }
    if p.hour > 23 || p.minute > 59 || p.second > 59 {
        return Err(value_error());
    }
    if digits > 9 {
        return Err(value_error());
    }
    let mut s = format!(
        "{:04}{:02}{:02}{:02}{:02}{:02}",
        p.year, p.month, p.day, p.hour, p.minute, p.second
    );
    if digits > 0 {
        let scale = 10u32.pow(9 - u32::from(digits));
        let frac = p.nanosecond / scale;
        let mut frac_str = format!("{frac:0width$}", width = usize::from(digits));
        while frac_str.ends_with('0') {
            frac_str.pop();
        }
        if !frac_str.is_empty() {
            s.push('.');
            s.push_str(&frac_str);
        }
    }
    s.push('Z');
    Any::new(Tag::GeneralizedTime, s.into_bytes())
}

/// Décode une valeur produite par [`encode`] — ou une forme sans fraction,
/// comme les fixtures historiques du corpus.
pub fn decode(any: &Any) -> Result<Parts, Error> {
    use der::Tagged;
    if any.tag() != Tag::GeneralizedTime {
        return Err(value_error());
    }
    let s = std::str::from_utf8(any.value()).map_err(|_| value_error())?;
    let s = s.strip_suffix('Z').ok_or_else(value_error)?;
    let (whole, frac) = match s.split_once('.') {
        Some((w, f)) => (w, f),
        None => (s, ""),
    };
    if whole.len() != 14 || !whole.bytes().all(|b| b.is_ascii_digit()) {
        return Err(value_error());
    }
    if !frac.bytes().all(|b| b.is_ascii_digit()) || frac.len() > 9 {
        return Err(value_error());
    }
    let digit = |s: &str| s.parse::<u32>().map_err(|_| value_error());
    let year = digit(&whole[0..4])? as u16;
    let month = digit(&whole[4..6])? as u8;
    let day = digit(&whole[6..8])? as u8;
    let hour = digit(&whole[8..10])? as u8;
    let minute = digit(&whole[10..12])? as u8;
    let second = digit(&whole[12..14])? as u8;
    let nanosecond = if frac.is_empty() {
        0
    } else {
        let scale = 10u32.pow(9 - frac.len() as u32);
        digit(frac)? * scale
    };
    Ok(Parts {
        year,
        month,
        day,
        hour,
        minute,
        second,
        nanosecond,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parts(nanosecond: u32) -> Parts {
        Parts {
            year: 2026,
            month: 1,
            day: 15,
            hour: 10,
            minute: 0,
            second: 0,
            nanosecond,
        }
    }

    #[test]
    fn a_zero_fraction_is_omitted_der_canonical() {
        let any = encode(&parts(0), 3).unwrap();
        assert_eq!(any.value(), b"20260115100000Z");
    }

    #[test]
    fn a_non_zero_fraction_drops_trailing_zeros() {
        // 120 ms -> ".12", pas ".120".
        let any = encode(&parts(120_000_000), 3).unwrap();
        assert_eq!(any.value(), b"20260115100000.12Z");
    }

    #[test]
    fn zero_digits_is_the_historical_whole_second_form() {
        let any = encode(&parts(999_000_000), 0).unwrap();
        assert_eq!(any.value(), b"20260115100000Z");
    }

    #[test]
    fn encode_then_decode_round_trips_within_the_truncated_precision() {
        let any = encode(&parts(123_456_789), 3).unwrap();
        let decoded = decode(&any).unwrap();
        assert_eq!(decoded.nanosecond, 123_000_000);
        assert_eq!(decoded.year, 2026);
        assert_eq!(decoded.second, 0);
    }

    #[test]
    fn decodes_the_whole_second_form_used_by_the_historical_corpus() {
        let any = Any::new(Tag::GeneralizedTime, b"20260115100000Z".to_vec()).unwrap();
        let decoded = decode(&any).unwrap();
        assert_eq!(decoded.nanosecond, 0);
        assert_eq!(decoded.hour, 10);
    }

    #[test]
    fn rejects_a_wrong_tag() {
        let any = Any::new(Tag::Utf8String, b"20260115100000Z".to_vec()).unwrap();
        assert!(decode(&any).is_err());
    }

    #[test]
    fn rejects_garbage_content() {
        let any = Any::new(Tag::GeneralizedTime, b"not-a-date".to_vec()).unwrap();
        assert!(decode(&any).is_err());
    }
}
