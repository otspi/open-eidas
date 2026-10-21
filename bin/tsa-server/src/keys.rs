//! Générations de la clé de la TSU (constat H-3 de l'audit du 2026-09-25, EN 319
//! 421 `TIS-7.6.7-07`) : chaque certificat de TSU a sa propre bi-clé.
//!
//! La première génération porte le label configuré (`OPENEIDAS_KEY_LABEL`), ce
//! qui garde les déploiements existants intacts ; la génération *n* ≥ 2 porte
//! `<label>.<n>`. Une clé n'est jamais écrasée ni relabellisée : au
//! renouvellement, `enroll` en génère une neuve, et `serve` ouvre celle dont la
//! clé publique est dans le certificat. Les anciennes clés restent dans le
//! token jusqu'à leur destruction par l'opérateur (docs/CA.md) — aucune
//! destruction automatique, elle est irréversible.

/// Nombre maximal de générations cherchées dans un token.
pub const MAX_GENERATIONS: u32 = 64;

/// Label PKCS#11 de la génération `generation` (1 = label de base).
pub fn generation_label(base: &str, generation: u32) -> String {
    if generation <= 1 {
        base.to_string()
    } else {
        format!("{base}.{generation}")
    }
}

/// Résultat de la recherche d'une génération dans un token.
#[derive(Debug, PartialEq, Eq)]
pub struct Generations {
    /// Génération dont la clé publique est celle du certificat, s'il y en a une.
    pub matching: Option<u32>,
    /// Plus récente génération présente dans le token, s'il y en a une.
    pub newest: Option<u32>,
}

/// Cherche, parmi les générations, celle qui correspond au certificat.
/// `spki_of(label)` rend la clé publique (SubjectPublicKeyInfo DER) de la clé
/// portant ce label, `Ok(None)` si elle n'existe pas ; toute autre panne (clé
/// ambiguë, token illisible) est rendue telle quelle, jamais prise pour une
/// absence.
pub fn find(
    base: &str,
    cert_spki: Option<&[u8]>,
    spki_of: impl Fn(&str) -> Result<Option<Vec<u8>>, String>,
) -> Result<Generations, String> {
    let mut found = Generations {
        matching: None,
        newest: None,
    };
    for generation in 1..=MAX_GENERATIONS {
        let Some(spki) = spki_of(&generation_label(base, generation))? else {
            continue;
        };
        found.newest = Some(generation);
        if cert_spki == Some(spki.as_slice()) {
            found.matching = Some(generation);
        }
    }
    Ok(found)
}

/// Ce que `enroll` doit faire de la clé, quand le certificat est à renouveler
/// (ou absent).
#[derive(Debug, PartialEq, Eq)]
pub enum KeyPlan {
    /// Aucune clé : générer la génération donnée.
    Generate(u32),
    /// Utiliser la clé de cette génération, déjà présente.
    Use(u32),
}

/// Plan de clé pour un enrôlement nécessaire. Un certificat qui correspond à la
/// plus récente clé impose d'en générer une neuve (une clé par certificat) ;
/// une clé plus récente que celle du certificat — ou un certificat absent —
/// signifie qu'un enrôlement précédent a échoué après la génération : on la
/// réutilise plutôt que d'en empiler une par tentative.
pub fn plan(found: &Generations) -> Result<KeyPlan, String> {
    match (found.matching, found.newest) {
        (_, None) => Ok(KeyPlan::Generate(1)),
        (Some(m), Some(n)) if m == n => {
            if n >= MAX_GENERATIONS {
                Err(format!(
                    "{MAX_GENERATIONS} générations de clé déjà dans le token : détruire les anciennes (docs/CA.md)"
                ))
            } else {
                Ok(KeyPlan::Generate(n + 1))
            }
        }
        (_, Some(n)) => Ok(KeyPlan::Use(n)),
    }
}

/// Une génération ne peut être détruite que si un certificat plus récent est en
/// service : jamais celle du certificat courant, jamais une clé en attente de son
/// certificat, jamais une génération absente du token.
pub fn check_retirable(found: &Generations, generation: u32) -> Result<(), String> {
    let Some(current) = found.matching else {
        return Err(
            "aucune clé du token ne correspond au certificat en service : rien n'est détruit"
                .to_string(),
        );
    };
    if generation == current {
        return Err(format!(
            "la génération {generation} porte le certificat en service"
        ));
    }
    if generation > current {
        return Err(format!(
            "la génération {generation} est plus récente que celle du certificat en service ({current}) : clé en attente de son certificat"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn token(
        labels: &'static [(&'static str, &'static [u8])],
    ) -> impl Fn(&str) -> Result<Option<Vec<u8>>, String> {
        move |label| {
            Ok(labels
                .iter()
                .find(|(l, _)| *l == label)
                .map(|(_, k)| k.to_vec()))
        }
    }

    #[test]
    fn the_first_generation_keeps_the_configured_label() {
        assert_eq!(generation_label("tsu-signing-key", 1), "tsu-signing-key");
        assert_eq!(generation_label("tsu-signing-key", 2), "tsu-signing-key.2");
        assert_eq!(generation_label("tsu-signing-key", 7), "tsu-signing-key.7");
    }

    #[test]
    fn find_selects_the_generation_that_holds_the_certificate_key() {
        let t = token(&[("k", b"A"), ("k.2", b"B"), ("k.3", b"C")]);
        let found = find("k", Some(b"B"), &t).unwrap();
        assert_eq!(
            found,
            Generations {
                matching: Some(2),
                newest: Some(3)
            }
        );
        let found = find("k", Some(b"Z"), &t).unwrap();
        assert_eq!(
            found,
            Generations {
                matching: None,
                newest: Some(3)
            }
        );
        let found = find("k", None, token(&[])).unwrap();
        assert_eq!(
            found,
            Generations {
                matching: None,
                newest: None
            }
        );
    }

    #[test]
    fn a_token_failure_is_not_taken_for_an_absent_key() {
        let broken = |_: &str| -> Result<Option<Vec<u8>>, String> { Err("clé ambiguë".into()) };
        assert!(find("k", None, broken).is_err());
    }

    #[test]
    fn a_renewal_generates_a_new_key_only_when_the_newest_one_is_in_use() {
        // Aucune clé : première génération.
        assert_eq!(
            plan(&Generations {
                matching: None,
                newest: None
            }),
            Ok(KeyPlan::Generate(1))
        );
        // Le certificat porte la clé la plus récente : une clé par certificat.
        assert_eq!(
            plan(&Generations {
                matching: Some(1),
                newest: Some(1)
            }),
            Ok(KeyPlan::Generate(2))
        );
        assert_eq!(
            plan(&Generations {
                matching: Some(3),
                newest: Some(3)
            }),
            Ok(KeyPlan::Generate(4))
        );
        // Une clé plus récente attend son certificat : réutilisée, pas empilée.
        assert_eq!(
            plan(&Generations {
                matching: Some(1),
                newest: Some(2)
            }),
            Ok(KeyPlan::Use(2))
        );
        // Pas de certificat (ou étranger) : la clé la plus récente.
        assert_eq!(
            plan(&Generations {
                matching: None,
                newest: Some(2)
            }),
            Ok(KeyPlan::Use(2))
        );
    }

    #[test]
    fn only_a_generation_older_than_the_certificate_in_service_is_retirable() {
        let found = Generations {
            matching: Some(3),
            newest: Some(4),
        };
        assert!(check_retirable(&found, 1).is_ok());
        assert!(check_retirable(&found, 2).is_ok());
        assert!(
            check_retirable(&found, 3).is_err(),
            "le certificat en service"
        );
        assert!(check_retirable(&found, 4).is_err(), "la clé en attente");
        let none = Generations {
            matching: None,
            newest: Some(2),
        };
        assert!(
            check_retirable(&none, 1).is_err(),
            "aucun certificat en service"
        );
    }

    #[test]
    fn the_generation_count_is_bounded() {
        let full = Generations {
            matching: Some(MAX_GENERATIONS),
            newest: Some(MAX_GENERATIONS),
        };
        assert!(plan(&full).is_err());
    }
}
