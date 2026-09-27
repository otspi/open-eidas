//! Constat D-2 de l'audit du 2026-09-25 : la matrice ne doit citer que des
//! preuves qui existent et qui s'exécutent. Chaque référence des champs
//! `test` et `in_service` de `system_matrix()` est résolue dans le dépôt :
//! le fichier existe, chaque fonction citée y est définie et n'est pas
//! `#[ignore]`, chaque étape de job citée existe dans le workflow. Une
//! matrice qui citerait un test renommé, supprimé ou ignoré ne passe plus.

use std::path::{Path, PathBuf};

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// Une référence : un chemin, et ce qu'on y cite (fonctions ou étape).
#[derive(Debug, PartialEq)]
struct Reference {
    path: String,
    items: Vec<String>,
}

/// Découpe `a.rs (f, g), b.yml (Étape (détail))` en références, en tenant
/// compte des parenthèses imbriquées d'un nom d'étape.
fn parse(field: &str) -> Vec<Reference> {
    let mut refs = Vec::new();
    let mut depth = 0usize;
    let mut path = String::new();
    let mut inner = String::new();
    let mut chars = field.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '(' => {
                if depth > 0 {
                    inner.push(c);
                }
                depth += 1;
            }
            ')' => {
                depth -= 1;
                if depth > 0 {
                    inner.push(c);
                }
            }
            ',' if depth == 0 && chars.peek() == Some(&' ') => {
                chars.next();
                refs.push(finish(&path, &inner));
                path.clear();
                inner.clear();
            }
            _ if depth > 0 => inner.push(c),
            _ => path.push(c),
        }
    }
    if !path.trim().is_empty() {
        refs.push(finish(&path, &inner));
    }
    refs
}

fn finish(path: &str, inner: &str) -> Reference {
    let path = path.trim().to_string();
    let items = if inner.is_empty() {
        Vec::new()
    } else if path.ends_with(".rs") {
        inner.split(", ").map(|s| s.trim().to_string()).collect()
    } else {
        // Un nom d'étape de workflow peut contenir des virgules : un seul élément.
        vec![inner.trim().to_string()]
    };
    Reference { path, items }
}

/// `Some(true)` si la fonction existe et n'est pas ignorée, `Some(false)` si
/// elle est ignorée, `None` si elle n'existe pas.
fn rust_fn_runs(source: &str, name: &str) -> Option<bool> {
    let lines: Vec<&str> = source.lines().collect();
    let pos = lines.iter().position(|l| {
        let l = l.trim_start();
        [format!("fn {name}("), format!("fn {name}<")]
            .iter()
            .any(|sig| {
                l.starts_with(sig.as_str())
                    || l.starts_with(&format!("async {sig}"))
                    || l.starts_with(&format!("pub {sig}"))
                    || l.starts_with(&format!("pub async {sig}"))
            })
    })?;
    let attributes = lines[..pos]
        .iter()
        .rev()
        .take_while(|l| {
            let t = l.trim_start();
            t.starts_with("#[") || t.starts_with("///") || t.starts_with("//")
        })
        .any(|l| l.contains("#[ignore"));
    Some(!attributes)
}

fn check(field_name: &str, key: &str, field: &str, problems: &mut Vec<String>) {
    for r in parse(field) {
        let file = root().join(&r.path);
        let Ok(source) = std::fs::read_to_string(&file) else {
            problems.push(format!(
                "{key} ({field_name}) : fichier introuvable {}",
                r.path
            ));
            continue;
        };
        if r.path.ends_with(".rs") {
            if r.items.is_empty() && source.contains("#[ignore") {
                problems.push(format!(
                    "{key} ({field_name}) : {} contient des tests ignorés, citer ceux qui s'exécutent",
                    r.path
                ));
            }
            for item in &r.items {
                match rust_fn_runs(&source, item) {
                    Some(true) => {}
                    Some(false) => problems.push(format!(
                        "{key} ({field_name}) : {}::{item} est #[ignore]",
                        r.path
                    )),
                    None => problems.push(format!(
                        "{key} ({field_name}) : {}::{item} introuvable",
                        r.path
                    )),
                }
            }
        } else {
            for item in &r.items {
                let step = format!("- name: {item}");
                if !source.lines().any(|l| l.trim() == step) {
                    problems.push(format!(
                        "{key} ({field_name}) : étape « {item} » introuvable dans {}",
                        r.path
                    ));
                }
            }
        }
    }
}

#[test]
fn every_cited_test_and_in_service_proof_exists_and_runs() {
    let mut problems = Vec::new();
    for e in &oe_conformance::system_matrix().0 {
        let key = e.requirement.to_string();
        check("test", &key, e.test, &mut problems);
        check("in_service", &key, e.in_service, &mut problems);
    }
    assert!(
        problems.is_empty(),
        "références de la matrice non résolues :\n{}",
        problems.join("\n")
    );
}

#[test]
fn references_are_parsed_with_nested_parentheses() {
    assert_eq!(
        parse("a/b.rs (f, g), .github/workflows/ci.yml (Horodate (openssl ts)), c.rs"),
        vec![
            Reference {
                path: "a/b.rs".into(),
                items: vec!["f".into(), "g".into()]
            },
            Reference {
                path: ".github/workflows/ci.yml".into(),
                items: vec!["Horodate (openssl ts)".into()]
            },
            Reference {
                path: "c.rs".into(),
                items: vec![]
            },
        ]
    );
}

#[test]
fn an_ignored_or_missing_function_is_reported() {
    let source =
        "#[test]\n#[ignore = \"x\"]\nfn skipped() {}\n\n#[tokio::test]\nasync fn runs() {}\n";
    assert_eq!(rust_fn_runs(source, "skipped"), Some(false));
    assert_eq!(rust_fn_runs(source, "runs"), Some(true));
    assert_eq!(rust_fn_runs(source, "absent"), None);
}
