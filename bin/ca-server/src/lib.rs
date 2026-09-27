//! Bibliothèque interne de `ca-server`, séparée du binaire uniquement pour
//! que ses tests d'intégration (`tests/`) puissent construire un `Server`
//! réel — la CLI (`main.rs`) reste le seul point d'entrée exécutable.

pub mod cli_review;
pub mod config;
pub mod http;
pub mod internal;
pub mod internal_tls;
pub mod registry_check;
pub mod revoker;
pub mod webauthn_models;
