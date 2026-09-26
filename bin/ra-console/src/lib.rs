//! `ra-console` : la console d'exploitation RA/CA (docs/WEBUI.md).
//!
//! Deux principes non négociables (§16) : elle **n'ouvre jamais de session
//! PKCS#11**, et elle **n'écrit jamais dans les tables de `ca-server`** ni n'est
//! une ancre de confiance. Elle est le seul composant exposé aux navigateurs,
//! donc le plus probablement compromis un jour : tout ce qui touche la PKI ou le
//! registre des opérateurs est vérifié *et* exécuté par `ca-server`, à partir de
//! la signature brute de l'opérateur, par le lien interne (mTLS).
//!
//! Cette première brique pose ce que tout le reste suppose : la configuration, la
//! preuve que le rôle PostgreSQL de la console est bien en lecture seule sur les
//! tables de `ca-server`, et le lien mTLS vers `ca-server`. Aucune authentification
//! d'opérateur n'y est encore branchée.

pub mod audit;
pub mod audit_search;
pub mod ca_link;
pub mod config;
pub mod db_guard;
pub mod http;
pub mod login;
pub mod purge;
pub mod requests;
pub mod session;
pub mod webauthn_models;
