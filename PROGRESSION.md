**2026-10-20 — série P1 mergée** (autorisation `--admin` de Philippe : #102, #103, #105, #106, #107, #108, #109, #110 ; #104 fermée, inutile). P2 en cours, une PR par constat : **C-3 = PR #111** (`fix/revocation-reason-allowlist`, liste blanche 1/3/4/5/9 dans `Issuer::revoke`). **C-5 = PR #112** (`fix/rsa-sha256-null-params`, NULL dans les AlgorithmIdentifier de certificats/CRL/OCSP/CSR ; reste : `pkilint` en CI, outil à choisir). **C-2 = PR #113** (`fix/production-pin-separation` : `OPENEIDAS_PRODUCTION`, PIN SO générés par le chart ; reste hors code : racine hors ligne, PVC séparés — à écrire dans la CPS). #111 mergée. **H-1 + gabarit H-3 = PR #114** (`fix/hsm-key-attributes`, provenance CKA_LOCAL/NEVER_EXTRACTABLE/ALWAYS_SENSITIVE/SIGN, un seul objet ; decrypt/unwrap/derive rendus mais pas exigés pour ne pas casser les clés déjà générées). #112 (C-5) mergée. Reste P2 : C-6 (bloqué : `organizationIdentifier` = identifiant de l'association, `certificatePolicies` = choix NCP+/OID propre, décisions Philippe/CPC), H-2 (vérification après signature, reconnexion, SoftwareToken derrière feature, PSS), H-3 (renouvellement de clé TSU, zeroize PIN), R-3, A-1, A-2, S-1..S-3. **2026-10-20 soir : #111, #112 (gardées par Philippe), #113 (C-2), #114 (H-1/H-3 gabarit), #115 (H-2 SoftwareToken derrière `testing`, garde CI `cargo tree`) mergées.** Reste P2 : C-6 (bloqué), H-2 (vérification après signature, reconnexion PKCS#11, PSS), H-3 (renouvellement de la clé TSU, zeroize), R-3, A-1, A-2, S-1..S-3, pkilint. **H-2 vérification après signature = PR #116** (`fix/verify-after-sign`, `oe_hsm::verify_signature` dans `Pkcs11Token::sign_digest`). **#116 (H-2 vérification après signature) mergée ; C-6 = PR #117** (`feat/tsu-subject-policy`, NCP+ et `organizationIdentifier` via `OPENEIDAS_ORG_IDENTIFIER`, **valeur RNA à fournir**) ; **#118 = avis RUSTSEC-2026-0381/-0382** (webpki, sqlx racines natives), non mergée (pas d'autorisation), son correctif est aussi dans #116/#117. Attention : le disque était plein à 100 % (target = 146 Go), `rm -rf target/debug/incremental` régulièrement. **S-1 (--locked + justification RUSTSEC-2023-0071) = PR #119** (`fix/supply-chain-locked` ; reste : épingler images/Actions, SBOM, cosign, SLSA) ; **S-2 (modes dégradés refusés en production) = PR #120** (`fix/production-refuses-degraded-modes` ; reste : journaliser un démarrage dégradé). Brouillons, CI à vérifier, merges non autorisés par Philippe. **#118 mergée ; A-2 (empreinte de session + inactivité 30 min) = PR #121** (`fix/session-hash-idle`, brouillon, merge non autorisé). **A-1 (empreinte CSR obligatoire pour tsa_signer/internal_*, `internal_client` réservé à `ca_operateur`, console qui expose et envoie l'empreinte) = PR #122** (brouillon ; Playwright à vérifier en CI, npm via `~/.nvm/versions/node/v24.18.1/bin`). Piège : les tests `oe-actions` sont ignorés sans `OE_CASTORE_TEST_DSN` — toute mutation doit être jouée avec PostgreSQL. **Reconnexion PKCS#11 = PR #123** (`fix/pkcs11-reconnect`, session dans un Mutex, `retrying` rejoue une fois, `lose_session_for_test` derrière la feature `testing` ; `oe-hsm` s'auto-active en dev-dependency). CI verte : #117 (C-6, brouillon), #121 (A-2) ; #122/#123 en cours. **PIN zéroïsé = PR #124** (empilée sur #123), **démarrage dégradé journalisé (fin de S-2) = PR #125**. **Décision de Philippe (2026-10-21) : RSASSA-PSS partout** (certificats, CRL, OCSP, jetons ; il a choisi cette option après que j'ai signalé le risque d'interopérabilité — à documenter dans la CPS). Plan en étapes, une PR chacune : (1) `oe-hsm` : `SignatureScheme { Pkcs1v15, Pss }`, `CKM_RSA_PKCS_PSS` (cryptoki `Mechanism::RsaPkcsPss(PkcsPssParams{hash_alg, mgf, s_len})`, sel = longueur du condensé), `SoftwareToken` et `verify_signature` en PSS ; (2) identifiants d'algorithme `RSASSA-PSS-params` (1.2.840.113549.1.1.10, RFC 4055/4056) dans certificats, CRL, OCSP, CSR ; (3) CMS du jeton RFC 3161 ; (4) configuration `OPENEIDAS_RSA_SCHEME`, matrice, CPS, CI (openssl vérifie). `check_signature_algorithm` d'`oe-conformance` (liste d'OID) à étendre. Reste P2 : A-1 (challenge dérivé du corps = décision O7), reconnexion PKCS#11, PSS, renouvellement clé TSU, zeroize PIN, S-1 (épinglage/SBOM/cosign), S-2 (journaliser démarrage dégradé), S-3, pkilint. Prochains : C-6 (`organizationIdentifier`, certificatePolicies : décision CPC probable), H-1 à H-3. Note : `cargo test --workspace` échoue en local sur le corpus `oe-rfc3161-asn1` (déjà sur dev, vert en CI). Piège : la CI utilise clippy 1.99 (plus strict que le local 1.97).

# PROGRESSION — état du travail en cours

Fichier de passage de relais, **local et non suivi** (comme `TODO.md` et `CLAUDE.md` : ne jamais le `git add`).
Il dit *où on en est* et *comment travailler ici sans refaire les erreurs déjà faites*. L'inventaire de ce
qui reste ouvert est dans `TODO.md` ; la conception dans `docs/WEBUI.md` (renvois `§N`) ; l'exploitation dans
`docs/CA.md` et `docs/RA-CONSOLE.md`. **Dernière mise à jour : 2026-10-13 (étape 5 complète : #98, #99, #100 ; CI accélérée ; ménage des branches).**

## 0. Reprise immédiate

**Audit P1 — découpage validé le 2026-10-13**, une PR par tranche vers `dev`, dans l'ordre
**journal → OCSP → temps**. Décisions de l'utilisateur : (1) J-1 d'abord (seule NC majeure restante) ;
(2) **scellement par la TSA maison, par HTTP** : `tsa-server` scelle son journal en interne, `ca-server`
et `ra-console` font horodater leur tête de chaîne par la TSA maison puis par la TSA tierce ;
(3) **NTS (RFC 8915) dans cette série** (tranche T-c, après le durcissement SNTP) ; (4) **C-4 : tous les
révoqués restent indéfiniment dans la CRL**, extension `ExpiredCertsOnCRL`. Tranches : **J-a** copie
hors site du journal de `tsa-server` (S3), **J-b** scellement périodique (`log.sealed`), **J-c**
contreseing tiers (`log.cross_sealed`) + `/healthz` dégradé après N échecs, **J-d** matrice et docs ;
**O-a** `tryLater` si `nextUpdate` passé, `cRLNumber` monotone, nonce, requêtes multiples ; **O-b**
révoqués conservés + CPS ; **T-a** durcissement SNTP, **T-b** seconde intercalaire, **T-c** NTS.
Précisions du même jour : pour `tsa-server`, **copie et scellement périodiques** (une entrée de journal
par jeton : pas de copie par événement ; l'émission ne dépend pas de S3, un échec prolongé dégrade
`/healthz`) ; **destination S3 comme les deux autres journaux** — le réplica WebDAV que le chart et
le compose déploient pour la TSA (`audit-replica`, `OPENEIDAS_AUDIT_REPLICA_*`, jamais alimenté) est
**à retirer** ; le crate `oe-replicate` reste (décision du 2026-09-25). Les TSA tierces sont déjà
configurées (`OPENEIDAS_CROSS_TSA_URLS`, FreeTSA et DigiCert par défaut).
**J-a mergée : #101** (`b29bdf3`, autorisation `--admin` donnée pour elle le 2026-10-13) : scellement
par la TSU et copie S3 dans `tsa-server` (`bin/tsa-server/src/seal.rs`, `oe_httpapi::JournalHealth`,
`oe_config::S3Config`), réplica WebDAV retiré du chart et du compose, `tsa.audit.s3.*`. `/healthz` reste
en 200 quand le journal est dégradé (sonde de vivacité) ; aucune alerte n'est branchée sur
`journal.degraded`. Le run de `dev` sur `b29bdf3` n'a pas été relevé.
**J-b faite : PR #102** (`feat/tsa-audit-cross-seal`, base `dev`, tête `a590c06`), en attente de CI et de
revue ; **pas d'autorisation `--admin` donnée pour elle**. Contreseing par les TSA d'`OPENEIDAS_CROSS_TSA_URLS`
dans la même boucle (`log.cross_sealed`), santé (`cross_tsas`, `last_cross_seal_count`,
`cross_seal_failures`), variable vide = désactivé (`${VAR-défaut}` dans le compose), CI sans TSA
publique. **À sa fusion, la TSA du staging enverra l'empreinte de sa tête de journal à FreeTSA et
DigiCert** (défaut du chart) : le dire à l'utilisateur avant de fusionner. Limite : signature des
jetons tiers non vérifiée à la collecte.
**J-c faite : PR #103** (`feat/journal-seal-ca-ra`, **empilée sur #102**, base `feat/tsa-audit-cross-seal` ;
après la fusion de #102 : `git rebase --onto origin/dev <tête de #102>` puis rebrancher sur `dev` par l'API REST),
en attente de CI et de revue ; **pas d'autorisation `--admin`**. Nouveau crate **`oe-seal`** (la boucle de
`bin/tsa-server/src/seal.rs` généralisée : trait `Stamper`, `HttpStamper` par `oe_crosstsa::Client::attest`,
`Options`, `Sealer::once`/`spawn_periodic`/`spawn_periodic_until`, `Health`) ; `JournalHealth`/`JournalReport`
déplacés dans `oe-audit` (réexportés par `oe-httpapi`) ; `tsa-server` ne garde que `AuthorityStamper`.
`ca-server` et `ra-console` : `OPENEIDAS_TSA_URL` (vide = pas de scellement, avertissement au démarrage),
`OPENEIDAS_AUDIT_SEAL_INTERVAL` (`_SECONDS` pour la console), `OPENEIDAS_CROSS_TSA_URLS` (absente = FreeTSA +
DigiCert, **vide = désactivé**), `/healthz` rend `journal` et passe `statut` en `degrade` **sans 503**.
Compose : `ca` scelle via `http://tsa:8318/tsa` (première passe en échec, reprise à 60 s : la TSA démarre
après la CA). Chart : `ca.audit.sealInterval`, `raConsole.audit.sealIntervalSeconds`, `raConsole.crossTSA.urls`
(vide par défaut : la NetworkPolicy de la console n'ouvre 80/443 que si renseigné ; egress vers le pod TSA
ajouté). La CI compose (`OPENEIDAS_CROSS_TSA_URLS=""`) et kind (`tsa.crossTSA.urls=`) n'appellent aucune TSA
publique pour la CA ; la console du kind garde `raConsole.crossTSA.urls` vide. **La matrice n'est pas touchée**
(mécanisme de `REQ-7.10-02` encore « ni scellés ni contresignés ») : c'est J-d.
**J-d faite : PR #105** (`feat/journal-seal-docs`, **empilée sur #103**) : `REQ-7.10-02` en couvert (limites
écrites : signature des jetons tiers non vérifiée, ra-console prouvée en mémoire seulement), étape de CI
« Vérifie que la CA a fait sceller son journal par la TSA » dans les deux démos (compose : `/healthz` de la CA
sur :8320 puis `verify-audit` ; kind : `verify-audit`), `CONFORMITE-ETSI.md` régénéré (24 couvertes),
`ARCHITECTURE.md`/`CPS.md`/`CA.md`/`README.md`. **J-1 est entièrement livré** en pile #102 → #103 → #105.
Ordre de fusion : #104 (rustls) → #102 → #103 (rebrancher sur `dev`) → #105 (idem).
**O-a faite : PR #106** (`feat/ocsp-crl-freshness`, base `dev`, indépendante de J-1) : `oe-ocsp-core` — `tryLater`
passé `nextUpdate` (horloge injectable `Options::clock`), `cRLNumber` monotone (`OcspError::CrlReplayed`, CRL sans
numéro refusée), nonce RFC 8954 repris (1..32 octets sinon `malformedRequest`), une `SingleResponse` par requête
(`MAX_REQUESTS` = 100). Six tests openssl, quatre mutations tuées. Matrice : ligne `CSS-6.3.10-03`/`OVR-6.6.3-01`
couverte (37 exigences, 24 couvertes), étape kind OCSP passée en `-nonce`. **O-b faite : PR #107** (`feat/crl-keep-revoked`, empilée sur #106, rebasée après le correctif CodeQL `3f78f5e` de #106) (même zone de la matrice) : `Store::revoked()` sans
`now`/`grace` (Memory + Postgres : tous les révoqués), `Options::crl_grace` et `OPENEIDAS_CRL_GRACE` supprimés
(12 appelants), `extensions::expired_certs_on_crl` (2.5.29.60, GeneralizedTime = `notBefore` de l'autorité) sur la
CRL et l'ARL, test `an_expired_revoked_certificate_stays_on_the_crl_which_declares_it` (+ assertion dans le test
d'ARL), étape kind « Vérifie le certificat TSU et la CRL avec openssl » grep 2.5.29.60, matrice : 411-1
`CSS-6.3.10-04` et **nouvelle norme 411-2 V2.6.1 (2025-06)** `CSS-6.3.10-02/-03/-05` (ajoutée à
`STANDARDS_WITH_IDS`), CA.md §6/§9, CPS.md. Deux mutations tuées. **CodeQL sur #106** : 5 faux positifs
`rust/hard-coded-cryptographic-value` sur `openssl_request(.., true)` (paramètre nommé `nonce`) → corrigé sur #106
(`flag: &str`, `"-nonce"`/`"-no_nonce"`), O-b rebasée. **T-a faite : PR #108** (`feat/sntp-hardening`, base `dev`) : `ntp.rs` découpé en `build_request`/`parse_response`,
transmit à 16 bits aléatoires et originate exigé à l'identique, LI ≠ 3, VN 3/4, mode 4, strate 1..15, horodatages
non nuls, RTT ≥ 0 et ≤ `max_rtt` (`OPENEIDAS_TIME_MAX_RTT`, 1 s, `Options::max_rtt`, `oe-config::time_max_rtt`),
`NtpSample::leap` rendu ; serveur UDP local dans les tests ; 4 mutations tuées ; matrice TIS-7.7.2-04/-05 en
écart avec cible NTS (T-c). **T-b faite : PR #109** (`feat/leap-second`, empilée sur #108) : `Sample::leap`/`Status::leap`, `time.leap_second`
(phases `annoncee`/`appliquee`, `Monitor::record_leap`), `leap_second_blocks` (dernière minute du jour UTC + mesure
antérieure au changement de jour), `leap_poll_due` dans le thread de sondage, `/healthz` `time_source.leap_second`,
test du binaire avec `fake_ntp_server(1)` dans `serve.rs` (env `OPENEIDAS_TIME_SOURCES` surchargé après `command()`),
matrice TIS-7.7.2-07/-08/-09 couverte, CPS B.2 (exigence d'exploitation : saut, pas de lissage, `[À COMPLÉTER]`).
Trois mutations tuées. **T-c faite : PR #110** (`feat/nts`, empilée sur #109) : `oe_timesource::nts` (NTS-KE rustls TLS 1.3, ALPN
`ntske/1`, AEAD 15, exportateur `EXPORTER-network-time-security`, cookies, `query` avec Unique Identifier / Cookie /
placeholders / Authenticator AES-SIV via `aes-siv`), `oe_timesource::testing::local_nts_server(Tamper)` (CA openssl,
`rustls::ServerConnection`, UDP authentifié ; `ca_pem` pour `OPENEIDAS_TIME_NTS_CA_FILE`), `Options::nts_extra_roots`,
`Sample::authenticated`, sources `nts://`, `oe-config::time_nts_ca_file`, test du binaire, matrice TIS-7.7.2-04/-05
couverte (25). Compose : `nts://ptbtime1.ptb.de` ; chart inchangé (bascule du staging = décision de Philippe, sortie
TCP/4460). Deux mutations tuées. **Toute la série P1 (J, O, T) est en PR.**
**Correctifs du jour sur #106** (`da927f7`, `+1`) : le répondeur OCSP refusait la CRL de la CA (« INTEGER not
canonically encoded ») — `ca-server` encodait le cRLNumber sur 8 octets (`Int::new(&u64::to_be_bytes())`) ; lecture
brute de la grandeur côté OCSP (`der_integer_magnitude`), encodage canonique `Uint` côté CA + test strict ; l'étape
kind du nonce ne cherche plus le mot « nonce » (openssl l'affiche dans l'extension) mais « no nonce in response » /
« nonce verify error » ; module `tests` déplacé en fin de `oe-ocsp-core/src/lib.rs` (clippy). #107 rebasée deux fois
(conflit sur la fin d'`issuance.rs`, recomposé). **À surveiller** : la CI de #106/#107 (compose, kind, Playwright :
7 tests e2e `ra-console` en timeout sur #106, a priori sans rapport — à relancer si ça persiste après le correctif).
**Pile et ordre de fusion proposés** : #104 (rustls) → #102 → #103 → #105 (J) ; #106 → #107 (O) ; #108 → #109 → #110
(T) ; chaque PR empilée est à rebrancher sur `dev` (`gh api -X PATCH … -f base=dev`) après la fusion de sa base.
**Piège du jour** : quatre avis RustSec sur `rustls` 0.23.45 (RUSTSEC-2026-0346 à 0349) cassent `cargo audit`
sur `dev` et toute PR → PR `chore(deps)` séparée vers `dev` (`cargo update -p rustls`), comme #97.
À savoir : le jeton du sceau est journalisé en `timestamp.granted` ; `tsa-server` est un binaire sans
`lib.rs`, les tests sont dans `seal.rs` ; deux instances du binaire partagent sans souci le même token
SoftHSM dans `serve.rs`.

**Étape 5 (workflow d'incident, WEBUI §6) — découpage 5a → 5b → 5c validé le 2026-10-12**, une PR
par tranche vers `dev`. **5a** : migration 0008 (`incidents`, `incident_actions`, dans `oe-castore`,
droits dans `ra_console_grants.sql`), `POST /api/v1/incidents`, `GET /api/v1/incidents?state=`,
`GET /api/v1/incidents/{id}` (les deux lectures ne sont pas au §5 : écart assumé). **5b** : actions
et clôture. **5c** : frontend `/incidents` selon `UI-UX.md` (pas de maquette d'incident).
Décisions de l'utilisateur : **journal bloquant, journal d'abord** pour toute écriture d'incident
(l'envoi S3 reste au mieux) ; **lien vers une action = référence après coup, vérifiée** dans la table
`actions` (`body_hash` recopié), aucun chemin d'exécution nouveau ; **la clôture exige une assertion
WebAuthn vérifiée par `ra-console` elle-même** et conservée avec le dossier (ouverture : session
seule). À noter : c'est le **premier vrai contrôle de rôle de `ra-console`** (`ra_operateur`),
`ca-server` ne voyant rien passer — garde de sécurité à tester par mutation.
**5a mergée : #98** (`b86de20`, autorisation `--admin` donnée pour elle le 2026-10-12) : migration 0008
(`incidents`), ouverture et lecture, `Recorder::record` (écriture bloquante, à côté d'`append`).
**5b mergée : #99** (`05bfef5`, autorisation `--admin` donnée pour elle) : migration 0009
(`incident_actions`, `incident_closures`, déclencheurs, challenge `incident_close`), entrées, clôture
signée, `LoginService::begin_reassertion`/`finish_reassertion` (réutilisable pour le libre-service §10).
**5c mergée : #100** (`4e14f16`, autorisation `--admin` donnée pour elle le 2026-10-13) :
`web/src/incidents.ts`, compteur dans `shell.ts`, `sign.ts` généralisé (`Signing.prepare`, corps figé en
texte), CSS, `e2e/incidents.spec.ts`, `dist` reconstruit. **L'étape 5 est complète et sur `dev`.**
Aucune PR ouverte hormis #5. Run de `dev` sur `4e14f16` : **vert**, staging réépinglé dessus. L'état réel du
staging reste à vérifier à la reprise (voir plus bas).
**À faire relire par antigravity** (pas de maquette d'incident). Reste possible : sélecteur d'actions à rattacher (aujourd'hui, identifiant à recopier), pagination.
Astuce : pour juger une mise en page, un spec Playwright temporaire `e2e/zz-*.spec.ts` avec
`page.screenshot` vers le scratchpad, supprimé ensuite ; `git checkout -- bin/ra-console/web/test-results`.
Pièges : ne plus toucher à une migration déjà appliquée à la base de test partagée (`oe-pg-test`,
base `postgres`) sans recréer le conteneur ; pour isoler une garde doublée par une autre, neutraliser
l'autre dans le test (ex. `DELETE FROM login_counters` avant de rejouer une assertion).
Piège zsh : `$var` non découpé en mots (`${=var}` ou `xargs -a`).

**2026-10-12 — fusion de #92, #95, #93, #94 et accélération de la CI.** Autorisation `--admin` donnée
par l'utilisateur ce jour pour #92, #93, #94, #95, #96 et #97 uniquement (pas pour #5 ni les PR futures).
Mergées sur `dev` : **#92** (`48eae65`, noms de base PostgreSQL uniques), **#95** (`825389b`, CI),
**#93** (`b21cd94`, arc d'OID 67027), **#94** (`3b49432`, 6d, explorateur d'audit : le frontend, étape 6, est complet).
**#97** (`6a9e47f`, `quinn-proto` 0.11.19 : trois avis RustSec publiés le jour même cassaient `cargo audit`
sur `dev` et sur toute PR), **#96** (`a82074b`, `owner: otspi`). **`dev` est entièrement vert sur `a82074b`**
(run 38293181329, 11 min), aucune PR ouverte hormis #5.
#84 et #88 étaient déjà mergées (le paragraphe du 2026-09-30 les dit encore bloquées : périmé).
- **CI accélérée (#95)** : run complet de 45 min à ~11 min. `num-bigint-dig` en `opt-level = 3`
  (profils dev/test : la génération de clés RSA des tests dominait, 63 s → 2 s sur `tsu_certificate`) ;
  une seule passe `cargo test --workspace --features oe-castore/postgres` (PostgreSQL + SoftHSM, même
  garde « test PostgreSQL ignoré ») ; `cargo audit` précompilé (`taiki-e/install-action`) ; un cache
  Docker par image (`scope`), relu par le job kind avec le même `VERSION` ; `build` n'attend plus
  `test`, mais `publish` exige `[build, test]`. En local, la même passe tourne en ~40 s.
  Chemin critique restant : la démo compose (~7 min, `scripts/bootstrap.sh` reconstruit les images).
- **Épinglage du staging** : le job échouait sur `dev` depuis #88 (`create-github-app-token` demandait
  `owner: open-eidas` → `repos/open-eidas/deploy/installation` 404). Corrigé par #96, **vérifié** : le job est vert et
  `otspi/deploy` a reçu `dc242c1` (« Épingle le staging sur …@a82074b »). **Chaque push sur `dev`
  réépingle désormais le staging et ArgoCD le déploie** (il était resté sur `2c7d29f` du 2026-09-19).
  **Constat du 2026-10-12 à 19:07 UTC (16 min après l'épinglage), depuis l'extérieur : le staging sert
  encore les anciens binaires** — CA : `/api/v1/conformance` rend 28 exigences (36 sur `dev`), route
  `.arl` de la racine en 404, CRL sans l'extension `67027.3.1` ; OCSP : `good` pour la série jamais
  émise `0x7e57` (le nouveau répondeur refuserait cette CRL) ; TSA : `genTime` sans millisecondes.
  Services en ligne, donc les Deployments (`Recreate`) n'ont pas encore reçu le nouveau tag : à voir
  dans ArgoCD (aucun accès au cluster d'ici). Paquets GHCR publics, chart rendu sans erreur avec
  `values-staging.yaml`.
  **Suites staging de #93 : rien à faire dans `otspi/deploy`** — l'OID de politique vient du
  `values.yaml` de `dev` (le TSA de staging émet déjà en `67027.9.1.1.1`, jeton vérifié), et le lien
  interne n'y est pas activé (`ca.internal.enabled: false`), donc aucun certificat interne à réémettre.
  **Point de bascule à surveiller** : dès que la nouvelle image OCSP démarre, elle refuse toute CRL
  sans l'extension des séries émises ; il faut que la nouvelle CA ait republié sa CRL (sinon OCSP en
  erreur jusqu'à la republication).
- `cargo audit` peut virer au rouge sans aucun changement du dépôt (base RustSec mise à jour en
  cours de journée) : comparer le nombre d'avis chargés entre deux runs avant de chercher ailleurs.
- **Ménage local (2026-10-12)** : 30 branches locales orphelines supprimées (toutes fusionnées, tête
  locale = tête de PR), ainsi que les deux worktrees d'agents `.claude/worktrees/agent-*` (propres,
  17 Go de `target/`) et leurs branches, puis `docs/matrix-after-audit-fixes`, `fix/ghcr-owner-otspi`
  et `feat/ra-console-audit-explorer` (têtes de #84, #88 et commit 6d-1 de #94).
  Sur GitHub : 38 branches distantes fusionnées supprimées (tête = tête de PR pour toutes) ; il ne
  reste que `dev`, `main` et `release-please--branches--dev`. En local : `dev`, `main` et
  `feat/provenance-mirror` (worktree `open-eidas-mirror`, sans amont désormais). Les mentions de ces worktrees plus bas sont périmées.
- Piège : ne jamais afficher la sortie de `gh pr checks --watch` (elle répète tout à chaque
  rafraîchissement) ; la jeter et relancer `gh pr checks` une fois à la fin.

**2026-09-30 — fusion de l'ensemble des PR en attente (demande de l'utilisateur : relecture complète,
puis squash-merge).** Relecture des 22 PR faite : aucun défaut bloquant. Fusion par vagues (rebase sur
`dev`, CI verte, `gh pr merge --squash --admin --delete-branch`, autorisé par l'utilisateur pour cette
pile ; règle de permission ajoutée par lui). **Pièges rencontrés** :
- GitHub traite les PR empilées comme une « stack » : impossible de changer la base par l'API
  (« part of a stack »), et **la suppression de la branche de tête mergée ferme les PR enfants** au
  lieu de les rebrancher. Solution retenue avec l'utilisateur : **ouvrir une nouvelle PR vers `dev`**
  (même titre, même corps, note « Remplace #N ») et commenter l'ancienne. Correspondances :
  #61→#75, #53→#76, #65→#77, #51→#78. Les enfants suivants suivront le même chemin.
- Conflits sémantiques (pas textuels) au rebase : `CeremonyOptions.public_url` (#56) manquait dans
  `bin/tsa-server/tests/serve.rs` (#63), `bin/ra-console/tests/action_challenge.rs` (#66) et
  `bin/ra-console/examples/e2e_console.rs` (#72) ; `Decider::approve` a gagné `&Via` (#58) : le test
  `issuance_immediately_republishes_the_crl_with_the_new_serial` (#55) devait le passer. Toujours
  lancer `cargo clippy --workspace --all-targets` (pas seulement les crates touchés) avant de pousser.
- `git rerere` est activé dans ce dépôt : les résolutions de conflits des simulations de rebase
  (branches locales `pre-*`, `pre70`) se rejouent au rebase réel. Vérifier quand même la compilation.
- La classification du mode automatique refuse `git reset --hard` dans les worktrees d'agents et la
  suppression de branches distantes : rebaser dans le worktree sans reset (`git -C … rebase --onto`).
- Après #56, `RootAuthority::revoke_authority` prend `&Via` (annotation `ca.authority_revoked`,
  commentaire obligatoire côté CLI) : fait dans #58.

**État des vagues** (2026-09-30, fin de la fusion) : mergées sur `dev` : #62, #60, #52, #55, #56, #57,
#64, #58, #75 (ex-61), #76 (ex-53), #77 (ex-65), #79 (ex-63), #80 (ex-54), #82 (ex-59), #81 (ex-66),
#83 (ex-67), #86 (ex-68), #85 (ex-69), #87 (ex-70), #89 (ex-71), #90 (ex-72), **#91 (ex-73, merge 3a0b4b5)**,
**#78 (ex-51, merge f636e6d)**. Audit P0/NC, étapes 3 et 4, frontend 6a/6b/6c/6e, déploiement, registre et
recherche d'audit sont donc sur `dev`. **Restent** : **#84** (docs, matrice 23 couvertes) et **#88**
(GHCR -> otspi), vertes mais **bloquées** : le jeton `gh` n'a pas la portée `workflow` (elles modifient
`ci.yml`) ; l'utilisateur doit lancer `! gh auth refresh -h github.com -s workflow`, puis
`gh pr merge 84|88 -R otspi/open-eidas --squash --admin --delete-branch`. **#5** (release-please) laissée à
l'utilisateur. GitGuardian sur l'ex-#68 (PR #86) laissé à l'utilisateur. Après #88 : passer les paquets
ghcr.io/otspi/* en public et vérifier la GitHub App sur otspi/deploy (organisation, hors dépôt).
**Reste côté produit** : l'explorateur d'audit dans le navigateur (étape 6d). **Pièges** : pousser une
branche sur une PR fermée par suppression de branche la rouvre (c'est ce qui est arrivé à #78, pas de
nouvelle PR nécessaire) ; les tests PostgreSQL nommant leur base par `as_nanos()` peuvent entrer en
collision entre tests parallèles (corrigé dans `action_challenge.rs` ; `db_guard.rs` a échoué une fois en
local, non reproduit, même motif probable : ajouter un compteur atomique).


**C-1 terminée : PR #56 ouverte** (`feat/authority-revocation-arl`, base `dev`, indépendante),
2026-09-26 soir. Contenu : migration 0007, `Store::revoke_authority`/ARL, CDP/AIA de l'émettrice,
`oe_ca_core::root::RootAuthority`, `ca-server authority revoke|publish-arl`, ARL initiale à la
cérémonie, routes `/download/<CN racine>.cer|.arl`, émission refusée par une émettrice révoquée
(relu à chaque émission). Toutes les vérifications vertes (fmt, clippy 1.97/1.98.1, tests avec
PostgreSQL, audit, `openssl verify -crl_check_all`, 3 mutations). **En attente de revue humaine et
des checks CI.** Restes notés dans `TODO.md` §0.

Des 7 NC majeures choisies : J-3 (#52), T-1 (#53), T-3 (#54), O-1 (#55), C-1 (#56) en PR.
**R-1/R-2 en cours**, découpage validé par l'utilisateur (2026-09-26) : **A** (R-2, chart Helm) —
**PR #57 ouverte** (`fix/helm-autoapprove-default`, base `dev`) ; puis **B** (R-1 : champ
`authenticated_via` `webauthn`/`cli` sur les événements de décision RA et de révocation, identité
système réelle côté CLI marquée « non authentifiée », commentaire obligatoire) ; puis **C** (commande
de revue a posteriori des décisions CLI, décision O4). **Décision : voie de secours CLI en
traçabilité seule** (WEBUI §20 : le CLI reste, jamais retiré ; le vrai contrôle est le RBAC
`kubectl exec`), **pas de PIN** façon `recover-admin`. Staging vérifié : `otspi/deploy`
(`apps/open-eidas-staging.yaml`) utilise `values-staging.yaml` de `dev`, qui garde l'approbation
automatique. **B faite : PR #58** (`feat/cli-decision-provenance`, base `dev`) — champ `authenticated_via` au nom
de §20 (anglais, choix de l'utilisateur), sous-champs en français (`identite_systeme`,
`authentifiee: false`, `uid`, `utilisateur`, `hote`) ; valeurs `webauthn`/`cli`/`automatique`.
**#56 et #58 se recouvrent** (`Issuer`, `main.rs`, `issuance.rs`) : rebaser celle mergée en second ;
après #56, annoter `ca.authority_revoked` en `Via::Cli`. **C faite : PR #59** (`feat/cli-decision-review`, **empilée sur #58**, tête de #58 à
l'ouverture : `7bb4b56`) — `ca-server audit cli-decisions`, acquittement tracé
(`ra.cli_decisions_reviewed`, choix de l'utilisateur), codes 0/1/2 (choix de l'utilisateur).
**Ordre de merge : #58 puis #59** (rebase `--onto origin/dev 7bb4b56` puis PATCH base=dev) ; #56 et #58
se recouvrent. **Les 7 NC majeures choisies sont toutes en PR** (#52 à #59). L'utilisateur a
ensuite choisi **D-1/D-2/D-3** (P0 docs/matrice), découpage **a → b → c** validé : **a faite, PR #60**
(`docs/align-docs-with-code`, base `dev`). **b faite : PR #61** (empilée sur #60,
tête `1eb46c1`). Les textes ETSI officiels ont été téléchargés et relus (etsi.org, `curl` avec un
user-agent de navigateur, sinon 403 ; `pdftotext -layout`) : 401 V3.2.1, 411-1 V1.5.1, 421 V1.3.1,
422 V1.1.1, TS 119 312 V2.1.1, 403-1 V2.3.1, 412-1 V1.7.1. **Piège** : ne jamais modifier une
migration déjà appliquée (même un commentaire) — `sqlx` en vérifie la somme. **c faite : PR #63**
(empilée sur #61, tête `d25ee8c`) ; elle contient le commit du **correctif #62** (base `dev`,
indépendante) : `error_response` d'`oe-tsa-core` encodait le `failInfo` avec un double octet « bits
inutilisés » (tous les refus RFC 3161 illisibles). **Ordre de merge : #62, #60, #61, #63.** Décisions
de l'utilisateur pour c : les jobs CI de démo comptent comme preuve « en service » ; écrire un test de
câblage plutôt que déclasser. **Les P0 D-1/D-2/D-3 sont tous en PR.** Ensuite, **retour au plan WEBUI, étape 3** (choix de l'utilisateur) : découpage **3a → 3b** validé ;
**décision : le lien assertion ↔ demande visée est contrôlé par `ca-server`** (champ `expect` sur
`/internal/v1/actions`, comparé au corps figé avant toute vérification ou consommation, ne peut que
restreindre). **3a faite : PR #64** (`feat/ra-console-action-challenge`, base `dev`) :
`POST /api/v1/webauthn/challenge`, `operator_hint` = session, seuls approve/reject, journal
`ra.action_challenge`. **3b faite : PR #65** (empilée sur #64, tête `37958f4`) :
`POST /api/v1/requests/{id}/approve|reject`, `expect` comparé par `oe_actions::Service::execute_expecting`
**avant** le retrait de l'état de la cérémonie (sinon l'assertion deviendrait inutilisable sur la bonne
route — vérifié par mutation). **Étape 3 complète côté API.** Ordre de merge : #64 puis #65.
**Étape 4 faite** (découpage 4a → 4b validé ; décision : la salle d'attente lit
`actions` de `ca-server`, SELECT ajouté au rôle de la console, pas de tables de collecte §8) :
**4a PR #66** (empilée sur #65, tête `457dc7e`), **4b PR #67** (empilée sur #66, tête `aac4dbc`).
Pile WEBUI : #64 → #65 → #66 → #67. Piège vu en 4b : un test de co-signature sur deux certificats
différents ne prouvait pas le contrôle d'`action_id` (le numéro de série suffisait) — toujours
construire le cas où **seule** la garde testée distingue.

**Parallélisation WEBUI (2026-09-27, demande de l'utilisateur)** : deux sous-agents (fork, worktree
isolé) + moi, tous empilés sur #67 : **#68** déploiement, **#69** registre, **#70** frontend 6a (moi).
Worktrees des agents dans `.claude/worktrees/agent-*` (branches extraites là-bas : pour y pousser un
correctif, travailler DANS le worktree). Frontend : TypeScript + esbuild, Playwright en CI (choix de
l'utilisateur) ; `web/dist` versionné, vérifié par la CI ; e2e = `examples/e2e_console.rs` + clé
SoftToken exportée (via `SoftTokenFile`) injectée par CDP. Piège : transports `internal` du SoftToken
→ l'authentificateur virtuel doit être `internal`. GitGuardian #68 à traiter par l'utilisateur. **6b : PR #71** (empilée sur #70). **6c : PR #72** (empilée sur #71). **6e : PR #73** (base #72, contient la fusion de #69 : merger #69 d'abord). CI : #68 tout vert sauf GitGuardian, #69 tout vert.

**État CI (2026-09-27)** : #49 à #65 tous verts. Vérifié dans les journaux de #63 : SoftHSM2 s'installe
sur le runner et `bin/tsa-server/tests/serve.rs` s'exécute réellement (pas ignoré). Les PR **empilées**
(base ≠ `dev`) n'ont ni CodeQL ni « Titre de PR conventionnel » : ces workflows ne ciblent que `dev`, ils
tourneront au rebase — pas un échec. Une étape CI distincte fait tourner les tests PostgreSQL et échoue
si l'un d'eux s'ignore. Piège : les jobs de démo tournent
en `OPENEIDAS_TIME_POLICY=monitor` (suspension prouvée seulement par `bin/tsa-server/tests/serve.rs`).

## 1. Où on en est

Étape 0 du plan WEBUI §15 (socle de confiance de `ca-server`) : **terminée**, sauf deux restes
(refus d'exécuter une clé sans chaîne valide ; renouvellement automatique du certificat du lien interne).
Étape 1 (`ra-console`) : squelette, relais de l'enregistrement de clé, retrait de `cryptoki`, et **1c
(connexion + sessions) entièrement livrée et mergée sur `dev`** (détail au §4). Il ne reste, côté code,
que la limitation de débit des routes anonymes — **décidée : à la Gateway seule**, reportée à la tranche
déploiement Helm de `ra-console` (TODO §2), aucun code applicatif prévu. **Étape 2 (lecture seule)
terminée** : découpage A→D (§5) intégralement proposé, 3 PR ouvertes (#49, #50, #51).

**2026-09-26 (après-midi) : priorité changée sur demande explicite de l'utilisateur.** Après l'état des
lieux (pile 2b complète), l'utilisateur a choisi de traiter en priorité les **7 non-conformités majeures
restantes de l'audit du 2026-09-25** (`docs/AUDIT_2026_09_25.md`, `TODO.md` §0) plutôt que de poursuivre
le plan WEBUI (étapes 3 à 6). Ordre choisi par l'utilisateur : **J-3 d'abord** (traçabilité des jetons
TSA) — **PR ouverte (#52)** — puis **T-1** (exactitude de `genTime`) — **PR ouverte (#53, empilée sur
#52)** — puis **T-3** (expiration de la clé TSU) — **PR ouverte (#54, empilée sur #53)** — puis **O-1**
(statut OCSP pour un certificat jamais émis) — **PR ouverte et entièrement verte (#55, indépendante,
base `dev`)**, après deux allers-retours avec la CI qui ont révélé deux vraies latences introduites par
O-1 (voir §3, piège de branche) : `oe_raflow::Flow::issue` ne republiait pas la CRL après émission
(corrigé : republication immédiate, même raisonnement que `ca-server revoke`) ; le répondeur OCSP ne
rafraîchissait sa CRL en cache que périodiquement, laissant un certificat tout juste émis `unknown`
jusqu'au prochain cycle (corrigé : rafraîchissement à la volée sur un `unknown`, borné à 1 par 2 s pour
éviter qu'une interrogation de séries au hasard ne déclenche un fetch à chaque appel). Pièges
rencontrés : `der::asn1::GeneralizedTime` interdit les fractions de seconde (profil RFC 5280) ; RFC 3161
ne reprend pas cette restriction pour `TSTInfo.genTime` — résolu par un encodage DER à la main
(`oe_rfc3161_asn1::gen_time`), compatible octet pour octet avec le corpus historique. `openssl req
-addext`/`openssl ca -crlexts` ne connaissent ni `privateKeyUsagePeriod` ni un OID privé arbitraire par
leur nom (« extension setting not supported ») — résolu en donnant le DER brut dans les deux cas (voir
`tests/fixtures/tsa/README.md` et `tests/fixtures/ocsp/README.md`) ; `x509_cert` fournit déjà le type
`PrivateKeyUsagePeriod`, pas d'encodage à la main côté production pour T-3. C-1 : PR #56. Restent, non commencées :
R-1, R-2 — proposer un découpage et le faire valider avant chacune, comme pour les tranches
précédentes.

Le dépôt est **`otspi/open-eidas`** (l'ancien nom `open-eidas/open-eidas` redirige : `git push` et
`gh api` fonctionnent, mais `gh pr create` se trompe de propriétaire → toujours
`gh pr create -R otspi/open-eidas --head <branche> --base <base> …`).

**PR #46 mergée** (2026-09-26, `--admin` en squash sur autorisation explicite, `9f4487a`) : double licence
`EUPL-1.2 OR AGPL-3.0-only`, `PROVENANCE.md`, `scripts/provenance.py`, modèle de PR, `deny.toml` + job CI
`licenses`. Archive de provenance : `~/archives/open-eidas/provenance` (lancer `scripts/provenance.py archive`
avant chaque fusion). Worktree et branche (locale et distante) supprimés.

Une PR ouverte, sans lien avec ce travail : **#5** (release-please, `chore(dev): release 0.2.0`, se
met à jour toute seule à chaque commit sur `dev`, checks verts, laissée en l'état sur demande explicite
de l'utilisateur — la merger déclenche un tag `v0.2.0`, décision qui lui appartient).

Un fichier **`docs/AUDIT_2026_09_25.md`** est apparu, non suivi, généré pendant cette session par un
autre processus (probablement une revue lancée en parallèle par l'utilisateur) : jamais touché, jamais
commité par ce travail. L'utilisateur l'a intégré à `TODO.md` (§0 : constats et plan de remédiation
P0/P1/P2). Un des items **P0 (J-2, journal bloquant partout)** recoupe exactement le chantier Recorder
en cours ci-dessous — les deux ont convergé sans concertation préalable.

## 2. Décisions prises avec l'utilisateur (à ne pas rediscuter)

- **PEN d'OTSPI : 67027** (2026-10-05). Arc de test `67027.9`, production `67027.1`. OID du lien interne `67027.2.9.1` (client) / `.2` (serveur), extension CRL `67027.3.1` : allocation proposée et choisie avec l'utilisateur, **à faire approuver par le CPC**. **PR #93** (`feat/oid-arc-pen-67027`, base `dev`). Dépôt de gouvernance : **PR #13** de `otspi/organisation` (`docs/oid-pen-67027`, base `main`) : `oid-arc.md` §4 bis (registre), statut, cases. `scripts/set-oid-arc.sh` modifie aussi `.claude/worktrees/agent-*` (grep récursif) : restaurer ces worktrees après (`git -C … restore --worktree -- .`).
- Révoquer un certificat : **2 `ca_operateur`** ; créer/retirer le rôle `admin` : **2 admins**. Fenêtre d'une action à quorum : **24 h** (chaque challenge WebAuthn reste à 5 min).
- `operators audit` : **journal obligatoire** pour les ancres (amorçage, récupération), le journal fait foi. Pas de lancement au démarrage dans cette tranche.
- `reconcile` : clé perdue → **acquittement explicite** et motivé (`--acknowledge-missing`), jamais en silence. Contrôle au démarrage et toutes les 60 s ; une divergence doit persister 3 s pour fermer la garde.
- `ra-console` **vérifie elle-même** les assertions de connexion (`oe-webauthn`, donc OpenSSL). Une session n'est pas une ancre de confiance : `ca-server` re-vérifie chaque action.
- **Connexion par nom, réponses uniformes** (le sans-nom du §16 n'est pas réalisable proprement : l'enregistrement attesté de `webauthn-rs` demande `resident_key: discouraged`, et la voie `resident-key-support` est « still in development »). Décoy à une seule clé (limite assumée, documentée dans `oe_webauthn::decoy`).
- `ra-console` **ne lie pas `cryptoki`** (feature `pkcs11` d'`oe-hsm`) ; le futur `Dockerfile` doit construire avec `-p ra-console`. `oe-ca-core` désactive elle aussi les fonctionnalités par défaut de son lien vers `oe-hsm` pour la même raison (voir piège ci-dessous).
- CodeQL : faux positifs sur des certificats (données publiques) traités en **remaniant le code** (ne plus afficher ce qui dérive d'un `SubmitResult`), pas en écartant les alertes.
- Session HTTP de `ra-console` : **8 h fixes** (pas de fenêtre glissante) ; purge périodique en **tâche de fond intégrée à `serve`** (comme `registry_check` côté `ca-server`), pas de sous-commande CLI ; limitation de débit **à la Gateway seule**.

## 3. Pièges et pratiques (chacun a coûté du temps)

- **`git add` : chemins de fichiers explicites, jamais un dossier.** `docs/mockups/` (antigravity) est non suivi et ne doit jamais être commité. Après commit : `git show --stat HEAD | grep -c mockups` doit valoir 0. **Depuis le 2026-09-25 : remorque `Co-authored-by: Claude <noreply@anthropic.com>` obligatoire** sur tout commit assisté (orthographe exacte, sans nom de modèle), auteur et committer humains, aucune autre métadonnée d'IA ; messages **en français** ; corps de PR suivant `.github/pull_request_template.md`, sans la ligne « Generated with Claude Code ». Voir PROVENANCE.md, et lancer `scripts/provenance.py archive` avant chaque fusion.
- **La CI utilise Rust 1.98 (`stable`), le local est en 1.97** : des lints existent en CI seulement (`result_large_err`…). Toolchain installée à côté : `CARGO_TARGET_DIR=/tmp/target-198 cargo +1.98.1 clippy --workspace --all-targets -- -D warnings`.
- **PostgreSQL de test** : conteneur `oe-pg-test`, port 55432, `OE_CASTORE_TEST_DSN=postgres://postgres:test@localhost:55432/postgres`. Changer de branche fait parfois échouer les tests (migration manquante) : **recréer le conteneur** (`docker rm -f oe-pg-test && docker run -d --name oe-pg-test -e POSTGRES_PASSWORD=test -p 55432:5432 postgres:17-alpine`).
- **6d (explorateur d'audit), découpage 6d-1 → 6d-2 validé (2026-10-06)** : 6d-1 = frontend seul sur l'API actuelle, commité sur `feat/ra-console-audit-explorer` (base `origin/dev`), mutation du blocage vérifiée ; 6d-2 **faite** (`feat/ra-console-audit-breaks`, **empilée sur 6d-1**, tête de 6d-1 : `54fdd09`) : `prev`/`hash` par entrée, `broken` (source, nature, séquence ou ligne), erreur de relecture locale = 503 et non rupture. **Décision de l'utilisateur : une seule PR (#94, `feat/ra-console-audit-breaks`, base `dev`) contenant les deux commits** ; la branche locale `feat/ra-console-audit-explorer` (6d-1 seul) n'est pas poussée. L'e2e d'audit passe par un S3 simulé dans `examples/e2e_console.rs`. Piège : `bin/ra-console/web/test-results/` est **suivi** par git et Playwright le modifie : `git checkout -- bin/ra-console/web/test-results` avant tout commit.
- **Binaires de test périmés dans `target/`** (2026-10-05) : `cargo test --workspace` a exécuté pendant des jours des binaires compilés depuis une *autre copie* du dépôt (`…/scratchpad/int/`, simulations de rebase) : cargo les jugeait « Fresh » (le hash ne dépend pas du chemin absolu) alors que `CARGO_MANIFEST_DIR` y est figé. Symptômes : `oe-audit cross_compat` et `oe-enroll against_local_server` en échec dans le workspace mais verts avec `-p` ; `no_pkcs11` et `references` verts **sans valeur** (ils lisaient l'ancienne copie). Contrôle : `strings target/debug/deps/<bin> | grep scratchpad/int/`. Remède : `cargo clean -p <paquet>`. Éviter de compiler une copie du dépôt avec le même `CARGO_TARGET_DIR` (utiliser un `CARGO_TARGET_DIR` à part pour les simulations).
- **Filtres de sortie qui masquent les échecs** : `| head -N` après un tri coupe les lignes `FAILED`. Toujours `grep -E "FAILED|panicked|^error|[1-9][0-9]* failed"` sur le fichier complet, et lire le code de sortie.
- **`mut()` de mutation** : vérifier que le test visé échoue *pour la bonne raison* ; un mutant qui survit est un test manquant. Un motif que `rustfmt` a déplacé fait échouer la mutation en silence.
- **Ajouter une dépendance *normale* (pas dev) à `ra-console` peut réintroduire `cryptoki`** sans qu'aucun message ne le dise : promouvoir `oe-actions` en dépendance normale (pour 1c) a réintroduit la chaîne `oe-actions → oe-raflow → oe-ca-core → oe-hsm` (défauts non désactivés). `tests/no_pkcs11.rs` l'a détecté immédiatement — **le relancer après tout ajout de dépendance normale à `ra-console`**. Corrigé une fois pour toutes en désactivant les fonctionnalités par défaut de la dépendance `oe-hsm` d'`oe-ca-core` (elle n'utilise que le trait `SigningToken`) ; `ca-server`, qui redemande `oe-hsm` directement, n'est pas affecté.
- **Le lien interne ne contrôle le certificat client qu'à la poignée de main** : `ra-console` n'a donc pas de réutilisation de connexion (`pool_max_idle_per_host(0)`).
- Actions déjà autorisées sur GitHub : relancer un job échoué. Écarter des alertes de sécurité ou relancer d'autres jobs : demander.
- Piège de rebase d'une pile de PR : après un rebase de la PR N, la PR N+1 reste basée sur l'**ancienne**
  tête de N ; noter les têtes d'origine avant de pousser (`git rev-parse origin/<branche>`).
- **Ajouter un nouvel état dérivé republié périodiquement (CRL, cache…) introduit une fenêtre de
  latence pour tout ce qui en dépend désormais pour un « bon » résultat, pas seulement pour un
  mauvais.** Repéré par la CI (jobs de démonstration réels, pas les tests unitaires) sur O-1 (PR #55) :
  ajouter la liste des séries émises à la CRL a rendu un certificat *tout juste émis* `unknown` en OCSP
  jusqu'à la prochaine republication/rafraîchissement — un cas que l'ancien défaut (`good` sans
  vérification) ne pouvait pas exposer. Deux correctifs, à généraliser : (1) republier immédiatement
  après toute action qui change ce que l'état dérivé doit refléter, pas seulement après les cas
  « négatifs » (révocation) déjà couverts ; (2) côté consommateur d'un cache périodique, un
  rafraîchissement à la volée **borné** (compteur de dernier essai partagé, pas par requête) avant de
  rendre un résultat défavorable par défaut. Les tests unitaires ne l'auraient pas trouvé : ils
  n'exercent jamais le délai réel entre deux cycles périodiques — les jobs « Amorçage complet +
  démonstration » (démo réelle, timing réel) sont irremplaçables pour ce genre de régression.

## 4. Étape 1c : connexion et sessions — **terminée et mergée sur `dev`**

- **1c-1 (PR #34)** : `login/begin {name}` → options WebAuthn de même forme que le nom existe ou non
  (clé factice dérivée de `HMAC-SHA256(secret du service, nom)`, `oe_webauthn::decoy_authentication_challenge`) ;
  `login/finish {challenge_id, credential}` → assertion vérifiée par `ra-console` elle-même contre le
  registre en lecture seule, challenge à usage unique dans `webauthn_challenges` (5 min), compteur
  anti-clonage dans `login_counters` (jamais `webauthn_credentials.sign_count`, en lecture seule pour
  `ra-console`).
- **1c-2a (PR #37)** : `login/finish` ouvre une session (cookie `HttpOnly; Secure; SameSite=Strict`,
  256 bits, 8 h fixes), `GET /api/v1/me`, `POST /api/v1/logout`. Identité et rôle relus en base à chaque
  requête (`ra_console::session::Sessions`), jamais mis en cache.
- **1c-2b (PR #39)** : purge périodique des sessions et challenges expirés, `ra_console::purge` (tâche
  de fond dans `serve`, `OPENEIDAS_PURGE_INTERVAL_SECONDS`, 60 s par défaut).

Au passage (hors pile, repéré en cours de route) : **#38** (mise à jour de `SECURITY.md` après le
passage en Rust, ouverte par l'utilisateur) mergée `--admin` (checks tous verts, sans lien avec 1c).

## 5. Étape 2 : lecture seule (en cours)

Découpage validé avec l'utilisateur (2026-09-25) :

- **2a (PR #40, mergée)** : `GET /api/v1/requests?state=PENDING` (lit `enrollment_requests`
  directement, en SQL, pas via `oe-castore` — son `Postgres::open` exécute les migrations, hors de portée
  du rôle restreint de `ra-console`) + `crate::http::authenticate`, extracteur de session réutilisé par
  `/api/v1/me` et cette route. **Le rôle minimal documenté n'est pas vérifié** : §3 dit explicitement que
  les contrôles de rôle de `ra-console` ne sont qu'un affichage, la vraie barrière reste côté `ca-server`
  pour l'écriture — donc pour une route de lecture seule, authentifié suffit.
- **2b (reportée)** : `GET /api/v1/audit/search`. Cette route doit relire **deux** journaux chaînés
  (§7) — celui de `ca-server` et celui de `ra-console`.

  **Décisions (2026-09-25, utilisateur)** :
  - Les deux journaux visent un **stockage objet compatible S3, auto-hébergé** (MinIO, Garage, Ceph…) —
    pas AWS, pas de volume partagé, pas de route interne dédiée. Attention : `oe-replicate` existant
    (WebDAV) a été choisi *précisément* pour éviter une dépendance à un fournisseur cloud
    (« hébergement souverain », commentaire du crate) — S3-compatible-auto-hébergé reste dans cet
    esprit, un vrai S3 géré (AWS) ne l'aurait pas respecté. Ne pas remplacer `oe-replicate`, qui reste
    utile tel quel pour qui préfère WebDAV.
  - **Nouveau crate dédié** pour le client S3 (SigV4, PUT/GET/LIST), pas une extension d'`oe-replicate`.

  **Découpage validé, A → D, une PR par lettre, chacune proposée avant d'écrire** :
  - **A. Faite (PR #41, mergée).** `ra-console` a maintenant sa propre instance `oe-audit`
    (`OPENEIDAS_RA_AUDIT_FILE`, `crate::audit`) : `ra.login_succeeded`/`ra.login_refused` (raison
    réelle)/`ra.session_opened`/`ra.session_closed`.
  - **B. Le chantier « Recorder » (async/propagation/réordonnancement) est terminé — voir ci-dessous.**
    Nouveau crate client S3 **fait et mergé** (PR #43). Reste, maintenant débloqué : câbler `ca-server`
    dessus (pas encore commencé).
  - **C. Fait, PR ouverte (#50, `feat/ra-console-audit-s3`, base `dev`, indépendante de #49).** `ra-console`
    écrit le sien (de A) sur le même S3, best-effort (décision distincte de #49 : un journal qui n'écrit
    pas ne doit pas faire échouer une connexion, l'envoi S3 suit la même règle — `tokio::spawn` détaché
    après l'écriture locale). Mêmes variables `OPENEIDAS_S3_*` que `ca-server`, `OPENEIDAS_S3_KEY` les
    distingue. `tests/s3_journal.rs` : copie identique quand S3 marche, ni blocage ni panique quand il
    est en panne, testé par mutation. **En attente de revue humaine et des checks CI.**
  - **D. Fait, PR ouverte (#51, `feat/ra-console-audit-search`, empilée sur #50 — pas `dev`).**
    `GET /api/v1/audit/search` lit et vérifie les deux chaînes depuis S3 (même logique que
    `ca-server verify-audit`, docs/WEBUI.md §7). Deux décisions : chaîne rompue → blocage total
    (`chain_verified: false`, `results` vide, même si l'autre chaîne est saine) ; S3 non configuré →
    503 (`ra-console` n'a aucun accès local au journal de `ca-server`). Nouvelle variable
    `OPENEIDAS_S3_CA_KEY` (défaut `ca-server/audit.log`). `tests/audit_search.rs` : fusion/tri,
    filtre par série, panne S3 distinguée d'une chaîne rompue, blocage testé par mutation.
    **En attente de revue humaine et des checks CI. Merger #50 avant #51 (pile).**

  **La pile 2b est maintenant complète (A→D)** : #41 (mergée), #49 (ca-server, en attente),
  #50 (ra-console écrit, en attente), #51 (ra-console lit, empilée sur #50, en attente).

  `oe-replicate` n'a par ailleurs jamais été câblé dans aucun binaire (grep vide sur `bin/*/src`) : rien
  à migrer depuis lui, seulement à construire à côté.

  ### Chantier découvert en cours de route : `Recorder` async, propagation de l'échec

  Décision de l'utilisateur (2026-09-25) : un échec du push S3 doit **bloquer** l'opération en cours
  (émission, révocation, décision RA…), pas juste être journalisé à côté. Trois couches de complexité
  trouvées en creusant, dans cet ordre :
  1. **Async** : `oe_ca_core::Recorder`/`oe_raflow::Recorder` (et `oe-actions` qui réutilise celui de
     `oe-raflow`) sont synchrones ; un push S3 est forcément asynchrone.
  2. **Propagation** : aujourd'hui, l'échec du journal est **ignoré partout** (`let _ = recorder.append(...)`)
     — le rendre async ne suffit pas, il faut aussi cesser de l'ignorer.
  3. **Ordre** : dans `oe-ca-core`, le journal s'écrivait *après* la mutation durable du store
     (`save_certificate`, `store.revoke`, `store.save_crl`) — propager son échec à ce point ferait échouer
     `issue()`/`revoke()`/`publish_crl()` pour une action déjà faite, irréversible. Décision : **le journal
     doit réussir avant l'opération irréversible**, pas après — réordonnancement, pas juste propagation.

  Chantier scindé en plusieurs PR, une par crate/famille, validées une à une — **toutes les quatre
  faites** :
  - **Fait (PR #42, mergée).** `oe_ca_core::Recorder` async ; `Issuer::record` propage l'échec
    (`CaError::Other`) ; réordonnancement dans `run_ceremony`, `issue`, `revoke`, `publish_crl` (journal
    avant la mutation durable qui suit). 4 tests dédiés (un `FailingRecorder` par flux) prouvent qu'aucune
    mutation n'a lieu quand le journal échoue. Ne touche ni `oe_raflow` ni `oe_tsa_core`.
  - **Fait (PR #45, mergée).** `oe_raflow::Recorder` async, même traitement. Deux cas trouvés en
    creusant, traités différemment :
    - `Flow::open` (nouvelle demande) : réordonné comme `oe-ca-core` (journal avant `create_request`).
    - `Decider::decide` (approve/reject RA) : **exception documentée, décidée avec l'utilisateur** —
      l'écriture optimiste (`update_request`, CAS sur l'état `Pending`) reste *avant* le journal, parce
      qu'elle départage deux décisions concurrentes sur la même demande. Journaliser avant risquerait de
      consigner une décision qui perd la course et n'a jamais eu lieu. Conséquence assumée et testée : un
      échec du journal après `decide()` laisse la décision déjà appliquée en base, malgré l'erreur rendue
      à l'appelant.
    - `oe-actions` avait déjà la propagation (`Error::Journal`, commentaire « le journal d'abord ») —
      seul le passage en async restait à faire (`.await` ajouté à 14 sites), plus deux écritures
      délibérément best-effort (refus d'amorçage, échec de republication de CRL) laissées telles quelles.
  - **Fait (PR #47, ouverte sur `dev`).** `oe_tsa_core::Recorder` et `oe_timesource::Recorder` (item
    **P0 J-2** de l'audit du 2026-09-25, `docs/AUDIT_2026_09_25.md`/`TODO.md` §0). **Restent
    synchrones**, à la différence des deux précédents — décidé avec l'utilisateur : leurs appelants
    tournent déjà hors de tout exécuteur async (`Authority::timestamp` sans `spawn_blocking`, `Monitor`
    dans un thread dédié pour les requêtes NTP bloquantes). `oe_tsa_core` : journal propagé
    (`TsaError::Other`), `timestamp.granted` réordonné avant la signature HSM. `oe_timesource` : pas
    d'appelant à faire échouer (mesure périodique) — un échec de journal marque `Status.traceable =
    false`, `now()` s'en charge ensuite.
  - **Fait, PR ouverte (#49, `feat/ca-server-audit-s3`, base `dev`).** `ca-server` câblé sur `oe-s3`
    (2b-B proprement dite) : `OPENEIDAS_S3_ENDPOINT/BUCKET/REGION/ACCESS_KEY/SECRET_KEY/KEY`, toutes
    optionnelles ensemble (sans `OPENEIDAS_S3_ENDPOINT`, purement local, rétrocompatible).
    `AuditRecorder` écrit en local puis, si configuré, relit le fichier entier et l'envoie en une fois
    à S3 (pas d'ajout partiel). Bloquant comme les trois PR précédentes. `tests/s3_journal.rs` (contre
    un vrai PostgreSQL et un serveur HTTP qui se comporte comme un service S3-compatible, MinIO
    indisponible dans cet environnement) : preuve que la copie envoyée est identique au journal local,
    et qu'un envoi S3 en échec ne commit rien en base — testé par mutation. `cargo fmt/clippy` (1.97 et
    1.98.1) / `cargo test --workspace` / `cargo audit` tous verts avant l'ouverture. **En attente de
    revue humaine et des checks CI.**

  ### Piège d'environnement rencontré pendant 2b-B/2b-C

  Le conteneur `oe-pg-test` par défaut (`docker run` sans `--shm-size`) a une mémoire partagée de 64 Mo :
  `cargo test --workspace` avec plusieurs suites PostgreSQL en parallèle peut la saturer (« could not
  resize shared memory segment… No space left on device »), un échec d'environnement, pas de code.
  **Recréer avec `--shm-size=256m`** :
  `docker rm -f oe-pg-test && docker run -d --name oe-pg-test --shm-size=256m -e POSTGRES_PASSWORD=test -p 55432:5432 postgres:17-alpine`.

  **Piège de branche** : ce chantier a démarré sur une branche qui contenait aussi le crate `oe-s3` non
  commité ; les deux ont été séparés en deux PR indépendantes (#42 sans `oe-s3`, #43 avec) en gardant de
  côté une copie de `Cargo.lock`/`Cargo.toml` complets (scratchpad) le temps de committer #42 sans les
  entrées de dépendances propres à `oe-s3` (`rusty-s3`, `jiff`, etc.), qui n'ont rien à y faire.

Reste ensuite : étapes 3 à 6 du plan WEBUI §15 (actions RA signées relayées ; révocation et double
contrôle ; workflow d'incident ; frontend). Proposer un découpage et le faire valider avant chacune,
comme pour 1c et 2.

## 6. Valider une tranche (avant de la déclarer prête)

```bash
export OE_CASTORE_TEST_DSN=postgres://postgres:test@localhost:55432/postgres
cargo fmt --check && cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace > /tmp/full.out 2>&1; echo "code=$?"; grep -E "FAILED|panicked|^error|[1-9][0-9]* failed" /tmp/full.out
cargo audit --ignore RUSTSEC-2023-0071
```

Puis : contrôle **par mutation** de chaque garde de sécurité, `TODO.md` à jour, commit (chemins explicites), push, PR **empilée** avec un corps
qui dit la base, l'ordre de rebase, les limites assumées et les vérifications.

## 7. Fichiers locaux non suivis (ne pas commiter)

`CLAUDE.md`, `TODO.md`, `PROGRESSION.md`, `docs/mockups/` (antigravity, ne pas toucher). Sur la machine : conteneur `oe-pg-test`,
toolchain `1.98.1`, `/tmp/target-198`, scratchpad de la session.


**PSS livré (2026-10-21), brouillons empilés, aucun merge autorisé :** #126 (oe-hsm) → #127 (`feat/rsa-pss-algid` : certificats/CRL/OCSP/CSR) → #128 (`feat/rsa-pss-token` : CMS du jeton) → #129 (`feat/rsa-pss-config` : `OPENEIDAS_RSA_SCHEME`, Helm `rsaScheme`, CPS A.6, matrice). Ordre de merge : #126 puis rebase `--onto origin/dev` de chaque suivante et retarget vers dev. Défaut = PKCS#1 v1.5 ; passer à PSS en production = décision séparée (hiérarchie existante en PKCS#1 ; `openssl ts -verify` ne vérifie pas PSS, `openssl cms -verify` oui). Reste : cérémonie PSS de bout en bout avec SoftHSM2 en CI, `pkilint`.

**H-3 = PR #130** (`feat/tsu-key-generations`, base dev, brouillon) : une clé par certificat (`keys.rs`), `OPENEIDAS_KEY_LABEL` = génération 1, `<label>.<n>` ensuite. Reste : destruction journalisée de l'ancienne clé (irréversible, à confirmer avec Philippe), rechargement à chaud. #129 touche aussi `bin/tsa-server/src/main.rs` (rebase à prévoir selon l'ordre de merge). **Chaîne de merge #126→#129 en cours** (script `scratchpad/chain.sh`, autorisé par Philippe le 2026-10-21).

**2026-10-21 soir : PSS (#126–#129) mergée sur dev.** Brouillons en attente d'autorisation : #117, #130 (H-3, rebasée), #131 (A-2), #132 (S-1).

**2026-10-21 nuit : #130, #131, #132 mergées.** Brouillons : #133 (cérémonie PSS), #117 (C-6).
