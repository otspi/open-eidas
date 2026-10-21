# TODO — Open eIDAS

Liste vivante de ce qui reste ouvert. À mettre à jour à chaque tranche mergée :
cocher, ajouter, retirer. Le détail et les justifications sont dans
[docs/WEBUI.md](docs/WEBUI.md) (les renvois `§N` en viennent) ; ici, seulement
l'inventaire.

Dernier état connu : le socle de confiance de la console (étape 0, WEBUI §15)
est **à moitié posé sur `dev`** — registre des opérateurs, `oe-webauthn`,
`oe-actions` (approbation/rejet signés), `ca-server operators bootstrap-admin`
(PR #15 à #18). Les deux routes internes sont câblées et protégées par mTLS (PR de la route interne, puis du mTLS).

## 0. Audit de préparation eIDAS / WebTrust du 2026-09-25

Rapport : [docs/AUDIT_2026_09_25.md](docs/AUDIT_2026_09_25.md) (local, non commité). 8 NC majeures,
gravités validées par l'utilisateur. Plan de remédiation au §6 du rapport ; rien n'est engagé.

- [x] **P0 avant tout échange avec un organisme** — D-1, D-2, D-3. Découpage validé le 2026-09-27 :
  **a** (D-1 docs) → **b** (D-3) → **c** (D-2).
  - [x] **a** — **PR ouverte** (#60, `docs/align-docs-with-code`, base `dev`) : §7.11 et §7.10 en
    écart (22/4/2), `ARCHITECTURE.md` §7/§8, README (FreeTSA/DigiCert, webui), `CA.md`, `API.md`,
    compose/values (variables lues non exploitées), en-tête `oe-tsa-core`.
  - [x] **b** — **PR ouverte** (#61, `docs/matrix-versions-ids`, **empilée sur #60**, tête de #60 :
    `1eb46c1`) : `version` + `ids`, `validate()` (version, identifiants, identifiant ↔ clause, une
    version par norme), 10 clauses + 4 autres corrigées (412-1 sort, TS 119 312 V2.1.1 renuméroté),
    lignes en écart pour les PR ouvertes. 36 exigences : 17/17/2. Textes ETSI relus (etsi.org).
    **À chaque merge de #52 à #59 : repasser la ligne correspondante en « couvert »** (voir PR #61).
  - [x] **c** — **PR ouverte** (#63, `docs/matrix-in-service`, **empilée sur #61**, tête `d25ee8c`,
    contient le commit de #62) : statut « implémenté, pas en service », `in_service` obligatoire
    (test de binaire ou étape de job de démo), `tests/references.rs` (références résolues, pas de
    `#[ignore]`), premier test du binaire `tsa-server`, SoftHSM2 en CI + `OE_REQUIRE_SOFTHSM`.
    17 couvertes / 1 implémentée / 16 écarts / 2 hors périmètre.
- [x] **Correctif** — **PR ouverte** (#62, `fix/tsa-failinfo-encoding`, base `dev`) : le `failInfo` des
  refus RFC 3161 était mal encodé (double octet « bits inutilisés », `timeNotAvailable` illisible).
  Trouvé par le test du binaire tsa-server. À merger **avant** #63.
- [x] **P0** J-2 : journal bloquant partout — **terminé**. `oe-ca-core` (PR #42, mergée), `oe-raflow`/
  `oe-actions` (PR #45, mergée : `Flow::open` réordonné, `Decider::decide` garde l'écriture optimiste
  *avant* le journal — exception documentée, décision concurrente), `oe-tsa-core`/`oe-timesource`
  (PR #47, mergée : `timestamp.granted` réordonné avant la signature HSM, `Monitor::record` marque
  `traceable=false` sur échec du journal).
- [x] **P0** J-3 : journaliser série du jeton, `genTime`, empreinte, état d'horloge (jeton relu) —
  **PR ouverte** (#52, `feat/tsa-audit-token-serial`, base `dev`) : `timestamp.granted` journalise la
  série du **jeton** (`tst_info.serial_number`, plus celle du certificat, constante), `messageImprint`
  (OID + valeur), l'empreinte du certificat TSU, `gen_time` en RFC 3339. `tsa-server` ajoute l'état de
  l'horloge (traçabilité, écart, sources) via un `Recorder` englobant, sans coupler `oe-tsa-core` à
  `oe-timesource` (décision déjà prise, préservée). Testé par mutation (deux jetons → deux séries
  distinctes). En attente de revue humaine et des checks CI.
- [x] **P0** T-1 : `genTime` en millisecondes ; config `0 < accuracy ≤ 1 s` et `≥ max_offset + résolution` —
  **PR ouverte** (#53, `fix/tsa-gen-time-fraction`, empilée sur #52) : `genTime` encodé à la main en
  `Any` (millisecondes, forme canonique DER, compatible octet pour octet avec le corpus historique et
  `openssl ts -verify`) ; `oe-config` refuse de démarrer si `accuracy < max_offset + résolution`. Testé
  par mutation. En attente de revue humaine et des checks CI ; merger #52 avant #53.
- [x] **P0** T-3 : date d'expiration de la clé TSU (`privateKeyUsagePeriod`), contrôle à chaque
  signature, nouvelle clé à chaque renouvellement (EN 319 421 `TIS-7.7.1-09`, `TIS-7.6.7-*`) —
  **PR ouverte** (#54, `fix/tsu-key-expiry`, empilée sur #53) : extension posée (`oe-ca-core`, certificat
  tsa_signer 2 ans / clé 1 an), vérifiée par `check_tsu_certificate` (`oe-conformance`), recontrôlée à
  chaque signature (`oe-tsa-core::Authority`, refus `systemFailure`, aucune signature ne survient).
  Testé par mutation. **Reste hors de cette PR** : nouvelle clé automatique à chaque renouvellement
  (`tsa-server enroll`/rechargement à chaud) — opérationnel, pas encore proposé. En attente de revue
  humaine et des checks CI ; merger #52 puis #53 avant #54.
- [x] **P0** R-1/R-2 : découpage validé le 2026-09-26 — **A** (R-2) → **B** (R-1, traçabilité) →
  **C** (R-1, revue a posteriori). Voie de secours CLI : **traçabilité seule** (WEBUI §20, pas de PIN).
  - [x] **A** — **PR ouverte** (#57, `fix/helm-autoapprove-default`, base `dev`) :
    `ca.autoApprove.enabled: false` par défaut, `production: true` refuse le rendu avec
    l'approbation automatique, staging/CI/quickstarts l'activent explicitement,
    `/healthz` affiche `approbation_automatique` (`OPENEIDAS_RA_AUTO_APPROVE`). En attente de revue.
  - [x] **B** — **PR ouverte** (#58, `feat/cli-decision-provenance`, base `dev`) :
    `oe_ca_core::provenance::Via` (`webauthn`/`cli`/`automatique`) passé par l'appelant à
    `Issuer::revoke` et `Decider::approve|reject`, `authenticated_via` + `identite_systeme`
    (`authentifiee: false`) au journal, commentaire obligatoire pour le CLI. 4 mutations tuées.
    **Conflit attendu avec #56** (rebaser la seconde mergée) ; après #56, annoter aussi
    `ca.authority_revoked` (`Via::Cli`).
  - [x] **C** — **PR ouverte** (#59, `feat/cli-decision-review`, **empilée sur #58**) :
    `ca-server audit cli-decisions` (journal chaîné seul, codes 0/1/2, `--since`, `--json`,
    `--journal`), `--acknowledge --reviewer` consigne `ra.cli_decisions_reviewed`. 4 mutations tuées.
    **Reste** : fréquence de revue O4 à fixer par l'association ; CronJob d'alerte éventuelle.
- [x] **NC majeure** O-1 : statut `good` pour un certificat jamais émis — **PR ouverte** (#55,
  `feat/ocsp-unknown-status`, base `dev`) : `ca-server` publie tous les numéros émis dans une
  extension privée de la CRL (jamais purgée, à la différence des révoqués), le répondeur OCSP
  répond `unknown` pour un numéro absent, en respectant la doctrine du crate (jamais d'accès direct
  au registre). Vérifié par `openssl ocsp` (tiers indépendant), testé par mutation. En attente de
  revue humaine et des checks CI.
- [x] **NC majeure** C-1 : révocation de l'émettrice et ARL de la racine — **PR ouverte** (#56,
  `feat/authority-revocation-arl`, base `dev`) : CDP/AIA vers la racine gravés dans l'émettrice,
  `oe_ca_core::root::RootAuthority`, `ca-server authority revoke|publish-arl` (token racine, jamais
  pendant `serve`, sans quorum), ARL initiale à la cérémonie, `/download/<CN racine>.cer|.arl`,
  émission refusée dès la révocation. Vérifié par `openssl verify -crl_check_all`, testé par
  mutation. En attente de revue humaine et des checks CI. **Restes** : alerte sur ARL proche de
  l'échéance (republication annuelle manuelle) ; quorum pour la révocation d'autorité ; émettrices
  existantes sans CDP/AIA (cérémonie idempotente) ; clause ARL à ajouter à `system_matrix()` (D-1/D-2).
- [ ] **P1**, découpage validé le 2026-10-13 (décisions dans PROGRESSION.md §0), ordre journal → OCSP → temps :
  [x] J-a scellement par la TSU et copie S3 du journal de `tsa-server`, `/healthz` (#101, mergée) ;
  [x] J-b contreseing tiers (**PR #102**, en attente de CI et de revue) ; [x] J-c scellement des journaux de `ca-server` et `ra-console` par la TSA (**PR #103**, empilée sur #102, crate `oe-seal`) ;
  [x] J-d matrice et docs (**PR #105**, empilée sur #103) ; [ ] alerte sur `journal.degraded` ; [x] O-a fraîcheur de la CRL côté OCSP (**PR #106**) ; [x] O-b révoqués conservés (tous) (**PR #107**, empilée sur #106) ;
  [x] T-a durcissement SNTP (**PR #108**) ; [x] T-b seconde intercalaire (**PR #109**, empilée sur #108) ; [x] T-c NTS (**PR #110**, empilée sur #109)
- [ ] **P2** : voir rapport §6 (~~C-2~~ **PR #113** (reste hors code), ~~C-3~~ mergé (#111), ~~C-5~~ mergé #112 (reste pkilint), H-1 **PR #114**, C-6, H-1 à H-3, R-3, A-1, A-2, S-1 à S-3 (PR #141)). **Série P1 entièrement mergée sur `dev` le 2026-10-20** (#102, #103, #105 à #110).

- [ ] **Fusions 2026-09-30 et 2026-10-12** : tout est sur `dev`, y compris #84, #88, #92, #93 (arc 67027), #94 (6d), #95 (CI accélérée, ~11 min), #96 (épinglage du staging) et #97 (`quinn-proto`). `dev` vert sur `a82074b`. **Reste** : #5 (release-please) à l'utilisateur ; GitGuardian sur l'ex-#68 (PR #86) ; paquets ghcr.io/otspi/* à passer en public ; **staging réépinglé sur `a82074b` le 2026-10-12** (`otspi/deploy` `dc242c1`) mais **encore sur les anciens binaires à 19:07 UTC** : voir ArgoCD, puis revérifier (route `.arl`, 36 exigences, OCSP `unknown` pour `0x7e57`, CRL avec l'extension `67027.3.1`) ; rien à poser dans `otspi/deploy` pour #93 (OID pris du chart, lien interne inactif) ; démo compose sans cache d'images (~7 min, chemin critique de la CI).

- [ ] **PEN 67027 obtenu (2026-10-05)** : PR #93 `feat/oid-arc-pen-67027` (OID de test `67027.9.1.1.1`, lien interne `67027.2.9.x`, extension CRL `67027.3.1`, fixtures OCSP régénérées) ; **#93 mergée le 2026-10-12** ; **reste** : revue/merge de la PR #13 (gouvernance), (staging : sans objet, OID pris du chart et lien interne inactif), registre d'OID et titulaire (association) dans `open-eidas-organisation`, CPS (OID du document et des CP, décision CPC). `cargo test --workspace` vert (95 suites, PostgreSQL actif) après purge du cache de build périmé (voir PROGRESSION.md §3).

## 1. Étape 0 — socle dans `ca-server` (reste à faire)

- [x] **Route interne HTTP** `POST /internal/v1/challenge` et `/internal/v1/actions` sur un second port (`OPENEIDAS_INTERNAL_LISTEN`, désactivé par défaut), `oe_actions::Service` câblé sur le journal réel. Réservé à la boucle locale tant que le mTLS n'existe pas (`internal::check_loopback`).
- [ ] Suite de la route interne : les routes d'enregistrement (jeton d'invitation / d'amorçage) et la valeur Helm `internalPort`.
- [x] **mTLS du lien interne** : profils `internal_client` / `internal_server`, contrôles explicites (EKU seul, politique, CN `ra-console`, présence en table, révocation) et terminaison TLS 1.3 dans `ca-server` ; `ca-server internal-cert server` pour le certificat du serveur (Jour 0, côté `ca-server`).
- [ ] Suite du mTLS : OID de politique du lien interne posés sous le PEN 67027 (`.2.9.1`/`.2.9.2`, branche en commit sur `feat/oid-arc-pen-67027`, **approbation CPC et registre d'OID à faire**) ; enrôlement du certificat `internal_client` **côté `ra-console`** (avec l'approbation au CLI, jamais par `ra-console` elle-même) ; relecture du statut après révocation côté `ra-console` ; renouvellement à 30 jours de l'échéance (aujourd'hui : relance manuelle + redémarrage) ; certificat de `ca-server` rechargé sans redémarrage.
- [x] **Helm : port interne et `NetworkPolicy` de la CA** (`ca.service.internalPort`, `ca.internal.*`, `templates/ca/networkpolicy.yaml`, ConfigMap de la liste blanche, attente du certificat `internal_server` à l'entrypoint). Optionnel, désactivé par défaut.
- [ ] Déploiement de `ra-console` : valeurs Helm `raConsole.*`, `NetworkPolicy` de `ra-console` (ingress Gateway interne seul, egress vers postgres et le port interne de la CA), service `ra-console` du `docker-compose.yml` (§17). Le `docker-compose.yml` n'expose pas encore le lien interne : rien à y raccorder tant que `ra-console` n'existe pas.
- [x] **Enregistrement de la clé avec le jeton d'invitation** : `POST /internal/v1/register/begin|finish`, attestation contre la liste blanche, empreinte de clé, invitation d'amorçage → registre (`initiated_by = 'bootstrap-admin'`), autre invitation → `pending_credentials` (migration 0004, expiration 72 h). Reste : l'action signée de **confirmation** qui fait passer une clé en attente dans le registre, et la purge des clés en attente expirées.
- [ ] Enregistrement : pas de compteur d'essais par invitation (jeton à 256 bits, vie ≤ 24 h, donc non bloquant) ; la réponse de `finish` ne renvoie pas encore la description du modèle tirée de la liste blanche (§5).
- [x] **Actions signées sur le registre (partie 1)** : `invite_operator`, `confirm_key` (empreinte dans le corps signé, pas d'auto-confirmation), `revoke_key` (motif obligatoire, jamais le dernier administrateur actif), `set_role`. Un seul chemin de code pour le contrôle (joué à blanc à l'émission) et l'exécution. Le jeton d'invitation n'est rendu que dans `result` de la réponse d'exécution.
- [ ] **Actions signées sur le registre (partie 2)** : ajout / retrait de clé en libre-service (avec **réassertion**), élévation et retrait du rôle `admin` (**2 admins**, dépend du quorum M-sur-N, aujourd'hui refusés), purge des clés en attente expirées.
- [x] **Action de révocation de certificat** (`revoke_certificate`, rôle `ca_operateur`, `Issuer::revoke` puis republication de la CRL via `oe_actions::Revoker`). Motifs admis : 1, 3, 4, 5, 9. Un échec de publication de la CRL n'annule pas la révocation (journalisé, `crl_published: false`). **Un seul signataire pour l'instant** : le §5 prévoit le double contrôle.
- [x] **Quorum M-sur-N** (§8) : seuil posé par la politique de `ca-server` (`actions.required_signatures`, migration 0005), jamais par l'appelant ; second signataire via `issue_challenge_for` / `{action_id}` sur `/internal/v1/challenge` ; fenêtre de 24 h (`QUORUM_WINDOW`), challenge toujours limité à 5 min ; opérateurs distincts et encore habilités à l'exécution ; exécution unique sous concurrence. Branché sur `revoke_certificate` (2 `ca_operateur`) et sur l'élévation / le retrait du rôle `admin` (2 admins).
- [ ] Quorum : il n'existe aucune liste des actions en attente côté `ca-server` (elle vit dans les tables de collecte de `ra-console`, §8) ; pas de purge des actions expirées ; pas de politique de seuil configurable (constante `QUORUM = 2`) ; pas encore de quorum pour la révocation d'une autorité ni pour la cérémonie.
- [x] **`recover-admin`** (PIN du token lu sur l'entrée standard, motif, drapeau explicite, événement `operators.admin_recovery`, clé activée directement, rien de désactivé) et garde « quorum impossible » (une action à N signatures n'est pas créée si le rôle compte moins de N titulaires actifs, §21).
- [x] **`operators audit`** : chaîne du registre re-vérifiée (signatures ES256, corps ↔ empreinte ↔ journal, ancres attestées par le journal). Codes de sortie 0 / 1 / 2. Reste : seul ES256 est vérifiable ; le rôle des signataires à l'époque n'est pas jugé.
- [x] **`operators reconcile`** et rejeu du journal (§21) : contrôle au démarrage et toutes les 60 s, garde fermée sur divergence (challenge, exécution et inscription refusés, `/healthz` 503 avec le détail), journal rompu = garde fermée ; `reconcile` ré-applique révocations et rôles, n'acquitte une clé perdue que sur demande explicite, consigne chaque résolution avant de la valider.
- [ ] **Refus d'exécuter une action signée par une clé sans chaîne valide** (§21, « une clé insérée en SQL … refusée à l'exécution ») : exige de relire le journal à chaque exécution et de lancer l'audit sur la clé signataire ; aujourd'hui l'audit est à la demande (`operators audit`) et le rejeu ne couvre que les divergences révocation / rôle / clé perdue. Le rejeu ne détecte pas non plus une clé **ajoutée** en base sans trace au journal (c'est le rôle de l'audit).
- [ ] Rejeu : la garde n'est câblée que si le lien interne est activé ; `/healthz` n'expose le blocage qu'alors. Pas d'alerte hors console (§21), à brancher sur `/healthz`.
- [ ] **Liste blanche de modèles de clés** : le chargeur existe (`OPENEIDAS_WEBAUTHN_MODELS_FILE`, JSON `description`/`aaguid`/`root_pem`) ; reste à produire et versionner la liste initiale (décision O6).
- [ ] **Test R2a de bout en bout** (§19, n°3) : avec le certificat mTLS mais sans signature valide, aucune demande `tsa_signer` ne sort en certificat.
- [x] `Config::load_without_hsm` : `ra list|approve|reject`, `operators bootstrap-admin|recover-admin|audit|reconcile` n'exigent plus `OPENEIDAS_ISSUING_PIN` ni `OPENEIDAS_PKI_PUBLIC_URL` ; `serve`, `ceremony` et `revoke` les exigent toujours (testé, mutation vérifiée).
- [x] **Anti-piège CI** : l'étape PostgreSQL échoue si la variable manque, si la base ne répond pas, ou si un test écrit « test PostgreSQL ignoré » (sortie lue avec `--nocapture`). **Reste** : le test de `recover-admin` avec SoftHSM s'ignore avec un autre message (« softhsm2-util absent ») que cette garde ne couvre pas : installer `softhsm2` dans la CI et étendre la garde.

## 2. Ensuite — plan WEBUI §15, étapes 1 à 6

- [ ] 1. Fondations de `ra-console` (`cryptoki` n'est plus lié : feature `pkcs11` d'`oe-hsm`, garde `no_pkcs11.rs`) : **squelette livré** (binaire, configuration, garde du rôle PostgreSQL, lien mTLS vers `ca-server`, `/healthz`, migration 0006 : `webauthn_challenges`, `sessions`, `login_counters`, `ra-console internal-cert`). **1b livré** : relais de l'enregistrement de clé (`register/begin|finish` vers `ca-server`, test de bout en bout avec le vrai routeur interne). **1c-1 livré** (PR #34) : `login/begin|finish`, assertion vérifiée contre le registre en lecture seule (`oe-webauthn`), connexion par nom à réponses uniformes, compteur anti-clonage dans `login_counters`. **1c-2a livré** : session ouverte par `login/finish` (cookie `HttpOnly; Secure; SameSite=Strict`, 8 h fixe, table `sessions`), `GET /api/v1/me` et `POST /api/v1/logout` (identité et rôle relus en base à chaque requête, jamais mis en cache). **1c-2b livré** : purge périodique des sessions et challenges expirés (`ra_console::purge`, tâche de fond dans `serve`, `OPENEIDAS_PURGE_INTERVAL_SECONDS`, 60 s par défaut). **Reste** : limitation de débit des routes anonymes, à la Gateway (déploiement Helm, §2, aucun code applicatif prévu). Voir [docs/RA-CONSOLE.md](docs/RA-CONSOLE.md).
- [x] `-p ra-console` ajouté à l'étape CI PostgreSQL.
- [ ] `ra-console` : image et Dockerfile, job CI, chart Helm (`raConsole.*`, `NetworkPolicy`), service du `docker-compose.yml` (§17) ; renouvellement du certificat client 30 jours avant l'échéance (aujourd'hui à la main) ; purge périodique des challenges et sessions expirés ; **limitation de débit** des routes anonymes (`register/*`, puis `login/*`) : par adresse et globale, en tenant compte du proxy de la Gateway.
- [ ] 2. Lecture seule (`requests`, `audit/search`, `counters`). **2a livrée** : `GET /api/v1/requests?state=` (lit `enrollment_requests` directement, authentification par session, rôle non vérifié — les contrôles de rôle de `ra-console` ne sont qu'un affichage, §3). **2b (`audit/search`) en cours**, découpage A→D validé (2026-09-25, détail dans PROGRESSION.md §5) : **(A) livrée** — journal `oe-audit` propre à `ra-console` (`OPENEIDAS_RA_AUDIT_FILE`), événements `ra.login_succeeded`/`ra.login_refused` (raison réelle, jamais dans la réponse HTTP uniforme)/`ra.session_opened`/`ra.session_closed`. **(B) faite, PR ouverte** (#49, `feat/ca-server-audit-s3`) : `ca-server` câblé sur `oe-s3`
  (`OPENEIDAS_S3_ENDPOINT/BUCKET/REGION/ACCESS_KEY/SECRET_KEY/KEY`, toutes optionnelles ensemble ; sans
  `OPENEIDAS_S3_ENDPOINT`, purement local) ; chantier `Recorder` async/propagation/réordonnancement
  terminé sur les quatre familles de crates (`oe-ca-core` #42, `oe-raflow`/`oe-actions` #45,
  `oe-tsa-core`/`oe-timesource` #47, tous mergés). En attente de revue et de checks. **(C) faite, PR ouverte** (#50, `feat/ra-console-audit-s3`, indépendante de #49) : `ra-console` écrit le sien sur le même S3, best-effort (décision distincte de #49, voir PROGRESSION.md §5). En attente de revue et de checks. **(D) faite, PR ouverte** (#51, `feat/ra-console-audit-search`, empilée sur #50) : `GET /api/v1/audit/search` lit et vérifie les deux depuis S3 (chaîne rompue → blocage total, S3 absent → 503). En attente de revue et de checks ; merger #50 avant #51. `oe-replicate` (WebDAV) n'est pas remplacé, seulement pas utilisé ici (jamais câblé dans un binaire de toute façon).
- [x] 3. Actions RA signées relayées à `ca-server`.
- [x] 4. Révocation et double contrôle.
- [x] 5. Workflow d'incident. Découpage validé le 2026-10-12 (décisions dans PROGRESSION.md §0) : [x] **5a** schéma, ouverture, lecture (#98, mergée) ; [x] **5b** actions (note, référence vérifiée) et clôture (assertion WebAuthn) (#99, mergée) ; [x] **5c** frontend (#100, mergée ; écran à faire relire par antigravity, pas de maquette). Restes : sélecteur d'actions à rattacher, pagination.
- [ ] 6. Frontend (6a, 6b, 6c, 6e mergés ; **6d mergé** : PR #94 (`3b49432`) ; reste : pagination et filtres opérateur/type côté API si le volume l'exige), en suivant [docs/UI-UX.md](docs/UI-UX.md) (piloté par antigravity).
- [ ] Certificats d'identité `identity_person` (§11) : profil, route publique `/api/v1/identity/enroll`, jetons `identity_enrollment_tokens`, vérification d'empreinte de CSR avec le demandeur.

## 3. Décisions à prendre (association)

- [ ] **O1** méthodes de vérification d'identité admises pour un certificat d'identité
- [ ] **O2** date de mise en service des certificats d'identité
- [ ] **O3** vérifications préalables au recrutement d'un opérateur, formation, revue des accès
- [ ] **O4** fréquence de revue des décisions prises par la voie de secours (CLI)
- [ ] **O5** qui peut initier / confirmer un onboarding administrateur
- [ ] **O6** seuil d'admission des clés (protection matérielle, niveau FIDO ou FIPS 140) et liste initiale de modèles
- [ ] **O8** objectif de temps de reprise de `ca-server` (pas de haute disponibilité) et politique de `recover-admin`

## 4. À vérifier au moment de l'implémentation

- [ ] **T6** préciser dans le CPS que « ECDSA refusé » (A.6) vise les signatures de certificats, pas l'authentification des opérateurs (les clés FIDO signent en ES256)
- [ ] **T7** l'AAGUID distingue-t-il les versions de firmware (type EUCLEAK) ? attestation « entreprise » disponible ?
- [ ] **T8** surveillance de l'horloge de `ca-server` (échéances de 5 min, fraîcheur de la CRL)
- [ ] `fido_mds3_attestation_ca` (candidate, vise `webauthn-rs` 0.6) : à réévaluer si la 0.6 sort ; sinon on garde la liste versionnée
- [ ] Le contrôle du drapeau BE **à l'assertion** n'est exercé par aucun test (`SoftToken` ne le produit pas)
- [ ] R3 (remise du secret d'identité en main propre, non vérifiable techniquement) et R4 (sauvegardes désynchronisées si plusieurs instances PostgreSQL)

## 5. Documentation à faire à l'implémentation

- [ ] Coller en code le §18 de WEBUI : 3 entrées dans `oe_conformance::system_matrix()`, puis régénérer `docs/CONFORMITE-ETSI.md` ; renseigner `docs/CPS.md` (A.1.3, A.1.4, A.3.2, A.5, A.6, A.7). **Ne pas les modifier avant que le code existe.**
- [ ] Mettre à jour l'en-tête de `docs/WEBUI.md` (« rien n'est implémenté » n'est plus vrai) et l'état des sections déjà livrées
- [ ] Ajouter `ra-console` à `docs/SIZING.md` **après mesure** (chiffres actuels = estimations)
- [x] `docs/CA.md` : `ca-server operators bootstrap-admin` et `recover-admin` documentés

## 6. Écarts ETSI restants (hors logiciel)

- [ ] Adoption formelle du CPS par l'association (EN 319 401 §6.1)

- [ ] Plan de cessation d'activité (§7.12) et audit par organisme accrédité (EN 319 403-1)

## 7. Autres

- [ ] PR **#5** `chore(dev): release 0.2.0` (release-please), en attente depuis le début
- [ ] `docs/mockups/` : maquettes d'antigravity, **non suivies**, ne pas les committer sans accord
- [ ] `README` / documentation d'exploitation du Jour 0 (ordre d'amorçage, §14) une fois la route interne en place

## Étape 3 WEBUI — actions RA signées (en cours, 2026-09-27)

- [x] **3a** — PR #64 (`feat/ra-console-action-challenge`, base `dev`) : relais du challenge
  (`POST /api/v1/webauthn/challenge`), approve/reject seulement, `operator_hint` tiré de la session.
- [x] **3b** — PR #65 (`feat/ra-console-action-execute`, **empilée sur #64**, tête `37958f4`) :
  `POST /api/v1/requests/{id}/approve|reject`, `expect` contrôlé par `ca-server`
  (`Service::execute_expecting`, avant consommation de la cérémonie), `ra.action_relayed`.
- [ ] Étape 3 : reste le frontend (étape 6).

## Étape 4 WEBUI — révocation et double contrôle (2026-09-27)

- [x] **4a** — PR #66 (`feat/ra-console-revoke`, empilée sur #65, tête `457dc7e`) :
  `POST /api/v1/certificates/{serial}/revoke`, première signature (AWAITING_QUORUM), `Expect.serial`.
- [x] **4b** — PR #67 (`feat/ra-console-quorum`, empilée sur #66, tête `aac4dbc`) : co-signature
  (`{"action_id"}`, `POST /api/v1/quorum/{id}/sign`, `Expect.action_id`), salle d'attente
  `GET /api/v1/quorum` lue dans `actions`/`decision_evidence` (SELECT ajouté au rôle ; **rejouer
  `ra_console_grants.sql` au déploiement**). Pas de tables de collecte (§8 mis à jour).
- [ ] Suivant possible : étape 5 (workflow d'incident).

## Chantiers parallèles sur #67 (2026-09-27, « parallélise WebUI »)

Trois PR empilées sur #67, **parallèles entre elles** (conflits attendus au merge sur
`bin/ra-console/src/http.rs`, `docs/RA-CONSOLE.md`, `.github/workflows/ci.yml`) :
- [x] **#68** déploiement (agent) : Dockerfile, chart `raConsole.*` (désactivé par défaut), Job des
  droits SQL rejoué à chaque upgrade, surcouche `docker-compose.console.yml` (secrets obligatoires,
  correctif `d8daeec`). **GitGuardian en échec** : anciennes valeurs dans le premier commit + faux
  positif `generated.yaml` (`randAlphaNum`) → à marquer par l'utilisateur. Décisions à valider dans la PR.
- [x] **#69** gestion du registre (agent) : `POST /api/v1/operators`, `/credentials/{id}/confirm|revoke`,
  `/operators/{name}/role` ; `Expect` gagne `credential_id` et `operator`. Écarts de routes au §5 à valider.
- [x] **#70** frontend 6a (moi) : TypeScript + esbuild (choix utilisateur), assets embarqués, CSP et
  en-têtes sur toutes les réponses, connexion FIDO2, verrouillage 15 min, Playwright en CI (clé du
  SoftToken injectée dans l'authentificateur virtuel de Chromium). **Après #68** : ajouter
  `raConsole.environment` → `OPENEIDAS_RA_ENVIRONMENT`.
- [x] **#71** 6b (moi, empilée sur #70) : file des demandes (j/k/a/r), inspecteur, modale de signature
  WYSIWYS (corps figé + empreinte), harnais e2e branché sur le vrai service d'actions. Motif de rejet
  obligatoire = garde d'interface seulement (à décider : l'exiger côté ca-server ?).
- [x] **#72** 6c (moi, empilée sur #71) : `GET /api/v1/certificates`, écrans certificats + révocation + salle de quorum, e2e à deux opérateurs CA.
- [x] **#73** 6e (moi, base #72, **contient la fusion de #69** → merger #69 avant) : `GET /api/v1/operators`, écran opérateurs (invitation, confirmation par empreinte, révocation de clé, rôle).
- [ ] suite du frontend : 6d audit (après #51) ; `raConsole.environment` au chart (après #68), 6d (audit, après #51), 6e
  (opérateurs, après #69). Trous d'API : liste des certificats, détail CSR, état CRL/HSM.

- [ ] PSS : merger #126 → #127 → #128 → #129 sur autorisation de Philippe ; ensuite décider du passage de la production à `OPENEIDAS_RSA_SCHEME=pss` (réémission de la hiérarchie) et ajouter une cérémonie PSS SoftHSM2 en CI.

- [x] PSS #126–#129 mergées (2026-10-21). Reste : passage de la production à `OPENEIDAS_RSA_SCHEME=pss` (décision), cérémonie PSS SoftHSM2 en CI.
- [ ] #140 (S-1 SBOM/cosign/SLSA) : attend autorisation de merge ; vérifier le premier publish sur dev (signature visible avec cosign verify).
