# `ra-console` — état et exploitation

Conception : [WEBUI.md](WEBUI.md). Ce document dit ce qui **existe** et comment
l'exploiter ; il ne décrit que du code en service.

## Ce qui existe

`ra-console` est la console d'exploitation RA/CA. Elle est le seul composant exposé
aux navigateurs, donc le plus probablement compromis un jour. Deux principes en
découlent ([WEBUI.md](WEBUI.md) §16) : elle **n'ouvre jamais de session PKCS#11**, et
elle **n'écrit jamais dans les tables de `ca-server`** ni n'est une ancre de confiance.

Elle sert `/healthz` et le **relais de l'enregistrement de clé** (voir plus bas). Elle
pose ce que tout le reste suppose :

- **Le rôle PostgreSQL est en lecture seule sur les tables de `ca-server`.** La base
  l'impose (`crates/oe-castore/sql/ra_console_grants.sql`), mais un déploiement qui
  donnerait à la console le DSN de `ca-server`, ou celui d'un superutilisateur, la
  contournerait sans qu'aucun test le voie. Au démarrage, la console relit les droits
  **réels** de son rôle (héritage de groupe compris) et **refuse de servir** s'il peut
  écrire dans l'une de ces tables, en les listant toutes.
- **Le lien mTLS vers `ca-server`** (TLS 1.3, port interne). Le mTLS ne prouve que
  l'identité des deux bouts : il ne donne aucun pouvoir à la console, qui n'agit que par
  des signatures d'opérateurs que `ca-server` vérifie lui-même. La console refuse de
  démarrer avec un certificat client qui n'est pas le sien (profil `internal_client`,
  nom `ra-console`, dans sa validité). Elle exige du serveur un certificat qui remonte à
  la seule CA émettrice, porte `serverAuth` **seul** et la politique dédiée
  `internal_server`, et couvre le nom auquel elle se connecte. Les connexions ne sont
  pas réutilisées : `ca-server` ne contrôle le certificat client (révocation comprise)
  qu'à la poignée de main, et une connexion gardée ouverte survivrait à la révocation.
- **Ses propres tables** (migration 0006) : challenges de connexion, sessions,
  compteurs de signatures des connexions. Rien de ce qui touche la PKI.

## Enregistrement de la clé d'un opérateur (relais)

`POST /api/v1/webauthn/register/begin` (`{"token": "…"}`) puis `/finish`
(`{"ceremony_id": "…", "credential": {…}}`) : l'invité présente son jeton
d'invitation, et la console **relaie** à `ca-server` (`/internal/v1/register/*`,
mTLS). Elle ne lit pas l'attestation et ne la comprend pas : c'est `ca-server` qui la
vérifie contre la liste blanche de modèles et range la clé. Rien de la clé n'est
gardé par la console.

- La console **reconstruit** ce qu'elle relaie à partir de champs qu'elle a validés
  (JSON déclaré, champs connus, jeton de 1 à 256 caractères, identifiant de cérémonie
  au format UUID, corps de 64 Kio au plus) ; elle ne fait jamais suivre tel quel ce
  qu'un navigateur lui envoie.
- Un refus de `ca-server` (4xx) est rendu avec son code et son message, faits pour
  cela ; une panne (5xx, injoignable) devient un `502 ca_unavailable` **générique** :
  ni adresse, ni cause, ni divergence du registre. Le jeton n'est ni journalisé ni
  renvoyé.
- Le certificat que `ca-server` présente est contrôlé (politique, SAN, validité) à
  **chaque** réponse, pas seulement à la sonde.
- Pas encore de limitation de débit (l'endpoint est anonyme ; le jeton fait 256 bits et
  vit 24 h au plus) : voir `TODO.md`.

## Préparation d'une action signée (relais du challenge)

`POST /api/v1/webauthn/challenge`, avec une session ouverte : le corps est l'action
demandée, dans la forme d'`oe_actions` (`{"action": "approve_request",
"transaction_id": "…", "comment": "…"}`, ou `reject_request`). La console relaie à
`ca-server` (`/internal/v1/challenge`), qui **fige** l'action et rend le corps qu'il
exécutera, son empreinte (`body_hash`) et les options WebAuthn à passer à la clé
(docs/WEBUI.md §4, étapes 1 à 3).

- Le challenge est émis pour **l'opérateur de la session** : l'identifiant relayé
  (`operator_hint`) vient de la session, jamais du navigateur. L'action est relue dans
  l'énumération fermée d'`oe_actions` puis resérialisée : un champ en trop ne franchit
  pas la console.
- Sont préparées toutes les actions d'`oe_actions` : l'approbation et le rejet d'une
  demande (§15, étape 3), la révocation d'un certificat (`revoke_certificate`, étape
  4), et la gestion du registre (`invite_operator`, `confirm_key`, `revoke_key`,
  `set_role`, voir plus bas). Une action ajoutée plus tard à l'énumération ne sera pas
  préparée tant que la console ne la nomme pas (`403 action_not_available`).
- Le rôle et l'état de la demande sont jugés par `ca-server` (un administrateur ne peut
  pas approuver) ; la console relaie son refus.
- Chaque préparation est inscrite au journal de la console (`ra.action_challenge` :
  opérateur, action, `action_id`, `body_hash`, statut), rapprochable du journal de
  `ca-server`, qui fait foi.

## Exécution d'une décision signée (approuver, rejeter)

`POST /api/v1/requests/{id}/approve` ou `/reject`, avec une session ouverte :
`{"challenge_id": "…", "assertion": {…}}`, l'assertion étant la sortie brute de
`navigator.credentials.get` sur les options du challenge. La console relaie à
`ca-server` (`/internal/v1/actions`) l'identifiant du challenge et l'assertion —
**jamais de corps** : `ca-server` exécute celui qu'il a figé (docs/WEBUI.md §4,
étapes 5 à 7). Réponse : `{"transaction_id", "state": "APPROVED" | "REJECTED",
"decided_by", "action_id"}`, où `decided_by` est l'opérateur **dont la clé a signé**,
lu dans le registre de `ca-server`, pas celui de la session.

- La console joint ce que la route promet (`expect` : l'action et la demande du
  chemin). `ca-server` le compare au corps figé **avant** toute vérification ou
  consommation, et refuse (`409 action_mismatch`) s'il diffère : une signature obtenue
  pour une demande ne décide jamais d'une autre, ni l'inverse de ce qui a été signé,
  et l'assertion reste utilisable sur la bonne route.
- Une assertion déjà utilisée est refusée (`409 already_used`) : le rejeu est
  impossible par construction.
- Chaque relais est inscrit au journal de la console (`ra.action_relayed` : opérateur
  de la session, action, demande, `action_id`, signataire selon `ca-server`, statut).
- Le certificat n'est pas émis à ce moment : comme avec `ca-server ra approve`, il l'est
  au prochain appel du demandeur à l'enrôlement.

## Révocation d'un certificat (première signature)

`POST /api/v1/certificates/{serial}/revoke`, avec une session ouverte et la même forme
de corps qu'une décision (`{"challenge_id", "assertion"}`), le challenge ayant été
préparé pour `{"action": "revoke_certificate", "serial": "…", "reason": …,
"comment": "…"}`. Le numéro de série est en hexadécimal minuscule, sans préfixe (la
forme canonique du corps figé) ; toute autre forme est refusée avant relais.

- La révocation exige, par la politique de `ca-server`, **deux `ca_operateur`
  distincts** (docs/WEBUI.md §8). La première signature est enregistrée par
  `ca-server` et **rien n'est révoqué** : réponse `{"status": "AWAITING_QUORUM",
  "signatures": 1, "required": 2, "action_id", "signed_by"}`. La signature suivante
  (co-signature) passe par la salle d'attente, ci-dessous.
- La cible est contrôlée par `ca-server` comme pour une décision (`expect` porte le
  numéro de série) : une signature ne révoque jamais un autre certificat.
- Un `ra_operateur` ne peut pas préparer de révocation : `ca-server` refuse.

## Double contrôle : salle d'attente et co-signature

- `GET /api/v1/quorum?state=PENDING` (session) : les actions à plusieurs signatures ni
  exécutées ni expirées — identifiant, type, **corps figé** (à afficher tel quel à qui
  va co-signer), empreinte, signatures recueillies et exigées, **qui a déjà signé**.
  La console lit l'état qui fait foi, dans la table `actions` et `decision_evidence`
  de `ca-server`, en lecture seule ; elle n'en tient aucune copie et ne conserve
  jamais d'assertion.
- Co-signer : `POST /api/v1/webauthn/challenge` avec `{"action_id": "…"}` (la console
  vérifie que l'action existe, n'est pas exécutée et relève des actions proposées),
  puis `POST /api/v1/quorum/{action_id}/sign` avec `{"challenge_id", "assertion"}`.
  La console joint à `expect` l'identifiant de l'action et sa cible : une
  co-signature ne compte que pour l'action pour laquelle son challenge a été émis.
- `ca-server` n'accepte qu'une signature par opérateur, relit le rôle de chacun et
  exécute **une seule fois**, au seuil fixé par sa politique : la dernière signature
  rend `{"status": "EXECUTED", "signatures": 2, "required": 2, …}`.

**Mise à jour d'un déploiement existant** : la salle d'attente exige le droit de
lecture sur `actions`, ajouté au script des droits. Rejouer
`psql -f crates/oe-castore/sql/ra_console_grants.sql` (idempotent) ; sans cela,
`GET /api/v1/quorum` et la co-signature répondent `503`.

## Frontend (étape 6a : socle)

La console sert elle-même son interface (docs/UI-UX.md) : `/` et `/assets/*`, embarqués
dans le binaire (aucun serveur web ni répertoire d'assets à déployer). Sources et
construction : [`bin/ra-console/web/`](../bin/ra-console/web/README.md).

- **Toutes** les réponses, API comprise, portent la CSP stricte d'UI-UX §6.3 (aucun
  script ni style en ligne, rien hors de l'origine, `frame-ancestors 'none'`),
  `X-Frame-Options: DENY`, `nosniff`, `Referrer-Policy: no-referrer` et
  `Cache-Control: no-store`.
- Bannière d'environnement sur tous les écrans, connexion comprise :
  `OPENEIDAS_RA_ENVIRONMENT` (`production`, `staging`, `demo`) ; non déclarée, la
  console affiche « ENVIRONNEMENT NON DÉCLARÉ » plutôt qu'un environnement sans risque.
  `GET /api/v1/console` (sans session) la rend au frontend.
- Connexion par nom et clé FIDO2, poste de travail (identité et rôle relus sur le
  serveur, compteurs des files), déconnexion, **verrouillage après 15 minutes
  d'inactivité** (avertissement à 14) : la session est révoquée côté serveur.
- **File des demandes (6b)** : tableau dense des demandes en attente, sélection au
  clavier (`j`/`k`, `a` approuver, `r` rejeter), inspecteur latéral. Une décision passe
  par une justification (**obligatoire pour un rejet**, garde d'interface seulement :
  `ca-server` ne l'exige pas pour la voie signée), puis par la **modale de signature**
  (`<dialog>` natif) : elle affiche le corps que `ca-server` a figé, tel quel, et son
  empreinte SHA-256, avant tout geste sur la clé. Une erreur laisse la modale ouverte ;
  un challenge consommé ou expiré est redemandé au besoin. Échap annule, sauf pendant
  la cérémonie matérielle.
- **Certificats et révocation (6c)** : `GET /api/v1/certificates?status=issued|revoked`
  (lecture seule de la table de `ca-server`, numéro de série sous la forme canonique
  qu'attend la révocation). L'écran liste les certificats actifs ; « Révoquer… » demande
  un motif RFC 5280 parmi ceux qu'admet `ca-server` (1, 3, 4, 5, 9) et une
  justification obligatoire, puis la modale de signature. La première signature part
  en salle de quorum.
- **Salle de quorum (6c)** : les actions en attente, leur corps figé et leur empreinte,
  qui a déjà signé ; la co-signature est désactivée pour qui a déjà signé (« le double
  contrôle requiert un opérateur distinct » — `ca-server` la refuserait de toute façon).
- **Opérateurs (6e)** : `GET /api/v1/operators` (lecture seule : opérateurs, leurs clés,
  clés en attente avec leur **empreinte recalculée par `oe_actions::key_fingerprint`**,
  la fonction même de `ca-server`). L'écran liste le registre ; un administrateur y
  invite (le **jeton s'affiche une seule fois**, à transmettre par un canal distinct),
  confirme une clé en attente après avoir **déclaré avoir comparé l'empreinte hors
  bande** (§10), révoque une clé (motif obligatoire) et change un rôle (le rôle `admin`
  exige un second administrateur, en salle de quorum). Pour les autres rôles, ces
  boutons sont désactivés — affichage seulement, `ca-server` juge.
- L'explorateur d'audit suit (6d, après #51).
## Gestion du registre des opérateurs

Même schéma : le challenge est préparé avec l'action voulue, puis l'assertion est
relayée à la route correspondante (`{"challenge_id", "assertion"}`), qui rend la forme
d'une action à plusieurs signatures (`status`, `signatures`, `required`, `signed_by`,
`result`). Seul un `admin` signe ces actions ; `ca-server` en décide.

| Route | Action préparée | Cible contrôlée par `ca-server` |
|---|---|---|
| `POST /api/v1/operators` | `{"action": "invite_operator", "name", "role"}` | le type seulement (l'opérateur n'existe pas encore) |
| `POST /api/v1/credentials/{credential_id}/confirm` | `{"action": "confirm_key", "credential_id", "key_fingerprint"}` | l'identifiant de la clé |
| `POST /api/v1/credentials/{credential_id}/revoke` | `{"action": "revoke_key", "credential_id", "reason"}` | l'identifiant de la clé |
| `POST /api/v1/operators/{name}/role` | `{"action": "set_role", "operator", "role"}` | l'opérateur, par son nom |

- **Invitation** : le jeton n'existe que dans `result.invite_token` de la réponse
  d'exécution, rendu **une seule fois** ; ni `ca-server` ni la console ne le
  journalisent ni ne le conservent. L'invité enregistre ensuite sa clé par le relais
  d'enregistrement (plus haut) : elle reste en attente, avec une empreinte que l'invité
  transmet hors bande.
- **Confirmation** : l'administrateur signe l'empreinte ; `ca-server` la recompare à la
  clé en attente et refuse qu'un opérateur confirme sa propre clé.
- **Révocation de clé** : motif obligatoire ; `ca-server` refuse de révoquer la dernière
  clé d'administrateur active (la voie de secours est `recover-admin`).
- **Rôle `admin`** : créer un administrateur, élever un opérateur au rôle `admin` ou
  changer le rôle d'un administrateur exige **deux administrateurs** — la première
  signature rend `AWAITING_QUORUM`, la seconde passe par la salle d'attente
  (`/api/v1/quorum/{action_id}/sign`). Un opérateur ne change pas son propre rôle.
- Identifiant de clé : base64url, 1 024 caractères au plus ; nom d'opérateur : 1 à 256
  caractères. Toute autre forme est refusée avant relais.

## Variables d'environnement

| Variable | Défaut | Rôle |
|---|---|---|
| `OPENEIDAS_DATABASE_URL` | — (obligatoire) | DSN du rôle PostgreSQL **de la console** (`openeidas_ra_console`) |
| `OPENEIDAS_CA_INTERNAL_URL` | — (obligatoire) | `https://<nom DNS>:<port interne>` ; le nom figure au SAN du certificat `internal_server` |
| `OPENEIDAS_INTERNAL_TLS_CERT_FILE` / `_KEY_FILE` | — (obligatoires) | Certificat `internal_client` de la console et sa clé (PEM) |
| `OPENEIDAS_CA_CERT_FILE` | — (obligatoire) | Certificat de la CA émettrice, seule racine de confiance du lien |
| `OPENEIDAS_RA_LISTEN` | `:8330` | Adresse d'écoute |
| `OPENEIDAS_RA_ENVIRONMENT` | — (non déclaré) | `production`, `staging` ou `demo` : bannière du frontend |
| `OPENEIDAS_ENROLL_URL` | — | (`internal-cert`) API d'enrôlement publique de la CA |
| `OPENEIDAS_ENROLL_HMAC_KEY` | — | (`internal-cert`) secret partagé d'enrôlement |
| `OPENEIDAS_ENROLL_TIMEOUT_SECONDS` | 600 | (`internal-cert`) attente de l'approbation |

## Jour 0

1. Créer le rôle de la console et lui donner ses droits :
   `psql -f crates/oe-castore/sql/ra_console_grants.sql`, puis un mot de passe.
2. Sur `ca-server` : le lien interne activé et son certificat `internal_server`
   ([CA.md](CA.md)).
3. Le certificat client de la console :

   ```bash
   ra-console internal-cert
   # attend l'approbation : un opérateur nommé, sur la CA,
   ca-server ra approve <transaction> prenom.nom "amorçage du lien interne"
   ```

   La console n'approuve **jamais** la demande de son propre certificat : ce serait
   une confiance circulaire. La clé (0600) et la demande survivent à un redémarrage.
4. `ra-console serve`. `/healthz` est sain seulement si la base répond **et** si le lien
   vers `ca-server` fonctionne.

## Ce qui n'existe pas encore

La liste des clés en attente de confirmation, le libre-service (ajout et retrait de ses
propres clés, §10), le workflow d'incident et le frontend : voir [WEBUI.md](WEBUI.md) §15 et `TODO.md`. La
connexion, les sessions et la lecture (`/api/v1/requests`) existent, mais ne sont pas
encore décrites ici. L'image, le chart Helm et le
`docker-compose.yml` de la console non plus. Le certificat client (3 mois) se
renouvelle à la main pour l'instant.
