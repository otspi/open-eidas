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
- Sont préparés à ce stade l'approbation et le rejet d'une demande (§15, étape 3) et
  la révocation d'un certificat (`revoke_certificate`, étape 4) ; toute autre action
  est refusée (`403 action_not_available`) sans solliciter `ca-server`.
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
  (co-signature) arrive avec l'étape 4b.
- La cible est contrôlée par `ca-server` comme pour une décision (`expect` porte le
  numéro de série) : une signature ne révoque jamais un autre certificat.
- Un `ra_operateur` ne peut pas préparer de révocation : `ca-server` refuse.

## Variables d'environnement

| Variable | Défaut | Rôle |
|---|---|---|
| `OPENEIDAS_DATABASE_URL` | — (obligatoire) | DSN du rôle PostgreSQL **de la console** (`openeidas_ra_console`) |
| `OPENEIDAS_CA_INTERNAL_URL` | — (obligatoire) | `https://<nom DNS>:<port interne>` ; le nom figure au SAN du certificat `internal_server` |
| `OPENEIDAS_INTERNAL_TLS_CERT_FILE` / `_KEY_FILE` | — (obligatoires) | Certificat `internal_client` de la console et sa clé (PEM) |
| `OPENEIDAS_CA_CERT_FILE` | — (obligatoire) | Certificat de la CA émettrice, seule racine de confiance du lien |
| `OPENEIDAS_RA_LISTEN` | `:8330` | Adresse d'écoute |
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

La co-signature et la liste des actions en attente (étape 4b), la gestion du registre
depuis la console, le workflow d'incident et le frontend : voir [WEBUI.md](WEBUI.md) §15 et `TODO.md`. La
connexion, les sessions et la lecture (`/api/v1/requests`) existent, mais ne sont pas
encore décrites ici. L'image, le chart Helm et le
`docker-compose.yml` de la console non plus. Le certificat client (3 mois) se
renouvelle à la main pour l'instant.
