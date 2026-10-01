# Interface web d'opération — proposition d'architecture

**Statut : conception, en cours d'implémentation.** Le socle de confiance de
`ca-server` (registre des opérateurs, actions signées, lien interne mTLS,
quorum, audit, récupération) et la première brique de `ra-console` (lien mTLS,
garde du rôle PostgreSQL) existent ; l'authentification des opérateurs, les
écrans et le workflow d'incident non. Voir [RA-CONSOLE.md](RA-CONSOLE.md) et le
`TODO.md` pour l'état exact.
Objectif : remplacer le CLI (`ca-server revoke`, `ca-server ceremony`, lecture
manuelle du journal d'audit) par une interface web pour les opérateurs RA/CA,
authentifiée exclusivement par clé FIDO2, où les actions sensibles portent
une signature liée à l'opérateur qui les a décidées.

## 1. Ce que ce document couvre, et ce qu'il ne couvre pas

Couvert : authentification des opérateurs humains (WebAuthn), autorisation
par rôle, signature des requêtes sensibles, nouvelle surface API HTTP pour
exposer ce que seul le CLI sait faire aujourd'hui, workflow d'incident
(investigation), impact sur la matrice de conformité ETSI.

Hors périmètre de ce document : le rendu frontend lui-même, les principes
UX et le système de design visuel (traités en détail dans [UI-UX.md](UI-UX.md)),
l'authentification des *services* entre eux (TSA/CA/
OCSP restent authentifiés HMAC comme aujourd'hui, voir CA.md), et la
cérémonie de clé initiale (`ca-server ceremony`), qui reste un acte
d'amorçage distinct du fonctionnement courant.

## 2. Identité des opérateurs et authentification FIDO2/WebAuthn

### État actuel

Le champ `operator` de `enrollment_requests` (voir
`crates/oe-castore/migrations/0001_schema.sql`) est une chaîne libre passée
en paramètre CLI — rien ne garantit aujourd'hui que la personne qui tape
`--operator alice` est réellement Alice. C'est l'écart à combler : la
contrainte `decision_imputable` existe déjà en base, il manque
l'authentification qui rend cette identité vérifiable.

### Modèle proposé

- Chaque opérateur possède un ou plusieurs credentials WebAuthn (clé
  matérielle FIDO2), enregistrés une fois via une cérémonie d'enrôlement
  administrée (un opérateur existant, ou l'admin initial, approuve
  l'enregistrement d'un nouveau credential — pas d'auto-enregistrement
  ouvert).
- **`userVerification: "required"`** est imposé à l'enregistrement et à
  chaque assertion : sans PIN/biométrie sur la clé, aucune session ne
  s'ouvre. C'est ce qui fait de FIDO2 une authentification à deux facteurs
  en une seule cérémonie (possession de la clé + vérification locale), pas
  une simple clé de session.
- Pas de mot de passe de repli : la perte d'une clé se traite par révocation
  du credential et ré-enrôlement, jamais par un canal plus faible.
- Session : un cookie de session côté serveur (opaque, `HttpOnly`,
  `Secure`, durée courte) est établi après l'assertion de login ; il porte
  uniquement l'identité de l'opérateur et son rôle, jamais de droits
  étendus au-delà de ce que l'API vérifie à chaque appel.

### Schéma de données

**Deux propriétaires, et c'est la décision la plus importante du schéma**
(voir §16 « Faille identifiée » pour ce qui l'impose) :

- **`ca-server` possède le registre des opérateurs** (`operators`,
  `webauthn_credentials`) et les preuves des décisions. Il est le seul à y
  écrire, et seulement après avoir vérifié lui-même la signature WebAuthn
  d'un opérateur habilité. `ra-console` y a un accès en lecture seule, pour
  vérifier les connexions et afficher ses écrans.
- **`ra-console` possède ce qui ne donne aucun pouvoir sur la PKI** :
  sessions, challenges de connexion, dossiers d'incident, collecte des
  signatures de quorum. Un `ra-console` compromis peut altérer ces tables ;
  il ne peut ni émettre, ni révoquer, ni s'ajouter une clé.

Même logique que `crates/oe-castore/migrations/0001_schema.sql` aujourd'hui :
les invariants qui comptent (imputabilité, refus des clés copiables,
usage unique d'une signature) sont posés en contraintes SQL, pas seulement
vérifiés côté application.

**Tables de `ca-server`** (migrations versionnées avec celles
d'`oe-castore`) :

```sql
CREATE TABLE operators (
    id          UUID PRIMARY KEY,
    name        TEXT        NOT NULL UNIQUE,
    role        TEXT        NOT NULL
        CHECK (role IN ('auditeur', 'ra_operateur', 'ca_operateur', 'admin')),
    created_at  TIMESTAMPTZ NOT NULL,
    created_by  TEXT        NOT NULL,  -- 'bootstrap-admin' pour le tout premier
    disabled_at TIMESTAMPTZ,
    disabled_by TEXT
);

-- Un credential par clé FIDO2 physique. credential_id est l'identifiant
-- que l'authentificateur choisit lui-même (base64url) : c'est la clé
-- primaire naturelle, on ne la remplace pas par un UUID interne.
CREATE TABLE webauthn_credentials (
    credential_id TEXT        PRIMARY KEY,
    operator_id   UUID        NOT NULL REFERENCES operators(id),
    public_key    BYTEA       NOT NULL,  -- clé publique COSE, jamais de secret
    -- Dernier compteur vu par ca-server, sur les assertions d'actions
    -- uniquement (voir « Anti-clonage » ci-dessous).
    sign_count    BIGINT      NOT NULL DEFAULT 0,
    aaguid        UUID        NOT NULL,
    transports    TEXT[]      NOT NULL DEFAULT '{}',
    -- Preuve de provenance matérielle (voir « Attestation » plus bas),
    -- vérifiée par ca-server lui-même et conservée telle quelle pour qu'un
    -- auditeur puisse la revérifier.
    attestation_format TEXT   NOT NULL,
    attestation_object BYTEA  NOT NULL,
    backup_eligible    BOOLEAN NOT NULL,
    -- Nom choisi par l'opérateur (« YubiKey bureau », « clé de secours
    -- coffre ») : sans lui, deux clés du même modèle sont indiscernables
    -- dans l'écran « Mes clés » au moment d'en retirer une.
    label         TEXT        NOT NULL DEFAULT '',
    last_used_at  TIMESTAMPTZ,
    -- Imputabilité de l'enrôlement lui-même (§10) : qui l'a initié, qui a
    -- confirmé l'identité hors bande. La contrainte interdit un credential
    -- actif sans les deux, comme decision_imputable interdit une décision
    -- RA sans opérateur identifié.
    initiated_by  TEXT        NOT NULL,
    initiated_at  TIMESTAMPTZ NOT NULL,
    confirmed_by  TEXT,
    confirmed_at  TIMESTAMPTZ,
    revoked_at    TIMESTAMPTZ,
    revoked_by    TEXT,
    revoked_reason TEXT,
    CONSTRAINT credential_confirmed_before_active CHECK (
        revoked_at IS NOT NULL
        OR (confirmed_by IS NOT NULL AND confirmed_at IS NOT NULL)
        OR initiated_by = 'bootstrap-admin'
    ),
    CONSTRAINT attestation_required CHECK (attestation_format <> 'none'),
    CONSTRAINT not_backup_eligible CHECK (backup_eligible = false)
);

-- Invitation d'un nouvel opérateur (§10). Elle n'est créée que par une
-- action signée d'un admin et vérifiée par ca-server. Pour le tout premier
-- admin, c'est le CLI local de ca-server qui la crée, au Jour 0. Le jeton
-- est à usage unique et n'est conservé que haché : il est présenté tel
-- quel à l'enregistrement, pas utilisé comme clé HMAC.
CREATE TABLE operator_invites (
    id           UUID        PRIMARY KEY,
    operator_id  UUID        NOT NULL REFERENCES operators(id),
    token_hash   BYTEA       NOT NULL UNIQUE,
    created_by   TEXT        NOT NULL,  -- admin signataire, ou 'bootstrap-admin'
    created_at   TIMESTAMPTZ NOT NULL,
    expires_at   TIMESTAMPTZ NOT NULL,  -- courte durée, ex. 15 min à 24 h
    consumed_at  TIMESTAMPTZ
);

-- Clé enregistrée par un invité mais pas encore confirmée par un admin
-- (§10). Elle ne peut pas vivre dans webauthn_credentials, dont la
-- contrainte credential_confirmed_before_active interdit toute ligne non
-- confirmée. Seule une confirmation signée, vérifiée par ca-server, la fait
-- passer dans le registre. L'attestation y est déjà vérifiée à l'entrée,
-- pour qu'un admin ne confirme jamais une clé qui serait refusée ensuite.
CREATE TABLE pending_credentials (
    credential_id      TEXT        PRIMARY KEY,
    operator_id        UUID        NOT NULL REFERENCES operators(id),
    public_key         BYTEA       NOT NULL,
    aaguid             UUID        NOT NULL,
    attestation_format TEXT        NOT NULL CHECK (attestation_format <> 'none'),
    attestation_object BYTEA       NOT NULL,
    backup_eligible    BOOLEAN     NOT NULL CHECK (backup_eligible = false),
    invite_id          UUID        NOT NULL,  -- invitation signée qui l'autorise (§10)
    registered_at      TIMESTAMPTZ NOT NULL,
    expires_at         TIMESTAMPTZ NOT NULL
);

-- Une action, créée par ca-server lui-même quand il émet le premier
-- challenge (§4). Le corps est figé ici, à l'émission : c'est ce corps-là,
-- et aucun autre, qu'exécutera ca-server, quoi que ra-console relaie
-- ensuite. Un quorum (§8) est une action à plusieurs challenges.
CREATE TABLE actions (
    id             UUID        PRIMARY KEY,
    body           JSONB       NOT NULL,     -- corps canonique, fixé à la création
    body_hash      BYTEA       NOT NULL,     -- SHA-256(body), aussi écrit au journal (§4)
    created_at     TIMESTAMPTZ NOT NULL,
    expires_at     TIMESTAMPTZ NOT NULL,     -- created_at + 5 min
    executed_at    TIMESTAMPTZ               -- posé une seule fois, dans la transaction d'exécution
);

-- Un challenge WebAuthn émis pour un opérateur, sur une action. Le challenge
-- est tiré par la bibliothèque WebAuthn (§22 « Instruction de T1 ») : il ne
-- dérive pas du corps, le lien challenge → corps est ce que cette table,
-- et l'entrée de journal écrite à l'émission, établissent. L'état de la
-- cérémonie reste en mémoire de ca-server (un seul réplica, comme son
-- token PKCS#11), pas ici : une cérémonie perdue à un redémarrage est
-- simplement refaite. Jamais purgée, decision_evidence la référence.
CREATE TABLE action_challenges (
    challenge_id   UUID        PRIMARY KEY,
    action_id      UUID        NOT NULL REFERENCES actions(id),
    challenge      BYTEA       NOT NULL UNIQUE,
    operator_hint  UUID        REFERENCES operators(id),  -- indication, jamais une décision de confiance
    issued_at      TIMESTAMPTZ NOT NULL,
    expires_at     TIMESTAMPTZ NOT NULL,
    consumed_at    TIMESTAMPTZ           -- usage unique : la clé primaire rejoue impossible
);

-- Preuve de chaque décision, une ligne par assertion (N lignes pour un
-- quorum). **Limite assumée** : la signature porte sur le challenge tiré
-- au hasard, pas sur le corps. Cette ligne prouve « cette clé a signé ce
-- challenge », et le lien avec le corps repose sur actions.body_hash tel
-- qu'écrit dans le journal chaîné de ca-server, horodaté et contresigné
-- par une TSA tierce à l'émission (§4). Un auditeur vérifie donc la
-- signature avec la clé publique du registre, *et* l'intégrité du journal ;
-- il ne peut pas se contenter de la signature seule.
CREATE TABLE decision_evidence (
    id                 UUID        PRIMARY KEY,
    challenge_id       UUID        NOT NULL UNIQUE REFERENCES action_challenges(challenge_id),
    action_id          UUID        NOT NULL REFERENCES actions(id),
    operator_id        UUID        NOT NULL REFERENCES operators(id),
    credential_id      TEXT        NOT NULL REFERENCES webauthn_credentials(credential_id),
    authenticator_data BYTEA       NOT NULL,
    client_data_json   BYTEA       NOT NULL,
    signature          BYTEA       NOT NULL,
    verified_at        TIMESTAMPTZ NOT NULL,
    UNIQUE (action_id, operator_id)  -- un opérateur ne compte qu'une fois par action
);
```

**Tables de `ra-console`**, dans le même PostgreSQL mais sous son propre
rôle (§16) :

```sql
-- Challenges de connexion et d'enregistrement, et corps d'action en attente
-- de signature. Pour 'action', la table sert seulement à relayer à
-- ca-server le corps exact qui a été montré puis signé : la protection
-- contre le rejeu qui compte est action_challenges, côté ca-server.
CREATE TABLE webauthn_challenges (
    id            UUID        PRIMARY KEY,
    kind          TEXT        NOT NULL
        CHECK (kind IN ('register', 'login', 'action')),
    challenge     BYTEA       NOT NULL,
    -- NULL pour 'login' tant que l'opérateur n'est pas identifié par son
    -- assertion ; obligatoire pour 'register' et 'action'.
    operator_id   UUID        REFERENCES operators(id),
    request_body  JSONB,
    created_at    TIMESTAMPTZ NOT NULL,
    expires_at    TIMESTAMPTZ NOT NULL,  -- created_at + 5 min, non négociable
    consumed_at   TIMESTAMPTZ
);

-- Sessions révocables côté serveur, pas un JWT auto-porteur : révoquer une
-- session (départ d'un opérateur, §14 Jour 2) doit être immédiat, pas
-- attendre l'expiration d'un jeton qu'on ne peut pas rappeler.
CREATE TABLE sessions (
    id            TEXT        PRIMARY KEY,  -- identifiant opaque, 256 bits
    operator_id   UUID        NOT NULL REFERENCES operators(id),
    credential_id TEXT        NOT NULL REFERENCES webauthn_credentials(credential_id),
    created_at    TIMESTAMPTZ NOT NULL,
    last_seen_at  TIMESTAMPTZ NOT NULL,
    expires_at    TIMESTAMPTZ NOT NULL,
    revoked_at    TIMESTAMPTZ
);

-- Compteur de signatures vu par ra-console sur les seules connexions
-- (webauthn_credentials.sign_count, lui, n'est écrit que par ca-server).
CREATE TABLE login_counters (
    credential_id   TEXT   PRIMARY KEY REFERENCES webauthn_credentials(credential_id),
    last_sign_count BIGINT NOT NULL
);
```

Les clés étrangères de `ra-console` vers `operators` et
`webauthn_credentials` supposent une instance PostgreSQL unique (risque R4,
§22) : elles exigent le droit `REFERENCES` sur ces tables, jamais `INSERT`
ni `UPDATE`.

Points d'implémentation qui ne se voient pas dans le schéma seul :

- **Anti-clonage (`sign_count`).** Chaque assertion WebAuthn porte un
  compteur ; si la valeur reçue est inférieure ou égale au dernier compteur
  vu, deux authentificateurs partagent potentiellement le même secret
  (clone matériel ou export illégitime) — l'assertion doit être rejetée et
  le credential suspendu, pas seulement journalisé. Deux vérificateurs
  tiennent chacun leur propre flux : `ra-console` pour les connexions
  (`login_counters`), `ca-server` pour les actions
  (`webauthn_credentials.sign_count`). Le compteur de l'authentificateur est
  unique et croissant, donc chacun voit une suite croissante avec des
  sauts, et la régression reste détectable dans chaque flux. Un clone
  utilisé seulement pour se connecter est repéré par `ra-console`, un clone
  utilisé pour agir par `ca-server`. La suspension, qui est une écriture
  dans le registre, reste le fait de `ca-server` : `ra-console` la
  *demande* (événement journalisé, refus de la session), il ne l'écrit pas.
  Nuance à
  ne pas rater : certains authentificateurs ne tiennent pas de compteur et
  renvoient toujours `0`. C'est typiquement le cas des passkeys
  synchronisées, qui sont de toute façon refusées ici (drapeau BE, voir
  « Attestation » plus bas), mais aussi de certaines clés matérielles. La
  règle de rejet ne s'applique donc qu'à une régression d'un compteur qui a
  déjà été strictement positif, jamais à une valeur constante à zéro. Pour
  un modèle sans compteur, la détection de clonage n'existe pas : c'est
  alors l'attestation qui porte seule la garantie de non-copie. C'est un
  critère de plus pour la liste blanche.
- **Le cookie de session ne contient que `sessions.id`.** L'identité, le
  rôle et tout le reste se relisent en base à chaque requête ; un cookie
  volé sans que la session soit aussi révoquée en base ne donne rien de plus
  qu'un identifiant à durée de vie courte.
- **Purge périodique** de `webauthn_challenges` (lignes expirées) et de
  `sessions` (lignes expirées non révoquées) — tâche de fond, pas une
  condition de sécurité en soi puisque `expires_at` est de toute façon
  vérifié à la lecture, mais nécessaire pour ne pas laisser ces tables
  croître indéfiniment.

### Relying Party ID et environnements (staging / production)

Un credential WebAuthn est lié à un **RP ID** (un nom de domaine) : une
assertion produite pour un RP ID n'est valide que pour lui. Le RP ID peut
être le nom d'hôte exact de la console ou n'importe quel suffixe
enregistrable de ce nom — `console.open-eidas.eu` comme `open-eidas.eu`.
Deux options, une seule retenue :

| | RP ID commun (`open-eidas.eu`) | RP ID = nom d'hôte exact de chaque console |
|---|---|---|
| Enregistrement | Une clé enregistrée une fois « vaut » pour staging et prod | Un enregistrement par environnement (la même clé physique peut les porter tous les deux) |
| Portée d'une assertion | Toute page de tout sous-domaine d'`open-eidas.eu` peut demander une assertion pour ce RP ID | Seule la console de cet environnement peut en demander une |
| Circulation de la confiance | Tentation de recopier les credentials de staging vers prod pour éviter le double enregistrement | Aucune : la prod n'hérite jamais d'un état de confiance établi dans un environnement moins protégé |

**Décision : RP ID égal au nom d'hôte exact de chaque console**
(`console.open-eidas.eu` en production, `console.staging.open-eidas.eu` en
staging), jamais le domaine racine. Deux raisons tirées du dépôt lui-même,
pas de principe abstrait :

- **`demo.open-eidas.eu` existe déjà** sous le même domaine racine (site de
  démonstration public, destinataire du CORS de la TSA dans
  `values-staging.yaml`). Avec un RP ID `open-eidas.eu`, une faille XSS sur
  ce site de démonstration — moins protégé par nature — suffirait à
  déclencher des demandes d'assertion pour les clés des opérateurs de la
  console. Le contrôle d'origine côté serveur rejetterait l'assertion, mais
  c'est alors la seule barrière restante ; un RP ID étroit en ajoute une
  seconde, portée par le navigateur et l'authentificateur eux-mêmes.
- **Staging est un environnement explicitement dégradé** (SoftHSM,
  bandeau « STAGING », approbation automatique possible). Un RP ID distinct
  rend techniquement impossible qu'un enregistrement fait là-bas — y compris
  par l'amorçage rapide qu'on y tolère — devienne une identité de confiance
  en production. L'onboarding de production (§10) avec sa confirmation hors
  bande n'est jamais « promu » depuis staging : il est refait.

Conséquences opérationnelles :

- **Configuration, pas code** : `OPENEIDAS_WEBAUTHN_RP_ID` et
  `OPENEIDAS_WEBAUTHN_ORIGIN` (une seule origine, pas de liste ni de
  joker). `ra-console` refuse de démarrer si le RP ID n'est pas exactement
  le nom d'hôte de l'origine configurée — même logique que
  `OPENEIDAS_KEY_BITS` refusé sous 3072 bits à la configuration : une
  mauvaise valeur doit empêcher le démarrage, pas produire un service qui
  fonctionne avec des garanties plus faibles.
- **Emplacements de clés résidentes** : avec `residentKey: preferred` (§16,
  connexion sans nom d'utilisateur), chaque enregistrement occupe un
  emplacement sur la clé physique, et leur nombre est limité (quelques
  dizaines selon le modèle et le firmware). Deux environnements = deux
  emplacements par opérateur — négligeable en pratique, mais à mentionner
  dans le guide d'onboarding plutôt qu'à découvrir le jour où une clé est
  pleine.
- **`rp.name`** porte l'environnement (« Open eIDAS Console — STAGING ») :
  selon le navigateur et le système, il peut apparaître dans l'invite de
  l'authentificateur, et renforce alors le bandeau d'environnement de
  [UI-UX.md](UI-UX.md) §2.1 au moment précis où l'opérateur engage sa clé.

### Attestation : prouver qu'une clé est matérielle et non copiable

**Réponse courte.** On ne peut pas le *prouver* au sens mathématique : une
assertion WebAuthn prouve la possession de la clé privée, rien sur l'endroit
où elle réside. On peut en revanche obtenir, dès l'enregistrement, une
**preuve vérifiable rattachée à une certification** : la clé a été générée
dans un authentificateur authentique, d'un modèle certifié, qui déclare lui-
même que la clé ne peut pas être synchronisée. On peut aussi **détecter a
posteriori** un clonage. C'est la même nature de garantie qu'un dispositif
qualifié (QSCD) en eIDAS : une certification sous un modèle d'attaque
défini, pas une démonstration. Cohérent avec la posture « construit comme
qualifié » du §11.

**Les quatre mécanismes, du plus fort au plus faible :**

1. **Attestation du fabricant.** À l'enregistrement, avec
   `attestation: "direct"`, l'authentificateur renvoie une déclaration
   signée par une clé d'attestation du fabricant, rattachée à sa racine
   publiée. Elle atteste le modèle (AAGUID) et que la paire de clés a été
   générée *à l'intérieur* de ce matériel. Sans attestation vérifiée
   (`attestation: "none"`), on ne sait rien de l'origine de la clé : elle
   peut venir d'un émulateur logiciel. **Règle : un enregistrement sans
   attestation vérifiable est refusé.**
2. **Liste blanche de modèles certifiés.** Le FIDO Alliance Metadata Service
   (MDS3) publie pour chaque modèle son niveau de certification FIDO (L1 à
   L3+), le type de protection des clés (`secure_element`, `hardware`,
   `software`…) et ses racines d'attestation. On n'accepte que les AAGUID
   d'une liste blanche. Cette liste est versionnée dans le dépôt et revue
   par PR, et n'est pas interrogée en direct chez un tiers au moment de
   l'enregistrement, conformément à l'esprit d'INDEPENDANCE.md : aucune
   dépendance réseau de `ra-console` envers `fidoalliance.org` à
   l'exécution. Seuil à décider par l'association (O6, §22) : protection
   matérielle ou élément sécurisé, et niveau de certification minimal
   (L2+, ou validation FIPS 140).
3. **Drapeau « éligible à la sauvegarde » (BE) de WebAuthn.** Chaque réponse
   d'authentificateur porte dans `authenticatorData` un drapeau qui dit si
   la clé *peut* être copiée vers d'autres appareils : c'est le cas des
   passkeys synchronisées (trousseau iCloud, gestionnaire de mots de passe
   Google). **Règle : `BE = 1` est refusé à l'enregistrement, et une
   assertion qui présenterait `BE = 1` pour une clé enregistrée à `BE = 0`
   est rejetée.** Ce drapeau est déclaré par l'authentificateur lui-même :
   c'est le mécanisme 1 qui le rend digne de foi, pas l'inverse.
4. **Détection de clonage par le compteur de signatures** (`sign_count`,
   déjà décrit plus haut dans ce §2). Il ne protège de rien a priori. Il
   signale après coup que deux exemplaires d'un même secret ont signé.

**Veille et limites, pour ne pas surévaluer la garantie :**

- **Une certification a un modèle d'attaque, et des attaques existent en
  dehors.** Exemple publié : EUCLEAK (NinjaLab, 2024), une attaque par canal
  auxiliaire sur l'implémentation ECDSA d'Infineon. Elle permettait
  d'extraire la clé de certaines clés de sécurité, dont des YubiKey 5 au
  firmware antérieur à 5.7, avec un accès physique prolongé et un matériel
  spécialisé. « Non extractible » veut donc dire « non extractible sans
  moyens d'un niveau que la certification juge hors de portée », pas
  « impossible ».
- **Le MDS publie des alertes par modèle** (compromission de la clé
  d'attestation, compromission physique ou à distance des clés
  utilisateur). Un job CI périodique, sur le modèle du `cargo audit` qui a
  signalé RUSTSEC-2026-0285/0286, compare la liste blanche au MDS. Il échoue
  si un modèle autorisé reçoit une alerte de compromission. Conséquence
  opérationnelle : revue et révocation des clés d'opérateurs de ce modèle
  (§14). Point à vérifier (T7, §22) : l'AAGUID distingue-t-il les versions
  de firmware concernées ? Si ce n'est pas le cas, la granularité de la
  liste blanche est le modèle entier.
- **La preuve reste disponible pour l'audit.** L'objet d'attestation brut
  est conservé avec le credential (colonnes ci-dessous). Un auditeur peut
  revérifier après coup, et hors de `ra-console`, que chaque clé d'opérateur
  vient bien d'un modèle autorisé. La preuve ne repose pas sur un simple
  journal applicatif qui l'affirmerait.
- **Option à évaluer : l'attestation « entreprise »**
  (`attestation: "enterprise"`), qui lie le credential au numéro de série
  d'une clé physique précise. Elle permettrait de tenir un inventaire
  « l'opérateur X détient la clé physique n° Y ». Sa disponibilité dépend du
  fabricant et de la configuration du navigateur : c'est à vérifier, pas à
  supposer (T7, §22).

Dans le schéma ci-dessus, `attestation_format`, `attestation_object` et
`backup_eligible` portent ces règles sur `webauthn_credentials`, et les
contraintes `attestation_required` et `not_backup_eligible` les imposent en
base. Surtout, **c'est `ca-server` qui vérifie l'attestation et la liste
blanche**, pas `ra-console` : sinon une console compromise ferait passer
une clé logicielle pour une clé certifiée.

### Ce que FIDO ne remplace pas

Voir la discussion de conformité en §7 : l'authentification forte d'un seul
opérateur ne satisfait pas une exigence de double contrôle. Une clé FIDO
compromise avec son PIN reste une compromission totale de cette identité,
comme n'importe quel facteur — la clé matérielle réduit le risque de vol à
distance, elle ne le supprime pas.

## 3. Rôles et séparation des tâches

Trois rôles, alignés sur ce que `oe_raflow`/`oe_ca_core` distinguent déjà
dans le code (décision RA, révocation, cérémonie) :

| Rôle | Peut | Ne peut pas |
|---|---|---|
| `auditeur` | Lire le journal d'audit, l'état des demandes, la matrice de conformité | Approuver, rejeter, révoquer |
| `ra_operateur` | Approuver/rejeter une demande d'enrôlement, ouvrir/faire évoluer un dossier d'incident | Révoquer un certificat de CA/TSU, lancer une cérémonie |
| `ca_operateur` | Tout ce que fait `ra_operateur`, plus révocation et actions de cérémonie (en double contrôle, §8) | — |

Le rôle est un attribut de l'opérateur en base, pas du credential : une
même personne peut changer de rôle sans réenrôler sa clé, un changement de
rôle est lui-même un événement audité.

**Qui fait respecter ce tableau.** Pour toute action qui modifie l'état de
la PKI ou du registre des opérateurs, c'est `ca-server` : il lit le rôle
dans son propre registre, à partir de l'opérateur identifié par la clé qui
a signé, jamais à partir d'un rôle ou d'un nom transmis par `ra-console`.
Les contrôles de rôle de `ra-console` ne servent qu'à l'affichage (masquer
un bouton inutile). Ce ne sont pas des contrôles de sécurité, et leur
contournement par une console compromise ne donne aucun pouvoir.

Hors du tableau, un quatrième rôle, **`admin`**, gère les opérateurs et
leurs clés (§10). Il ne donne aucun droit sur les certificats.

## 4. Signature des requêtes sensibles

Une assertion WebAuthn signe un challenge, pas le contenu métier affiché à
l'écran (la plupart des clés FIDO2 n'ont pas d'écran de confirmation
« what-you-see-is-what-you-sign »). Le schéma retenu pour qu'une signature
engage réellement l'opérateur sur *cette* action précise :

**Décision O7 : challenge émis par `ca-server` avec la bibliothèque
WebAuthn, lien avec le corps établi côté serveur.** La bibliothèque retenue
impose de tirer elle-même le challenge (§22 « Instruction de T1 »). Le
challenge ne peut donc pas être le hachage du corps, et la signature
n'engage pas cryptographiquement sur le corps. Le schéma compense côté
`ca-server`, et cette limite est assumée plus bas.

1. Le navigateur demande à `ra-console` de préparer l'action. `ra-console`
   transmet le corps demandé à `ca-server` (`POST /internal/v1/challenge`),
   par exemple `{"action":"revoke","serial":"...","reason":4,
   "comment":"..."}`.
2. **`ca-server` fige l'action.** Il ajoute lui-même l'échéance (5 minutes),
   crée la ligne `actions` avec le corps et `body_hash = SHA-256(corps)`,
   demande à la bibliothèque un challenge d'authentification pour les clés
   de l'opérateur visé, et l'enregistre dans `action_challenges`. **Avant de
   répondre**, il écrit dans son journal chaîné : `action_id`,
   `body_hash`, l'identifiant du challenge et l'opérateur visé. Ce journal
   est contresigné par la TSA tierce déjà prévue (§7), donc le lien
   « ce challenge ↔ ce corps » est horodaté *avant* toute signature.
3. `ca-server` renvoie le challenge et le corps figé. `ra-console` les
   présente à l'opérateur (WYSIWYS, [UI-UX.md](UI-UX.md) §3.1), et le
   navigateur les passe à la clé.
4. L'opérateur touche sa clé ; le navigateur obtient l'assertion.
5. `ra-console` relaie **l'identifiant du challenge et l'assertion brute**
   (`POST /internal/v1/actions`, §16). **Il ne relaie plus de corps :**
   `ca-server` exécute le corps qu'il a figé à l'étape 2, quoi que
   `ra-console` lui présente ensuite. Une console compromise ne peut donc
   pas faire signer un corps puis en faire exécuter un autre.
6. **`ca-server` vérifie tout lui-même**, sans rien croire de
   `ra-console`, à travers la bibliothèque (`finish_attested_passkey_authentication`)
   et ses propres contrôles :
   - l'action n'est ni expirée ni déjà exécutée, et le challenge n'est pas
     consommé (`action_challenges`) ;
   - le challenge de l'assertion est celui qu'il a émis ;
   - le credential est actif dans *son* registre, et c'est celui d'un
     opérateur qu'il a désigné à l'étape 2 (l'indication ne vaut pas
     décision : c'est la clé qui a signé qui fait foi) ;
   - la signature est valide pour cette clé publique, l'origine et le
     `rpIdHash` sont ceux attendus ;
   - les drapeaux présence et vérification de l'utilisateur, et `BE = 0` ;
   - aucune régression du compteur ;
   - le rôle de l'opérateur (lu dans son registre) suffit pour cette action.
7. Seulement alors l'action est exécutée. Dans la même transaction,
   `ca-server` pose `consumed_at` et `executed_at`, enregistre la preuve
   (`decision_evidence`) et écrit l'événement dans son journal chaîné, avec
   l'identité de l'opérateur *telle que lue dans son registre*.

Le rejeu est impossible par construction, et de façon générique : il ne
repose pas sur le fait qu'une action particulière soit idempotente. Sans
cette règle, par exemple, une ancienne signature « passer X au rôle admin »,
rejouée après une rétrogradation, rétablirait silencieusement le rôle.

**Ce que cette variante garantit, et ce qu'elle ne garantit plus.**
- *Toujours vrai* : personne, y compris une console compromise, ne peut
  faire exécuter un corps que l'opérateur n'a pas vu signer, puisque
  `ca-server` exécute son propre corps figé.
- *Plus vrai* : la signature seule ne prouve plus quel corps a été
  approuvé. Elle prouve « cette clé a signé ce challenge ». Le lien avec le
  corps repose sur le journal de `ca-server`, écrit avant la signature et
  contresigné par un tiers. Un auditeur doit donc vérifier la signature
  *et* l'intégrité de ce journal. Contre un attaquant qui contrôlerait
  `ca-server` lui-même, la preuve est plus faible qu'avec un challenge égal
  au hachage du corps. C'est le prix du choix de bibliothèque ; la
  contrepartie est de ne pas écrire de code cryptographique maison.

Limite à documenter dans le CPS (dans le même esprit que les écarts déjà
listés) : ce schéma prouve qu'un opérateur muni de cette clé a validé une
cérémonie que `ca-server` avait liée à un corps donné ; il ne prouve pas que
l'opérateur a personnellement relu ce corps si le poste client est compromis.
C'est la limite structurelle de WebAuthn sans affichage de transaction sur
l'authentificateur — à énoncer plutôt qu'à passer sous silence.

## 5. Nouvelle surface API HTTP

Rien de ceci n'existe aujourd'hui : `bin/ca-server` n'expose que
`/api/v1/enroll`, `/api/v1/ca.pem`, `/api/v1/conformance`, la CRL et
`/healthz` (voir `bin/ca-server/src/http.rs`). Toutes les routes ci-dessous
sont nouvelles et exposées au navigateur par `ra-console`, un service
distinct de `ca-server`. La règle de partage est simple :

- **les lectures** (files d'attente, certificats, registre, compteurs)
  passent par un accès direct en lecture seule à la base de `ca-server` ;
- **toute écriture** qui touche la PKI ou le registre des opérateurs est
  *relayée* à `ca-server` (`POST /internal/v1/actions`, §16) avec
  l'assertion brute de l'opérateur, et c'est `ca-server` qui la vérifie
  puis l'exécute (§4). Cela vaut pour décider, révoquer, inviter ou
  confirmer un opérateur, ajouter ou retirer une clé, changer un rôle ou
  créer un jeton d'identité.

Dans les tableaux qui suivent, « rôle minimal » désigne donc le rôle que
`ca-server` exigera. `ra-console` n'en tient compte que pour l'affichage
(§3). Le §16 explique pourquoi le partage est tracé ainsi.

| Route | Rôle minimal | Description |
|---|---|---|
| `POST /api/v1/webauthn/register/begin` puis `/finish` | admin (ou lien d'onboarding, §10) | Enregistre un nouveau credential |
| `POST /api/v1/webauthn/login/begin` puis `/finish` | — | Ouvre une session |
| `POST /api/v1/webauthn/challenge` | authentifié | Étape 2 du schéma de signature (§4) |
| `GET /api/v1/requests?state=PENDING` | `auditeur` | Liste des demandes d'enrôlement |
| `POST /api/v1/requests/{id}/approve` | `ra_operateur` | Nécessite une assertion signée (§4) |
| `POST /api/v1/requests/{id}/reject` | `ra_operateur` | Idem |
| `POST /api/v1/certificates/{serial}/revoke` | `ca_operateur`, double contrôle | Idem, voir §8 |
| `GET /api/v1/audit/search` | `auditeur` | Recherche dans le journal chaîné (par série, opérateur, période) — lecture seule, ne modifie jamais le journal |
| `POST /api/v1/incidents` | `ra_operateur` | Ouvre un dossier d'investigation, voir §6 |
| `POST /api/v1/incidents/{id}/actions` | selon l'action liée | Consigne une action dans le dossier |
| `POST /api/v1/incidents/{id}/close` | `ra_operateur` | Clôture avec justification obligatoire |
| `GET /api/v1/quorum?state=PENDING` | tout rôle concerné par l'action | Actions M-sur-N en attente, voir §8 |
| `POST /api/v1/quorum/{id}/sign` | selon `action_kind` | Ajoute une signature ; exécute dès le seuil atteint |
| `POST /api/v1/operators` | `admin` | Initie l'onboarding d'un nouvel opérateur (§10), renvoie un lien à usage unique |
| `POST /api/v1/operators/onboarding/{token}/register` | — (token à usage unique) | L'invité enregistre sa clé FIDO2 |
| `POST /api/v1/operators/onboarding/{token}/confirm` | `admin` | Confirmation hors bande, active le compte |
| `POST /api/v1/operators/{id}/role` | `admin` | Change le rôle d'un opérateur existant |
| `POST /api/v1/credentials/{credential_id}/revoke` | `admin` | Révoque un credential (perte de clé, départ, §14) |
| `GET /api/v1/counters` | tout rôle authentifié | Compteurs agrégés pour les badges de [UI-UX.md](UI-UX.md) §2.2 — un seul appel, pas un par section (voir note temps réel ci-dessous) |
| `GET /api/v1/me/credentials` | tout rôle authentifié | Liste les clés FIDO de l'opérateur connecté (§10) |
| `POST /api/v1/me/credentials/register/begin` puis `/finish` | authentifié + réassertion | Auto-ajout d'une clé de secours (§10), sans confirmation d'un tiers |
| `DELETE /api/v1/me/credentials/{credential_id}` | authentifié | Auto-retrait ; refusé s'il s'agit de la dernière clé active (§10) |

### Mise à jour des compteurs : polling, pas de canal persistant

[UI-UX.md](UI-UX.md) §2.2 prévoit des badges dynamiques (demandes en
attente, quorum, incidents) présentés comme « temps réel ». Décision pour
ce document : un **polling court** (toutes les 10 secondes, valeur de
départ ajustable) sur `GET /api/v1/counters`, pas un canal persistant
(SSE/WebSocket). Ce n'est pas un renoncement technique mais un choix
délibéré au regard de ce que ce service est réellement :

- Une console d'opération RA/CA n'a pas les contraintes de latence d'une
  salle de marché — un badge qui se met à jour en 10 secondes plutôt qu'en
  temps réel ne dégrade aucune décision, l'opérateur ouvre de toute façon la
  liste correspondante avant d'agir.
- Un canal persistant ajoute une classe de problèmes que ce document devrait
  alors traiter et qu'il n'a pas besoin de traiter : réglage des délais
  d'inactivité de la Gateway pour ne pas couper une connexion SSE ouverte
  (aucune mention de ce réglage dans les `HTTPRoute` actuels), logique de
  reconnexion côté client, comportement pendant le verrouillage de session
  d'inactivité (§UI-UX.md 6.3).
- `GET /api/v1/counters` reste un point unique, authentifié par le même
  cookie de session que tout le reste (§2), sans mécanisme de transport
  distinct à auditer séparément — cohérent avec la préférence du dépôt pour
  peu de mécanismes, bien vérifiés, plutôt que plus de mécanismes.

Si l'usage réel montre que 10 secondes est trop lent pour un badge de
quorum critique (§8), la réponse la plus simple est de raccourcir
l'intervalle de polling avant d'envisager un canal persistant — un
changement de configuration, pas un changement d'architecture.

### Détail requête/réponse des routes non triviales

Convention commune : toute réponse d'erreur est
`{"error": "<code>", "message": "..."}` avec un statut HTTP 4xx/5xx ; aucune
route n'expose de trace interne. Les corps `PublicKeyCredential*` suivent le
format JSON standard du niveau 3 de WebAuthn (`navigator.credentials.create`/
`.get` renvoient directement des objets sérialisables dans cette forme) —
aucun format maison à inventer côté client. Côté serveur, la vérification
des assertions/attestations passe par une bibliothèque WebAuthn éprouvée
(`webauthn-rs`, pas encore une dépendance du projet) plutôt qu'une
réimplémentation, dans le même esprit que le recours à `cryptoki`/`rustls`
existant plutôt qu'à du code maison pour PKCS#11/TLS.

**`POST /api/v1/webauthn/register/begin`**

```json
// Requête (admin authentifié, ou token d'onboarding en paramètre de route)
{"operator_name": "alice"}
```
```json
// Réponse : options WebAuthn à passer telles quelles à navigator.credentials.create()
{
  "challenge": "base64url...",
  "rp": {"id": "console.open-eidas.eu", "name": "Open eIDAS Console"},
  "user": {"id": "base64url(operator_id)", "name": "alice", "displayName": "alice"},
  "pubKeyCredParams": [{"type": "public-key", "alg": -7}],
  "authenticatorSelection": {"userVerification": "required", "residentKey": "preferred", "authenticatorAttachment": "cross-platform"},
  "attestation": "direct",
  "timeout": 60000
}
```
`attestation: "direct"` est indispensable : sans lui, le navigateur peut
supprimer l'attestation du fabricant, et le serveur refuserait alors
l'enregistrement (§2 « Attestation »). `authenticatorAttachment:
"cross-platform"` oriente vers une clé de sécurité externe ; ce n'est qu'une
indication pour le navigateur. Le vrai contrôle reste la liste blanche
d'AAGUID vérifiée côté serveur.
Le serveur insère la ligne `webauthn_challenges` (`kind = 'register'`) avant
de répondre ; `/finish` échoue si aucune ligne correspondante, non expirée,
non consommée n'existe.

**`POST /api/v1/webauthn/register/finish`**

```json
// Requête : sortie brute de navigator.credentials.create(), au format JSON WebAuthn L3
{
  "id": "base64url(credential_id)",
  "rawId": "base64url...",
  "type": "public-key",
  "response": {
    "clientDataJSON": "base64url...",
    "attestationObject": "base64url..."
  }
}
```
```json
// Réponse
{"credential_id": "base64url...", "operator_id": "uuid", "status": "pending_confirmation", "key_fingerprint": "3F9A C0 12 …", "model": "<description du modèle, tirée de la liste blanche>"}
```
`ra-console` relaie la réponse d'enregistrement à `ca-server`, avec le jeton
d'invitation ou, pour un ajout en libre-service, le corps signé par une clé
déjà active (§10). `ca-server` vérifie ensuite lui-même :
- dans `clientDataJSON` : le type `webauthn.create`, l'origine attendue et
  le `rpIdHash` ;
- l'attestation, contre la liste blanche ;
- les drapeaux vérification de l'utilisateur et `BE = 0`.

Puis il range la clé dans `pending_credentials`, *pas* dans le registre :
tant qu'aucune confirmation signée n'est arrivée, elle ne permet ni de se
connecter ni d'agir.

`key_fingerprint` sert à la confirmation hors bande (§10) : l'invité le lit
sur *son* écran, l'admin le compare à celui qu'il s'apprête à signer.
Portée exacte de cette comparaison :
- **Elle protège contre l'interception du lien d'invitation.** Si un tiers
  a enregistré sa clé en premier, l'empreinte que l'invité lit ne
  correspond pas à celle que voit l'admin, qui refuse.
- **Elle ne protège pas contre une console compromise**, qui produit les
  deux écrans et peut y afficher la même fausse empreinte.

Contre ce dernier cas, la garantie est une *détection* rapide, pas une
prévention : la vraie clé de l'invité échouera à la première action
qu'elle tentera, puisque `ca-server` vérifie contre le registre, où c'est
une autre clé qui figure. C'est le risque résiduel R2 (§22), appliqué à
l'enregistrement.

**`POST /api/v1/webauthn/login/finish`**

```json
// Réponse en cas de succès
{"session": "opaque-256-bits", "operator": {"id": "uuid", "name": "alice", "role": "ra_operateur"}}
```
Le cookie de session est posé par le serveur (`Set-Cookie`, `HttpOnly`,
`Secure`, `SameSite=Strict`) ; le corps JSON ne renvoie `session` que pour
les clients non-navigateur (scripts d'exploitation), un navigateur n'a pas
besoin de le lire.

**`POST /api/v1/webauthn/challenge`** (étapes 1 à 3 du schéma de signature, §4)

```json
// Requête : l'action prévue. Le corps final est fixé par ca-server, pas par le client.
{"action": "revoke", "serial": "5a3f...", "reason": 4, "comment": "Signalement CERT-FR #2026-991"}
```
```json
// Réponse : le corps figé par ca-server, à afficher tel quel, et les options WebAuthn
{
  "challenge_id": "uuid",
  "body": {"action": "revoke", "serial": "5a3f...", "reason": 4, "comment": "...", "expires_at": "..."},
  "body_hash": "e3b0c442 98fc1c14 …",
  "webauthn": {"challenge": "base64url(challenge tiré par la bibliothèque)", "allowCredentials": [...], "userVerification": "required", "timeout": 60000}
}
```
`body` est celui que `ca-server` exécutera. `body_hash` s'affiche dans la
fenêtre de signature de [UI-UX.md](UI-UX.md) §3.1, et se retrouve dans le
journal de `ca-server`.

**`POST /api/v1/requests/{id}/approve`**

```json
// Requête : l'identifiant du challenge et l'assertion obtenue. Pas de corps.
{
  "challenge_id": "uuid",
  "assertion": {"id": "...", "rawId": "...", "type": "public-key", "response": {"clientDataJSON": "...", "authenticatorData": "...", "signature": "...", "userHandle": "..."}}
}
```
```json
// Réponse
{"transaction_id": "...", "state": "APPROVED", "decided_by": "alice"}
```
`ra-console` relaie `challenge_id` et l'assertion brute à `ca-server`
(`POST /internal/v1/actions`). C'est `ca-server` qui vérifie tout (§4,
étape 6). Le corps qu'il exécute est celui qu'il a figé à l'émission du
challenge. Il contrôle que ce corps désigne bien *cette* `transaction_id`,
pour qu'une signature ne puisse pas servir à une autre demande. Il
n'appelle `oe_raflow::Decider::approve` qu'ensuite, avec l'identité lue dans
son registre. `decided_by` est cette identité-là, renvoyée par `ca-server`,
pas celle de la session `ra-console`. L'état renvoyé est `APPROVED`, pas
`ISSUED` : comme aujourd'hui, le certificat n'est signé qu'au prochain appel
du demandeur à l'enrôlement (`resume()`, §16).

**`POST /api/v1/quorum/{id}/sign`**

```json
// Requête, même forme que /requests/{id}/approve
{"challenge_id": "uuid", "assertion": { "...": "..." }}
```
```json
// Réponse tant que le seuil n'est pas atteint
{"quorum_request_id": "uuid", "signatures": 1, "required": 2, "status": "AWAITING_QUORUM"}
```
```json
// Réponse dès que la signature déclenche l'exécution
{"quorum_request_id": "uuid", "signatures": 2, "required": 2, "status": "EXECUTED", "result": { "...": "action-dépendant" }}
```
Retourne `409 Conflict` (`{"error": "duplicate_signer"}`) si l'opérateur
authentifié a déjà signé cette même `quorum_request_id`. La contrainte
`UNIQUE(quorum_request_id, operator_id)` de la table de collecte de
`ra-console` (§8) donne ce retour immédiat à l'interface. Ce n'est qu'un
confort : la garantie que les N signatures viennent de N opérateurs
distincts est vérifiée par `ca-server` au moment de l'exécution, sur son
propre registre et par sa contrainte
`UNIQUE(action_id, operator_id)` de `decision_evidence`.

**`GET /api/v1/audit/search`**

```
GET /api/v1/audit/search?serial=5a3f...&from=2026-09-01T00:00:00Z&to=2026-09-19T00:00:00Z
```
```json
{
  "chain_verified": true,
  "entries_checked": 14285,
  "results": [
    {"sequence": 14201, "at": "2026-09-12T10:03:11Z", "operator": "alice", "kind": "REVOKE", "payload": {"serial": "5a3f...", "reason": 4}}
  ]
}
```
`chain_verified`/`entries_checked` portent sur l'intégralité du journal
relu pour cette requête (§7), pas seulement sur les entrées retournées — un
`chain_verified: false` doit bloquer l'affichage des résultats plutôt que
les montrer à côté d'une alerte, pour qu'aucun opérateur ne puisse ignorer
une rupture par inattention.

## 6. Workflow d'incident (investigation)

Un dossier d'incident est une structure d'imputabilité, pas un nouveau
pouvoir : chaque action qu'il déclenche (révocation, suspension) passe par
les API existantes du §5, avec leurs propres contrôles — le dossier
regroupe et justifie, il ne contourne rien.

Table proposée (même logique d'imputabilité que `enrollment_requests`) :

```sql
CREATE TABLE incidents (
    id           UUID PRIMARY KEY,
    title        TEXT        NOT NULL,
    opened_by    TEXT        NOT NULL,
    opened_at    TIMESTAMPTZ NOT NULL,
    state        TEXT        NOT NULL
        CHECK (state IN ('OUVERT', 'CLOS')),
    closed_by    TEXT,
    closed_at    TIMESTAMPTZ,
    closing_note TEXT,
    CONSTRAINT closing_imputable CHECK (
        state = 'OUVERT' OR (closed_by IS NOT NULL AND closing_note <> '')
    )
);

CREATE TABLE incident_actions (
    id          UUID PRIMARY KEY,
    incident_id UUID        NOT NULL REFERENCES incidents(id),
    at          TIMESTAMPTZ NOT NULL,
    operator    TEXT        NOT NULL,
    kind        TEXT        NOT NULL,  -- 'note', 'revocation_liee', 'export_logs', ...
    reference   TEXT,                  -- ex. serial_hex si kind = 'revocation_liee'
    detail      TEXT        NOT NULL DEFAULT ''
);
```

Ces deux tables appartiennent à `ra-console` : un dossier n'a aucun pouvoir
sur la PKI, il regroupe et justifie. Chaque `incident_action` est écrite
dans le journal chaîné **de `ra-console`** (une instance `oe-audit` propre,
dans un fichier distinct), avec l'`incident_id` en référence croisée. En
revanche, l'action qu'elle désigne (une révocation par exemple) figure dans
le journal **de `ca-server`**, qui l'a vérifiée et exécutée (§4). Les deux
journaux se recoupent par le `body_hash` de l'action (§4) : le dossier
affirme « révocation liée à l'incident I », et le journal de `ca-server` le
confirme avec la preuve (`decision_evidence`).

## 7. Deux journaux chaînés, interrogés en lecture seule

Deux écrivains, deux chaînes, jamais un fichier partagé :

- **`ca-server`** écrit tout ce qui fait foi pour la PKI et le registre :
  émissions, décisions, révocations, invitations, activations et retraits
  de clés d'opérateurs, changements de rôle.
- **`ra-console`** écrit ce qui relève de l'usage de la console :
  connexions, sessions, refus de connexion (dont les régressions de
  compteur détectées), dossiers d'incident.

Un `ra-console` compromis ne peut donc ni écrire, ni même ajouter de faux
événements dans le journal qui fait foi.

`GET /api/v1/audit/search` ne doit avoir aucun chemin d'écriture. Il relit
les deux fichiers avec la même logique de vérification de chaîne que
`ca-server verify-audit` (voir ARCHITECTURE.md §7) avant de répondre,
plutôt que de faire confiance à un index qui pourrait avoir divergé des
fichiers source après une modification malveillante. `chain_verified` porte
sur les deux chaînes. Chaque résultat indique de quel journal il provient.

## 8. Contrôle à double personne pour les actions critiques

FIDO répond à « qui a agi », pas à « une seule personne a-t-elle suffi » —
voir §2. Pour les actions déjà identifiées comme sensibles dans
`docs/CONFORMITE-ETSI.md` (cérémonie de clé, §6.5.1 EN 319 411-1) et pour
la révocation d'une autorité elle-même (pas un certificat terminal), le
schéma de signature du §4 se généralise en M-sur-N : la requête n'est
exécutée que lorsque *N* assertions provenant de *N* credentials distincts
ont signé des challenges liés à la même action (le même corps figé par
`ca-server`, §4), dans une fenêtre de temps bornée. Un seul opérateur, même avec deux clés à lui, ne peut pas satisfaire
cette condition — les credentials engagés doivent appartenir à des
opérateurs différents.

**Répartition des rôles entre les deux services.** `ra-console` *collecte*
les signatures au fil de l'eau (tables ci-dessous) : il sait qui a déjà
signé, affiche la salle d'attente de [UI-UX.md](UI-UX.md) §3.2 et relaie
l'ensemble à `ca-server` une fois le seuil atteint. **C'est `ca-server` qui
fait respecter la règle.** Le nombre de signatures exigé et le rôle requis
pour chaque type d'action viennent de *sa* politique (code ou
configuration de `ca-server`), jamais d'un champ transmis par `ra-console` :
sinon une console compromise ramènerait `required_signatures` à 1. Pour
chacune des N assertions, `ca-server` effectue toutes les vérifications du
§4. Il contrôle ensuite que les N opérateurs, lus dans son registre, sont
distincts et ont chacun le rôle requis. Enfin il exécute une seule fois :
le challenge est consommé dans la même transaction.

Ce mécanisme ne remplace pas la cérémonie en présence d'un témoin indépendant
que vise la cible actuelle du CPS ; il en est le pendant numérique pour les
actions qui, elles, doivent rester exécutables à distance (ex. révocation
d'urgence d'une CA hors heures ouvrées).

**Ce qui est construit (étape 4, 2026-09-27) diffère du schéma ci-dessous, en
plus sûr.** `ca-server` enregistre chaque signature au fil de l'eau
(`decision_evidence`, une ligne par opérateur, `UNIQUE(action_id, operator_id)`)
et n'exécute qu'au seuil : chaque signataire obtient son propre challenge sur
l'action figée (`issue_challenge_for`), et son assertion est vérifiée et
consommée aussitôt. `ra-console` n'a donc aucune table de collecte et ne
conserve jamais d'assertion : sa salle d'attente lit `actions` et
`decision_evidence` en lecture seule (voir [RA-CONSOLE.md](RA-CONSOLE.md)).
Les tables qui suivent sont conservées pour mémoire de la conception initiale.

Tables de collecte, côté `ra-console` (propriété et droits : §2, §16) — **non
construites** :

```sql
CREATE TABLE quorum_requests (
    id                   UUID        PRIMARY KEY,
    action_kind          TEXT        NOT NULL,  -- 'revoke_authority', 'ceremony', ...
    request_body         JSONB       NOT NULL,  -- corps canonique, voir §4
    -- Copie pour l'affichage (« 1 signature sur 2 »). La valeur qui fait
    -- foi est celle de la politique de ca-server, relue à l'exécution.
    required_signatures  INTEGER     NOT NULL CHECK (required_signatures >= 2),
    created_by           TEXT        NOT NULL,
    created_at           TIMESTAMPTZ NOT NULL,
    expires_at           TIMESTAMPTZ NOT NULL,
    executed_at          TIMESTAMPTZ
);

-- Refuse tout de suite une seconde signature de la même personne, pour que
-- l'interface puisse le dire (409 duplicate_signer, §5). Ce n'est qu'un
-- confort : la garantie opposable est portée par ca-server, à l'exécution
-- (UNIQUE(action_id, operator_id) de decision_evidence, §2).
CREATE TABLE quorum_signatures (
    id                 UUID        PRIMARY KEY,
    quorum_request_id  UUID        NOT NULL REFERENCES quorum_requests(id),
    operator_id        UUID        NOT NULL REFERENCES operators(id),
    credential_id      TEXT        NOT NULL REFERENCES webauthn_credentials(credential_id),
    -- Assertion brute, conservée pour être relayée telle quelle à
    -- ca-server au moment où le seuil est atteint.
    assertion          JSONB       NOT NULL,
    signed_at          TIMESTAMPTZ NOT NULL,
    UNIQUE (quorum_request_id, operator_id)
);
```

**L'exécution a lieu une seule fois, même sous concurrence.** Si deux
signatures atteignent le seuil au même instant, `ra-console` peut relayer
deux fois le même lot à `ca-server`. Le premier relais pose
`actions.executed_at` et consomme les challenges (`action_challenges`, §2)
dans la transaction qui exécute l'action. Le second trouve l'action déjà
exécutée et échoue, sans rien exécuter. La garantie est portée par la base de `ca-server` : elle
tient même si `ra-console` se trompe ou est compromis.

## 9. Impact sur la matrice de conformité ETSI

À la mise en œuvre, ce chantier permet de :

- renforcer §6.2.1 EN 319 411-1 (déjà couvert par l'imputabilité en base) en
  la rendant *vérifiable cryptographiquement* plutôt que déclarative. Chaque
  décision conserve sa preuve (`decision_evidence`, §2). Un auditeur vérifie
  la signature avec la clé publique du registre *et* l'intégrité du journal
  chaîné de `ca-server`, qui lie le challenge au corps (§4) : la signature
  seule ne suffit pas, c'est une limite assumée de la bibliothèque retenue.
  La preuve ne repose en revanche ni sur `ra-console` ni sur un journal
  applicatif modifiable après coup ;
- réduire, sans le clore entièrement, l'écart §6.5.1 EN 319 411-1 (double
  contrôle) pour les actions qui passent par le schéma M-sur-N du §8 — la
  cérémonie de clé physique sur HSM certifié reste hors périmètre logiciel ;
- documenter dans le CPS (`docs/CPS.md`, section A.4.7 notamment) le nouveau
  mécanisme de révocation à distance authentifiée, qui n'existe pas
  aujourd'hui (seul le CLI local y donne accès).

Chaque changement de statut dans `docs/CONFORMITE-ETSI.md` devra être fait
dans `oe_conformance::system_matrix` (le code), pas dans le Markdown
généré — rappel déjà posé dans `docs/CPS.md` : la matrice ne se vérifie pas
elle-même, un humain doit la tenir à jour à chaque changement de
comportement réel.

## 10. Onboarding et gestion des comptes/clés FIDO

**Principe commun : le registre des opérateurs est une chaîne de
signatures, ancrée dans `ca-server`.** Toute clé du registre y est entrée
par une action signée avec une clé *déjà* présente dans le registre, et
vérifiée par `ca-server` (§4). En remontant la chaîne, on arrive toujours
au premier administrateur, enregistré au Jour 0 depuis le CLI local de
`ca-server`. `ra-console` ne fait que présenter les écrans et relayer les
signatures. Il ne peut pas s'ajouter une clé : c'est ce qui rend le
correctif du §16 effectif (sans cette chaîne, une console compromise
écrirait sa propre clé publique dans le registre et signerait à volonté).

Trois cas :

- **Amorçage du tout premier administrateur** (aucun opérateur n'existe
  encore). Il ne peut pas passer par une action signée, puisqu'aucune clé
  n'existe pour signer. C'est un acte d'amorçage local, analogue à
  `ca-server ceremony` aujourd'hui, et il appartient donc à `ca-server`, pas
  à `ra-console` :
  1. `ca-server operators bootstrap-admin <nom>`, exécuté sur l'hôte de
     `ca-server`, crée l'opérateur et une invitation à usage unique de
     courte durée (ex. 15 min, `operator_invites`).
  2. L'événement est consigné dans le journal de `ca-server` dès la
     création de l'invitation, pas seulement à son utilisation, pour qu'une
     invitation générée puis jamais consommée reste visible.
  3. L'administrateur enregistre sa clé par la console, qui relaie
     l'enregistrement. `ca-server` vérifie le jeton et l'attestation, puis
     inscrit la clé directement dans le registre
     (`initiated_by = 'bootstrap-admin'`, seule exception admise par la
     contrainte du §2).
  4. La commande refuse de s'exécuter si un administrateur actif existe
     déjà. Le bootstrap sert à amorcer le système, pas à reprendre la main
     sur un système qui a déjà des administrateurs. Conséquence : si tous
     les administrateurs perdent leurs clés, il n'y a plus d'issue par cette
     commande. La voie de récupération, volontairement plus lourde, est
     décrite au §21 (`recover-admin`).
- **Onboarding de tout opérateur suivant**, en deux actions signées par un
  admin, séparées par l'enregistrement de l'invité :
  1. *Invitation* : l'admin signe « inviter `<nom>` au rôle `<rôle>` ».
     `ca-server` vérifie la signature, crée l'opérateur et l'invitation, et
     renvoie le lien à usage unique.
  2. *Enregistrement* : l'invité ouvre le lien sur son propre poste et
     enregistre sa clé. `ca-server` vérifie l'attestation et range la clé
     dans `pending_credentials`, hors du registre (§5).
  3. *Confirmation* : l'admin vérifie l'identité de l'invité de visu, ou
     par un canal hors bande (téléphone, vidéo). Il compare l'empreinte de
     clé que l'invité lit sur son écran avec celle affichée par la console,
     puis signe « activer la clé d'empreinte `<F>` pour `<nom>` ».
     L'empreinte fait partie du corps signé : l'admin s'engage sur *cette*
     clé, pas sur « la clé en attente de `<nom>` », quelle qu'elle soit.
     `ca-server` fait alors passer la clé dans le registre. Portée et
     limite de cette comparaison : voir `register/finish` au §5.
- **Auto-gestion : un opérateur déjà actif ajoute ou retire lui-même une de
  ses clés**, sans admin ni confirmation hors bande. La confirmation
  d'identité n'a de sens qu'une fois, à la création du compte. La répéter à
  chaque clé de secours n'apporterait rien que la signature par une clé
  déjà vérifiée ne prouve déjà. Deux garde-fous :
  - **Ajout** : la nouvelle clé est enregistrée (attestation vérifiée par
    `ca-server`, rangée en attente), puis l'opérateur signe avec une clé
    *déjà active* « ajouter la clé d'empreinte `<F>` à mon compte ».
    `ca-server` vérifie la signature et active la clé :
    - `confirmed_by` vaut l'opérateur lui-même ;
    - `confirmed_at` vaut l'instant de cette signature.

    Une session ouverte ne suffit pas. Sans cette signature, une session
    volée permettrait de planter une clé de secours pour un attaquant,
    invisible tant que le titulaire légitime ne perd pas sa propre clé.
  - **Retrait** : l'opérateur signe « retirer la clé `<id>` ». `ca-server`
    refuse, dans la transaction même, s'il s'agit de sa dernière clé
    active. Se retrouver sans aucune clé redevient le cas « perte de clé »
    du §14, qui passe par un admin.

**Autres actions sur le registre**, toutes signées et vérifiées par
`ca-server` :
- révocation de la clé d'un tiers par un admin (perte signalée, départ) ;
- changement de rôle.

Proposition de politique, à valider avec O5 (§22) : élever un opérateur au
rôle `admin` exige la signature de deux admins (quorum, §8). C'est le seul
rôle qui peut modifier le registre lui-même, et une élévation par un seul
admin compromis suffirait sinon à en créer d'autres.

Chaque entrée dans le registre et chaque sortie laissent une trace dans le
journal de `ca-server` : qui a initié, qui a confirmé, avec quelle preuve
(`decision_evidence`). C'est la racine de confiance de tout ce que fait
ensuite la console, et elle mérite la même rigueur que l'émission d'un
certificat.

## 11. Émission de certificats d'identité — points de vigilance eIDAS

**Décision affinée : non qualifié statutairement, mais construit comme s'il
visait la qualification — même posture que le reste du projet.**
`docs/ARCHITECTURE.md` §8 et `docs/CONFORMITE-ETSI.md` appliquent déjà cette
règle à toute la TSA : le système est bâti au niveau d'exigence d'un service
qualifié, la matrice distingue honnêtement ce qui est *couvert* de ce qui
reste *hors périmètre logiciel* (l'audit par un organisme accrédité,
EN 319 403-1), et rien ne prétend être qualifié tant que cet audit n'a pas eu
lieu. Ce module d'identité suit exactement la même ligne plutôt que d'en
inventer une nouvelle :

- **Ce qui reste au niveau qualifié, sans concession.** Profil de certificat
  complet selon ETSI EN 319 412-2, preuve d'identité menée au niveau
  substantiel/élevé au sens eIDAS Art. 24 en pratique (vérification en
  personne ou équivalent supervisé — voir ci-dessous), clé de l'utilisateur
  final protégée par un module cryptographique quand le poste de l'usager
  le permet (dans l'esprit de `QcSSCD` sans en revendiquer le statut légal),
  durée de vie plafonnée et vérifiée comme tout profil existant. Rien de
  tout cela n'est réservé aux PSCo qualifiés : c'est de la rigueur
  technique, pas un privilège statutaire.
- **La seule ligne qu'on ne franchit pas avant l'audit : les assertions
  légales, pas la rigueur technique.** L'extension `QCStatements`
  (`id-etsi-qcs-QcCompliance`, EN 319 412-5) est une déclaration juridique
  qu'un organisme accrédité a vérifiée — la poser sans audit serait une
  fausse déclaration, pas une anticipation. Le profil ne l'inclut donc pas
  tant que la qualification n'est pas obtenue, et le `serialNumber` du sujet
  utilise un espace de nommage propre à l'association plutôt que le format
  d'un identifiant national eIDAS-notifié (réservé aux schémas notifiés).
  La politique de certification affichée dans l'UI et le certificat porte
  une mention explicite et stable : « émis selon les exigences techniques
  ETSI EN 319 412-2 ; qualification eIDAS en cours, non encore obtenue » —
  vérifiable, datée, jamais présentée comme un fait accompli.
- **Preuve d'identité : le même niveau d'exigence que si l'audit avait déjà
  eu lieu.** Le flux RA existant (`oe_raflow`, authentification HMAC de la
  CSR) n'authentifie qu'une requête, pas un humain. Proposition : réutiliser
  le mécanisme d'onboarding administrateur du §10 (lien à usage unique +
  vérification en personne ou par canal hors bande équivalent à une
  identification supervisée), avec la méthode exacte consignée en
  commentaire de la décision RA (`enrollment_requests.comment`, déjà
  obligatoire à la décision) — de sorte qu'un futur audit d'accréditation
  puisse rejouer la procédure sur des dossiers réels, pas seulement sur la
  documentation.

Conception :

- **Nouveau profil `identity_person`** dans `crates/oe-ca-core/src/profile.rs`
  (aux côtés de `tsa_signer`/`ocsp_responder`), conforme EN 319 412-2 :
  `keyUsage` digitalSignature (+ nonRepudiation si un usage de signature est
  visé), `extKeyUsage` clientAuth et/ou emailProtection selon l'usage réel,
  `CA:FALSE` critique, `subjectAltName` si une adresse email est portée, pas
  de `QCStatements` tant que non qualifié (voir ci-dessus).
- **Réutilise l'enrôlement existant** (`oe_raflow::Flow::submit` puis
  décision RA) plutôt qu'un nouveau pipeline : la personne génère sa propre
  paire de clés et sa CSR côté client (l'UI ne doit jamais voir ni manipuler
  la clé privée d'un utilisateur final), la soumet authentifiée, un
  opérateur RA vérifie l'identité au niveau substantiel/élevé et approuve —
  exactement le circuit §A.3.3 du CPS, avec ce nouveau profil en plus des
  deux existants.
- **Durée de vie courte par défaut** et renouvellement par re-soumission,
  cohérent avec ce que `oe_conformance::check_certificate_lifetime` applique
  déjà pour plafonner tout profil.
- **Entrée dédiée dans `docs/CONFORMITE-ETSI.md`** dès l'implémentation
  (nouvelles lignes EN 319 412-2, statut *couvert* pour le profil et la
  preuve d'identité procédurale, *hors périmètre logiciel* pour la
  qualification elle-même — la même ligne que celle déjà posée pour la TSA
  au §7 EN 319 403-1, pas une seconde ligne d'audit séparée).

Ce module reste indépendant du reste de ce document (authentification
WebAuthn des opérateurs, workflow d'incident) : il ajoute un profil et un
écran d'émission par-dessus une architecture d'enrôlement qui existe déjà,
il ne remplace rien.

### Flux détaillé de dépôt (demandeur externe)

Le demandeur externe n'est jamais un opérateur : pas de compte, pas de clé
FIDO2, pas de session sur `ra-console`. Il ne passe **pas** par
`POST /api/v1/enroll` — cette route reste, comme aujourd'hui,
strictement interne au cluster
(`deploy/helm/open-eidas/templates/ca/httproute.yaml` : « l'API d'enrôlement
reste interne au cluster »), puisque rien ne l'oblige à changer pour les
services d'infrastructure qui l'utilisent déjà (TSU, OCSP). À la place,
`bin/ca-server` expose une route publique **distincte et volontairement
étroite**, `POST /api/v1/identity/enroll`, qui délègue à la même logique
métier (`oe_raflow::Flow::submit`) mais impose côté routeur, avant même
d'atteindre cette logique : `profile` figé à `"identity_person"` (toute
autre valeur soumise sur ce chemin est rejetée sans même consulter la base)
et `enrollment_token` obligatoire, jamais optionnel sur ce chemin. Résout le
risque R1 du §22 en évitant d'élargir la surface publique de la route
d'enrôlement générique : ce qui devient public, c'est un chemin qui ne peut
techniquement rien faire d'autre qu'ouvrir ou faire progresser une demande
de certificat d'identité munie d'un jeton valide — jamais spammer les
profils d'infrastructure, jamais contourner la vérification d'identité
puisqu'un jeton n'existe qu'après elle.

**Ce que `oe_raflow::Flow::submit` fait déjà, à ne pas dupliquer.** La
vérification HMAC porte sur *chaque* appel, y compris une re-soumission :
c'est ce qui permet à un client de repolliner l'état de sa demande en
renvoyant simplement la même CSR et la même signature après le
`retry_after` reçu (`resume()`, voir `crates/oe-raflow/src/lib.rs`) — il n'y
a pas besoin d'un second endpoint de consultation de statut, le mécanisme
de polling existe déjà pour les services d'infrastructure et se réutilise
tel quel.

**Ce qui manque : un secret par personne, pas un secret unique pour tout le
serveur.** Aujourd'hui, `oe_raflow::Flow` ne connaît qu'un seul
`hmac_secret` de configuration, partagé par tous les enrôlements
d'infrastructure (TSU, OCSP) — adapté à un petit nombre de services connus
à l'avance, pas à une population de demandeurs individuels. Ce schéma HMAC
reste inchangé pour l'infrastructure. Pour les personnes, extension
proposée :

1. Un opérateur RA, **après avoir vérifié l'identité en personne** (ou par
   le moyen supervisé équivalent retenu ci-dessus), signe l'action « créer
   un jeton d'enrôlement pour `<sujet>` » (`POST /api/v1/identity-enrollments`,
   relayée à `ca-server` comme toute écriture, §5).
2. `ca-server` vérifie la signature, puis génère un `enrollment_token`
   (identifiant public) et un secret aléatoire de 256 bits. Il ne conserve
   que le haché du secret, et le renvoie une seule fois pour affichage :

   ```sql
   -- Table de ca-server : c'est lui qui vérifie les soumissions.
   CREATE TABLE identity_enrollment_tokens (
       token          TEXT        PRIMARY KEY,
       secret_hash    BYTEA       NOT NULL,  -- SHA-256 du secret, jamais le secret
       subject_name   TEXT        NOT NULL,
       profile        TEXT        NOT NULL,
       created_by     TEXT        NOT NULL,  -- opérateur RA, lu dans le registre
       created_at     TIMESTAMPTZ NOT NULL,
       expires_at     TIMESTAMPTZ NOT NULL,  -- courte durée, ex. 24h
       -- Posé à la première CSR acceptée avec ce token : le token authentifie
       -- ensuite le polling de *cette* demande, mais ne peut plus en ouvrir
       -- une seconde avec une CSR différente.
       bound_fingerprint TEXT
   );
   ```

   **Pourquoi un secret présenté tel quel, et pas une clé HMAC.** Pour
   vérifier un HMAC, le serveur doit détenir la clé elle-même, pas son
   haché. Une version antérieure de ce document stockait pourtant un haché
   tout en décrivant une signature HMAC : les deux étaient incompatibles.
   Le choix retenu est le secret présenté tel quel dans la requête (le TLS
   en protège le transit). Il permet de ne garder que le haché en base, si
   bien qu'une lecture de la base par un attaquant ne lui donne pas de quoi
   soumettre à la place du demandeur. La liaison du secret à une CSR
   précise, qu'apportait le HMAC, est assurée par `bound_fingerprint`.
3. Le secret est remis **en main propre**, pendant le rendez-vous de
   vérification d'identité (QR code affiché à l'écran, jamais envoyé par
   email en clair) — le canal de remise du secret doit avoir la même
   garantie que la vérification d'identité elle-même, sinon cette dernière
   ne sert à rien.
4. Le demandeur génère sa paire de clés et sa CSR **localement, avec un
   outil qu'il contrôle** (`openssl req` suffit ; l'UI de `ra-console` ne
   doit jamais voir ni transporter une clé privée d'utilisateur final), et
   soumet `{"pkcs10": "...", "enrollment_token": "...",
   "enrollment_secret": "..."}` à `POST /api/v1/identity/enroll`. Pas de
   champ `profile` à fournir : la route l'impose elle-même.
5. `oe_raflow::Flow::submit` (étendu) retrouve le jeton, compare en temps
   constant le haché du secret présenté à `secret_hash` et vérifie
   l'échéance, puis :
   - si `bound_fingerprint` est vide, l'accepte et le fixe à l'empreinte de
     cette CSR (première ouverture) ;
   - si `bound_fingerprint` est déjà posé, n'accepte que cette même
     empreinte (polling légitime) et rejette toute CSR différente — un
     token compromis après coup ne permet donc pas d'ouvrir une seconde
     identité, seulement de relire l'état de la demande déjà associée.
6. Le demandeur reçoit `transaction_id` (déterministe, dérivé de sa CSR —
   il peut le recalculer sans rien conserver côté client, comme le prévoit
   déjà `oe_raflow::transaction_id`) et un `retry_after`. Il repollinera en
   renvoyant le même appel jusqu'à obtenir `certificate`/`chain` dans la
   réponse, exactement comme un service d'infrastructure le fait
   aujourd'hui.
7. **Approbation liée à la clé du demandeur, vérifiée avec lui.** Le corps
   que signe l'opérateur RA pour approuver contient l'empreinte de la clé
   publique de la CSR (`csr_fingerprint`), pas seulement le
   `transaction_id`. Avant de signer, l'opérateur fait lire cette empreinte
   au demandeur (téléphone, visio). Le demandeur la calcule *avec son
   propre outil* :

   ```
   openssl req -in demande.csr -pubkey -noout | openssl pkey -pubin -outform DER | sha256sum
   ```

   Ici, contrairement à l'onboarding d'un opérateur (§10), la comparaison
   protège réellement contre une console compromise. La valeur du
   demandeur vient d'un outil que la console ne contrôle pas. Si la console
   fait approuver une autre demande que celle du demandeur, les deux
   empreintes diffèrent. C'est aussi ce qui neutralise la course au jeton :
   un attaquant qui aurait intercepté le secret et soumis sa CSR le premier
   produirait une empreinte que le demandeur ne reconnaîtrait pas.
8. Le rejet suit le même chemin qu'un rejet RA classique
   (`oe_raflow::Decider::reject`, exécuté par `ca-server` après
   vérification de la signature) : la réponse renvoyée au demandeur reste
   volontairement laconique (voir le commentaire déjà présent dans
   `handle_enroll` sur la distinction secret/CSR), la justification
   détaillée restant dans le journal d'audit et la vue opérateur, jamais
   exposée publiquement.

## 12. Liste fonctionnelle des interfaces nécessaires

Périmètre fonctionnel — le rendu visuel de chaque écran est spécifié dans
[UI-UX.md](UI-UX.md), pas ici.

| Écran | Rôle minimal | Fonction |
|---|---|---|
| Connexion | — | Assertion WebAuthn, pas de mot de passe (§2) |
| Tableau de bord | tous | Compteurs (demandes en attente, quorum en attente, incidents ouverts), état HSM/CRL, raccourci vers l'action la plus urgente |
| File de demandes d'enrôlement | `auditeur` (lecture), `ra_operateur` (décision) | Liste + inspecteur CSR, approbation/rejet signés (§4) |
| Détail d'un certificat émis | `auditeur` | Recherche par série/DN/date, statut, chaîne, historique d'audit lié |
| Révocation | `ca_operateur` | Formulaire motif RFC 5280 + justification, signature (§4) |
| Salle de quorum | `ca_operateur` (ou rôle concerné par l'action) | Actions M-sur-N en attente d'une seconde signature (§8) |
| Dossiers d'incident | `ra_operateur`+ | Ouverture, actions liées, clôture justifiée (§6) |
| Explorateur d'audit | `auditeur` | Recherche en lecture seule dans le journal chaîné, vérification de chaîne visible (§7) |
| Conformité ETSI | `auditeur` | Miroir de `GET /api/v1/conformance`, déjà servi par `ca-server` |
| Gestion des opérateurs | `admin` | Liste des opérateurs/credentials, initiation d'onboarding (§10), changement de rôle, révocation de credential |
| Mes clés de sécurité | tout rôle authentifié | Liste de ses propres clés FIDO (nom donné, dernière utilisation, date d'ajout), ajout d'une clé de secours avec réassertion, retrait d'une clé qui n'est pas la dernière (§10) |
| Émission de certificat d'identité | `ra_operateur` (décision), le demandeur (soumission) | CSR déposée par le demandeur, vérification d'identité, décision — voir §11 |

## 13. Flux utilisateurs par persona

- **Auditeur** : connexion → tableau de bord → explorateur d'audit ou liste
  de certificats, en lecture seule de bout en bout. Aucun flux de ce
  persona ne déclenche de modale WebAuthn de signature — seulement la
  session de login.
- **Opérateur RA** : connexion → file de demandes → sélection d'une demande
  → lecture du CSR et, pour un certificat d'identité, de la preuve
  d'identité apportée hors bande → décision signée → la demande quitte la
  file, l'événement apparaît immédiatement dans l'audit de ce même
  opérateur (fermeture de boucle visible sans changer d'écran).
- **Opérateur CA** : hérite du flux RA, plus un flux de révocation
  (recherche du certificat → formulaire motif/justification → signature) et
  un flux de quorum (soit initiateur, soit second validateur — jamais les
  deux pour la même action, contrôle serveur, §8).
- **Administrateur** : flux d'onboarding (§10) dans les deux sens — initier
  l'enrôlement d'un nouvel opérateur, ou confirmer hors bande un
  enrôlement en cours. Flux additionnel de gestion du cycle de vie d'un
  credential (perte de clé signalée → révocation immédiate du credential →
  ré-enrôlement).
- **Demandeur externe (sujet d'un certificat d'identité)** : ne se connecte
  jamais à cette UI avec un rôle opérateur. Il génère sa CSR côté client
  avec un outil qu'il contrôle, la soumet au même endpoint d'enrôlement
  public que les demandes de certificats d'infrastructure, authentifiée par
  le secret à usage court remis lors de la vérification d'identité — détail
  complet du parcours en §11. Il suit ensuite son statut via l'identifiant
  de transaction déjà retourné par `oe_raflow::Flow::submit` — un flux de
  consultation minimal, sans
  authentification WebAuthn puisque ce n'est pas un opérateur du service.

## 14. Jour 0 / Jour 2

**Jour 0 — amorçage**, tout ce qui doit fonctionner avant que la console
n'ait un seul utilisateur régulier :

- **Ordre d'amorçage**, chaque étape dépendant de la précédente :
  1. `ca-server` démarre, cérémonie faite, et enregistre sa demande de
     certificat `internal_server` (§16) ;
  2. `ra-console` démarre et enregistre sa demande `internal_client` ;
  3. un opérateur nommé approuve ces deux demandes au CLI
     (`ca-server ra approve`, §20) ;
  4. `ca-server operators bootstrap-admin` crée l'invitation du premier
     administrateur (§10), qui enregistre sa clé par la console désormais
     joignable.

  Toutes ces étapes demandent un accès local à l'hôte de `ca-server` et
  aucune ne passe par une décision de `ra-console` : la console ne peut pas
  s'amorcer elle-même.
- Politique fixe dans le code de `ca-server`, pas configurable en base :
  - les quatre rôles (§3) ;
  - le nombre de signatures et le rôle exigés par type d'action (§8).

  Un rôle mal défini ou un quorum abaissé serait un trou de contrôle
  d'accès, pas un paramètre de déploiement.
- Vérification que la base d'`operators`/`webauthn_credentials` est
  sauvegardée par le même mécanisme que `enrollment_requests`/
  `certificates` (même instance PostgreSQL aujourd'hui, voir
  `crates/oe-castore`) — pas une base séparée qu'on oublierait de
  sauvegarder.
- Premier exercice à blanc du flux de quorum (§8) avant mise en service :
  un mécanisme de double contrôle qu'on découvre en situation d'incident
  réel plutôt qu'à l'entraînement a de bonnes chances d'échouer au pire
  moment.

**Jour 2 — exploitation courante**, ce qui doit être pensé avant, pas
découvert en production :

- **Perte d'une clé FIDO d'opérateur**, deux cas :
  - *Il lui reste une clé de secours active* : il retire lui-même la clé
    perdue depuis « Mes clés de sécurité » (§10, §12) en se connectant avec
    la clé restante — c'est précisément la raison d'être de l'auto-gestion,
    et la recommandation à faire à chaque opérateur dès l'onboarding :
    enregistrer une seconde clé, conservée séparément de la première.
  - *Il n'a plus aucune clé* : révocation par un autre admin (jamais par
    l'opérateur lui-même, qui ne peut plus s'authentifier) puis
    ré-enrôlement complet avec confirmation hors bande (§10) — pas de
    récupération de compte par email ou question secrète, cohérent avec
    « pas de mot de passe de repli » du §2.

  Dans les deux cas, la révocation de la clé perdue invalide aussi les
  sessions ouvertes avec elle (`sessions.credential_id`, §2) : une clé
  perdue qui aurait encore une session active ne doit pas survivre à sa
  propre révocation.
- **Départ d'un opérateur** : un admin signe la révocation de toutes ses
  clés, et `ca-server` l'exécute. Jamais une simple désactivation de compte
  qui laisserait une clé valide orpheline. `ra-console` coupe alors les
  sessions correspondantes. L'événement est consigné dans le journal de
  `ca-server` comme tout changement du registre.
- **Rotation/expiration de session** : cookies de session à durée courte
  (§2), pas de session « longue durée » persistante pour un rôle
  d'opérateur, même au prix d'une réauthentification WebAuthn plus
  fréquente.
- **Panne du service `ra-console`** : `ca-server`/`tsa-server`/
  `ocsp-responder` continuent de fonctionner sans lui (ils ne dépendent pas
  de cette console pour l'émission automatique ou la réponse OCSP). Les
  décisions humaines restent possibles par le CLI existant en secours
  (§20), au prix explicite de perdre l'accountability FIDO le temps de la
  panne — un compromis assumé plutôt qu'une indisponibilité totale de la
  capacité de révocation d'urgence. À vérifier explicitement en test :
  `ra-console` ne doit jamais devenir un point de défaillance unique pour
  les fonctions déjà couvertes par le CLI existant.
- **Montée de version du schéma** (`operators`, `webauthn_credentials`,
  `incidents`) : migrations SQL versionnées comme
  `crates/oe-castore/migrations/0001_schema.sql` aujourd'hui, jamais de
  modification manuelle en production.
- **Revue périodique des rôles** : qui a quel rôle, quels credentials sont
  encore actifs — un point de contrôle récurrent plutôt qu'un sujet traité
  une seule fois à l'onboarding.

## 15. Plan de mise en œuvre proposé

0. **Le socle de confiance, dans `ca-server`, avant toute console.** Il
   s'agit du registre des opérateurs et des tables de preuve (§2), de la
   vérification WebAuthn (assertions et attestation, liste blanche), de
   `POST /internal/v1/actions` avec son anti-rejeu, et de
   `ca-server operators bootstrap-admin`. Cette étape vient en premier
   parce que tout le reste en dépend : c'est l'ordre inverse de
   l'intuition, qui voudrait commencer par l'écran de connexion. Elle
   inclut les trois tests de la faille R2a (§19), à écrire avant le code
   qu'ils protègent.
1. **Fondations de `ra-console`** : enregistrement relayé à `ca-server`,
   connexion vérifiée contre le registre en lecture seule, sessions, droits
   PostgreSQL en lecture seule sur les tables de `ca-server`. Aucune action
   métier n'est encore branchée : il s'agit juste de prouver qu'on sait
   authentifier un opérateur par sa clé FIDO.
2. **Lecture seule** : `GET /api/v1/requests`, `GET /api/v1/audit/search`,
   `GET /api/v1/conformance` (déjà là) exposés derrière l'authentification —
   première version utile sans aucun risque d'action irréversible.
3. **Actions RA signées** : approve/reject d'enrôlement, relayés à
   `ca-server` selon le schéma du §4 — pas encore la révocation.
4. **Révocation et double contrôle** : `POST /certificates/{serial}/revoke`,
   d'abord single-operator si le premier déploiement ne couvre que des
   certificats terminaux, puis M-sur-N pour les cas les plus sensibles.
5. **Workflow d'incident** : une fois les briques 3-4 posées, l'incident
   n'est plus qu'une couche de regroupement/justification par-dessus des
   actions qui existent déjà.
6. **Frontend** : peut commencer en parallèle de 2-3 une fois l'API de
   lecture stable, en suivant les directives de [UI-UX.md](UI-UX.md), pour
   éviter de maquetter contre une API qui bouge encore.

## 16. Sécurité et isolation du service `ra-console`

### Qui touche le HSM, qui décide, qui écrit

Deux principes non négociables :

1. **`ra-console` n'ouvre jamais de session PKCS#11.** Seul `ca-server`
   détient la clé de signature de l'autorité : dupliquer cet accès dans un
   second binaire doublerait la surface d'attaque sur la clé, pour un gain
   nul.
2. **`ra-console` n'écrit jamais dans les tables de `ca-server` et n'est
   jamais une ancre de confiance.** Il est le seul composant exposé aux
   navigateurs, donc le plus probablement compromis un jour. Toute écriture
   qui modifie la PKI ou le registre des opérateurs est vérifiée *et*
   exécutée par `ca-server`, à partir de la signature brute de l'opérateur.
   Ce second principe est venu tard : une première version de ce
   paragraphe ne retenait que le premier et laissait `ra-console` écrire
   les approbations. « Faille identifiée », plus bas, explique pourquoi
   c'était une erreur.

| Opération | Touche le HSM ? | Vérifiée et exécutée par |
|---|---|---|
| Approbation/rejet RA (`oe_raflow::Decider`) | Non, mais une approbation *déclenche* l'émission au prochain appel du demandeur | `ca-server`, après vérification de la signature de l'opérateur (§4) |
| Émission effective d'un certificat (`Issuer::issue`) | Oui | `ca-server`, inchangé : au *prochain* appel du demandeur à l'enrôlement après approbation (`resume()`) |
| Révocation (`Issuer::revoke`) puis republication de la CRL (`Issuer::publish_crl`) | Oui, pour la CRL | `ca-server`, après vérification de la signature (et du quorum si applicable, §8) |
| Invitation, activation ou retrait d'une clé d'opérateur, changement de rôle | Non | `ca-server`, après vérification de la signature (§10) |
| Création d'un jeton d'enrôlement d'identité | Non | `ca-server`, après vérification de la signature (§11) |
| Sessions, challenges de connexion, dossiers d'incident, collecte des signatures de quorum | Non | `ra-console`, sur ses propres tables, sans aucun pouvoir sur la PKI (§2) |

Toutes les écritures passent par **deux routes internes** de `ca-server`,
génériques plutôt qu'une route par action (le challenge, puis
l'exécution). Elles vérifient tout de la même façon, et chaque action
ajoutée hérite de cette vérification sans rien avoir à réimplémenter :

```
POST /internal/v1/challenge   (ca-server, internalPort, jamais exposé hors du cluster)
{ "body": { "action": "revoke", "serial": "...", "reason": 4, "comment": "..." },
  "operator_hint": "uuid" }
→ { "challenge_id": "...", "body": { ... , "expires_at": "..." }, "body_hash": "...",
    "webauthn": { ... } }

POST /internal/v1/actions
{ "challenge_id": "...",
  "assertion": { "credential_id": "...", "authenticatorData": "...",
                 "clientDataJSON": "...", "signature": "..." } }
```

La seconde route ne reçoit **pas de corps** : `ca-server` exécute celui qu'il
a figé à l'émission du challenge (§4). Pour un quorum, `assertions` devient
une liste, chaque assertion référençant son propre `challenge_id` et toutes
portant sur la même action.

La réponse porte le résultat de l'action, et `ca-server` y indique
l'identité lue dans *son* registre. Il ne reçoit jamais d'identité
d'opérateur déclarée par `ra-console` : `operator_hint` n'est qu'une
indication pour choisir les clés à proposer, jamais une décision de
confiance. Deux autres routes internes, non signées par un opérateur,
servent à l'enregistrement des clés :
- le dépôt d'une clé en attente, authentifié par le jeton d'invitation ;
- l'enregistrement du premier administrateur, authentifié par le jeton
  d'amorçage.

Toutes deux exigent en outre une attestation valide (§2, §10).

**Le mTLS du lien interne prouve seulement que l'appelant est bien
`ra-console`** (sous-section « Lien interne » ci-dessous). Il ne donne à lui
seul aucun pouvoir. Un attaquant qui volerait le certificat client de
`ra-console` ne pourrait faire exécuter aucune action sans une signature
d'opérateur valide, fraîche et jamais utilisée.

`ca-server` doit donc vérifier lui-même des assertions et des attestations
WebAuthn : de la vérification de signatures, sans aucun secret en jeu, dont
la sécurité ne dépend que des clés publiques de son propre registre. Le
coût réel est plus élevé que je ne l'avais écrit en première version
(« modeste ») : le choix de bibliothèque est instruit en T1 (§22) et pose
deux questions, l'arrivée d'OpenSSL dans le processus de la CA et
l'impossibilité d'imposer son propre challenge. Décision O7 : `webauthn-rs`
seul, OpenSSL accepté. Conséquences concrètes à traiter à l'implémentation :
- l'étage de build de `deploy/ca-server/Dockerfile` (`rust:1-bookworm`) a
  besoin des en-têtes OpenSSL (`libssl-dev`, `pkg-config`) ;
- l'image d'exécution (`debian:bookworm-slim` avec `softhsm2`) embarque sans
  doute déjà `libssl3`, dont dépend SoftHSM : à confirmer, ce n'est pas
  vérifié ici ;
- `cargo audit` (job « Clippy, tests ») suivra désormais les avis
  `openssl`/`openssl-sys`, qui s'ajoutent à ceux de `rustls` et `cryptoki`
  vus lors de la PR #3 ;
- `ra-console` ne lie la bibliothèque (`oe-webauthn`, donc OpenSSL) que pour
  **vérifier les connexions** (§15, étape 1) : une session n'est pas une ancre de
  confiance, et chaque *action* est re-vérifiée par `ca-server`, qui est seul à
  décider. Pour les actions elle ne fait que relayer. (Une première version de ce
  paragraphe disait qu'elle ne la liait pas du tout : c'était en contradiction avec
  la vérification des connexions du §15.)

### Isolation réseau

`deploy/helm/open-eidas/templates/ca/httproute.yaml` n'expose aujourd'hui
que `/download`, `/api/v1/ca.pem`, `/api/v1/conformance` et `/` — **`/api/v1/enroll`
reste volontairement interne au cluster**, atteint seulement par les
services qui s'y enrôlent (commentaire du fichier : « l'API d'enrôlement
reste interne au cluster »), et **le reste** : le flux du §11 n'y touche
pas, il introduit à la place un chemin public séparé et étroit,
`/api/v1/identity/enroll`, qui ne peut techniquement porter que le profil
`identity_person` muni d'un jeton d'enrôlement valide (§11 détaille pourquoi
ce choix ferme, plutôt que déplace, le risque d'élargir l'enrôlement
générique).

```yaml
# httproute.yaml — nouvelle entrée matches, à côté des chemins déjà publics
- matches:
    - path: {type: Exact, value: /api/v1/identity/enroll}
  backendRefs:
    - name: {{ $name }}
      port: {{ .Values.ca.service.port }}
```

Reste, même sur ce chemin restreint, un risque de volume que le HMAC ne
couvre pas (il protège le contenu, pas le débit) : une limite de débit par
IP se pose au niveau de la Gateway (politique de rate limiting de Gateway
API — le CRD exact dépend de l'implémentation retenue, ex.
`BackendTrafficPolicy` pour Envoy Gateway), pas dans le code applicatif,
cohérent avec l'esprit du dépôt de ne pas réimplémenter au niveau
applicatif ce qu'une couche existante fait déjà correctement.
`DefaultBodyLimit` (`OPENEIDAS_MAX_REQUEST_BYTES`) continue de s'appliquer
sans changement, cette route passant par le même routeur axum.

`ra-console`, à l'inverse, ne doit **jamais** partager le même `HTTPRoute`
public que `ca-server`. Aucun rôle de ce document (§3) n'a besoin d'un accès
Internet non authentifié à la console : elle est exposée sur un
`HTTPRoute`/`Gateway` séparé, réservé à un réseau interne ou à un accès VPN,
distinct de celui qui sert `/tsa`, `/download` et l'enrôlement. Les routes
internes de `ca-server` (`/internal/v1/*`, sous-section précédente) n'ont,
elles, aucun `HTTPRoute` du tout — seule une `NetworkPolicy` Kubernetes
autorisant explicitement les pods `ra-console` à joindre les pods `ca-server`
sur ce port doit l'exposer, jamais un chemin public.

### Secrets et informations sensibles propres à `ra-console`

- **Aucune clé de signature de session.** Les sessions sont des jetons
  opaques vérifiés en base (`sessions.id`, §2) plutôt que des JWT
  auto-portés — il n'existe donc pas de secret de signature de session à
  générer, protéger ou faire tourner. C'est une classe entière de secret en
  moins par rapport à une architecture à jetons signés.
- **Connexion PostgreSQL** : `ra-console` utilise un rôle applicatif dédié,
  distinct de celui de `ca-server`. Ses droits se résument en une règle :
  **lecture seule sur tout ce qui appartient à `ca-server`, écriture sur ses
  seules tables** (§2).

  | Tables | Droits de `ra-console` |
  |---|---|
  | Ses tables : `webauthn_challenges`, `sessions`, `login_counters`, `incidents`, `incident_actions`, `quorum_requests`, `quorum_signatures` | Lecture et écriture |
  | `enrollment_requests`, `certificates`, `operators`, `webauthn_credentials`, `pending_credentials`, `decision_evidence` | `SELECT` seul (files d'attente, recherche, vérification des connexions) |
  | `operators`, `webauthn_credentials` | En plus, `REFERENCES`, pour les clés étrangères de ses propres tables |
  | `identity_enrollment_tokens`, `operator_invites`, `actions`, `action_challenges`, `authorities`, `crls` | Aucun droit : même la lecture est inutile, et les hachés de secrets n'ont pas à circuler |

  **Aucun droit `INSERT`, `UPDATE` ou `DELETE` sur une table de
  `ca-server`.** C'est ce qui ferme la faille du §16 : un test vérifie ces
  droits contre un vrai PostgreSQL (§19).
- **Authentification du lien interne vers `ca-server`** : TLS mutuel plutôt
  qu'un jeton statique partagé — détail des certificats, de leur émission
  et de ce que leur possession permet (ou ne doit pas permettre) dans la
  sous-section « Lien interne » ci-dessous.
- **`identity_enrollment_tokens.secret_hash`** (§11) : un hachage simple
  (SHA-256) suffit, contrairement à un mot de passe utilisateur — le secret
  est un jeton aléatoire à haute entropie généré par le serveur, pas une
  valeur choisie par un humain avec un espace de recherche restreint ; une
  fonction de dérivation lente (Argon2/bcrypt) n'apporterait rien ici et
  ajouterait une dépendance sans bénéfice de sécurité réel.

### Lien interne `ra-console` ↔ `ca-server` : certificats

**Provenance : la CA émettrice elle-même, par le circuit d'enrôlement
existant** — ni autorité interne parallèle, ni outil tiers (type
cert-manager) :

| | Profil (nouveau, `oe_ca_core::profile`) | Porteur | Clé | Durée de vie |
|---|---|---|---|---|
| Client | `internal_client` : EKU `clientAuth` seul, OID de politique dédié, sujet imposé `CN=ra-console` | `ra-console` | Logicielle, générée par le service sur son propre volume, jamais exportée | 3 mois (comme `ocsp_responder`, CPS A.6) |
| Serveur | `internal_server` : EKU `serverAuth` seul, OID de politique dédié, SAN = nom DNS interne du service `ca` | `ca-server`, sur `internalPort` (§17) | Logicielle, distincte du token PKCS#11, qui ne porte que les clés d'autorité | 3 mois |

Pourquoi la CA émettrice plutôt qu'une petite CA interne dédiée :

- **La révocation prend effet immédiatement.** Le vérificateur côté
  serveur *est* la CA : à chaque connexion, `ca-server` contrôle le statut
  du certificat client présenté directement dans sa propre table
  `certificates`. Révoquer le certificat de `ra-console` (par le CLI de
  secours, §20) coupe l'accès dès la connexion suivante. Une CA interne
  séparée n'aurait ni CRL ni OCSP : seule l'expiration fermerait l'accès.
- **L'émission reste auditée.** Chaque certificat passe par une décision RA
  consignée dans le journal chaîné, comme tous les autres. Une CA parallèle
  émettrait en dehors de cette chaîne.
- **Aucune nouvelle dépendance**, et la même mécanique fonctionne en
  docker-compose et en Helm.

Ces clés sont logicielles, et ce n'est pas une contradiction avec « les clés
vivent dans un token PKCS#11 » (EN 319 401 §7.5, REQ-7.5-01, dans la matrice). Cette
exigence vise les clés qui produisent le service de confiance : signature de
certificats, de jetons d'horodatage, de réponses OCSP. Les deux clés
ci-dessus n'authentifient qu'un canal interne. Leur compromission ne permet
de signer aucun certificat, aucun jeton, aucune réponse OCSP — *à condition*
que la possession du certificat client ne donne pas elle-même un pouvoir
équivalent. C'est désormais garanti : `ca-server` exige, en plus du canal,
une signature d'opérateur qu'il vérifie lui-même (« Qui touche le HSM, qui
décide, qui écrit », plus haut). La sous-section suivante explique
pourquoi ce n'était pas le cas dans la première version.

**Contrôles côté `ca-server`, sur `internalPort`.** Vérifier seulement que
le certificat remonte à la CA émettrice ne suffit pas : les certificats de la
TSU et du répondeur OCSP y remontent aussi, et surtout les certificats
`identity_person` (§11) peuvent porter l'EKU `clientAuth`. Sur ce seul
critère, n'importe quel porteur externe d'un certificat d'identité passerait
la poignée de main TLS (la `NetworkPolicy` du §17 le bloquerait au niveau
réseau, mais serait alors la seule barrière). `ca-server` exige donc
explicitement, sans s'en remettre aux valeurs par défaut de la bibliothèque
TLS :

1. une chaîne vers la CA émettrice ;
2. l'EKU `clientAuth` ;
3. l'OID de politique propre à `internal_client`, que ne porte aucun autre
   profil ;
4. le sujet exact `CN=ra-console` ;
5. un statut non révoqué dans sa propre table `certificates`.

Symétriquement, `ra-console` exige l'OID `internal_server` et le SAN attendu
côté serveur. Après chaque révocation, il relit en plus le statut dans
`certificates` (il y a accès en lecture) avant d'annoncer le succès à
l'opérateur. Sans cette relecture, un faux `ca-server` qui répondrait 200
sans rien faire ferait échouer une révocation d'urgence en silence.

**Terminaison TLS : dans `ca-server` lui-même** (ce qui tranche T5, §22).
Le contrôle 5 exige un accès à la table `certificates` au moment de la
poignée de main, ce qu'un maillage de service externe ne sait pas faire. Et
`rustls` est déjà une dépendance.

**Amorçage (Jour 0) et renouvellement.**

- Les deux services demandent leur certificat par le `/api/v1/enroll`
  interne, avec le secret HMAC d'infrastructure, comme la TSA et le
  répondeur OCSP. En production, `ca.autoApprove` est désactivé : les deux
  premières demandes sont approuvées au CLI (`ca-server ra approve`, §20)
  par un opérateur nommé, pendant l'amorçage. `ra-console` n'approuve jamais
  la demande de son propre certificat initial : ce serait une confiance
  circulaire.
- Contrairement à `tsa-server`, qui ne vérifie l'échéance qu'au démarrage
  (CPS A.4.6), les deux services la vérifient périodiquement et soumettent
  une nouvelle CSR 30 jours avant l'expiration. La demande apparaît dans la
  file RA, signalée comme « certificat interne ». Tant qu'elle n'est pas
  approuvée, l'échéance reste affichée au tableau de bord (via
  `GET /api/v1/counters`).
- Durcissement possible : donner à `ra-console` un secret d'enrôlement
  propre, accepté pour le seul profil `internal_client`, plutôt que le
  secret HMAC partagé par l'infrastructure. Même mécanisme que les jetons
  d'identité du §11.

### Faille identifiée en cours de conception : approuver, c'est émettre

Cette sous-section garde la trace d'une erreur de conception et de sa
correction. Un relecteur ou un auditeur doit pouvoir comprendre *pourquoi*
`ra-console` n'écrit rien chez `ca-server`, et ne pas le prendre pour une
précaution arbitraire qu'on pourrait assouplir plus tard.

**Le constat, vérifié dans le code.** `oe_raflow::Flow::resume`
(`crates/oe-raflow/src/lib.rs`) transforme toute demande en état
`Approved` en certificat au prochain appel du demandeur
(`RequestState::Approved => self.issue(...)`). Il ne revérifie pas qui a
approuvé : la contrainte `decision_imputable` exige seulement que le champ
`operator` soit non vide. La première version de ce §16 donnait pourtant à
`ra-console` un accès en écriture direct à `enrollment_requests` pour
`approve`/`reject`. L'affirmation « approuver ne touche pas le HSM » était
exacte ; en conclure que l'approbation pouvait rester hors de `ca-server`
était une erreur, car **approuver déclenche l'émission**.

**Ce qu'un `ra-console` compromis aurait pu faire avec cette première
version, sans aucun opérateur :**

1. Soumettre une CSR `tsa_signer` avec une clé qu'il contrôle. Il détient
   le secret HMAC d'infrastructure pour sa propre demande de certificat
   (T3).
2. L'écrire comme `APPROVED` en base, avec un nom d'opérateur quelconque.
3. Relancer la demande : `ca-server` signe un certificat de TSU valide pour
   la clé de l'attaquant. Par la règle « une seule unité active par sujet »
   (même fonction `issue`), il révoque au passage le certificat de la TSU
   légitime.

C'était une émission arbitraire de certificats, suivie d'une mise hors
service de l'horodatage.

**Correctif appliqué, sur un principe unique : `ca-server` vérifie
lui-même la signature de l'opérateur ; `ra-console` n'est qu'un relais,
jamais une ancre de confiance.** C'est le schéma classique d'une PKI qui
sépare une RA frontale d'un cœur de CA : c'est le cœur qui vérifie la
signature de l'officier RA, pas la RA qui s'en porte garante. Il se
traduit par trois règles, reprises dans tout le document :

1. **Un seul écrivain.** `ca-server` est seul à écrire dans ses tables.
   `ra-console` n'y a qu'un accès en lecture (droits PostgreSQL, plus haut).
   Toute écriture passe par `/internal/v1/actions` avec l'assertion brute de
   l'opérateur (ou les N assertions d'un quorum, §8), et `ca-server` la
   vérifie entièrement (§4).
2. **Anti-rejeu générique.** Une signature ne sert qu'une fois
   (`action_challenges` et `actions.executed_at`, §2) et expire au bout de 5 minutes. Cette
   règle ne dépend pas du fait qu'une action particulière soit idempotente.
3. **Un registre ancré dans `ca-server`.** Sans cette règle, les deux
   premières ne vaudraient rien : une console compromise y ajouterait sa
   propre clé publique, puis produirait des signatures « valides » à
   volonté. Toute entrée dans le registre et toute sortie sont une action
   signée par une clé déjà présente, vérifiée et exécutée par `ca-server`.
   La chaîne remonte jusqu'au premier administrateur, enregistré au Jour 0
   par le CLI de `ca-server` (§10). Même la révocation d'une clé suit ce
   chemin : elle ne fait que retirer du pouvoir, mais un écrivain unique,
   sans exception, est plus simple à auditer.

**Ce que le correctif ne résout pas**, pour rester honnête : un
`ra-console` compromis contrôle encore l'écran de l'opérateur. Il peut
afficher « révoquer X » et faire signer « révoquer Y » : c'est la limite du
§4, faute d'affichage de la transaction sur la clé elle-même. La
compromission passe de « émission arbitraire, sans personne » à « il faut
qu'un opérateur réel touche sa clé, et l'action est tracée à son nom, avec
la preuve ». Le gain est net, la garantie n'est pas absolue. Ce qui réduit
réellement ce risque résiduel (R2, §22), c'est ce qui passe par une vue
*indépendante* de la console :
- la vérification d'empreinte avec le demandeur, pour les certificats
  d'identité (§11), dont la valeur vient de son propre outil ;
- une revue a posteriori du journal de `ca-server` par un moyen qui ne
  passe pas par `ra-console` (`ca-server verify-audit` en local, ou un
  récapitulatif émis par `ca-server` lui-même) : un opérateur y
  reconnaîtrait une action qu'il n'a pas voulue.

Le quorum (§8), en revanche, n'aide pas ici : si les deux opérateurs
passent par la même console compromise, elle peut les tromper de la même
façon.

### Surface d'attaque du binaire

- **`ra-console` ne lie pas `cryptoki`** (elle garde, de `oe-hsm`, le seul trait
  `SigningToken` : la feature `pkcs11` est désactivée, et
  `bin/ra-console/tests/no_pkcs11.rs` lit le graphe réel des dépendances) : pas de module PKCS#11
  dans son image de conteneur, pas de variable `OPENEIDAS_PIN`, pas de
  volume de token à monter. L'image est plus petite et son profil
  `cargo audit` est mécaniquement plus court que celui de `ca-server`.
- **Connexion sans nom d'utilisateur (« discoverable credentials »).**
  `POST /api/v1/webauthn/login/begin` ne prend aucun paramètre
  d'identification : avec `residentKey: preferred` posé à l'enregistrement
  (§2, déjà dans le schéma proposé), l'authentificateur présente lui-même
  les identifiants disponibles. Ça évite qu'un point d'énumération des
  noms d'opérateurs existe sur l'endpoint de connexion — une réponse
  identique, que le nom existe ou non, serait sinon nécessaire et fragile à
  maintenir dans le temps.
- **Assets statiques embarqués dans le binaire** (déjà posé par
  [UI-UX.md](UI-UX.md) §7.2) : aucune dépendance runtime vers un CDN ou un
  répertoire d'assets externe, cohérent avec la CSP stricte du même document
  (§6.3) — les deux mesures se renforcent, l'une empêchant le chargement
  d'un script tiers, l'autre garantissant qu'aucun script tiers n'est même
  atteignable au démarrage.

## 17. Déploiement — Helm et docker-compose

### `ra-console` remplace `ca.autoApprove` en production, il ne s'y ajoute pas

Fait déjà présent dans `deploy/helm/open-eidas/values.yaml` (§`ca.autoApprove`) :
« n'ouvre aucun token PKCS#11 (approuver, c'est décider, pas signer) —
footprint minimal ». C'est exactement la propriété du chemin RA de
`ra-console` établie au §16 — `ca.autoApprove` en est la version
« conteneur technique nommé » actuelle, destinée à la démonstration/CI
(`ca.autoApprove.enabled: true`) mais explicitement désactivée pour un
déploiement visant la qualification. `ra-console` n'est donc pas un
service de plus à côté de l'existant : c'est ce que devient
`ca.autoApprove.enabled: false` une fois qu'un humain authentifié par FIDO2
remplace le `kubectl exec … ca-server ra approve` déjà documenté comme
alternative en production.

### Nouveau port interne sur `ca-server`

`bin/ca-server` ne sert aujourd'hui qu'un seul port pour toutes ses routes
(`.Values.ca.service.port`, voir `deployment.yaml`/`service.yaml`). Une
`NetworkPolicy` ne voit pas les chemins HTTP, seulement les ports. Pour
isoler réellement les routes internes (`/internal/v1/*`, §16) au niveau
réseau, elles doivent écouter sur un **second port dédié**, jamais mélangé
avec le port public existant. Ce port sert en mTLS, terminé par `ca-server`
lui-même (§16 « Lien interne »).

```yaml
# values.yaml — section ca, nouveau champ
ca:
  service:
    port: 8320        # inchangé : /api/v1/enroll, /download, .pem, conformance, healthz
    internalPort: 8321 # nouveau : /internal/v1/* (mTLS) uniquement, jamais de HTTPRoute
```

### Valeurs Helm proposées pour `ra-console`

```yaml
raConsole:
  image:
    repository: ghcr.io/otspi/open-eidas-ra-console
    tag: "latest"
  replicaCount: 1
  service:
    port: 8330
  # Pas encore mesuré (voir docs/SIZING.md pour la méthode à répliquer ici) :
  # ces valeurs sont un point de départ prudent, pas un résultat de test.
  # `ra-console` n'ouvre aucun token PKCS#11 (§16) : son plancher réel
  # devrait être proche de celui de `ca.autoApprove` ci-dessus, pas de
  # `ca-server` lui-même.
  resources:
    requests: { cpu: 10m, memory: 32Mi }
    limits: { cpu: 100m, memory: 128Mi }
  # Gateway distinct de shared-gateway : interne/VPN uniquement, jamais le
  # même Gateway que ca/tsa/ocsp (§16).
  gateway:
    enabled: false
    name: internal-gateway
    namespace: ingress
    host: console.open-eidas.example
  # RP ID = nom d'hôte exact de la console, jamais le domaine racine (§2).
  # ra-console refuse de démarrer si rpId diffère de l'hôte de origin.
  webauthn:
    rpId: console.open-eidas.example
    rpName: "Open eIDAS Console"
    origin: https://console.open-eidas.example
```

Et dans `values-staging.yaml`, un enregistrement propre à l'environnement,
jamais partagé avec la production :

```yaml
raConsole:
  gateway:
    host: console.staging.open-eidas.eu
  webauthn:
    rpId: console.staging.open-eidas.eu
    rpName: "Open eIDAS Console — STAGING"
    origin: https://console.staging.open-eidas.eu
```

### `NetworkPolicy` — les deux premières du chart

Avant le lien interne, aucune `NetworkPolicy` n'existait dans
`deploy/helm/open-eidas/templates/` : l'isolation reposait entièrement sur le
choix de ce qui a un `HTTPRoute` ou non. La première, celle de la CA
(`templates/ca/networkpolicy.yaml`, activée avec `ca.internal.enabled`), est
livrée ; celle de `ra-console` reste à écrire avec le service. Ça suffisait tant qu'aucun
port applicatif ne portait d'action privilégiée à distance ; `internalPort`
en introduit un, ce qui rend une politique explicite nécessaire plutôt
qu'optionnelle.

```yaml
# templates/ca/networkpolicy.yaml (nouveau)
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: {{ include "open-eidas.fullname" . }}-ca
spec:
  podSelector:
    matchLabels:
      {{- include "open-eidas.componentSelectorLabels" (dict "context" . "component" "ca") | nindent 6 }}
  policyTypes: [Ingress]
  ingress:
    # Port public : ouvert à tout le cluster (le Gateway y accède depuis son
    # propre namespace, les services d'infrastructure s'y enrôlent).
    - ports: [{port: {{ .Values.ca.service.port }}}]
    # Port interne : uniquement depuis les pods ra-console.
    - ports: [{port: {{ .Values.ca.service.internalPort }}}]
      from:
        - podSelector:
            matchLabels:
              {{- include "open-eidas.componentSelectorLabels" (dict "context" . "component" "ra-console") | nindent 14 }}
```

```yaml
# templates/ra-console/networkpolicy.yaml (nouveau)
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: {{ include "open-eidas.fullname" . }}-ra-console
spec:
  podSelector:
    matchLabels:
      {{- include "open-eidas.componentSelectorLabels" (dict "context" . "component" "ra-console") | nindent 6 }}
  policyTypes: [Ingress, Egress]
  ingress:
    # Rien d'autre que le Gateway interne (§16) — pas d'accès pod-à-pod
    # arbitraire vers la console.
    - from:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: {{ .Values.raConsole.gateway.namespace }}
  egress:
    - to:
        - podSelector:
            matchLabels:
              {{- include "open-eidas.componentSelectorLabels" (dict "context" . "component" "postgres") | nindent 14 }}
    - to:
        - podSelector:
            matchLabels:
              {{- include "open-eidas.componentSelectorLabels" (dict "context" . "component" "ca") | nindent 14 }}
      ports: [{port: {{ .Values.ca.service.internalPort }}}]
    - ports: [{port: 53, protocol: UDP}]  # résolution DNS, sinon rien d'autre ne sort
```

### `docker-compose.yml`

Même service, sans les à-côtés Kubernetes (Gateway, NetworkPolicy)
puisqu'un unique réseau Docker relie déjà tout en démonstration. Suit
exactement la convention de `docs/SIZING.md`/`docker-compose.yml`
existants (`mem_reservation`/`mem_limit`/`cpus`, valeurs à mesurer une fois
le service écrit, pas avant) :

```yaml
  ra-console:
    container_name: openeidas_ra_console
    # Pas de PKCS#11, pas de volume de token (§16) : contrairement à ca/tsa/
    # ocsp-responder, ce service n'a besoin ni de OPENEIDAS_PIN ni d'un
    # volume SoftHSM.
    mem_reservation: 32m
    mem_limit: 128m
    cpus: 0.10
    environment:
      OPENEIDAS_DATABASE_URL: postgres://openeidas@db/openeidas
      OPENEIDAS_CA_INTERNAL_URL: https://ca:8321
```

À ajouter à `docs/SIZING.md` une fois le service implémenté : une section
« `ra-console` » suivant la même méthode de mesure directe que le reste du
document (échec net en mémoire, régime sous charge réelle) — jusque-là, les
chiffres ci-dessus restent un point de départ, explicitement non mesurés,
au même titre que ce que ce document signale déjà pour le réplica d'audit
et `ra-autoapprove` dans sa version actuelle.

## 18. Texte prêt à intégrer — CPS et matrice de conformité, à l'implémentation

**Rien de ce paragraphe ne doit être copié dans `docs/CPS.md` ou
`docs/CONFORMITE-ETSI.md` avant que le code décrit dans ce document
n'existe réellement.** Les deux documents cibles énoncent chacun cette
règle pour eux-mêmes — `docs/CPS.md` : « le contenu technique... est tiré
du code réellement en service... et non inventé » ; `docs/CONFORMITE-ETSI.md` :
« document généré... ne pas modifier à la main ». Cette section est donc un
brouillon à coller *une fois* les crates/routes correspondantes livrées,
pas une modification à appliquer aujourd'hui.

### Dans `crates/oe-conformance/src/lib.rs` (`system_matrix()`)

Trois entrées nouvelles, au format exact des entrées existantes :

```rust
Entry {
    requirement: Requirement { standard: "ETSI EN 319 411-1", clause: "§6.2.1", title: "Enregistrement et responsabilité de la décision d'émission — authentification de l'opérateur" },
    status: Status::Covered,
    mechanism: "L'identité de l'opérateur RA/CA n'est plus une chaîne libre déclarée au CLI : chaque décision (approbation, rejet, révocation) exige une assertion WebAuthn (FIDO2, userVerification requise, clé attestée non copiable) que ca-server vérifie lui-même contre son propre registre d'opérateurs — jamais sur la foi de la console — avant tout appel à oe_raflow::Decider ou oe_ca_core::Issuer::revoke. La preuve de chaque décision est conservée (decision_evidence), vérifiable avec la clé publique du registre et le journal chaîné qui lie le challenge au corps ; une signature ne sert qu'une fois.",
    test: "<chemin des tests d'intégration ra-console à écrire, ex. bin/ra-console/tests/webauthn_signing.rs>",
    target: "",
},
Entry {
    requirement: Requirement { standard: "ETSI EN 319 411-1", clause: "§6.5.1", title: "Cérémonie de génération des clés d'autorité — double contrôle" },
    status: Status::Gap,
    mechanism: "Les actions désignées comme critiques (révocation d'une autorité, actions liées à la cérémonie) exigent désormais N assertions WebAuthn d'opérateurs distincts, une contrainte SQL UNIQUE(quorum_request_id, operator_id) rendant impossible la double signature par la même personne.",
    test: "<tests de la contrainte de quorum à écrire>",
    target: "Cérémonie physique en double contrôle sous témoin indépendant sur HSM certifié — le quorum numérique en est le pendant pour les actions à distance, pas un substitut pour la cérémonie elle-même.",
},
Entry {
    requirement: Requirement { standard: "ETSI EN 319 412-2", clause: "§4", title: "Profil de certificat de personne physique" },
    status: Status::Gap,
    mechanism: "Profil identity_person (oe_ca_core::profile) conforme au sujet/extensions EN 319 412-2, preuve d'identité procédurale au niveau substantiel/élevé (WEBUI.md §11), aucune QCStatements posée.",
    test: "<tests du profil identity_person à écrire>",
    target: "Qualification eIDAS du service (audit EN 319 403-1 déjà suivi §7 de ce document) avant toute extension QCStatements — pas une seconde ligne d'audit séparée.",
},
```

### Dans `docs/CPS.md`

**A.1.3 Acteurs de la PKI** — deux lignes ajoutées au tableau :

```markdown
| Opérateurs RA/CA | Personnes nominatives authentifiées par clé FIDO2 (WebAuthn), sans mot de passe de repli | `ra-console`, voir WEBUI.md §2 |
| Sujets de certificats d'identité | Personnes physiques dont l'identité a été vérifiée par un opérateur RA (en personne ou méthode supervisée équivalente) — porteurs externes à l'association, distincts des services internes ci-dessus | profil `identity_person`, voir WEBUI.md §11 |
```

**A.1.4 Usage des certificats** — la ligne du tableau des profils gagne une
troisième entrée, et le paragraphe qui suit (« Cette CA n'émet pas de
certificats pour des tiers externes... ») est remplacé :

```markdown
| `identity_person` | Certificat d'identité **non qualifié** pour personne physique — aucune valeur légale eIDAS tant que le service n'est pas qualifié | `extKeyUsage` clientAuth/emailProtection selon l'usage, aucune QCStatements, `CA:FALSE` critique |
| `internal_client` | Authentification TLS de `ra-console` auprès de `ca-server`, et rien d'autre | EKU `clientAuth` seul, OID de politique dédié exigé par le vérificateur, sujet imposé — voir WEBUI.md §16 |
| `internal_server` | Authentification TLS du port interne de `ca-server` | EKU `serverAuth` seul, OID de politique dédié, SAN restreint au nom DNS interne du service |

Cette CA émet, en plus des deux profils d'infrastructure, des certificats
d'identité pour des personnes physiques externes à l'association depuis
`[À COMPLÉTER — date de mise en service]`. Ces certificats sont
explicitement non qualifiés au sens eIDAS : la politique affichée à
l'émission et dans le certificat le dit sans ambiguïté (voir WEBUI.md §11).
`[À COMPLÉTER — si une qualification eIDAS est obtenue par la suite, cette
section et le profil doivent être révisés ensemble, pas l'un sans l'autre]`.
```

**A.3.2 Validation initiale de l'identité** — remplace le paragraphe
`[À COMPLÉTER]` actuel :

```markdown
Pour les services internes (TSA, répondeur OCSP), l'authentification de la
demande repose sur un secret HMAC-SHA256 partagé, provisionné hors bande au
déploiement (inchangé).

Pour un certificat d'identité de personne physique, la vérification
d'identité est menée par un opérateur RA au niveau substantiel/élevé au sens
eIDAS Art. 24 (vérification en personne, ou méthode supervisée équivalente
retenue par l'association : `[À COMPLÉTER — méthode(s) précisément admise(s)
et justificatifs exigés]`), préalable à la remise d'un secret d'enrôlement à
usage court propre à cette personne (voir WEBUI.md §11). La méthode utilisée
est consignée dans le commentaire de la décision RA correspondante.
```

**A.5 Contrôles de sécurité physiques, organisationnels et humains** —
complète, sans le remplacer, le `[À COMPLÉTER]` existant :

```markdown
L'accès au rôle d'opérateur RA/CA sur `ra-console` exige un credential
FIDO2 personnel, enregistré via une cérémonie d'onboarding elle-même
imputable (initiateur et confirmateur hors bande consignés, voir WEBUI.md
§10) — le contrôle technique de cette section est couvert ; restent à
décider par l'association : `[À COMPLÉTER — vérifications préalables au
recrutement d'un opérateur, formation, fréquence de revue des accès]`.
```

**A.6 Contrôles techniques de sécurité** — nouvelle ligne :

```markdown
| Taille de clé — certificat d'identité | RSA ≥ 3072 bits | `oe_raflow::parse_and_verify_csr`, même contrôle que pour la TSU/OCSP |
```

**A.7 Profils de certificat, CRL et OCSP** — bullet supplémentaire :

```markdown
- profil de certificat d'identité : `oe_ca_core::profile::identity_person`,
  sans `QCStatements` tant que le service n'est pas qualifié (voir A.1.4).
```

## 19. Tests et stratégie de vérification

Même doctrine que le reste du dépôt : tester contre un système réel plutôt
qu'une simulation de sa réponse. `crates/oe-hsm` teste contre un vrai
SoftHSM2, `oe-crosstsa`/`oe-replicate` contre un vrai serveur RFC 3161/WebDAV
— la logique WebAuthn de ce module suit la même règle contre un
**authentificateur logiciel réel** (un client CTAP2/WebAuthn qui exécute
réellement le protocole, génère de vraies paires de clés et produit de
vraies attestations/assertions), pas des objets `Assertion { valid: true }`
fabriqués à la main. `webauthn-rs` (bibliothèque de vérification pressentie,
§5) a un projet compagnon fournissant ce type d'authentificateur logiciel
pour les tests d'intégration — nom et API exacts à vérifier sur leur
documentation au moment de l'implémentation, pas à figer ici par avance.

### Découpage en crate testable

Comme `oe_raflow`/`oe_ca_core` sont des bibliothèques indépendantes du
transport HTTP (`bin/ca-server` ne fait que les brancher à axum), la
logique d'identité/WebAuthn/quorum de ce document devrait vivre dans une
nouvelle bibliothèque (`crates/oe-console-auth` proposé) plutôt que dans
`bin/ra-console` directement : chaque invariant peut alors être testé sans
serveur HTTP, exactement comme les tests actuels de `oe_raflow`.

### Tests à écrire, par propriété de sécurité qu'ils protègent

- **Le compte n'est pas actif avant confirmation hors bande.** Enregistrer
  un credential (`register/finish`) puis tenter un login immédiat sans
  passer par `confirm` (§10) : doit échouer — vérifie
  `credential_confirmed_before_active` en base autant que le code appelant.
- **Un challenge ne se rejoue pas, des deux côtés.**
  - *Connexion*, côté `ra-console` : consommer une ligne
    `webauthn_challenges`, puis retenter la même assertion. Doit échouer,
    `consumed_at` étant déjà posé. Une ligne expirée doit échouer, même
    jamais consommée.
  - *Action*, côté `ca-server` : relayer deux fois le même
    `challenge_id` et la même assertion. La seconde fois doit échouer
    (`consumed_at` déjà posé, action déjà exécutée), y compris pour une action non idempotente
    comme un changement de rôle.
- **Une signature d'action n'exécute que le corps figé à l'émission (§4).**
  C'est le test qui ne doit jamais régresser en silence : il donne son sens
  à « signature d'une requête sensible ». Trois cas :
  1. obtenir un challenge pour le corps A (révoquer le certificat X), signer,
     puis relayer l'assertion : c'est A qui s'exécute, et rien d'autre ;
  2. la route `/internal/v1/actions` refuse tout champ `body` (elle n'en
     accepte pas) : un `ra-console` qui tente d'en glisser un obtient une
     erreur, jamais une exécution ;
  3. une assertion produite pour le challenge de l'action A, relayée en
     citant le `challenge_id` d'une action B : doit échouer, le challenge
     n'étant pas celui de B.

  Et l'écriture au journal précède la signature : à l'émission du
  challenge, l'entrée `action_id` + `body_hash` doit déjà exister dans le
  journal chaîné de `ca-server` (vérifiée en relisant la chaîne avant de
  relayer l'assertion).
- **Régression du `sign_count`.** Une deuxième assertion avec un compteur
  inférieur ou égal au précédent (déjà positif) doit être rejetée et le
  credential suspendu. Un authentificateur qui renvoie systématiquement `0`
  ne doit en revanche jamais déclencher ce rejet (§2) — deux tests
  distincts, pas un seul, pour que la nuance ne se perde pas dans un futur
  refactor.
- **Attestation : trois refus à l'enregistrement.** Avec l'authentificateur
  logiciel de test, tenter successivement : un enregistrement en
  `attestation: "none"` ; un AAGUID absent de la liste blanche ; un
  credential au drapeau `BE = 1`. Les trois doivent être refusés, et les
  contraintes `attestation_required` et `backup_eligible = false` doivent
  aussi faire échouer une insertion directe en base. Un quatrième cas se
  teste à l'usage : une assertion `BE = 1` pour un credential enregistré à
  `BE = 0` doit être rejetée. Corollaire assumé : l'authentificateur
  logiciel de test ne figure *jamais* dans la liste blanche de production.
  Il ne doit exister que dans la configuration de test, sinon il deviendrait
  une clé copiable acceptée en production.
- **Port interne : seul le certificat `internal_client` attendu passe.**
  Présenter successivement un certificat `identity_person` (porteur de
  l'EKU `clientAuth`), le certificat de la TSU, un `internal_client`
  révoqué, et un `internal_client` au sujet inattendu : la poignée de main
  doit échouer dans les quatre cas. Le premier cas est le plus important :
  sans contrôle explicite de l'OID de politique, il passerait (§16 « Lien
  interne »).
- **Révocation annoncée seulement si elle est effective.** Un faux
  `ca-server` qui répond 200 sans rien révoquer : `ra-console` doit le
  détecter en relisant `certificates` et afficher un échec, jamais un
  succès.
- **Faille R2 fermée, prouvée par trois tests à écrire en premier.** Le
  correctif ne modifie pas `resume()`, qui émet toujours sur la foi de
  l'état en base. Il retire à `ra-console` tout moyen de produire cet
  état. C'est donc ce retrait qu'on prouve :
  1. *Droits PostgreSQL* : sous le rôle de `ra-console`, contre un vrai
     PostgreSQL (dans l'esprit de `crates/oe-castore/tests/postgres.rs`),
     les écritures suivantes échouent sur un refus de permission :
     - un `UPDATE enrollment_requests SET state = 'APPROVED'` ;
     - un `INSERT INTO webauthn_credentials` ;
     - un `INSERT INTO operator_invites`.
  2. *Route interne* : `POST /internal/v1/actions` avec un corps
     d'approbation valide doit être refusé, sans rien écrire, dans chacun
     de ces cas :
     - aucune assertion ;
     - une signature invalide ;
     - un credential inconnu du registre, ou révoqué ;
     - un opérateur `auditeur` ;
     - un corps expiré ;
     - un challenge déjà consommé ;
     - une assertion portant sur un autre corps.
  3. *De bout en bout* : avec le certificat client mTLS de `ra-console`
     mais sans signature valide d'opérateur, aucune demande `tsa_signer` ne
     sort en certificat.

  Ensemble, ces trois tests prouvent en exécutant du code que la faille est
  fermée, au lieu de seulement l'affirmer.
- **Registre ancré dans `ca-server`.** Une action « activer la clé
  d'empreinte F » signée par un opérateur non admin, ou par une clé en
  attente plutôt qu'active, doit être refusée. Le bootstrap doit être
  refusé si un administrateur actif existe déjà (§10).
- **RP ID et origine incohérents → refus de démarrer.** Une configuration
  où `OPENEIDAS_WEBAUTHN_RP_ID` diffère du nom d'hôte de
  `OPENEIDAS_WEBAUTHN_ORIGIN` (ex. RP ID `open-eidas.eu` pour une origine
  `https://console.open-eidas.eu`) doit faire échouer le chargement de la
  configuration, sur le modèle de `load_fails_on_undersized_key_bits`
  (`crates/oe-config`).
- **Auto-ajout de clé sans réassertion refusé.** Avec une session valide
  mais sans réassertion récente, `POST /api/v1/me/credentials/register/begin`
  doit échouer — c'est ce qui empêche une session volée de planter une clé
  de secours pour un attaquant (§10).
- **Retrait de la dernière clé active refusé.** Un opérateur avec une seule
  clé active qui tente de la retirer lui-même doit être refusé ; avec deux
  clés, le retrait d'une seule doit réussir. Inclure le cas concurrent :
  deux retraits simultanés des deux dernières clés ne doivent jamais
  laisser l'opérateur à zéro (le comptage se fait en transaction, §10).
- **Révocation d'une clé → ses sessions tombent.** Une session ouverte avec
  un credential ensuite révoqué doit être refusée à la requête suivante (§14).
- **Quorum : N signatures de N opérateurs distincts, vérifiées par
  `ca-server`.** Relayer à `/internal/v1/actions` deux assertions valides,
  mais produites par deux clés du *même* opérateur, pour une action qui en
  exige deux : doit être refusé. Réplique, dans l'esprit de
  `reserve_serial_twice_conflicts` (`crates/oe-castore/src/lib.rs`), de la
  contrainte `UNIQUE(action_id, operator_id)` de `decision_evidence` :
  le refus doit venir de la base de `ca-server`, pas seulement de
  l'application. Même chose si `ra-console` transmet un
  `required_signatures` abaissé à 1 : `ca-server` applique sa propre
  politique.
- **Quorum : l'action s'exécute une seule fois.** Relayer le même lot
  complet deux fois en parallèle (test concurrent, dans l'esprit de ce que
  `reserve_serial` garantit déjà pour l'unicité des séries) : une seule
  exécution, l'autre trouvant `actions.executed_at` déjà posé.
- **Jeton d'enrôlement d'identité lié à une seule empreinte de CSR (§11).**
  Soumettre la CSR A avec le jeton T (ouverture), puis la CSR B avec le même
  jeton T : la seconde doit échouer. Resoumettre A avec T doit en revanche
  continuer à fonctionner (c'est le mécanisme de polling), y compris après
  l'expiration du secret d'origine tant que `bound_fingerprint` correspond.
  Un secret faux, ou seulement son haché présenté à sa place, doit échouer.
- **`ra-console` ne lie pas PKCS#11 (§16).** Vérifier, dans l'arbre de
  dépendances du binaire `ra-console` (`cargo tree`), l'absence d'`oe-hsm`
  et de `cryptoki`, et lancer ses tests dans une image sans bibliothèque
  PKCS#11. Avec le correctif, les décisions RA s'exécutent dans
  `ca-server`. Ce qui reste à prouver, c'est que la console n'a jamais eu
  de quoi toucher le HSM, pas seulement qu'elle ne s'en sert pas.

### Ce qui reste hors de portée d'un test automatisé

La vérification d'identité en personne (§11), la confirmation hors bande à
l'onboarding (§10) et la revue périodique des rôles (§14) sont des
procédures humaines : aucun test ne peut les remplacer, seulement vérifier
que le système *refuse de fonctionner sans elles* (les tests ci-dessus le
font déjà, indirectement, en testant les contraintes qui les rendent
obligatoires plutôt que les procédures elles-mêmes).

## 20. Migration et cohabitation avec le CLI existant

### Le CLI ne disparaît pas — son statut change

`ca-server ra approve`/`reject` et `ca-server revoke` continuent d'exister
et d'écrire dans les mêmes tables (`enrollment_requests`, `certificates`),
avec les mêmes bibliothèques (`oe_raflow`, `oe_ca_core`) que la route
interne qu'utilise `ra-console`. Dans les deux cas, c'est donc le processus
`ca-server` qui écrit ; seule la preuve d'identité de l'opérateur diffère.
Le CLI s'exécute dans le périmètre de confiance de `ca-server`, qui est
l'accès à son hôte. Il n'affaiblit donc pas le principe du §16 : c'est une
autre porte d'entrée, gardée autrement (voir plus bas), pas un contournement
par `ra-console`. Rien dans ce document ne propose de les retirer : `ra-console` s'ajoute
comme voie *primaire*, le CLI devient la voie de **secours**, documentée
comme telle plutôt que supprimée — cohérent avec ce que
`ca.autoApprove.enabled: false` recommande déjà aujourd'hui
(« approuve par `kubectl exec … ca-server ra approve` ») en l'absence de
toute console. Retirer cette capacité créerait exactement le risque que
`ra-console` est censée réduire, pas l'inverse : une panne de `ra-console`
ne doit jamais rendre une révocation d'urgence impossible (§8, §14).

### Ce que le secours coûte, explicitement

Une décision prise par le CLI ne porte pas de signature WebAuthn — c'est un
`operator` en texte libre, comme aujourd'hui. Deux mesures pour que ce
compromis reste visible plutôt que silencieux :

- **Distinguer la provenance dans le journal d'audit.** Les événements déjà
  émis par `oe_raflow`/`oe_ca_core` (`ca.request_received`,
  `ca.certificate_revoked`, ...) gagnent un champ `authenticated_via`
  (`"webauthn"` ou `"cli"`) au moment de l'appel, pas reconstruit après
  coup par heuristique sur le format du champ `operator`. Un audit qui
  compte les décisions `authenticated_via = "cli"` sur une période donnée
  mesure directement à quel point l'accountability FIDO a été contournée,
  intentionnellement ou non.
- **Restreindre qui peut atteindre le CLI, au niveau infrastructure, pas
  applicatif.** L'accès `kubectl exec` vers les pods `ca-server` est un
  levier RBAC Kubernetes qui existe déjà indépendamment de ce chantier —
  le documenter comme le contrôle réel du secours (qui peut l'utiliser)
  évite d'avoir à réimplémenter une notion d'habilitation redondante avec
  celle de `ra-console`.

### Séquencement, aligné sur le plan du §15

| Étape (§15) | Statut du CLI |
|---|---|
| 0-2 (socle `ca-server`, fondations, lecture seule) | Seule voie de décision, inchangé — la console ne relaie encore aucune action |
| 3 (approve/reject signés) | Devient le secours pour l'enrôlement ; toute décision CLI sur cette période mérite une revue explicite, pas seulement un comptage rétrospectif |
| 4 (révocation, quorum) | Devient le secours pour la révocation — le cas qui compte le plus, vu l'usage de révocation d'urgence hors heures ouvrées motivant le quorum au §8 |
| Après adoption complète | Reste disponible indéfiniment comme secours documenté ; jamais retiré du code |

### Ce que ça change dans le CPS, une fois adopté (à ajouter à l'annexe du §18)

```markdown
#### A.3.4 Identification pour une demande de révocation (complément)

Deux voies existent : `ra-console`, authentifiée par clé FIDO2 (voie
primaire), et le CLI `ca-server revoke`, accessible uniquement aux
personnes disposant d'un accès d'exploitation à l'infrastructure
(voie de secours, sans signature cryptographique de l'identité). Chaque
décision porte la trace de la voie utilisée (`authenticated_via`) dans le
journal d'audit. `[À COMPLÉTER — fréquence de revue des décisions prises
par la voie de secours, décidée par l'association]`.
```

## 21. Modes de défaillance de `ca-server`

Avec le §16, `ca-server` est le seul point de décision : il porte le
registre des opérateurs, vérifie les signatures et exécute. C'est voulu,
mais il devient aussi le composant dont la panne ou la corruption coûte le
plus cher. Cette section dit ce qui se passe, ce qui est déjà couvert, et
ce qui reste à décider. Rien ici n'est nouveau côté PKI : ce sont les
conséquences, pour la console, d'une architecture à écrivain unique.

Faits vérifiés dans le dépôt : `ca-server` tourne en **un seul réplica**
(`replicaCount: 1`, comme `tsa`, parce que chacun détient un token PKCS#11
sur un volume) ; le répondeur OCSP lit la CRL *chez* `ca-server`
(`OPENEIDAS_PKI_INTERNAL_URL`) ; la CRL est valable 24 h et republiée
toutes les heures, et `/healthz` passe en 503 dès qu'elle est périmée.

### Panne de `ca-server` (processus ou hôte indisponible)

| Ce qui continue | Ce qui s'arrête |
|---|---|
| Horodatage (`tsa-server`, clé et token propres) | Toute décision : approbation, révocation, invitation, changement de rôle |
| Réponses OCSP et CRL servies *tant que la CRL en cache reste valide* | Émission de certificats (dont le renouvellement de la TSU et de l'OCSP, §16) |
| Écrans de lecture de la console (accès direct en lecture seule à la base) | Republication de la CRL |

Deux points à ne pas minimiser :
- **La révocation d'urgence est impossible pendant la panne.** Le CLI de
  secours (§20) vit sur le même hôte que `ca-server` et signe avec le même
  HSM : il ne contourne pas une panne de `ca-server`, seulement une panne de
  `ra-console`. Ce qui limite le dommage, c'est le délai de reprise (RTO),
  qu'il faut donc fixer (O8).
- **Passé 24 h, l'OCSP dégrade** : la CRL périmée fait refuser au répondeur
  de garantir un statut (comportement déjà voulu, `oe_ocsp_core`). Une
  panne de plus de 24 h de `ca-server` devient donc visible des tiers. Le
  compte à rebours de CRL de [UI-UX.md](UI-UX.md) §2.1 (alerte orange sous 2 h)
  est la bonne alerte ; elle doit aussi partir *hors* de la console, qui ne
  saurait pas prévenir de sa propre cause.

Pas de haute disponibilité prévue : la contrainte est le token PKCS#11 (un
volume, un écrivain), pas un oubli. La documenter comme limite du MVP plutôt
que la découvrir en incident.

### Corruption ou perte du registre des opérateurs

Le registre est dans PostgreSQL (§2). Trois cas :

1. **Perte totale du registre, sans sauvegarde** : plus aucune clé connue,
   donc plus personne ne peut signer. C'est un verrouillage, pas une perte de
   données PKI. Voir « Récupération du dernier administrateur ».
2. **Restauration d'une sauvegarde plus ancienne que le journal** : cas
   piégeux. Une clé révoquée à T réapparaîtrait *active* dans une base
   restaurée à T-1, alors que le journal chaîné (fichier, réplicable, non
   restauré avec la base) atteste la révocation. Défense : au démarrage,
   `ca-server` **rejoue les événements du journal qui touchent le registre**
   (activation, retrait de clé, changement de rôle) et les compare à la
   base. Toute divergence bloque l'exécution d'actions (échec fermé,
   `/healthz` en 503 avec le détail) jusqu'à résolution explicite par
   l'opérateur de l'hôte (`ca-server operators reconcile`, qui ré-applique
   le journal et consigne la résolution). Le journal fait foi pour le
   registre, pas l'inverse.
3. **Altération directe de la base** (une clé insérée en SQL par un
   attaquant qui aurait obtenu l'écriture, par une faille de
   `ra-console` ou par un compte de base compromis). Le §16 l'empêche pour
   `ra-console`, mais le cas doit être détectable. Puisque toute entrée dans
   le registre est une action signée (§10), `ca-server operators audit`
   **parcourt la chaîne** : pour chaque clé active, il retrouve
   l'activation signée dans `decision_evidence`, vérifie la signature avec
   une clé elle-même déjà validée, et remonte jusqu'au bootstrap. Une clé
   sans chaîne valide est signalée. L'attaquant peut forger une ligne, pas
   la signature d'une clé existante. La commande tourne au démarrage et
   périodiquement (job, alerte hors console).

### Récupération du dernier administrateur

`ca-server operators bootstrap-admin` refuse de s'exécuter si un administrateur
actif existe (§10) : c'est voulu, mais cela signifie qu'un système où tous les
administrateurs ont perdu leurs clés est **verrouillé** sans issue prévue.
Il faut une issue, aussi lourde que la cérémonie :

- `ca-server operators recover-admin`, exécuté sur l'hôte de `ca-server`,
  exige de présenter le PIN du token PKCS#11 (preuve de garde de l'hôte, pas
  seulement d'un accès shell), un motif écrit, et un drapeau explicite ;
- il crée une invitation d'administrateur comme au Jour 0, sans rien
  désactiver du registre existant ;
- il écrit dans le journal, contresigné par la TSA tierce, un événement
  distinct et bruyant (`operators.admin_recovery`), visible dans l'explorateur
  d'audit et le tableau de bord ;
- politique organisationnelle à décider (O8) : témoin requis, deux
  détenteurs du PIN, revue a posteriori.

Prévention plutôt que remède : la console signale (tableau de bord, hors
échelle de sécurité) tout état où il reste **moins de trois administrateurs
actifs**, ou un administrateur avec **une seule clé** (§10). Trois, parce que
l'élévation au rôle admin exige déjà deux signatures (§10) et qu'il faut en
garder un de réserve. Et un quorum ne doit jamais être exigé sur un rôle
qui compte moins de N titulaires actifs : `ca-server` refuse de *créer*
l'action plutôt que de la laisser en attente indéfiniment.

### Journal indisponible ou saturé

Le §4 fait écrire le lien challenge → corps au journal *avant* de répondre.
Si l'écriture échoue (disque plein, verrou, fichier corrompu), **`ca-server`
n'émet pas de challenge** : échec fermé, `/healthz` en 503. Un système qui
signerait sans pouvoir consigner perdrait la propriété qui donne son sens à
tout ce document. Le coût, une indisponibilité des décisions, est accepté.
La réplication WebDAV et le contreseing existants (EN 319 401 §7.11 dans la
matrice) sont la sauvegarde du journal.

### Ce que cette architecture ne protège pas

Un attaquant qui contrôle l'hôte de `ca-server` avec les droits du processus
détient le HSM (déverrouillé), le registre et le journal. Aucun mécanisme
de ce document ne l'arrête : il peut signer des CRL, émettre, et fabriquer un
registre cohérent. Ce qui subsiste, c'est la **détection** : le journal
contresigné par une TSA tierce et répliqué hors de l'hôte permet à un
auditeur de constater une divergence après coup (ce que l'attaquant n'a
pas pu réécrire, il ne l'a pas contresigné). C'est la même limite que pour
toute CA en ligne ; elle relève du HSM certifié et du contrôle d'accès à
l'hôte (CPS A.5, A.6), pas de la console.

### Horloge

Les échéances de 5 minutes (§4) et la fraîcheur de la CRL reposent sur
l'horloge de `ca-server`. Aujourd'hui seule la TSA surveille sa source de
temps (`oe_timesource`). Une horloge qui avance ferait expirer des actions
légitimes, une horloge en retard élargirait la fenêtre de rejeu. À décider
(T8, §22) : appliquer à `ca-server` la même surveillance NTP, avec refus de
créer une action si la dérive dépasse un seuil.

### Tests à ajouter au §19

- *Registre restauré en arrière* : révoquer une clé, restaurer une base
  antérieure, redémarrer : `ca-server` doit refuser les actions et
  `/healthz` doit être en 503 avec la divergence, jusqu'à `reconcile`.
- *Clé insérée en SQL* : l'insérer directement dans `webauthn_credentials`,
  puis `operators audit` doit la signaler, et une action signée par cette clé
  doit être refusée à l'exécution.
- *Journal en échec* : rendre le fichier non inscriptible : aucun challenge
  ne doit être émis.
- *Récupération* : `recover-admin` sans le bon PIN échoue ; avec, il écrit
  l'événement distinct au journal.
- *Quorum impossible* : demander une action à deux signatures avec un seul
  titulaire actif du rôle : refus immédiat de créer l'action.

## 22. Journal des risques et hypothèses non validées

Point de clôture du brouillon : tout ce qui, dans les 20 sections
précédentes, reste une décision à prendre, une hypothèse technique à
vérifier au moment de l'écrire, ou un risque architectural identifié mais
non résolu — pour qu'aucun de ces points ne se perde en cours
d'implémentation faute d'avoir été rassemblé une seule fois.

### Décisions organisationnelles (association, pas code)

| # | Sujet | Section |
|---|---|---|
| O1 | Méthode(s) précise(s) de vérification d'identité admise(s) pour un certificat `identity_person` (en personne uniquement ? vidéo supervisée admise ? quels justificatifs ?) | §11, §18 (A.3.2) |
| O2 | Date de mise en service des certificats d'identité, à consigner dans le CPS une fois décidée | §18 (A.1.4) |
| O3 | Vérifications préalables au recrutement d'un opérateur RA/CA, formation, fréquence de revue des accès | §14, §18 (A.5) |
| O4 | Fréquence de revue des décisions prises par la voie de secours CLI | §20 |
| O5 | Qui, dans l'association, peut initier/confirmer un onboarding administrateur (au-delà du mécanisme technique du §10) | §10 |
| O6 | Seuil d'admission des clés d'opérateurs : protection matérielle ou élément sécurisé exigé ? Niveau de certification FIDO minimal (L2+ ?) ou validation FIPS 140 ? Liste initiale des modèles autorisés | §2 « Attestation » |
| O8 | Objectif de temps de reprise (RTO) de `ca-server` (pas de haute disponibilité : un token PKCS#11, un écrivain), et politique de `recover-admin` : témoin requis, deux détenteurs du PIN, revue a posteriori | §21 |

### Hypothèses techniques à vérifier au moment de l'implémentation

| # | Sujet | Section | Ce qu'il faut vérifier |
|---|---|---|---|
| T7 | Granularité et options de l'attestation | §2 « Attestation » | Deux choses à vérifier auprès des fabricants retenus : (1) l'AAGUID distingue-t-il les versions de firmware (ex. avant/après un correctif de type EUCLEAK) ? Si non, la liste blanche ne peut exclure qu'un modèle entier ; (2) l'attestation « entreprise » (lien au numéro de série physique) est-elle disponible pour ces modèles et ces navigateurs ? |
| T8 | Surveillance de l'horloge de `ca-server` | §21 | Seule la TSA surveille aujourd'hui sa source de temps. Les échéances de 5 minutes (§4) et la fraîcheur de la CRL dépendent de l'horloge de `ca-server` : décider s'il reprend `oe_timesource` avec refus de créer une action au-delà d'un seuil de dérive |
| T6 | Algorithme des assertions vérifiées par `ca-server` | §4, §16 | Les clés FIDO2 signent le plus souvent en ES256 (ECDSA P-256). La ligne « ECDSA explicitement refusé » de CPS A.6 concerne les signatures *de certificats* de la PKI, pas l'authentification des opérateurs : le préciser dans le CPS pour qu'un auditeur ne lise pas une contradiction là où il y a deux usages distincts |

### Instruction de T1 : `webauthn-rs`, ce qui est confirmé et ce qui ne l'est pas

Sources : docs.rs (`webauthn-rs` 0.5.5, `fido_mds3_attestation_ca`,
`webauthn-authenticator-rs`) et code source de `kanidm/webauthn-rs`
(dernière version publiée : 0.5.2 sur GitHub au 2026-09-19).

**Confirmé — conforme à ce que le document exige :**
- **Attestation obligatoire avec liste de racines** :
  `start_attested_passkey_registration` exige un `AttestationCaList`
  (paramètre non optionnel). Un authentificateur hybride ne peut pas être
  attesté, ce qui exclut par construction les passkeys de téléphone.
- **Refus des clés copiables** : à l'enregistrement, le code rejette un
  credential `backup_eligible` tant que `allow_synchronised_authenticators`
  n'est pas activé, et rejette un `backup_state` sans éligibilité déclarée.
  À l'authentification, tout changement du drapeau d'éligibilité est refusé,
  sauf si `allow_backup_eligible_upgrade` est activé (à ne jamais activer ici).
  Ces comportements sont dans le code, pas dans la documentation publiée.
- **Authentificateur logiciel de test** : `webauthn-authenticator-rs`
  fournit `SoftToken` et `SoftPasskey` (features `softtoken`/`softpasskey`),
  utilisables en dépendance de test. Non documenté : le format
  d'attestation qu'ils produisent. À vérifier en essayant.
- **Liste blanche hors ligne** : `fido_mds3_attestation_ca` construit
  l'`AttestationCaList` depuis un blob MDS3, avec un filtre
  (`AttestationFilter`, `build_ca_list()`), et sait le charger depuis un
  fichier local (`loader`). Cela permet la liste versionnée dans le dépôt
  que le §2 exige, sans appel réseau à l'exécution (le téléchargement est
  facultatif).

**Écarts avec le document, à trancher :**
1. **Impossible d'imposer son propre challenge.** Le challenge est
   toujours tiré au hasard par la bibliothèque : le constructeur
   d'authentification n'a pas de champ challenge, et l'état
   (`AuthenticationState`) a ses champs privés. Or le schéma du §4 exige
   `challenge = SHA-256(corps canonique)`, pour que la signature elle-même
   engage sur le corps. Avec la bibliothèque telle quelle, il faudrait
   soit (a) faire émettre le challenge par `ca-server` et lier
   challenge → hachage du corps *dans sa base*, ce qui affaiblit
   `decision_evidence` (la signature seule ne prouve plus quel corps a été
   approuvé, un auditeur doit faire confiance à la base de `ca-server`) ;
   soit (b) contourner l'état via la feature
   `danger-allow-state-serialisation`, fragile ; soit (c) écrire son propre
   vérificateur d'assertion (voir la recommandation).
2. **OpenSSL entre dans le processus de la CA.** `webauthn-rs-core`
   dépend d'`openssl`/`openssl-sys`. Or `Cargo.lock` n'en contient
   aujourd'hui aucun, ni `p256`/`ecdsa` (le dépôt s'appuie sur `rustls`,
   `ring` et RustCrypto). Ajouter OpenSSL au binaire qui tient la clé de
   l'autorité est une décision à part entière : dépendance FFI, avis
   RUSTSEC supplémentaires à suivre par `cargo audit`, bibliothèque
   système dans l'image, et un écart avec l'esprit d'INDEPENDANCE.md. Elle
   ne se prend pas par défaut parce qu'une bibliothèque en a besoin.
3. **Compatibilité de version.** `fido_mds3_attestation_ca` est en
   `0.1.1-rc.2` et annonce viser `webauthn-rs` **0.6.0-dev**, pas la 0.5.5
   stable. À vérifier avant de la retenir : compilation contre la 0.5.x, ou
   attente de la 0.6.

**Décision prise (O7) : option 3 ci-dessous, `webauthn-rs` seul.** Les options étudiées :

**Recommandation initiale, non retenue : répartir les rôles.**
- *Enregistrement et attestation* (la partie complexe : formats `packed`,
  chaînes x5c, liste de racines, politique BE) : `webauthn-rs`, dans
  `ca-server`. C'est là qu'une bibliothèque éprouvée vaut le plus.
- *Assertion d'action* (la partie simple et bien spécifiée : signature
  ES256 sur `authenticatorData ‖ SHA-256(clientDataJSON)`) : un vérificateur
  d'une centaine de lignes, dans une crate dédiée testée contre `SoftToken`
  et des vecteurs publics, ce qui permet le challenge imposé du §4 et une
  preuve autoportante.
- OpenSSL est alors accepté *avec* ce coût énoncé (O7), ou l'attestation
  est restreinte au seul format `packed` avec un vérificateur maison, plus
  lourd à écrire et à auditer, mais sans dépendance nouvelle.

La décision retenue est plus simple : pas de vérificateur maison, mais une
preuve moins forte, assumée au §4. Elle a été propagée dans §2 (schéma),
§4, §5, §8, §9, §16, §18 et §19.

### Points résolus en cours de rédaction

| # | Sujet | Résolution |
|---|---|---|
| T3 | Origine du certificat client mTLS de `ra-console` | Résolu : profils `internal_client`/`internal_server` émis par la CA émettrice via l'enrôlement existant, clés logicielles, 3 mois, approbation initiale au CLI (Jour 0), renouvellement périodique ; contrôle explicite de l'OID de politique et du sujet, pas seulement de la chaîne — voir §16 « Lien interne » |
| T5 | Terminaison TLS du port interne | Résolu : dans `ca-server` lui-même, parce que le contrôle de révocation du certificat client lit sa propre table `certificates` — voir §16 « Lien interne » |
| T2 | RP ID WebAuthn entre staging et production | Résolu : RP ID égal au nom d'hôte exact de chaque console, jamais le domaine racine (`demo.open-eidas.eu` existe sous le même domaine) ; un enregistrement par environnement, jamais recopié de staging vers prod ; `ra-console` refuse de démarrer si RP ID et origine ne concordent pas — voir §2 « Relying Party ID et environnements » |
| O7 | Bibliothèque WebAuthn de `ca-server` | Décidé (2026-09-19) : `webauthn-rs` seul, avec le challenge tiré par la bibliothèque ; OpenSSL accepté dans le processus de la CA ; lien challenge → corps établi côté serveur et écrit au journal chaîné avant la signature — voir §4. Preuve moins forte qu'avec un challenge égal au hachage du corps, assumée |
| T1 | Choix et vérification de la bibliothèque | Instruit sur docs.rs et le code source (voir « Instruction de T1 ») ; reste à vérifier à l'implémentation la compatibilité de `fido_mds3_attestation_ca` (version candidate visant la 0.6 non publiée) avec la 0.5.x, et le format d'attestation produit par `SoftToken` |
| T4 | Mise à jour des compteurs/badges ([UI-UX.md](UI-UX.md) §2.2) | Résolu : polling court sur `GET /api/v1/counters` (§5), pas de canal persistant SSE/WebSocket — voir §5 « Mise à jour des compteurs » pour la justification |
| R1 | Exposition publique de l'enrôlement pour le flux d'identité (§11) | Résolu : pas d'exposition de `/api/v1/enroll` (reste interne), route publique séparée et étroite `/api/v1/identity/enroll` qui ne peut porter que le profil `identity_person` avec jeton obligatoire — voir §16 « Isolation réseau » |
| R2a | Un `ra-console` compromis pouvait faire émettre n'importe quel certificat, TSU comprise, sans aucun opérateur : il écrivait l'approbation en base, et `ca-server` signe au prochain appel sans revérifier qui a approuvé | Résolu : `ca-server` est seul à écrire ses tables, vérifie lui-même chaque signature d'opérateur (anti-rejeu générique) et porte le registre des clés, ancré dans son CLI au Jour 0 ; `ra-console` n'a plus aucun droit d'écriture chez lui — voir §16 « Qui touche le HSM, qui décide, qui écrit » et « Faille identifiée », tests au §19 |
| C1 | Incohérence du jeton d'identité : un secret stocké sous forme de haché mais décrit comme clé HMAC, invérifiable | Corrigé : secret présenté tel quel dans la requête (sous TLS), seul son haché est stocké, et la liaison à une CSR est assurée par `bound_fingerprint` — voir §11 |
| C2 | Exemple d'approbation (§5) renvoyant `ISSUED`, alors que l'émission n'a lieu qu'au prochain appel du demandeur | Corrigé : la réponse renvoie `APPROVED` |
| C3 | Clé d'invité « en base mais inutilisable », alors que la contrainte `credential_confirmed_before_active` interdit toute ligne non confirmée | Corrigé : table `pending_credentials` distincte (§2), dont on ne sort que par une confirmation signée (§10) |

### Risques architecturaux identifiés, non résolus par ce document

| # | Sujet | Section | Nature du risque |
|---|---|---|---|
| R2 | Risque résiduel, une fois R2a résolu : un `ra-console` compromis contrôle encore l'écran de l'opérateur, et peut afficher une action pour en faire signer une autre (limite du §4, faute d'affichage de la transaction sur la clé). Il ne peut plus agir *seul*, mais il peut tromper un opérateur réel | §4, §16 « Faille identifiée » | Atténué seulement par ce qui passe hors de la console : la vérification d'empreinte avec le demandeur (§11) et la revue du journal de `ca-server` par un moyen indépendant. Le quorum n'y change rien, puisque les deux opérateurs passent par la même console. Toute action trompée reste tracée au nom de l'opérateur, avec sa preuve |
| R3 | Le secret d'enrôlement d'identité (§11) remis en main propre dépend entièrement de la discipline humaine au moment de la remise — aucun contrôle technique ne peut vérifier que la remise a réellement eu lieu en face à face | §11 | Compensé uniquement par la consignation de la méthode dans le commentaire de décision RA (traçabilité a posteriori, pas prévention) |
| R4 | Aucune section de ce document ne couvre la sauvegarde/restauration désynchronisée entre la base d'`oe_castore` (partagée en lecture avec `ra-console`, §16) et les tables propres à `ra-console` si elles finissaient dans des instances Postgres séparées | §14, §16 | Suppose implicitement une seule instance Postgres partagée (cohérent avec §14) — à confirmer explicitement si un déploiement futur les sépare |

Ce journal n'appelle aucune action immédiate : c'est la liste de ce qu'il
faudra rouvrir, dans l'ordre qui conviendra, au fil de l'implémentation —
pas un blocage supplémentaire avant de commencer.
