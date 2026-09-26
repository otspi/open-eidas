# Autorité de certification Open eIDAS

Ce document décrit l'autorité de certification et d'enregistrement du projet
(`cmd/ca-server`) : sa hiérarchie, la procédure de cérémonie de clé, les
profils qu'elle émet, son modèle de menace, et les procédures d'exploitation
qu'un auditeur demandera. Il complète
[CONFORMITE-ETSI.md](CONFORMITE-ETSI.md), qui donne l'état exigence par
exigence, et [ARCHITECTURE.md](ARCHITECTURE.md), qui situe la CA dans la pile.

Le remplacement d'OpenXPKI par ce moteur est motivé et arbitré dans
[INDEPENDANCE.md](../INDEPENDANCE.md).

## 1. Hiérarchie

```
  Open eIDAS Root CA          RSA-4096, ~20 ans, pathLenConstraint = 1
   (token « open-eidas-root », hors ligne)
            │
            ▼  signe uniquement la CA émettrice
  Open eIDAS Issuing CA       RSA-4096, ~10 ans, pathLenConstraint = 0
   (token « open-eidas-issuing »)
            │
            ├──▶ certificat de l'unité d'horodatage   profil tsa_signer, 1 an
            └──▶ certificat du répondeur OCSP         profil ocsp_responder, 3 mois
```

Deux niveaux, deux tokens PKCS#11 distincts. `pathLenConstraint` interdit
toute autorité intermédiaire supplémentaire : même qui obtiendrait la clé de
la CA émettrice ne pourrait pas créer de sous-autorité.

La CA émettrice n'expire jamais après sa racine : la cérémonie tronque sa
validité si nécessaire, faute de quoi elle émettrait, sur sa dernière période,
des certificats invérifiables.

## 2. Cérémonie de clé

### Ce que fait `ca-server ceremony`

1. ouvre les deux tokens PKCS#11 et y génère les bi-clés si elles n'existent
   pas — les clés privées ne sortent jamais du module ;
2. signe la racine (auto-signée), puis la CA émettrice ;
3. relit chaque certificat depuis son DER et le soumet aux règles
   d'[`internal/conformance`](../internal/conformance) : une autorité non
   conforme n'est jamais enregistrée ;
4. inscrit les deux autorités au registre PostgreSQL ;
5. consigne un **procès-verbal** au journal d'audit (événement `ca.ceremony`) :
   opérateur, date, sujets, numéros de série, empreintes SHA-256 des
   certificats, labels des tokens.

La commande est **idempotente**. Relancée, elle relit la hiérarchie
enregistrée au lieu d'en créer une seconde — ce qui invaliderait tous les
certificats déjà émis. Elle vérifie au passage que la clé de chaque token
correspond toujours au certificat enregistré : un token remplacé (volume
effacé, restauration partielle) est détecté immédiatement, plutôt que de
produire des signatures invérifiables.

### Vérifier le procès-verbal

Les empreintes consignées sont celles que produit `openssl` : un auditeur les
recalcule sans aucun outil propre au projet.

```bash
docker compose exec ca ca-server verify-audit
docker compose exec ca sh -c \
    'grep ca.ceremony /var/lib/open-eidas/state/ca-audit.log'
curl -fsS http://localhost:8320/api/v1/ca.pem \
    | openssl x509 -noout -fingerprint -sha256
```

### Écart avec une cérémonie qualifiée

La cérémonie est ici **scriptée et exécutée sans témoin**, sous une identité
technique (`OPENEIDAS_CEREMONY_OPERATOR`, `ci-bootstrap` par défaut). Une
cérémonie destinée à la qualification exige, en plus :

- un **HSM certifié** FIPS 140-2 niveau 3 ou CC EAL4+ à la place de SoftHSM2 —
  le code applicatif est déjà compatible, seul `OPENEIDAS_PKCS11_MODULE`
  change ;
- un **double contrôle** : deux porteurs de secret distincts pour activer le
  token de la racine ;
- un **témoin indépendant** et un procès-verbal papier contresigné, en plus de
  l'entrée du journal ;
- la racine **hors ligne** après la cérémonie : son token retiré du système et
  conservé en coffre, ressorti uniquement pour renouveler la CA émettrice.

Ces points sont portés comme écarts dans la matrice
(ETSI EN 319 401 §7.4, EN 319 411-1 §6.5.1).

## 3. Profils émis

Les profils sont des **structures Go compilées**
([`internal/ca/profile.go`](../internal/ca/profile.go)), et non de la
configuration interprétée au démarrage. C'est délibéré : un profil OpenXPKI
mal formé échouait silencieusement à l'émission, sans que rien ne le signale
au chargement. Ici, un profil incohérent est soit une erreur de compilation,
soit un test rouge.

| | `tsa_signer` | `ocsp_responder` |
|---|---|---|
| Validité | 1 an | 3 mois |
| `keyUsage` (critique) | digitalSignature, contentCommitment | digitalSignature |
| `extendedKeyUsage` | id-kp-timeStamping, **critique**, seul | id-kp-OCSPSigning, critique |
| `basicConstraints` | CA:FALSE, critique | CA:FALSE, critique |
| `id-pkix-ocsp-nocheck` | — | oui |
| Point de distribution de CRL | oui | non |
| AIA (ca_issuers, ocsp) | oui | non |

Le sujet est **composé** : seul le nom courant vient de la demande, l'unité,
l'organisation et le pays sont imposés par le profil. Un service ne peut donc
pas se réclamer d'une organisation qui n'est pas la sienne.

`ocsp_responder` ne porte ni CDP ni AIA parce que `ocsp-nocheck` dispense de
vérifier la révocation de ce certificat précis — la contrepartie étant sa
durée de vie courte, contrôlée à l'émission.

### Profils du lien interne

Deux profils supplémentaires servent au canal `ra-console` ↔ `ca-server`
([docs/WEBUI.md](WEBUI.md) §16). Ils n'authentifient qu'un canal : leurs clés
sont logicielles et ne signent ni certificat, ni jeton, ni réponse OCSP.

| | `internal_client` | `internal_server` |
|---|---|---|
| Porteur | `ra-console` | `ca-server` (port interne) |
| Validité | 3 mois | 3 mois |
| `extendedKeyUsage` | `clientAuth`, critique, seul | `serverAuth`, critique, seul |
| Politique (`certificatePolicies`) | OID dédié, qu'aucun autre profil ne porte | OID dédié |
| Nom courant | imposé : `ra-console` | un nom DNS en minuscules, repris en `subjectAltName` |

Les OID de politique sont **provisoires** (`oe_conformance::OID_POLICY_INTERNAL_*`,
sous le numéro d'entreprise 0, réservé) : à remplacer par l'arc de l'association
avant toute mise en production.

`ca-server` termine lui-même le TLS du port interne (`OPENEIDAS_INTERNAL_LISTEN`,
TLS 1.3 seul, certificat client obligatoire). En plus de la chaîne vers la CA
émettrice, il exige à **chaque connexion**, avant de lire la moindre requête :
l'EKU `clientAuth` seul, la politique dédiée, le nom courant `ra-console`, et un
certificat inscrit dans sa table `certificates` sous le profil `internal_client`,
identique octet pour octet et non révoqué. Révoquer le certificat de `ra-console`
(`ca-server revoke`) coupe donc l'accès dès la connexion suivante. Sans
`OPENEIDAS_INTERNAL_TLS_*`, le port interne refuse de s'ouvrir ailleurs que sur
la boucle locale.

```bash
# Jour 0 : certificat du serveur interne (crée la clé, en 0600, si besoin)
ca-server internal-cert server ca.open-eidas.svc   # code 3 : en attente
ca-server ra approve <transaction_id> "prenom.nom" "amorçage du lien interne"
ca-server internal-cert server ca.open-eidas.svc   # écrit le certificat
```

Le certificat n'est lu qu'au démarrage : le renouveler (tous les 3 mois) demande
de relancer la commande puis de redémarrer `ca-server`.

### Actions à double contrôle

Certaines actions signées par les opérateurs (console d'exploitation,
[docs/WEBUI.md](WEBUI.md) §8) n'agissent qu'avec **deux signatures d'opérateurs
distincts** : la révocation d'un certificat (deux `ca_operateur`) et la création
ou le retrait d'un rôle `admin` (deux administrateurs). Le seuil vient de la
politique de `ca-server`, jamais de l'appelant.

Le premier signataire fige l'action ; les suivants signent exactement le même
corps. Chaque challenge WebAuthn reste limité à 5 minutes, mais l'action reste
signable 24 heures. À l'exécution, chaque signataire doit encore être actif et
détenir le rôle requis, et l'action ne s'exécute qu'une fois, même si deux
signatures arrivent ensemble. Toute signature, exécutée ou non, laisse une trace
au journal chaîné.

La commande de secours `ca-server revoke` reste un seul opérateur nominatif : c'est
la voie de la révocation d'urgence, avec la revue prévue par la décision O4.

### Amorçage et récupération des administrateurs

Le registre des opérateurs de la console
([docs/WEBUI.md](WEBUI.md) §10, §21) démarre vide. Deux commandes locales,
exécutées sur l'hôte de `ca-server` comme la cérémonie de clé, créent une
invitation d'administrateur à usage unique ; le jeton n'est affiché qu'une fois,
sur la sortie standard, et n'est conservé (haché) nulle part ailleurs.

```bash
# Jour 0 : le premier administrateur. Refuse si un administrateur actif existe.
TOKEN=$(ca-server operators bootstrap-admin alice --ttl-minutes 15)

# Système verrouillé : les administrateurs « actifs » ont perdu leurs clés et
# personne n'a plus l'autorité de les révoquer.
read -rs PIN
printf %s "$PIN" | ca-server operators recover-admin bob \
    --reason "clé de alice perdue, ticket 1234" --confirm-recovery --pin-stdin
```

`recover-admin` est volontairement plus lourd : il exige le **PIN du token
PKCS#11** (lu sur l'entrée standard, jamais en argument ni en variable
d'environnement), un **motif écrit** et un drapeau explicite. Le PIN présenté doit
ouvrir le token de la CA émettrice ; la valeur de `OPENEIDAS_ISSUING_PIN` du
service, lisible de tout accès shell, n'est pas ce qui compte. Un PIN refusé est
consigné (`operators.admin_recovery_refused`). Une récupération réussie écrit
l'événement distinct `operators.admin_recovery` (motif, nombre d'administrateurs
actifs) et **ne désactive rien** : la clé perdue est ensuite révoquée par une
action signée du nouvel administrateur. Sa clé entre directement dans le
registre, sans confirmation d'un tiers (il n'y en a plus). Un seul administrateur
ainsi créé ne suffit pas à en élever un autre (deux signatures) : lancer la
commande une seconde fois.

La politique de récupération (témoin, deux détenteurs du PIN, revue a
posteriori) reste une décision de l'association (O8).

### Audit du registre des opérateurs

```bash
ca-server operators audit [--journal <copie répliquée>]
```

Refait, pour chaque **clé active**, le chemin par lequel elle est entrée dans le
registre ([docs/WEBUI.md](WEBUI.md) §21), sans croire la base sur parole :

- une clé **confirmée** doit avoir une action `confirm_key` exécutée : corps
  inchangé (empreinte `body_hash`), engageant bien cette clé, signée par assez
  d'opérateurs distincts, **chaque signature étant re-vérifiée** (ES256) contre la
  clé du signataire, qui a lui-même une chaîne valide jusqu'à une ancre ;
- une clé **d'ancre** (amorçage, récupération) ne se prouve pas dans la base : la
  contrainte du registre l'admet sans confirmation. Elle doit figurer au journal
  chaîné ;
- le corps de chaque action doit être celui que le journal a consigné **avant** la
  signature : la signature porte sur le challenge, pas sur le corps, donc un corps
  réécrit avec son empreinte passerait la cryptographie seule.

Code de sortie **0** : registre sain ; **1** : constats (une ligne `KO` par clé) ;
**2** : journal illisible ou rompu, auquel cas le registre n'est pas jugé. Pointer
`--journal` vers la copie répliquée hors de l'hôte est le meilleur usage : une
copie que la base et l'hôte ne contrôlent pas.

Limites : seul ES256 est vérifiable (une autre clé est signalée, pas tenue pour
bonne) ; l'audit ne juge pas le rôle qu'avaient les signataires à l'époque. Il est
lancé à la demande (ou par un job périodique, avec une alerte hors console) ; le
lancement au démarrage et le blocage des actions sur constat relèvent de
`operators reconcile`, à venir.

### Registre restauré en arrière : rejeu du journal et `reconcile`

Le journal chaîné est un fichier, répliqué hors de l'hôte : il n'est pas restauré
avec la base. Une clé révoquée à T réapparaît donc **active** dans une base
restaurée à T-1 alors que le journal atteste la révocation. Le journal fait foi
pour le registre ([docs/WEBUI.md](WEBUI.md) §21).

Quand le lien interne est activé, `ca-server` rejoue au démarrage, puis toutes les
`OPENEIDAS_REGISTRY_CHECK_INTERVAL` (60 s), les événements du journal qui touchent
le registre et les compare à la base. Toute divergence **ferme la garde** :
plus aucun challenge, aucune exécution, aucune inscription de clé
(`registry_blocked`, 503), et `/healthz` passe en 503 avec le détail. Un journal
illisible ou rompu ferme aussi la garde : on ne juge pas le registre contre un
journal douteux. Une divergence doit persister quelques secondes pour fermer la
garde (le journal s'écrit *avant* la validation en base : un contrôle qui tombe
dans cette fenêtre ne doit rien bloquer).

```bash
ca-server operators reconcile --reason "base restaurée du 2026-09-18" --dry-run
ca-server operators reconcile --reason "base restaurée du 2026-09-18"
# une clé perdue ne se recrée pas : on en prend acte, ou on la ré-enrôle
ca-server operators reconcile --reason "…" --acknowledge-missing <credential_id>
```

- **Réparable** : une révocation ou un rôle du journal absent de la base est
  ré-appliqué.
- **Non réparable** : une clé que le journal dit active et que la base n'a plus. Le
  journal ne porte pas la clé publique : `reconcile` ne peut pas la recréer, et n'en
  prend acte que sur `--acknowledge-missing`, motivé, consigné au journal. La clé se
  ré-enrôle par une invitation. On ne cache jamais une clé perdue.
- Chaque résolution s'écrit au journal (`operators.reconciled`) **avant** d'être
  validée : journal en échec, rien n'est modifié.
- Codes de sortie : `0` tout est résolu ; `1` reste des divergences ; `2` journal
  illisible ou rompu.

La garde se rouvre au contrôle suivant (au plus 60 s) ou au redémarrage.

## 4. Enrôlement et approbation

```
        (HMAC valide)      (ra approve, opérateur)      (émission)
 CSR ──────────────────► PENDING ──────────────────► APPROVED ─────────► ISSUED
                            │
                            └──── (ra reject, opérateur) ────► REJECTED
```

Deux propriétés structurent la machine à états
([`internal/raflow`](../internal/raflow)) :

- **aucun chemin ne mène à l'émission sans approbation.** Il n'existe ni règle
  d'éligibilité, ni auto-approbation, ni contournement — c'est exactement ce
  qu'OpenXPKI faisait silencieusement, et que ce moteur supprime ;
- **toute décision exige une identité d'opérateur**, consignée en base et au
  journal (ETSI EN 319 411-1 §6.2.1). La contrainte est portée par le schéma
  PostgreSQL autant que par le code : une décision anonyme est refusée par la
  base elle-même.

L'émission a lieu côté `serve`, quand le demandeur revient chercher son
certificat — pas au moment de l'approbation. L'opérateur RA n'a donc jamais
besoin d'accéder à la clé de l'autorité : **approuver, c'est décider, pas
signer**.

### Commandes

```bash
# Demandes en attente de décision
ca-server ra list PENDING

# Approuver ou rejeter, sous une identité nominative
ca-server ra approve <transaction_id> "prenom.nom" "identité vérifiée le ..."
ca-server ra reject  <transaction_id> "prenom.nom" "sujet non reconnu"

# Historique complet
ca-server ra list
```

### Écart assumé

En démonstration et en CI, l'approbation est automatisée sous l'identité
technique `ci-bootstrap` (boucle de `scripts/bootstrap.sh` en docker-compose,
conteneur `ra-autoapprove` dans le chart Helm). Le point d'approbation reste
**réellement actif** : c'est une décision, prise sous une identité distincte,
et visible comme telle dans le journal d'audit. Dans le chart Helm, cette
automatisation est **désactivée par défaut** (`ca.autoApprove.enabled: false`,
constat R-2) : la démonstration l'active explicitement, et `production: true`
en refuse le rendu. Quand elle est active, le chart le déclare à `ca-server`
(`OPENEIDAS_RA_AUTO_APPROVE`), qui l'affiche dans `/healthz`
(`"approbation_automatique": true`).

## 5. Révocation

```bash
ca-server revoke <numéro_de_série> <code_motif> "prenom.nom" "commentaire"
```

Les codes sont ceux de RFC 5280 §5.3.1 — les plus utilisés ici :

| Code | Motif | Cas d'usage |
|---|---|---|
| 1 | `keyCompromise` | clé privée exposée ou soupçonnée de l'être |
| 4 | `superseded` | remplacé par un renouvellement (appliqué automatiquement) |
| 5 | `cessationOfOperation` | service arrêté définitivement |

Un motif est **obligatoire** : `unspecified` (0) est accepté par RFC 5280 mais
signalé comme insuffisant par les règles de conformité — il ne justifie rien
devant un auditeur.

La révocation est idempotente et la **première date fait foi** : la
réappliquer ne repousse pas l'instant à partir duquel le certificat cesse
d'être fiable. `revoke` republie la CRL immédiatement — une révocation non
publiée ne protège personne.

Le renouvellement d'un service révoque automatiquement le certificat précédent
du même sujet, avec le motif `superseded` : une seule unité active par sujet
à tout instant.

## 6. Publication de l'état de révocation

La CRL est régénérée toutes les heures (`OPENEIDAS_CRL_REFRESH`) avec une
fenêtre de validité de 24 h (`OPENEIDAS_CRL_VALIDITY`) : bien avant expiration,
de sorte qu'un cycle raté ne rende jamais la CRL périmée.

Elle est publiée **même vide**. Une CRL récente sans aucune entrée prouve que
le service de statut fonctionne ; l'absence de CRL ne prouve rien
(ETSI EN 319 411-1 §6.3.10).

`/healthz` bascule en **503** dès que la CRL publiée est périmée : un service
qui ne peut plus dire ce qui est révoqué ne doit pas se déclarer sain.

Chemins de publication, ceux-là mêmes qui sont gravés dans les extensions CDP
et AIA des certificats émis :

| Chemin | Contenu |
|---|---|
| `/download/<CN>.crl` | CRL de la CA émettrice, DER |
| `/download/<CN>.cer` | certificat de la CA émettrice, DER (AIA `ca_issuers`) |
| `/api/v1/ca.pem` | chaîne complète (émettrice + racine), PEM |
| `/api/v1/conformance` | matrice ETSI telle que l'instance l'applique |

Le nom de fichier dérive du nom courant de l'émettrice
(`certs.FileName`) — une seule définition, partagée par l'émetteur qui grave
l'URL, le serveur qui publie et le répondeur OCSP qui va chercher la CRL.

## 7. Modèle de menace

| Menace | Ce qui la contient | Ce qui reste ouvert |
|---|---|---|
| Vol de la clé de la CA émettrice | La clé ne quitte jamais le token PKCS#11 ; seul le conteneur `ca` y accède | SoftHSM2 est logiciel : qui obtient le volume et le PIN obtient la clé. Un HSM certifié lève ce point |
| Vol du secret HMAC d'enrôlement | Il authentifie le demandeur, il ne décide pas : toute demande reste soumise à approbation | Une clé volée permet de déposer des demandes, pas d'en faire émettre |
| Compromission d'un opérateur RA | Chaque décision est consignée avec son auteur ; le journal est chaîné, scellé et répliqué hors site | Un opérateur seul peut approuver : il n'y a pas de double validation |
| Numéro de série prédit ou rejoué | 128 bits sur `crypto/rand`, unicité portée par la clé primaire du registre | — |
| Certificat non conforme émis | Le DER produit est relu et re-contrôlé avant d'être enregistré ; l'émission est annulée sinon | — |
| CRL ancienne rejouée pour masquer une révocation | `CRLNumber` strictement croissant, servi par une séquence PostgreSQL ; le répondeur OCSP refuse de répondre plutôt que de servir un statut obsolète | — |
| Altération du journal d'audit | Chaînage par hachage vérifié à l'ouverture ; un journal altéré empêche le démarrage | — |
| Perte de l'instance | Registre PostgreSQL sauvegardable, journal répliqué hors site à chaque scellement | Sauvegarde et restauration non encore testées de bout en bout |

## 8. Continuité et cessation d'activité

### Continuité (ETSI EN 319 401 §7.11)

Ce qui doit être sauvegardé, et suffit à reconstituer l'autorité :

1. les **tokens PKCS#11** (volume `catokens`) — sans eux, la hiérarchie est
   définitivement perdue ;
2. la **base PostgreSQL** — registre des certificats, demandes, historique des
   CRL ;
3. le **journal d'audit** (volume `castate`), déjà répliqué hors site à chaque
   scellement.

État actuel : instance unique, sauvegarde non automatisée. C'est un écart
documenté ; la cible est une redondance active/active, une sauvegarde
planifiée et une restauration testée périodiquement.

### Cessation d'activité (ETSI EN 319 401 §7.12)

Procédure prévue, non encore formalisée juridiquement :

1. annoncer la cessation avec un préavis suffisant aux utilisateurs des
   certificats émis ;
2. cesser toute émission — désactiver l'approbation RA suffit, aucune
   émission n'est possible sans décision ;
3. révoquer les certificats en cours avec le motif `cessationOfOperation` (5) ;
4. publier une **dernière CRL à longue validité** couvrant l'expiration du
   dernier certificat émis, et la maintenir accessible à son URL de
   publication ;
5. remettre les journaux d'audit et le registre à l'organe de contrôle, ou les
   placer sous séquestre ;
6. détruire les clés d'autorité, procès-verbal à l'appui.

L'engagement juridique correspondant relève de l'association, pas du logiciel :
il est porté comme exigence hors périmètre dans la matrice.

## 9. Variables d'environnement

| Variable | Défaut | Rôle |
|---|---|---|
| `OPENEIDAS_DB_DSN` | — (obligatoire) | DSN PostgreSQL du registre |
| `OPENEIDAS_ISSUING_PIN` | — (obligatoire) | PIN du token de la CA émettrice |
| `OPENEIDAS_ROOT_PIN` | valeur de `ISSUING_PIN` | PIN du token de la racine |
| `OPENEIDAS_PKI_PUBLIC_URL` | — (obligatoire) | Adresse **publique** gravée dans les extensions CDP/AIA |
| `OPENEIDAS_OCSP_PUBLIC_URL` | — | Adresse publique du répondeur OCSP (AIA) |
| `OPENEIDAS_ENROLL_HMAC_KEY` | — | Secret partagé authentifiant les demandes |
| `OPENEIDAS_CEREMONY_OPERATOR` | — (obligatoire pour `ceremony`) | Identité consignée au procès-verbal |
| `OPENEIDAS_CA_KEY_BITS` | 4096 | Taille des clés d'autorité (≥ 3072) |
| `OPENEIDAS_ROOT_CN` / `OPENEIDAS_ISSUING_CN` | Open eIDAS Root/Issuing CA | Noms courants des autorités |
| `OPENEIDAS_ROOT_VALIDITY` / `OPENEIDAS_ISSUING_VALIDITY` | 20 ans / 10 ans | Durées de vie des autorités |
| `OPENEIDAS_CRL_VALIDITY` | 24h | Fenêtre `thisUpdate` → `nextUpdate` |
| `OPENEIDAS_CRL_REFRESH` | 1h | Fréquence de republication |
| `OPENEIDAS_CRL_GRACE` | 720h | Délai après expiration pendant lequel un certificat révoqué reste listé |
| `OPENEIDAS_AUDIT_FILE` | `/var/lib/open-eidas/state/ca-audit.log` | Journal d'audit |
| `OPENEIDAS_AUDIT_RETENTION` | 8760h | Durée de conservation ; le service refuse de démarrer en deçà d'un an |
| `OPENEIDAS_LISTEN` | `:8320` | Adresse d'écoute |
| `OPENEIDAS_INTERNAL_LISTEN` | — (désactivé) | Adresse du lien interne `/internal/v1/*` |
| `OPENEIDAS_INTERNAL_TLS_CERT_FILE` / `_KEY_FILE` | — | Certificat `internal_server` et sa clé (PEM). Les deux ou aucun ; sans eux, boucle locale seulement |
| `OPENEIDAS_WEBAUTHN_RP_ID` / `_ORIGIN` / `_RP_NAME` | — (obligatoires avec le lien interne, sauf le nom) | Relying Party WebAuthn des opérateurs |
| `OPENEIDAS_RA_AUTO_APPROVE` | false | Déclaration du déploiement : les demandes sont approuvées par un conteneur technique ; affichée par `/healthz`, sans autre effet |
| `OPENEIDAS_REGISTRY_CHECK_INTERVAL` | 60s | Fréquence du contrôle du registre contre le journal (avec le lien interne) |
| `OPENEIDAS_WEBAUTHN_MODELS_FILE` | — (obligatoire avec le lien interne) | Liste blanche de modèles de clés (JSON : `description`, `aaguid`, `root_pem`) |
