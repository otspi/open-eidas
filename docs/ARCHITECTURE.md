# Architecture technique — MVP

## 1. Objectif du prototype

Démontrer qu'une autorité d'horodatage (TSA) conforme à la RFC 3161, adossée à
une PKI et à un module cryptographique, tient dans une pile reproductible que
l'on démarre en une commande. Le prototype vise la crédibilité technique
auprès de financeurs, pas encore la qualification eIDAS : les écarts au
référentiel sont listés en section 8.

## 2. Vue d'ensemble

```
                 ┌──────────────────────────────────────────────────┐
  client         │                   Open eIDAS                     │
  (curl,         │                                                  │
   openssl ts,   │   ┌───────────────┐  PKCS#11 ┌─────────────┐     │
   Sign*)        │   │  tsa-server   │─────────▶│  SoftHSM2   │     │
     │ RFC 3161  │   │    (Rust)     │          │ (→ HSM FIPS │     │
     ├──────────▶│   │               │          │   en prod)  │     │
     │  :8318    │   └──┬─────────┬──┘          └─────────────┘     │
     │           │      │         │ POST /api/v1/enroll             │
     │           │      │         ▼                                 │
     │           │      │  ┌───────────────┐   ┌─────────────┐      │
     │           │      │  │   ca-server   │───│ PostgreSQL  │      │
     │  OCSP     │      │  │    (Rust)     │   │  (registre) │      │
     ├──────────▶│   ┌──┴──┤ racine +      │   └─────────────┘      │
     │  :8319    │   │ocsp │ CA émettrice  │                        │
     │           │   │(Rust│    :8320      │──▶ PKCS#11 (2 tokens)  │
     │           │   └─────┴───────┬───────┘                        │
     │           │        CRL      │ /download/<CA>.crl, .cer       │
                 └─────────────────┼────────────────────────────────┘
                        │ NTP      │
                        ▼          ▼
              UTC(OP) · UTC(PTB)   tiers qui vérifient un certificat
```

Quatre services, tous écrits et compris par l'équipe :

| Composant | Rôle | Image / langage |
|---|---|---|
| `tsa-server` | Service RFC 3161, signature des jetons | Rust, binaire unique |
| `ca-server` | Autorité de certification et d'enregistrement : cérémonie de clé, émission depuis une CSR, approbation RA, publication de la CRL et du certificat de la CA | Rust, binaire unique |
| `ocsp-responder` | Répondeur OCSP (RFC 6960) pour la CA émettrice | Rust, binaire unique |
| SoftHSM2 | Conservation des clés privées (racine, CA émettrice, TSU, répondeur OCSP — un token par rôle) | `softhsm2` (Debian), PKCS#11 |
| PostgreSQL | Registre de la CA : autorités, certificats émis, demandes d'enrôlement, historique des CRL | `postgres:17-alpine` |

`tsa-server` et `ocsp-responder` s'enrôlent auprès de `ca-server` par la même
API (`POST /api/v1/enroll`, authentifiée par un secret HMAC partagé), en
demandant chacun son profil. Le répondeur OCSP consulte ensuite la CRL publiée
par la CA (`/download`), rafraîchie périodiquement — plutôt qu'un accès direct
au registre : il ne voit ainsi que ce qu'un tiers pourrait voir lui-même. Voir
`crates/oe-ocsp-core` et [CA.md](CA.md).

## 3. Choix techniques et justification

**Rust pour les trois services.** Binaire unique sans runtime ni ramasse-
miettes, surface d'attaque réduite, `unsafe_code = "forbid"` sur tout le
workspace sauf la seule crate d'accès au HSM (`crates/oe-hsm`, bindings
PKCS#11 via `cryptoki`) — la garantie de sécurité mémoire qu'exige un
composant qui manipule des clés de signature est ainsi vérifiable
mécaniquement, pas seulement déclarée. Le projet a d'abord été écrit en
Go, puis intégralement reporté en Rust pour cette raison ; l'ASN.1/X.509
est porté à la main sur `der`/`x509-cert` (RustCrypto), faute de
bibliothèque RFC 3161/6960 clé en main compatible à l'époque du portage.

**PKCS#11 dès le prototype.** La clé privée de la TSU ne quitte jamais le
module cryptographique : `tsa-server` ne manipule qu'un `SigningToken` dont
chaque signature est déléguée au token. SoftHSM2 parle exactement le même
protocole qu'un HSM certifié FIPS 140-2 niveau 3 ou Critères Communs. Le
passage en production se fait en changeant `OPENEIDAS_PKCS11_MODULE` et le
label du token — aucune ligne de code applicatif à modifier.

**Une autorité de certification écrite en propre.** Le certificat de la TSU
doit être émis par une CA distincte, avec un profil contraint et un cycle de
vie auditable. Le projet a d'abord intégré OpenXPKI Community, puis l'a
remplacé par `bin/ca-server` : l'intégration avait exigé, à plusieurs
reprises, de rétro-ingénierier des comportements internes non documentés,
portant précisément sur les contrôles qu'un audit vient vérifier — validité du
profil émis, effectivité de l'approbation RA. L'arbitrage complet est dans
[INDEPENDANCE.md](../INDEPENDANCE.md).

Le périmètre réellement couvert est étroit et le reste : émettre depuis une
CSR selon un profil compilé, publier une CRL, révoquer, et une machine à états
d'approbation à un seul workflow. En contrepartie, l'équipe peut expliquer
chaque règle ligne à ligne à un auditeur, et chaque exigence normative est
portée par un test exécutable.

**Les règles ETSI définies une seule fois.** `crates/oe-conformance` porte
chaque exigence technique applicable sous forme de vérification appelable,
utilisée à trois endroits qui ne peuvent pas diverger : les tests unitaires,
les gardes d'exécution (le certificat produit est relu depuis son DER et
re-contrôlé avant d'être délivré), et le rapport `ca-server conformance` qui
alimente [CONFORMITE-ETSI.md](CONFORMITE-ETSI.md). Une exigence déclarée
couverte sans mécanisme ni test nommé fait échouer la CI.

**Séparation enrôlement / service.** Le binaire expose deux sous-commandes :
`enroll` obtient le certificat, `serve` signe les jetons. Le service refuse de
démarrer si le certificat ne correspond pas à la clé du HSM ou ne porte pas
l'usage étendu `id-kp-timeStamping`. Cette séparation permet, en production, de
confier l'enrôlement à un opérateur habilité et de ne donner au service qu'un
accès en lecture au certificat.

## 4. Séquence de démarrage

1. `scripts/bootstrap.sh` génère et persiste le secret HMAC d'enrôlement.
2. PostgreSQL démarre ; `ca-server` applique ses migrations, exécute la
   **cérémonie de clé** (idempotente : deux bi-clés RSA-4096 dans deux tokens
   PKCS#11 distincts, racine puis CA émettrice, procès-verbal consigné au
   journal d'audit) et publie une première CRL. Son `/healthz` ne passe qu'une
   fois cet état servable.
3. Les conteneurs TSA et OCSP initialisent leur propre token SoftHSM au premier
   lancement.
4. `tsa-server enroll` génère une bi-clé RSA-3072 **dans le token**, produit
   une CSR signée par cette clé et la soumet à
   `POST /api/v1/enroll` avec son authentifiant HMAC. La demande atterrit en
   **attente d'approbation** : aucun chemin du code ne mène à l'émission sans
   décision d'un opérateur identifié. `ocsp-responder enroll` fait de même avec
   son profil.
5. Un opérateur RA approuve (`ca-server ra approve <transaction> <opérateur>`).
   En démonstration et en CI, cette approbation est automatisée sous une
   identité technique — écart assumé, tracé comme tel au journal et déclaré
   par `/healthz` ; désactivée par défaut dans le chart Helm (voir
   [CA.md](CA.md)).
6. À sa scrutation suivante, chaque service reçoit son certificat et sa chaîne,
   écrits sur son volume d'état. Le certificat est relu et re-contrôlé côté CA
   avant d'être délivré.
7. `tsa-server serve` charge le certificat, vérifie sa cohérence avec la clé du
   token et sa conformité au profil ETSI, puis écoute sur le port 8318.

L'enrôlement est idempotent de bout en bout : la CA reconnaît une CSR déjà
soumise à son empreinte et retrouve la demande existante, et le service
conserve au redémarrage un certificat encore valide et apparié à la clé du
HSM. Le renouvellement se déclenche automatiquement dans les 30 jours
précédant l'expiration (`OPENEIDAS_RENEW_BEFORE`) et révoque le certificat
précédent avec le motif `superseded`.

## 5. Structure du jeton produit

Le jeton est une `TimeStampResp` DER contenant un CMS `SignedData` :

- `TSTInfo` porte la politique d'horodatage, le `messageImprint` soumis, un
  numéro de série unique, `genTime` en UTC et la précision annoncée ;
- l'attribut signé `signingCertificateV2` (RFC 5035) lie le jeton au
  certificat exact de la TSU, comme l'exige ETSI EN 319 422 ;
- le nonce du client est repris tel quel lorsqu'il est présent ;
- le certificat de la TSU et sa chaîne sont inclus si le client les demande
  (`certReq`).

Empreintes acceptées : SHA-256, SHA-384, SHA-512. SHA-1 est refusé avec
`badAlg`, conformément à ETSI TS 119 312.

## 6. Traçabilité de l'heure

Un jeton d'horodatage ne vaut que ce que vaut l'horloge qui l'a produit. ETSI
EN 319 421 impose que l'heure soit traçable jusqu'à UTC et que la TSA **cesse
d'émettre** dès qu'elle ne peut plus garantir la précision qu'elle annonce.

Le service interroge donc périodiquement plusieurs serveurs NTP de
laboratoires de métrologie — par défaut l'Observatoire de Paris (UTC(OP)) et
la PTB (UTC(PTB)) — et recoupe leurs réponses. L'heure est jugée traçable
lorsque les quatre conditions suivantes sont réunies :

1. le quorum de sources est joignable (`OPENEIDAS_TIME_MIN_SOURCES`, 2 par défaut) ;
2. la dérive mesurée reste sous le seuil (`OPENEIDAS_TIME_MAX_OFFSET`, 500 ms) ;
3. les sources s'accordent entre elles à l'intérieur du même seuil ;
4. la dernière mesure n'est pas périmée (`OPENEIDAS_TIME_MAX_AGE`, 1 h).

Dès qu'une condition tombe, la politique `enforce` fait refuser chaque
demande avec le `failureInfo` **`timeNotAvailable`** — une réponse RFC 3161
parfaitement valide — et `/healthz` bascule en `503`. Le service ne produit
jamais de jeton dont il ne peut pas défendre la date, ce qui est précisément
ce qu'un auditeur vient vérifier.

L'état complet des mesures (écart par source, dispersion, strate, temps
d'aller-retour, horodatage de la dernière synchronisation) est publié sur
`/healthz` et `/api/v1/policy`, et journalisé à chaque cycle.

Deux politiques dégradées existent pour le développement : `monitor`
journalise l'écart sans bloquer l'émission, `disabled` désactive la
surveillance. Aucune des deux n'est admissible en production.

## 7. Journal d'audit inaltérable

Un auditeur ne vérifie pas seulement qu'un jeton est correct : il vérifie que
le service *était sous contrôle* au moment où il l'a émis, et que la trace de
cet instant n'a pas été retouchée depuis.

Le service tient donc un journal en JSON Lines dont chaque enregistrement
porte l'empreinte SHA-256 du précédent. Modifier une ligne, en supprimer une
ou en intercaler une rompt la chaîne, et la rupture est détectable par
quiconque relit le fichier — y compris sans accès au service :

```bash
docker compose exec tsa tsa-server verify-audit
```

Y sont consignés l'ouverture du journal, chaque jeton émis
(`timestamp.granted` : `genTime`, politique, présence d'un nonce, et le numéro
de série du **certificat** TSU), chaque refus avec son `failureInfo`
(`timestamp.rejected`) et chaque mesure de temps avec l'écart par source
(`time.measurement`). La CA tient son propre journal chaîné, où figurent les
demandes d'enrôlement, les décisions RA, les émissions et les révocations.

**Écart en cours de correction** (constat J-3 de l'audit du 2026-09-25,
PR #52) : le journal de la TSA ne consigne pas encore le numéro de série du
**jeton**, ni l'empreinte soumise, et le jeton n'est pas relu avant d'être
consigné.

Deux propriétés rendent le dispositif exploitable :

- **Une écriture ratée annule l'émission.** L'événement est écrit *avant* la
  signature : si le journal ne peut pas être écrit, la requête échoue et rien
  n'est signé. Un jeton non tracé ne sort jamais du service. Il en va de même
  côté CA pour l'émission, la révocation et la publication de la CRL.
- **Un journal altéré empêche le démarrage.** La chaîne est vérifiée
  intégralement à l'ouverture.

### Limite : l'intégrité repose sur l'hôte (écart déclaré)

Le chaînage SHA-256 n'utilise pas de clé : quiconque peut écrire dans le
fichier peut en tronquer la fin ou le réécrire en recalculant la chaîne, sans
que `verify-audit` le voie. Ce qui ancre la tête de chaîne hors du système
**n'est pas encore en service** (constat J-1) :

- **Scellement périodique** par la TSU elle-même (`log.sealed`) : le format
  est prévu (`oe_audit::EVENT_SEALED`, compté par `verify-audit`), mais aucun
  service ne scelle.
- **Contreseing par des TSA tierces** indépendantes (`oe-crosstsa`, protocole
  RFC 3161 standard, vérifiable par `openssl ts -verify` sans rien d'Open
  eIDAS) : bibliothèque écrite et testée contre un vrai serveur, non câblée.
- **Réplication hors site** : `oe-replicate` (WebDAV) est écrit et testé, non
  câblé ; une copie vers un stockage objet compatible S3 auto-hébergé est en
  cours (PR #49 et #50).

Les variables `OPENEIDAS_AUDIT_SEAL_INTERVAL`, `OPENEIDAS_CROSS_TSA_URLS` et
`OPENEIDAS_AUDIT_REPLICA_*` du `docker-compose.yml` et du chart Helm sont
lues sans être exploitées. D'ici là, l'intégrité du journal revient au
contrôle d'accès de son volume (voir [CPS.md](CPS.md) B.3 et
[CONFORMITE-ETSI.md](CONFORMITE-ETSI.md)).

## 8. Écarts assumés du prototype vis-à-vis d'une TSA qualifiée

L'état exigence par exigence, avec le mécanisme qui la porte et le test qui le
vérifie, est dans [CONFORMITE-ETSI.md](CONFORMITE-ETSI.md) — généré depuis
`crates/oe-conformance`, donc incapable de diverger du code. Le tableau
ci-dessous en donne la lecture d'ensemble.

| Exigence | État du prototype | Cible |
|---|---|---|
| Module cryptographique | SoftHSM2 (logiciel), quatre tokens distincts (racine, CA émettrice, TSU, répondeur OCSP) | HSM certifié FIPS 140-2 niv. 3 / CC EAL4+ ; seul `OPENEIDAS_PKCS11_MODULE` change |
| Source de temps | Surveillance NTP de deux sources UTC(k) avec suspension automatique de l'émission | Réception redondante et indépendante, calibration documentée, journal des mesures conservé et audité |
| Cérémonie de clé | Scriptée, idempotente, procès-verbal consigné au journal d'audit (empreintes, opérateur, horodatage) — mais sans double contrôle ni témoin | Double contrôle, témoin indépendant, HSM certifié, racine hors ligne après cérémonie (voir [CA.md](CA.md)) |
| Approbation RA | Point d'approbation réellement actif : aucun chemin du code ne mène à l'émission sans décision d'un opérateur identifié, consignée en base et au journal. Automatisée sous un compte technique pour que la démonstration/CI s'amorce sans opérateur humain | Revue humaine réelle par un opérateur RA nominatif, à la place de l'approbation automatisée |
| Journalisation | Journal chaîné par hachage, écrit avant chaque émission ; durée de conservation contrôlée au démarrage côté CA seulement. Scellement, contreseing tiers et réplication hors site **non câblés** (écart J-1) | Scellement et contreseing périodiques, copie hors site, conservation contrôlée côté TSA, politique de conservation formalisée |
| Politique d'horodatage | OID de test `1.3.6.1.4.1.99999.1.1.1` ; brouillon de Policy/Practice Statement dans [CPS.md](CPS.md) | OID sous l'arc PEN de l'association, [CPS.md](CPS.md) adopté formellement et publié |
| Profils de certificat | Structures Rust compilées et testées ; le certificat émis est relu depuis son DER et re-contrôlé avant délivrance ; CDP, AIA `ca_issuers` et répondeur OCSP réellement publiés et vérifiés | OID de politique de certification propre |
| Continuité | Instance unique ; registre PostgreSQL sauvegardable ; journal **non** répliqué hors site (écart J-1) | Redondance active/active, sauvegarde et restauration testées, plan de cessation d'activité engagé (voir [CA.md](CA.md)) |
| Audit | Aucun | Évaluation par un organisme accrédité (LSTI, Apave), inscription à la liste de confiance |

Le prototype refuse de démarrer sur les écarts qui rendraient les jetons ou
les certificats invalides (clé et certificat désaccordés, usage étendu absent
ou non critique, clé trop courte, certificat expiré, autorité elle-même non
conforme) et journalise un avertissement sur les écarts non bloquants.

**Sur le moteur de CA/RA.** Il n'y en a plus de tiers : `bin/ca-server` a
remplacé OpenXPKI Community. Le motif était la difficulté répétée à établir ce
que le moteur faisait réellement — un profil de certificat mal formé y
échouait silencieusement à l'émission plutôt qu'au chargement, et le point
d'approbation RA était contourné par une règle d'éligibilité sans qu'aucune
erreur ne le signale. Ce type d'opacité porte précisément sur des contrôles
qu'un audit eIDAS vient examiner. L'arbitrage, le périmètre repris et l'effort
consenti sont détaillés dans [INDEPENDANCE.md](../INDEPENDANCE.md).

Ce que ce remplacement ne supprime pas : la nécessité d'un audit de
sécurité externe et indépendant — un auditeur scrutera probablement du code
maison *plus* attentivement, faute d'antécédent — ni les mesures
organisationnelles (cérémonie sous double contrôle, opérateur RA nominatif,
CP/CPS publiés), identiques quel que soit le moteur.

## 9. Trajectoire vers la production

1. **Temps.** Passer d'une synchronisation réseau à une réception redondante
   et indépendante, conserver le journal des mesures et faire calibrer la
   chaîne de temps.
2. **HSM.** Remplacer SoftHSM par un module certifié ; le code applicatif est
   déjà compatible.
3. **Politique.** Publier la TSA Policy et la Practice Statement, obtenir un
   arc OID propre.
4. **Cérémonie de clé.** Rejouer la cérémonie sur HSM certifié, sous double
   contrôle et témoin indépendant, avec procès-verbal contresigné ; retirer
   ensuite le token de la racine du système (voir [CA.md](CA.md)).
5. **Autorité d'enregistrement.** Substituer un opérateur RA nominatif à
   l'approbation automatisée de la démonstration.
6. **Exploitation.** Supervision, deux instances derrière un répartiteur,
   sauvegarde et restauration testées, procédure de révocation testée.
7. **Qualification.** Constituer le dossier ANSSI et engager l'audit d'un
   organisme accrédité, en s'appuyant sur
   [CONFORMITE-ETSI.md](CONFORMITE-ETSI.md) comme point d'entrée.
