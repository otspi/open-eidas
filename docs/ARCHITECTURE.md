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
au registre : il ne voit ainsi que ce qu'un tiers pourrait voir lui-même. Il ne
sert qu'une CRL signée par la CA émettrice et dont le `cRLNumber` n'est pas
inférieur au dernier accepté (une CRL plus ancienne rejouée est refusée) ; passé
le `nextUpdate` de la CRL en cache, il répond `tryLater` plutôt que de signer un
statut échu. Ses réponses reprennent le nonce du client (RFC 8954) et couvrent
chaque requête de la liste (constat O-2). Voir `crates/oe-ocsp-core` et
[CA.md](CA.md).

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

Chaque mesure est un échange SNTP (RFC 5905) dont le client, écrit dans le
dépôt (`crates/oe-timesource/src/ntp.rs`), ne retient une réponse que si elle
répond bien à sa requête (constat T-2 de l'audit du 2026-09-25) : le
*transmit* de la requête porte des bits aléatoires que l'*originate* de la
réponse doit reprendre à l'identique, depuis un port source éphémère — une
réponse forgée hors chemin est écartée. Sont refusées aussi une réponse d'une
source non synchronisée (indicateur de saut 3, strate 0 ou ≥ 16), d'un autre
mode ou d'une autre version que serveur 3/4, sans horodatages, ou dont
l'aller-retour dépasse `OPENEIDAS_TIME_MAX_RTT` (1 s) — l'écart mesuré serait
trop incertain. Le protocole NTP seul n'est pas authentifié : contre un
attaquant en chemin, seul **NTS** (RFC 8915) protège. Une source déclarée
`nts://hôte` est mesurée par NTS (`crates/oe-timesource/src/nts.rs`) : une
session TLS 1.3 avec le laboratoire (NTS-KE, ALPN `ntske/1`, port 4460,
certificat vérifié contre les racines publiques embarquées ou
`OPENEIDAS_TIME_NTS_CA_FILE`) négocie NTPv4 et `AES-SIV-CMAC-256`, remet des
cookies et dérive les clés par l'exportateur TLS ; chaque requête NTP porte
ensuite un identifiant unique, un cookie et un authentificateur qui couvre le
paquet, et la réponse n'est retenue que si elle reprend l'identifiant et
vérifie sous la clé du serveur. La mesure est marquée `authenticated` dans le
journal et `/healthz`. La PTB propose NTS (`nts://ptbtime1.ptb.de`),
l'Observatoire de Paris non : le choix des sources est une décision de
déploiement.

L'indicateur de saut des réponses est lu (constat T-4) : dès qu'une source
annonce une seconde intercalaire, `/healthz` le montre
(`time_source.leap_second`, 1 insertion ou 2 suppression), le journal la
consigne (`time.leap_second`, phase `annoncee`), et, en politique `enforce`,
le service suspend l'émission (`timeNotAvailable`) pendant la dernière minute
du jour UTC annoncé — c'est là que l'ajustement a lieu — jusqu'à ce qu'une
mesure prise après le changement de jour, déclenchée sans attendre
l'intervalle, confirme l'écart de l'horloge locale ; cette mesure est
consignée (phase `appliquee`, écart mesuré). L'horloge système doit appliquer
la seconde par un saut, jamais par lissage : c'est une exigence d'exploitation
(voir la CPS), que le code ne peut pas vérifier.

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
(`timestamp.granted` : numéro de série du **jeton** tel que relu dans le
jeton construit, `genTime` avec sa fraction de seconde, politique, empreinte
soumise et son algorithme, présence d'un nonce, empreinte du certificat TSU,
et l'état de l'horloge à cet instant — traçabilité, écart, sources), chaque
refus avec son `failureInfo` (`timestamp.rejected`) et chaque mesure de temps
avec l'écart par source (`time.measurement`). C'est ce qui permet, après un
incident, d'identifier un par un les jetons affectés (EN 319 421
`OVR-7.13-05`). La CA tient son propre journal chaîné, où figurent les
demandes d'enrôlement, les décisions RA (avec la voie par laquelle l'opérateur
a été identifié : `authenticated_via`), les émissions, les révocations et les
actes de la racine (révocation d'une autorité, ARL).

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
que `verify-audit` le voie. La tête de chaîne est donc ancrée hors du système,
périodiquement, par le crate `oe-seal`, **en service dans les trois services**
(constat J-1 ; décision du 2026-10-13 : scellement par la TSA maison, en HTTP) :

- **Scellement périodique** par la TSA de la maison. Au démarrage puis à chaque
  `OPENEIDAS_AUDIT_SEAL_INTERVAL`, `tsa-server` fait horodater la tête de son
  journal par sa propre autorité, en mémoire ; `ca-server` et `ra-console` font
  horodater la leur par `tsa-server` (`OPENEIDAS_TSA_URL`), **en HTTP, comme
  n'importe quel client RFC 3161**. Chacun consigne `log.sealed` avec la tête
  scellée et le jeton, certificat compris (et, pour un sceau obtenu en HTTP, le
  nom de l'autorité) : `openssl ts -verify -digest <tête>` le vérifie sans rien
  d'Open eIDAS. Réécrire un journal avant un sceau demanderait de reforger un
  jeton signé par la clé du module cryptographique de la TSA. Sans
  `OPENEIDAS_TSA_URL`, la CA et la console le disent au démarrage et ne scellent
  pas.
- **Copie hors site** sur un stockage objet compatible S3, auto-hébergé :
  chaque service y dépose son journal entier après chaque scellement
  (`log.replicated`) ; `ca-server` le fait de plus à chaque écriture, de façon
  bloquante, et `ra-console` au mieux. La copie périodique n'attend aucune
  écriture — le journal de la TSA reçoit une entrée par jeton — et l'émission
  n'en dépend pas.
- **Contreseing par des TSA tierces** indépendantes (`oe-crosstsa`, protocole
  RFC 3161 standard). La tête qui vient d'être scellée est aussi horodatée par
  chaque autorité de `OPENEIDAS_CROSS_TSA_URLS` ; chaque réponse est consignée
  (`log.cross_sealed`) avec son jeton, vérifiable par `openssl ts -verify` et le
  certificat de l'autorité, sans rien d'Open eIDAS. C'est ce qui sort le sceau
  de l'auto-référence. Le service contrôle que le jeton porte l'empreinte
  soumise ; il n'en vérifie pas la signature, faute d'ancres de confiance pour
  ces autorités : cette vérification se fait après coup. La variable posée à
  vide désactive le contreseing (la CI, un réseau sans sortie : la console, dont
  la NetworkPolicy du chart ne s'ouvre vers l'extérieur que si
  `raConsole.crossTSA.urls` est renseigné).

Un scellement, un contreseing ou une copie en échec ne suspend ni l'émission ni
le service. Un scellement en échec est retenté après une minute au plus (au
démarrage, l'heure de la TSA peut ne pas être encore traçable, ou la TSA pas
encore enrôlée : la CA démarre avant elle) ; au-delà de trois passes consécutives
en échec (pour le contreseing : trois passes sans aucune autorité tierce),
`/healthz` se déclare dégradé (`journal.degraded`, statut `degrade`), sans passer
en erreur : c'est à la supervision d'alerter. La démonstration de la CI vérifie
que la CA a bien fait sceller son journal par la TSA. `oe-replicate`
(WebDAV) reste disponible mais n'est appelé par aucun binaire. Voir
[CPS.md](CPS.md) B.3 et [CONFORMITE-ETSI.md](CONFORMITE-ETSI.md).

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
| Politique d'horodatage | OID de test `1.3.6.1.4.1.67027.9.1.1.1` ; brouillon de Policy/Practice Statement dans [CPS.md](CPS.md) | OID sous l'arc PEN de l'association, [CPS.md](CPS.md) adopté formellement et publié |
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
