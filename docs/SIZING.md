# Dimensionnement de la pile

Mesures directes du plancher réel de RAM pour `postgres`, `ca-server`, `tsa`
et `ocsp-responder`, et de CPU pour `ca-server` (le seul dont l'opération
dominante — la cérémonie de clé — est sensiblement limitée par le CPU), pour
que les demandes/limites déclarées dans `docker-compose.yml` et
`deploy/helm/open-eidas/values.yaml` soient des faits vérifiés plutôt que des
estimations pour ces services. Un service produisant des signatures
cryptographiques pour un tiers de confiance mérite mieux qu'un chiffre au
doigt mouillé.

Le conteneur Helm `ra-autoapprove` n'a pas été mesuré : ses valeurs
(16/64 Mio) sont une estimation par analogie avec les services mesurés, pas un
résultat de test. `[À COMPLÉTER — mesurer effectivement ce service]`

Les limites CPU de `postgres`, `tsa` et `ocsp-responder`, elles, ne sont pas
issues d'une mesure de plancher de rupture :
faute d'opération CPU-bound comparable à la cérémonie de clé chez ces
services, elles reprennent un ratio raisonnable par rapport à leur RAM
retenue plutôt qu'un chiffre mesuré. `[À COMPLÉTER — mesurer effectivement
ces planchers CPU si une contrainte de capacité concrète l'exige]`

Cohérent avec la mission de l'association (voir README.md) : une
infrastructure aussi frugale que possible réduit le coût d'exploitation, donc
le coût du service rendu.

## Méthode

Chaque service a été isolé (réseau Docker dédié, hors du `docker-compose.yml`
normal) et testé sous contrainte croissante avec `docker run
--memory=<N> --memory-swap=<N> --cpus=<N>`, en observant :

1. l'échec net (`OOMKilled`, code de sortie non nul) — le plancher que rien
   ne doit franchir ;
2. le régime réellement coûteux — pas le service au repos, mais l'opération
   la plus lourde qu'il exécute : la cérémonie de clé pour la CA (deux
   paires RSA-4096), l'enrôlement pour la TSA et le répondeur OCSP (une
   paire RSA-3072 chacun), une salve de requêtes réelles (horodatage,
   réponse OCSP, publication de CRL) une fois en service.

Les valeurs retenues dans la configuration ne sont **pas** les planchers de
rupture : elles portent une marge (typiquement ×2 sur la mémoire) pour
absorber la variabilité d'un hôte de production (bruit voisin, pics de
l'allocateur mémoire sous charge, connexions concurrentes) que ce protocole
de mesure, volontairement isolé, ne reproduit pas.

## Résultats

### PostgreSQL (registre de la CA)

| Test | Résultat |
|---|---|
| 32 Mio | **Échec net** — `OOMKilled` pendant `initdb`, reproductible |
| 40-48 Mio | Démarre et répond, ~20 Mio réellement utilisés |
| 64 Mio (retenu, requête) | Marge confortable |

### `ca-server` — cérémonie de clé (2× RSA-4096 via PKCS#11/SoftHSM)

| Mémoire | Résultat |
|---|---|
| 6 Mio (plancher minimal accepté par Docker lui-même) | **Réussit**, de façon reproductible |

Aucun plancher mémoire n'a pu être atteint dans la plage que Docker autorise.

| CPU | Durée de la cérémonie |
|---|---|
| 1,0 | ~2 s |
| 0,5 | ~3 s |
| 0,25 | ~9 s |
| 0,1 | ~32 s |
| 0,05 | ~41 s |
| 0,02 | **Échec** après ~8 min (délai dépassé ailleurs dans la chaîne) |

Aux valeurs retenues (100m demandé, 1,0 en limite), le CPU est un facteur de
**durée**, pas de panne, pour cette opération ponctuelle au premier
démarrage. Il ne redevient un facteur de panne qu'en dessous de ~0,05 CPU,
un plancher bien inférieur à la configuration retenue.

### `ca-server` — régime `serve` sous charge réelle d'enrôlement

Une CA en service, recevant une vraie demande d'enrôlement (parsing de CSR,
écritures PostgreSQL, ajout au journal d'audit chaîné) — plus coûteux qu'un
simple `GET /healthz` :

| Mémoire | Résultat |
|---|---|
| 8 Mio | **Instable** — un `OOMKilled` observé sous salve concurrente (rafale de `GET` + enrôlement simultané), mais l'enrôlement seul réussit de façon répétée |
| 9-16 Mio | Stable de façon répétée, y compris sous enrôlement réel |
| 32 Mio (retenu, requête) | Usage observé : 4-5 Mio — large marge |

### `tsa-server` / `ocsp-responder` — enrôlement (1× RSA-3072)

| Mémoire | Résultat |
|---|---|
| 6 Mio (plancher Docker) | **Réussit**, pour les deux services |

### `tsa-server` / `ocsp-responder` — régime `serve` sous charge réelle

Dix horodatages RFC 3161 signés consécutivement (TSA), cinq requêtes OCSP
vérifiées `openssl ocsp` (répondeur) :

| Service | Mémoire testée | Usage observé sous charge |
|---|---|---|
| TSA | 16 Mio | jusqu'à 9,3 Mio |
| Répondeur OCSP | 16 Mio | 3,3 Mio |

Retenu : 32 Mio (TSA) / 24 Mio (OCSP) — marge confortable au-dessus de
l'usage observé.

## Configuration retenue

Ce tableau donne la configuration Helm (requêtes et limites CPU/RAM). Le
`docker-compose.yml` ne reprend que les colonnes « Limite CPU » (`cpus`) et
« Requête/Limite RAM » (`mem_reservation`/`mem_limit`) : Compose n'a pas de
notion de requête CPU.

| Service | Requête CPU | Limite CPU | Requête RAM | Limite RAM |
|---|---|---|---|---|
| `ca` (cérémonie + service) | 100m | 1 | 32Mi | 128Mi |
| `ca` — approbation automatique (démonstration) | 5m | 50m | 16Mi | 64Mi |
| `tsa` | 25m | 250m | 32Mi | 128Mi |
| `ocsp-responder` | 15m | 150m | 24Mi | 96Mi |
| `postgres` | 50m | 500m | 64Mi | 256Mi |

**Total `docker-compose.yml`** (`ca`, `tsa`, `ocsp-responder`, `postgres`
— l'approbation RA y est une boucle dans
`scripts/bootstrap.sh`, pas un conteneur séparé) : Compose ne déclare qu'une
limite CPU par service (`cpus`, pas de réservation) et une réservation/limite
mémoire (`mem_reservation`/`mem_limit`) ; il n'y a donc pas de total de CPU
« demandé » pour cette pile, seulement ~1,9 CPU cumulés en limite et ~152 Mio
de RAM réservée (~608 Mio en limite).

**Total chart Helm** (les mêmes, plus le conteneur `ra-autoapprove`) : Helm
déclare requêtes *et* limites CPU/RAM par service : ~195m CPU demandés
(1,95 CPU en limite), ~168 Mio de RAM demandée (~672 Mio en limite).

Sur un unique nœud modeste dans les deux cas, là où la pile OpenXPKI
précédente exigeait 4 conteneurs supplémentaires (MariaDB compris) pour un
service fonctionnellement plus restreint (voir
[INDEPENDANCE.md](../INDEPENDANCE.md)).

## Limite de la méthode

Ces mesures isolent un service à la fois : elles ne capturent pas la
contention réelle d'un nœud de production sous charge simultanée de tous les
services, ni le comportement du disque/réseau sous IO concurrentes. Les
marges retenues (généralement ×2 sur la mémoire testée stable) sont un choix
délibérément prudent pour cette raison, pas une tentative de reproduire un
environnement de production. Une observation `docker stats` /
`kubectl top pod` sur un déploiement réel reste la vérification qui fait
foi ; ces chiffres sont un point de départ documenté, pas une garantie.
