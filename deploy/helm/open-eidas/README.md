# Chart Helm Open eIDAS

Déploie la même pile que le `docker-compose.yml` de démonstration —
PostgreSQL, l'autorité de certification maison (racine + CA émettrice,
`cmd/ca-server`), un serveur WebDAV de réplication du journal d'audit, le
répondeur OCSP et le service d'horodatage — sur Kubernetes, pilotable par
ArgoCD.

**Comme le docker-compose, ce chart est une démonstration** : cérémonie de
clé sans double contrôle ni témoin, approbation RA automatisée sous un compte
technique, SoftHSM en lieu d'un HSM certifié. L'état exigence par exigence
est dans [docs/CONFORMITE-ETSI.md](../../../docs/CONFORMITE-ETSI.md) ; les
écarts au référentiel eIDAS dans
[docs/ARCHITECTURE.md](../../../docs/ARCHITECTURE.md).

## Installation

Démonstration, qui s'amorce seule (approbation RA automatique, voir plus bas) :

```bash
helm install open-eidas deploy/helm/open-eidas --namespace open-eidas --create-namespace \
    --set ca.autoApprove.enabled=true
```

Sans `ca.autoApprove.enabled=true` (valeur par défaut), la TSU et le répondeur
OCSP attendent qu'un opérateur nommé approuve leur demande (voir « Approbation
RA »).

L'amorçage complet (cérémonie de clé, publication de la première CRL,
enrôlement puis approbation de la TSU et du répondeur OCSP) prend 1 à 2
minutes — l'essentiel étant la génération de deux bi-clés RSA-4096 dans
SoftHSM. Suivre la progression :

```bash
kubectl -n open-eidas get pods -w
kubectl -n open-eidas logs deploy/open-eidas-ca -c ca -f
kubectl -n open-eidas logs deploy/open-eidas-ca -c ra-autoapprove -f
```

Vérifier l'horodatage :

```bash
kubectl -n open-eidas port-forward svc/open-eidas-tsa 8318:8318 &
curl -s -X POST http://localhost:8318/api/v1/timestamp \
     -H 'Content-Type: application/json' \
     -d "{\"hash\":\"$(sha256sum facture.pdf | cut -d' ' -f1)\"}"
```

## Déploiement avec ArgoCD

Voir [otspi/deploy](https://github.com/otspi/deploy), dépôt
app-of-apps qui référence ce chart.

## Déploiement public de démonstration (staging)

Guide détaillé pas-à-pas : [docs/STAGING.md](../../../docs/STAGING.md).

`values-staging.yaml` expose la TSA sur `api.staging.open-eidas.eu` et la
publication de la CA (CRL, certificat de la CA émettrice) sur
`pki.staging.open-eidas.eu`, via des `HTTPRoute` Gateway API (pas d'Ingress).
L'API d'enrôlement, elle, n'est jamais exposée : seuls les services du
cluster s'y adressent.

Préalables sur le cluster cible (à provisionner séparément, non gérés par ce
chart — voir [otspi/deploy](https://github.com/otspi/deploy) pour
ce qui EST géré par ce dépôt) :

1. Une Gateway API (`gateway.networking.k8s.io`) nommée `shared-gateway`
   dans le namespace `ingress`, avec un listener HTTPS par hôte
   (`api`/`pki`/`ocsp.staging.open-eidas.eu`), chacun avec
   son `Certificate` cert-manager.
2. Trois enregistrements DNS pointant vers l'adresse publique de cette
   Gateway : `api.staging.open-eidas.eu`, `pki.staging.open-eidas.eu` et
   `ocsp.staging.open-eidas.eu`.
3. Le Secret `open-eidas-generated` (scellé via kubeseal, voir
   `otspi/deploy`) déjà présent dans le namespace `open-eidas-staging`,
   ainsi que le Cluster CloudNativePG qu'il amorce.

Puis, soit en `helm install` direct :

```bash
helm install open-eidas deploy/helm/open-eidas \
    --namespace open-eidas-staging --create-namespace \
    -f deploy/helm/open-eidas/values-staging.yaml
```

soit via ArgoCD : [apps/open-eidas-staging.yaml](https://github.com/otspi/deploy/blob/main/apps/open-eidas-staging.yaml)
dans le dépôt [otspi/deploy](https://github.com/otspi/deploy).

## Architecture du chart

| Ressource | Rôle |
|---|---|
| `<release>-postgres` (StatefulSet) | Registre de la CA : autorités, certificats émis, demandes d'enrôlement, historique des CRL |
| `<release>-ca` (Deployment) | Autorité de certification et d'enregistrement. Deux conteneurs : `ca` (cérémonie, émission, publication de la CRL) et `ra-autoapprove` (approbation automatique — voir ci-dessous). PVC pour ses deux tokens SoftHSM et son journal d'audit |
| `<release>-audit-replica` (Deployment) | Serveur WebDAV cible de la réplication du journal d'audit |
| `<release>-tsa` (Deployment) | Service d'horodatage, avec PVC pour le token SoftHSM et l'état (certificat, journal d'audit) |
| `<release>-ocsp` (Deployment) | Répondeur OCSP (RFC 6960) pour la CA émettrice — PVC dédié pour son propre token SoftHSM et son état |
| `<release>-generated` (Secret) | Mot de passe PostgreSQL, PIN SoftHSM (un par token : TSU, OCSP, racine, émettrice), mot de passe WebDAV, secret HMAC d'enrôlement — générés une fois et stables d'un `helm upgrade` à l'autre (motif `lookup`) |

Le Pod `ca` est le seul à détenir les clés d'autorité, et il n'a qu'un
réplica : les tokens PKCS#11 et le journal d'audit chaîné vivent sur des
volumes `ReadWriteOnce`, et la clé d'une CA n'a pas vocation à être répliquée.
La cérémonie de clé est idempotente et rejouée à chaque démarrage : elle relit
la hiérarchie enregistrée plutôt que d'en créer une seconde, et refuse de
démarrer si la clé d'un token ne correspond plus au certificat enregistré.

## Approbation RA — écart assumé

**Désactivée par défaut** (constat R-2 de l'audit du 2026-09-25). Activée
(`ca.autoApprove.enabled: true`), le conteneur `ra-autoapprove` approuve les
demandes d'enrôlement sous l'identité `ca.autoApprove.operator`
(`ci-bootstrap` par défaut), afin que la démonstration et la CI s'amorcent sans
opérateur humain. `/healthz` de la CA le déclare
(`"approbation_automatique": true`), et le chart refuse le rendu si
`production: true` est posé en même temps.

Ce n'est **pas** un contournement du point d'approbation : aucun chemin du
code ne mène à l'émission sans décision identifiée (voir `internal/raflow`),
et cette identité technique figure telle quelle au journal d'audit — l'écart
est donc visible d'un auditeur, pas masqué. Le conteneur ne monte d'ailleurs
aucun token PKCS#11 : approuver, c'est décider, pas signer.

Un déploiement destiné à la qualification pose :

```yaml
production: true
```

(qui garantit que l'approbation automatique reste désactivée) et approuve à la
main, sous une identité nominative :

```bash
kubectl -n open-eidas exec deploy/open-eidas-ca -c ca -- ca-server ra list PENDING
kubectl -n open-eidas exec deploy/open-eidas-ca -c ca -- \
    ca-server ra approve <transaction_id> "prenom.nom" "identité vérifiée le ..."
```

## Lien interne des actions d'opérateur (optionnel)

`ca-server` peut exposer, sur un **second port** (`ca.service.internalPort`,
8321), les routes `/internal/v1/*` par lesquelles la console d'exploitation
(`ra-console`, section suivante) fait exécuter des actions signées par des
opérateurs ([docs/WEBUI.md](../../../docs/WEBUI.md) §16-17). Désactivé par
défaut : un port qui accepte des actions privilégiées ne s'ouvre que sur
décision explicite.

```yaml
ca:
  internal:
    enabled: true
    webauthn:
      rpId: console.open-eidas.example        # nom d'hôte exact de l'origine
      origin: https://console.open-eidas.example
    models:                                    # liste blanche de clés (décision O6)
      - description: "YubiKey 5 (série X)"
        aaguid: "…"
        rootPem: |
          -----BEGIN CERTIFICATE-----
```

Ce que ça ajoute : le port dans le `Service` de la CA (**jamais** dans une
`HTTPRoute`), une `ConfigMap` de la liste blanche, et une `NetworkPolicy` qui
n'ouvre le port interne qu'aux pods `ra-console` de la release (le port public
reste ouvert au cluster). Le rendu **échoue** si `rpId`, `origin` ou `models`
manquent : un lien interne à moitié configuré n'est pas déployé. Le cluster doit
faire appliquer les `NetworkPolicy` ; sans cela, le port serait joignable de tout
le cluster (le mTLS reste, lui, exigé par `ca-server`).

**Certificat du serveur (Jour 0).** Au premier démarrage, l'entrypoint dépose la
demande de certificat `internal_server` (`ca-server internal-cert server`) et
attend son approbation avant d'ouvrir le service : le sidecar d'approbation la
traite en démonstration ; en production, un opérateur nommé l'approuve :

```bash
kubectl -n <ns> exec deploy/<release>-open-eidas-ca -c ca -- \
    ca-server ra list PENDING
kubectl -n <ns> exec deploy/<release>-open-eidas-ca -c ca -- \
    ca-server ra approve <transaction> prenom.nom "amorçage du lien interne"
```

La clé et le certificat vivent sur le volume d'état (`internal-tls/`, clé en
0600). La demande et la clé survivent à un redémarrage. Le certificat vaut 3 mois
et n'est lu qu'au démarrage : le renouveler demande de supprimer `server.pem`
puis de redémarrer le pod. Le certificat **client** de `ra-console` se demande
côté `ra-console`, jamais approuvé par elle-même.

## Console d'exploitation `ra-console` (optionnelle)

La console RA/CA ([docs/RA-CONSOLE.md](../../../docs/RA-CONSOLE.md)) : connexion
des opérateurs par clé FIDO2, décisions d'enrôlement et révocations signées,
relayées à `ca-server` par le lien interne. **Désactivée par défaut** ; elle exige
le lien interne ci-dessus, dont elle **réutilise** la configuration WebAuthn et la
liste blanche de modèles (une seule Relying Party). Le rendu **échoue** si
`raConsole.enabled` est posé sans `ca.internal.enabled`.

```yaml
ca:
  internal:
    enabled: true
    webauthn: { rpId: console.open-eidas.example, origin: https://console.open-eidas.example }
    models: [...]
raConsole:
  enabled: true
  gateway:              # Gateway INTERNE : jamais une Gateway publique
    enabled: true
    name: internal-gateway
    namespace: ingress
    host: console.open-eidas.example   # = l'hôte de ca.internal.webauthn.origin
```

Ce que ça ajoute :

- un `Deployment` (une instance, volume d'état `ReadWriteOnce` : clé et certificat
  client, certificat de la CA, journal d'audit de la console), son `Service` et, si
  `raConsole.gateway.enabled`, une `HTTPRoute` ;
- une `NetworkPolicy` : en entrée, le seul namespace de la Gateway ; en sortie, le
  DNS, PostgreSQL et la CA (API publique et port interne). Sans Gateway, rien
  n'entre par le réseau du cluster (`kubectl port-forward` reste possible) ;
- un **Job** (hook `post-install`/`post-upgrade`) qui applique les droits du rôle
  PostgreSQL en lecture seule `openeidas_ra_console`
  (`files/ra_console_grants.sql`, copie vérifiée par la CI de
  `crates/oe-castore/sql/ra_console_grants.sql`) et lui donne son mot de passe. Un
  Job plutôt qu'un conteneur d'initialisation de la console : **les identifiants
  d'administration de la base n'entrent jamais dans le pod de la console**, le
  composant le plus exposé. Rejoué à chaque mise à jour, il fait arriver les
  nouveaux droits sans geste manuel. Il attend que `ca-server` ait appliqué ses
  migrations. Le compte `postgres.user` doit pouvoir créer un rôle (c'est le cas du
  StatefulSet intégré ; pour une base externe, à vérifier) ;
- deux clés au Secret généré : `ra-console-db-password` et
  `ra-console-decoy-secret` (réponses de connexion uniformes). Avec
  `secrets.existingSecret`, le Secret fourni doit les contenir.

**Premier démarrage.** L'entrypoint (`deploy/ra-console/entrypoint.sh`) récupère
le certificat de la CA émettrice sur l'API interne de la CA (`/api/v1/ca.pem`, le
premier certificat fait foi), puis demande le certificat client `internal_client`
(`ra-console internal-cert`) et **attend son approbation** : le sidecar
d'approbation la traite en démonstration ; en production, un opérateur nommé
l'approuve sur la CA (`ca-server ra approve`), comme pour `internal_server`. La
console n'approuve jamais son propre certificat. Un conteneur d'initialisation
attend, avec les identifiants **de la console**, que le Job ait créé son rôle.

## Écarts notables avec le docker-compose

Aucun, désormais, sur le plan des permissions : le remplacement d'OpenXPKI par
`cmd/ca-server` a fait disparaître le Pod à quatre conteneurs et les
contournements qu'il imposait (`fsGroup` et `supplementalGroups` partagés,
vhost Apache recopié faute d'équivalent au bind-mount de fichier unique,
groupe des workers Apache forcé pour atteindre un socket Unix). Les trois
services sont des binaires Go qui écoutent en HTTP et n'ont besoin d'aucun
partage de socket entre conteneurs.

Reste une différence de forme : l'approbation automatique des demandes est un
conteneur permanent ici, une boucle dans `scripts/bootstrap.sh` en
docker-compose.

## Valeurs principales

Voir `values.yaml` pour la liste complète. Les plus utiles :

| Valeur | Rôle |
|---|---|
| `tsa.image.repository` / `tsa.image.tag` | Image du service d'horodatage |
| `tsa.time.policy` | `enforce`, `monitor` ou `disabled` — passer à `monitor` si le cluster n'a pas de sortie UDP/123 |
| `tsa.gateway.enabled` / `tsa.gateway.name` / `tsa.gateway.namespace` / `tsa.gateway.host` | Exposition HTTP(S) du service via une `HTTPRoute` Gateway API |
| `tsa.pin` / `ocsp.pin` / `auditReplica.password` | Valeurs explicites plutôt que générées aléatoirement |
| `ca.publicURL` / `ca.gateway.enabled` / `ca.gateway.host` | Adresse publique gravée dans les points CRL et AIA des certificats émis — à fixer si les certificats seront vérifiés par des tiers hors du cluster |
| `production` | Déploiement de qualification ou de production : refuse le rendu si un raccourci de démonstration reste actif (`ca.autoApprove.enabled`) |
| `ca.autoApprove.enabled` / `ca.autoApprove.operator` | Approbation RA automatique, désactivée par défaut (voir ci-dessus) |
| `ca.keyBits`, `ca.rootCommonName`, `ca.issuingCommonName` | Paramètres de la cérémonie de clé — sans effet une fois la hiérarchie créée |
| `ca.crl.validity` / `ca.crl.refresh` | Fenêtre de validité des CRL et fréquence de republication |
| `ca.audit.retention` | Durée de conservation du journal (ETSI EN 319 401 §7.10) ; le service refuse de démarrer en deçà d'un an |
| `ocsp.publicURL` / `ocsp.gateway.enabled` / `ocsp.gateway.host` | Adresse publique gravée dans l'extension AIA du certificat TSU, et son exposition HTTP(S) |
| `raConsole.enabled`, `raConsole.gateway.*`, `raConsole.networkPolicy.enabled` | Console d'exploitation (voir ci-dessus), désactivée par défaut |
| `secrets.existingSecret` | Secret existant (ex. scellé via kubeseal) à utiliser à la place de celui généré par le motif `lookup` |
| `postgres.external.enabled` / `postgres.external.host` / `postgres.external.port` | PostgreSQL externe (ex. CloudNativePG) à la place du StatefulSet intégré |
| `postgres.persistence.size`, `tsa.persistence.*.size`, `ocsp.persistence.*.size`, `auditReplica.persistence.size` | Tailles des volumes persistants |

## Développement local (kind)

```bash
docker build -f deploy/ca-server/Dockerfile -t openeidas-ca:dev .
docker build -f deploy/tsa/Dockerfile -t openeidas-tsa:dev .
docker build -f deploy/ocsp-responder/Dockerfile -t openeidas-ocsp-responder:dev .
kind create cluster --name open-eidas
for image in openeidas-ca openeidas-tsa openeidas-ocsp-responder; do
    kind load docker-image "$image:dev" --name open-eidas
done
helm install open-eidas deploy/helm/open-eidas -n open-eidas --create-namespace \
    --set ca.image.repository=openeidas-ca --set ca.image.tag=dev \
    --set ca.autoApprove.enabled=true \
    --set tsa.image.repository=openeidas-tsa --set tsa.image.tag=dev \
    --set ocsp.image.repository=openeidas-ocsp-responder --set ocsp.image.tag=dev
```
