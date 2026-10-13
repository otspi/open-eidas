# Déploiement de staging public

Guide pas-à-pas pour mettre en ligne la démonstration Open eIDAS sur
`api.staging.open-eidas.eu` (TSA) et `pki.staging.open-eidas.eu` (PKI —
interface, CRL, AIA), à partir d'un cluster Kubernetes managé vierge.

Ce guide part du principe que le cluster est déjà créé et que `kubectl` y
est configuré (`kubectl cluster-info` répond) — la création du cluster
lui-même (console web de l'hébergeur, facturation, choix de région) est
spécifique à chaque fournisseur et reste à faire séparément. Tout ce qui
suit est générique à n'importe quel Kubernetes managé (Scaleway Kapsule,
OVHcloud Managed Kubernetes, DigitalOcean, etc.) ou à un `k3s` sur VM.

**Dimensionnement recommandé pour cet usage (démonstration, pas de charge
réelle)** : un unique nœud, 2 vCPU / 4 Go de RAM suffisent largement (la
pile complète — PostgreSQL, autorité de certification, TSA, répondeur OCSP,
réplica d'audit — représente au
total moins de 2 Go de limites mémoire cumulées, voir `values.yaml`).

L'exposition externe se fait via la [Gateway API](https://gateway-api.sigs.k8s.io/)
(`HTTPRoute`), pas via un Ingress classique ; les secrets sensibles et le
PostgreSQL de staging sont gérés en dehors du chart, dans le dépôt
app-of-apps [otspi/deploy](https://github.com/otspi/deploy).

## 0. Outils requis en local

- `kubectl` configuré sur le cluster cible (`kubectl config current-context`
  doit pointer dessus)
- `helm` (v3)
- `kubeseal` (CLI de [sealed-secrets](https://github.com/bitnami-labs/sealed-secrets)),
  pour sceller le Secret de l'étape 4
- Optionnel : `argocd` CLI, si vous préférez piloter le déploiement via
  ArgoCD plutôt qu'en `helm install` direct

## 1. Installer les CRD et contrôleurs requis

Trois briques tournent en dehors du chart open-eidas et sont prérequises :

1. **Gateway API** (CRD) + un contrôleur qui les implémente (ex. Cilium en
   mode Gateway API, ou tout contrôleur listé par le projet upstream).
2. **[sealed-secrets](https://github.com/bitnami-labs/sealed-secrets)**, pour
   déchiffrer côté cluster les Secret scellés committés dans
   `otspi/deploy` :
   ```bash
   helm install sealed-secrets sealed-secrets \
       --repo https://bitnami-labs.github.io/sealed-secrets \
       --namespace sealed-secrets --create-namespace
   ```
3. **[CloudNativePG](https://cloudnative-pg.io/)**, pour le PostgreSQL de
   staging (un Cluster CR géré par `otspi/deploy`, pas le StatefulSet
   intégré au chart) :
   ```bash
   kubectl apply --server-side -f \
       https://raw.githubusercontent.com/cloudnative-pg/cloudnative-pg/release-1.29/releases/cnpg-1.29.1.yaml
   ```

Puis une `Gateway` (nommée par exemple `shared-gateway`, dans un namespace
`ingress`) avec un listener HTTPS par hôte de staging
(`api`/`pki`/`ocsp.staging.open-eidas.eu`), chacun avec son
`Certificate` cert-manager — voir
[cert-manager](https://cert-manager.io/docs/installation/) et son intégration
[Gateway API (gateway-shim)](https://cert-manager.io/docs/usage/gateway/).
Cette Gateway est une ressource partagée, généralement gérée dans un dépôt
d'infrastructure distinct plutôt que dans celui-ci.

## 2. Configurer le DNS

Créer trois enregistrements DNS (A ou CNAME selon ce qu'expose la Gateway)
pointant vers son adresse publique :

| Nom | Cible |
|---|---|
| `api.staging.open-eidas.eu` | adresse publique de la Gateway |
| `pki.staging.open-eidas.eu` | adresse publique de la Gateway |
| `ocsp.staging.open-eidas.eu` | adresse publique de la Gateway |

Vérifier la propagation avant de continuer :

```bash
dig +short api.staging.open-eidas.eu
dig +short pki.staging.open-eidas.eu
dig +short ocsp.staging.open-eidas.eu
```

## 3. Créer le namespace et générer les secrets

```bash
kubectl create namespace open-eidas-staging
```

Générer les valeurs sensibles (mot de passe PostgreSQL, PIN des tokens
PKCS#11, secret HMAC d'enrôlement) — elles ne sont produites qu'une fois ici,
puis scellées et committées, à la différence du motif `lookup` du chart
(utilisé par défaut hors staging) :

```bash
kubectl create secret generic open-eidas-generated \
    --namespace open-eidas-staging --dry-run=client -o yaml \
    --from-literal=postgres-password="$(openssl rand -base64 24)" \
    --from-literal=username=openeidas \
    --from-literal=password="$(openssl rand -base64 24)" \
    --from-literal=tsa-pin="$(shuf -i 10000000-99999999 -n1)" \
    --from-literal=ocsp-pin="$(shuf -i 10000000-99999999 -n1)" \
    --from-literal=ca-root-pin="$(shuf -i 10000000-99999999 -n1)" \
    --from-literal=ca-issuing-pin="$(shuf -i 10000000-99999999 -n1)" \
    --from-literal=enroll-hmac-key="$(openssl rand -base64 36)" \
    > /tmp/open-eidas-generated.yaml
```

(`password` doit reprendre la même valeur que `postgres-password` : c'est le
Secret que CloudNativePG utilise pour amorcer l'utilisateur applicatif.)

## 4. Sceller le secret et provisionner PostgreSQL

Sceller le Secret généré à l'étape précédente avec `kubeseal`, en ciblant le
contrôleur sealed-secrets du cluster :

```bash
kubeseal --controller-namespace sealed-secrets \
    -f /tmp/open-eidas-generated.yaml -w sealed-secret.yaml
shred -u /tmp/open-eidas-generated.yaml
```

Committer `sealed-secret.yaml` dans `otspi/deploy` (voir son README),
avec le Cluster CloudNativePG qui le consomme via
`bootstrap.initdb.secret.name`. Une fois ces manifestes fusionnés et
synchronisés (ArgoCD ou `kubectl apply` direct), vérifier que le Secret a
bien été déchiffré et que le Cluster est prêt :

```bash
kubectl -n open-eidas-staging get secret open-eidas-generated
kubectl -n open-eidas-staging get cluster.postgresql.cnpg.io -w
```

## 5. Déployer Open eIDAS

Deux options équivalentes :

**Option A — `helm install` direct :**

```bash
helm install open-eidas deploy/helm/open-eidas \
    --namespace open-eidas-staging \
    -f deploy/helm/open-eidas/values-staging.yaml
```

**Option B — ArgoCD** (si déjà installé sur le cluster) :

Appliquer une fois `root-app.yaml` du dépôt
[otspi/deploy](https://github.com/otspi/deploy) (motif
app-of-apps) :

```bash
kubectl apply -f root-app.yaml
```

ArgoCD crée alors les Applications `open-eidas-staging-postgres` (Secret
scellé + Cluster CloudNativePG) et `open-eidas-staging` (ce chart), et
synchronise ensuite automatiquement tout changement fusionné sur `main`.

## 6. Suivre l'amorçage

Compter 1 à 3 minutes pour l'amorçage complet — cérémonie de clé, première
CRL, puis enrôlement et approbation de la TSU et du répondeur OCSP (voir
`docs/CA.md`) :

```bash
kubectl -n open-eidas-staging get pods -w
kubectl -n open-eidas-staging logs deploy/open-eidas-ca -c ca -f
```

Vérifier que les `HTTPRoute` sont bien acceptées par la Gateway :

```bash
kubectl -n open-eidas-staging get httproute -o wide
```

## 7. Vérifier le déploiement

```bash
echo "test staging $(date -Is)" > facture.txt
openssl ts -query -data facture.txt -sha256 -cert -out facture.tsq
curl -sf -H 'Content-Type: application/timestamp-query' \
    --data-binary @facture.tsq https://api.staging.open-eidas.eu/tsa \
    -o facture.tsr
curl -sf https://api.staging.open-eidas.eu/api/v1/certificate -o chain.pem
awk '/BEGIN CERTIFICATE/{n++} {print > (n == 1 ? "tsu.pem" : "ca.pem")}' chain.pem
openssl ts -verify -in facture.tsr -queryfile facture.tsq -CAfile ca.pem

# Vérifie que la CRL publiée est effectivement récupérable publiquement :
curl -sf https://pki.staging.open-eidas.eu/download/*.crl -o staging.crl \
    2>/dev/null || echo "adapter le nom de fichier — voir l'AIA du certificat TSU"
openssl x509 -in tsu.pem -noout -text | grep -A3 "CRL Distribution"

# Vérifie que le répondeur OCSP répond publiquement pour ce certificat :
openssl ocsp -issuer ca.pem -cert tsu.pem -CAfile ca.pem -no_nonce \
    -url https://ocsp.staging.open-eidas.eu/ocsp -resp_text
```

## Dépannage

- **Une `HTTPRoute` n'apparaît jamais `Accepted`** : vérifier que le nom et
  le namespace de la Gateway référencés (`tsa.gateway.name`/`.namespace`
  dans `values-staging.yaml`) sont corrects, et que son listener HTTPS
  couvre bien l'hôte demandé (`kubectl -n ingress describe gateway
  shared-gateway`).
- **`kubectl wait` ou `helm install` semblent bloqués sur le Pod `ca`** :
  la cérémonie génère deux bi-clés RSA-4096 dans SoftHSM, ce qui prend
  jusqu'à quelques minutes sur un nœud modeste. Suivre
  `kubectl logs deploy/open-eidas-ca -c ca -f`.
- **Les Pods ne démarrent pas, erreur de connexion PostgreSQL** : vérifier
  que le Cluster CloudNativePG de `open-eidas-staging-postgres` est bien
  `Ready` et que son Service `-rw` correspond à `postgres.external.host`
  dans `values-staging.yaml`.
- **La TSA ou le répondeur OCSP restent en attente de certificat** : leur
  demande attend une décision de l'autorité d'enregistrement. Vérifier que le
  conteneur d'approbation automatique tourne
  (`kubectl logs deploy/open-eidas-ca -c ra-autoapprove`), ou approuver à la
  main si `ca.autoApprove.enabled` est à `false` :
  `kubectl exec deploy/open-eidas-ca -c ca -- ca-server ra list PENDING`.
- **La TSA refuse de signer (`heure non traçable`)** : le cluster n'a pas
  de sortie UDP/123 vers les serveurs NTP configurés
  (`tsa.time.policy` / `tsa.time.sources`, voir `values.yaml`) — vérifier
  que le security group du cluster autorise le trafic UDP sortant, ou à
  défaut passer `tsa.time.policy=monitor` dans `values-staging.yaml` (perte
  de la traçabilité temporelle ETSI EN 319 421, à documenter comme écart
  dans `docs/ARCHITECTURE.md` si conservé au-delà d'un test ponctuel).
