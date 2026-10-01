<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/logo/logo-horizontal-dark.svg">
    <img alt="Open eIDAS" src="docs/logo/logo-horizontal.svg" width="420">
  </picture>
</p>

# Open eIDAS — Les services de confiance eIDAS comme infrastructure ouverte

[![CI](https://github.com/otspi/open-eidas/actions/workflows/ci.yml/badge.svg)](https://github.com/otspi/open-eidas/actions/workflows/ci.yml)
[![Licence EUPL-1.2 OU AGPL-3.0](https://img.shields.io/badge/licence-EUPL--1.2%20%7C%20AGPL--3.0-blue.svg)](#licence)
[![Site Web](https://img.shields.io/badge/Site%20Web-open--eidas.eu-003399?style=flat-square)](https://open-eidas.eu)
[![Contact](https://img.shields.io/badge/Contact-contact%40open--eidas.eu-0F2042?style=flat-square)](mailto:contact@open-eidas.eu)

**Démocratiser la confiance numérique eIDAS dans toute l'économie, de façon sûre, ouverte et sans rente.**

Le règlement européen eIDAS a posé le cadre juridique de la confiance numérique : horodatage qualifié, signature et cachet électroniques, archivage à valeur probante, envoi recommandé et portefeuilles d'identité numérique (eIDAS 2.0 / EUDI).

Pourtant, dans la pratique économique, ces briques indispensables restent captives d'un modèle de rente oligopolistique :
- **Facturation au jeton ou à l'acte**, transformant des obligations légales (facturation électronique obligatoire B2B, archivage légal, contractualisation dématérialisée) en péage privé récurrent ;
- **Friction technique et contractuelle majeure** : portails fermés, SDK propriétaires, délais d'intégration qui se comptent en semaines ;
- **Fracture pour l'économie réelle** : là où de grands groupes négocient des volumes, les TPE/PME, éditeurs indépendants et administrations de proximité sont freinés ou contraints de bricoler sans garanties de conformité.

Le même verrou existait pour le chiffrement web avant Let's Encrypt.

**Open eIDAS applique le modèle de l'ISRG à l'écosystème eIDAS** : une gouvernance d'intérêt général à but non lucratif, une infrastructure cryptographique souveraine et auditable, des API ouvertes et standardisées, et un coût d'accès nul ou à prix coûtant. Notre mission est de démocratiser eIDAS dans l'économie de manière rigoureuse et pérenne — sans compromis sur la sécurité.

---

## Notre premier service : l'horodatage qualifié (RFC 3161)

Pour bâtir un édifice de confiance, il faut d'abord maîtriser le temps. L'**horodatage qualifié** est le premier service développé par Open eIDAS : il constitue le socle d'antériorité et d'intégrité temporelle universel, nécessaire à la signature électronique (validité à long terme LTA), au cachet d'entreprise, à la facturation électronique et à l'archivage à valeur probante.

Là où le marché impose des barrières contractuelles, l'intégration Open eIDAS est immédiate :

```bash
DIGEST=$(sha256sum facture.pdf | cut -d' ' -f1)

curl -s -X POST http://localhost:8318/api/v1/timestamp \
     -H 'Content-Type: application/json' \
     -d "{\"hash\":\"$DIGEST\"}"
```

Voilà l'intégration complète. Pas de compte, pas de SDK propriétaire, pas de bon de commande.

La feuille de route d'Open eIDAS étendra progressivement ce socle aux autres services de confiance essentiels : **cachet électronique de personne morale (seal)** automatisable, **validation de signatures qualifiées**, et passerelles d'attestation conformes à eIDAS 2.

---

## Ce que fait ce dépôt

Ce dépôt héberge le prototype **fonctionnel et vérifiable** du premier service Open eIDAS — l'autorité d'horodatage (TSA) :

- un service d'horodatage **RFC 3161** écrit en Rust (mémoire sûre par
  construction — `unsafe_code` interdit dans tout le workspace sauf le
  module d'accès au HSM), dont la clé de signature ne quitte jamais un
  module cryptographique (**PKCS#11**) ;
- une **autorité de certification écrite en propre** — racine, CA émettrice,
  profils compilés et testés, approbation RA effective, publication de la CRL
  et réponses OCSP — qui délivre le certificat de l'unité d'horodatage par
  enrôlement automatisé ;
- une **matrice de conformité ETSI** générée depuis le code
  ([docs/CONFORMITE-ETSI.md](docs/CONFORMITE-ETSI.md)), qui cite la version
  de chaque norme et ses identifiants d'exigence : une exigence n'y est
  « couverte » que si un binaire en service l'applique (test du binaire ou
  job de démonstration réelle), sinon elle est déclarée « implémentée, pas en
  service » ou « écart » avec sa cible — la CI échoue si une ligne perd sa
  preuve ou cite un test introuvable ou ignoré ;
- un **HSM logiciel SoftHSM2** parlant le protocole d'un HSM certifié, pour que
  le passage en production soit un changement de configuration, pas de code ;
- une **heure traçable jusqu'à UTC** : le service recoupe deux serveurs de
  laboratoires de métrologie (Observatoire de Paris, PTB) et **cesse d'émettre**
  dès que la dérive dépasse le seuil annoncé, comme l'exige ETSI EN 319 421 ;
- un **journal d'audit chaîné par hachage**, écrit *avant* chaque signature :
  si le journal ne peut pas être écrit, aucun jeton ne sort. Le scellement de
  la tête de chaîne par des TSA tierces publiques et la réplication hors site
  existent en bibliothèques (`oe-crosstsa`, `oe-replicate`) mais **ne sont pas
  encore câblés dans les services** — écart déclaré dans
  [docs/CONFORMITE-ETSI.md](docs/CONFORMITE-ETSI.md) ;
- le tout orchestré en `docker compose`, démarrable en une commande.

Ce n'est pas encore une TSA qualifiée : les écarts avec le référentiel eIDAS
sont listés explicitement dans
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md#8-écarts-assumés-du-prototype-vis-à-vis-dune-tsa-qualifiée)
et, exigence par exigence, dans
[docs/CONFORMITE-ETSI.md](docs/CONFORMITE-ETSI.md) — HSM certifié, cérémonie
de clé sous double contrôle, opérateur RA nominatif, redondance, audit d'un
organisme accrédité. Le chiffrage de ce chemin est connu : **70 à 95 k€** pour
l'infrastructure et l'audit initial.

## Démarrage

Prérequis : Docker avec le plugin Compose, `git`, `openssl`, `curl`.

```bash
git clone https://github.com/otspi/open-eidas.git
cd open-eidas

make up      # amorce la CA, émet les certificats TSU et OCSP, démarre la pile
make demo    # horodate un fichier et vérifie le jeton avec openssl ts
```

`make up` est idempotent et prend quelques minutes au premier lancement :
l'essentiel du temps est la génération des bi-clés dans les tokens SoftHSM
(racine et CA émettrice en RSA-4096, TSU et répondeur OCSP en RSA-3072). La
cérémonie de clé est rejouée à chaque démarrage sans jamais recréer de
hiérarchie existante.

Chaque demande de certificat attend l'approbation d'un opérateur
d'enregistrement : `make up` l'accorde automatiquement sous un compte
technique pour que la démonstration s'amorce seule — écart assumé, tracé comme
tel au journal d'audit (voir [docs/CA.md](docs/CA.md)).

### Vérifier un jeton avec les outils standards

```bash
openssl ts -query -data facture.pdf -sha256 -cert -out facture.tsq

curl -s -H 'Content-Type: application/timestamp-query' \
     --data-binary @facture.tsq http://localhost:8318/tsa -o facture.tsr

curl -s http://localhost:8318/api/v1/certificate -o tsa-chain.pem
awk '/BEGIN CERTIFICATE/{n++} {print > (n == 1 ? "tsu.pem" : "ca.pem")}' tsa-chain.pem

openssl ts -verify -in facture.tsr -queryfile facture.tsq -CAfile ca.pem
```

### Relire le journal d'audit

```bash
docker compose exec tsa tsa-server verify-audit
```

Autres cibles : `make test`, `make lint`, `make audit`, `make logs`,
`make down`, `make purge`.

### Déployer sur Kubernetes

La même pile est packagée en chart Helm, pour un déploiement piloté par
ArgoCD ou un `helm install` direct :

```bash
helm install open-eidas deploy/helm/open-eidas --namespace open-eidas --create-namespace \
    --set ca.autoApprove.enabled=true   # démonstration : approbation RA automatique
```

Voir [deploy/helm/open-eidas/README.md](deploy/helm/open-eidas/README.md) et
le dépôt app-of-apps [otspi/deploy](https://github.com/otspi/deploy).

## Documentation

- [Architecture technique](docs/ARCHITECTURE.md) — choix de conception,
  séquence de démarrage, écarts au référentiel, trajectoire de qualification.
- [Référence de l'API](docs/API.md) — endpoints, codes d'erreur RFC 3161,
  variables de configuration.
- [Chart Helm](deploy/helm/open-eidas/README.md) — déploiement Kubernetes /
  ArgoCD.

## Structure du dépôt

```
bin/tsa-server/        point d'entrée de la TSA : enroll, serve, verify-audit
bin/ca-server/         autorité de certification : ceremony, serve, ra, revoke
bin/ocsp-responder/    répondeur OCSP (RFC 6960)
crates/oe-tsa-core/    cœur RFC 3161 : validation, TSTInfo, CMS SignedData
crates/oe-conformance/ exigences ETSI sous forme exécutable, et la matrice
crates/oe-ca-core/     moteur d'émission : profils, cérémonie, CRL
crates/oe-raflow/      machine à états d'enrôlement et d'approbation RA
crates/oe-castore/     registre de la CA (PostgreSQL, et mémoire pour les tests)
crates/oe-hsm/         accès PKCS#11 aux clés de signature (seule crate autorisant `unsafe`)
crates/oe-timesource/  surveillance de la traçabilité de l'heure
crates/oe-audit/       journal d'audit chaîné par hachage
crates/oe-crosstsa/    contreseing du journal par des TSA tierces publiques (pas encore câblé)
crates/oe-enroll/      client d'enrôlement auprès de la CA
crates/oe-httpapi/     endpoints HTTP (RFC 3161 + façade JSON)
deploy/                images des trois services, chart Helm
scripts/               amorçage et démonstration
```

## Modèle & Sûreté

- **Gouvernance non lucrative d'intérêt général** : association financée par le mécénat et le soutien d'acteurs de la souveraineté numérique. Service gratuit ou à prix coûtant, sans quota commercial ni rente monopolistique. La frugalité se vérifie : la pile complète tient dans ~200 Mio de RAM demandée, mesuré service par service dans [docs/SIZING.md](docs/SIZING.md).
- **Sûreté intransigeante** : aucun compromis sur la sécurité. L'architecture est conçue pour satisfaire rigoureusement les normes ETSI (EN 319 421, EN 319 422, etc.) et les exigences de qualification eIDAS / ANSSI.
- **Transparence intégrale** : code source libre, politiques de service publiques, traçabilité métrologique documentée et rapports d'audit tiers publiés.

## Contribuer

Les contributions sont bienvenues, en particulier sur l'intégration de HSM
certifiés, le journal d'audit inaltérable, la redondance du service, la
conformité ETSI EN 319 421 / 319 422 et le développement des futurs services de confiance.

## Contact & Liens
 
- **Site web officiel :** [https://open-eidas.eu](https://open-eidas.eu)
- **Contact :** [contact@open-eidas.eu](mailto:contact@open-eidas.eu)
- **Organisation GitHub :** [github.com/otspi](https://github.com/otspi)
- **Code source du site web :** [otspi/website](https://github.com/otspi/website)

## Licence

Open eIDAS est distribué sous **double licence**, au choix de celui qui le réutilise (identifiant SPDX `EUPL-1.2 OR AGPL-3.0-only`) :

- la licence publique de l'Union européenne **EUPL v1.2** — voir [LICENSE](LICENSE) ;
- la **GNU Affero General Public License v3** (version 3 uniquement) — voir [LICENSE-AGPL-3.0](LICENSE-AGPL-3.0).

Les deux sont des licences à réciprocité (*copyleft*) : toute version modifiée et distribuée, y compris lorsqu'elle est mise à disposition en tant que service en réseau, doit rester publiée sous la licence choisie. La branche AGPL permet d'intégrer directement Open eIDAS dans un projet sous AGPL ou GPL v3, sans passer par l'annexe de compatibilité de l'EUPL.

Les versions publiées avant le passage à l'EUPL restaient déjà disponibles sous AGPL v3.
