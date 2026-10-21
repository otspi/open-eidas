# R-3 — Identité mTLS des demandeurs d'enrôlement (note de conception)

Statut : **décisions prises le 2026-10-21 (§7) ; tranches 1 à 4 en PR (#152 à #155).** Elle
prolonge le constat R-3 de l'[audit du 2026-09-25](AUDIT_2026_09_25.md) :
« un secret, ou mieux une identité (mTLS), par demandeur ».

## 1. Où l'on en est

Livré : un secret HMAC **par demandeur**, lié à ses profils et à son CN
(`OPENEIDAS_ENROLL_REQUESTERS_FILE`, [CA.md](CA.md)) ; le renouvellement ne
révoque que les certificats du même demandeur ; en production, la CA exige ce
fichier et n'accepte plus le secret historique ; l'approbation d'un certificat de
TSU exige deux opérateurs.

Ce qui reste faible : le secret HMAC est **partagé** entre le service qui le
détient et la CA, et circule dans les Secrets Kubernetes. Qui le lit se fait passer
pour le demandeur. Une identité de transport (certificat client) se prouve sans
être divulguée à la CA.

## 2. Principe

La CA ouvre un **port d'enrôlement en TLS mutuel**. Le demandeur y présente un
certificat client émis par cette PKI ; la CA le rattache à un demandeur déclaré
dans le même fichier (`client_cn` au lieu de `secret`), puis applique les mêmes
règles qu'aujourd'hui (profils autorisés, CN imposé, révocation limitée au
demandeur). Le HMAC sur la CSR est conservé en second contrôle pendant la
transition, puis retiré en production.

```
tsa-server ──mTLS (cert client « tsa »)──► ca-server :8322 /api/v1/enroll
                                           └─ demandeur = CN du certificat client
                                           └─ profils/CN autorisés (fichier)
```

Le vérificateur existe déjà : `bin/ca-server/src/internal_tls.rs` (lien interne
ra-console ↔ ca-server, `WebPkiClientVerifier`). Le nouveau port le réutilise avec
une autre ancre de confiance et un autre profil.

## 3. Amorçage (le point délicat)

Le premier certificat client d'un demandeur ne peut pas s'obtenir par mTLS.
Proposition, calquée sur `internal-cert` (CA.md) :

1. L'opérateur déclare le demandeur et émet **un secret d'amorçage à usage unique**
   (HMAC, profil `enroll_client` seulement, expire en 24 h).
2. Le demandeur soumet une CSR `enroll_client` avec ce secret ; l'approbation
   exige **deux opérateurs** (même règle que le certificat de TSU).
3. Il reçoit son certificat client ; le secret d'amorçage est brûlé. Ensuite il
   s'enrôle et se renouvelle **par mTLS seul**, y compris pour renouveler son
   propre certificat client avant l'expiration.

Profil `enroll_client` : EKU `clientAuth` seul, CN imposé par demandeur, validité
de 90 jours (clé logicielle : même catégorie que le lien interne), non utilisable comme `internal_client` (le lien interne de ra-console
reste distinct).

## 4. Découpage en tranches (une PR chacune)

1. **CA** : profil `enroll_client`, port d'enrôlement mTLS, rattachement du
   certificat client au demandeur (`client_cn`), tests (certificat inconnu,
   expiré, révoqué, mauvais CN, bon CN) vérifiés par mutation.
2. **Client** : `oe_enroll::Client` présente un certificat client (fichiers
   certificat + clé), refuse de partir sans.
3. **Services** : `tsa-server`/`ocsp-responder` (amorçage, renouvellement,
   rechargement), chart Helm (volume, NetworkPolicy du nouveau port).
4. **Production** : le HMAC n'authentifie plus ; seul le secret d'amorçage subsiste.

## 5. Ce que cela ne résout pas

- La clé du certificat client est une clé **de service** : si elle est logicielle,
  qui lit le volume la vole (comme la clé du lien interne, WEBUI.md §16). Un HSM
  pour cette clé est une option (décision §6.a), plus lourde.
- Un `ca-server` compromis reste maître de ses propres règles : le mTLS protège la
  CA **contre un faux demandeur**, pas contre elle-même.

## 6. Décisions à prendre

a. **Clé du certificat client** : logicielle sur volume dédié (comme le lien
   interne) ou dans le HSM du service ?
b. **Ancre de confiance du port d'enrôlement** : l'autorité émettrice (simple) ou
   une autorité dédiée aux certificats clients (cloisonnement, un token de plus) ?
c. **Amorçage** : secret à usage unique + deux opérateurs (§3), ou autre voie ?
d. **Retrait du HMAC** : dès la tranche 4 en production, ou après une période de
   double authentification ?

## 7. Décisions prises (Philippe, 2026-10-21)

a. Clé du certificat client : **logicielle sur volume dédié** (comme le lien interne).
b. Ancre de confiance : **l'autorité émettrice existante**, profil `enroll_client` dédié.
c. Amorçage : **secret à usage unique (24 h) + approbation par deux opérateurs**.
d. HMAC : retiré en production **après une période de double authentification**
   (les deux contrôles coexistent le temps de la bascule).

## 8. Tranche 4 (en PR #155)

En production, un demandeur qui a un `client_cn` n'utilise plus son secret que pour le profil `enroll_client` (`Flow::with_hmac_bootstrap_only`). Les autres demandeurs gardent leur secret jusqu'à ce qu'on leur ajoute un `client_cn` : la bascule se fait demandeur par demandeur, ce qui est la « période de double authentification » décidée en §7.d.
