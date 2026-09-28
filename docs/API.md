# API du service d'horodatage

Base par défaut : `http://localhost:8318`

Deux chemins d'accès coexistent : l'endpoint **RFC 3161** natif, qui est le
seul à faire foi et que consomment les outils standards, et une **façade
JSON** de confort destinée à l'intégration rapide et à la démonstration.

---

## `POST /tsa` — horodatage RFC 3161

Endpoint normatif. Le corps est une `TimeStampReq` encodée en DER.

| | |
|---|---|
| `Content-Type` attendu | `application/timestamp-query` (ou `application/octet-stream`) |
| `Content-Transfer-Encoding` | `base64` accepté en option |
| Réponse | `application/timestamp-reply`, `TimeStampResp` DER |
| Taille maximale | 64 Kio (`OPENEIDAS_MAX_REQUEST_BYTES`) |

```bash
openssl ts -query -data facture.pdf -sha256 -cert -out facture.tsq

curl -s -H 'Content-Type: application/timestamp-query' \
     --data-binary @facture.tsq \
     http://localhost:8318/tsa -o facture.tsr

openssl ts -reply -in facture.tsr -text
```

Un refus protocolaire reste une réponse RFC 3161 valide, renvoyée avec un
statut HTTP 200 et un `PKIStatusInfo` de type `rejection` :

| Cas | `failureInfo` |
|---|---|
| Requête ASN.1 illisible, longueur d'empreinte incohérente | `badDataFormat` |
| Heure non traçable jusqu'à UTC | `timeNotAvailable` |
| Algorithme d'empreinte refusé (SHA-1 notamment) | `badAlg` |
| Politique demandée non servie par cette TSA | `unacceptedPolicy` |
| Extension critique inconnue | `unacceptedExtension` |
| Défaillance interne (HTTP 500) | `systemFailure` |

---

## `POST /api/v1/timestamp` — façade JSON

Le service construit lui-même la requête ASN.1 à partir de l'empreinte
fournie : aucune dépendance ASN.1 côté client.

Requête :

```json
{
  "hash": "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae",
  "algorithm": "sha256",
  "cert_req": true,
  "nonce": true
}
```

| Champ | Type | Défaut | Description |
|---|---|---|---|
| `hash` | string | — | Empreinte du document, en hexadécimal ou base64 |
| `algorithm` | string | `sha256` | `sha256`, `sha384` ou `sha512` |
| `cert_req` | bool | `true` | Inclure le certificat de la TSU dans le jeton |
| `nonce` | bool | `false` | Ajouter un nonce aléatoire de 64 bits |

Réponse :

```json
{
  "granted": true,
  "token": "MIIQ...",
  "gen_time": "2026-09-06T14:32:07Z",
  "serial_number": "5310430...",
  "policy": "1.3.6.1.4.1.99999.1.1.1",
  "accuracy": "1s",
  "hash_algorithm": "sha256"
}
```

`token` est la `TimeStampResp` DER complète, encodée en base64 : elle se
décode et se vérifie avec les outils standards.

```bash
DIGEST=$(sha256sum facture.pdf | cut -d' ' -f1)

curl -s -X POST http://localhost:8318/api/v1/timestamp \
     -H 'Content-Type: application/json' \
     -d "{\"hash\":\"$DIGEST\"}" \
  | jq -r .token | base64 -d > facture.tsr
```

En cas de refus, la réponse est un JSON `{"error": "..."}` avec un statut
HTTP 400 (requête invalide) ou 500 (défaillance interne).

---

## `GET /api/v1/policy` — paramètres publiés

```json
{
  "policy_oid": "1.3.6.1.4.1.99999.1.1.1",
  "accuracy": "1s",
  "accepted_hashes": ["sha256", "sha384", "sha512"],
  "tsu_subject": "CN=Open eIDAS Time-Stamping Unit 1,OU=Time Stamping Authority,O=Open eIDAS,C=FR",
  "tsu_issuer": "CN=Open eIDAS Issuing CA,O=Open eIDAS,C=FR",
  "tsu_not_after": "2027-09-06T12:00:00Z",
  "tsu_serial": "...",
  "rfc3161_endpoint": "/tsa",
  "version": "dev"
}
```

## `GET /api/v1/certificate` — chaîne de confiance

Retourne, en `application/x-pem-file`, le certificat de la TSU suivi de sa
chaîne d'émission. C'est le fichier à passer à `openssl ts -verify`.

## `GET /healthz` — supervision

`200` tant que le certificat de la TSU est valide et que l'heure reste
traçable ; `503` si le certificat a expiré ou si la traçabilité de l'heure est
perdue sous politique `enforce`.

```json
{
  "status": "ok",
  "time_source": {
    "policy": "enforce",
    "traceable": true,
    "offset": "7.633304ms",
    "spread": "8.3047ms",
    "last_sync": "2026-09-06T13:30:20Z",
    "sources": [
      {"server": "ntp.obspm.fr", "offset": "671.396µs", "rtt": "15.649242ms", "stratum": 2, "at": "..."},
      {"server": "ptbtime1.ptb.de", "offset": "-7.633304ms", "rtt": "29.35773ms", "stratum": 1, "at": "..."}
    ]
  },
  "version": "dev"
}
```

Lorsque l'heure n'est plus traçable, toute demande d'horodatage est refusée
avec le `failureInfo` `timeNotAvailable` — voir
[la section traçabilité de l'heure](ARCHITECTURE.md#6-traçabilité-de-lheure).

---

## Vérification d'un jeton

```bash
curl -s http://localhost:8318/api/v1/certificate -o tsa-chain.pem

# Le premier bloc PEM est le certificat de la TSU, les suivants sa chaîne.
awk '/BEGIN CERTIFICATE/{n++} {print > (n == 1 ? "tsu.pem" : "ca.pem")}' tsa-chain.pem

openssl ts -verify -in facture.tsr -queryfile facture.tsq -CAfile ca.pem
```

La vérification atteste que l'empreinte soumise existait avant la date
`genTime`, et que le jeton a été signé par la clé de la TSU.

---

## Vérification du journal d'audit

Le journal est relisible indépendamment du service :

```bash
tsa-server verify-audit /var/lib/open-eidas/audit.log
```

La commande recalcule toute la chaîne de hachage et échoue en nommant
l'enregistrement fautif si une ligne a été modifiée, supprimée ou intercalée.
Voir [la section journal d'audit](ARCHITECTURE.md#7-journal-daudit-inaltérable).

---

## Configuration du service

Toutes les options sont pilotées par variables d'environnement.

| Variable | Défaut | Rôle |
|---|---|---|
| `OPENEIDAS_LISTEN` | `:8318` | Adresse d'écoute HTTP |
| `OPENEIDAS_PKCS11_MODULE` | `/usr/lib/softhsm/libsofthsm2.so` | Module PKCS#11 du HSM |
| `OPENEIDAS_TOKEN_LABEL` | `open-eidas-tsa` | Label du token |
| `OPENEIDAS_KEY_LABEL` | `tsu-signing-key` | Label de la bi-clé de signature |
| `OPENEIDAS_PIN` | — (obligatoire) | Code PIN du token, 4 à 255 caractères (contrainte SoftHSM) |
| `OPENEIDAS_KEY_BITS` | `3072` | Taille de clé RSA, minimum 3072 |
| `OPENEIDAS_CERT_FILE` | `/var/lib/open-eidas/tsu.pem` | Certificat de la TSU |
| `OPENEIDAS_CHAIN_FILE` | `/var/lib/open-eidas/chain.pem` | Chaîne d'émission |
| `OPENEIDAS_POLICY_OID` | `1.3.6.1.4.1.99999.1.1.1` | OID de la politique d'horodatage |
| `OPENEIDAS_PRODUCTION` | `false` | Mode production : le service refuse de démarrer si l'OID de politique appartient à un arc de test (ancien numéro `99999`, ou sous-arc `9` d'un numéro d'entreprise) |
| `OPENEIDAS_ACCURACY` | `1s` | Précision annoncée dans le `TSTInfo` |
| `OPENEIDAS_SIGNING_DIGEST` | `sha256` | Empreinte utilisée pour signer le jeton |
| `OPENEIDAS_MAX_REQUEST_BYTES` | `65536` | Taille maximale d'une requête |
| `OPENEIDAS_AUDIT_FILE` | `/var/lib/open-eidas/audit.log` | Journal d'audit chaîné par hachage |
| `OPENEIDAS_AUDIT_SEAL_INTERVAL` | `1h` | Période de scellement de la tête de chaîne (`0` désactive) |
| `OPENEIDAS_CROSS_TSA_URLS` | `https://freetsa.org/tsr,http://timestamp.digicert.com` | TSA tierces contresignant chaque scellement, séparées par des virgules |
| `OPENEIDAS_CROSS_TSA_TIMEOUT` | `15s` | Délai d'attente par TSA tierce |
| `OPENEIDAS_AUDIT_REPLICA_URL` | — | Base WebDAV où répliquer le journal à chaque scellement (vide = désactivé) |
| `OPENEIDAS_AUDIT_REPLICA_USER` | — | Utilisateur WebDAV |
| `OPENEIDAS_AUDIT_REPLICA_PASSWORD` | — | Mot de passe WebDAV |
| `OPENEIDAS_AUDIT_REPLICA_TIMEOUT` | `30s` | Délai d'attente de la réplication |
| `OPENEIDAS_TIME_POLICY` | `enforce` | `enforce` (refus de signer si l'heure n'est pas traçable), `monitor` ou `disabled` |
| `OPENEIDAS_TIME_SOURCES` | `ntp.obspm.fr,ptbtime1.ptb.de` | Serveurs de temps de référence, séparés par des virgules |
| `OPENEIDAS_TIME_MIN_SOURCES` | `2` | Nombre de sources devant répondre pour établir la traçabilité |
| `OPENEIDAS_TIME_MAX_OFFSET` | `500ms` | Dérive et désaccord maximaux tolérés |
| `OPENEIDAS_TIME_MAX_AGE` | `1h` | Ancienneté maximale de la dernière mesure |
| `OPENEIDAS_TIME_POLL` | `5m` | Période d'interrogation des sources |
| `OPENEIDAS_TIME_TIMEOUT` | `5s` | Délai d'attente par source |
| `OPENEIDAS_ENROLL_ENDPOINT` | — | URL de l'API d'enrôlement de la CA (`/api/v1/enroll`) |
| `OPENEIDAS_ENROLL_PROFILE` | `tsa_signer` | Profil de certificat demandé |
| `OPENEIDAS_ENROLL_HMAC_KEY` | — | Secret partagé authentifiant la demande de certificat (HMAC-SHA256 sur la CSR) |
| `OPENEIDAS_ENROLL_CA_FILE` | — | Ancre de confiance TLS de la PKI |
| `OPENEIDAS_ENROLL_INSECURE` | `false` | Désactive la vérification TLS (démonstration seulement) |
| `OPENEIDAS_ENROLL_TIMEOUT` | `5m` | Délai maximal d'attente d'un certificat |
| `OPENEIDAS_RENEW_BEFORE` | `720h` | Fenêtre de renouvellement anticipé |
| `OPENEIDAS_SUBJECT_CN` | `Open eIDAS Time-Stamping Unit 1` | `CN` demandé dans la CSR |

## Répondeur OCSP (`ocsp-responder`)

Service séparé (`cmd/ocsp-responder`) répondant aux requêtes OCSP (RFC 6960)
pour la CA émettrice — voir `docs/ARCHITECTURE.md` §2 et
`internal/ocspresponder`.

### `POST /ocsp` — requête OCSP

Corps : requête OCSP encodée en DER (`Content-Type: application/ocsp-request`,
non imposé côté serveur). Réponse : `application/ocsp-response`, DER.

```bash
openssl ocsp -issuer ca.pem -cert tsu.pem -CAfile ca.pem \
    -url http://localhost:8319/ocsp -resp_text
```

### `GET /healthz` — supervision

Répond `200 ok` sans condition — le service ne sert que si son certificat et
sa clé sont chargés (l'entrypoint bloque tant que l'enrôlement RPC n'a pas
réussi, voir `deploy/ocsp-responder/entrypoint.sh`).

### Configuration

| Variable | Défaut | Rôle |
|---|---|---|
| `OPENEIDAS_LISTEN` | `:8319` | Adresse d'écoute HTTP |
| `OPENEIDAS_PKCS11_MODULE` | `/usr/lib/softhsm/libsofthsm2.so` | Module PKCS#11 du HSM |
| `OPENEIDAS_TOKEN_LABEL` | `open-eidas-ocsp` | Label du token |
| `OPENEIDAS_KEY_LABEL` | `ocsp-signing-key` | Label de la bi-clé de signature |
| `OPENEIDAS_PIN` | — (obligatoire) | Code PIN du token |
| `OPENEIDAS_KEY_BITS` | `3072` | Taille de clé RSA, minimum 3072 |
| `OPENEIDAS_CERT_FILE` | `/var/lib/open-eidas/ocsp.pem` | Certificat de signature OCSP |
| `OPENEIDAS_CHAIN_FILE` | `/var/lib/open-eidas/chain.pem` | Chaîne d'émission (l'émetteur, `chain[0]`, sert de référence pour les requêtes) |
| `OPENEIDAS_ENROLL_ENDPOINT` | — | URL de l'API d'enrôlement de la CA (`/api/v1/enroll`) |
| `OPENEIDAS_ENROLL_PROFILE` | `ocsp_responder` | Profil de certificat demandé |
| `OPENEIDAS_ENROLL_HMAC_KEY` | — | Même secret partagé que la TSA |
| `OPENEIDAS_ENROLL_CA_FILE` / `OPENEIDAS_ENROLL_INSECURE` / `OPENEIDAS_ENROLL_TIMEOUT` | — / `false` / `5m` | Identiques à la TSA |
| `OPENEIDAS_RENEW_BEFORE` | `720h` | Fenêtre de renouvellement anticipé |
| `OPENEIDAS_SUBJECT_CN` / `_OU` / `_O` / `_C` | `Open eIDAS OCSP Responder 1` / `OCSP Responder` / `Open eIDAS` / `FR` | Sujet demandé dans la CSR |
| `OPENEIDAS_PKI_INTERNAL_URL` | — (obligatoire) | Adresse à laquelle CE SERVICE joint la PKI pour interroger sa CRL (interne au déploiement — distincte de l'adresse publique gravée dans les certificats) |
| `OPENEIDAS_PKI_CA_FILE` / `OPENEIDAS_PKI_INSECURE` | — / `false` | Ancre de confiance TLS pour `OPENEIDAS_PKI_INTERNAL_URL`, ou tolérance explicite d'un certificat auto-signé (démonstration) |
| `OPENEIDAS_OCSP_CRL_REFRESH` | `5m` | Période de rafraîchissement de la CRL |
| `OPENEIDAS_MAX_REQUEST_BYTES` | `16384` | Taille maximale d'une requête OCSP |
