# Certificat TSU de test (oe-tsa-core)

`tsu-key.pem` / `tsu-cert.pem` — bi-clé RSA-3072 et certificat auto-signé
générés par `openssl req` (profil `keyUsage=critical,digitalSignature,
nonRepudiation`, `extendedKeyUsage=critical,timeStamping`,
`basicConstraints=critical,CA:FALSE`). Utilisés par les tests de
`crates/oe-tsa-core` (`tests/end_to_end.rs`, tests unitaires de `lib.rs`).

**Pas un secret** : ce matériel n'a d'autre usage que ces tests. Ne jamais le
réutiliser en dehors du dépôt.

**`-days` doit rester strictement inférieur à 1170** (39 mois,
`oe_conformance::MAX_END_ENTITY_LIFETIME`) : `oe_tsa_core::Authority::new`
rejette désormais tout certificat TSU dont la durée de vie dépasse ce
plafond, y compris cette fixture.

**Porte aussi `privateKeyUsagePeriod`** (constat T-3 de l'audit du
2026-09-25) : `oe_conformance::check_tsu_certificate` (appelée par
`Authority::new`) exige cette extension, avec un `notAfter` strictement
antérieur à celui du certificat. `openssl req -addext` ne connaît pas cette
extension par son nom (« extension setting not supported ») : elle est
donnée en DER brut (`2.5.29.16=DER:<hex>`), calculé pour un `notAfter`
`SEQUENCE { [1] IMPLICIT GeneralizedTime }` — voir le script Python en
commentaire ci-dessous pour en calculer un autre.

Régénérer (le `notAfter` de `privateKeyUsagePeriod` ci-dessous,
`20280926000000Z`, doit rester antérieur à celui du certificat produit par
`-days 1095`, sans quoi `check_tsu_certificate` refuse la fixture) :

```
# python3 -c "
# content = '20280926000000Z'.encode()
# inner = bytes([0x81, len(content)]) + content
# outer = bytes([0x30, len(inner)]) + inner
# print(outer.hex())
# "
openssl req -x509 -newkey rsa:3072 -nodes \
  -keyout tests/fixtures/tsa/tsu-key.pem \
  -out tests/fixtures/tsa/tsu-cert.pem \
  -days 1095 \
  -subj "/CN=Open eIDAS Time-Stamping Unit (fixture de test Rust)" \
  -addext "keyUsage=critical,digitalSignature,nonRepudiation" \
  -addext "extendedKeyUsage=critical,timeStamping" \
  -addext "basicConstraints=critical,CA:FALSE" \
  -addext "2.5.29.16=DER:3011810f32303238303932363030303030305a"
```
