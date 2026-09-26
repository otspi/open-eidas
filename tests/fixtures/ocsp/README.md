# Fixtures OCSP (oe-ocsp-core)

Matériel de test pour `crates/oe-ocsp-core/tests/against_real_crl.rs`. **Pas
des secrets** : aucun usage en dehors de ces tests.

- `issuer-key.pem` / `issuer-cert.pem` — CA auto-signée de test (RSA-3072).
- `responder-key.pem` / `responder-cert.pem` — certificat de signature OCSP
  (`extendedKeyUsage=OCSPSigning`, `id-pkix-ocsp-nocheck`), émis par la CA
  ci-dessus.
- `issuer.crl.der` — CRL réelle signée par la CA, générée via `openssl ca`,
  contenant un certificat révoqué (motif `keyCompromise`, série `0x1000`) et
  l'extension privée `oe_conformance::OID_CRL_ISSUED_SERIALS` (constat O-1 de
  l'audit du 2026-09-25) portant les deux séries émises par cette fixture
  (`0x1000` révoquée, `0x1001` le certificat sain).
- `request-good.der` / `request-revoked.der` — vraies requêtes OCSP DER
  produites par `openssl ocsp -issuer ... -cert ...` pour un certificat sain
  (série `0x1001`) et un certificat révoqué (série `0x1000`) émis par cette
  même CA.
- `request-unknown.der` — requête OCSP pour une série jamais émise par cette
  CA (`0x9999`, absente de `OID_CRL_ISSUED_SERIALS` ci-dessus), produite par
  `openssl ocsp -issuer issuer-cert.pem -serial 0x9999 -reqout
  request-unknown.der` (constat O-1).
- `issuer.crl.stale.der` — même CRL, mais antérieure à l'émission de `0x1001`
  (numéro de CRL `4095` au lieu de `4096`, `OID_CRL_ISSUED_SERIALS` ne porte
  que `0x1000`) : simule l'instantané que le répondeur a en cache juste avant
  qu'une CA republie une CRL plus récente — sert à prouver le rafraîchissement
  à la volée (`try_on_demand_refresh`).

Régénéré via une CA `openssl ca` classique (répertoire `newcerts`/`index.txt`)
puis `openssl ocsp -reqout` — voir l'historique de commit introduisant ces
fichiers pour la séquence exacte de commandes.

**`OID_CRL_ISSUED_SERIALS`** : `openssl ca -crlexts` ne connaît pas cette
extension par son nom (comme `privateKeyUsagePeriod`, voir
`tests/fixtures/tsa/README.md`) — donnée en DER brut. Pour régénérer
`issuer.crl.der` en gardant cette extension à jour (par ex. après avoir
changé les séries revoquées/émises) :

```
# python3 -c "
# def der_int(n):
#     b = n.to_bytes((n.bit_length() + 7) // 8 or 1, 'big')
#     if b[0] & 0x80:
#         b = b'\x00' + b
#     return bytes([0x02, len(b)]) + b
# content = der_int(0x1000) + der_int(0x1001)  # séries émises
# seq = bytes([0x30, len(content)]) + content
# print(seq.hex())
# "
# Dans un répertoire de travail avec cacert.pem/cakey.pem (copies de
# issuer-cert.pem/issuer-key.pem), un index.txt à une ligne par entrée
# révoquée (format `openssl ca`) et crlnumber = 4096 :
#
# [crl_ext]
# crlNumber = DER:02021000
# 1.3.6.1.4.1.0.1.3 = DER:30080202100002021001
#
openssl ca -config openssl.cnf -gencrl -out newcrl.pem
openssl crl -in newcrl.pem -outform DER -out issuer.crl.der
```
