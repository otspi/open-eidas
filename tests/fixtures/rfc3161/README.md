# Corpus de non-régression RFC 3161 (Go ↔ Rust)

Généré une fois pour toutes par `scripts/gen-fixtures` (supprimé avec le
reste du code Go — voir INDEPENDANCE.md pour l'état de la dépréciation) à
partir du code Go de référence (`internal/tsa`, également supprimé). Jalon
J0 du plan de migration Go → Rust, achevé
(`/home/philippe/.claude/plans/witty-hopping-nest.md`).

Ce corpus n'est plus régénérable : le binaire Go de référence n'existe
plus dans ce dépôt. Il reste figé tel quel, comme trace historique de
non-régression contre l'implémentation d'origine.

## Contenu

- `keys/tsu-test-key.pem`, `keys/tsu-test-cert.pem` — bi-clé RSA-3072 et
  certificat TSU de test, dérivés d'une graine fixe (`math/rand` seedé). Ce
  n'est **pas** un secret : ne jamais réutiliser ce matériel hors de ce
  corpus. La fenêtre de validité du certificat est relative à l'instant de
  génération (elle ne peut pas être figée : ETSI EN 319 421 §7.6.5 plafonne
  la durée de vie d'un certificat TSU à 28080h).
- Un répertoire par cas (`<nom>/`) :
  - `request.der` — `TimeStampReq` DER.
  - `response.der` — `TimeStampResp` DER (uniquement si le cas est accordé).
  - `meta.json` — résultat attendu (`want_granted`, `want_failure`, etc.).

## Ce que ce corpus garantit — et ce qu'il ne garantit pas

Le `genTime` de chaque jeton accordé est figé (horloge injectée,
`2026-01-15T10:00:00Z`), donc reproductible. Le **numéro de série** du jeton
est en revanche généré aléatoirement par `github.com/digitorus/timestamp`
(`generateTSASerialNumber`) à chaque appel : une régénération du corpus ne
produira donc **pas** un `response.der` identique bit à bit au précédent, même
si la requête et la clé de test sont inchangées.

Ce corpus sert à :
1. **Round-trip DER** (jalon J1, `oe-rfc3161-asn1`) : décoder puis ré-encoder
   `request.der`/`response.der` doit reproduire exactement les mêmes octets —
   ceci ne dépend pas de l'aléa du numéro de série, puisqu'on part d'un DER
   déjà produit.
2. **Vérification cryptographique** (jalon J6) : tout jeton produit par
   l'implémentation Rust pour les mêmes requêtes doit être accepté par
   `openssl ts -verify` avec `keys/tsu-test-cert.pem`, sans exiger une
   égalité bit à bit avec `response.der` (accuracy/serial diffèrent
   légitimement).
3. **Non-régression des rejets** : les cas `rejects-*` documentent le
   `failureInfo` RFC 3161 attendu — un portage qui perdrait un cas de rejet
   doit faire échouer les tests correspondants.
