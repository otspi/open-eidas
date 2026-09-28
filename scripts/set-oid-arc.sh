#!/usr/bin/env bash
# SPDX-License-Identifier: EUPL-1.2
# Remplace l'OID de test historique (1.3.6.1.4.1.99999.1.1.1) par l'OID de l'arc de TEST d'OTSPI,
# 1.3.6.1.4.1.<PEN>.9.1.1.1, une fois le numéro d'entreprise IANA attribué.
# Voir docs/cadrage/oid-arc.md du dépôt de gouvernance (otspi/organisation).
#
# Usage :
#     scripts/set-oid-arc.sh <PEN>
#
# L'OID de production (<PEN>.1.1.1) n'est PAS posé ici : il n'est renseigné qu'à la mise en service
# du service qualifié, après approbation de la politique par le CPC, avec OPENEIDAS_PRODUCTION=true.

set -euo pipefail

if [ "$#" -ne 1 ] || ! [[ "$1" =~ ^[0-9]+$ ]]; then
  echo "usage : $0 <numéro d'entreprise IANA>" >&2
  exit 2
fi
pen="$1"
old="1.3.6.1.4.1.99999.1.1.1"
new="1.3.6.1.4.1.${pen}.9.1.1.1"

cd "$(git rev-parse --show-toplevel)"
files="$(grep -rlF "$old" . --exclude-dir=.git --exclude-dir=target --exclude=set-oid-arc.sh || true)"
if [ -z "$files" ]; then
  echo "Aucune occurrence de $old" >&2
  exit 1
fi

# shellcheck disable=SC2086
sed -i "s/${old//./\\.}/${new}/g" $files
echo "OID de test remplacé par $new dans :"
echo "$files"

# Le test de configuration compare l'OID par défaut sous forme de suite d'entiers.
sed -i "s/cfg.policy_oid, vec!\[1, 3, 6, 1, 4, 1, 99999, 1, 1, 1\]/cfg.policy_oid, vec![1, 3, 6, 1, 4, 1, ${pen}, 9, 1, 1, 1]/" crates/oe-config/src/lib.rs

if grep -rF "99999.1.1.1" . --exclude-dir=.git --exclude-dir=target --exclude=set-oid-arc.sh >/dev/null; then
  echo "Il reste des occurrences de l'ancien OID : à traiter à la main." >&2
  exit 1
fi
echo "Vérifier ensuite : cargo fmt --check && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace"
