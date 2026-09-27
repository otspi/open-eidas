#!/bin/sh
# Premier démarrage de ra-console (docs/WEBUI.md §14, §16, Jour 0) : obtient le
# certificat de la CA émettrice et le certificat client `internal_client` du
# lien interne, puis démarre la console.
#
# Le certificat de la CA est la seule racine de confiance du lien mTLS. Il est
# récupéré une fois, sur l'API de la CA interne au cluster (même canal que
# l'enrôlement), puis conservé : un redémarrage ne le remplace pas. Le premier
# certificat du fichier fait foi, et `/api/v1/ca.pem` commence par la CA
# émettrice.
#
# `ra-console internal-cert` dépose la demande et attend qu'un opérateur nommé
# l'approuve sur la CA (`ca-server ra approve`) ; en démonstration, le sidecar
# d'approbation automatique la traite. La clé survit à un redémarrage.
set -eu

: "${OPENEIDAS_CA_CERT_FILE:?OPENEIDAS_CA_CERT_FILE est obligatoire}"
: "${OPENEIDAS_INTERNAL_TLS_CERT_FILE:?OPENEIDAS_INTERNAL_TLS_CERT_FILE est obligatoire}"
: "${OPENEIDAS_INTERNAL_TLS_KEY_FILE:?OPENEIDAS_INTERNAL_TLS_KEY_FILE est obligatoire}"

if [ "${1:-serve}" = "serve" ]; then
    # La clé privée n'est lisible que par ce service, dès la création du dossier.
    (umask 077 && mkdir -p "$(dirname "${OPENEIDAS_INTERNAL_TLS_KEY_FILE}")")

    if [ ! -s "${OPENEIDAS_CA_CERT_FILE}" ]; then
        : "${OPENEIDAS_CA_CHAIN_URL:?OPENEIDAS_CA_CHAIN_URL est obligatoire au premier démarrage}"
        attempt=1
        until curl -fsS "${OPENEIDAS_CA_CHAIN_URL}" -o "${OPENEIDAS_CA_CERT_FILE}.tmp"; do
            if [ "${attempt}" -ge "${OPENEIDAS_CA_ATTEMPTS:-60}" ]; then
                echo "abandon : certificat de la CA injoignable (${OPENEIDAS_CA_CHAIN_URL})" >&2
                exit 1
            fi
            echo "CA injoignable (tentative ${attempt}), nouvel essai dans 5 s"
            attempt=$((attempt + 1))
            sleep 5
        done
        mv "${OPENEIDAS_CA_CERT_FILE}.tmp" "${OPENEIDAS_CA_CERT_FILE}"
    fi

    if [ ! -s "${OPENEIDAS_INTERNAL_TLS_CERT_FILE}" ]; then
        attempt=1
        until ra-console internal-cert; do
            if [ "${attempt}" -ge "${OPENEIDAS_INTERNAL_CERT_ATTEMPTS:-12}" ]; then
                echo "abandon : certificat client du lien interne toujours non obtenu après ${attempt} tentatives" >&2
                exit 1
            fi
            echo "certificat client non obtenu (tentative ${attempt}), nouvel essai dans 10 s"
            attempt=$((attempt + 1))
            sleep 10
        done
    fi
fi

exec ra-console "$@"
