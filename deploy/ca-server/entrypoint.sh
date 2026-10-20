#!/bin/sh
# Prépare les deux tokens PKCS#11 de la hiérarchie (racine et CA émettrice),
# exécute la cérémonie de clé — idempotente — puis démarre le service.
#
# Deux tokens et non un seul : la racine ne signe que la CA émettrice. En
# production, ils sont portés par deux modules distincts, sous deux contrôles
# distincts, et seule l'émettrice reste accessible au service en
# fonctionnement (voir docs/CA.md).
set -eu

: "${OPENEIDAS_ROOT_TOKEN_LABEL:=open-eidas-root}"
: "${OPENEIDAS_ISSUING_TOKEN_LABEL:=open-eidas-issuing}"
: "${OPENEIDAS_ISSUING_PIN:?OPENEIDAS_ISSUING_PIN est obligatoire}"

# Constat C-2 (EN 319 411-1 OVR-6.5.7-05, GEN-6.5.1-04) : en production, aucun
# repli silencieux. Chaque token a son PIN et son PIN SO, tous explicites ; ni
# le PIN de la racine ni un PIN SO ne reprennent un autre PIN. Hors production
# (démonstration, CI), les replis restent admis.
if [ "${OPENEIDAS_PRODUCTION:-false}" = "true" ]; then
    : "${OPENEIDAS_ROOT_PIN:?OPENEIDAS_ROOT_PIN est obligatoire en production (jamais celui de l'émettrice)}"
    : "${OPENEIDAS_ROOT_SO_PIN:?OPENEIDAS_ROOT_SO_PIN est obligatoire en production}"
    : "${OPENEIDAS_ISSUING_SO_PIN:?OPENEIDAS_ISSUING_SO_PIN est obligatoire en production}"
    if [ "${OPENEIDAS_ROOT_PIN}" = "${OPENEIDAS_ISSUING_PIN}" ]; then
        echo "en production, OPENEIDAS_ROOT_PIN doit différer d'OPENEIDAS_ISSUING_PIN (deux tokens, deux contrôles)" >&2
        exit 1
    fi
    if [ "${OPENEIDAS_ROOT_SO_PIN}" = "${OPENEIDAS_ROOT_PIN}" ] || [ "${OPENEIDAS_ISSUING_SO_PIN}" = "${OPENEIDAS_ISSUING_PIN}" ]; then
        echo "en production, un PIN SO doit différer du PIN utilisateur de son token" >&2
        exit 1
    fi
fi
: "${OPENEIDAS_ROOT_PIN:=${OPENEIDAS_ISSUING_PIN}}"
: "${OPENEIDAS_ROOT_SO_PIN:=${OPENEIDAS_ROOT_PIN}}"
: "${OPENEIDAS_ISSUING_SO_PIN:=${OPENEIDAS_ISSUING_PIN}}"

init_token() {
    label="$1"
    pin="$2"
    so_pin="$3"
    # SoftHSM refuse silencieusement un PIN hors de cette plage et se rabat sur
    # une invite interactive, ce qui bloquerait le conteneur sans message clair.
    len=${#pin}
    if [ "$len" -lt 4 ] || [ "$len" -gt 255 ]; then
        echo "le PIN du token ${label} doit contenir entre 4 et 255 caractères (SoftHSM)" >&2
        exit 1
    fi
    if ! softhsm2-util --show-slots | grep -q "Label: *${label}"; then
        echo "initialisation du token SoftHSM ${label}"
        softhsm2-util --init-token --free --label "${label}" \
            --pin "${pin}" --so-pin "${so_pin}"
    fi
}

init_token "${OPENEIDAS_ROOT_TOKEN_LABEL}" "${OPENEIDAS_ROOT_PIN}" "${OPENEIDAS_ROOT_SO_PIN}"
init_token "${OPENEIDAS_ISSUING_TOKEN_LABEL}" "${OPENEIDAS_ISSUING_PIN}" "${OPENEIDAS_ISSUING_SO_PIN}"

if [ "${1:-serve}" = "serve" ]; then
    # PostgreSQL peut mettre un moment à accepter des connexions au premier
    # démarrage : la cérémonie est réessayée, et reste sans effet une fois la
    # hiérarchie créée.
    attempt=1
    until ca-server ceremony; do
        if [ "${attempt}" -ge "${OPENEIDAS_CEREMONY_ATTEMPTS:-30}" ]; then
            echo "abandon : la cérémonie de clé a échoué après ${attempt} tentatives" >&2
            exit 1
        fi
        echo "cérémonie impossible (tentative ${attempt}), nouvel essai dans 5 s"
        attempt=$((attempt + 1))
        sleep 5
    done
fi

# Lien interne ra-console <-> ca-server (docs/WEBUI.md §14, §16) : le certificat
# `internal_server` doit exister avant `serve`, qui refuse d'ouvrir le port
# interne sans lui. La demande passe par la file RA comme toute autre : en
# démonstration le sidecar d'approbation la traite ; en production, un opérateur
# nommé l'approuve (`ca-server ra approve`), et ce démarrage attend sa décision.
# La clé et la demande survivent à un redémarrage (même clé, même demande).
if [ "${1:-serve}" = "serve" ] && [ -n "${OPENEIDAS_INTERNAL_LISTEN:-}" ] \
    && [ ! -s "${OPENEIDAS_INTERNAL_TLS_CERT_FILE:-}" ]; then
    : "${OPENEIDAS_INTERNAL_DNS_NAME:?OPENEIDAS_INTERNAL_DNS_NAME est obligatoire avec OPENEIDAS_INTERNAL_LISTEN}"
    : "${OPENEIDAS_INTERNAL_TLS_CERT_FILE:?OPENEIDAS_INTERNAL_TLS_CERT_FILE est obligatoire}"
    : "${OPENEIDAS_INTERNAL_TLS_KEY_FILE:?OPENEIDAS_INTERNAL_TLS_KEY_FILE est obligatoire}"
    # La clé privée n'est lisible que par ce service, dès la création du dossier.
    (umask 077 && mkdir -p "$(dirname "${OPENEIDAS_INTERNAL_TLS_KEY_FILE}")")
    attempt=1
    while :; do
        rc=0
        ca-server internal-cert server "${OPENEIDAS_INTERNAL_DNS_NAME}" || rc=$?
        [ "${rc}" -eq 0 ] && break
        # Code 3 : demande déposée, en attente d'approbation. Tout autre code est
        # une erreur, à ne pas réessayer en boucle.
        if [ "${rc}" -ne 3 ]; then
            echo "abandon : le certificat du lien interne n'a pas pu être demandé (code ${rc})" >&2
            exit 1
        fi
        if [ "${attempt}" -ge "${OPENEIDAS_INTERNAL_CERT_ATTEMPTS:-120}" ]; then
            echo "abandon : demande de certificat du lien interne toujours non approuvée après ${attempt} tentatives" >&2
            exit 1
        fi
        echo "certificat du lien interne en attente d'approbation (tentative ${attempt}), nouvel essai dans 5 s"
        attempt=$((attempt + 1))
        sleep 5
    done
fi

exec ca-server "$@"
