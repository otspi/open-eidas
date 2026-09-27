FROM rust:1-bookworm AS build

WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY bin ./bin

ARG VERSION=dev
# `-p ra-console` seul, jamais `--workspace` : la console n'ouvre aucune session
# PKCS#11 et ne doit pas lier `cryptoki` (docs/WEBUI.md §16). Construite avec
# le reste du workspace, l'unification des fonctionnalités de Cargo réactiverait
# la feature `pkcs11` d'`oe-hsm` ; `bin/ra-console/tests/no_pkcs11.rs` en est la
# garde. `oe-webauthn` lie OpenSSL dynamiquement (`libssl3` à l'exécution).
RUN cargo build --release -p ra-console --bin ra-console \
 && cp target/release/ra-console /out-ra-console \
 && rm -rf target


FROM debian:bookworm-slim

# Même invalidation quotidienne du cache que les autres images (CACHEBUST, voir
# .github/workflows/ci.yml) : sans elle, `apt-get upgrade` resterait gelé.
# Ni SoftHSM ni opensc : la console n'a aucun token. `curl` sert à l'entrypoint
# pour récupérer le certificat de la CA émettrice au premier démarrage.
ARG CACHEBUST=unset
RUN echo "cachebust=${CACHEBUST}" \
 && apt-get update \
 && apt-get upgrade -y \
 && apt-get install -y --no-install-recommends libssl3 ca-certificates curl \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --system --uid 10004 --create-home --home-dir /var/lib/open-eidas ra \
 && mkdir -p /var/lib/open-eidas/state \
 && chown -R ra:ra /var/lib/open-eidas

COPY --from=build /out-ra-console /usr/local/bin/ra-console
COPY deploy/ra-console/entrypoint.sh /usr/local/bin/entrypoint.sh

ENV OPENEIDAS_RA_LISTEN=:8330 \
    OPENEIDAS_INTERNAL_TLS_CERT_FILE=/var/lib/open-eidas/state/internal-tls/client.pem \
    OPENEIDAS_INTERNAL_TLS_KEY_FILE=/var/lib/open-eidas/state/internal-tls/client.key \
    OPENEIDAS_CA_CERT_FILE=/var/lib/open-eidas/state/internal-tls/ca.pem \
    OPENEIDAS_RA_AUDIT_FILE=/var/lib/open-eidas/state/ra-console-audit.log

USER ra
WORKDIR /var/lib/open-eidas
EXPOSE 8330

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["serve"]
