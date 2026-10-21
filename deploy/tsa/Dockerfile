FROM rust:1-bookworm@sha256:665b6e0a9290a7298236c08c6e4f1e754e3f0d9b70421c434daa3dfba888d63e AS build

WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY bin ./bin

ARG VERSION=dev
# Pas de CGO à activer : le binding PKCS#11 (crate `cryptoki`) charge le
# module du HSM via dlopen au même titre que le binaire Go, mais sans lien
# statique contre une bibliothèque C particulière au moment de la
# compilation.
RUN cargo build --locked --release --bin tsa-server \
 && cp target/release/tsa-server /out-tsa-server \
 && rm -rf target


FROM debian:bookworm-slim@sha256:7ff6ba31527b9e336162fa061746c366c4b2032f4d2cff2078bea43f78efe3f8

# Invalide volontairement le cache Docker de cette couche une fois par jour
# (CACHEBUST passé par la CI, voir .github/workflows/ci.yml) : sans ça,
# `cache-from: type=gha` rejoue indéfiniment le même `apt-get upgrade`,
# gelant les paquets installés à leur version du premier build en cache.
ARG CACHEBUST=unset
RUN echo "cachebust=${CACHEBUST}" \
 && apt-get update \
 && apt-get upgrade -y \
 && apt-get install -y --no-install-recommends softhsm2 opensc ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --system --uid 10001 --create-home --home-dir /var/lib/open-eidas --groups softhsm tsa \
 && mkdir -p /var/lib/softhsm/tokens /var/lib/open-eidas/state \
 && chown -R tsa:tsa /var/lib/softhsm/tokens /var/lib/open-eidas

COPY --from=build /out-tsa-server /usr/local/bin/tsa-server
COPY deploy/tsa/entrypoint.sh /usr/local/bin/entrypoint.sh

ENV SOFTHSM2_CONF=/etc/softhsm/softhsm2.conf \
    OPENEIDAS_PKCS11_MODULE=/usr/lib/softhsm/libsofthsm2.so \
    OPENEIDAS_LISTEN=:8318

USER tsa
WORKDIR /var/lib/open-eidas
EXPOSE 8318

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["serve"]
