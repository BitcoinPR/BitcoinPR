# docker/bitcoin-knots/Dockerfile
#
# Bitcoin Knots — drop-in bitcoind replacement with policy enhancements.
# Downloads the official binary release and installs it into a minimal image.
#
# Build args:
#   KNOTS_VERSION   — release 29.3.knots20260508
#   KNOTS_SHA256    — SHA-256 of the .tar.gz (verify at https://bitcoinknots.org)
#
# Update KNOTS_VERSION and KNOTS_SHA256 to the latest release before building.
# Checksums are published alongside each release at bitcoinknots.org/files/.

ARG KNOTS_VERSION=29.3.knots20260508
ARG TARGETARCH=amd64

FROM debian:bookworm-slim AS downloader

ARG KNOTS_VERSION
ARG TARGETARCH

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /tmp

# Map Docker arch to Knots release arch suffix.
# Keep the tarball under its original name so sha256sum -c can find it.
RUN case "${TARGETARCH}" in \
      amd64)  ARCH_SUFFIX="x86_64-linux-gnu"  ;; \
      arm64)  ARCH_SUFFIX="aarch64-linux-gnu"  ;; \
      armv7)  ARCH_SUFFIX="arm-linux-gnueabihf" ;; \
      *)      echo "Unsupported arch: ${TARGETARCH}" && exit 1 ;; \
    esac && \
    TARBALL="bitcoin-${KNOTS_VERSION}-${ARCH_SUFFIX}.tar.gz" && \
    BASE_URL="https://bitcoinknots.org/files/29.x/${KNOTS_VERSION}" && \
    curl -fsSL "${BASE_URL}/${TARBALL}" -o "${TARBALL}" && \
    curl -fsSL "${BASE_URL}/SHA256SUMS" -o SHA256SUMS && \
    grep "${TARBALL}" SHA256SUMS | sha256sum -c - && \
    tar -xzf "${TARBALL}" && \
    install -m 0755 "bitcoin-${KNOTS_VERSION}/bin/bitcoind"    /usr/local/bin/bitcoind && \
    install -m 0755 "bitcoin-${KNOTS_VERSION}/bin/bitcoin-cli" /usr/local/bin/bitcoin-cli

# ── Runtime stage ─────────────────────────────────────────────────────────────
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    libssl3 \
    libevent-2.1-7 \
    libzmq5 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Run as non-root bitcoin user (uid 1000 — same as official bitcoin/bitcoin image)
RUN groupadd -r bitcoin --gid=1000 && \
    useradd -r -g bitcoin --uid=1000 --home-dir=/data --shell=/bin/false bitcoin && \
    mkdir -p /data && chown bitcoin:bitcoin /data

COPY --from=downloader /usr/local/bin/bitcoind    /usr/local/bin/bitcoind
COPY --from=downloader /usr/local/bin/bitcoin-cli /usr/local/bin/bitcoin-cli

# P2P and RPC ports (regtest defaults)
EXPOSE 18444 18443

VOLUME ["/data"]

USER bitcoin

ENTRYPOINT ["bitcoind"]
CMD ["-datadir=/data", "-server=1", "-printtoconsole=1"]
