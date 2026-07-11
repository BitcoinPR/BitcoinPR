# docker/libbitcoin/Dockerfile
#
# Libbitcoin Server (bs) — alternative full-node implementation.
# Builds from source using the official libbitcoin install script.
#
# WARNING: This build takes 60–120 minutes the first time.  Cache the image:
#   docker compose -f docker-compose.interop.yml build libbitcoin
#   docker tag interop-libbitcoin libbitcoin-server:local
#
# To see the full compiler output if the build fails:
#   docker compose -f docker-compose.interop.yml build --progress=plain libbitcoin
#
# Protocol notes:
#   - Libbitcoin uses a ZMQ-based query interface (NOT Bitcoin JSON-RPC).
#   - Block sync with peers uses the standard Bitcoin P2P wire protocol.
#   - bx (bitcoin-explorer) is also installed and used by the interop scripts.
#
# Regtest support:
#   - Configured via the [network] section of bs.cfg (see ./bs.cfg).
#   - The regtest P2P magic is 0xDAB5BFFA; this must match all peers.

ARG LIBBITCOIN_BRANCH=version3

# ── Build stage ───────────────────────────────────────────────────────────────
# Ubuntu 20.04 / GCC 9 is the proven build environment for libbitcoin v3.
# Ubuntu 22.04's GCC 11 enforces stricter C++17 compliance that breaks the
# older codebase.
FROM ubuntu:20.04 AS builder

ARG LIBBITCOIN_BRANCH
ARG DEBIAN_FRONTEND=noninteractive

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    autoconf \
    automake \
    libtool \
    pkg-config \
    git \
    wget \
    curl \
    ca-certificates \
    python3 \
    libzmq3-dev \
    libssl-dev \
    libgmp-dev \
    liblzma-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

RUN wget -q \
    "https://raw.githubusercontent.com/libbitcoin/libbitcoin-server/${LIBBITCOIN_BRANCH}/install.sh" \
    -O install.sh && chmod +x install.sh

# --build-boost  : Ubuntu 20.04 ships Boost 1.71; libbitcoin v3 requires >=1.73.
# --build-zmq    : Ubuntu 20.04 ships libzmq 4.3.2; libbitcoin v3 requires >=4.3.4.
# --disable-shared: static libs so the runtime stage only needs system .so files.
RUN ./install.sh --prefix=/usr/local --build-boost --build-zmq --disable-shared \
        2>&1 | tee /tmp/install.log; \
    status="${PIPESTATUS[0]}"; \
    if [[ "$status" != "0" ]]; then \
        echo "=== install.sh failed (exit ${status}) — last 100 lines ==="; \
        tail -100 /tmp/install.log; \
        exit "$status"; \
    fi

# bx (bitcoin-explorer) is a separate project not built by the server install.sh.
# libbitcoin-client is its only extra dependency; everything else (system, network,
# protocol) is already installed above.
RUN git clone --depth 1 -b version3 \
        https://github.com/libbitcoin/libbitcoin-client.git /build/libbitcoin-client && \
    cd /build/libbitcoin-client && \
    ./autogen.sh && \
    ./configure --prefix=/usr/local --disable-shared \
        PKG_CONFIG_PATH=/usr/local/lib/pkgconfig && \
    make -j"$(nproc)" && \
    make install

RUN git clone --depth 1 -b version3 \
        https://github.com/libbitcoin/libbitcoin-explorer.git /build/libbitcoin-explorer && \
    cd /build/libbitcoin-explorer && \
    ./autogen.sh && \
    ./configure --prefix=/usr/local --disable-shared \
        PKG_CONFIG_PATH=/usr/local/lib/pkgconfig && \
    make -j"$(nproc)" && \
    make install


RUN echo "=== Installed libbitcoin binaries ===" && \
    find /usr/local/bin -name "bs" -o -name "bx" | sort && \
    test -f /usr/local/bin/bs || { echo "ERROR: bs not found after install"; exit 1; } && \
    test -f /usr/local/bin/bx || { echo "ERROR: bx not found after install"; exit 1; } && \
    echo "OK: bs and bx present"

# ── Runtime stage ─────────────────────────────────────────────────────────────
# Static linking means we only need the system shared libraries that bs/bx
# link against (OpenSSL, ZMQ, GMP).  No Boost or libbitcoin .so files needed.
FROM ubuntu:20.04

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    libssl1.1 \
    libzmq5 \
    liblzma5 \
    libgmp10 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /usr/local/bin/bs  /usr/local/bin/bs
COPY --from=builder /usr/local/bin/bx  /usr/local/bin/bx

COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

RUN mkdir -p /etc/libbitcoin /data/libbitcoin

# ZMQ: query, heartbeat, block publisher, transaction publisher
EXPOSE 9090 9091 9093 9094

# P2P (regtest)
EXPOSE 18445

VOLUME ["/data/libbitcoin"]

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
