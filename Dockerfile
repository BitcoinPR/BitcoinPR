# Build stage
FROM rust:1.88 AS builder

# Install clang for RocksDB
RUN apt-get update && apt-get install -y --no-install-recommends \
    clang libclang-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY . .

ARG FEATURES=""
RUN if [ -z "$FEATURES" ]; then \
        cargo build --release; \
    else \
        cargo build --release --features "$FEATURES"; \
    fi

# Runtime stage
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    libssl3 ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/target/release/bitcoinprd /usr/local/bin/bitcoinprd

# Create data directory
RUN mkdir -p /data/bitcoinpr

# P2P and RPC ports (mainnet defaults; regtest uses 18444/18443)
EXPOSE 8333 8332 18444 18443

VOLUME ["/data/bitcoinpr"]

ENTRYPOINT ["bitcoinprd"]
CMD ["--datadir", "/data/bitcoinpr"]
