# docker/btcd/Dockerfile
#
# btcd — btcsuite's full-node Bitcoin implementation written in Go.
# In the interop cluster it acts as a sync/validation node: it connects to
# bitcoinpr1 over P2P, syncs the regtest chain, and is cross-checked for tip
# agreement.  btcd has no built-in wallet (that's btcwallet), so it does not
# participate in the active generate/relay RPC tests.
#
# Built from source — btcd is pure Go and compiles in well under a minute, and
# there is no reliably-maintained official btcd image on Docker Hub.
#
# Build args:
#   BTCD_VERSION   — git release tag to install (see https://github.com/btcsuite/btcd/releases)
#
# btcd v0.26.0 requires Go 1.25+ (per its go.mod).

ARG BTCD_VERSION=v0.26.0

# ── Build stage ───────────────────────────────────────────────────────────────
FROM golang:1.25-alpine AS builder

ARG BTCD_VERSION

RUN apk add --no-cache git

ENV GOPATH=/go
ENV CGO_ENABLED=0

# Install both the node (btcd) and its control client (btcctl).  `go install`
# with a version suffix builds the pinned release into $GOPATH/bin.
RUN go install github.com/btcsuite/btcd@${BTCD_VERSION} && \
    go install github.com/btcsuite/btcd/cmd/btcctl@${BTCD_VERSION}

# ── Runtime stage ─────────────────────────────────────────────────────────────
FROM alpine:latest

RUN apk add --no-cache ca-certificates bash

# Run as a non-root user (uid 1000 — same convention as the core/knots images)
# with its home/data dir at /data.
RUN addgroup -g 1000 btcd && \
    adduser -D -u 1000 -G btcd -h /data btcd && \
    mkdir -p /data && chown btcd:btcd /data

COPY --from=builder /go/bin/btcd   /usr/local/bin/btcd
COPY --from=builder /go/bin/btcctl /usr/local/bin/btcctl

# P2P and RPC ports (regtest)
EXPOSE 18444 18443

VOLUME ["/data"]

USER btcd

ENTRYPOINT ["btcd"]
CMD ["--datadir=/data"]
