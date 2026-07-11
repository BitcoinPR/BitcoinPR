# Regtest Interoperability Cluster

A Docker Compose environment that runs BitcoinPR alongside Bitcoin Core, Bitcoin
Knots, btcd, and Libbitcoin Server on an isolated regtest network.  The cluster is
used to validate that BitcoinPR accepts the same blocks, rejects the same
invalid transactions, and stays in consensus with every other major full-node
implementation.

## Architecture

```
                     ┌─────────────────────────────┐
                     │   Docker network: interop    │
                     │   subnet: 172.30.0.0/24      │
                     │                              │
    ┌────────────────┤  bitcoinpr1  (miner / seed)  ├────────────────┐
    │  P2P           │  P2P  :18444                 │                │
    │  connect       │  RPC  :18443 → host :18443   │                │
    │                └──────────┬──────────────────┘                │
    │                           │ P2P                                │
    ▼                           ▼                                    ▼
bitcoinpr2               bitcoin-core                        bitcoin-knots
P2P  :18444             P2P  :18444                         P2P  :18444
RPC  → host :28443      RPC  → host :38443                  RPC  → host :48443

                  btcd                       libbitcoin
                  P2P  :18444                P2P  :18445
                  RPC  → host :58443         ZMQ  → host :59091–59094
```

All nodes connect to `bitcoinpr1` as their initial P2P peer.  `bitcoinpr1` is
the designated block miner for regtest purposes.

## Nodes

| Container | Image / Source | Host RPC/ZMQ | Notes |
|---|---|---|---|
| `interop-bitcoinpr1` | Local Dockerfile (this repo) | `:18443` | Seed node + miner |
| `interop-bitcoinpr2` | Local Dockerfile (this repo) | `:28443` | Validator, connects to bitcoinpr1 |
| `interop-bitcoin-core` | `bitcoin/bitcoin:latest` | `:38443` | Official Core image |
| `interop-bitcoin-knots` | `docker/bitcoin-knots/Dockerfile` | `:48443` | Downloads official Knots binary |
| `interop-btcd` | `docker/btcd/Dockerfile` | `:58443` | btcd (Go); builds from source (fast). Sync/validation only — no wallet |
| `interop-libbitcoin` | `docker/libbitcoin/Dockerfile` | ZMQ `:59091–59094` | Builds from source; ~60–90 min |

All nodes run with `--loglevel debug` / `-debug=net` so P2P and validation
events are visible in the container logs.

## File Layout

```
docker-compose.interop.yml          Main compose file
docker/
  bitcoin-knots/
    Dockerfile                      Downloads official Knots binary release
  btcd/
    Dockerfile                      Builds btcd + btcctl from source (Go)
  libbitcoin/
    Dockerfile                      Builds libbitcoin-server from source
    bs.cfg                          Regtest config for Libbitcoin Server
scripts/
  interop-cluster.sh                Cluster lifecycle (start/stop/reset/status)
  interop-generate.sh               Block generation + sync verification
  interop-logs.sh                   Log collection and analysis
data/interop/                       Node data dirs (gitignored, created at runtime)
logs/                               Log dumps from interop-logs.sh (gitignored)
```

## Quick Start

### 1. Build images

Bitcoin Core is pulled automatically.  Bitcoin Knots and Libbitcoin must be
built locally.  Build Libbitcoin first since it is the longest step (~60–90 min):

```bash
docker compose -f docker-compose.interop.yml build libbitcoin   # one-time, cache it
docker compose -f docker-compose.interop.yml build bitcoin-knots
docker compose -f docker-compose.interop.yml build btcd          # fast (pure Go)
```

btcd is built from source (`go install`) because there is no reliably-maintained
official btcd image; the build is quick.  Confirm the pinned `BTCD_VERSION` in
`docker/btcd/Dockerfile` matches a current release at
<https://github.com/btcsuite/btcd/releases>.

Before building Knots, confirm the version and checksum in
`docker/bitcoin-knots/Dockerfile` match the latest release at
<https://bitcoinknots.org>.

### 2. Start the cluster

```bash
./scripts/interop-cluster.sh start
```

This creates the data directories, starts all six containers, and waits
until the five JSON-RPC nodes are responsive.  Libbitcoin readiness is checked
via container state only (it uses ZMQ, not JSON-RPC).

### 3. Generate blocks

```bash
./scripts/interop-generate.sh 150
```

Generates 150 blocks on `bitcoinpr1`, waits for all JSON-RPC nodes to sync,
then cross-checks that every node reports the same tip hash.  A hash mismatch
is flagged as a potential consensus failure.

## Scripts Reference

### `interop-cluster.sh`

```
./scripts/interop-cluster.sh start [--build]   Start (optionally rebuild images)
./scripts/interop-cluster.sh stop              Stop containers, preserve data
./scripts/interop-cluster.sh restart           Stop then start
./scripts/interop-cluster.sh reset [--build]   Wipe data and start fresh
./scripts/interop-cluster.sh status            Height / peers / tip table for all 6 nodes
./scripts/interop-cluster.sh wait              Block until all nodes are responsive (bx for libbitcoin)
./scripts/interop-cluster.sh build             Build custom images only
```

Environment variables:

| Variable | Default | Purpose |
|---|---|---|
| `DATA_DIR` | `./data/interop` | Root directory for all node data |
| `COMPOSE` | `docker-compose.interop.yml` | Compose file path |

### `interop-generate.sh`

```
./scripts/interop-generate.sh [BLOCKS] [OPTIONS]

  BLOCKS              Blocks to generate (default: 50)
  --address ADDR      Coinbase recipient address
  --no-verify         Skip post-generation sync check
  --timeout SECS      Per-node sync timeout (default: 120)
  --continuous N      Generate N blocks repeatedly
  --interval SECS     Interval between continuous rounds (default: 10)
```

Waits for all **6** nodes to reach the target height in parallel.
JSON-RPC nodes are also cross-checked for tip hash agreement; libbitcoin's
tip hash is derived from the block header returned by `bx fetch-block-header`.

### `interop-logs.sh`

```
./scripts/interop-logs.sh [MODE] [OPTIONS]

  MODE    follow   Interleaved colour-coded live stream (default)
          dump     Save each node's logs to ./logs/interop-<timestamp>/
          summary  Block / peer / error digest per node
          diff     Live chain-state snapshot (all 6 nodes) + block hash log lines

  --lines N       Lines of history (default: 500)
  --level LVL     Filter: error | warn | info | debug
  --node NAME     Restrict to one node (repeatable)
  --since T       Docker --since flag (e.g. "5m", "1h")
  --out DIR       Output directory for dump mode
```

The `diff` mode queries every node's current height and tip hash — via
JSON-RPC for the five Core-compatible nodes and via `bx` for libbitcoin —
then prints a consensus-check table before showing the log-based block
event lines.  A `← MISMATCH` marker flags any node whose tip hash differs
from `bitcoinpr1`.

## RPC Endpoints

The five JSON-RPC nodes share the same credentials (`test` / `test`).  btcd
(`:58443`) serves RPC over TLS — it refuses `--notls` on a non-localhost bind —
so query it with `https` and `curl -k`; the other four are plain HTTP.

```bash
# Quick block count check across all JSON-RPC nodes
# (btcd on :58443 is https; -k is a harmless no-op for the http nodes)
for port in 18443 28443 38443 48443 58443; do
  scheme=http; [ "$port" = 58443 ] && scheme=https
  echo -n "localhost:${port}  height: "
  curl -sk --max-time 5 -X POST "${scheme}://test:test@127.0.0.1:${port}" \
    -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","method":"getblockcount","params":[],"id":1}' \
    | python3 -c "import sys,json; print(json.load(sys.stdin).get('result','?'))"
done

# Libbitcoin height via bx (runs inside the container)
docker exec interop-libbitcoin bx fetch-height -c /etc/libbitcoin/bs.cfg
```

## Querying Libbitcoin via bx

The scripts invoke `bx` (bitcoin-explorer) inside the `interop-libbitcoin`
container using `docker exec` — no host-side `bx` installation is required.

| Query | Command |
|---|---|
| Current block height | `docker exec interop-libbitcoin bx fetch-height -c /etc/libbitcoin/bs.cfg` |
| Block header at height N | `docker exec interop-libbitcoin bx fetch-block-header N -c /etc/libbitcoin/bs.cfg` |
| Block header by hash | `docker exec interop-libbitcoin bx fetch-block-header <hash> -c /etc/libbitcoin/bs.cfg` |

`bx fetch-block-header` returns structured text that includes a `hash` field,
which the scripts parse to obtain the tip hash for cross-node comparison.
If the bx server is still initialising, the commands will time out gracefully
and the scripts will proceed with height-only checks.

## Libbitcoin Notes

Libbitcoin Server (`bs`) differs from the other nodes in three ways:

1. **ZMQ instead of JSON-RPC.** The server exposes a ZMQ-based query interface.
   The scripts use `bx` inside the container (via `docker exec`) to bridge this.
   No host-side tooling is needed; see the table above for the raw commands.

2. **Long build time.** The Dockerfile builds the entire libbitcoin stack from
   source.  After the first build, tag and cache the image:

   ```bash
   docker tag interop-libbitcoin libbitcoin-server:local
   ```

   To restore it later without rebuilding:
   ```bash
   docker tag libbitcoin-server:local interop-libbitcoin
   ```

3. **Regtest magic.** `bs.cfg` sets `identifier = 3669680122` (the regtest P2P
   magic `0xDAB5BFFA`).  This must match all peers on the network.

## Interoperability Testing Workflow

The primary use case is comparing what each implementation logs when a new
block arrives — looking for validation differences, rejection messages, or
unexpected disconnects.

**Suggested workflow:**

1. Start clean: `./scripts/interop-cluster.sh reset`
2. Generate a baseline chain: `./scripts/interop-generate.sh 101`
   (101 blocks makes coinbase outputs spendable in regtest)
3. The script waits for all 6 nodes — including libbitcoin via `bx` — to reach
   height 101, then prints a consensus table showing each node's height and tip
   hash.  A mismatch on any node is flagged immediately.
4. Optionally mine continuously: `./scripts/interop-generate.sh --continuous 1 --interval 30`
5. At any point, get a live chain-state snapshot across all 6 nodes:
   ```bash
   ./scripts/interop-logs.sh diff
   # or, filtered to just the last minute of block events:
   ./scripts/interop-logs.sh diff --since 1m
   ```
6. For a per-node log digest (recent block acceptances, peer events, errors):
   ```bash
   ./scripts/interop-logs.sh summary
   ./scripts/interop-logs.sh summary --level error
   ```

Any node that rejects a block accepted by the others, or reports an error
where others are silent, is a signal worth investigating in its source code.

### Reading the diff output

```
── Live chain state ──────────────────────────────────────────────────
NODE                HEIGHT    TIP HASH
----                ------    --------
bitcoinpr1           101       00000032f1a9...
bitcoinpr2           101       00000032f1a9...
bitcoin-core        101       00000032f1a9...
bitcoin-knots       101       00000032f1a9...
libbitcoin          101       00000032f1a9...   ← queried via bx

All queried nodes agree on tip.

── Block events in logs (last 500 lines, lines containing a block hash) ──
bitcoinpr1
  2026-05-10T12:00:01Z  validated block 00000032f1a9... height=101
bitcoinpr2
  ...
```

The first timestamp each node logged the new hash is the P2P propagation
latency from `bitcoinpr1` to that peer.
