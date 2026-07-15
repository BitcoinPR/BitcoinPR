# BitcoinPR

> **Warning:** This is an experimental Bitcoin node implementation. It has not been extensively audited or battle-tested. **Do not use this software to manage or secure substantial funds.** Use at your own risk.

A Bitcoin full node implementation in Rust. Connects to the Bitcoin peer-to-peer network, validates blocks with full script verification, maintains a UTXO set, and serves a Bitcoin Core-compatible JSON-RPC API.

The default build is a **lean validator** (core consensus + P2P + RPC + mining). Optional features (web explorer, Electrum indexing) can be enabled at compile time.

## Architecture

```
bitcoinpr/              # Daemon binary (CLI, event loop, signal handling)
bitcoinpr-core/         # Consensus rules, validation, script interpreter, mempool, event bus
bitcoinpr-p2p/          # TCP wire protocol, peer management, sync engine
bitcoinpr-storage/      # RocksDB indexes, flat-file block storage, UTXO set
bitcoinpr-rpc/          # JSON-RPC HTTP server (jsonrpsee)
bitcoinpr-mining/       # Stratum V1 + SV2 mining gateway, share tracking
bitcoinpr-index/        # Scripthash indexing, Electrum TCP server  [optional: --features indexing]
bitcoinpr-web/          # Embedded web explorer (Axum HTTP/WS)      [optional: --features web]
```

## Features

### Core

- **Full node** — connects to mainnet, testnet3, testnet4, signet, or regtest
- **Headers-first IBD** — syncs block headers first, then downloads blocks in parallel from 24 peers with bandwidth-weighted allocation (EWMA tracking, faster peers get more blocks); head-of-line unblocking re-requests stalled blocks after 10s with rotating peer selection; `notfound` handling immediately re-queues blocks from pruned peers; address manager learns peer reliability from connect/disconnect history and filters out chronically-failing IPs; getdata write failures trigger immediate peer disconnect and block re-queue; non-blocking inter-task channels prevent deadlocks; logs sync progress percentage against peer-reported best height
- **Assume-valid** — skips script verification for blocks at or before block 840,000 for faster IBD
- **Full script verification** — complete opcode coverage for legacy, SegWit, and Tapscript including full BIP 65/112 CLTV/CSV semantics in tapscript (OP_PICK, OP_ROLL, OP_ROT, OP_3DUP, OP_2OVER, OP_2ROT, OP_2SWAP, OP_CHECKSIGADD, disabled opcodes, OP_SUCCESS)
- **UTXO set** — RocksDB-backed with DashMap concurrent cache (compact per-coin storage, ~135 bytes/entry vs moka's ~500), crash-consistent batched flush every 1000 blocks (or 200k buffer overflow), configurable cache budget via `--dbcache` (default 450 MB, split 60/40 between RocksDB block cache and UTXO cache), bloom filters for fast negative lookups, HDD-optimized RocksDB settings (2MB compaction readahead, 16KB blocks, cached index/filter), coinbase maturity checks, atomic flush-height tracking for crash recovery, validated_height persisted on every flush for safe crash recovery
- **Chain reorganization** — detects forks via chain work comparison, disconnects stale blocks with UTXO undo (v2 undo data with created outpoints + prev hash for block-store-free rollback), and switches to the heaviest chain
- **Block validation** — proof-of-work, merkle root, weight limits, full 256-bit difficulty retarget, BIP 34 coinbase, BIP 30 duplicate tx check, sigop counting, witness commitment (BIP 141)
- **Transaction mempool** — validates against UTXO set, script verification, fee tracking, RBF (BIP 125), ancestor/descendant limits (25/25), persistence across restarts, 2-week expiry
- **Relay policy filters (Knots-style)** — configurable mempool/relay/mining standardness beyond Core's defaults: `--datacarrier`/`--datacarriersize` (OP_RETURN gating), `--permitbaremultisig` (default 0 — rejects the Stamps/SRC-20 data-embedding vector), `--rejectparasites` (default 1 — rejects inscription envelopes in tapscript witnesses), `--rejecttokens` (default 1 — rejects Runes, Omni, Counterparty, and BRC-20 markers). Policy only: blocks containing filtered transactions still validate, so these can never fork the node. See `docs/relay-policy.md`
- **Fee estimation** — 20-bucket fee rate estimator (1-10,000 sat/vB) with confirmation rate tracking and adaptive thresholds
- **Signature cache** — 100k-entry, 64-way sharded cache (wtxid+input+flags keyed) to skip redundant ECDSA/Schnorr verification; random per-shard eviction when full, cleared on a 10k-block cadence
- **Parallel verification** — rayon thread pool sized to `available_parallelism()`−2 (clamped to ≥2, leaving headroom for the async runtime) for concurrent script execution, batched UTXO prefetch via `batched_multi_get_cf` to warm cache before validation; block validation and mempool signature checks run on `spawn_blocking` threads so the async event loop stays responsive
- **Graceful shutdown** — responsive to `stop` RPC and Ctrl-C even mid-IBD (AtomicBool checked in drain loop); crash recovery uses `max(validated_height, utxo_flush_height)` to avoid catastrophic rollback
- **Raw block passthrough** — threads raw serialized bytes from P2P network directly to block store, skipping re-serialization
- **Transaction index** — optional `-txindex` for full `getrawtransaction` from disk, with height tracking and automatic background backfill on startup
- **Block pruning** — `--prune <MiB>` deletes the oldest block files (and their undo records) once total block-file size exceeds the target; always keeps the most recent 288 blocks and never prunes above the last UTXO-flushed height, so crash recovery keeps working. Advertises BIP 159 `NODE_NETWORK_LIMITED` instead of `NODE_NETWORK`; `pruneblockchain` RPC for manual pruning; `getblockchaininfo` reports `pruned`/`pruneheight`. Incompatible with `--txindex`/`--index`. **Note: a pruned node is not a full node** — it still validates every block and enforces all consensus rules, but it discards historical block data, so it cannot serve old blocks to syncing peers, rescan history, or act as an archival source for indexes

### P2P Networking

- **Outbound connections** — 24 outbound peers via DNS seeds or manual `--connect` (supports hostnames and IPs); DNS seeds resolved concurrently with a 3s per-seed timeout and dials spawned off the P2P event loop, so a dead seed or anchor list never stalls message processing; height=0 honeypot peers filtered from block downloads; chronic non-delivering peers (pruned nodes) auto-disconnected to free slots for full nodes; address manager tracks success/failure per IP and uses reliability-sorted list for reconnection
- **Self-connection detection** — Core-style version-nonce check aborts handshakes with our own looped-back dials, the dialer skips its own discovered external address, and IP dedup canonicalizes IPv4-mapped IPv6 (`::ffff:a.b.c.d`)
- **Inbound connections** — listens for up to 101 inbound peers (24 outbound + 101 inbound = Core's 125-connection default)
- **Transaction relay** — requests transactions announced via INV, validates and adds to mempool, relays to peers
- **GetData serving** — responds to peer transaction requests from mempool
- **GetAddr handling** — responds to address requests with known peers from the address manager
- **Seen-txid tracking** — bounded 50k-entry dedup set prevents redundant requests
- **Peer scoring** — misbehavior tracking with automatic IP banning
- **Subnet diversity** — limits outbound connections to max 2 per /16 subnet
- **Address manager** — stores, scores, and relays peer addresses (addr/addrv2 — BIP 155)
- **Direct header announcements** — sends `sendheaders` (BIP 130) post-handshake so peers push headers instead of inv-then-getheaders
- **Witness-txid relay** — handles `wtxidrelay` (BIP 339) for witness-aware transaction deduplication
- **Preferred download peer** — selects the best peer by chain height and protocol version
- **Fee filter** — BIP 133 feefilter message support (stored per-peer)
- **Connection retry** — exponential backoff with address rotation
- **Compact block relay** — BIP 152 with SipHash-2-4 short transaction IDs, mempool-based block reconstruction, and `getblocktxn`/`blocktxn` fallback for missing transactions
- **Compact block filters** — BIP 157/158 Golomb-Rice coded sets for light client support
- **V2 encrypted transport** — BIP 324 with real ElligatorSwift key exchange (libsecp256k1), BIP 324-compatible ECDH shared secret derivation, HKDF session keys, ChaCha20-Poly1305 framing
- **Bloom filter SPV serving** — optional BIP 37 (`--peerbloomfilters`, off by default): `filterload`/`filteradd`/`filterclear`, `merkleblock` serving for filtered blocks, BIP 35 `mempool` inv relay, and `NODE_BLOOM` (BIP 111) advertisement. MurmurHash3 wire-compatible with Bitcoin Core. Never enabled on outbound connections
- **Service flags** — BIP 159 `NODE_NETWORK_LIMITED` advertised (in place of `NODE_NETWORK`) when running with `--prune`
- **Tor & I2P** — outbound over a SOCKS5 proxy (`--proxy`/`--onion`) with per-connection Tor stream isolation; inbound via an auto-created v3 `.onion` hidden service (`--listenonion`: Tor control-port `ADD_ONION` with password/SAFECOOKIE/cookie auth and a persisted key for a stable address); I2P via a SAM v3 bridge (`--i2psam`) with `STREAM CONNECT`/`ACCEPT` and a persisted `.b32.i2p` destination; BIP 155 `addrv2` learning, relay, and self-advertisement of the `.onion`/`.b32.i2p`; `--onlynet` to restrict which networks are dialed, skipping clearnet DNS entirely in Tor/I2P-only mode. See [`docs/tor-i2p.md`](docs/tor-i2p.md)

### Consensus BIPs

- BIP 8/BIP 9 — versionbits soft-fork deployment state machine (signaling/dashboard for buried forks; BIP 110 additionally drives a reorg-safe BIP-8 state machine on the consensus path)
- BIP 14 — `/Name:Version/` user-agent format (advertised as `/bitcoinpr:0.1.110/`)
- BIP 16 — Pay-to-Script-Hash (P2SH): redeemScript hash-commit + evaluation, gated on the BIP 16 activation time
- BIP 30 — duplicate transaction rejection
- BIP 34 — coinbase height encoding
- BIP 35 — `mempool` message (inv relay, filter-aware; requires `--peerbloomfilters`)
- BIP 37 — bloom-filter SPV serving (`filterload`/`add`/`clear`, `merkleblock`; opt-in)
- BIP 65 — CHECKLOCKTIMEVERIFY (full semantics in legacy and tapscript; 5-byte `CScriptNum` for lock-time values)
- BIP 66 — strict DER signature encoding
- BIP 68 — relative lock-time via sequence numbers
- BIP 90 — buried soft-fork deployments (per-network activation heights, incl. dedicated `csv_height`)
- BIP 110 — Reduced Data Temporary Softfork (RDTS): seven data-restriction rules (scriptPubKey ≤34 / OP_RETURN ≤83, push & witness items ≤256, undefined witness/Tapleaf versions, Taproot annex, control blocks ≤257, OP_SUCCESS, OP_IF/OP_NOTIF) with UTXO grandfathering by creation height. Signaling-driven activation via a reorg-safe BIP-8 state machine (mandatory-signaling window, expiry); `--bip110height` fixed-mode override for testing. Includes a **chain-split monitor** — if the majority chain violates BIP-110, the node holds its chain (durable invalid-block markers + taint-aware fork choice; non-signaling mandatory-window headers are classified without downloading blocks), tracks both chains (`getchainsplitinfo`, web Split page), and offers an **abandon minority chain** action once the rival leads by 6+ blocks and equivalent work: a persisted flag + restart disables RDTS enforcement and the node rejoins the most-work chain
- BIP 111 — `NODE_BLOOM` service flag (paired with BIP 37, opt-in)
- BIP 112 — CHECKSEQUENCEVERIFY (full semantics in legacy and tapscript; 5-byte `CScriptNum` for lock-time values)
- BIP 113 — median-time-past for lock-time
- BIP 125 — replace-by-fee signaling
- BIP 130 — `sendheaders` direct header announcements (sent on every handshake)
- BIP 133 — fee filter
- BIP 141/143/144 — SegWit (witness commitment, witness script verification, on-the-wire witness serialization)
- BIP 147 — NULLDUMMY: the CHECKMULTISIG/CHECKMULTISIGVERIFY dummy element must be empty (enforced from the SegWit activation height)
- BIP 152 — compact block relay
- BIP 155 — `addrv2` / `sendaddrv2` extended address relay
- BIP 157/158 — compact block filters (GCS)
- BIP 159 — `NODE_NETWORK_LIMITED` service flag (advertised when pruning via `--prune`)
- BIP 324 — V2 encrypted P2P transport
- BIP 325 — Signet support (custom challenge scripts)
- BIP 339 — `wtxidrelay` (witness-txid based transaction relay)
- BIP 340/341/342 — Taproot, Schnorr signatures, Tapscript (OP_CHECKSIGADD)
- BIP 350 — bech32m address handling, audited end-to-end (`validateaddress`, scripthash index)

### JSON-RPC

- **30 Bitcoin Core-compatible methods** — works with `bitcoin-cli`; `getpeerinfo` reports live per-peer `synced_headers`/`synced_blocks` tracked from headers and block-inv announcements; `invalidateblock`/`reconsiderblock` for operator-driven fork management; plus `getchainsplitinfo` / `abandonbip110` for the BIP-110 chain-split monitor
- **HTTP Basic authentication** — `rpcuser`/`rpcpassword` enforced at the HTTP layer (constant-time compare) for *every* method before dispatch; unauthenticated requests get `401`. The node refuses to start if RPC is bound to a non-loopback address while still using the default password
- **Batch request support** — up to 100 requests per batch
- **Health check endpoint** — HTTP health on RPC port + 100 with status, height, peers, uptime

### Web Block Explorer

- **Embedded web server** — Axum-based HTTP server on port 3000 with REST API and WebSocket
- **PHOSPHOR theme** — cypherpunk 8-bit dark UI: design-token CSS (true Bitcoin orange accent, pixel display font + monospace data font), fully self-hosted fonts (zero third-party requests), CRT accents
- **Timechain strip** — pixel-art chain visualization: confirmed block cubes, dashed confirmation divider, live mempool cube, and a stepped slide animation as new blocks confirm (in-place WebSocket updates, no page reload); block pages center the viewed block with ghost slots for unmined heights
- **Dashboard** — chain height, difficulty, mempool stats, peer count, recent blocks, and a **recent confirmed transactions** feed (newest txs walked back from the tip)
- **Info page** — node status hub: sync/index progress bars, storage breakdown, running services, and a live peer table showing current block height per peer (updated from headers and block-inv announcements, not stale handshake height)
- **Block/Transaction/Address explorer** — search and inspect blockchain data
- **Block transaction list** — paginated child transactions per block, each clickable with a truncated source → destination address summary
- **Expandable transaction flow diagram** — Sankey visualization of inputs/outputs with hover highlighting, now interactive: a `+` on any input expands the graph backward into the previous transaction (unlimited, follow the chain), and a `+` on an output expands forward into its spender — both unconfirmed (mempool) and confirmed spenders, the latter resolved via the cross-block scripthash index so you can follow the money forward across blocks. Each output carries a spend badge (UTXO / spent / pending) resolved from the mempool, UTXO set, and scripthash index
- **Mempool visualization** — fee-rate histogram, paginated transaction list, and a **sat/vByte-over-time** stepped chart with 15m/30m/1h/2h timeframe selection, fed by a periodic in-memory sampler
- **Mining dashboard** — real-time hashrate, shares, workers, blocks found (requires `--mining`)
- **Chain Split page** — BIP-110 split monitor: two-chain race view (fork point, both tips, block/work deficit, first invalid rival block, signaling stats) with an **Abandon minority chain** action (typed confirmation + `--webadmintoken`) once the rival chain leads by the threshold. The tab only appears while the split is live (a tracked rival at or above our chain work); once the rival is out-worked, resolved, or abandoned it disappears again (the page stays reachable at `#/split`)
- **WebSocket** — real-time push notifications for new blocks, transactions, mining events, and chain-split state changes; IBD-aware (suppresses rapid-fire block events during initial sync)
- **Unified search** — look up blocks, transactions, and addresses from a single search bar

<details>
  <summary>Web Screenshots</summary>
  <img src="docs/screenshots/dash.png" alt="dashboard page"/>
  <img src="docs/screenshots/mempool.png" alt="mempool page"/>
  <img src="docs/screenshots/mining.png" alt="mining page"/>
  <img src="docs/screenshots/info.png" alt="info page"/>
  <img src="docs/screenshots/split.png" alt="chain split monitor page"/>
</details>

### Electrum Server

- **Electrum protocol v1.4** — JSON-RPC over newline-delimited TCP (requires `--index`)
- **Dual transport** — plain TCP (default 50001) and SSL/TLS (default 50002); both ports configurable via `--electrumport` / `--electrumsslport`
- **TLS certificate** — self-signed cert created on startup, or bring your own with `--electrumcert` / `--electrumkey`
- **Configurable MOTD banner** — `--electrumbanner` sets the `server.banner` response
- **Scripthash subscriptions** — real-time balance/transaction notifications, fired on both confirmed blocks (`NewBlock`) and unconfirmed mempool activity (`NewTx`)
- **Mempool awareness** — scripthash status, `get_history`, `get_mempool`, and unconfirmed `get_balance` all surface mempool transactions (height `0`, or `-1` for unconfirmed parents); prevouts are resolved against the mempool, UTXO set, and tx index to detect spends
- **Address indexing** — RocksDB-backed scripthash-to-transaction mapping; backfill resolves cross-block prevouts via a rolling outpoint → (scriptPubKey, value) cache (2M entries ≈ 300 MB, seeded from each indexed block, auto-cleared after backfill) with cache misses batched through parallel tx-index lookups and partial funding-block decodes; progress visible via `getindexinfo` RPC
- **Transaction lookup** — `blockchain.transaction.get` returns raw tx hex from mempool or tx index
- **Transaction broadcast** — `blockchain.transaction.broadcast` accepts raw tx hex
- **Standard methods** — `server.version`, `server.features`, `server.ping`, `blockchain.scripthash.subscribe/get_balance/listunspent/get_history/get_mempool`, `blockchain.headers.subscribe`, `blockchain.transaction.get/broadcast`, `blockchain.estimatefee`, `mempool.get_fee_histogram`

### Mining Gateway

- **Stratum V1** — full support for cgminer, bfgminer, cpuminer, bitaxe, and other standard miners
  - `mining.subscribe` / `mining.authorize` / `mining.notify` / `mining.submit`
  - `mining.set_difficulty`, `mining.configure` (BIP 310 version rolling with mask `1fffe000`), `mining.extranonce.subscribe`
  - Flexible handshake: handles `mining.configure` before or after `mining.authorize`
  - Coinbase construction with configurable payout address (`--miningaddress`)
  - Share validation with actual difficulty computed from header hash, BIP 310 version bit XOR, minimum share difficulty enforcement with proper stratum error codes (23=low-diff, 21=stale)
- **SV2 Template Distribution Protocol** — sections 7.1-7.7 (NewTemplate, SetNewPrevHash, SubmitSolution)
- **Auto-detection** — automatically detects V1 or SV2 protocol on connection
- **Template provider** — pushes block templates from chain tip + mempool; mempool-driven re-templating throttled to 30s to reduce stale shares
- **New block notifications** — instantly pushes new jobs/templates when a block arrives (no throttle)
- **Share tracking** — rolling-window hashrate estimation, per-worker stats
- **Mining dashboard** — web UI with real-time hashrate, shares, workers, acceptance rate
- **Runtime mining configuration** — `MiningConfig` persisted to `{datadir}/mining.toml`, shared behind `Arc<RwLock<..>>` with a watch-channel version counter for live reload; configurable coinbase scriptSig tag (pool attribution, capped at 80 bytes), pool name, mining address, and mode (solo/datum). Editable live via `GET`/`POST /api/mining/config` and the `#/mining/config` web form (changes apply without a restart). See `docs/mining-config.md`
- **Datum protocol client** — template-sovereign pool mining (OCEAN-style): the miner builds templates while the pool coordinates payouts. TLS transport (rustls + Mozilla roots), newline-delimited JSON `DatumMessage` framing, handshake → `ServerHello` → steady-state loop with exponential-backoff reconnect (degraded mode keeps local mining alive), pool coinbase-output splits applied to the coinbase, qualifying-share forwarding, and live pool-connection cards on the dashboard. See `docs/datum.md`

### Operational

- **Configuration file** — `bitcoinpr.conf` with Bitcoin Core-style key=value format (see `example.bitcoinpr.conf`)
- **Structured JSON logging** — `--jsonlog` flag for machine-readable log output
- **Sync progress** — logs block validation progress as percentage of peer-reported best height
- **Smart chain recovery** — self-healing after crashes with no manual `--reindex` needed:
  - UTXO flush-height tracking: atomically persists chain height with UTXO data; on startup, detects and resolves tip/UTXO desync automatically
  - Block-store-free rollback: v2 undo data enables rolling back blocks without reading from the block store, using only the undo records (created outpoints + prev block hash)
  - Block store integrity scanning: verifies the last 1000 blocks on startup, queues missing or corrupt blocks for re-download
  - TxIndex height tracking: tracks indexed height, backfills gaps in a background task on startup
- **Persistent blocksdir pointer** — when `--blocksdir` relocates block storage, a `blocksdir.conf` pointer is saved automatically; on next startup the node remembers the location even without the flag, preventing accidental chain re-download
- **Crash consistency** — on-disk chain tip only advances when UTXO buffer flushes; on crash, re-validates gap blocks automatically; reorgs force immediate UTXO flush
- **WAN IP discovery** — discovers external IP from outbound peer version messages (vote-based consensus), advertises routable address for inbound connections
- **Reindex** — `--reindex` flag rebuilds UTXO set, headers, and indexes from stored block data
- **Mempool persistence** — saves/loads mempool across restarts
- **Docker image** — multi-stage Dockerfile
- **Systemd service** — `contrib/bitcoinprd.service` with hardening options
- **Graceful shutdown** — flushes UTXO cache, persists chain tip, saves mempool, closes databases

## Dashboard

A single-screen progress dashboard (workspace LOC, module weights, BIP coverage, git history, and live sync/peer/mempool stats when a local `bitcoinprd` is reachable):

```bash
./scripts/dashboard.sh                 # one-shot snapshot, good to share
./scripts/dashboard.sh --watch         # refresh every 5s
./scripts/dashboard.sh --watch 2       # refresh every 2s
./scripts/dashboard.sh --no-rpc        # skip live node probe
./scripts/dashboard.sh --rpc http://user:pass@host:port
./scripts/dashboard.sh --plain         # disable ANSI colour
```

## Building

```bash
# Lean validator (default: core + P2P + RPC + mining)
cargo build --release

# With web explorer and Electrum indexing
cargo build --release --features full

# Individual features
cargo build --release --features indexing    # adds Electrum server + scripthash index
cargo build --release --features web         # adds web explorer (implies indexing)
```

Requires a C++ compiler for RocksDB (first build takes ~6 minutes).

## Running

```bash
# Mainnet (default)
./target/release/bitcoinprd

# Testnet3
./target/release/bitcoinprd --network testnet

# Testnet4
./target/release/bitcoinprd --network testnet4

# Regtest
./target/release/bitcoinprd --network regtest

# Signet
./target/release/bitcoinprd --network signet

# With transaction index and JSON logging
./target/release/bitcoinprd --txindex --jsonlog

# Custom data directory and connect to specific peer
./target/release/bitcoinprd --datadir /path/to/data --connect 192.168.1.100:8333
```

### Docker

```bash
# Build lean validator
docker build -t bitcoinpr .

# Build with all features
docker build --build-arg FEATURES=full -t bitcoinpr-full .

# Run single node
docker run -p 8333:8333 -p 8332:8332 -v bitcoinpr-data:/data bitcoinpr

# Run the interop regtest cluster: 2× BitcoinPR + Bitcoin Core 31.0 + Knots +
# btcd + libbitcoin, to test cross-implementation consensus, relay, and mining.
./scripts/interop-cluster.sh start --build      # start|stop|restart|reset [--build]
./scripts/interop-test.sh                        # 18-test end-to-end suite

# Manual regtest block generation (bitcoinpr1 RPC on :18443 in the cluster)
curl -X POST http://test:test@127.0.0.1:18443 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"generatetoaddress","params":[10,"bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080"],"id":1}'
```

### Mining

BitcoinPR includes a built-in mining gateway that supports both Stratum V1 and SV2 miners. The protocol is auto-detected on connection.

```bash
# Enable mining on testnet with payout to your address
./target/release/bitcoinprd --network testnet --mining --miningaddress tb1qyouradresshere

# Enable mining on regtest (OP_TRUE output, anyone-can-spend — fine for testing)
./target/release/bitcoinprd --network regtest --mining

# Custom port
./target/release/bitcoinprd --network testnet --mining --miningport 4444 --miningaddress tb1q...
```

Point your miner at the node:

```bash
# cgminer / bfgminer
cgminer -o stratum+tcp://127.0.0.1:3333 -u worker -p x

# cpuminer
minerd -a sha256d -o stratum+tcp://127.0.0.1:3333 -u worker -p x
```

The mining gateway:
- Sends `mining.set_difficulty` (per-worker vardiff: starts at 512 or the miner's `suggest_difficulty` and ramps toward ~1 share/15 s; pin a fixed value with `--miningdifficulty`) and `mining.notify` jobs from the current chain tip
- Pushes new jobs immediately when a new block is seen on the network; mempool changes throttled to every 30s to reduce stale shares
- Validates submitted shares against the share difficulty floor and tracks per-worker hashrate; rejects low-difficulty and stale shares with proper stratum error codes (23/21)
- If a share meets the network difficulty target, the block is assembled, validated, and broadcast

Mining stats are visible via the web dashboard (`--features web`) or the RPC:

```bash
bitcoin-cli -rpcport=8332 -rpcuser=bitcoinpr -rpcpassword=bitcoinpr getmininginfo
```

### CLI Options

| Flag | Default | Description |
|------|---------|-------------|
| `--network` | `mainnet` | Network: mainnet, testnet, testnet4, signet, regtest |
| `--datadir` | `~/.bitcoinpr` | Data directory for blockchain storage |
| `--blocksdir` | (datadir) | Store raw block files (blk*.dat) on a separate disk; indexes stay in datadir (mirrors Core's `-blocksdir`). A `blocksdir.conf` pointer is saved automatically so the node remembers the location even if restarted without `--blocksdir` |
| `--migrateblocks` | off | One-shot: move existing blk*.dat into `--blocksdir`, then keep running (indexes untouched; pointer saved) |
| `--rpcbind` | `127.0.0.1` | RPC server bind address |
| `--rpcport` | 8332/18332/48332/18443/38332 | RPC server port (network-dependent default) |
| `--rpcuser` | `bitcoinpr` | RPC username |
| `--rpcpassword` | `bitcoinpr` | RPC password |
| `--port` | 8333/18333/48333/18444/38333 | P2P listen port |
| `--connect` | (DNS seeds) | Connect to specific peer (repeatable) |
| `--peerbloomfilters` | off | Serve BIP 37 bloom filters to inbound peers (advertises `NODE_BLOOM`; enables BIP 35 `mempool`) |
| `--loglevel` | `info` | Log level: trace, debug, info, warn, error |
| `--txindex` | off | Maintain a full transaction index |
| `--jsonlog` | off | Output structured JSON logs |
| `--index` | off | Enable address indexing (explorer + Electrum) |
| `--reindex` | off | Rebuild UTXO set, headers, and indexes from stored blocks |
| `--reindex-chainstate` | off | Rebuild UTXO/tx/scripthash indexes by replaying stored block files (headers and blk*.dat kept) |
| `--prune` | 0 (off) | Keep total block-file size under this many MiB by deleting the oldest block files + undo records (min 550; most recent 288 blocks always kept). Incompatible with `--txindex`/`--index` |
| `--electrumport` | 50001 | Electrum plain-text TCP port (requires `--index`) |
| `--electrumsslport` | `electrumport`+1 | Electrum SSL/TLS port |
| `--electrumcert` | (self-signed) | PEM TLS certificate chain for the Electrum SSL port |
| `--electrumkey` | (self-signed) | PEM private key matching `--electrumcert` |
| `--electrumbanner` | `BitcoinPR Electrum Server` | MOTD banner for Electrum `server.banner` |
| `--webport` | 3000 | Web explorer HTTP port |
| `--webadmintoken` | (unset) | Bearer token required for mutating web endpoints (e.g. mining config); unset = explorer is read-only |
| `--healthbind` | rpcbind:rpcport+100 | Bind address for the plain-HTTP health endpoint |
| `--mining` | off | Enable mining gateway |
| `--miningport` | 3333 | Mining gateway TCP port |
| `--miningaddress` | OP_TRUE | Coinbase payout address (e.g. `tb1q...`) |
| `--miningdifficulty` | (vardiff) | Pin the share difficulty for `mining.set_difficulty`, disabling vardiff; without this, each worker's difficulty ramps automatically toward ~1 share per 15 s |
| `--coinbasetag` | `/BitcoinPR/` | Coinbase scriptSig tag (pool attribution, ≤ 80 bytes) |
| `--poolname` | `BitcoinPR` | Pool attribution name |
| `--disableipv6` | off | Disable IPv6 peer connections |
| `--no-v2transport` | off | Disable the BIP 324 v2 encrypted transport (v1-only peers connect via automatic fallback either way) |
| `--proxy` | — | Route outbound connections through a SOCKS5 proxy (e.g. Tor at `127.0.0.1:9050`); `.onion` resolved by the proxy (see `docs/tor-i2p.md`) |
| `--onion` | = `--proxy` | SOCKS5 proxy specifically for `.onion` targets |
| `--onlynet` | all | Restrict outbound to `ipv4`/`ipv6`/`onion`/`i2p` (repeatable); Tor-only mode skips clearnet DNS |
| `--proxyrandomize` | 1 | Randomize SOCKS5 credentials per connection for Tor stream isolation |
| `--listenonion` | 1 | Create a v3 `.onion` hidden service via the Tor control port (inbound over Tor) |
| `--torcontrol` | `127.0.0.1:9051` | Tor control port for `--listenonion` |
| `--torpassword` | — | Tor control-port password (else cookie/SAFECOOKIE auth) |
| `--i2psam` | — | I2P SAM bridge (`host:port`) enabling the I2P transport (e.g. i2pd at `127.0.0.1:7656`) |
| `--i2pacceptincoming` | 1 | Accept inbound I2P connections (when `--i2psam` set) |
| `--dbcache` | 450 | UTXO database cache size in MB (60% RocksDB block cache, 40% in-memory UTXO entry cache) |
| `--bip110height` | (per-network) | BIP 110 RDTS fixed-mode activation height override (active from this height, no signaling/expiry). Mainnet computes activation from signaling; mainly for exercising RDTS on regtest. Ignored once the operator has abandoned the minority chain (`abandonbip110` / web Split page) |
| `--datacarrier` | 1 | Relay/mine transactions with OP_RETURN outputs; `0` rejects them from the mempool (policy only — see `docs/relay-policy.md`) |
| `--datacarriersize` | 83 | Max OP_RETURN script size in bytes, including the opcode (Core default 83; Knots uses 42) |
| `--permitbaremultisig` | 0 | Relay/mine bare (non-P2SH) multisig outputs; `1` restores Bitcoin Core-compatible relay |
| `--rejectparasites` | 1 | Reject parasitic-protocol transactions (inscription envelopes in tapscript witnesses) |
| `--rejecttokens` | 1 | Reject token-protocol transactions (Runes runestones, Omni/Counterparty payloads, BRC-20 inscriptions) |

## RPC Methods

Compatible with `bitcoin-cli`:

```bash
bitcoin-cli -rpcport=8332 -rpcuser=bitcoinpr -rpcpassword=bitcoinpr getblockchaininfo
```

| Category | Method |
|----------|--------|
| Blockchain | `getblockchaininfo`, `getblock`, `getblockhash`, `getblockcount`, `getdifficulty`, `getbestblockhash`, `pruneblockchain`, `getchainsplitinfo`, `invalidateblock`, `reconsiderblock` |
| Transactions | `getrawtransaction`, `sendrawtransaction`, `decoderawtransaction` |
| UTXO | `gettxout` |
| Mempool | `getmempoolinfo`, `getrawmempool` |
| Network | `getnetworkinfo`, `getpeerinfo`, `getconnectioncount` |
| Util | `validateaddress` (BIP 350: `scriptPubKey`, `witness_version`, `witness_program`), `estimatesmartfee` |
| Mining | `getblocktemplate` (BIP 22/23: `rules`, `longpollid`, `capabilities`, `default_witness_commitment`, `proposal` mode), `submitblock`, `generatetoaddress`, `getmininginfo` |
| Control | `stop`, `help`, `uptime`, `getindexinfo`, `abandonbip110` |

## Testing

```bash
# Unit tests (324 tests across all crates)
cargo test --workspace --all-features

# Interop integration suite (requires Docker)
# Brings up the 6-node cluster (2× BitcoinPR + Bitcoin Core + Knots + btcd + libbitcoin)
# and runs 18 end-to-end tests: sync agreement, mempool relay, Stratum mining,
# Electrum, web, restart/reconnect resilience, and cross-implementation propagation.
./scripts/interop-cluster.sh start --build
./scripts/interop-test.sh

# BIP-110 chain-split scenario (requires Docker; separate 2-node cluster)
# Forges an RDTS-violating block on Bitcoin Core past --bip110height, asserts
# the node holds its chain, the split monitor tracks/arms, and the full
# "abandon minority chain" capitulation (flag + restart) converges onto the
# majority chain. --monitor-only skips the capitulation steps.
./scripts/interop-split-test.sh

# Static quality gate: fmt --check, clippy --all-features -D warnings,
# cargo audit, cargo machete (unused deps), and the full test suite
./scripts/gate.sh
```

Unit tests cover consensus params, block validation, script interpretation (incl. 5-byte `CScriptNum` for lock-time opcodes), buried-deployment activation (`deployment_active`, `csv_height`), BIP 110 RDTS (all seven rules + the P2A exemption, and the signaling state machine: full lifecycle DEFINED→ACTIVE→EXPIRED, mandatory-floor lock-in, and reorg-safety across forks), storage roundtrips, serialization, mempool operations, address management, signature caching, compact block filters, BIP 37 bloom filters (MurmurHash3 verified against Core's `bloom_tests.cpp` vectors), V2 transport, versionbits, fee estimation, mining templates, coinbase-tag injection, `MiningConfig` save/load + validation, `DatumMessage` serialization, the Datum client (solo-idle, share-queue, coinbase-output decoding), bech32m (BIP 350) taproot address vectors and scripthash derivation, UTXO flush-height recovery, undo data v2 rollback, block pruning (ceiling bounds, file/undo deletion, file-numbering survival across reopen), block store verification, tx index height tracking, and cross-block prevout resolution (including the cold-cache disk path through the tx index and partial block decode). Property tests (proptest) pin the hand-rolled u256 chainwork arithmetic against a num-bigint oracle and the shared merkle module against rust-bitcoin's implementation.

The interop suite verifies end-to-end block generation, P2P propagation, mempool relay, Stratum mining, and consensus agreement across a 6-node Docker cluster that deliberately mixes implementations — 2× BitcoinPR alongside Bitcoin Core 31.0, Bitcoin Knots, btcd (Go), and libbitcoin — so cross-implementation compatibility is exercised on every run (a live bitaxe ASIC can also mine the cluster's Stratum port). btcd participates as a sync/validation node (it has no built-in wallet) and is cross-checked for height and tip agreement.

<img src="docs/screenshots/interop-regtest-sparrow.png" alt="interop regtest cluster"/>

## Dependencies

**Always included:**
- **bitcoin** v0.32 — primitives and serialization (consensus validation is implemented from scratch)
- **rocksdb** — header index, UTXO set, transaction index storage
- **tokio** — async runtime for P2P networking, mining gateway
- **jsonrpsee** v0.24 — JSON-RPC HTTP server with batch support
- **rayon** — parallel script verification (thread pool sized from `available_parallelism()`)
- **dashmap** — concurrent UTXO cache with compact per-coin storage (size configurable via `--dbcache`)
- **clap** — CLI argument parsing
- **tracing** — structured logging (text and JSON formats)
- **toml** — `mining.toml` runtime mining-config serialization
- **rustls / tokio-rustls / webpki-roots** — TLS transport for the Datum protocol client

**With `--features web`:**
- **axum** v0.8 — embedded web server for the block explorer (HTTP + WebSocket)
- **tower-http** — CORS and static file serving middleware
- **rust-embed** — embeds static frontend assets into the binary

**With `--features indexing`:**
- **rocksdb** (additional column families) — scripthash-to-transaction index

## License

MIT
