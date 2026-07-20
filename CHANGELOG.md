# BitcoinPR — Changelog

Completed work, newest first (moved from TODO.md on 2026-07-11).

> Note: `docs/archive/…` paths referenced below were removed from the repo
> on 2026-07-11; retrieve those documents from git history.

## Validation/IBD Performance Batch, Scripthash Resolver v2, BIP-110 Config Fingerprint (2026-07-20)

Closes the IBD Performance backlog (all 8 items from the Core PR #32043
analysis), the top two Signature Verification Throughput items, the
scripthash-resolver byte-offset follow-up, and the substantive fix from the
BIP-110 late-upgrade chainstate-gap audit.

**Scripthash resolver: v2 `TxIndexEntry` with tx byte locations.** The
2026-07-12 backfill was still CPU-bound on partial block scans for
cache-missed prevouts (~5.3 s/block, ETA >1 month). Tx-index entries now
carry `(offset, len)` of the serialized tx within its raw block (v2, 44
bytes; block-relative so entries survive block-file migration/reindex) in a
write-new/read-both migration with legacy 36-byte v1 entries. A v2 prevout
resolves with one small positional read (`BlockStore::read_block_slice`) +
one tx decode instead of decoding the block up to the tx position. The
existing all-v1 index upgrades itself opportunistically: when a v1 entry
forces a funding-block scan anyway, the scan records the tx locations it
walks past (txids already known from the outpoints — no hashing) and
batch-rewrites those entries to v2, so repeat lookups of hot funding txs go
direct. New blocks index as v2 at connect/backfill/catch-up.

**IBD performance batch** (Core tracking PR #32043 analogues):
- `remove_for_block` early-returns against an empty mempool (Core #32827) —
  was a full-block `compute_txid` pass under the mempool write lock per
  connected block during IBD; the connect path now also passes its
  precomputed txids in, killing the re-hash even when the mempool is live.
- wtxids are computed once per block (witness-commitment check hands them to
  script-check queueing) instead of twice (Core #32487 spirit).
- `FastOutpointBuildHasher` (`storage/src/fast_hash.rs`, Core #30442
  analogue): rotate-xor fold with a per-process seed instead of SipHash-1-3
  for outpoint/txid-keyed maps — sound because those keys are SHA256d
  output; used by the UTXO write buffer, DashMap read cache, intra-block
  spend maps, duplicate-input check, and mempool `spent_outpoints`.
- Single-map write buffer (Core #33602 idea): `inserts`+`deletions` merged
  into one `FastHashMap<[u8;36], Option<UtxoEntry>>` (`None` = tombstone) —
  one probe instead of two on every `get`/`contains`/`apply_batch`.
- `check_transaction` small-input fast path (Core #31682 analogue): 1 input
  no check, ≤32 inputs sorted-scan, HashSet only beyond that; null-prevout
  check folded into the same pass.
- Inline small-script coin storage (Core #32279/#25325 analogue):
  `CoinScript` stores scriptPubKeys ≤36 bytes inline (covers P2WPKH 22,
  P2SH 23, P2PKH 25, P2WSH/P2TR 34 — ~99% of outputs), heap fallback above.
- Batched block-file I/O (Core #31551 analogue): the background writer keeps
  a persistent file handle and coalesces same-file queued blocks into one
  write; readers share a small cache of `Arc<File>` handles with positional
  (`read_exact_at`) reads — no per-read open, no seek contention; handles
  evicted on prune.
- Chunked UTXO flush (Core #31645, inverted): giant `--dbcache` flushes
  commit inserts + undo records in ~128 MB idempotent chunks, deletions all
  together last, so peak memory no longer doubles the batch and a crash
  mid-flush replays cleanly.

**Signature verification** (from the libbitcoin GPU-claim analysis): one
shared `Secp256k1<VerifyOnly>` context (`OnceLock`) replaces per-check
construction (was fresh per candidate signature — 5× for a 3-of-5
multisig), and one `SighashCache` per `verify_script` call is threaded
through the interpreter to every ECDSA/taproot check for that input, so the
segwit/taproot tx-wide midstates (`hashPrevouts`/`hashOutputs`/…) are
computed once per input instead of once per signature tried. No
consensus-logic change; multisig and many-output txs stop re-hashing free
work.

**BIP-110 enforcement-config fingerprint + fail-closed startup** (the
substantive fix from the blockslop.dev late-upgrade chainstate-gap audit):
RDTS rules run only in `connect_block`, but startup trusted the persisted
chainstate — a config change between runs (pre-BIP110 datadir upgraded in
place, `--bip110height` added/lowered, abandoned flag flipped) left
already-validated blocks unchecked under the current rules. The effective
config (fixed height / deployment params / off) is fingerprinted in
header-index META with the validated height it covers from; on startup, a
changed config that would enforce at or below the validated tip refuses to
start and demands `--reindex-chainstate` (a true replay-from-genesis here).
Turning enforcement *off* (abandonment) just re-records; pre-fingerprint
datadirs running the unmodified network default are grandfathered (this
lineage always enforced the default deployment, so their chainstate is
covered). Any future un-abandon path automatically hits the same machinery.

## Split-Monitor Follow-ups: Repair-Path Fork Choice, invalidateblock/reconsiderblock, Rival Persistence (2026-07-15)

Closes the three follow-ups logged with the chain-split monitor:

**Headers repair path re-runs fork choice.** Re-announced already-stored
headers used to take an "index-repair" path that pre-wrote height-index
entries for branches that never won fork choice — polluting the index above
the validated tip (three split-monitor misreads and a peer-serving stall
traced back to it) — while never re-evaluating fork choice, so a cleared
branch was only adopted on its next new block. The walk now stores nothing
and remembers the segment's tip; after the batch, fork choice re-evaluates
it (taint check, strictly-greater work, catch-up guard) and adopts by
backfilling the branch index + resetting the header tip. Post-capitulation
and post-`reconsiderblock` convergence now happen from the re-announcement
alone. Normal batch adoption also backfills ancestor index holes. A
generation counter on the invalid-marker set invalidates HeaderSync's taint
memo whenever markers change outside the header path.

**`invalidateblock` / `reconsiderblock` RPCs** (Bitcoin Core parity, on the
marker machinery): `invalidateblock` durably marks a block
(`INVALID_REASON_MANUAL`), feeds the split monitor, and — when the block is
on the active chain — disconnects down to its parent and resets the header
tip; the node then follows the next-best untainted chain (disconnected
transactions are not returned to the mempool). `reconsiderblock` clears the
marker from the block and every marked descendant; the branch is adopted on
its next fork-choice evaluation.

**Rival tips persist across restarts.** The split monitor's tracked tips are
written to storage on every change (68-byte records in the header-index
meta CF) and restored at startup, so a mid-split restart resumes with
`getchainsplitinfo`/the Split page live immediately — verified by a new
restart step in `interop-split-test.sh` (which also now asserts convergence
with no explicit post-capitulation block). Cleared on capitulation and when
the last rival is pruned.

## BIP-110 Chain-Split Monitor + "Abandon Minority Chain" (2026-07-15)

If BIP-110 activates against majority hashrate, the node follows a minority
chain. The node now handles that scenario end-to-end. Foundation: durable
invalid-block markers (new `invalid_blocks` column family, WAL-flushed, with
an in-memory mirror) and taint-aware fork choice — a heavier chain containing
a marked-invalid block is stored for observability but can never win fork
choice or trigger a reorg, closing a wedge where the reorg's disconnect phase
ran before discovering the new branch's blocks fail validation (recovery
reorgs back and replays our own blocks from disk). Deterministic consensus
rejections are marked immediately instead of re-fetched five times; a startup
guard resets a header tip stranded on an invalid branch.

On top of that: a chain-split monitor (`bitcoinpr-core/src/splitmon.rs`)
tracks rival branches (fork point, both tips, block + chain-work deficits,
first invalid block, signaling stats) and arms the operator action at a
rival lead of 6 blocks AND the equivalent work; surfaced via
`getchainsplitinfo`, `GET /api/split`, a `ChainSplit` WebSocket event, and a
web Split page (tab visible only while the split is live — a tracked
rival at or above our chain work; gone once the rival is out-worked or
after a post-abandon restart, with the page still reachable by URL). Capitulation is persistent-flag + restart: `POST
/api/split/capitulate` (typed `ABANDON-BIP110` confirmation, same-origin +
`--webadmintoken` gating, refused while unarmed unless forced) or
`abandonbip110 [force]` RPC persists `bip110_abandoned` and gracefully shuts
down; the next start overrides `--bip110height`/the mainnet deployment,
clears the invalid markers, and the node reorgs onto the most-work chain
(`getblockchaininfo` then reports softfork status `abandoned`). Mainnet
signaling mode additionally classifies mandatory-signaling-window violations
at header level, excluding a non-signaling rival branch without downloading
any block bodies.

Three pre-existing bugs found by the new harness and fixed: a reorg-path
deadlock (the download-scheduling step re-locked `chain_state` while its own
guard was live, freezing the event loop on any reorg that schedules
downloads); missing header persistence for blocks connected via raw-block
broadcast (a fresh node IBD-ing from a single block-pushing peer wedged
header sync with "prev header has no stored data"); and header sync not
engaging for deep catch-up off a purely inbound peer.

Gating: dedicated 2-node scenario cluster (`docker-compose.split.yml`,
separate project/volumes/ports — never touches the live interop cluster) +
`scripts/interop-split-test.sh`: Core forges a >83-byte OP_RETURN block past
`--bip110height 110` via `generateblock`, the node holds its chain, the
monitor arms at +6, capitulation runs over the web API, docker restarts the
node, and it converges onto Core's chain. Full pass, plus gate.sh and the
18/18 interop suite green at every phase. 12 new unit tests across storage,
p2p, core, and web.

## Stratum Vardiff: Per-Worker Share Difficulty Ramping (2026-07-13)

The stratum gateway used to send a single static `mining.set_difficulty`
(65536, or a `--miningdifficulty` override), badly matched to small ASICs:
a ~450 GH/s bitaxe averaged one share per ~10.4 min — the same length as the
`ShareTracker` 10-min rolling window — so the dashboard flapped between
0 H/s and a single-share estimate and the worker list stayed empty. Now each
V1 connection runs classic vardiff (`bitcoinpr-mining/src/vardiff.rs`):
start at difficulty 512 (or the miner's `mining.suggest_difficulty`,
clamped, which is now honored instead of ack-and-ignored — including
mid-session), then retarget toward ~1 share per 15 s with a [7.5 s, 30 s]
dead band and a ×4/÷4 per-step clamp. Ramp-up is driven by the observed rate
(evaluated every 4 accepted shares); ramp-down by a 30 s session tick that
treats 60+ s of silence as a too-high difficulty, so a miner that never
clears the current floor still converges. Difficulty is capped at the
network difficulty (tracking chain retargets) and floored at 0.001. Every
retarget pushes `set_difficulty` plus a fresh clean job so the miner applies
it immediately. Share difficulty remains a submit-rate filter only — block
detection still checks the header hash against the job's real nBits target,
so ramping can never lose a block.

`--miningdifficulty` now means "pin the share difficulty, vardiff disabled"
(unchanged behavior otherwise); on trivial-difficulty chains (regtest,
network difficulty below the vardiff floor) the gateway keeps the old
static network-difficulty behavior, where every share is a block. The
interop cluster's `--miningdifficulty 70000` pin stays in
`docker-compose.interop.yml` deliberately: a live bitaxe mines that cluster,
and on regtest the share difficulty is really a block-cadence policy (~1
block/10 min at 450 GH/s) — removing the pin during this work turned the
bitaxe into a block-per-second firehose (~590 blocks in minutes, two subsidy
halvings, 5 interop tests broken by the racing chain) until it was restored.
Auto-ramping can't replace the pin there: vardiff targeting ~1 share/15 s
would still mean 4 blocks/min of chain pollution. 10 unit tests in
vardiff.rs.

## Web Storage Breakdown: Undo Split Out of "utxo" (2026-07-13)

The Info page's per-directory disk usage reported `utxo/` as one ~249 GiB
number, but that RocksDB holds two very different things: the live UTXO
set (`utxo` CF, ~16 GB — comparable to Core's ~13 GB chainstate) and
never-pruned per-block undo records (`undo` CF, ~230 GB; Core's equivalent
lives in blocks/rev*.dat). Labeling the whole directory "utxo" made the
UTXO set look ~17x oversized. `UtxoSet::cf_disk_sizes()` now exposes
per-CF SST totals (`rocksdb.total-sst-files-size`), and `storage_breakdown`
(bitcoinpr-web/src/api/info.rs) carves the undo CF's bytes out of the
directory total into a separate "undo" bucket — the remainder (utxo CF
plus shared WAL/meta) stays "utxo", so the buckets still sum to the real
on-disk footprint. Follow-up in TODO.md: prune undo records beyond a
reorg-safe depth to reclaim most of that 230 GB.

## Unconnecting-Header Getheaders Loop Cap (2026-07-13)

A bogus peer (`/Satoshi:0.12.0/`, claimed height 1,194,990, serving
low-difficulty headers from a foreign chain) locked the node in a
`getheaders` ping-pong for ~2 min at ~7 msgs/sec on 2026-07-12: every
unconnecting header (`HeaderSyncError::Unconnected`) triggered an
unconditional re-`getheaders` to the same peer, whose response didn't
connect either — no rate limit, no penalty. Now `HeaderSync` keeps a
per-peer counter of consecutive unconnecting-header messages
(`MAX_UNCONNECTING_HEADERS = 10`, Core's cap): below the cap the gap-fill
re-request behaves as before; at and beyond it the node stops re-requesting
and applies a new `Misbehavior::UnconnectingHeaders` penalty (20 points)
on every cap multiple, so a persistent offender walks itself to the
100-point ban. The counter resets as soon as one of the peer's headers
connects, and is dropped on disconnect. The post-sync "Clamping peer
start_height" path (a peer claiming a higher chain it cannot serve) feeds
the same penalty.

## Stratum Prevhash Byte-Order Fix (2026-07-13)

A bitaxe (~450 GH/s) pointed at the solo-mining stratum gateway showed
"1 connected worker" but an empty worker list, 0 H/s, and — after lowering
the share difficulty from the default 65536 to 1000 via `--miningdifficulty`
— every submitted share rejected as "Low difficulty share". The rejected
shares' server-computed difficulties (visible in `/api/mining/history`) were
all ~4e-10, i.e. uniformly random hashes: the server was reconstructing a
different header than the miner mined. Root cause:
`template_prev_hash_stratum` (`bitcoinpr-mining/src/template_provider.rs`)
emitted the `mining.notify` prevhash in reversed-chunk order instead of the
canonical Stratum V1 encoding (LE header words in order, bytes swapped
within each word — canonical strings end with the zero run, ours started
with it). Miners build their headers from that string, so the per-word swap
they apply (`swap_endian_words`) yielded display-order prevhash bytes and no
submit could ever match the server's reconstruction from the true
`prev_hash`.

The function had been flipped *into* the broken state by an earlier "fix"
that misdiagnosed a miner showing "BLOCK FOUND" without submitting — that
symptom was actually the static 65536 share-difficulty throttle (~1 share
per 10.4 min at 450 GH/s, the same length as the tracker's 10-min rolling
window). The flip was invisible on regtest, where a wrongly reconstructed
header still beats the trivial target ~50% of the time and the
server-assembled block (built with the correct prevhash) validates — which
also explains the long-standing regtest oddity of accepted shares and
connected blocks alongside a 0 H/s dashboard (shares were credited ~4e-10
actual difficulty).

Fixed the encoding, corrected the genesis unit test (it asserted the wrong
convention), and added a mainnet regression vector pinning the
zero-run-at-end property. Verified live: bitaxe reconnected and produced
7 accepted / 0 rejected shares in the first minute at diff 1000, worker list
and hashrate populated. Follow-up (TODO): per-worker vardiff instead of the
static difficulty cap.

Follow-up (2026-07-13, same day): `scripts/sv1_mine_one.py` was missed in
this fix — it still decoded the notify prevhash in the old reversed-chunk
order, so after the server switched to the canonical encoding the script
mined a wrongly reconstructed header, and interop test 10 became a ~50%
coin flip (the server's differing reconstruction still meets the trivial
regtest target about half the time). Updated the script to undo the
canonical per-word swap; 3/3 deterministic accepts verified.

## README Accuracy Pass (2026-07-12)

Verified the README's claims against the current code before the day's public
snapshot: unit-test count refreshed (279 → 324), the Electrum "Address
indexing" bullet updated from the retired 200-block LRU description to the
outpoint-resolver design (rolling outpoint cache, batched tx-index lookups,
partial funding-block decode), and the test-coverage paragraph now mentions
cross-block prevout resolution. Everything else checked out: 26 RPC methods,
24 outbound / 101 inbound peer targets, assume-valid at 840,000, and the CLI
flag table.

## Scripthash Backfill Efficiency (2026-07-12)

The scripthash index backfill was crawling at ~9 blocks/min (~7 s/block at
height ~400k, worsening with block size — a months-long projection for the
remaining 556k blocks) while pinning one core and issuing ~14 GB of page-cache
re-reads per indexed block (91 TB rchar in 12 h). Root cause: the prevout
resolver read and **fully deserialized the entire funding block for nearly
every cross-block input** — the old 200-block LRU had a near-zero hit rate at
these heights, and `TxIndexEntry` carries no byte offset, so a whole-block
parse was unavoidable per miss. Reworked `ScripthashIndex`
(`bitcoinpr-index/src/scripthash.rs`):

- **Outpoint cache instead of block cache** — the resolver LRU now maps
  outpoint → (scriptPubKey, value) (2M entries ≈ 300 MB), seeded with every
  indexed block's still-unspent, non-OP_RETURN outputs and popped on use (an
  outpoint spends at most once). During sequential backfill this acts as a
  rolling recent-UTXO set: young spends resolve with zero I/O. Cache is only
  used when a resolver is configured, so no-`--txindex` skip semantics stay
  deterministic.
- **Batched, grouped, parallel disk resolution** — cache misses are resolved
  per block in one batch: parallel txid → (block, tx_pos) tx-index lookups,
  grouped by funding block so each distinct block is read once, then decoded
  across up to 8 scoped threads (previously: one full block read + parse per
  input, single-threaded).
- **Partial block decode** — funding blocks are parsed transaction-by-
  transaction (`deserialize_partial`) and decoding stops at the highest
  needed tx position instead of materializing the whole block.
- **Lock hygiene** — the resolver-cache mutex is scoped to lookups/inserts
  only, never held across disk I/O or deserialization (it previously
  serialized concurrent Electrum/web queries behind the backfill).
- New test: cold-cache cross-block spend resolves via tx index + partial
  decode (funding tx at non-zero position); existing resolver/no-resolver
  tests unchanged and green. Backfill resumes from the last indexed height,
  so restarting on the new binary is safe.

Round 2 (same day): live monitoring after the restart showed ~1.6× (12 vs
7.6 blocks/min) with the cache still cold, and steady-state reads of
~4.2 GB/s — dominated not by block reads but by **tx-index point lookups**:
`TxIndex::open` cached index/filter blocks but never set a block cache, so
they were squeezed through RocksDB's tiny default LRU and every random txid
get re-read (and re-verified) MB-scale filter/index blocks.

- **`bitcoinpr-storage/src/tx_index.rs`** — dedicated 1 GB block cache;
  `optimize_filters_for_hits` (resolution lookups are for txids that exist,
  so bottom-level bloom filters rarely short-circuit anything); new
  `get_many` batched `MultiGet` lookup.
- **`bitcoinpr-index/src/scripthash.rs`** — resolver phase 1 deduplicates
  funding txids (inputs often spend several outputs of one tx) and uses
  chunked `get_many` across the worker threads instead of per-key `get`.

## Log-Level Hygiene, Round 2 — WARN Triage (2026-07-12)

Triaged the WARN messages seen during routine at-tip operation (20 in a
32-minute window) and demoted the ones that describe normal behavior:

- **`bitcoinpr-p2p/src/peer.rs`** — "Write error" on peer hang-up (broken
  pipe mid-write) `warn` → `debug`; the Disconnected event drives all cleanup.
- **`bitcoinpr/src/node.rs`** — "Header sync peer disconnected, will retry"
  `warn` → `info` (peer churn is routine); "Header sync stalled, sending
  getheaders to multiple peers" stays `warn` during IBD but is `info` once
  synced (at tip it just means a quiet spell); "Clamping peer start_height"
  `warn` → `info` (defense against lying/stale crawler nodes working as
  designed); "Cleared stale received set" `warn` → `info` (recovery path
  working as designed).
- Kept as `warn`: "Slow block connect" (>5 s is worth seeing), plus the
  head-of-line / stale-per-peer / pipeline-stall cluster — those misfire at
  tip because staleness keys off the global `last_block_connect` timer; the
  real fix (per-request timestamps in `BlockSync::in_flight`) is a TODO
  follow-up rather than a demotion, since the warns are meaningful during IBD.

## Small Fixes Batch (2026-07-12)

Four TODO follow-ups resolved, one commit each (gate green; web changes
smoke-tested against a live debug node):

- **Web: mining-tab visibility** (`022c697`) — the `mining_enabled` check that
  hides the Mining / Mining Config tabs ran only in the dashboard render, so a
  full load/refresh of `#/info` or `#/mempool` on a mining-unconfigured node
  showed the tabs until the user visited the dashboard. Now applied (with the
  footer version, same bug) once at init on every route.
- **Web: footer repo link** (`000c454`) — "Powered by BitcoinPR" links to
  <https://github.com/BitcoinPR/BitcoinPR>.
- **Dashboard script revamp** (`a463c03`) — symmetric rule + title cleanup,
  version read from the workspace `Cargo.toml`, READINESS section with
  refreshed scores (L1 90 / L2 85 / L3 50), and RPC URLs are
  credential-stripped before display.
- **Log-level hygiene** (`ba9fca6`) — periodic "Sync heartbeat" and "Pipeline
  diagnostic" lines demoted from `info` to `debug`; one-shot transitions
  ("IBD clear", busy/collapse warnings) keep their levels.

## Chain-Work Corruption Repair & Sync Wedge Fix (2026-07-11)

Fixed a mainnet-observed permanent sync wedge (commit `1493e96`): a crash left
a header's data missing while its descendants survived, `process_headers`
silently fell back to zero prev-work, and every later header stored cumulative
work that restarted from zero. The tip's work collapsed below
`nMinimumChainWork`, so header sync rotated peers forever ("empty headers below
minimum chain work") and block download re-paused with a full queue — the node
froze a few blocks behind tip while peers advanced.

- **`bitcoinpr-p2p/src/sync.rs`** — missing prev-header data is now a hard
  `Unconnected` error (triggers the existing gap-refetch recovery) instead of
  silent zero work; this was the corruption source.
- **`bitcoinpr-storage/src/header_index.rs`** — the startup integrity scan now
  recomputes cumulative chain work over its window and rewrites mismatches,
  extending past the validated tip to the header tip (`HeaderSync` seeds
  `best_chain_work` from the header tip, so poisoned work up there re-wedges
  sync — observed live at height 957648 after the first repair pass stopped at
  the validated tip).
- **`bitcoinpr/src/node.rs` / `main.rs`** — the min-chain-work download gate is
  now truly monotonic: initial pause set at startup, the event loop only ever
  opens it. The old `download_paused = !downloads_allowed` re-closed the gate
  mid-run when `best_chain_work` collapsed.
- **Verification** — regression tests for the missing-prev-data error path and
  integrity-scan repair below/above the validated tip; gate green
  (fmt/clippy/audit/machete/323 tests); fresh-cluster interop 18/18 on rebuilt
  images. Published to public `main` as `2d4316f`.

## Tor & I2P Privacy Networking (2026-07-09)

Built-in Tor and I2P transports so peer traffic can't be observed or attributed
at the IP layer by a hostile ISP. Delivered on `claude/add-tor-i2p-support-g3kg5o`
(7 commits, workspace green, `cargo fmt --check` clean, 82 p2p unit tests
passing). Both **Tor** and **I2P** items from the former Privacy & Advanced
Networking backlog are done. Everything is hand-rolled — no new dependencies —
matching the BIP-324 / DNS-worker / codec ethos. Full docs in `docs/tor-i2p.md`.

- **Shared address foundation** — new `NetAddr` type
  (`bitcoinpr-p2p/src/netaddr.rs`) supersedes `SocketAddr` across the address
  book (`peers.dat` bumped to format v2), dialer, `PeerInfo`, and gossip so
  `.onion`/`.b32.i2p` peers are first-class; IP peers behave identically.
  Includes a hand-rolled SHA3-256 (onion v3 checksum) + RFC 4648 base32, tested
  against a real v3 onion address.
- **BIP 155 addrv2** — previously received and discarded (no-op arms); now the
  node sends `sendaddrv2`, learns/stores/relays onion & I2P peers (reusing the
  legacy-`addr` storm-prevention rule), and self-advertises its own onion/I2P
  addresses.
- **SOCKS5 dialer** (`bitcoinpr-p2p/src/socks5.rs`) — RFC 1928/1929 CONNECT to
  IP and domain (`.onion`) targets with per-connection credential randomization
  (Tor stream isolation). Config: `--proxy`, `--onion`, `--onlynet` (repeatable),
  `--proxyrandomize`; `-onlynet` gates dials and skips clearnet DNS entirely in
  Tor/I2P-only mode (no DNS leak).
- **Tor hidden service** (`bitcoinpr-p2p/src/tor.rs`) — control-port client
  (`--listenonion`/`--torcontrol`/`--torpassword`): authenticates
  (HASHEDPASSWORD / SAFECOOKIE HMAC-SHA256 / COOKIE / NULL), `ADD_ONION` creates
  an ephemeral v3 service forwarding to the local listener, private key persisted
  to `<net_dir>/onion_v3_key` for a stable `.onion`, self-dial protected.
- **I2P via SAM v3** (`bitcoinpr-p2p/src/i2p.rs`) — `--i2psam`/`--i2pacceptincoming`:
  SAM v3.3 STREAM session with a persisted destination
  (`<net_dir>/i2p_private_key`) for a stable `.b32.i2p`, `STREAM CONNECT`
  outbound + a `STREAM ACCEPT` inbound loop, dispatched by `NetAddr` variant at
  the same dial choke point.
- **Reporting** — `getnetworkinfo` now populates `networks[]` (per-family
  reachable/limited/proxy) and `localaddresses`; `getpeerinfo` and the web
  dashboard show a per-peer `network` column (ipv4/ipv6/onion/i2p).
- **Verification** — unit-tested (netaddr round-trips, onion checksum, SOCKS5
  framing, Tor SAFECOOKIE HMAC RFC-4231 vector + control-reply parsing, SAM
  reply/I2P-base64 parsing, `peers.dat` v2). **Not yet run:** live smoke against
  a real `tor`/`i2pd` daemon and the interop-cluster onion/i2p case (no anonymity
  daemon in the build env) — a follow-up before relying on it in production.

## Knots-Style Relay Policy Filters (2026-07-05)

Four Bitcoin Knots relay-policy options implemented, enforced, and verified on
`claude/knots-policy-options` (gate green at every commit; 18/18 interop; not
yet merged). All policy-only: blocks containing filtered transactions still
validate. Full documentation in `docs/relay-policy.md`.

- **Config surface** — `--datacarrier` (default 1), `--datacarriersize`
  (default 83, previously fixed), `--permitbaremultisig` (default 0, Knots
  default — a default-behavior change vs BitcoinPR's prior accept-all),
  `--rejectparasites` (default 1, Knots default), `--rejecttokens` (default 1,
  stricter than Knots' 0 by operator preference). CLI flag + conf key each;
  CLI wins; Core-style bool values (`1/0/true/false/...`); bare `--rejecttokens`
  means on (conf file requires `=1`)
- **Enforcement** — per-output rules extracted from `Mempool::accept` into
  `check_output_policy`, wrapped with the parasite/token filters in
  `check_relay_policy` (mempool.rs): one choke point covering RPC
  `sendrawtransaction`, P2P tx relay, and block templates (GBT + Stratum)
- **Detection** (script.rs, beside the BIP-110 helpers) —
  `tx_first_inscription_input`: `OP_FALSE OP_IF … OP_ENDIF` envelope inside a
  structurally-recognized taproot script-path leaf (control-block shape
  `33+32m` bytes / leaf version `0xc0`, annex-aware — no prevouts at accept);
  `tx_token_protocol`: Runes runestone (`OP_RETURN OP_13`), Omni (`omni`
  payload prefix), Counterparty (`CNTRPRTY` prefix), BRC-20 (`brc-20` inside
  an envelope payload)
- **Verification** — 8 new unit tests (envelope/annex/key-path/P2WPKH witness
  shapes, all four token markers, per-flag opt-outs, configurable
  datacarriersize); two 18/18 interop runs via the recreate-only-bitcoinpr
  procedure (only `bitcoinpr-local` images rebuilt; Core/Knots/btcd/libbitcoin
  untouched); live cluster proof: omni-prefixed OP_RETURN tx rejected by
  bitcoinpr1 over both RPC and P2P while Core accepted it, then mined by Core
  into block 775 and the block accepted by BitcoinPR — policy provably does not
  touch consensus

## PHOSPHOR Web Explorer Redesign (2026-07-04)

Complete visual re-imagining of the web explorer — a "cypherpunk 8-bit"
dark-only theme, executed as 8 incremental hot-reload-reviewed steps on
`claude/web-redesign` (each committed separately, app functional throughout).
Visual/markup-only: no routes, handlers, or data models changed.

- **Token layer** — single source of truth in `static/css/style.css` `:root`:
  warm near-black surfaces, true Bitcoin orange `#f7931a` accent, cyan/green/
  amber/red semantics, 4px spacing grid, type scale, zero border radii, hard
  offset shadows; legacy variable names migrated then deleted
- **Self-hosted fonts** — Inter + Google Fonts CDN removed (zero third-party
  requests); JetBrains Mono (variable) for body/data + Silkscreen pixel font
  for display roles (logo, nav, page titles, labels), 47KB total in
  `static/fonts/`, embedded via rust-embed
- **Timechain strip** — mempool.space-inspired chain visualization: pixel-art
  block cubes with hard shadows; dashboard shows tip-adjacent dashed divider +
  pulsing striped mempool cube and a stepped slide-in animation on block
  confirmation (page updates in place via new `refreshDashboard()` instead of
  full re-render); block pages center the viewed block as an inverted
  "you are here" cube with dashed "?" ghost slots for unmined future heights
- **Per-page restyles** — 8-bit press-down buttons (pagination, prev/next,
  primary); pixel-label detail cards; tx Sankey recolored to cyan-input/
  orange-output with token-derived band palette and node-clipping fixes
  (MIN_H 40→60, wider flow stages); stepped crispEdges mempool fee chart with
  15m/30m/1h/2h timeframe selector; mining hashrate hero with blinking CRT
  cursor + segmented LED acceptance meter; pixel-glyph error/404 states
- **A11y/polish** — global `:focus-visible` outlines, orange selection, CRT
  scanlines on nav, square LED status dots, emoji removed from page titles
- **Dev workflow** — hot-reload via debug build in a `rust:1.88` container on
  the interop network (rust-embed serves `static/` from disk in debug builds);
  edit → browser refresh, no rebuilds

## Web Explorer — Peers Page Re-enabled (2026-07-02)

Per-peer `synced_height` is now tracked in `bitcoinpr_p2p::PeerInfo` from
headers/block-inv announcements, surfaced via `getpeerinfo`
synced_headers/synced_blocks and the web peers API; nav links and the `/peers`
route were restored. The page had been hidden because per-peer block heights
could disagree with the chain tip, which was more misleading than helpful.

## Code Review 2026-07-02 Fix Line — all 7 phases + follow-ups (2026-07-02)

Full-codebase standards review (archived at `docs/archive/code-review-2026-07-02.md`)
implemented end-to-end and merged via PR #43. Every phase gated on the new
`scripts/gate.sh` (fmt --check, clippy `--all-features -D warnings`, cargo audit,
cargo machete, full test suite) plus an 18/18 `interop-test.sh` run.

- **H1** — `disconnect_block` fails CLOSED on missing undo data with the typed
  `CoreError::UndoMissing { hash, height }` (pruning-aware); regression test also
  caught and fixed a latent `delete_undo` bug (in-memory undo write-buffer skipped)
- **H2** — block templates fill by descending feerate (ties by arrival time; CPFP
  documented as unsupported) instead of HashMap iteration order
- **H3** — DNS seeds resolved concurrently with a 3s per-seed timeout; outbound
  dials spawned off the P2P event loop (`OutboundConnected`/`OutboundFailed`
  events, in-flight dial dedup counted toward the outbound target)
- **Block pruning** — `--prune <MiB>` (`bitcoinpr_storage::prune`): oldest blk files
  + positions + undo records deleted past the target; 288-block keep window,
  never above the last UTXO-flushed height; BIP 159 `NODE_NETWORK_LIMITED`
  advertised instead of `NODE_NETWORK`; `pruneblockchain` RPC;
  `pruned`/`pruneheight` in `getblockchaininfo`; `find_latest_file` fixed to scan
  for the max file number (would have restarted numbering in the pruned gap)
- **M2** — block validation + mempool acceptance on `spawn_blocking` threads;
  rayon pool sized `available_parallelism()-2`
- **M9** — unknown `--network` names and malformed conf values are fatal (a typo
  no longer silently starts mainnet)
- **Refactors** — M6 `CoreError::Storage(#[from] StorageError)` + `ChainContext`
  variant; M4 seven merkle builders consolidated into `bitcoinpr_core::merkle`
  (CVE-2012-2459 detection now everywhere); M8 hot-path clone removal;
  M1 SigCache sharded 64 ways with random eviction; L3 `verify_script` drops the
  redundant `prev_output` parameter
- **Hygiene** — workspace clippy-clean with `#![warn(clippy::unwrap_used)]` on all
  8 crates; full-tree `cargo fmt`; `cargo audit` clean (anyhow/lru bumped,
  rustls-pemfile → rustls-pki-types); unused deps removed (cargo machete in gate)
- **Property tests** — u256 chainwork arithmetic vs a num-bigint oracle
  (incl. `calculate_work` vs `floor(2^256/(target+1))`); merkle module vs
  rust-bitcoin's `calculate_root`; 279 unit tests total
- **M5 deferred** as consensus surgery with cross-reference warnings on both
  script interpreters; M3 (hand-rolled BIP-324 AEAD) deferred to bundle with
  BIP-324 hardening
- **Follow-ups (found verifying live)** — Core-style version-nonce
  self-connection detection + own-external-IP dial guard + IPv4-mapped-IPv6
  canonical comparison (the seed was dialing its own gossiped address);
  per-peer `synced_height` tracked from headers/block-inv announcements *and
  blocks served via getdata* (download-only peers like Core/Knots never announce
  back), surfaced in `getpeerinfo` `synced_headers`/`synced_blocks`; **web Peers
  page re-enabled**
- **Docs** — both review docs archived; README accuracy pass (pruning + "a pruned
  node is not a full node" note, 26 RPC methods, corrected peer caps, missing
  CLI flags)

## Active Soft-Fork Audit + BIP 147 NULLDUMMY (2026-07-01)

Audited enforcement against the active-soft-fork list
(<https://d-central.tech/bitcoin-soft-forks/>). All are confirmed enforced in
`bitcoinpr-core` and shown on the dashboard: BIP 30 (duplicate txid), BIP 16
(P2SH), BIP 34 (coinbase height), BIP 66 (strict DER), BIP 65 (CLTV),
BIP 68/112/113 (CSV), BIP 141/143 (SegWit), BIP 340/341/342 (Taproot).

The audit surfaced one gap, now closed:

- **BIP 147 — NULLDUMMY** (`bitcoinpr-core/src/script.rs`) — CHECKMULTISIG /
  CHECKMULTISIGVERIFY popped the "off-by-one" dummy element but never required it
  to be empty, so a non-null dummy was accepted here while Bitcoin Core rejects it
  (a rule since SegWit activation) — a latent consensus split. Added a dedicated
  `ScriptFlags.verify_nulldummy` (bit 7 of the sig-cache key), gated in `for_height`
  on the segwit activation height and mapped from Core's `NULLDUMMY` token in the
  `core_vectors` harness. Both multisig paths now reject a non-null dummy when the
  flag is active. Covered by `test_bip147_nulldummy_checkmultisig` (rejects the
  non-null dummy for CHECKMULTISIG and CHECKMULTISIGVERIFY, accepts an empty dummy,
  and accepts a non-null dummy with the flag off). Also documented BIP 16 (P2SH) in
  the README consensus list (enforced but previously undocumented). `bitcoinpr-core`
  suite green (102 tests) incl. the Core `tx_valid`/`tx_invalid`/`script_tests`
  vectors.

## BIP-110 — Reduced Data Temporary Softfork (2026-06-30)

Implemented the seven-rule RDTS consensus softfork with UTXO grandfathering,
merged via PR #39 (8 commits, phased). Plan + design archived in
**`docs/archive/bip110-plan.md`**.

- **Phase 0 — activation gate**: `ConsensusParams.bip110_activation_height`
  (mainnet `965664`, others unconfigured) + `bip110_active(height)`;
  `--bip110height` CLI/conf override (regtest testing). *(Phase 0 also added a
  `bip110` entry to the generic versionbits tracker for signaling/dashboard; the
  signaling follow-up below superseded it with the dedicated `Bip110Checker`, and
  the now-redundant tracker entry was later removed so BIP-110 has a single source
  of truth in `crate::bip110`.)*
- **Phases 1-2 — enforcement**: per-input enforcement via
  `ScriptFlags.verify_bip110` decided from the spent UTXO's creation height
  (grandfathering). Rule 1 (output scriptPubKey ≤34 / OP_RETURN ≤83, gated on
  the spending-block height) in `validate_transactions`; rules 2-7 (push/witness
  ≤256 with BIP-16 redeemScript exemption, undefined-witness/Tapleaf reject with
  P2A exempt, annex reject, control-block ≤257, OP_SUCCESS pre-scan, OP_IF/NOTIF)
  in `script.rs`.
- **Phase 3 — policy/mining/RPC**: mempool mirrors all rules; miner signals
  bit 4 in the template version pre-activation; `getblocktemplate` advertises the
  `bip110` rule + `vbavailable`, `getblockchaininfo` reports `softforks.bip110`.
- **Phase 4 — tests**: 11 unit tests covering all 7 rules + P2A exemption +
  activation gate.

- **Signaling-driven dynamic activation** (follow-up): mainnet now computes the
  activation height from on-chain bit-4 signaling via a reorg-safe, cached
  BIP-8-style state machine (`bitcoinpr-core/src/bip110.rs`,
  `Bip110Checker`/`Bip110Deployment`), replacing the earlier fixed-height
  simplification. `connect_block` enforces mandatory signaling and grandfathers
  by the computed activation height; mempool/mining/RPC share the same checker.
  `--bip110height` remains a fixed-mode override for deterministic regtest tests.
  See `docs/archive/bip110-plan.md` §6.

Verification: full `bitcoinpr-core` suite green (101 tests incl. 16 BIP-110:
7 rules + P2A + activation gate + 5 state-machine lifecycle/reorg tests);
`scripts/interop-test.sh` **18/18 PASS** (no regression — RDTS is inactive on
regtest by default, so Core/Knots/btcd/libbitcoin interop is unaffected); live
smoke test mined 6 blocks past an activated `--bip110height=3` regtest node
(standard coinbases pass rule 1).

## Persistent blocksdir pointer (2026-06-23)

`resolve_blocks_dir` (`recovery.rs`) now writes a `blocksdir.conf` pointer file
inside `<net_dir>/` whenever a non-default blocks directory is used (via
`--blocksdir` or `--migrateblocks`). On next startup without `--blocksdir`, the
pointer is read and validated: if the saved directory has `blk*.dat` files it is
used (INFO logged); if the directory exists but is empty it is still used (fresh
target); if the directory is missing, a WARN is logged and the default is used
(external drive detached). An explicit `--blocksdir` always wins and updates the
pointer. Prevents the node from silently re-downloading the entire blockchain
when restarted without the `--blocksdir` flag.

## Stratum Solo Mining Fixes (2026-06-23)

Observed on mainnet at tip (block 954997) with a bitaxe (~500 GH/s). Four
server-side fixes:

- **Default share difficulty cap** (`template_provider.rs`) — `mining.set_difficulty`
  now capped at 65,536 when no `--miningdifficulty` override is set, so consumer
  ASICs get a reachable target instead of ~125T network difficulty. The block nBits
  in `mining.notify` remains the correct consensus value for block detection.
- **Low-difficulty share rejection** — `handle_v1_submit` checks
  `share_difficulty < min_share_difficulty` and returns typed rejection reasons.
  Caller maps reasons to proper stratum error codes (23 for low-diff, 21 for stale
  job, 20 for other) instead of generic "Job not found" for all rejections.
- **Mempool re-template throttle** — Increased from 1.5s to 30s
  (`MEMPOOL_RETEMPLATE_INTERVAL`). New-block jobs still fire immediately. Reduces
  stale share rate from ~15% to near zero for small ASICs.
- **`getblock` actual difficulty** (`server.rs`) — Replaced hardcoded `1.0` with
  `compact_target_to_difficulty(stored.header.bits.to_consensus())` so the RPC
  returns real block difficulty (~125T for recent mainnet blocks).

## Scripthash Index Backfill Improvements (2026-06-23)

- **LRU block cache in prevout resolver** (`scripthash.rs`) — 200-entry
  `Mutex<LruCache<BlockHash, Block>>` avoids redundant HDD block reads during
  backfill. Inputs overwhelmingly spend outputs from nearby blocks, yielding 90%+
  hit rate and 10-50x backfill speedup. Cache cleared automatically after backfill
  (~400 MB freed).
- **Backfill diagnostic logging** (`node.rs`) — Replaced silent nested `if let`
  chain with explicit `match` arms. Each failure path (missing header hash, missing
  block position, read error, deserialization failure) now emits a `warn!` with
  height, hash, and error. Skip count tracked and reported at completion.
- **Removed misleading IBD log** (`main.rs`) — Deleted unconditional "Scripthash
  indexing deferred until IBD completes" message that fired even when backfill was
  already running.
- **`getindexinfo` scripthash status** (`server.rs`) — Added
  `scripthash: { synced: bool, best_block_height: u32 }` to `getindexinfo` output
  via shared `AtomicU32` updated by backfill and drain loop. Operators can now
  monitor backfill progress via RPC without parsing logs.

## main.rs Decomposition (2026-06-15)

Code-review finding 2.6 (`docs/archive/code-review-2026-06-12.md`). `main.rs`
went from **4,398 → 990 lines**; the daemon now reads top-to-bottom as
config → recovery → service wiring → `Node::run()`. PRs #32/#33.

- **`config.rs`** (361) — CLI/conf parsing + merge helpers.
- **`recovery.rs`** (822) — startup phases A–D + reindex/integrity paths.
- **`node.rs`** (2,784) — the `Node` struct, the event loop, graceful shutdown,
  and the extracted low-coupling `NodeEvent` handlers (PeerConnected/Disconnected,
  NotFound, BlockInv, Transaction).
- **`SyncState { Download, Replay { end_height } }`** replaces the
  `replay_active`/`replay_end_height` flag pair (scoped: `is_ibd` and
  `header_sync.synced` stay authoritative — see the archived 2.6 banner).

Behaviour-preserving: the event-loop body was moved verbatim (machine-verified
byte-identical), each step gated at **17/17 interop** with the workspace tests
green.

## Code Review 2026-06-12 Fix Program (2026-06-15)

All blocking/high/medium findings from the 2026-06-12 full-codebase review,
closed across PR #31 (then #32/#33 for the decomposition above). Each gated on
the workspace suite + a 17/17 interop run; full per-finding detail in
`docs/archive/code-review-2026-06-12.md`, current snapshot in
`docs/code-review-2026-06-17.md` (the 06-15 snapshot is archived alongside it).

- **Consensus:** mempool/template nLockTime finality + BIP-68 sequence locks at
  acceptance *and* template assembly (parents-before-children); fail-closed on
  missing chain context (MTP/nBits/BIP-68 lookups error instead of accept);
  side-chain retarget ancestor walk (`HeaderIndex::get_ancestor`); header-level
  retarget rejection with peer scoring; clock-panic guards.
- **Robustness/DoS:** per-command codec size caps with incremental reads; the
  unwrap sweep (`#![warn(clippy::unwrap_used)]` on -core/-p2p/-storage, 0
  residual); the Core-semantics mempool policy engine (64 MiB byte budget,
  feerate eviction, descendant limits, RBF descendant cleanup, min-relay/dust).
- **Eclipse/restart:** addrman + banlist persistence with outbound anchors.
- **Spec/security:** BIP-324 record-layer FSChaCha rekeying (vector-verified;
  socket wiring still pending); same-origin CORS + token-gated mining-config;
  health-endpoint slowloris hardening; persisted Electrum TLS cert.

Three additional latent bugs were found and fixed during verification
(`is_ibd` never cleared on the RPC-mining path, unconnecting-header announcements
warn-dropped without gap-fill, and an unordered template emitting a child before
its parent).

## Core Script-Vector Test Harness (2026-06-10)

Code-review item #3 (testing, §3.2): a `script_tests.json`-format vector runner
inside `bitcoinpr-core/src/script.rs` (`core_script_vectors`). It parses Core's
script-assembly grammar (decimal numbers → minimal `CScriptNum`, `0x..` raw
bytes, `'strings'`, opcode names), parses the flags string into `ScriptFlags`,
builds Core's exact crediting/spending transaction pair, and runs each vector
through our real `verify_script`, asserting `OK` vs failure.

Seeded with the deterministic (non-signature, non-tx-context) subset of
`script_tests.json` — stack, numeric, boolean, and push semantics (25 vectors,
all passing). The harness is structured so signature / CLTV / CSV vectors and a
larger verbatim import can be added later (the tx builders already match Core's
`BuildCreditingTransaction`/`BuildSpendingTransaction`, so precomputed signature
vectors will validate). Tracked as a follow-up.

## Difficulty-Retarget Enforcement + Sigop Weight Parity + pow_limit fix (2026-06-10)

Completes code-review item #4 §2.1: the last two consensus rules that were
warn-only or diverged from Core. Verified by `cargo test` (62 core tests) and a
**14/14** `scripts/interop-test.sh --quick` run.

- **Difficulty retarget now rejected, not warned** — new
  `validation::get_next_work_required` (a faithful port of Core's
  `GetNextWorkRequired`: no-retargeting, the testnet/testnet4 20-minute
  minimum-difficulty rule, within-period inheritance, and the 2016-block
  boundary recompute). `connect_block` now rejects any block whose `nBits` don't
  match the required target (skipped for signet, whose validity is the challenge
  signature). The regtest cluster exercises the no-retargeting (`bits == prev`)
  path; the retarget math is unit-tested for clamp behaviour.
- **Sigop counting now matches Core's weighted cost** — replaced the flat
  `accurate-count ≤ 80000` (4× too lenient) with `MAX_BLOCK_SIGOPS_COST`: legacy
  sigops ×4 + P2SH redeem-script sigops ×4 + witness sigops ×1
  (`script::p2sh_redeem_script`, `script::witness_sigop_cost`).
- **pow_limit corrected (pre-existing bug)** — `pow_limit_mainnet`/`testnet`
  returned `0x00000000ffff…ffff` (2^224-1) instead of Bitcoin's actual
  difficulty-1 target `0x00000000ffff0000…0`. The oversized value made the header
  target check lenient and would have mis-capped retargets near the limit on
  testnet (potentially rejecting valid min-difficulty retarget blocks). Now the
  correct difficulty-1 target (compact `0x1d00ffff`); regtest/signet limits
  unchanged. Found while adding retarget enforcement.

**Caveat:** the retarget and sigop paths cannot be exercised by the regtest
interop cluster (regtest has no retargeting and trivial sigop counts); they are
covered by unit tests and a faithful port of Core's algorithms, but have not been
integration-tested against a live mainnet/testnet retarget boundary.

## Consensus Enforcement + Low-Hanging Fixes (2026-06-10)

Code-review priority items #3 (low-hanging §1.1–1.5) and the first half of #4
(consensus enforcement §2.1) and #5 (exact chain-work §2.3). All verified by
`cargo test` and a **14/14** `scripts/interop-test.sh --quick` run against the
live 5-node cluster (incl. Bitcoin Core and Knots).

**Exact chain-work (§2.3)** — `bitcoinpr-core/src/validation.rs` `calculate_work`
replaced the approximate u128 math (which discarded the low 128 bits of the
target in one branch and could misorder near-equal chains during fork choice)
with Bitcoin Core's exact `(~target / (target+1)) + 1` via 256-bit long division.
Unit-tested against the known genesis chainwork `0x100010001` and pow_limit `2^32`.

**Consensus rules now enforced (§2.1)** — previously implemented-but-unenforced
or checked-and-ignored rules, any one of which could split us from the
Core-following network:
- **CheckTransaction sanity** (`validation::check_transaction`, called per-tx in
  `chain.rs` and in mempool): empty vin/vout, per-output and total value range
  (`MAX_MONEY`), duplicate inputs within a tx, null non-coinbase prevouts.
- **CVE-2012-2459 merkle mutation** — `verify_merkle_root_with_txids` now rejects
  blocks whose merkle tree is mutated (duplicate txs arranged to reproduce the
  root), via a faithful port of Core's `MerkleComputation` mutation flag.
- **Median-time-past (BIP 113)** — block timestamp must be strictly greater than
  the MTP of the previous 11 blocks.
- **nLockTime finality** (`validation::is_final_tx`) enforced at block connect.
- **BIP 68 relative locktimes** (`validate_sequence_locks`) wired into
  `connect_block` with per-input confirmation heights and (for time-based locks)
  the MTP at `coinHeight-1`, matching Core's `CalculateSequenceLocks`. Gated on
  the CSV buried height; no-ops for v1 txs / disable-bit inputs (the common case),
  so the per-input MTP lookups only happen for genuine relative-locktime txs.
- **10,000-byte script size limit** in the legacy/SegWit-v0 interpreter.
- Difficulty-retarget *rejection* and sigop weight parity are the remaining §2.1
  items, tracked separately.

**Low-hanging fruit (§1.1–1.5)**
- Removed leftover debug logging in `chain.rs` (heights 390–400).
- P2P codec now validates the network magic before allocating for the payload
  (`bitcoinpr-p2p/src/codec.rs`); wrong-network/garbage traffic is rejected.
- Mempool `add_transaction`: removed a second UTXO lookup whose `.unwrap()` could
  panic on a race with a concurrent block connect (prevouts now collected in the
  first pass); ancestor-limit check moved before RBF eviction so a rejected
  replacement no longer drops the originals; `remove_for_block` now clears *all*
  outpoints of an evicted conflicting tx (no more dangling `spent_outpoints`).
- Difficulty-retarget timespan computed in signed `i64` (no u32 underflow when
  timestamps go backwards across a period).

**Stratum timestamp fix (necessitated by MTP enforcement)** — the V1/SV2 template
provider now hands miners an `ntime` clamped to `max(now, MTP+1)` (new
`TemplateData.min_time`). Without this, after rapid mining pushes recent block
timestamps ahead of wall-clock, a Stratum-mined block carried `ntime <= MTP` and
was (correctly) rejected by the new MTP rule — and would have been rejected by
Core/Knots too. interop test 9 (Stratum V1 mining) passes again.

## Security Fixes — RPC Auth & Sig-Cache Verification Bypass (2026-06-10)

First two **critical** findings from the full code review (`docs/code-review-2026-06-10.md`):

- **RPC authentication is now enforced** (`bitcoinpr-rpc/src/auth.rs`, `server.rs`, `bitcoinpr/src/main.rs`). Previously `RpcState.auth_header` was populated but never checked — every method (`stop`, `sendrawtransaction`, `generatetoaddress`, …) was open to anyone who could reach the port. Added an `AuthLayer` tower middleware wired via jsonrpsee's `set_http_middleware`, so HTTP Basic credentials are validated (constant-time compare) before method dispatch; missing/wrong credentials get `401 Unauthorized`. The node now also **refuses to start** when RPC is bound to a non-loopback address while still using the default `rpcpassword`. Verified live against the interop cluster: no-creds → 401, wrong-creds → 401, `test:test` → 200.
- **Sig-cache script-verification bypass fixed** (`bitcoinpr-core/src/script.rs`, `chain.rs`, `mempool.rs`). `SigCache` was keyed by `(txid, input_index)`, which doesn't commit to witness data: an attacker could relay a valid tx (caching its txid) then mine a block carrying the same txid with a malleated/invalid witness, and the cache hit would skip verification — accepting an invalid block. The key is now `(wtxid, input_index, flags)` (commits to witness, and scopes the result to the rule set it was checked under). Verified: r1-mined blocks still validate and connect on r2 (height 170→172, tips agree).

Remaining critical/high items from the review (consensus under-enforcement, exact chain-work math, codec size caps, unwrap sweep, mempool policy) are tracked in `docs/code-review-2026-06-10.md` §2/§4.

## IBD Download Optimization (2026-06-08)

Nine-item optimization pass targeting the Jun 7–8 micro-stall (1 b/min, 1 good_peer, 11k channel drops, orphan/getheaders storms). See `docs/ibd-comparison.md`.

- **Adaptive stale timeout** (`bitcoinpr-p2p/src/ibd.rs`, `main.rs`) — `stale_base_timeout(height)` scales 30s / 120s / 300s by era; stale-clear debounce and connect gate scale with it.
- **Gate orphan-while-synced** (`main.rs` `handle_received_block`) — orphan getheaders only when `!is_catching_up(block_tip, header_tip)`; stuck-orphan maintenance path gated the same way.
- **Throttle replay scheduling** (`main.rs`) — skip `replay_active` when `block_pos` missing; 30s debounce after zero-block replay ends before re-queue/post-replay getheaders.
- **Fix block position reindex** (`bitcoinpr-storage/src/block_store.rs`) — only index on-disk blocks whose hash matches the canonical height→hash entry (fork/orphan positions no longer block replay).
- **Relax good-peer filter** (`bitcoinpr-p2p/src/ibd.rs`, `main.rs`) — `NETWORK_LIMITED` peers eligible for historical `getdata` when `header_tip - block_tip > 10_000`; centralized `eligible_download_peer_ids()`.
- **Dedicated block-ingestion path** (`manager.rs`, `main.rs`) — 16K-capacity `block_event_tx` separate from 4K `node_event_tx`; blocks no longer compete with headers/inv/tx.
- **Peer maintenance under single-peer download** (`manager.rs` `RefreshPeerConnections`, `main.rs`) — when `good_peers <= 2` and gap > 10K, disconnect height=0 inbound peers and dial fresh outbound archive nodes.
- **Skip fork-header work during deep IBD** (`sync.rs` `process_headers`) — minority-fork header batches skipped when `is_catching_up()`.
- **Pipeline diagnostic → action** (`main.rs`) — when `good_peers <= 2 && queue > 5K && stalled 60s+`, emergency `assign_to_peers_emergency`, aggressive peer refresh, disconnect worst stale-cycle peer.

## Reorg Height→Hash Index Fix — Spoke Stranding (2026-06-05)

The last interop reorg-propagation failure. When the **seed** reorged from chain A
onto a peer's deeper competing chain C, only its block tip and the chain-C *tip*
height→hash entry updated; the **intermediate** reorged heights kept pointing at
the orphaned chain. Reproduced with a controlled pause-partition deep fork: seed
tip = 13c, `getblockhash(13)` = 13c ✓ but `getblockhash(12)` = **12a** and
`(11)` = **11a** (orphan chain-A hashes). So when a spoke (bitcoinpr2 **or** Bitcoin
Knots) sent getheaders with its chain-A locator, the seed matched the locator's
`12a` against its own stale `get_hash_at_height(12) == 12a`, concluded the peer was
already at height 12, and returned only the tip header `13c` — whose parent `12c`
the peer lacked — so the spoke buffered `13c` as an orphan and stayed on the losing
chain **forever** (knots verified stuck >90 s even as the seed mined on).

- **`ChainState::connect_block` now writes the height→hash index** (`bitcoinpr-core/src/chain.rs` via new `HeaderIndex::set_height_hash`, `bitcoinpr-storage/src/header_index.rs`). `CF_HEIGHT_INDEX` was previously written only by header-first sync and RPC `generate` (`insert_header*`); a reorg connects the new chain's blocks through `connect_block` alone, without re-inserting their headers, leaving the intermediate heights stale. The new per-connect write establishes the invariant "`CF_HEIGHT_INDEX[h]` == the block connected at `h` on the active chain", covering all connect paths (sync, RPC, Stratum, reorg).
- **Verified:** controlled deep-fork reorgs now propagate to all spokes (incl. Knots) in **0 s** (was: stranded indefinitely); `scripts/interop-test.sh --quick` is **14/14 PASS** — the non-seed propagation probes (16/17) converge in ~7 s instead of timing out. (The earlier "equal-height tie" worry was a symptom, not a cause: ties only formed *because* propagation failed; with propagation fixed each probe extends cleanly.)

## Block-Store Read-Your-Writes Race (2026-06-05)

A node could **silently fail to serve a just-connected block to a peer**, which
stranded that peer after a reorg (the peer's getdata got silence, not the block).
Found while chasing the interop reorg-propagation failures: `store_block_async()`
returns a `BlockPos` and writes `set_block_pos` immediately, but queues the actual
flat-file write to a background thread, so a read right after connect (serving via
getdata, or reading reorg blocks for propagation) races ahead of the write and
hits NotFound / "failed to fill whole buffer" (UnexpectedEof) / a partial size
header. The seed's getdata handler then logged a WARN and served **nothing** —
observed live: the seed dropped reorg blocks to Bitcoin Knots, which stuck a block
behind, while a peer requesting the same block ~1 ms later got it fine.

- **`BlockStore::read_block` retry-after-flush** (`bitcoinpr-storage/src/block_store.rs`) — on any read error, drain the writer queue via `flush()` and retry once (read-your-writes for the serve/replay/reorg paths). The common already-on-disk case is unaffected (succeeds first try, no flush).
- **getdata serves `notfound` on read failure** (`bitcoinpr-p2p/src/manager.rs`) — when a block read still fails after the retry, send an explicit `notfound` so the peer re-requests elsewhere promptly instead of stalling on silence.

## Post-IBD Gap / Stuck-Node Recovery (2026-06-05)

Follow-up to the relay fix: a BitcoinPR node that fell behind **after** IBD (missed
an intermediate block, so later blocks buffered as orphans) could get stuck one or
more blocks behind **forever** — the IBD safety nets (`main.rs` ~3586) only run
while `is_ibd` is true, and the recovery getheaders used a header-tip-anchored
locator that made the sync peer answer with 0 headers. Verified live: bitcoinpr2,
stuck 16 min at height 247 while the cluster was at 250, healed to the tip within
~15 s of deploying these fixes.

- **Block-tip-anchored getheaders** (`bitcoinpr-p2p/src/sync.rs` `build_getheaders_command_from`) — a locator variant anchored at the *connected block tip* rather than `header_sync.best_height`. When the header tip has run ahead of what we've connected (accepted-but-unconnected fork headers, or a missing intermediate block), the header-tip-anchored locator's top hash is a height the peer recognises as its own tip, so it returns 0 headers and the gap never heals. The connected-tip anchor guarantees the peer serves forward (including a more-work fork from its fork point). Wired into the orphan-while-synced path (`main.rs`).
- **Height→hash index repair in `process_headers`** (`bitcoinpr-p2p/src/sync.rs`) — the smoking gun for the permanent stall: a node had block 248's header in `CF_HEADERS` but a **gap at 248 in `CF_HEIGHT_INDEX`** (a prior crash/reorg left them inconsistent). `process_headers` `continue`d on the already-known header without repairing the index, and the block re-request loop (`for h in start..=tip { get_hash_at_height(h) }`) silently skipped the missing height, so block 248 was never requested. Now, on an already-known header, repair the missing/stale height→hash entry and advance the chain walk from it.
- **Idle-pipeline fast recovery** (`bitcoinpr/src/main.rs`) — when the download pipeline is idle (nothing in flight/queued) the block re-request debounce drops from 60 s → 15 s (kept at 60 s during active IBD so we don't spam peers). Plus a stuck-with-orphans detector: if synced, the pipeline is idle, and orphan blocks are buffered, re-ask the best peer for headers anchored at the block tip every ~10 s (the per-arrival orphan getheaders only fires when a *new* orphan lands, so a node holding already-buffered orphans needs this nudge).

## Interop Findings Fixes (2026-06-05)

Three of the four 2026-06-04 interop findings resolved, plus the relay half of the
fourth. Verified against the live 5-node regtest cluster.

- **#1 relay peer-received blocks** (`bitcoinpr/src/main.rs`, `bitcoinpr-p2p/src/manager.rs`) — The drain loop that connects peer-sourced blocks never re-announced them; only the self-mine paths (Stratum `template_provider.rs`, RPC `submit_block`/`generate_to_address`) sent `PeerCommand::BroadcastBlock`. Now, after a peer block connects while not in IBD, `main.rs` sends `BroadcastBlock` to re-announce via inv/headers (the block is already in the block store from `connect_block_with_raw`, so the follow-up `getdata` is servable — this also defuses the getheaders→`notfound` livelock). The `manager.rs` `Inv` handler now skips `getdata` for blocks already in our store (`get_block_pos`), so the re-announce fan-out can't echo into a request storm. **Result:** a block mined on any non-seed node propagates cluster-wide in 0–11 s (was unreliable/never). The post-IBD *reorg-across-forks* latency is split out as the remaining open item under Pending Work.
- **#2 Core tx reaches BitcoinPR mempools** (`bitcoinpr/src/main.rs`) — The inbound-tx handler (`NodeEvent::Transaction`) silently dropped txs whose inputs weren't in the chain UTXO set. Reworked to resolve inputs from the chain UTXO set **or** an existing mempool tx (chained/package prevout), and to never drop without a logged reason. A Core `sendtoaddress` tx now relays into all four RPC mempools (harness test 6 passes).
- **#3 log a reason for every rejected inbound tx** (`bitcoinpr/src/main.rs`) — The former silent `trace!` drops (IBD-skip, inputs-unknown) and the mempool-reject are now a single explicit `debug!("tx rejected: <reason>", …)` so this class of bug is self-evident in logs.
- **#4 expose peer direction in `getpeerinfo`** (`bitcoinpr-rpc/src/types.rs`, `server.rs`) — `PeerInfo.inbound` was tracked correctly (and already used by `getnetworkinfo`) but the `PeerInfoEntry` getpeerinfo response omitted it. Added `inbound: bool`. Verified live: hub reports its spokes `inbound:true`, the outbound dialer reports `inbound:false` (harness test 2 passes).

## Interop Cluster Findings (2026-06-04)

Surfaced by the new end-to-end harness `scripts/interop-test.sh` against the
5-node docker regtest cluster (`docker-compose.interop.yml`). The harness re-runs
all of these (`./scripts/interop-test.sh`, or `--quick` to skip the restart
phase) and prints a timed pass/fail/observation report. See memory
`interop-nonseed-relay-unreliable`.

**Resolved 2026-06-05** — see the two **Interop Findings Fixes** entries under
Completed: #2/#3/#4 and the relay half of #1, plus the post-IBD *gap/stuck-node*
recovery. The remaining open item is multi-step reorg **latency** under
competing peer forks, below.

All four 2026-06-04 findings and the follow-on reorg work are now **resolved** —
`scripts/interop-test.sh` reports **18/18 PASS** (the suite has since grown from
14 to 18 tests, and the cluster from 5 to 6 nodes with btcd). See the Completed
entries below.

## IBD Notification Flood — Live Catch-Up Gate (2026-06-03)

`is_ibd` is a one-way latch (`main.rs:1673`): set `true` at startup, only ever `swap(false)` at four sites, never re-armed. The web UI, Electrum server, and mining gateway all suppressed per-block activity by reading this latch. But the clear conditions can be satisfied transiently before the chain is actually synced (e.g. `header_sync.synced` flips `true` on any <2000-header batch — including an empty `headers` message from a lagging/caught-up peer — while the block tip momentarily equals `header_sync.best_height`). Once cleared mid-IBD the latch never re-arms, so a mainnet node in IBD toasted a "new block" for every connected block (web unusable), flooded subscribed Electrum wallets, and could start mining on a stale tip. RPC was unaffected because `getblockchaininfo` computes IBD live (`bitcoinpr-rpc/src/server.rs:158`).

Fix: replace latch reads with a self-correcting live check — `header_tip - block_tip > MARGIN` (margin 4), using `HeaderIndex::get_header_tip_height()` (the downloaded-header tip) — in all three consumers:
- **Web** (`bitcoinpr-web/src/ws.rs`) — `is_catching_up()` gates `NewBlock` WS forwarding.
- **Electrum** (`bitcoinpr-index/src/electrum.rs`) — `is_catching_up()` gates the `NewBlock`/`NewTx` client notifications and the keepalive heartbeat (so a stuck-`true` latch can no longer suppress the heartbeat forever either).
- **Mining** (`bitcoinpr-mining/src/template_provider.rs`) — `is_catching_up()` gates job push, mempool re-templating, and the connect-time work-deferral loop. Subsumes the old "at genesis" special case (header_tip == block_tip == 0 ⇒ gap 0 ⇒ work served immediately). The vestigial `is_ibd` plumbing is left in place (underscored where unused).

## Cross-Block Spend Indexing & Forward Sankey Flow (2026-06-03)

The scripthash address index only recorded *received* outputs (and intra-block spends), so a transaction that spent an output funded in an earlier block never appeared in the spending address's history. Electrum clients — which derive a wallet's UTXO set and tx confirmations purely from address history — therefore kept already-spent coins as live UTXOs (causing `missing input UTXO` errors on rebroadcast) and could not promote send-only transactions out of "Local" status. Sparrow was unaffected because it SPV-verifies known txids directly.

- **`ScripthashIndex` cross-block spend indexing** (`bitcoinpr-index/src/scripthash.rs`) — `index_block_transactions` now attributes every non-coinbase input to the prevout's scripthash. Intra-block spends are resolved from the block; cross-block spends use an optional prevout resolver (`set_prevout_resolver`) that recovers the spent scriptPubKey + value via the tx index + block store. Balance is now a signed per-block delta (outputs add, spends subtract, saturating at zero) instead of cumulative lifetime-received. Wired in `main.rs` where the index is constructed (requires `--txindex`; logs a warning otherwise). `listunspent` is correct automatically once the spend is in history. Existing indexes need `--reindex` to backfill historical spends. Unit tests cover the resolver and the no-resolver fallback.
- **Forward Sankey flow expansion** (`bitcoinpr-web/src/api/txs.rs`, `static/js/app.js`) — `get_outspends` now resolves the spender of a *confirmed* output (previously `txid:null`) by scanning the output address's scripthash history for the input that consumes the outpoint (bounded to 1000 candidate txs). The explorer's already-built forward-expand `+` button now lights up for confirmed spends, not just mempool spends, so you can follow the money forward across blocks.

## Header-Gap Re-sync & Infinite `getheaders` Loop Fixes (2026-05-31)

Both bugs originally documented under "Pending Work" on 2026-05-30; reproduced
on a testnet4 restart after the PR #25 merge (validated tip 133633, header tip
137173, 26,951 broadcast iterations over ~2 min with only 103 blocks validated).

**Header-gap re-sync (durability):**
- **`HeaderIndex::flush_wal()`** (`bitcoinpr-storage/src/header_index.rs`) — new method that calls `db.flush_wal(true)` to fsync the RocksDB WAL on demand.
- **`ChainState::connect_block`** (`bitcoinpr-core/src/chain.rs`) — calls `header_index.flush_wal()` at the UTXO flush boundary (after `set_best_tip` + `set_validated_height`). Guarantees: when `best_tip` is durable at height N, every height→hash entry for blocks ≤ N is on disk. One fsync per ~500 blocks during IBD.
- **`verify_chain_integrity` logging** — gap warnings now spell out the exact missing height, scan-start, and best-height in both the structured fields and the message string, so the next restart's logs immediately show whether the gap is new or pre-existing.
- **Block file reindex shutdown guard** — new `BlockStore::reindex_block_files_cancellable(&HeaderIndex, Option<Arc<AtomicBool>>)` checks `shutting_down` between files. Wired up at the background-spawn site in `main.rs` so the reindex thread stops within one file-scan of shutdown instead of running 48 min past it. Original `reindex_block_files(&HeaderIndex)` signature preserved (delegates with `None`) so the integrity-scan call path in `main.rs` is untouched.

**Infinite `getheaders` loop (post-replay broadcast):**
- **`main.rs` post-replay broadcast** — three guards added in the post-replay fan-out block:
  1. Skip if `block_sync.queue` or `block_sync.in_flight` is non-empty (nothing new to discover until pending downloads land).
  2. Skip if `last_post_replay_getheaders_height` already equals the current validated tip (replay ending at the same height means no progress; re-asking the same peers returns the same answer).
  3. Pick the single peer with the highest `start_height` instead of fanning out to all peers (the shotgun was the direct cause of the feedback loop; the gate naturally lifts when the tip advances).

## Electrum Mempool, Stratum & CLI Fixes (2026-05-30)

**Electrum mempool support** (`bitcoinpr-index/src/electrum.rs`) — surfaces unconfirmed transactions to connected wallets via a shared `scan_mempool_for_scripthash()` helper (prevout resolution order: other mempool txs → UTXO set → tx index/block store):
- `compute_scripthash_status()` walks the mempool for txs paying to OR spending from the scripthash and appends `"txid:height:"` entries (height 0, or -1 when an input spends another unconfirmed tx) after the confirmed entries before the SHA256. Confirmed-only output is byte-identical when the mempool is empty, so existing status hashes are unchanged.
- `handle_client` now handles `NodeNotification::NewTx`: it resolves the tx, collects all affected input (resolved-prevout) and output scripthashes, and pushes `blockchain.scripthash.subscribe` status updates to subscribed clients (previously only `NewBlock` was handled).
- `get_history` appends mempool entries (height 0/-1) after the confirmed history; new `get_mempool` returns only the unconfirmed subset; `get_balance` computes the `unconfirmed` field from the mempool on demand.

**`generatetoaddress` pushes a new Stratum job** — `RpcState` carries an `Option<Arc<EventBus>>`, and `generate_to_address()` publishes `NodeNotification::NewBlock { hash, height }` after each successful `connect_block`. The Stratum template provider re-issues jobs on the new tip immediately, so RPC-mined blocks no longer leave connected miners (e.g. bitaxe) on a stale prevhash.

**Web dashboard peer `synced_height` via `inv`** — new `NodeEvent::BlockInv(PeerId, Vec<BlockHash>)` is published by the P2P manager when a peer announces block hashes via `inv`. The coordinator resolves those hashes against the header index and advances the web `PeerEntry.synced_height`. This works regardless of whether peers echo `headers` announcements, so the dashboard shows correct per-peer block counts even when all nodes start at genesis.

**Shutdown-aware scripthash backfill** — `spawn_scripthash_backfill()` takes the shutdown `AtomicBool` and checks it every 100 blocks, breaking early (and clearing the running flag) when set. Safe to interrupt because `META_INDEXED_HEIGHT` is written per block (`scripthash.rs:169`) and startup resumes the backfill from the last indexed height. Eliminates the multi-hour shutdown delay on mainnet with a high `--dbcache`.

**`--jsonlog` wiring** — logging now installs JSON `tracing_subscriber::fmt` layers (both stdout and file, via `.json().boxed()`) when `--jsonlog` is set, falling back to the human-readable format otherwise. `jsonlog` is parsed from `bitcoinpr.conf` and documented in `example.bitcoinpr.conf`. A new `parse_conf_bool()` helper makes all boolean conf options accept `1`/`0`/`yes`/`no`/`on`/`off` in addition to `true`/`false` — previously only `true`/`false` parsed, so the `=1` syntax documented throughout `example.bitcoinpr.conf` (e.g. `txindex=1`) silently failed.

## Event Loop Starvation & Peer Discouragement Fix (2026-05-10)

Root cause analysis of multi-hour sync stalls on mainnet (height ~367K) and testnet4 (height ~133K). Peers were disconnecting and adding our IP to their discouraged list due to pathological behavior caused by event loop blocking.

- **Chunked local replay** — `block_in_place(replay_loop)` that blocked the event loop for hours replaced with async 100-blocks-per-tick batched replay. The P2P event channel (4096 capacity) was overflowing within 30 seconds of blocking, causing 508+ block drops on mainnet.
- **Background reindex** — `block_in_place(reindex_block_files)` (17+ minutes per scan) moved to `tokio::task::spawn_blocking()`. Added once-per-session guard to prevent repeated scans on every header sync completion.
- **Removed nuclear peer reset** — "Disconnect ALL peers after 5 minutes of no blocks" created a rapid connect→getdata→silence→disconnect→reconnect cycle (every 30s) that triggered Bitcoin Core's anti-DoS discouragement. Individual stale-peer eviction handles non-deliverers without burning all connections.
- **Replay-aware gating** — Shotgun-requesting, stale-clearing, and download scheduling skip while `replay_active` is true, preventing the node from blaming peers for "non-delivery" when blocks are being replayed from local disk.
- **Per-peer batch reduction** — `max_per_peer` reduced from 64 to 16 (matches Core's limit) to reduce wasted in-flight slots when event loop falls behind.

## Pruned Peer Handling & Stall Recovery (2026-05-07)

- **`notfound` message handling** — Peers that respond with `notfound` (pruned nodes lacking historical blocks) now trigger immediate re-queue and reassignment to other peers, instead of waiting 90s for stale timeout. Added `NodeEvent::NotFound` and `BlockSync::blocks_not_found()`
- **Peer rotation for chronic non-deliverers** — Track per-peer `notfound` count and stale-cycle count; auto-disconnect peers with >50 notfound blocks OR 3+ stale-clear cycles without any delivery via `PeerCommand::DisconnectPeer`, freeing connection slots for full nodes
- **Preserve bandwidth EWMA across stale clears** — Stale-clear no longer wipes `peer_bandwidth`, so the weighted assignment retains knowledge of which peers are fast vs. slow
- **Expanded head-of-line unblocking** — Now handles blocks stuck in `queue` (not just `in_flight`), covering the window when stale-clear moves the critical next block between tracking structures
- **Silent non-deliverer eviction** — Peers that silently ignore `getdata` (no `notfound`, no response) are tracked via `peer_stale_cycles`; evicted after 3 failed rounds in both the per-peer stale clear and pipeline stall recovery paths

## P2P & Download Pipeline Overhaul (2026-05-06)

- **Bandwidth-weighted peer selection** — EWMA per-peer throughput tracking (α=0.3), proportional block allocation (faster peers get more blocks), per-1000-block bandwidth logging
- **Per-peer stale clearing** — Reverse index for O(1) per-peer cleanup, graduated timeout (120s base + 500ms per assigned block), only re-queues from the specific stale peer
- **Scripthash IBD deferral** — Skip index writes during IBD via `is_ibd` gate, automatic backfill on IBD completion
- **Head-of-line unblocking** — When chain stalls waiting for a specific block, re-request it from the fastest available peer after 10s (eliminates multi-hour stalls from out-of-order delivery)
- **Non-blocking channels** — Replaced all blocking `send().await` with `try_send()` on inter-task channels (node_event: 256→4096, command: 256→1024, peer_event: 256→1024) to prevent bounded-channel deadlock between main event loop and PeerManager
- **Maintenance starvation fix** — Replaced `continue` in empty-headers handler with if/else fallthrough so drain loop, stale clearing, re-requests, and pings always execute
- **P2P protocol alignment** — `TcpStream::into_split()` for independent read/write halves (no mutex), TCP_NODELAY, 16-block getdata chunks matching Core's MAX_BLOCKS_IN_TRANSIT_PER_PEER, write-loop sends disconnect events, height=0 honeypot peers filtered from block downloads
- **Pipeline diagnostic** — Logs in_flight/queue/pending/peers every 60s when stalled for debugging

## IBD Download Optimization

Reduce download stalls that dominate sync time (blocks validated faster than they arrive).

- **Increase outbound peer count** — 8 → 24 outbound with 128-block batches for more download parallelism
- **Bandwidth-weighted peer selection** — EWMA tracking (α=0.3, default 500KB/s), proportional allocation gives faster peers more blocks
- **Per-peer stale clearing** — Reverse index (`peer_requests: HashMap<PeerId, HashSet<BlockHash>>`), graduated timeout (120s + 500ms/block)
- **Disable scripthash indexing during IBD** — Gate on `is_ibd` flag, backfill on completion via `spawn_scripthash_backfill()`
- **Head-of-line unblocking** — Re-request specific stalled next-in-sequence block after 10s from fastest peer
- **Non-blocking channels** — `try_send()` on all inter-task channels (node_event 4096, command 1024) to prevent bounded-channel deadlock
- **P2P protocol fixes** — `into_split()` (no mutex), TCP_NODELAY, 16-block getdata chunks, write-loop disconnect events, height=0 peer filter
- **Handle `notfound` responses** — Peers that can't serve historical blocks (pruned) now trigger immediate re-queue and reassignment to other peers instead of waiting for 90s stale timeout
- **Peer rotation for non-deliverers** — Track per-peer `notfound` count, auto-disconnect peers with >50 failed blocks to free connection slots for full nodes
- **Preserve bandwidth data across stale clears** — EWMA history no longer wiped on stale-clear, improving weighted assignment quality
- **Expanded head-of-line unblocking** — Now handles blocks in queue (not just in-flight), covering the gap when stale clear moves the critical block between tracking structures
- **Address manager peer learning** — Wire up `mark_good()`/`mark_failed()` in connect/disconnect paths; use `get_for_connect()` reliability-sorted list for reconnection instead of raw DNS, reducing early-eof peer churn from 189 to ~10 disconnects per cycle
- **Getdata write-failure disconnect** — When `getdata` send fails (broken pipe), immediately disconnect and re-queue blocks instead of waiting for stale timeout
- **Rotating head-of-line peer selection** — Use attempt counter instead of `height % peers` so stuck blocks cycle through ALL eligible peers rather than alternating between two
- **Independent pipeline stall timer** — Pipeline stall fires on its own 30s debounce, no longer gated on `last_block_connect` which head-of-line trickle kept resetting
- **Reduced per-peer batch size** — Max 16 blocks per peer (matching Bitcoin Core's MAX_BLOCKS_IN_TRANSIT_PER_PEER) to avoid overwhelming peers
- **Defer missing-block re-download** — Already-validated blocks missing from block store no longer clog the download pipeline during IBD (was consuming 1001 of 1024 in-flight slots, leaving almost no capacity for forward progress)
- **Shotgun head-of-line** — Critical next-in-sequence block requested from ALL eligible peers simultaneously; first to deliver wins (was one peer per 10s = N×10s delay)
- **Proven-peer assignment** — Peers that have delivered ≥1 block get proportional bulk allocation; unproven peers get only 2-block probe batches to avoid wasting in-flight slots
- **Non-blocking local replay** — Chunked replay (100 blocks/tick) replaces `block_in_place()` that blocked the event loop for hours during local block replay, causing channel overflow (508 dropped blocks) and cascading stalls
- **Background block file reindex** — `reindex_block_files()` moved to `spawn_blocking()` with once-per-session guard, preventing repeated 17-minute event loop freezes on each header sync completion
- **Removed nuclear peer reset** — "Disconnect all peers after 5 minutes" caused rapid connect/disconnect cycling that triggered Bitcoin Core's anti-DoS discouragement; individual stale-peer eviction is sufficient
- **Replay-aware peer management** — Stale-clearing, shotgun-requesting, and block download scheduling are gated on `!replay_active` to prevent blaming peers for "non-delivery" while replay is running from disk

## IBD Performance

- **Per-coin UTXO cache** — Replaced moka LRU with DashMap + CompactCoin (~135 bytes/entry vs ~500), fitting 3.7x more entries in the same `--dbcache` budget
- **UTXO cache** — 2M-entry moka lock-free concurrent cache (replaced `Mutex<LruCache>`)
- **RocksDB bloom filters** — 10-bit bloom filters on UTXO column family to eliminate ~99% of unnecessary disk reads
- **RocksDB tuning** — 1GB block cache, 128MB write buffers, dynamic level compaction
- **Download pipeline** — 512 in-flight blocks, 64-block batches, pipelined download/validation
- **Txid caching** — pre-compute txids once per block, reuse across merkle root, validation, and tx index
- **Raw block passthrough** — skip re-serialization by threading raw bytes from network to block store
- **Async block storage** — flat-file writes run on a dedicated background thread
- **Batched undo writes** — coalesced undo data writes into the same RocksDB batch as UTXO flushes
- **Batched UTXO prefetch** — `batched_multi_get_cf` to warm cache before sequential validation
- **Parallel script verification** — rayon thread pool (6 threads) for concurrent ECDSA/Schnorr checks
- **HDD optimizations** — RocksDB compaction readahead (2MB), 16KB block size, index/filter caching, 128MB target file size, `--dbcache` CLI flag, flush interval 1000 blocks, `block_in_place` + yield in drain loop
- **Stale request debounce** — Increased per-peer stale timeout from 60s to 120s and added 90s cooldown between stale-clear cycles, preventing a reassignment spam loop that stalled IBD around block 366K when blocks grew to ~1MB
- **Larger pending buffer** — Increased `pending_blocks` cap from 512 to 2048 with gentler eviction (evict oldest half instead of nuke-all), so downloaded blocks aren't discarded and re-requested

## Shutdown & Crash Recovery

- **Responsive shutdown** — `AtomicBool` flag checked in drain loop and after select; RPC `stop` and Ctrl-C both set it immediately so the node exits within seconds even mid-IBD
- **Crash-safe validated_height** — Now written on every UTXO flush (not just clean shutdown), so crash recovery only loses ~1000 blocks instead of the entire sync
- **Recovery uses UTXO flush_height** — Startup uses `max(validated_height, utxo_flush_height)` as the safe rollback point, preventing catastrophic truncation when validated_height is stale
- **Skip cache.clear() on exit** — DashMap with millions of entries took minutes to drop; OS reclaims all memory instantly on process exit

## Event Loop & Reliability

- **Drain loop moved out of event handler** — Block validation now runs after the select loop (max 32 blocks per tick), keeping the event loop responsive to peer messages and keepalives
- **100ms maintenance interval** — Reduced from 30s so pending blocks drain promptly without starving I/O
- **Header sync peer rotation** — Stall detection now rotates to a different peer with height > 0 instead of retrying the same unresponsive peer
- **Initial sync peer filter** — Only starts header sync with peers that report start_height > 0 (skips pruned/light nodes)
- **File descriptor limit** — Raises soft ulimit to min(hard, 65536) at startup; sets max_open_files on all RocksDB instances (UTXO: 10K, txindex: 5K, index: 5K, headers: 2K)

## Datum Mining Gateway

Stratum V1 (full: subscribe, authorize, configure with BIP 310 version rolling, notify, submit, set_difficulty, extranonce.subscribe) + SV2 Template Distribution Protocol (7.1-7.7), template construction from chain tip + mempool, share tracking (rolling-window hashrate with actual share difficulty from header hash, per-worker stats via shared atomic counter), real-time template push, mining dashboard (conditionally hidden when `--mining` not set).

- **BIP 22/23 enhancements** — full `getblocktemplate` extensions (rules, longpollid, proposal mode, capabilities, `default_witness_commitment`); see **Script Validation & BIP Coverage**. Datum-specific handshake wiring on top of this remains as part of the SV2/Datum pending item.

**Runtime mining configuration** — `MiningConfig` (`bitcoinpr-mining/src/config.rs`) persisted to `{datadir}/mining.toml`, shared via `Arc<RwLock<MiningConfig>>` with a `watch`-channel version counter for live reload; coinbase scriptSig tag injection (capped at 80 bytes); `--coinbasetag`/`--poolname` CLI + conf keys merged over the file (CLI precedence); `GET`/`POST /api/mining/config` with validation; `#/mining/config` web form applying changes live. See `docs/mining-config.md`.

**Datum protocol client** — `DatumClient` (`bitcoinpr-mining/src/datum.rs`): TLS transport (tokio-rustls/rustls/webpki-roots), newline-delimited JSON `DatumMessage` framing, connect → handshake → `ServerHello` → steady-state `select!` loop, exponential-backoff reconnect (degraded mode keeps local mining alive), pool coinbase-output splits applied to template construction, qualifying-share forwarding, and `DatumConnected/Disconnected/ShareSubmitted/Payout` event-bus notifications surfaced on the dashboard. See `docs/datum.md`.

**Datum web UI** — Pool connection status cards (status, pool name, payout scheme, difficulty, shares submitted/accepted, recent payout) on the mining dashboard, driven by `datum_status` in `GET /api/mining` and live WebSocket `Datum*` events.

## Stratum V1 Bug Fixes

- Extranonce1 double-counted in coinbase split (ASIC vs server hash mismatch)
- Segwit marker/flag/witness stripped from coinbase TXID serialization
- `handle_v1_submit` coinbase reconstruction with correct extranonce1 insertion
- Handshake loop for `mining.configure` before `mining.authorize` (BIP 310 version-rolling response)
- Share difficulty from actual header hash (`hash_to_share_difficulty()`) instead of `network_difficulty.min(1.0)`
- BIP 310 version rolling: 6th `mining.submit` param XORed with base version
- Connected workers tracked via `Arc<AtomicU32>` shared between TemplateProvider and MiningDashboard
- Mining tab hidden when `--mining` not set (`mining_enabled` in `/api/stats`)

## Script Validation & BIP Coverage

Node-relevant BIP support is closed out (BIP 35, 37, 90, 111, 159, 22/23, and 350 plus dashboard BIP-label hygiene). Wallet-only BIPs (32/39/44/49/84/86/174/...) are intentionally excluded — BitcoinPR is a node, not a wallet. Documented in `docs/bip-coverage.md`.

**Script validation:** `decode_num` now takes a `max_size` bound — the four lock-time sites (legacy + tapscript CLTV/CSV) allow 5-byte `CScriptNum` (Core's `nMaxNumSize = 5`), matching consensus for locktime/sequence values up to 2^39-1; all other call sites keep the 4-byte limit. Fixes the testnet4 stall at block 133634 (`"number too large"`).

**BIP 90 (buried deployments):** `ConsensusParams` gained a per-network `csv_height` (mainnet 419 328, testnet3 770 112, others 1); CSV (BIP 68/112/113) is now gated on `csv_height` instead of reusing `bip65_height`, and a `ConsensusParams::deployment_active(name, height)` helper exposes buried activation. The BIP 9/8 versionbits state machine is retained only for `getblocktemplate` signaling and the dashboard — never on the consensus-critical path.

**BIP 35 / 37 / 111 / 159 (P2P):** Optional `--peerbloomfilters` (off by default; never on outbound). When enabled: a wire-compatible BIP 37 bloom filter (`bitcoinpr-p2p/src/bloom.rs`, MurmurHash3 verified against Core's `bloom_tests.cpp` vectors), `filterload`/`filteradd`/`filterclear` handling, `merkleblock` + matched-tx serving for filtered-block `getdata`, BIP 35 `mempool` inv relay (filtered when a filter is loaded), and `NODE_BLOOM` (BIP 111) advertised via `node_service_flags`. BIP 159 `NODE_NETWORK_LIMITED` is advertised (instead of `NODE_NETWORK`) when block pruning is enabled.

**Block pruning (`--prune <MiB>`, 2026-07-02):** Core-style pruning in `bitcoinpr_storage::prune` — deletes the oldest `blk*.dat` files plus their block-position index entries and undo records once total block-file size exceeds the target (minimum 550 MiB; 0 disables). Always keeps the most recent 288 blocks and never prunes above the last UTXO-flushed height (crash-recovery replay window). Runs as a 5-minute tick in the node event loop on a blocking thread; `pruneblockchain` RPC for manual pruning; `getblockchaininfo` reports `pruned`/`pruneheight`. Incompatible with `--txindex`/`--index` (enforced at startup).

**BIP 22/23 (`getblocktemplate`):** `rules` array from buried deployments, empty `vbavailable`/`vbrequired`, `longpollid`, `capabilities: ["proposal"]`, `default_witness_commitment`, and `proposal` mode (structural offline validation returning `null` or a reject reason without connecting the block).

**BIP 350 (bech32m):** `validateaddress` now returns `scriptPubKey`, `witness_version`, and `witness_program`; regtest/mainnet/signet/testnet taproot (witness v1) vectors are covered by tests, including the scripthash-index path.

## Indexing & Electrum Layer (`--features indexing`)

Address-to-scripthash index, transaction history, Electrum TCP server (JSON-RPC, scripthash subscribe/balance/listunspent, SSL/TLS via rustls), event bus notifications.

## Web Block Explorer (`--features web`)

Axum HTTP/WebSocket server, search (TxID/Address/Height), mempool fee-rate histogram, real-time WebSocket updates (IBD-aware — suppresses NewBlock during initial sync), dashboard metrics (difficulty, fees, peers), mining dashboard, transaction flow Sankey diagram.

## Inbound Peer Connectivity

- **Send `getaddr` after outbound handshake** — Triggers remote peers to remember us and relay our address
- **Periodic `addr` re-advertisement** — Re-broadcast our address to all peers every ~24h (matching Bitcoin Core behavior)
- **Dynamic `start_height`** — Connections advertise current validated height via shared `RwLock<i32>` instead of stale startup height

## Hardening & Consensus Parity

Full consensus parity with Bitcoin Core.

**P2P:** Inbound peers (max 117), peer banning/scoring, addr relay, compact block relay (BIP 152 with mempool reconstruction), fee filter (BIP 133), preferred download peer, exponential backoff, /16 subnet diversity, compact block filters (BIP 157/158), V2 encrypted transport (BIP 324 with real ElligatorSwift encoding and BIP 324-compatible ECDH)

**Consensus:** Full difficulty retarget (256-bit chain work), BIP 68/112/113 (relative lock-times, CSV, MTP), BIP 141/143/144 (SegWit), BIP 340/341/342 (Taproot/Schnorr with full CLTV/CSV semantics in tapscript), block reorgs, BIP 30, signature caching, full script parity (all legacy + tapscript opcodes), BIP 9/8 versionbits, signet (BIP 325)

**Storage:** Transaction index, UTXO set (moka lock-free cache), parallel script verification, coalesced UTXO writes, assume-valid (block 840000), startup integrity checks, RocksDB memory limits

**RPC & Mempool:** HTTP Basic auth, `getblock` verbosity=2, `getblocktemplate` (with MTP-based mintime), `getdifficulty` (real nBits computation), `getmininginfo`, `getmempoolinfo` (heap usage estimation), RBF (BIP 125), fee estimation (20-bucket), ancestor/descendant limits, mempool persistence

## Stability & Memory Optimization

Lean default build, OOM-safe testnet sync.

- Cap `pending_blocks` buffer (512 blocks), UTXO cache (2M entries, moka lock-free), SigCache (100k entries)
- Batched UTXO flush (500 blocks / 50k overflow), RocksDB memory limits (1GB block cache + 128MB write buffers, bloom filters)
- Rayon thread pool (6 threads), feature gating (`indexing`, `web`), mining always enabled
- `generatetoaddress` + `submitblock` RPCs, Docker Compose 3-node regtest cluster
- Runtime fixes: `block_in_place()` for RPC, hostname resolution, inbound listener, health check port

## Operational Improvements

- Electrum logging verbosity (info for connections/txs, debug for rest)
- Inbound P2P connections: `GetAddr` handler, `build_self_addr` for address advertisement
- Block validation progress percentage in logs (sync % from peer-reported height)
- WebSocket IBD suppression (`is_ibd` flag defers NewBlock pushes until caught up)
- WAN IP discovery from outbound peers (vote-based consensus from version message `receiver` field)
- Crash-consistent UTXO tip tracking (`set_best_tip` only persists on UTXO flush; disconnect forces flush)
- Forward recovery: wipe UTXO + reset tip to genesis when UTXO/tip mismatch detected on startup
- Header sync guard: ignore empty headers from non-sync peers to prevent premature sync completion
- Stale in-flight timeout (120s, debounced 90s) to recover from stuck block downloads after peer disconnect — prevents reassignment spam loop
- Reorg guard: skip reorg when blocks already in-flight, preventing repeated in-flight clearing
- `--reindex` flag for full UTXO/headers/index rebuild from stored blocks

## Code Quality Fixes

- RPC: real difficulty from nBits (`compact_target_to_difficulty` in `bitcoinpr-core`), MTP-based mintime, heap-aware mempool usage, `getmininginfo` method
- Consensus: corrected 256-bit math comments (implementation was already sound), full BIP 65/112 CLTV/CSV in tapscript
- P2P: BIP 152 compact block reconstruction from mempool with `getblocktxn` fallback, real BIP 324 ElligatorSwift via libsecp256k1
