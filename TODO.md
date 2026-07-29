# BitcoinPR — Roadmap & TODO

Completed work lives in [CHANGELOG.md](CHANGELOG.md).

## Pending Work

### Bitcoin Core Block Import

- [ ] **Accept Bitcoin Core `blk*.dat` files for bootstrap** — Core's per-block
  framing is `[4B network magic][4B size LE][block data]`; ours is
  `[4B size LE][block data]`. The raw block bytes (consensus wire format) are
  identical. Tweak the block-file reader (`block_store.rs`) to detect and skip
  the 4-byte magic prefix, so a user can point a fresh BitcoinPR instance at a
  directory containing Core's `blocks/blk*.dat` files and `--reindex` from them.
  The node would ingest existing blocks (building headers, UTXO set, undo data,
  and indexes as if freshly downloaded), then continue writing new blocks in our
  native format. Old Core-format files remain readable because `BlockPos.offset`
  points past the magic to the size prefix — both formats coexist in the same
  data directory.

### Follow-ups

- [ ] **Block-download stall detectors misfire at tip** — the head-of-line
  escalation (node.rs "Head-of-line block stalled"), stale per-peer request
  clearing ("Cleared stale per-peer block requests"), and pipeline-stall
  recovery ("Pipeline stall") all key off the global `last_block_connect`
  timer, which is meaningless once synced: a natural 10–20 min gap between
  blocks trips them and triggers redundant emergency getdata to multiple
  peers. Fix: give `BlockSync::in_flight` (p2p/sync.rs) per-request
  timestamps and escalate/clear only requests that are actually old, keeping
  the warns meaningful during IBD.

- [ ] **Prune undo records beyond a reorg-safe depth** — the `undo` CF of
  the utxo RocksDB (~230 GB, now reported as its own "undo" bucket on the
  web Info page) keeps per-block undo records forever, but they are only
  needed to disconnect blocks during a reorg. Deleting records deeper than
  a reorg-safe depth (a few thousand blocks) would reclaim most of that
  230 GB. Core keeps the equivalent in `rev*.dat` and prunes it with block
  files.

### SV2 / Datum Mining Gateway

The Datum runtime-config, Datum client, and Datum web UI are complete (see the
**Datum Mining Gateway** entry in [CHANGELOG.md](CHANGELOG.md), plus
`docs/mining-config.md` and `docs/datum.md`). Remaining:

- [ ] **SV2 Noise handshake** — `protocol.rs` — Connection setup uses JSON-RPC instead of the full SV2 Noise_NX handshake (requires the `noise-protocol` crate and CA infrastructure). The Datum client likewise uses TLS + newline-delimited JSON framing rather than the binary Datum wire format.

---

## Parked PRs (merge when BIP-110 activates)

### BIP-110 Bare-Envelope Parasite Filter (BitcoinPR/BitcoinPR#1)

Branch `bip110-bare-envelope-filter` — mirrors Bitcoin Knots PR #319.
Ordinals (ord#4545) announced a BIP-110-compatible envelope
(`<marker> <data>… OP_2DROP…OP_DROP`, no `OP_IF`) that evades classic
envelope detection. The branch extends `rejectparasites` to count
drop-balanced push/pushnum runs in tapscript leaves against
`datacarriersize` (Knots' DatacarrierBytes accounting), and feeds
bare-envelope payloads into the token scanner. Gate green on the branch.
Before merging: rebase if needed and run the interop suite.

### OP_PLENTY Covert Opcode-Choice Filter

Branch `claude/op-plenty-covert-opcode-filter` — a public gist
("OP_PLENTY") demonstrates data embedding that performs no data push at
all: payload nibbles are encoded as the *choice* of opcode at each
tapscript position, evading datacarrier, the BIP-110 push-size limit, and
classic/bare envelope detectors alike. The branch adds structural detection
(`tx_first_covert_opcode_input` in script.rs): flags a taproot leaf script
with a 24+ opcode run drawn only from the 28-opcode alphabet the encoder
uses, immediately followed by one of its three stack-collapsing footers.
Wired into `rejectparasites`. Before merging: rebase if needed, open
upstream PR, and run the interop suite.

---

## Deferred (pending measurement / activation)

### BIP-110 Late-Upgrade Chainstate Gap

From blockslop.dev audit of Knots (analyzed 2026-07-18). Core enforcement-config
fingerprint + fail-closed startup shipped 2026-07-20 (see CHANGELOG). Remaining:

- [ ] **Assume-valid/BIP-110 interlock** — startup check: if the hardcoded
  assume-valid block height is ever ≥ the mandatory-window start, warn or
  refuse; prevents a future assume-valid bump from silently skipping
  per-input RDTS script rules for buried blocks.
- [ ] **`Bip110Checker::activation_for` fails open on missing ancestors**
  (minor) — returns `INACTIVE` (no enforcement) when an ancestor header is
  missing (bip110.rs:172-188); comment calls it fail-closed but "don't
  enforce" is fail-open for a consensus check. Likely unreachable in the
  connect path (MTP check fails closed first) — return an error to match the
  rest of validation's failure direction.

### Signature Verification Throughput

From libbitcoin GPU-verification claim (analyzed 2026-07-20). CPU fixes
(shared `Secp256k1<VerifyOnly>` context, per-input `SighashCache`) shipped
2026-07-20 (see CHANGELOG). We already have parity with libbitcoin's default
build via rayon `par_iter` script checks; the gap is algorithmic
batching / GPU, which stock libsecp256k1 doesn't provide natively.

- [ ] **Profile `--reindex-chainstate` / post-assumevalid script-check
  wall-clock before considering a batch/GPU backend** — normal IBD skips
  script verification below assume-valid (mainnet 840,000). Batching would
  pay off for a full `--reindex-chainstate` replay or a raised/removed
  assume-valid height. Our 2026-07-03 mainnet IBD was network-bound
  (10–15 Mbps), not CPU-bound — measure before investing further.
- [ ] **If profiling justifies it: batch/GPU verification as an
  experimental, opt-in backend only** — extract sig-check triples from
  standard script templates, accumulate across a lookahead window of many
  blocks, submit to GPU, fall back to per-input rayon for non-standard.
  Requires bit-for-bit differential gate against current libsecp256k1 —
  consensus-critical surface; even libbitcoin's own attempt was unmerged.
