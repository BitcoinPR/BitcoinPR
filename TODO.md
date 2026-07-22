# BitcoinPR — Roadmap & TODO

Completed work lives in [CHANGELOG.md](CHANGELOG.md).

## Pending Work

### BIP-110 Bare-Envelope Parasite Filter (parked — BitcoinPR/BitcoinPR#1)

- [ ] **Merge [BitcoinPR/BitcoinPR#1](https://github.com/BitcoinPR/BitcoinPR/pull/1)
  (branch `bip110-bare-envelope-filter`) if/when BIP-110
  activates** — mirrors Bitcoin Knots PR #319: ordinals (ord#4545) announced a
  BIP-110-compatible envelope (`<marker> <data>… OP_2DROP…OP_DROP`, no
  `OP_IF`) that evades classic envelope detection. The branch extends
  `rejectparasites` to count drop-balanced push/pushnum runs in tapscript
  leaves against `datacarriersize` (Knots' DatacarrierBytes accounting), and
  feeds bare-envelope payloads into the token scanner. Gate green on the
  branch; deliberately left unmerged until BIP-110 activation is confirmed.
  Before merging: rebase if needed and run the interop suite via the
  recreate-only-bitcoinpr procedure.

### OP_PLENTY Covert Opcode-Choice Parasite Filter (parked)

- [ ] **Merge branch `claude/op-plenty-covert-opcode-filter` (not yet
  opened as a public PR) if/when BIP-110 activates** — a public gist
  ("OP_PLENTY", stevenrabinow-hash) demonstrates a data-embedding technique
  that performs no data push at all: payload nibbles are encoded as the
  *choice* of opcode at each script position, drawn from a 28-opcode
  alphabet picked to avoid BIP342 `OP_SUCCESSx` ranges. Evades
  `datacarrier`, the BIP-110 push-size limit, and the classic/bare envelope
  detectors, none of which see a data push or an `OP_IF`/`OP_2DROP`-run to
  key on. The branch extends `rejectparasites` with
  `tx_first_covert_opcode_input` (`script.rs`): a contiguous run of 24+
  alphabet-only opcodes immediately followed by one of the three
  stack-collapsing footers the construction requires. Gate green + interop
  18/18 on the branch (2026-07-22); parked per the same convention as the
  bare-envelope filter below — land it alongside other BIP-110-era
  relay-policy additions once BIP-110 activation is confirmed. See
  `docs/relay-policy.md`.

### BIP-110 Late-Upgrade Chainstate Gap (from blockslop.dev audit of Knots, analyzed 2026-07-18)

blockslop.dev documents a gap class in Knots v29.3: BIP-110 validation runs
only in `ConnectBlock()`, but restart trusts the persisted chainstate — a node
that connected RDTS-invalid blocks *before* enabling enforcement keeps them
after upgrade, forking the network into as many chains as there are
pre-upgrade histories. Their fix: per-block "validated under BIP-110" status
bits + startup ancestry scan + fail-closed `-reindex-chainstate` demand
(SegWit `BLOCK_OPT_WITNESS`/`NeedsRedownload()` precedent). We share the
shape (validation in `connect_block`, `load_chain_tip` trusts the tip, no
positive provenance), and enforcement config can change between runs on one
datadir three ways: a pre-BIP110-build datadir upgraded in place, adding or
lowering `--bip110height`, and any future un-abandon of the capitulation
flag. Mitigations we already have: `--reindex-chainstate` is a true
replay-from-genesis through full `connect_block`; output-size rules run
outside the assume-valid script gate (chain.rs:561); mainnet assume-valid
(840,000) sits below the mandatory window (~961,632).

Done 2026-07-20 (see CHANGELOG): enforcement-config fingerprint +
fail-closed startup. The fingerprint machinery also covers any future
un-abandon path automatically (config change → mismatch → reindex demand).
Remaining:

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

### Follow-ups (added 2026-07-12)

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

### IBD Performance (from Core tracking PR bitcoin/bitcoin#32043, analyzed 2026-07-17)

All 8 actionable analogues implemented 2026-07-20 (see CHANGELOG). Left on
the table from that analysis: pipelining the next block's UTXO prefetch
during script verification (new architecture, not a port — our `multi_get`
prefetch already covers Core #31132's win otherwise), and
`ingest_external_file` sorted-SST flushes as a further RocksDB-only step
beyond the chunked-flush fix. Caveat still applies: the 2026-07-03 mainnet
IBD was substantially network-bound (10–15 Mbps), so profile before chasing
more CPU wins.

### Signature Verification Throughput (from libbitcoin GPU-verification claim, analyzed 2026-07-20)

A libbitcoin developer cited a 59-minute full validation run "using GPU
signature verification." That traces to libbitcoin-system PR #1855
("GPU/CPU batch signature verification, UltrafastSecp256k1 backend"),
opened and closed same-day (2026-05-30) by maintainer evoskuil as "Retain
for reference" — an unmerged proof-of-concept, not a shipped feature. It
packs `(hash, pubkey, signature)` triples extracted during script execution
into flat row buffers and dispatches to a GPU backend (CUDA/OpenCL/Metal)
with mandatory CPU fallback, gated by a bit-for-bit consensus differential
check against stock libsecp256k1. Their non-GPU fallback is thread-parallel
CPU verification — the same idea as our existing rayon `par_iter` script
checks (`chain.rs:846`), so we already have parity with libbitcoin's
*default* build; the gap is algorithmic batching / GPU, which stock
libsecp256k1 (underneath both projects) doesn't provide natively either.

The two free-standing CPU fixes surfaced by that comparison (shared
`Secp256k1<VerifyOnly>` context; one `SighashCache` per `verify_script`
threaded through the interpreter) were implemented 2026-07-20 — see
CHANGELOG. Note: the cache ended up per-input rather than per-transaction
(`SighashCache` is not `Clone`/shareable across the rayon fan-out), which
still captures the multisig/taproot re-hash win with zero consensus risk.

Bigger structural option, deferred pending measurement:

- [ ] **Profile `--reindex-chainstate` / post-assumevalid script-check
  wall-clock before considering a batch/GPU backend** — `chain.rs:223`
  skips script verification entirely below the assume-valid block
  (mainnet 840,000 per the BIP-110 gap section above), so a normal
  from-genesis IBD only runs full signature verification for the tail past
  that height. The place batching would actually pay off for us is a full
  `--reindex-chainstate` replay (genesis-to-tip through `connect_block`,
  no assume-valid shortcut) or a future raised/removed assume-valid height.
  Our 2026-07-03 mainnet IBD was network-bound (10-15 Mbps), not CPU-bound,
  except specific stretches — measure before investing further.
- [ ] **If profiling justifies it: batch/GPU verification as an
  experimental, opt-in backend only** — recognize standard script
  templates (P2PKH/P2WPKH/P2TR-keypath/P2WSH-multisig; none branch control
  flow on a CHECKSIG result, unlike generic Script), extract their
  sig-check triples without full interpretation, accumulate across a
  lookahead window of many blocks (one block's ~thousands of inputs is too
  thin a batch for GPU throughput to matter), submit once, fall back to
  today's per-input rayon path for anything non-standard. Requires the
  same bit-for-bit differential gate against our current libsecp256k1 path
  that libbitcoin's own (unmerged) attempt insisted on — this is
  consensus-critical surface, and even its originating project wasn't
  comfortable shipping it yet.

### SV2 / Datum Mining Gateway

The Datum runtime-config, Datum client, and Datum web UI are complete (see the
**Datum Mining Gateway** entry in [CHANGELOG.md](CHANGELOG.md), plus
`docs/mining-config.md` and `docs/datum.md`). Remaining:

- [ ] **SV2 Noise handshake** — `protocol.rs` — Connection setup uses JSON-RPC instead of the full SV2 Noise_NX handshake (requires the `noise-protocol` crate and CA infrastructure). The Datum client likewise uses TLS + newline-delimited JSON framing rather than the binary Datum wire format.
