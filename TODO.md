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

### Follow-ups (added 2026-07-12)

- [ ] **Scripthash resolver: byte offset in `TxIndexEntry`** — the structural
  follow-up to the 2026-07-12 backfill efficiency rework (see CHANGELOG):
  storing `(offset, len)` alongside `(block_hash, tx_pos)` would make each
  cache-missed prevout a single small read + one tx decode instead of a
  partial block scan. Needs a v2 entry format and a tx-index reindex (or
  write-new/read-both migration).

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
