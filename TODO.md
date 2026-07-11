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

### SV2 / Datum Mining Gateway

The Datum runtime-config, Datum client, and Datum web UI are complete (see the
**Datum Mining Gateway** entry in [CHANGELOG.md](CHANGELOG.md), plus
`docs/mining-config.md` and `docs/datum.md`). Remaining:

- [ ] **SV2 Noise handshake** — `protocol.rs` — Connection setup uses JSON-RPC instead of the full SV2 Noise_NX handshake (requires the `noise-protocol` crate and CA infrastructure). The Datum client likewise uses TLS + newline-delimited JSON framing rather than the binary Datum wire format.
