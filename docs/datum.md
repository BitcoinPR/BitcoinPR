# Datum Protocol Client

The Datum client lets BitcoinPR participate in **template-sovereign pool mining** (the
model used by OCEAN): the *miner* builds block templates (selecting its own transactions),
while the *pool* coordinates payouts and supplies the coinbase outputs for the payout
split. This is the opposite of traditional pools, where the pool constructs the block.

Enable it by setting `mode = "datum"` in `mining.toml` (or via the web config page) and
filling in the `[datum]` section. See `docs/mining-config.md`.

## Architecture

```
            BitcoinPR node
  Mempool + ChainState
        │
        ▼
  TemplateProvider ──► Stratum V1 / SV2 miners
     │      │                 │
     │      ▼                 │
     │  ShareTracker ◄────────┘
     ▼
  DatumClient ──► Datum server (e.g. OCEAN)
```

The `DatumClient` (`bitcoinpr-mining/src/datum.rs`) runs alongside the `TemplateProvider`.
It is spawned at startup only when `mode == Datum`. It shares the same
`Arc<RwLock<MiningConfig>>` and config-version watch channel as the TemplateProvider, so a
live config change reconnects it with updated credentials.

## Transport & messages

- **TLS** via `tokio-rustls` 0.26 / `rustls` 0.23, trusting the Mozilla root set from
  `webpki-roots`. SNI uses the host from `datum.server_url` (`host:port`).
- **Framing**: newline-delimited JSON `DatumMessage` values (`bitcoinpr-mining/src/protocol.rs`).
  This mirrors BitcoinPR's existing SV2 design, which also uses JSON framing in place of a
  full binary/Noise handshake.

`DatumMessage` variants:

| Direction | Message | Purpose |
|-----------|---------|---------|
| C → S | `Handshake` | protocol version, worker name, payout address, auth token, user agent |
| C → S | `SubmitShare` | forward a qualifying share (session, height, header hash, nonce, ntime, coinbase, difficulty) |
| C → S | `TemplateUpdate` | notify the pool of a new template (height, prev hash, coinbase value, tx count) |
| S → C | `ServerHello` | accepted version, session id, pool name, pool difficulty, coinbase output specs, payout scheme |
| S → C | `CoinbaseOutputUpdate` | revised payout-split coinbase outputs |
| S → C | `ShareResult` | accepted/rejected (+ optional reason, pool hashrate) |
| S → C | `PayoutNotification` | completed payout (txid, amount, block height) |
| S → C | `Error` | error code + message |

## Connection lifecycle

1. **Idle** in Solo mode (cheap 2s poll + immediate wake on config change).
2. **Connect** over TLS, send `Handshake`.
3. **`ServerHello`** → mark connected, store pool name / difficulty / payout scheme /
   session id / coinbase output specs, broadcast `DatumConnected`.
4. **Steady state** (`select!`):
   - read server messages (`CoinbaseOutputUpdate`, `ShareResult`, `PayoutNotification`,
     `Error`),
   - drain the internal share queue → `SubmitShare`,
   - detect config-version changes → reconnect if Datum settings changed.
5. **Disconnect / error** → broadcast `DatumDisconnected`, exponential-backoff reconnect
   (1s → 2s → … → 60s cap; reset on the next `ServerHello`). The client never panics on a
   connection failure — local mining continues in degraded mode.

## Coinbase output integration

Pool `CoinbaseOutputSpec`s (`{ value_fraction, script_pubkey_hex, label }`) are applied in
`build_template` → `build_v1_job` / `assemble_mined_block`:

- each pool output value = `floor(value_fraction × coinbase_value)`,
- the miner's primary output is reduced by the sum of pool outputs,
- if that would underflow (or no valid pool outputs decode), it falls back to a single
  full-value miner output — the coinbase is never made invalid,
- in Solo mode (no specs) the coinbase is byte-identical to before.

## Share forwarding

When a Stratum V1 share is accepted **and** the live mode is Datum **and** the share's
difficulty ≥ the pool's difficulty, the share is forwarded via
`DatumClient::submit_share`. In Solo mode this path is skipped entirely.

## Events & dashboard

`NodeNotification::{DatumConnected, DatumDisconnected, DatumShareSubmitted, DatumPayout}`
are published on the event bus and forwarded over the web WebSocket. The mining dashboard
shows a **Pool Connection** section (status, pool name, payout scheme, difficulty, shares
submitted/accepted, recent payout) sourced from `datum_status` in `GET /api/mining` and
updated live by these events.

## Status snapshot

`DatumClient::status()` returns `DatumStatus { connected, pool_name, pool_difficulty,
payout_scheme, shares_submitted, shares_accepted, last_payout, uptime_secs }`, surfaced via
`MiningStatsSnapshot.datum_status`.

## Notes & limitations

- The JSON `DatumMessage` framing is BitcoinPR's own representation of the Datum exchange;
  interoperability with a specific production Datum/OCEAN server depends on that server
  speaking the same framing.
- Missed shares during a disconnect are not replayed (standard pool behavior).
