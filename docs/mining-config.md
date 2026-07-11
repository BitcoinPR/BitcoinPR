# Runtime Mining Configuration

BitcoinPR's mining gateway is configured at runtime through a `MiningConfig` that is loaded
from `{datadir}/{network}/mining.toml`, merged with CLI/conf overrides at startup, and
editable live via the web API without restarting the node.

## Configuration sources & precedence

1. `mining.toml` in the per-network data directory (created/updated on startup when
   `--mining` is set).
2. `bitcoinpr.conf` keys.
3. CLI flags (highest precedence).

The merged result is validated and persisted back to `mining.toml`. `stratum_port` is the
only field that cannot change at runtime (rebinding the listener requires a restart).

## `mining.toml`

```toml
mining_address = "bc1q..."   # omit or empty => OP_TRUE (anyone-can-spend; test only)
coinbase_tag   = "/BitcoinPR/" # appended after the BIP34 height in the coinbase scriptSig
pool_name      = "BitcoinPR"
stratum_port   = 3333
mode           = "solo"        # "solo" | "datum"

[datum]
server_url     = "datum.ocean.xyz:3334"
payout_address = "bc1q..."
worker_name    = "rig1"
# auth_token   = "..."        # optional
```

`coinbase_tag` is stored as a UTF-8 string when printable; non-UTF-8 tags are stored as
`"hex:<bytes>"`. The tag is capped at **80 bytes** (`MAX_COINBASE_TAG_LEN`) so the full
scriptSig (height push + tag + 8 bytes of extranonce) stays within the 100-byte limit;
oversized tags are truncated with a warning.

## CLI flags

| Flag | Description |
|------|-------------|
| `--mining` | Enable the mining gateway |
| `--miningport <port>` | Stratum/SV2 listen port (default 3333) |
| `--miningaddress <addr>` | Coinbase payout address (default OP_TRUE) |
| `--coinbasetag <string>` | Coinbase scriptSig tag (default `/BitcoinPR/`) |
| `--poolname <string>` | Pool attribution name |
| `--miningdifficulty <f64>` | Stratum share-difficulty throttle (does not change block nBits) |

`bitcoinpr.conf` accepts the same keys (`coinbasetag=`, `poolname=`, …).

## Coinbase scriptSig layout

```
scriptSig = [BIP34 height push] [coinbase_tag bytes] [extranonce1] [extranonce2]
```

The tag is embedded in the Stratum V1 `coinbase1`, so the server-side coinbase
reconstruction (`coinbase1 + extranonce1 + extranonce2 + coinbase2`) is unchanged. With an
empty tag, the produced coinbase is byte-identical to the pre-tag behavior.

## Web API

### `GET /api/mining/config`
Returns the current config:

```json
{
  "mining_address": "bc1q...",
  "coinbase_tag": "/BitcoinPR/",
  "pool_name": "BitcoinPR",
  "stratum_port": 3333,
  "mode": "solo",
  "datum": {
    "server_url": "datum.ocean.xyz:3334",
    "payout_address": "bc1q...",
    "worker_name": "rig1",
    "auth_token_set": false
  }
}
```

### `POST /api/mining/config`
Partial update (all fields optional). `stratum_port` is ignored (read-only). Applies the
change live (TemplateProvider rebuilds and pushes a fresh job; DatumClient reconnects if
its credentials changed) and persists to `mining.toml`.

```json
{
  "mining_address": "bc1q...",
  "coinbase_tag": "/BitcoinPR/ocean/",
  "pool_name": "BitcoinPR",
  "mode": "datum",
  "datum": { "server_url": "datum.ocean.xyz:3334", "payout_address": "bc1q...", "worker_name": "rig1" }
}
```

Response: `200 {"ok": true, "persisted": true, "config": { … }}`, or `400 {"error": "…"}`
on validation failure (invalid address, oversized tag, bad `mode`, or — in Datum mode —
an empty/malformed `server_url` or invalid payout address). Omitting `datum.auth_token`
leaves any existing token unchanged; sending an empty value clears it.

## Web UI

The **Mining → Mining Config** page (`#/mining/config`) provides a form for all of the
above. The nav link is hidden when `--mining` is not enabled. Saving applies changes live.
