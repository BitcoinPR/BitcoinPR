# Prometheus & Grafana Monitoring

BitcoinPR exposes a Prometheus-compatible `/metrics` endpoint on the same port as
the web explorer (`--webport`, default `3000`), when the node is built with the
`web` Cargo feature (included in `full`):

```sh
cargo build --release --features full
./target/release/bitcoinprd --web --webport 3000 ...
curl http://localhost:3000/metrics
```

`/metrics` is a read-only `GET` endpoint, unauthenticated like `/api/stats` and
`/api/info` — it does not require the admin token used by mutating endpoints
(e.g. `POST /api/mining/config`). If you want to restrict scrape access, do it on
the Prometheus side (`basic_auth` in the scrape config) or with a firewall/reverse
proxy in front of the port; there's nothing node-side to configure.

## Prometheus scrape config

Add a job to your existing `prometheus.yml`:

```yaml
scrape_configs:
  - job_name: bitcoinpr
    static_configs:
      - targets: ["<node-host>:3000"]
    # metrics_path defaults to /metrics
```

## Exported metrics

All metrics use the `bitcoinpr_` prefix (not `bitcoin_`), so they coexist cleanly
if the same Prometheus/Grafana also scrapes a real Bitcoin Core node via a
separate exporter.

| Metric | Type | Description |
|---|---|---|
| `bitcoinpr_block_height` | gauge | Height of the best validated block. The core "blockchain growth" metric. |
| `bitcoinpr_header_height` | gauge | Height of the best known header (leads `block_height` during IBD). |
| `bitcoinpr_difficulty` | gauge | Proof-of-work difficulty of the current tip. |
| `bitcoinpr_chain_work_log2` | gauge | log2 of cumulative chain work at the tip. |
| `bitcoinpr_is_ibd` | gauge | 1 while in initial block download, else 0. |
| `bitcoinpr_peers_connected` | gauge | Number of connected P2P peers. |
| `bitcoinpr_mempool_transactions` | gauge | Mempool transaction count. |
| `bitcoinpr_mempool_bytes` | gauge | Mempool size in bytes. |
| `bitcoinpr_mempool_fee_rate_sat_per_vb{percentile}` | gauge | Mempool fee-rate p10/p50/p90, sat/vB. |
| `bitcoinpr_storage_bytes{component}` | gauge | On-disk usage by datadir component (`blocks`, `utxo`, `undo`, `headers`, `other`); refreshed every 60s. |
| `bitcoinpr_tip_age_seconds` | gauge | Seconds since the tip's block timestamp; a stall/liveness indicator. |
| `bitcoinpr_uptime_seconds` | gauge | Seconds since the node process started. |
| `bitcoinpr_mining_hashrate` | gauge | Estimated local mining hashrate in H/s (only present when `--mining` is enabled). |

## Graphing blockchain growth over time

Prometheus's own TSDB gives you the growth curve for free once
`bitcoinpr_block_height` is scraped repeatedly — just graph it directly as a time
series. Two derived queries are worth adding as their own panels:

- **Blocks per 10 minutes** (stall detection): `increase(bitcoinpr_block_height[10m])`.
  A flat zero for longer than expected means sync has stalled.
- **On-disk chain growth**: `bitcoinpr_storage_bytes` graphed by `component`
  (stacked) shows the chain's actual disk footprint growing over time, not just
  its height.

## Grafana dashboard

Import [`contrib/grafana/bitcoinpr-dashboard.json`](../contrib/grafana/bitcoinpr-dashboard.json)
into your existing Grafana. On import, Grafana will prompt you to pick your
existing Prometheus datasource for the dashboard's `DS_PROMETHEUS` variable — no
other setup is required.
