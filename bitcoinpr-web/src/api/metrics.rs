//! Prometheus text-exposition-format metrics (`GET /metrics`).
//!
//! Hand-rolled rather than pulled in via the `prometheus` crate: the metric
//! set is small and every value is already sitting in `WebState` (or, for the
//! one expensive stat, in a periodically-refreshed cache — see
//! `WebServer::run`'s storage-snapshot sampler in `server.rs`), so a crate
//! dependency would buy nothing but indirection.
//!
//! All metrics are prefixed `bitcoinpr_` (not `bitcoin_`) so they coexist
//! cleanly if the same Prometheus/Grafana also scrapes a real Bitcoin Core
//! node via a separate exporter.

use std::fmt::Write as _;

use axum::extract::State;
use axum::http::header;
use axum::response::IntoResponse;

use crate::api::stats::bits_to_difficulty;
use crate::state::WebState;

pub async fn get_metrics(State(state): State<WebState>) -> impl IntoResponse {
    let best_height = *state.best_height.read().await;
    let best_hash = *state.best_hash.read().await;
    let header_height = state
        .header_index
        .get_header_tip_height()
        .ok()
        .flatten()
        .unwrap_or(best_height);

    let stored_tip = state.header_index.get_header(&best_hash).ok().flatten();
    let difficulty = stored_tip
        .as_ref()
        .map(|s| bits_to_difficulty(s.header.bits.to_consensus()))
        .unwrap_or(0.0);
    let chain_work_log2 = stored_tip
        .as_ref()
        .map(|s| chain_work_log2(&s.chain_work))
        .unwrap_or(0.0);
    let tip_age_secs = stored_tip.as_ref().map(|s| {
        let tip_time = s.header.time as i64;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(tip_time);
        (now - tip_time).max(0)
    });

    let is_ibd = state.is_ibd.load(std::sync::atomic::Ordering::Relaxed);
    let peer_count = state.peers.read().await.len();
    let (mempool_size, mempool_bytes) = {
        let mempool = state.mempool.read().await;
        (mempool.size(), mempool.total_bytes())
    };
    let fee_percentiles = state
        .mempool_history
        .read()
        .await
        .back()
        .map(|s| (s.fee_p10, s.fee_p50, s.fee_p90));
    let storage = state.storage_snapshot.read().await.clone();
    let uptime_secs = state.start_time.elapsed().as_secs();

    let hashrate_hs = state
        .mining_dashboard
        .as_ref()
        .map(|dash| dash.hashrate_hs());

    let mut out = String::new();

    gauge(
        &mut out,
        "bitcoinpr_block_height",
        "Height of the best validated block.",
        best_height as f64,
    );
    gauge(
        &mut out,
        "bitcoinpr_header_height",
        "Height of the best known header (may lead block_height during IBD).",
        header_height as f64,
    );
    gauge(
        &mut out,
        "bitcoinpr_difficulty",
        "Proof-of-work difficulty of the current tip.",
        difficulty,
    );
    gauge(
        &mut out,
        "bitcoinpr_chain_work_log2",
        "log2 of cumulative chain work at the current tip.",
        chain_work_log2,
    );
    gauge(
        &mut out,
        "bitcoinpr_is_ibd",
        "1 if the node is in initial block download, else 0.",
        if is_ibd { 1.0 } else { 0.0 },
    );
    gauge(
        &mut out,
        "bitcoinpr_peers_connected",
        "Number of connected P2P peers.",
        peer_count as f64,
    );
    gauge(
        &mut out,
        "bitcoinpr_mempool_transactions",
        "Number of transactions in the mempool.",
        mempool_size as f64,
    );
    gauge(
        &mut out,
        "bitcoinpr_mempool_bytes",
        "Total size of the mempool in bytes.",
        mempool_bytes as f64,
    );
    if let Some(secs) = tip_age_secs {
        gauge(
            &mut out,
            "bitcoinpr_tip_age_seconds",
            "Seconds since the current tip's block timestamp; a stall/liveness indicator.",
            secs as f64,
        );
    }
    gauge(
        &mut out,
        "bitcoinpr_uptime_seconds",
        "Seconds since the node process started.",
        uptime_secs as f64,
    );

    if let Some((p10, p50, p90)) = fee_percentiles {
        header_type(
            &mut out,
            "bitcoinpr_mempool_fee_rate_sat_per_vb",
            "Mempool fee-rate percentile, sat/vB.",
        );
        writeln!(
            out,
            "bitcoinpr_mempool_fee_rate_sat_per_vb{{percentile=\"p10\"}} {p10}"
        )
        .ok();
        writeln!(
            out,
            "bitcoinpr_mempool_fee_rate_sat_per_vb{{percentile=\"p50\"}} {p50}"
        )
        .ok();
        writeln!(
            out,
            "bitcoinpr_mempool_fee_rate_sat_per_vb{{percentile=\"p90\"}} {p90}"
        )
        .ok();
    }

    if !storage.is_empty() {
        header_type(
            &mut out,
            "bitcoinpr_storage_bytes",
            "On-disk storage usage by datadir component (blocks, utxo, undo, headers, other).",
        );
        for (component, bytes) in &storage {
            writeln!(
                out,
                "bitcoinpr_storage_bytes{{component=\"{component}\"}} {bytes}"
            )
            .ok();
        }
    }

    if let Some(hs) = hashrate_hs {
        gauge(
            &mut out,
            "bitcoinpr_mining_hashrate",
            "Estimated local mining hashrate in H/s (only present when mining is enabled).",
            hs,
        );
    }

    ([(header::CONTENT_TYPE, "text/plain; version=0.0.4")], out).into_response()
}

/// Append a `# HELP` / `# TYPE gauge` / value block for a single-sample gauge.
fn gauge(out: &mut String, name: &str, help: &str, value: f64) {
    header_type(out, name, help);
    writeln!(out, "{name} {value}").ok();
}

fn header_type(out: &mut String, name: &str, help: &str) {
    writeln!(out, "# HELP {name} {help}").ok();
    writeln!(out, "# TYPE {name} gauge").ok();
}

/// Approximate log2 of a 256-bit big-endian unsigned integer (chain work).
/// Precise to the leading ~64 significant bits, which is far more precision
/// than a log2 graph needs (chain work log2 for mainnet is currently ~90).
fn chain_work_log2(work: &[u8; 32]) -> f64 {
    let Some(idx) = work.iter().position(|&b| b != 0) else {
        return 0.0;
    };
    let take = (32 - idx).min(8);
    let mut mantissa_bytes = [0u8; 8];
    mantissa_bytes[8 - take..].copy_from_slice(&work[idx..idx + take]);
    let mantissa = u64::from_be_bytes(mantissa_bytes) as f64;
    let remaining_bytes = 32 - idx - take;
    mantissa.log2() + (remaining_bytes * 8) as f64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chain_work_log2_zero() {
        assert_eq!(chain_work_log2(&[0u8; 32]), 0.0);
    }

    #[test]
    fn chain_work_log2_one() {
        let mut work = [0u8; 32];
        work[31] = 1;
        assert_eq!(chain_work_log2(&work), 0.0);
    }

    #[test]
    fn chain_work_log2_power_of_two() {
        // 2^200 set as the single high bit of byte index 6 (256 - 200 = 56;
        // byte 6 holds bits 255..248, i.e. exponents 248..255; bit 200 sits
        // in byte index (255-200)/8 = 6, bit position 200 % 8 = 0).
        let mut work = [0u8; 32];
        work[6] = 1 << (200 % 8);
        let got = chain_work_log2(&work);
        assert!((got - 200.0).abs() < 1e-9, "got {got}");
    }

    #[test]
    fn chain_work_log2_exact_for_top_byte_aligned_value() {
        // Only the top 2 bytes nonzero, the remaining 30 bytes zero: the
        // true value is exactly mantissa * 256^24, so the approximation
        // (which only looks at the leading 8 bytes plus a shift for the
        // rest) is exact, not just close.
        let mut work = [0u8; 32];
        work[0] = 0xAB;
        work[1] = 0xCD;
        let mantissa = u64::from_be_bytes([0xAB, 0xCD, 0, 0, 0, 0, 0, 0]);
        let expected = (mantissa as f64).log2() + 24.0 * 8.0;
        let got = chain_work_log2(&work);
        assert!(
            (got - expected).abs() < 1e-9,
            "got {got} expected {expected}"
        );
    }
}
