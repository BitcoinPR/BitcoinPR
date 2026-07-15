use axum::extract::State;
use axum::Json;
use serde_json::{json, Value};

use crate::state::WebState;

pub async fn get_stats(State(state): State<WebState>) -> Json<Value> {
    let best_height = *state.best_height.read().await;
    let best_hash = *state.best_hash.read().await;

    let (mempool_size, mempool_bytes) = {
        let mempool = state.mempool.read().await;
        (mempool.size(), mempool.total_bytes())
    };

    let peer_count = state.peers.read().await.len();

    let difficulty = match state.header_index.get_header(&best_hash) {
        Ok(Some(stored)) => bits_to_difficulty(stored.header.bits.to_consensus()),
        _ => 0.0,
    };

    let uptime_secs = state.start_time.elapsed().as_secs();

    // Split page visibility: only surface the tab while the network is
    // genuinely contested — a tracked rival branch at or above our chain
    // work. Hidden when no rival is tracked AND once we out-work the rival
    // (split resolved in our favor); the page stays reachable at #/split
    // until a restart clears the tracker. Allocation-free state reads.
    let split_active = state
        .split_monitor
        .as_ref()
        .map(|m| m.rival_leads())
        .unwrap_or(false);

    Json(json!({
        "height": best_height,
        "best_hash": best_hash.to_string(),
        "difficulty": difficulty,
        "network": state.network.to_string(),
        "mempool_size": mempool_size,
        "mempool_bytes": mempool_bytes,
        "peer_count": peer_count,
        "uptime_secs": uptime_secs,
        "node_version": env!("CARGO_PKG_VERSION"),
        "mining_enabled": state.mining_enabled,
        "split_active": split_active,
    }))
}

pub async fn get_peers(State(state): State<WebState>) -> Json<Value> {
    let peers = state.peers.read().await;
    Json(json!({ "peers": *peers }))
}

fn bits_to_difficulty(bits: u32) -> f64 {
    let exponent = (bits >> 24) as i32;
    let mantissa = (bits & 0x00ffffff) as f64;
    if mantissa == 0.0 {
        return 0.0;
    }
    (65535.0 / mantissa) * 2f64.powi(8 * (0x1d - exponent))
}
