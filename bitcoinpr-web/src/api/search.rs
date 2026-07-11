use axum::extract::{Path, State};
use axum::Json;
use serde_json::{json, Value};

use crate::state::WebState;

pub async fn search(State(state): State<WebState>, Path(query): Path<String>) -> Json<Value> {
    let query = query.trim();

    // 1. Try as block height (purely numeric)
    if let Ok(height) = query.parse::<u32>() {
        if let Ok(Some(hash)) = state.header_index.get_hash_at_height(height) {
            return Json(json!({
                "type": "block",
                "height": height,
                "hash": hash.to_string(),
            }));
        }
    }

    // 2. 64-character hex — could be a block hash or txid
    if is_hex64(query) {
        // Try as block hash
        if let Ok(hash) = query.parse::<bitcoin::BlockHash>() {
            if let Ok(Some(stored)) = state.header_index.get_header(&hash) {
                return Json(json!({
                    "type": "block",
                    "height": stored.height,
                    "hash": hash.to_string(),
                }));
            }
        }

        // Try as transaction ID (mempool, then on-disk index)
        if let Ok(txid) = query.parse::<bitcoin::Txid>() {
            {
                let mempool = state.mempool.read().await;
                if mempool.contains(&txid) {
                    return Json(json!({
                        "type": "tx",
                        "txid": txid.to_string(),
                    }));
                }
            }

            if let Some(ref tx_index) = state.tx_index {
                if let Ok(Some(_)) = tx_index.get(&txid) {
                    return Json(json!({
                        "type": "tx",
                        "txid": txid.to_string(),
                    }));
                }
            }
        }
    }

    // 3. Try as a Bitcoin address
    if let Ok(unchecked) = query.parse::<bitcoin::Address<bitcoin::address::NetworkUnchecked>>() {
        if unchecked.require_network(state.network).is_ok() {
            return Json(json!({
                "type": "address",
                "address": query,
            }));
        }
    }

    // 4. Nothing matched
    Json(json!({"type": "not_found"}))
}

fn is_hex64(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}
