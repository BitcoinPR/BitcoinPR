use axum::extract::{Path, State};
use axum::Json;
use serde_json::{json, Value};

use bitcoinpr_index::ScripthashIndex;

use crate::state::WebState;

pub async fn get_address(
    State(state): State<WebState>,
    Path(address): Path<String>,
) -> Json<Value> {
    let index = match &state.scripthash_index {
        Some(idx) => idx,
        None => return Json(json!({"error": "Address indexing is not enabled"})),
    };

    let unchecked: bitcoin::Address<bitcoin::address::NetworkUnchecked> = match address.parse() {
        Ok(a) => a,
        Err(_) => return Json(json!({"error": "Invalid Bitcoin address"})),
    };

    let checked = match unchecked.require_network(state.network) {
        Ok(a) => a,
        Err(_) => {
            return Json(json!({
                "error": format!("Address is not valid for network {}", state.network)
            }))
        }
    };

    let script = checked.script_pubkey();
    let scripthash = ScripthashIndex::compute_scripthash(script.as_bytes());

    let balance = match index.get_balance(&scripthash) {
        Ok(b) => b,
        Err(e) => return Json(json!({"error": format!("Index error: {e}")})),
    };
    let history = match index.get_tx_history(&scripthash) {
        Ok(h) => h,
        Err(e) => return Json(json!({"error": format!("Index error: {e}")})),
    };

    let tx_entries: Vec<Value> = history
        .iter()
        .map(|h| {
            json!({
                "txid": h.txid,
                "height": h.height,
                "tx_index": h.tx_index,
            })
        })
        .collect();

    Json(json!({
        "address": address,
        "scripthash": hex::encode(scripthash),
        "balance": {
            "confirmed": balance.confirmed,
            "unconfirmed": balance.unconfirmed,
        },
        "tx_count": tx_entries.len(),
        "tx_history": tx_entries,
    }))
}
