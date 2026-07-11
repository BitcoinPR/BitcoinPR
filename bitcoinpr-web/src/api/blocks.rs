use axum::extract::{Path, Query, State};
use axum::Json;
use bitcoin::consensus::encode;
use bitcoin::Block;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::api::txs::{resolve_prevout, script_to_addr};
use crate::state::WebState;

#[derive(Deserialize)]
pub struct BlockParams {
    page: Option<usize>,
    per_page: Option<usize>,
}

/// Maximum number of inputs/outputs included per tx in the block listing.
const MAX_IO_PER_TX: usize = 8;

pub async fn get_block(
    State(state): State<WebState>,
    Path(hash_or_height): Path<String>,
    Query(params): Query<BlockParams>,
) -> Json<Value> {
    let page = params.page.unwrap_or(1).max(1);
    let per_page = params.per_page.unwrap_or(25).clamp(1, 100);

    if let Ok(height) = hash_or_height.parse::<u32>() {
        return match state.header_index.get_hash_at_height(height) {
            Ok(Some(hash)) => get_block_by_hash(&state, &hash, page, per_page).await,
            Ok(None) => Json(json!({"error": "Block not found at this height"})),
            Err(e) => Json(json!({"error": format!("Storage error: {e}")})),
        };
    }

    match hash_or_height.parse::<bitcoin::BlockHash>() {
        Ok(hash) => get_block_by_hash(&state, &hash, page, per_page).await,
        Err(_) => Json(json!({"error": "Invalid block hash or height"})),
    }
}

async fn get_block_by_hash(
    state: &WebState,
    hash: &bitcoin::BlockHash,
    page: usize,
    per_page: usize,
) -> Json<Value> {
    let stored = match state.header_index.get_header(hash) {
        Ok(Some(s)) => s,
        Ok(None) => return Json(json!({"error": "Block not found"})),
        Err(e) => return Json(json!({"error": format!("Storage error: {e}")})),
    };

    let best_height = *state.best_height.read().await;
    let confirmations = (best_height as i64) - (stored.height as i64) + 1;

    let mut response = json!({
        "hash": hash.to_string(),
        "height": stored.height,
        "confirmations": confirmations,
        "version": stored.header.version.to_consensus(),
        "merkleroot": stored.header.merkle_root.to_string(),
        "time": stored.header.time,
        "nonce": stored.header.nonce,
        "bits": format!("{:x}", stored.header.bits.to_consensus()),
        "difficulty": bits_to_difficulty(stored.header.bits.to_consensus()),
        "previousblockhash": stored.header.prev_blockhash.to_string(),
    });

    // Try to load the full block to expose per-tx details. If this fails for
    // any reason, fall back to the header-only response above.
    let block = state
        .header_index
        .get_block_pos(hash)
        .ok()
        .flatten()
        .and_then(|pos| state.block_store.read_block(&pos).ok())
        .and_then(|raw| encode::deserialize::<Block>(&raw).ok());

    if let Some(block) = block {
        let tx_count = block.txdata.len();
        let start = (page - 1) * per_page;
        let end = (start + per_page).min(tx_count);

        let txs: Vec<Value> = if start < tx_count {
            block.txdata[start..end]
                .iter()
                .map(|tx| tx_json(state, tx))
                .collect()
        } else {
            vec![]
        };

        // Miner fee revenue: coinbase output total minus the block subsidy.
        // Saturating handles miners that claimed less than the full subsidy.
        if let Some(coinbase) = block.txdata.first() {
            let coinbase_out: u64 = coinbase.output.iter().map(|o| o.value.to_sat()).sum();
            let subsidy = state.params.block_subsidy(stored.height);
            response["fees"] = json!(coinbase_out.saturating_sub(subsidy));
        }

        response["tx_count"] = json!(tx_count);
        response["page"] = json!(page);
        response["per_page"] = json!(per_page);
        response["txs"] = json!(txs);
    }

    Json(response)
}

/// Build the per-tx JSON object for the block transaction listing.
fn tx_json(state: &WebState, tx: &bitcoin::Transaction) -> Value {
    let is_coinbase = tx.is_coinbase();
    let value: u64 = tx.output.iter().map(|o| o.value.to_sat()).sum();
    let size = encode::serialize(tx).len();
    let weight = tx.weight().to_wu();
    let vsize = weight.div_ceil(4);

    let inputs_count = tx.input.len();
    let outputs_count = tx.output.len();

    // Resolve inputs (bounded to MAX_IO_PER_TX). Accumulate total_in over the
    // resolved inputs we actually visit for fee calculation; only consider the
    // fee resolvable when every input resolves.
    let mut total_in: u64 = 0;
    let mut all_resolved = !is_coinbase;
    let inputs: Vec<Value> = if is_coinbase {
        tx.input
            .iter()
            .take(MAX_IO_PER_TX)
            .map(|_| json!({ "coinbase": true }))
            .collect()
    } else {
        tx.input
            .iter()
            .take(MAX_IO_PER_TX)
            .map(|inp| {
                let mut obj = json!({
                    "txid": inp.previous_output.txid.to_string(),
                    "vout": inp.previous_output.vout,
                });
                if let Some((v, spk)) = resolve_prevout(state, &inp.previous_output) {
                    obj["value"] = json!(v);
                    if let Some(addr) = script_to_addr(&spk, state.network) {
                        obj["address"] = json!(addr);
                    }
                }
                obj
            })
            .collect()
    };

    // Fee: resolve ALL inputs (not just the displayed ones) for correctness.
    let fee = if is_coinbase {
        None
    } else {
        for inp in &tx.input {
            match resolve_prevout(state, &inp.previous_output) {
                Some((v, _)) => total_in += v,
                None => {
                    all_resolved = false;
                    break;
                }
            }
        }
        if all_resolved && total_in >= value {
            Some(total_in - value)
        } else {
            None
        }
    };

    let outputs: Vec<Value> = tx
        .output
        .iter()
        .enumerate()
        .take(MAX_IO_PER_TX)
        .map(|(n, out)| {
            let mut obj = json!({
                "n": n,
                "value": out.value.to_sat(),
                "script_pubkey": hex::encode(out.script_pubkey.as_bytes()),
            });
            if let Some(addr) = script_to_addr(out.script_pubkey.as_bytes(), state.network) {
                obj["address"] = json!(addr);
            }
            obj
        })
        .collect();

    json!({
        "txid": tx.compute_txid().to_string(),
        "is_coinbase": is_coinbase,
        "value": value,
        "fee": fee,
        "size": size,
        "vsize": vsize,
        "weight": weight,
        "inputs_count": inputs_count,
        "outputs_count": outputs_count,
        "inputs": inputs,
        "outputs": outputs,
    })
}

fn bits_to_difficulty(bits: u32) -> f64 {
    let exponent = (bits >> 24) as i32;
    let mantissa = (bits & 0x00ffffff) as f64;
    if mantissa == 0.0 {
        return 0.0;
    }
    (65535.0 / mantissa) * 2f64.powi(8 * (0x1d - exponent))
}
