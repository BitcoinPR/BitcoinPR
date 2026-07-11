use axum::extract::{Query, State};
use axum::Json;
use bitcoin::consensus::encode;
use bitcoin::Block;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::api::txs::resolve_prevout;
use crate::state::WebState;

#[derive(Deserialize)]
pub struct RecentParams {
    limit: Option<usize>,
}

/// Maximum number of recent blocks to scan when collecting recent txs.
const MAX_BLOCKS_SCANNED: u32 = 8;

/// Return the most recent confirmed transactions, walking backward from the tip.
pub async fn get_recent_txs(
    State(state): State<WebState>,
    Query(params): Query<RecentParams>,
) -> Json<Value> {
    let limit = params.limit.unwrap_or(12).clamp(1, 50);

    let best_height = *state.best_height.read().await;

    let mut transactions: Vec<Value> = Vec::with_capacity(limit);
    let mut blocks_scanned = 0u32;
    let mut height = best_height;

    loop {
        if transactions.len() >= limit || blocks_scanned >= MAX_BLOCKS_SCANNED {
            break;
        }

        let hash = match state.header_index.get_hash_at_height(height) {
            Ok(Some(h)) => h,
            _ => {
                if height == 0 {
                    break;
                }
                height -= 1;
                continue;
            }
        };

        let block = state
            .header_index
            .get_block_pos(&hash)
            .ok()
            .flatten()
            .and_then(|pos| state.block_store.read_block(&pos).ok())
            .and_then(|raw| encode::deserialize::<Block>(&raw).ok());

        blocks_scanned += 1;

        if let Some(block) = block {
            let block_time = block.header.time;
            let block_hash = hash.to_string();

            for tx in &block.txdata {
                if transactions.len() >= limit {
                    break;
                }

                let is_coinbase = tx.is_coinbase();
                let value: u64 = tx.output.iter().map(|o| o.value.to_sat()).sum();
                let size = encode::serialize(tx).len();
                let weight = tx.weight().to_wu();
                let vsize = weight.div_ceil(4);

                let fee = if is_coinbase {
                    None
                } else {
                    let mut total_in: u64 = 0;
                    let mut resolved_all = true;
                    for inp in &tx.input {
                        match resolve_prevout(&state, &inp.previous_output) {
                            Some((v, _)) => total_in += v,
                            None => {
                                resolved_all = false;
                                break;
                            }
                        }
                    }
                    if resolved_all && total_in >= value {
                        Some(total_in - value)
                    } else {
                        None
                    }
                };

                transactions.push(json!({
                    "txid": tx.compute_txid().to_string(),
                    "block_height": height,
                    "block_hash": block_hash,
                    "time": block_time,
                    "value": value,
                    "fee": fee,
                    "size": size,
                    "vsize": vsize,
                    "is_coinbase": is_coinbase,
                }));
            }
        }

        if height == 0 {
            break;
        }
        height -= 1;
    }

    Json(json!({ "transactions": transactions }))
}
