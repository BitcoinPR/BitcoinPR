use axum::extract::{Path, State};
use axum::Json;
use bitcoin::consensus::encode;
use bitcoin::{Block, Network, OutPoint};
use serde_json::{json, Value};

use crate::state::WebState;

/// Try to decode a script_pubkey to a human-readable address string.
pub(crate) fn script_to_addr(script_bytes: &[u8], network: Network) -> Option<String> {
    let script = bitcoin::Script::from_bytes(script_bytes);
    bitcoin::Address::from_script(script, network)
        .ok()
        .map(|a| a.to_string())
}

/// Build a JSON output object from a transaction output.
pub(crate) fn output_json(n: usize, out: &bitcoin::TxOut, network: Network) -> Value {
    let mut obj = json!({
        "n": n,
        "value": out.value.to_sat(),
        "script_pubkey": hex::encode(out.script_pubkey.as_bytes()),
    });
    if let Some(addr) = script_to_addr(out.script_pubkey.as_bytes(), network) {
        obj["address"] = json!(addr);
    }
    obj
}

/// Find the confirmed transaction that spends `outpoint`.
///
/// Uses the scripthash index to enumerate the transactions touching the
/// output's address, then loads each and checks for an input consuming
/// `outpoint`, returning `(spender_txid, vin)`. This relies on cross-block
/// spends being recorded in the scripthash index — without that, the spending
/// tx would never appear in the address's history and confirmed spends would be
/// unresolvable.
///
/// Scans at most `MAX_SPENDER_SCAN` candidate transactions so a heavily-reused
/// address can't make a single outspends lookup unbounded; returns `None` if
/// the spender isn't found within that budget (the caller then reports the
/// output as spent with an unknown spender, the prior behaviour).
fn find_confirmed_spender(
    state: &WebState,
    outpoint: &OutPoint,
    spk: &[u8],
) -> Option<(bitcoin::Txid, usize)> {
    const MAX_SPENDER_SCAN: usize = 1000;

    let index = state.scripthash_index.as_ref()?;
    let tx_index = state.tx_index.as_ref()?;
    let scripthash = bitcoinpr_index::ScripthashIndex::compute_scripthash(spk);
    let history = index.get_tx_history(&scripthash).ok()?;

    for entry in history.iter().take(MAX_SPENDER_SCAN) {
        let cand_txid: bitcoin::Txid = match entry.txid.parse() {
            Ok(t) => t,
            Err(_) => continue,
        };
        // The funding tx itself touches the address but can't spend its own output.
        if cand_txid == outpoint.txid {
            continue;
        }

        let idx_entry = match tx_index.get(&cand_txid).ok().flatten() {
            Some(e) => e,
            None => continue,
        };
        let pos = match state
            .header_index
            .get_block_pos(&idx_entry.block_hash)
            .ok()
            .flatten()
        {
            Some(p) => p,
            None => continue,
        };
        let raw = match state.block_store.read_block(&pos) {
            Ok(r) => r,
            Err(_) => continue,
        };
        let block = match encode::deserialize::<Block>(&raw) {
            Ok(b) => b,
            Err(_) => continue,
        };
        let tx = match block.txdata.get(idx_entry.tx_pos as usize) {
            Some(t) => t,
            None => continue,
        };

        for (vin, inp) in tx.input.iter().enumerate() {
            if &inp.previous_output == outpoint {
                return Some((cand_txid, vin));
            }
        }
    }

    None
}

/// Resolve value and address for a previous outpoint via tx_index + block_store.
pub(crate) fn resolve_prevout(state: &WebState, outpoint: &OutPoint) -> Option<(u64, Vec<u8>)> {
    let tx_index = state.tx_index.as_ref()?;
    let prev_entry = tx_index.get(&outpoint.txid).ok()??;
    let pos = state
        .header_index
        .get_block_pos(&prev_entry.block_hash)
        .ok()??;
    let raw = state.block_store.read_block(&pos).ok()?;
    let block = encode::deserialize::<Block>(&raw).ok()?;
    let prev_tx = block.txdata.get(prev_entry.tx_pos as usize)?;
    let prev_out = prev_tx.output.get(outpoint.vout as usize)?;
    Some((
        prev_out.value.to_sat(),
        prev_out.script_pubkey.as_bytes().to_vec(),
    ))
}

pub async fn get_transaction(
    State(state): State<WebState>,
    Path(txid_str): Path<String>,
) -> Json<Value> {
    let txid: bitcoin::Txid = match txid_str.parse() {
        Ok(t) => t,
        Err(_) => return Json(json!({"error": "Invalid transaction ID"})),
    };

    // Check mempool first — gives us the full Transaction object
    {
        let mempool = state.mempool.read().await;
        if let Some(entry) = mempool.get(&txid) {
            let inputs: Vec<Value> = entry
                .tx
                .input
                .iter()
                .map(|inp| {
                    let mut obj = json!({
                        "txid": inp.previous_output.txid.to_string(),
                        "vout": inp.previous_output.vout,
                        "sequence": inp.sequence.0,
                    });
                    // Resolve input value/address from UTXO set or other mempool txs
                    if let Ok(Some(utxo)) = state.utxo_set.get(&inp.previous_output) {
                        obj["value"] = json!(utxo.amount);
                        if let Some(addr) = script_to_addr(&utxo.script_pubkey, state.network) {
                            obj["address"] = json!(addr);
                        }
                    } else if let Some(prev_entry) = mempool.get(&inp.previous_output.txid) {
                        if let Some(prev_out) =
                            prev_entry.tx.output.get(inp.previous_output.vout as usize)
                        {
                            obj["value"] = json!(prev_out.value.to_sat());
                            if let Some(addr) =
                                script_to_addr(prev_out.script_pubkey.as_bytes(), state.network)
                            {
                                obj["address"] = json!(addr);
                            }
                        }
                    }
                    obj
                })
                .collect();

            let outputs: Vec<Value> = entry
                .tx
                .output
                .iter()
                .enumerate()
                .map(|(n, out)| output_json(n, out, state.network))
                .collect();

            return Json(json!({
                "txid": txid.to_string(),
                "confirmed": false,
                "confirmations": 0,
                "fee": entry.fee,
                "fee_rate": entry.fee_rate,
                "size": entry.size,
                "weight": entry.weight,
                "time": entry.time,
                "inputs": inputs,
                "outputs": outputs,
            }));
        }
    }

    // Fall through to on-disk tx index — load full block for rich tx data
    if let Some(ref tx_index) = state.tx_index {
        match tx_index.get(&txid) {
            Ok(Some(index_entry)) => {
                let best_height = *state.best_height.read().await;

                let (height, confirmations) =
                    match state.header_index.get_header(&index_entry.block_hash) {
                        Ok(Some(stored)) => {
                            let confs = (best_height as i64) - (stored.height as i64) + 1;
                            (stored.height, confs)
                        }
                        _ => (0, 0),
                    };

                // Try to load the full block and extract the transaction
                let full_tx = state
                    .header_index
                    .get_block_pos(&index_entry.block_hash)
                    .ok()
                    .flatten()
                    .and_then(|pos| state.block_store.read_block(&pos).ok())
                    .and_then(|raw| encode::deserialize::<Block>(&raw).ok())
                    .and_then(|block| block.txdata.get(index_entry.tx_pos as usize).cloned());

                if let Some(tx) = full_tx {
                    let is_coinbase = tx.is_coinbase();

                    let inputs: Vec<Value> = tx
                        .input
                        .iter()
                        .map(|inp| {
                            if is_coinbase {
                                return json!({ "coinbase": true });
                            }
                            let mut obj = json!({
                                "txid": inp.previous_output.txid.to_string(),
                                "vout": inp.previous_output.vout,
                                "sequence": inp.sequence.0,
                            });
                            if let Some((value, spk)) =
                                resolve_prevout(&state, &inp.previous_output)
                            {
                                obj["value"] = json!(value);
                                if let Some(addr) = script_to_addr(&spk, state.network) {
                                    obj["address"] = json!(addr);
                                }
                            }
                            obj
                        })
                        .collect();

                    let outputs: Vec<Value> = tx
                        .output
                        .iter()
                        .enumerate()
                        .map(|(n, out)| output_json(n, out, state.network))
                        .collect();

                    let size = encode::serialize(&tx).len();
                    let weight = tx.weight().to_wu();

                    // Calculate fee from input/output totals
                    let total_in: u64 = inputs
                        .iter()
                        .filter_map(|i| i.get("value").and_then(|v| v.as_u64()))
                        .sum();
                    let total_out: u64 = outputs
                        .iter()
                        .filter_map(|o| o.get("value").and_then(|v| v.as_u64()))
                        .sum();
                    let fee = if total_in > 0 && total_in >= total_out {
                        Some(total_in - total_out)
                    } else {
                        None
                    };

                    let vsize = weight.div_ceil(4);
                    let fee_rate = fee.map(|f| f as f64 / vsize as f64);

                    return Json(json!({
                        "txid": txid.to_string(),
                        "confirmed": true,
                        "block_hash": index_entry.block_hash.to_string(),
                        "block_height": height,
                        "tx_pos": index_entry.tx_pos,
                        "confirmations": confirmations,
                        "size": size,
                        "weight": weight,
                        "fee": fee,
                        "fee_rate": fee_rate,
                        "inputs": inputs,
                        "outputs": outputs,
                    }));
                }

                // Fallback: couldn't load full block, return minimal data
                return Json(json!({
                    "txid": txid.to_string(),
                    "confirmed": true,
                    "block_hash": index_entry.block_hash.to_string(),
                    "block_height": height,
                    "tx_pos": index_entry.tx_pos,
                    "confirmations": confirmations,
                }));
            }
            Ok(None) => {}
            Err(e) => {
                return Json(json!({"error": format!("Storage error: {e}")}));
            }
        }
    }

    Json(json!({"error": "Transaction not found"}))
}

/// Return the spend status of each output of a transaction, aligned by vout.
///
/// Considers only the mempool (for unconfirmed spenders) and the UTXO set
/// (for confirmed unspent outputs). Does not perform a scripthash scan, so a
/// confirmed-but-spent output reports a `null` spender txid.
pub async fn get_outspends(
    State(state): State<WebState>,
    Path(txid_str): Path<String>,
) -> Json<Value> {
    let txid: bitcoin::Txid = match txid_str.parse() {
        Ok(t) => t,
        Err(_) => return Json(json!({"error": "Invalid transaction ID"})),
    };

    let mempool = state.mempool.read().await;

    // Determine where the funding tx lives and load its outputs.
    let confirmed = state
        .tx_index
        .as_ref()
        .map(|idx| idx.contains(&txid).unwrap_or(false))
        .unwrap_or(false);

    let outputs: Vec<bitcoin::TxOut> = if let Some(entry) = mempool.get(&txid) {
        entry.tx.output.clone()
    } else if confirmed {
        // Load from the block via tx_index + block_store.
        let loaded = state.tx_index.as_ref().and_then(|idx| {
            let index_entry = idx.get(&txid).ok().flatten()?;
            let pos = state
                .header_index
                .get_block_pos(&index_entry.block_hash)
                .ok()
                .flatten()?;
            let raw = state.block_store.read_block(&pos).ok()?;
            let block = encode::deserialize::<Block>(&raw).ok()?;
            block
                .txdata
                .get(index_entry.tx_pos as usize)
                .map(|tx| tx.output.clone())
        });
        match loaded {
            Some(outs) => outs,
            None => return Json(json!({"error": "Transaction not found"})),
        }
    } else {
        return Json(json!({"error": "Transaction not found"}));
    };

    // Single pass over the mempool: map vout -> (spender_txid, vin) for any
    // input that spends one of this tx's outputs.
    let mut spenders: std::collections::HashMap<u32, (bitcoin::Txid, usize)> =
        std::collections::HashMap::new();
    for spender_txid in mempool.all_txids() {
        if let Some(entry) = mempool.get(&spender_txid) {
            for (vin, inp) in entry.tx.input.iter().enumerate() {
                if inp.previous_output.txid == txid {
                    spenders
                        .entry(inp.previous_output.vout)
                        .or_insert((spender_txid, vin));
                }
            }
        }
    }

    drop(mempool);

    let result: Vec<Value> = outputs
        .iter()
        .enumerate()
        .map(|(v, out)| {
            let vout = v as u32;
            let spk = out.script_pubkey.as_bytes();
            // OP_RETURN -> unspendable.
            if spk.first() == Some(&0x6a) {
                return json!({ "spent": false, "unspendable": true });
            }
            if let Some((spender, vin)) = spenders.get(&vout) {
                return json!({
                    "spent": true,
                    "confirmed": false,
                    "txid": spender.to_string(),
                    "vin": vin,
                });
            }
            if confirmed {
                let outpoint = OutPoint { txid, vout };
                let unspent = matches!(state.utxo_set.get(&outpoint), Ok(Some(_)));
                if !unspent {
                    // Resolve which confirmed tx spent this output so the
                    // explorer can expand the flow forward. Falls back to a
                    // null spender if the scripthash index can't pin it down.
                    if let Some((spender, vin)) = find_confirmed_spender(&state, &outpoint, spk) {
                        return json!({
                            "spent": true,
                            "confirmed": true,
                            "txid": spender.to_string(),
                            "vin": vin,
                        });
                    }
                    return json!({
                        "spent": true,
                        "confirmed": true,
                        "txid": Value::Null,
                    });
                }
            }
            json!({ "spent": false })
        })
        .collect();

    Json(Value::Array(result))
}
