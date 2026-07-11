use axum::extract::{Query, State};
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::state::WebState;

#[derive(Deserialize)]
pub struct PaginationParams {
    page: Option<usize>,
    per_page: Option<usize>,
}

/// Fee-rate bucket boundaries (sat/vB) and labels.
const FEE_BUCKETS: &[(f64, f64, &str)] = &[
    (0.0, 1.0, "0-1"),
    (1.0, 2.0, "1-2"),
    (2.0, 5.0, "2-5"),
    (5.0, 10.0, "5-10"),
    (10.0, 20.0, "10-20"),
    (20.0, 50.0, "20-50"),
    (50.0, 100.0, "50-100"),
    (100.0, 500.0, "100-500"),
    (500.0, f64::MAX, "500+"),
];

/// Rolling history of periodic mempool fee-rate samples (oldest -> newest).
pub async fn get_mempool_history(State(state): State<WebState>) -> Json<Value> {
    let history = state.mempool_history.read().await;
    let samples: Vec<Value> = history.iter().map(|s| json!(s)).collect();
    Json(json!({ "samples": samples }))
}

/// Summary of mempool state including a fee-rate histogram.
pub async fn get_mempool(State(state): State<WebState>) -> Json<Value> {
    let mempool = state.mempool.read().await;

    let size = mempool.size();
    let total_bytes = mempool.total_bytes();
    let total_fee = mempool.total_fees();

    let mut buckets: Vec<(usize, usize)> = vec![(0, 0); FEE_BUCKETS.len()];

    let txids = mempool.all_txids();
    for txid in &txids {
        if let Some(entry) = mempool.get(txid) {
            for (i, &(lo, hi, _)) in FEE_BUCKETS.iter().enumerate() {
                if entry.fee_rate >= lo && entry.fee_rate < hi {
                    buckets[i].0 += 1;
                    buckets[i].1 += entry.size;
                    break;
                }
            }
        }
    }

    drop(mempool);

    let histogram: Vec<Value> = FEE_BUCKETS
        .iter()
        .zip(buckets.iter())
        .map(|(&(_, _, label), &(count, bytes))| {
            json!({
                "range": label,
                "count": count,
                "size": bytes,
            })
        })
        .collect();

    Json(json!({
        "size": size,
        "bytes": total_bytes,
        "total_fee": total_fee,
        "fee_histogram": histogram,
    }))
}

/// Paginated list of mempool transactions sorted by fee rate (descending).
pub async fn get_mempool_txs(
    State(state): State<WebState>,
    Query(params): Query<PaginationParams>,
) -> Json<Value> {
    let page = params.page.unwrap_or(1).max(1);
    let per_page = params.per_page.unwrap_or(25).clamp(1, 100);

    let mempool = state.mempool.read().await;
    let txids = mempool.all_txids();

    let mut tx_list: Vec<(f64, Value)> = txids
        .iter()
        .filter_map(|txid| {
            mempool.get(txid).map(|entry| {
                (
                    entry.fee_rate,
                    json!({
                        "txid": txid.to_string(),
                        "fee": entry.fee,
                        "fee_rate": entry.fee_rate,
                        "size": entry.size,
                        "weight": entry.weight,
                        "time": entry.time,
                    }),
                )
            })
        })
        .collect();

    // Release the lock before sorting
    drop(mempool);

    tx_list.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal));

    let total = tx_list.len();
    let start = (page - 1) * per_page;
    let transactions: Vec<Value> = if start < total {
        tx_list[start..(start + per_page).min(total)]
            .iter()
            .map(|(_, v)| v.clone())
            .collect()
    } else {
        vec![]
    };

    Json(json!({
        "total": total,
        "page": page,
        "per_page": per_page,
        "transactions": transactions,
    }))
}
