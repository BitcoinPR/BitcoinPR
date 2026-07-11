use std::path::Path;
use std::sync::atomic::Ordering;

use axum::extract::State;
use axum::Json;
use serde_json::{json, Value};

use crate::state::WebState;

/// Node operator overview: version, sync/index progress, storage usage,
/// and exposed services. Backs the "Info" page.
pub async fn get_info(State(state): State<WebState>) -> Json<Value> {
    let best_height = *state.best_height.read().await;
    let best_hash = *state.best_hash.read().await;

    let header_tip = state
        .header_index
        .get_header_tip_height()
        .ok()
        .flatten()
        .unwrap_or(best_height);

    // Timestamp of the last verified block, so the UI can show tip age and
    // estimate overall chain progress during IBD.
    let tip_time = state
        .header_index
        .get_header(&best_hash)
        .ok()
        .flatten()
        .map(|s| s.header.time);

    let txindex_height = state
        .tx_index
        .as_ref()
        .map(|t| t.get_indexed_height().ok().flatten().unwrap_or(0));
    let addrindex_height = state
        .scripthash_index
        .as_ref()
        .map(|i| i.get_indexed_height().ok().flatten().unwrap_or(0));
    let pruned_height = state.header_index.get_pruned_height().ok().flatten();

    let (mempool_size, mempool_bytes) = {
        let mempool = state.mempool.read().await;
        (mempool.size(), mempool.total_bytes())
    };
    let peer_count = state.peers.read().await.len();

    // On-disk usage per datadir component; walked off the async executor.
    let storage = match state.datadir.clone() {
        Some(dir) => {
            let blocks_dir = state.blocks_dir.clone();
            tokio::task::spawn_blocking(move || storage_breakdown(&dir, blocks_dir.as_deref()))
                .await
                .unwrap_or_default()
        }
        None => vec![],
    };
    let storage_total: u64 = storage.iter().map(|(_, s)| s).sum();
    let storage_json: Vec<Value> = storage
        .iter()
        .map(|(name, size)| json!({ "name": name, "bytes": size }))
        .collect();

    Json(json!({
        "node_version": env!("CARGO_PKG_VERSION"),
        "user_agent": format!("/BitcoinPR:{}/", env!("CARGO_PKG_VERSION")),
        "network": state.network.to_string(),
        "uptime_secs": state.start_time.elapsed().as_secs(),
        "is_ibd": state.is_ibd.load(Ordering::Relaxed),
        "header_tip": header_tip,
        "blocks_verified": best_height,
        "best_hash": best_hash.to_string(),
        "tip_time": tip_time,
        "txindex_height": txindex_height,
        "addrindex_height": addrindex_height,
        "pruned_height": pruned_height,
        "peer_count": peer_count,
        "mempool_size": mempool_size,
        "mempool_bytes": mempool_bytes,
        "mining_enabled": state.mining_enabled,
        "datadir": state.datadir.as_ref().map(|d| d.display().to_string()),
        "storage": storage_json,
        "storage_total_bytes": storage_total,
        "services": state.services,
    }))
}

/// Per-component disk usage of the datadir: one entry per subdirectory
/// (blocks, utxo, headers, ...) plus an "other" bucket for loose files
/// (logs, mempool.dat, ...). When the block files live outside the datadir
/// (--blocksdir), they are counted explicitly so the breakdown still shows
/// them. Sorted largest-first.
fn storage_breakdown(datadir: &Path, blocks_dir: Option<&Path>) -> Vec<(String, u64)> {
    let mut out: Vec<(String, u64)> = Vec::new();
    let mut loose_files: u64 = 0;

    let Ok(entries) = std::fs::read_dir(datadir) else {
        return out;
    };
    for entry in entries.flatten() {
        let Ok(meta) = entry.metadata() else { continue };
        if meta.is_dir() {
            let name = entry.file_name().to_string_lossy().into_owned();
            out.push((name, dir_size(&entry.path(), 0)));
        } else {
            loose_files += meta.len();
        }
    }
    if loose_files > 0 {
        out.push(("other".to_string(), loose_files));
    }

    // A relocated blocks dir is not a datadir subdirectory, so the walk above
    // missed it; add it under the same "blocks" component name.
    if let Some(bd) = blocks_dir {
        if !bd.starts_with(datadir) {
            out.push(("blocks".to_string(), dir_size(bd, 0)));
        }
    }

    out.sort_by(|a, b| b.1.cmp(&a.1));
    out
}

fn dir_size(path: &Path, depth: u32) -> u64 {
    if depth > 8 {
        return 0;
    }
    let Ok(entries) = std::fs::read_dir(path) else {
        return 0;
    };
    entries
        .flatten()
        .filter_map(|e| {
            let meta = e.metadata().ok()?;
            Some(if meta.is_dir() {
                dir_size(&e.path(), depth + 1)
            } else {
                meta.len()
            })
        })
        .sum()
}
