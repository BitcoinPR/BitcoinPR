use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use serde_json::{json, Value};

use bitcoinpr_mining::MiningMode;

use crate::state::WebState;

pub async fn get_mining_stats(State(state): State<WebState>) -> Json<Value> {
    let dashboard = match &state.mining_dashboard {
        Some(d) => d,
        None => return Json(json!({"error": "Mining is not enabled"})),
    };

    let snap = dashboard.snapshot().await;
    Json(json!({
        "hashrate": snap.hashrate,
        "hashrate_unit": snap.hashrate_unit,
        "shares_accepted": snap.shares_accepted,
        "shares_rejected": snap.shares_rejected,
        "blocks_found": snap.blocks_found,
        "best_share_difficulty": snap.best_share_difficulty,
        "connected_workers": snap.connected_workers,
        "uptime_secs": snap.uptime_secs,
        "solo_mining": snap.solo_mining,
        "gateway_status": snap.gateway_status,
        "datum_status": snap.datum_status,
    }))
}

pub async fn get_workers(State(state): State<WebState>) -> Json<Value> {
    let dashboard = match &state.mining_dashboard {
        Some(d) => d,
        None => return Json(json!({"workers": []})),
    };

    let workers: Vec<Value> = dashboard
        .workers()
        .await
        .into_iter()
        .map(|w| {
            json!({
                "name": w.name,
                "hashrate": w.hashrate,
                "shares_accepted": w.shares_accepted,
                "shares_rejected": w.shares_rejected,
                "last_share_time": w.last_share_time,
            })
        })
        .collect();

    Json(json!({ "workers": workers }))
}

pub async fn get_share_history(State(state): State<WebState>) -> Json<Value> {
    let dashboard = match &state.mining_dashboard {
        Some(d) => d,
        None => return Json(json!({"shares": []})),
    };

    let shares: Vec<Value> = dashboard
        .recent_shares(100)
        .await
        .into_iter()
        .map(|s| {
            json!({
                "worker": s.worker,
                "timestamp": s.timestamp,
                "difficulty": s.difficulty,
                "accepted": s.accepted,
            })
        })
        .collect();

    Json(json!({ "shares": shares }))
}

pub async fn get_mining_config(State(state): State<WebState>) -> Json<Value> {
    let cfg = match &state.mining_config {
        Some(c) => c.read().await.clone(),
        None => return Json(json!({"error": "Mining is not enabled"})),
    };
    Json(json!({
        "mining_address": cfg.mining_address,
        "coinbase_tag": cfg.coinbase_tag_str(),
        "pool_name": cfg.pool_name,
        "stratum_port": cfg.stratum_port,
        "mode": cfg.mode,
        "datum": {
            "server_url": cfg.datum.server_url,
            "payout_address": cfg.datum.payout_address,
            "worker_name": cfg.datum.worker_name,
            // never echo back the auth token in plaintext beyond a presence flag
            "auth_token_set": cfg.datum.auth_token.is_some(),
        },
    }))
}

pub async fn update_mining_config(
    State(state): State<WebState>,
    headers: axum::http::HeaderMap,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    // Changing the coinbase payout is wallet-adjacent: require the admin
    // token (and same-origin) before even looking at the request body.
    if let Err(reject) = crate::auth::authorize_admin(&headers, state.web_admin_token.as_deref()) {
        return reject;
    }

    let cfg_lock = match &state.mining_config {
        Some(c) => c,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "Mining is not enabled"})),
            )
        }
    };

    let mut new_cfg = cfg_lock.read().await.clone();

    // mining_address: distinguish absent vs present(null/empty -> None).
    if let Some(v) = body.get("mining_address") {
        if v.is_null() {
            new_cfg.mining_address = None;
        } else if let Some(s) = v.as_str() {
            new_cfg.mining_address = if s.is_empty() {
                None
            } else {
                Some(s.to_string())
            };
        }
    }

    if let Some(s) = body.get("coinbase_tag").and_then(|v| v.as_str()) {
        new_cfg.coinbase_tag = s.as_bytes().to_vec();
    }

    if let Some(s) = body.get("pool_name").and_then(|v| v.as_str()) {
        new_cfg.pool_name = s.to_string();
    }

    if let Some(v) = body.get("mode") {
        match v.as_str() {
            Some("solo") => new_cfg.mode = MiningMode::Solo,
            Some("datum") => new_cfg.mode = MiningMode::Datum,
            _ => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({"error": "invalid mode: expected \"solo\" or \"datum\""})),
                )
            }
        }
    }

    if let Some(datum) = body.get("datum") {
        if let Some(s) = datum.get("server_url").and_then(|v| v.as_str()) {
            new_cfg.datum.server_url = s.to_string();
        }
        if let Some(s) = datum.get("payout_address").and_then(|v| v.as_str()) {
            new_cfg.datum.payout_address = s.to_string();
        }
        if let Some(s) = datum.get("worker_name").and_then(|v| v.as_str()) {
            new_cfg.datum.worker_name = s.to_string();
        }
        if let Some(v) = datum.get("auth_token") {
            if v.is_null() {
                new_cfg.datum.auth_token = None;
            } else if let Some(s) = v.as_str() {
                new_cfg.datum.auth_token = if s.is_empty() {
                    None
                } else {
                    Some(s.to_string())
                };
            }
        }
    }

    if let Err(msg) = new_cfg.validate() {
        return (StatusCode::BAD_REQUEST, Json(json!({"error": msg})));
    }

    // Persist to mining.toml; failure is non-fatal (reported via "persisted").
    let mut persisted = true;
    if let Some(dir) = &state.datadir {
        if let Err(e) = new_cfg.save(dir) {
            tracing::warn!(error = %e, "failed to persist mining config");
            persisted = false;
        }
    } else {
        persisted = false;
    }

    *cfg_lock.write().await = new_cfg.clone();

    if let Some(tx) = &state.mining_config_tx {
        tx.send_modify(|v| *v += 1);
    }

    (
        StatusCode::OK,
        Json(json!({
            "ok": true,
            "persisted": persisted,
            "config": {
                "mining_address": new_cfg.mining_address,
                "coinbase_tag": new_cfg.coinbase_tag_str(),
                "pool_name": new_cfg.pool_name,
                "stratum_port": new_cfg.stratum_port,
                "mode": new_cfg.mode,
                "datum": {
                    "server_url": new_cfg.datum.server_url,
                    "payout_address": new_cfg.datum.payout_address,
                    "worker_name": new_cfg.datum.worker_name,
                    "auth_token_set": new_cfg.datum.auth_token.is_some(),
                },
            },
        })),
    )
}
