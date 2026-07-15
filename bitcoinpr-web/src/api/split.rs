//! Chain-split monitor API.
//!
//! `GET /api/split` — BIP-110 mode, the tracked rival branch (fork point,
//! both tips, block/work deficit, capitulation arming), and whether the
//! operator has abandoned BIP-110 ("abandon minority chain"). `split` is
//! `null` while no rival branch is tracked.

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};
use tracing::warn;

use crate::state::WebState;

/// Confirmation phrase the operator must type to abandon the minority chain.
const CONFIRM_PHRASE: &str = "ABANDON-BIP110";

pub async fn get_split(State(state): State<WebState>) -> Json<Value> {
    let abandoned_at = state.header_index.get_bip110_abandoned().ok().flatten();
    let mode = if abandoned_at.is_some() {
        "abandoned"
    } else if state.params.bip110_activation_height.is_some() {
        "fixed"
    } else if state.params.bip110_deployment.is_some() {
        "signaling"
    } else {
        "disabled"
    };

    let monitor = state.split_monitor.clone();
    // The snapshot walks RocksDB prev-links; keep it off the async worker.
    let split = match monitor {
        Some(m) => tokio::task::spawn_blocking(move || m.snapshot())
            .await
            .ok()
            .flatten(),
        None => None,
    };

    // Mirrors /api/stats split_active: the split is "live" while a rival
    // matches/exceeds our work; a resolved (out-worked) rival keeps the page
    // but not the nav tab.
    let split_live = state
        .split_monitor
        .as_ref()
        .map(|m| m.rival_leads())
        .unwrap_or(false);

    Json(json!({
        "bip110": {
            "mode": mode,
            "activation_height": state.params.bip110_activation_height,
        },
        "split": split,
        "split_live": split_live,
        "abandoned": abandoned_at.is_some(),
        "abandoned_at": abandoned_at,
        "threshold_blocks": bitcoinpr_core::CAPITULATION_THRESHOLD_BLOCKS,
    }))
}

#[derive(Deserialize)]
pub struct CapitulateRequest {
    /// Must equal `ABANDON-BIP110`.
    pub confirm: String,
    /// Abandon even while the split monitor has not armed.
    #[serde(default)]
    pub force: bool,
}

/// `POST /api/split/capitulate` — "abandon minority chain".
///
/// Persists the BIP-110 abandon flag (WAL-flushed) and gracefully shuts the
/// node down; the supervisor (docker `restart: unless-stopped`, systemd, …)
/// restarts it, and startup then disables RDTS enforcement, clears the
/// invalid-block markers, and the node reorgs onto the most-work chain.
/// Gated by the same-origin + admin-token check used for mining config.
pub async fn capitulate(
    State(state): State<WebState>,
    headers: HeaderMap,
    Json(req): Json<CapitulateRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    crate::auth::authorize_admin(&headers, state.web_admin_token.as_deref())?;

    if req.confirm != CONFIRM_PHRASE {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": format!("confirmation phrase mismatch: type {CONFIRM_PHRASE} to proceed")
            })),
        ));
    }

    let (Some(shutdown_tx), Some(shutting_down)) =
        (state.shutdown_tx.clone(), state.shutting_down.clone())
    else {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({ "error": "node shutdown channel unavailable" })),
        ));
    };

    let armed = match state.split_monitor.clone() {
        Some(m) => tokio::task::spawn_blocking(move || m.snapshot())
            .await
            .ok()
            .flatten()
            .map(|s| s.capitulation_armed)
            .unwrap_or(false),
        None => false,
    };
    if !armed && !req.force {
        return Err((
            StatusCode::CONFLICT,
            Json(json!({
                "error": "capitulation is not armed (rival chain lead below threshold); \
                          pass force=true to abandon BIP-110 anyway"
            })),
        ));
    }

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let header_index = state.header_index.clone();
    tokio::task::spawn_blocking(move || header_index.set_bip110_abandoned(now))
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "flag persistence task failed" })),
            )
        })?
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": format!("failed to persist flag: {e}") })),
            )
        })?;

    warn!("capitulate: minority chain abandoned by operator — shutting down");
    shutting_down.store(true, std::sync::atomic::Ordering::Relaxed);
    tokio::spawn(async move {
        let _ = shutdown_tx.send(()).await;
    });

    Ok(Json(json!({ "abandoned_at": now, "shutting_down": true })))
}
