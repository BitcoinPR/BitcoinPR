use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::State;
use axum::response::IntoResponse;
use tracing::{debug, warn};

use bitcoinpr_core::NodeNotification;

use crate::state::WebState;

/// How far the validated block tip may trail the downloaded header tip before a
/// `NewBlock` notification is treated as catch-up (IBD) progress and suppressed.
/// A small margin tolerates the normal race where a block's header is known a
/// block or two ahead of its connection at the chain tip, while still hiding the
/// thousands of per-block events during a real sync.
const IBD_NOTIFY_MARGIN: u32 = 4;

/// Decide whether a freshly-connected block at `height` should be suppressed as
/// initial-block-download progress.
///
/// We deliberately do *not* trust the `is_ibd` latch here: it is a one-way flag
/// (set once at startup, only ever cleared) and can be cleared before the chain
/// is actually synced, after which it never re-arms — leaving the web UI to toast
/// every block for the rest of IBD. Comparing the validated block height against
/// the downloaded header tip (the same signal the RPC layer uses for
/// `getblockchaininfo`'s IBD state) is self-correcting and can't get stuck.
fn is_catching_up(state: &WebState, height: u32) -> bool {
    let header_tip = state
        .header_index
        .get_header_tip_height()
        .ok()
        .flatten()
        .unwrap_or(0);
    header_tip.saturating_sub(height) > IBD_NOTIFY_MARGIN
}

pub async fn ws_handler(ws: WebSocketUpgrade, State(state): State<WebState>) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_socket(socket, state))
}

async fn handle_socket(mut socket: WebSocket, state: WebState) {
    debug!("WebSocket client connected");
    let mut rx = state.event_bus.subscribe();

    loop {
        tokio::select! {
            result = rx.recv() => {
                match result {
                    Ok(event) => {
                        // Suppress per-block notifications while the node is
                        // still catching up, so IBD doesn't flood the UI with a
                        // toast for every connected block. Gauged live from the
                        // block-vs-header-tip gap rather than the `is_ibd` latch
                        // (which can be cleared prematurely and never re-arm).
                        if let NodeNotification::NewBlock { height, .. } = event {
                            if is_catching_up(&state, height) {
                                continue;
                            }
                        }
                        match serde_json::to_string(&event) {
                            Ok(json) => {
                                if socket.send(Message::Text(json.into())).await.is_err() {
                                    break;
                                }
                            }
                            Err(e) => {
                                warn!(error = %e, "Failed to serialize notification");
                            }
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                        warn!(missed = n, "WebSocket client lagged behind");
                    }
                    Err(_) => break,
                }
            }
            msg = socket.recv() => {
                match msg {
                    Some(Ok(Message::Close(_))) | None => break,
                    Some(Err(e)) => {
                        debug!(error = %e, "WebSocket receive error");
                        break;
                    }
                    _ => {}
                }
            }
        }
    }

    debug!("WebSocket client disconnected");
}
