use std::net::SocketAddr;

use axum::http::{header, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use tracing::info;

use crate::api;
use crate::state::WebState;
use crate::ws;

#[derive(rust_embed::Embed)]
#[folder = "static/"]
struct StaticAssets;

pub struct WebServer {
    state: WebState,
    port: u16,
}

impl WebServer {
    pub fn new(state: WebState, port: u16) -> Self {
        WebServer { state, port }
    }

    pub async fn run(&self) -> anyhow::Result<()> {
        let app = build_router(self.state.clone());

        // Spawn the mempool fee-rate sampler: every 10s, snapshot the mempool
        // and append a MempoolSample to the rolling history (capped at 720).
        {
            let mempool = self.state.mempool.clone();
            let history = self.state.mempool_history.clone();
            tokio::spawn(async move {
                let mut interval = tokio::time::interval(std::time::Duration::from_secs(10));
                loop {
                    interval.tick().await;

                    let (count, vsize, total_fee, mut rates) = {
                        let mp = mempool.read().await;
                        let mut vsize: u64 = 0;
                        let mut total_fee: u64 = 0;
                        let mut rates: Vec<f64> = Vec::new();
                        let txids = mp.all_txids();
                        for txid in &txids {
                            if let Some(entry) = mp.get(txid) {
                                vsize += entry.weight.div_ceil(4);
                                total_fee += entry.fee;
                                rates.push(entry.fee_rate);
                            }
                        }
                        (rates.len(), vsize, total_fee, rates)
                    };

                    rates.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
                    let pct = |p: f64| -> f64 {
                        if rates.is_empty() {
                            0.0
                        } else {
                            let idx = (p * (rates.len() as f64 - 1.0)).floor() as usize;
                            rates[idx.min(rates.len() - 1)]
                        }
                    };

                    let time = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_secs())
                        .unwrap_or(0);

                    let sample = crate::state::MempoolSample {
                        time,
                        count,
                        vsize,
                        total_fee,
                        fee_p10: pct(0.10),
                        fee_p50: pct(0.50),
                        fee_p90: pct(0.90),
                    };

                    let mut hist = history.write().await;
                    hist.push_back(sample);
                    while hist.len() > 720 {
                        hist.pop_front();
                    }
                }
            });
        }

        let addr = SocketAddr::from(([0, 0, 0, 0], self.port));
        info!(addr = %addr, "Web explorer listening");

        let listener = tokio::net::TcpListener::bind(addr).await?;
        axum::serve(listener, app).await?;

        Ok(())
    }
}

/// Build the explorer's Axum router.
///
/// Deliberately carries NO CORS layer: every consumer of /api/* is the static
/// UI served from this same origin (all fetches in static/js use relative
/// paths), so browsers' default same-origin policy is exactly the access
/// control we want. The previous `CorsLayer::permissive()` let any website a
/// user visits read API responses and POST /api/mining/config cross-origin.
/// Mutating endpoints additionally require the admin token (see crate::auth).
pub(crate) fn build_router(state: WebState) -> Router {
    Router::new()
        .route("/api/block/{hash_or_height}", get(api::blocks::get_block))
        .route("/api/tx/{txid}", get(api::txs::get_transaction))
        .route("/api/tx/{txid}/outspends", get(api::txs::get_outspends))
        .route("/api/recent-txs", get(api::recent::get_recent_txs))
        .route("/api/address/{address}", get(api::address::get_address))
        .route("/api/mempool", get(api::mempool::get_mempool))
        .route("/api/mempool/txs", get(api::mempool::get_mempool_txs))
        .route(
            "/api/mempool/history",
            get(api::mempool::get_mempool_history),
        )
        .route("/api/search/{query}", get(api::search::search))
        .route("/api/stats", get(api::stats::get_stats))
        .route("/api/info", get(api::info::get_info))
        .route("/api/peers", get(api::stats::get_peers))
        .route("/api/mining", get(api::mining::get_mining_stats))
        .route("/api/mining/workers", get(api::mining::get_workers))
        .route("/api/mining/history", get(api::mining::get_share_history))
        .route(
            "/api/mining/config",
            get(api::mining::get_mining_config).post(api::mining::update_mining_config),
        )
        .route("/ws", get(ws::ws_handler))
        .fallback(serve_static)
        .with_state(state)
}

fn content_type_for(path: &str) -> &'static str {
    if path.ends_with(".html") {
        "text/html; charset=utf-8"
    } else if path.ends_with(".css") {
        "text/css; charset=utf-8"
    } else if path.ends_with(".js") {
        "application/javascript; charset=utf-8"
    } else if path.ends_with(".json") {
        "application/json"
    } else if path.ends_with(".svg") {
        "image/svg+xml"
    } else if path.ends_with(".png") {
        "image/png"
    } else if path.ends_with(".ico") {
        "image/x-icon"
    } else if path.ends_with(".woff2") {
        "font/woff2"
    } else if path.ends_with(".woff") {
        "font/woff"
    } else {
        "application/octet-stream"
    }
}

async fn serve_static(uri: Uri, req_headers: axum::http::HeaderMap) -> Response {
    let path = uri.path().trim_start_matches('/');

    if let Some(file) = StaticAssets::get(path) {
        return asset_response(path, file, &req_headers);
    }

    // SPA fallback: serve index.html for unmatched routes
    if let Some(file) = StaticAssets::get("index.html") {
        return asset_response("index.html", file, &req_headers);
    }

    StatusCode::NOT_FOUND.into_response()
}

/// Serve an embedded asset with validation-based caching. Assets have no
/// cache-busting names, so browsers must revalidate (`no-cache`) or UI
/// updates never appear on a plain reload; the content-hash ETag makes
/// revalidation a cheap 304. Fonts are effectively immutable and get a day.
fn asset_response(
    path: &str,
    file: rust_embed::EmbeddedFile,
    req_headers: &axum::http::HeaderMap,
) -> Response {
    let etag = format!("\"{}\"", hex::encode(file.metadata.sha256_hash()));

    let etag_matches = req_headers
        .get(header::IF_NONE_MATCH)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| {
            v.split(',')
                .any(|t| t.trim().trim_start_matches("W/") == etag)
        });
    if etag_matches {
        return (StatusCode::NOT_MODIFIED, [(header::ETAG, etag)]).into_response();
    }

    let cache_control = if path.starts_with("fonts/") {
        "public, max-age=86400"
    } else {
        "no-cache"
    };

    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, content_type_for(path).to_string()),
            (header::ETAG, etag),
            (header::CACHE_CONTROL, cache_control.to_string()),
        ],
        file.data.to_vec(),
    )
        .into_response()
}

/// Router-level tests for the admin-token gate on mutating endpoints.
/// They drive the real Axum router (real handlers, real WebState backed by
/// temp RocksDB stores) via `tower::ServiceExt::oneshot`.
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicBool;
    use std::sync::Arc;

    use axum::body::Body;
    use axum::http::Request;
    use bitcoin::hashes::Hash as _;
    use tokio::sync::RwLock;
    use tower::util::ServiceExt;

    use crate::state::WebState;

    fn test_state(dir: &std::path::Path, token: Option<&str>) -> WebState {
        let blocks_dir = dir.join("blocks");
        std::fs::create_dir_all(&blocks_dir).unwrap();
        WebState {
            network: bitcoin::Network::Regtest,
            params: bitcoinpr_core::ConsensusParams::for_network(bitcoin::Network::Regtest),
            header_index: Arc::new(
                bitcoinpr_storage::HeaderIndex::open(&dir.join("headers")).unwrap(),
            ),
            block_store: Arc::new(bitcoinpr_storage::BlockStore::open(&blocks_dir).unwrap()),
            utxo_set: Arc::new(bitcoinpr_storage::UtxoSet::open(&dir.join("utxo"), None).unwrap()),
            tx_index: None,
            mempool: Arc::new(RwLock::new(bitcoinpr_core::Mempool::new(1 << 20))),
            scripthash_index: None,
            mining_dashboard: None,
            event_bus: Arc::new(bitcoinpr_index::EventBus::new(8)),
            best_height: Arc::new(RwLock::new(0)),
            best_hash: Arc::new(RwLock::new(bitcoin::BlockHash::all_zeros())),
            mempool_history: Arc::new(RwLock::new(std::collections::VecDeque::new())),
            peers: Arc::new(RwLock::new(Vec::new())),
            start_time: std::time::Instant::now(),
            is_ibd: Arc::new(AtomicBool::new(false)),
            mining_enabled: true,
            mining_config: Some(Arc::new(RwLock::new(
                bitcoinpr_mining::MiningConfig::default(),
            ))),
            mining_config_tx: None,
            datadir: None,
            blocks_dir: None,
            services: Vec::new(),
            web_admin_token: token.map(str::to_string),
        }
    }

    fn post_config(extra_headers: &[(&str, &str)]) -> Request<Body> {
        let mut builder = Request::post("/api/mining/config")
            .header("content-type", "application/json")
            .header("host", "localhost:3000");
        for (k, v) in extra_headers {
            builder = builder.header(*k, *v);
        }
        builder.body(Body::from("{}")).unwrap()
    }

    #[tokio::test]
    async fn static_assets_have_etag_and_revalidation_caching() {
        let dir = tempfile::tempdir().unwrap();
        let router = build_router(test_state(dir.path(), None));
        let resp = router
            .oneshot(Request::get("/css/style.css").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers().get(header::CACHE_CONTROL).unwrap(),
            "no-cache"
        );
        assert!(resp.headers().contains_key(header::ETAG));
    }

    #[tokio::test]
    async fn matching_if_none_match_returns_304() {
        let dir = tempfile::tempdir().unwrap();
        let router = build_router(test_state(dir.path(), None));
        let first = router
            .clone()
            .oneshot(Request::get("/css/style.css").body(Body::empty()).unwrap())
            .await
            .unwrap();
        let etag = first.headers().get(header::ETAG).unwrap().clone();

        let second = router
            .oneshot(
                Request::get("/css/style.css")
                    .header(header::IF_NONE_MATCH, etag)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(second.status(), StatusCode::NOT_MODIFIED);
    }

    #[tokio::test]
    async fn fonts_get_long_lived_cache() {
        let dir = tempfile::tempdir().unwrap();
        let router = build_router(test_state(dir.path(), None));
        let resp = router
            .oneshot(
                Request::get("/fonts/silkscreen-latin-400.woff2")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers().get(header::CACHE_CONTROL).unwrap(),
            "public, max-age=86400"
        );
    }

    #[tokio::test]
    async fn get_endpoints_unaffected_by_token_gate() {
        let dir = tempfile::tempdir().unwrap();
        let router = build_router(test_state(dir.path(), Some("secret")));
        let resp = router
            .oneshot(
                Request::get("/api/mining/config")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn post_without_token_is_unauthorized() {
        let dir = tempfile::tempdir().unwrap();
        let router = build_router(test_state(dir.path(), Some("secret")));
        let resp = router.oneshot(post_config(&[])).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn post_with_wrong_token_is_unauthorized() {
        let dir = tempfile::tempdir().unwrap();
        let router = build_router(test_state(dir.path(), Some("secret")));
        let resp = router
            .oneshot(post_config(&[("authorization", "Bearer nope")]))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn post_with_valid_token_is_ok() {
        let dir = tempfile::tempdir().unwrap();
        let router = build_router(test_state(dir.path(), Some("secret")));
        let resp = router
            .oneshot(post_config(&[("authorization", "Bearer secret")]))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn post_when_no_token_configured_is_forbidden() {
        let dir = tempfile::tempdir().unwrap();
        let router = build_router(test_state(dir.path(), None));
        let resp = router
            .oneshot(post_config(&[("authorization", "Bearer anything")]))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn post_cross_origin_rejected_even_with_valid_token() {
        let dir = tempfile::tempdir().unwrap();
        let router = build_router(test_state(dir.path(), Some("secret")));
        let resp = router
            .oneshot(post_config(&[
                ("authorization", "Bearer secret"),
                ("origin", "http://evil.example"),
            ]))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn post_same_origin_with_valid_token_is_ok() {
        let dir = tempfile::tempdir().unwrap();
        let router = build_router(test_state(dir.path(), Some("secret")));
        let resp = router
            .oneshot(post_config(&[
                ("authorization", "Bearer secret"),
                ("origin", "http://localhost:3000"),
            ]))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }
}
