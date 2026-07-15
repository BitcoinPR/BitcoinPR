use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use bitcoin::Network;
use serde::Serialize;
use tokio::sync::RwLock;

use bitcoinpr_core::{ConsensusParams, Mempool};
use bitcoinpr_index::{EventBus, ScripthashIndex};
use bitcoinpr_mining::MiningDashboard;
use bitcoinpr_storage::{BlockStore, HeaderIndex, TxIndex, UtxoSet};

/// A point-in-time snapshot of mempool fee-rate statistics, sampled periodically.
#[derive(Debug, Clone, Serialize)]
pub struct MempoolSample {
    /// Unix timestamp (seconds) when the sample was taken.
    pub time: u64,
    /// Number of transactions in the mempool.
    pub count: usize,
    /// Sum of transaction vsizes (vbytes).
    pub vsize: u64,
    /// Sum of transaction fees (satoshis).
    pub total_fee: u64,
    /// 10th percentile of per-tx fee rate (sat/vB), count-based.
    pub fee_p10: f64,
    /// 50th percentile (median) of per-tx fee rate (sat/vB), count-based.
    pub fee_p50: f64,
    /// 90th percentile of per-tx fee rate (sat/vB), count-based.
    pub fee_p90: f64,
}

/// A network service exposed by the node (P2P, RPC, Electrum, ...), used by
/// the Info page to show the operator what is listening where.
#[derive(Debug, Clone, Serialize)]
pub struct ServiceEntry {
    pub name: String,
    pub port: Option<u16>,
    pub enabled: bool,
}

/// Lightweight peer descriptor populated by the daemon from its p2p layer.
#[derive(Debug, Clone, Serialize)]
pub struct PeerEntry {
    pub id: u64,
    pub addr: String,
    /// Reachable-network class of `addr`: `ipv4`, `ipv6`, `onion`, or `i2p`.
    pub network: String,
    pub version: u32,
    pub subver: String,
    pub start_height: i32,
    /// Latest observed chain tip height for this peer; updated from headers
    /// announcements and connected blocks. Starts equal to start_height.
    pub synced_height: i32,
}

/// Shared application state threaded through every Axum handler.
#[derive(Clone)]
pub struct WebState {
    pub network: Network,
    pub params: ConsensusParams,
    pub header_index: Arc<HeaderIndex>,
    pub block_store: Arc<BlockStore>,
    pub utxo_set: Arc<UtxoSet>,
    pub tx_index: Option<Arc<TxIndex>>,
    pub mempool: Arc<RwLock<Mempool>>,
    pub scripthash_index: Option<Arc<ScripthashIndex>>,
    pub mining_dashboard: Option<Arc<MiningDashboard>>,
    pub event_bus: Arc<EventBus>,
    pub best_height: Arc<RwLock<u32>>,
    pub best_hash: Arc<RwLock<bitcoin::BlockHash>>,
    /// Rolling history of periodic mempool fee-rate samples (oldest -> newest).
    pub mempool_history:
        std::sync::Arc<tokio::sync::RwLock<std::collections::VecDeque<MempoolSample>>>,
    pub peers: Arc<RwLock<Vec<PeerEntry>>>,
    pub start_time: std::time::Instant,
    /// True while initial block download is in progress; WebSocket notifications
    /// for new blocks are suppressed to prevent UI instability from rapid-fire events.
    pub is_ibd: Arc<AtomicBool>,
    /// Whether the mining module is enabled (controls UI tab visibility).
    pub mining_enabled: bool,
    /// Live mining configuration, shared with TemplateProvider/DatumClient.
    pub mining_config: Option<Arc<RwLock<bitcoinpr_mining::MiningConfig>>>,
    /// Watch channel to signal config changes for live-reload consumers.
    pub mining_config_tx: Option<tokio::sync::watch::Sender<u64>>,
    /// Per-network data dir, used to persist mining.toml on config updates
    /// and to report on-disk storage usage on the Info page.
    pub datadir: Option<std::path::PathBuf>,
    /// Resolved block-files directory. Defaults to <datadir>/blocks but may
    /// live elsewhere via --blocksdir; the Info page storage breakdown counts
    /// it explicitly when it is outside the datadir.
    pub blocks_dir: Option<std::path::PathBuf>,
    /// Network services this node exposes (P2P, RPC, Electrum, ...).
    pub services: Vec<ServiceEntry>,
    /// Admin token required (`Authorization: Bearer <token>`) for mutating
    /// endpoints such as POST /api/mining/config. `None` disables those
    /// endpoints entirely (read-only explorer).
    pub web_admin_token: Option<String>,
    /// Chain-split monitor (rival-branch tracking + capitulation arming);
    /// drives the Split page. `None` in minimal embeddings.
    pub split_monitor: Option<Arc<bitcoinpr_core::SplitMonitor>>,
    /// Node shutdown channel — used by POST /api/split/capitulate to stop
    /// the node gracefully after persisting the abandon flag.
    pub shutdown_tx: Option<tokio::sync::mpsc::Sender<()>>,
    /// Node shutdown flag, set alongside `shutdown_tx`.
    pub shutting_down: Option<Arc<AtomicBool>>,
}
