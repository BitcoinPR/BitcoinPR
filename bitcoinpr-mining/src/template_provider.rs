use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::tcp::OwnedWriteHalf;
use tokio::net::TcpListener;
use tokio::sync::{broadcast, RwLock};
use tracing::{debug, error, info, warn};

use bitcoin::blockdata::block::Header as BlockHeader;
use bitcoin::blockdata::script::ScriptBuf;
use bitcoin::hashes::{sha256d, Hash};
use bitcoin::locktime::absolute::LockTime;
use bitcoin::transaction::Version as TxVersion;
use bitcoin::{Block, BlockHash, CompactTarget, Target, Transaction, TxIn, TxOut, Txid, Witness};
use bitcoinpr_core::NodeNotification;
use bitcoinpr_core::{
    add_chain_work, calculate_next_work_required, calculate_work, compact_target_to_difficulty,
    ChainState, ConsensusParams, Mempool,
};
use bitcoinpr_index::ScripthashIndex;
use bitcoinpr_p2p::PeerCommand;
use bitcoinpr_storage::{HeaderIndex, StoredHeader};

use crate::config::{MiningConfig, MiningMode};
use crate::datum::{DatumClient, DatumShare};
use crate::protocol::{
    JsonRpcNotification, JsonRpcRequest, JsonRpcResponse, SetupConnection, SetupConnectionSuccess,
    Sv2Message,
};
use crate::shares::ShareTracker;
use crate::vardiff::{Vardiff, VARDIFF_MIN, VARDIFF_START, VARDIFF_TICK_SECS};

/// Legacy share-difficulty cap, kept as a safety bound for the non-vardiff
/// static regime. Real networks now use per-connection vardiff (vardiff.rs)
/// instead of this single static value; on regtest the network difficulty is
/// far below the cap, so it is a no-op there too.
const DEFAULT_SHARE_DIFFICULTY: f64 = 65536.0;

/// Interval between mempool-driven job rebuilds. 30 seconds matches standard
/// pool practice and lets small ASICs scan enough nonce space before a job
/// refresh. New blocks still trigger immediate job pushes (separate code path).
const MEMPOOL_RETEMPLATE_INTERVAL: Duration = Duration::from_secs(30);

/// Compute the share difficulty for the two non-vardiff regimes.
///
/// Priority: CLI `--miningdifficulty` override (via `bits_override`) pins the
/// share difficulty for the whole session (vardiff disabled). Otherwise cap
/// at [`DEFAULT_SHARE_DIFFICULTY`] — in practice this branch is only reached
/// on trivial-difficulty chains (regtest), where the network difficulty is
/// far below the cap and every share is a block; on real networks the session
/// uses per-connection vardiff instead (see `vardiff.rs`).
fn effective_share_difficulty(bits_override: Option<u32>, template_bits: u32) -> f64 {
    if let Some(bits) = bits_override {
        return compact_target_to_difficulty(bits);
    }
    let net = compact_target_to_difficulty(template_bits);
    net.min(DEFAULT_SHARE_DIFFICULTY)
}

/// How far the validated block tip may trail the downloaded header tip before
/// the node is treated as still catching up. While catching up the gateway
/// neither serves work nor re-templates, since any block found would build on a
/// stale tip. See [`is_catching_up`].
const IBD_MINING_MARGIN: u32 = 4;

/// Whether the node is still catching up to the chain tip, judged live from the
/// gap between the downloaded header tip and `block_height`.
///
/// Replaces a direct read of the `is_ibd` latch: that flag is set once at
/// startup and only ever cleared, so it can drop to `false` mid-sync and never
/// re-arm, which would let miners build templates on a stale tip for the rest of
/// IBD (the exact hazard the work-deferral gate guards against). The
/// header-tip-vs-block-tip gap is self-correcting and matches the RPC layer's
/// `getblockchaininfo` IBD signal. It also subsumes the old "at genesis" special
/// case: a fresh node at height 0 has header_tip == block_tip == 0, so the gap is
/// zero and work is served immediately.
fn is_catching_up(header_index: &HeaderIndex, block_height: u32) -> bool {
    let header_tip = header_index
        .get_header_tip_height()
        .ok()
        .flatten()
        .unwrap_or(0);
    header_tip.saturating_sub(block_height) > IBD_MINING_MARGIN
}

/// Internal representation of a generated block template.
#[derive(Clone)]
struct TemplateData {
    template_id: u64,
    prev_hash: BlockHash,
    transactions: Vec<Vec<u8>>,
    coinbase_value: u64,
    version: u32,
    bits: u32,
    height: u32,
    merkle_path: Vec<[u8; 32]>,
    /// Coinbase scriptSig tag bytes (from runtime config), inserted between the
    /// BIP34 height push and the extranonces.
    coinbase_tag: Vec<u8>,
    /// Pool-required coinbase output specs (Datum mode only). Empty in solo mode.
    pool_outputs: Vec<crate::protocol::CoinbaseOutputSpec>,
    /// BIP 141 witness-commitment scriptPubKey (`OP_RETURN 0x24 0xaa21a9ed ...`)
    /// for the extra coinbase output, present only when at least one selected
    /// transaction carries witness data. `None` ⇒ no witness txs ⇒ no commitment
    /// output (and no coinbase witness reserved value) is required.
    witness_commitment: Option<Vec<u8>>,
    /// Minimum valid block timestamp: median-time-past(prev 11) + 1. The block's
    /// nTime must be strictly greater than MTP (BIP 113), so the job ntime handed
    /// to miners must be at least this — otherwise the mined block is rejected by
    /// our own validation and by Core/Knots ("time-too-old"). This matters after
    /// rapid mining pushes recent timestamps ahead of wall-clock.
    min_time: u32,
}

/// Stratum V2 Template Distribution Protocol server.
///
/// Accepts mining client connections over TCP (newline-delimited JSON),
/// distributes block templates built from the current chain tip and mempool,
/// and tracks submitted shares via the shared [`ShareTracker`].
pub struct TemplateProvider {
    params: ConsensusParams,
    header_index: Arc<HeaderIndex>,
    mempool: Arc<RwLock<Mempool>>,
    best_height: Arc<RwLock<u32>>,
    best_hash: Arc<RwLock<BlockHash>>,
    event_sender: broadcast::Sender<NodeNotification>,
    share_tracker: ShareTracker,
    port: u16,
    templates: Arc<RwLock<HashMap<u64, TemplateData>>>,
    next_template_id: Arc<RwLock<u64>>,
    /// Shared runtime mining configuration (address, coinbase tag, mode, ...).
    mining_config: Arc<RwLock<crate::config::MiningConfig>>,
    /// Bumped whenever `mining_config` changes; V1 sessions watch it to push
    /// fresh jobs live.
    config_version: tokio::sync::watch::Receiver<u64>,
    /// Optional Datum pool client (present only in Datum mode).
    datum_client: Option<Arc<crate::datum::DatumClient>>,
    /// Optional nBits override — bypasses calculate_next_bits() for every
    /// template.  Useful in regtest where pow_no_retargeting=true means the
    /// chain never self-adjusts.  Set via --miningdifficulty on the CLI.
    bits_override: Option<u32>,
    worker_count: Arc<AtomicU32>,
    is_ibd: Arc<AtomicBool>,
    chain_state: Option<Arc<tokio::sync::Mutex<ChainState>>>,
    command_tx: Option<tokio::sync::mpsc::Sender<PeerCommand>>,
    /// Scripthash index — when present, each successfully-mined block is
    /// indexed inline (before the NewBlock event fires) so that Electrum
    /// clients receive accurate subscription notifications immediately.
    scripthash_index: Option<Arc<ScripthashIndex>>,
}

impl TemplateProvider {
    /// `best_height` and `best_hash` are the **shared** Arcs from the node core
    /// (the same ones the RPC server reads).  Passing them directly means any
    /// update made here — including in `submit_mined_block` — is immediately
    /// visible to `getblockchaininfo` without an extra synchronisation step.
    // TODO(L2): 17 parameters — fold into a TemplateProviderConfig struct/builder.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        params: ConsensusParams,
        header_index: Arc<HeaderIndex>,
        mempool: Arc<RwLock<Mempool>>,
        best_height: Arc<RwLock<u32>>,
        best_hash: Arc<RwLock<BlockHash>>,
        event_sender: broadcast::Sender<NodeNotification>,
        share_tracker: ShareTracker,
        port: u16,
        mining_config: Arc<RwLock<crate::config::MiningConfig>>,
        config_version: tokio::sync::watch::Receiver<u64>,
        bits_override: Option<u32>,
        worker_count: Arc<AtomicU32>,
        is_ibd: Arc<AtomicBool>,
        chain_state: Option<Arc<tokio::sync::Mutex<ChainState>>>,
        command_tx: Option<tokio::sync::mpsc::Sender<PeerCommand>>,
        scripthash_index: Option<Arc<ScripthashIndex>>,
        datum_client: Option<Arc<crate::datum::DatumClient>>,
    ) -> Self {
        TemplateProvider {
            params,
            header_index,
            mempool,
            best_height,
            best_hash,
            event_sender,
            share_tracker,
            port,
            templates: Arc::new(RwLock::new(HashMap::new())),
            next_template_id: Arc::new(RwLock::new(1)),
            mining_config,
            config_version,
            datum_client,
            bits_override,
            worker_count,
            is_ibd,
            chain_state,
            command_tx,
            scripthash_index,
        }
    }

    /// Start accepting connections and serving templates.
    ///
    /// This method runs indefinitely. Spawn it on the Tokio runtime.
    pub async fn run(&self) -> anyhow::Result<()> {
        let listener = TcpListener::bind(("0.0.0.0", self.port)).await?;
        info!(
            port = self.port,
            "SV2 Template Distribution Protocol server listening"
        );

        // Internal signal broadcast when a new block is observed on the event bus.
        let (new_block_tx, _) = broadcast::channel::<()>(64);

        // Spawn an event-bus listener that updates the chain tip and signals clients.
        {
            let mut event_rx = self.event_sender.subscribe();
            let best_height = self.best_height.clone();
            let best_hash = self.best_hash.clone();
            let new_block_tx = new_block_tx.clone();
            let header_index = self.header_index.clone();

            tokio::spawn(async move {
                // Leading-edge throttle for mempool-driven re-templating: collapse a
                // burst of NewTx notifications into at most one job rebuild per 1.5s.
                let mut last_retemplate = Instant::now() - MEMPOOL_RETEMPLATE_INTERVAL;
                loop {
                    match event_rx.recv().await {
                        Ok(NodeNotification::NewBlock { hash, height }) => {
                            if let Ok(block_hash) = hash.parse::<BlockHash>() {
                                *best_hash.write().await = block_hash;
                                *best_height.write().await = height;
                                // Don't push jobs to miners while catching up —
                                // templates would be based on stale chain tips,
                                // wasting hashrate. Judged from the live
                                // header/block gap, not the `is_ibd` latch.
                                if is_catching_up(&header_index, height) {
                                    continue;
                                }
                                let _ = new_block_tx.send(());
                                info!(height, %hash, "New block received, notifying mining clients");
                            }
                        }
                        Ok(NodeNotification::NewTx { .. }) => {
                            // A mempool change should refresh the active job so the new
                            // transaction becomes eligible without waiting for the next
                            // block. Skip while catching up and throttle bursts.
                            if is_catching_up(&header_index, *best_height.read().await) {
                                continue;
                            }
                            if last_retemplate.elapsed() >= MEMPOOL_RETEMPLATE_INTERVAL {
                                last_retemplate = Instant::now();
                                let _ = new_block_tx.send(());
                                debug!("Mempool change, re-templating mining job");
                            }
                        }
                        Err(broadcast::error::RecvError::Lagged(n)) => {
                            warn!(lagged = n, "Event bus receiver lagged");
                        }
                        Err(broadcast::error::RecvError::Closed) => {
                            info!("Event bus closed, stopping template provider listener");
                            break;
                        }
                        _ => {}
                    }
                }
            });
        }

        loop {
            let (stream, addr) = listener.accept().await?;
            info!(%addr, "New mining client connected");

            let params = self.params.clone();
            let header_index = self.header_index.clone();
            let mempool = self.mempool.clone();
            let best_height = self.best_height.clone();
            let best_hash = self.best_hash.clone();
            let templates = self.templates.clone();
            let next_template_id = self.next_template_id.clone();
            let share_tracker = self.share_tracker.clone();
            let event_sender = self.event_sender.clone();
            let new_block_rx = new_block_tx.subscribe();
            let mining_config = self.mining_config.clone();
            let config_version = self.config_version.clone();
            let datum_client = self.datum_client.clone();
            let bits_override = self.bits_override;
            let worker_count = self.worker_count.clone();
            let is_ibd = self.is_ibd.clone();
            let chain_state = self.chain_state.clone();
            let command_tx = self.command_tx.clone();
            let scripthash_index = self.scripthash_index.clone();

            tokio::spawn(async move {
                worker_count.fetch_add(1, Ordering::Relaxed);
                let result = handle_client(
                    stream,
                    addr,
                    params,
                    header_index,
                    mempool,
                    best_height,
                    best_hash,
                    templates,
                    next_template_id,
                    share_tracker,
                    event_sender,
                    new_block_rx,
                    mining_config,
                    config_version,
                    datum_client,
                    bits_override,
                    is_ibd,
                    chain_state,
                    command_tx,
                    scripthash_index,
                )
                .await;
                worker_count.fetch_sub(1, Ordering::Relaxed);
                if let Err(e) = result {
                    error!(%addr, error = %e, "Mining client handler error");
                }
                info!(%addr, "Mining client disconnected");
            });
        }
    }
}

// ---------------------------------------------------------------------------
// Per-client handler
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
async fn handle_client(
    stream: tokio::net::TcpStream,
    addr: SocketAddr,
    params: ConsensusParams,
    header_index: Arc<HeaderIndex>,
    mempool: Arc<RwLock<Mempool>>,
    best_height: Arc<RwLock<u32>>,
    best_hash: Arc<RwLock<BlockHash>>,
    templates: Arc<RwLock<HashMap<u64, TemplateData>>>,
    next_template_id: Arc<RwLock<u64>>,
    share_tracker: ShareTracker,
    event_sender: broadcast::Sender<NodeNotification>,
    mut new_block_rx: broadcast::Receiver<()>,
    mining_config: Arc<RwLock<MiningConfig>>,
    mut config_version: tokio::sync::watch::Receiver<u64>,
    datum_client: Option<Arc<DatumClient>>,
    bits_override: Option<u32>,
    is_ibd: Arc<AtomicBool>,
    chain_state: Option<Arc<tokio::sync::Mutex<ChainState>>>,
    command_tx: Option<tokio::sync::mpsc::Sender<PeerCommand>>,
    scripthash_index: Option<Arc<ScripthashIndex>>,
) -> anyhow::Result<()> {
    let (reader, mut writer) = stream.into_split();
    let reader = BufReader::new(reader);
    let mut lines = reader.lines();

    // --- Auto-detect protocol from first message ---
    let first_line = match lines.next_line().await? {
        Some(line) => line,
        None => return Ok(()),
    };

    // Try SV2 SetupConnection first
    if let Ok(_setup) = serde_json::from_str::<SetupConnection>(&first_line) {
        debug!(%addr, "Detected SV2 protocol");
        send_json(
            &mut writer,
            &SetupConnectionSuccess {
                used_version: 2,
                flags: 0,
            },
        )
        .await?;

        return handle_sv2_session(
            lines,
            &mut writer,
            addr,
            &params,
            &header_index,
            &mempool,
            &best_height,
            &best_hash,
            &templates,
            &next_template_id,
            &share_tracker,
            &event_sender,
            &mut new_block_rx,
            &mining_config,
            &mut config_version,
            &datum_client,
            &is_ibd,
        )
        .await;
    }

    // Try Stratum V1 JSON-RPC
    if let Ok(rpc) = serde_json::from_str::<JsonRpcRequest>(&first_line) {
        debug!(%addr, method = %rpc.method, "Detected Stratum V1 protocol");
        return handle_v1_session(
            rpc,
            lines,
            &mut writer,
            addr,
            &params,
            &header_index,
            &mempool,
            &best_height,
            &best_hash,
            &templates,
            &next_template_id,
            &share_tracker,
            &event_sender,
            &mut new_block_rx,
            &mining_config,
            &mut config_version,
            &datum_client,
            bits_override,
            &is_ibd,
            &chain_state,
            &command_tx,
            &scripthash_index,
        )
        .await;
    }

    anyhow::bail!(
        "Unrecognized mining protocol: {}",
        &first_line[..first_line.len().min(100)]
    );
}

/// Handle an SV2 client session (existing logic, extracted from handle_client).
#[allow(clippy::too_many_arguments)]
async fn handle_sv2_session(
    mut lines: tokio::io::Lines<BufReader<tokio::net::tcp::OwnedReadHalf>>,
    writer: &mut OwnedWriteHalf,
    addr: SocketAddr,
    params: &ConsensusParams,
    header_index: &Arc<HeaderIndex>,
    mempool: &Arc<RwLock<Mempool>>,
    best_height: &Arc<RwLock<u32>>,
    best_hash: &Arc<RwLock<BlockHash>>,
    templates: &Arc<RwLock<HashMap<u64, TemplateData>>>,
    next_template_id: &Arc<RwLock<u64>>,
    share_tracker: &ShareTracker,
    event_sender: &broadcast::Sender<NodeNotification>,
    new_block_rx: &mut broadcast::Receiver<()>,
    mining_config: &Arc<RwLock<MiningConfig>>,
    _config_version: &mut tokio::sync::watch::Receiver<u64>,
    datum_client: &Option<Arc<DatumClient>>,
    _is_ibd: &Arc<AtomicBool>,
) -> anyhow::Result<()> {
    debug!(%addr, "SV2 setup handshake complete");
    let mut coinbase_max_additional_size: u32 = 0;

    loop {
        tokio::select! {
            result = lines.next_line() => {
                match result {
                    Ok(Some(line)) => {
                        let msg: Sv2Message = match serde_json::from_str(&line) {
                            Ok(m) => m,
                            Err(e) => {
                                warn!(%addr, error = %e, "Failed to parse client message");
                                continue;
                            }
                        };

                        handle_message(
                            msg, addr, params, header_index, mempool,
                            best_height, best_hash, templates, next_template_id,
                            share_tracker, event_sender, writer,
                            &mut coinbase_max_additional_size,
                            mining_config, datum_client,
                        )
                        .await?;
                    }
                    Ok(None) => {
                        info!(%addr, "Client closed connection");
                        break;
                    }
                    Err(e) => {
                        error!(%addr, error = %e, "Read error");
                        break;
                    }
                }
            }

            result = new_block_rx.recv() => {
                match result {
                    Ok(()) if coinbase_max_additional_size > 0 => {
                        push_new_block_template(
                            params, header_index, mempool, best_height, best_hash,
                            templates, next_template_id,
                            coinbase_max_additional_size, writer,
                            mining_config, datum_client,
                        )
                        .await?;
                    }
                    Ok(()) => {}
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        warn!(%addr, lagged = n, "Client new-block receiver lagged");
                    }
                    Err(broadcast::error::RecvError::Closed) => {
                        info!(%addr, "New block channel closed");
                        break;
                    }
                }
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Message dispatch
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
async fn handle_message(
    msg: Sv2Message,
    addr: SocketAddr,
    params: &ConsensusParams,
    header_index: &Arc<HeaderIndex>,
    mempool: &Arc<RwLock<Mempool>>,
    best_height: &Arc<RwLock<u32>>,
    best_hash: &Arc<RwLock<BlockHash>>,
    templates: &Arc<RwLock<HashMap<u64, TemplateData>>>,
    next_template_id: &Arc<RwLock<u64>>,
    share_tracker: &ShareTracker,
    event_sender: &broadcast::Sender<NodeNotification>,
    writer: &mut OwnedWriteHalf,
    coinbase_max_additional_size: &mut u32,
    mining_config: &Arc<RwLock<MiningConfig>>,
    datum_client: &Option<Arc<DatumClient>>,
) -> anyhow::Result<()> {
    match msg {
        Sv2Message::CoinbaseOutputConstraints {
            coinbase_output_max_additional_size,
            ..
        } => {
            *coinbase_max_additional_size = coinbase_output_max_additional_size;
            debug!(%addr, coinbase_output_max_additional_size, "Received coinbase constraints");

            let template = build_template(
                params,
                header_index,
                mempool,
                best_height,
                best_hash,
                next_template_id,
                coinbase_output_max_additional_size,
                mining_config,
                datum_client,
            )
            .await;

            let new_template_msg = template_to_new_template(&template);
            templates
                .write()
                .await
                .insert(template.template_id, template);
            send_json(writer, &new_template_msg).await?;
        }

        Sv2Message::RequestTransactionData { template_id } => {
            let guard = templates.read().await;
            if let Some(template) = guard.get(&template_id) {
                let tx_list: Vec<String> = template.transactions.iter().map(hex::encode).collect();
                drop(guard);

                send_json(
                    writer,
                    &Sv2Message::RequestTransactionDataSuccess {
                        template_id,
                        excess_data: String::new(),
                        transaction_list: tx_list,
                    },
                )
                .await?;
            } else {
                drop(guard);
                send_json(
                    writer,
                    &Sv2Message::RequestTransactionDataError {
                        template_id,
                        error_code: "template-not-found".to_string(),
                    },
                )
                .await?;
            }
        }

        Sv2Message::SubmitSolution {
            template_id,
            version: _,
            header_timestamp: _,
            header_nonce: _,
            coinbase_tx: _,
        } => {
            let guard = templates.read().await;
            let difficulty = guard
                .get(&template_id)
                .map(|t| compact_target_to_difficulty(t.bits))
                .unwrap_or(1.0);
            let known = guard.contains_key(&template_id);
            drop(guard);

            if known {
                share_tracker.record_share(addr.to_string(), difficulty, true);

                let _ = event_sender.send(NodeNotification::MiningShare {
                    worker: addr.to_string(),
                    accepted: true,
                    hashrate: share_tracker.hashrate(),
                    difficulty,
                });

                debug!(%addr, template_id, difficulty, "Share accepted");
            } else {
                share_tracker.record_share(addr.to_string(), 1.0, false);
                warn!(%addr, template_id, "Share rejected: unknown template");
            }
        }

        other => {
            warn!(%addr, ?other, "Unexpected message from client");
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Template construction
// ---------------------------------------------------------------------------

/// Build a block template from the current chain tip and mempool.
///
/// Weight budget follows the SV2 spec: reserve `1168 + 4 * coinbase_max_additional_size`
/// weight units for the SegWit coinbase, then greedily pack transactions up to the
/// remaining capacity (max 4 000 transactions).
///
/// The block nBits is always computed by `calculate_next_bits()` so that all peers
/// (Bitcoin Core, Knots, etc.) accept the block.  Use `--miningdifficulty` to control
/// only the Stratum share-difficulty threshold sent to miners via `mining.set_difficulty`.
#[allow(clippy::too_many_arguments)]
async fn build_template(
    params: &ConsensusParams,
    header_index: &Arc<HeaderIndex>,
    mempool: &Arc<RwLock<Mempool>>,
    best_height: &Arc<RwLock<u32>>,
    best_hash: &Arc<RwLock<BlockHash>>,
    next_template_id: &Arc<RwLock<u64>>,
    coinbase_max_additional_size: u32,
    mining_config: &Arc<RwLock<MiningConfig>>,
    datum_client: &Option<Arc<DatumClient>>,
) -> TemplateData {
    let height = *best_height.read().await;
    let prev_hash = *best_hash.read().await;
    let next_height = height + 1;

    // Read runtime config once: coinbase tag (length-enforced) and mode.
    let (coinbase_tag, mode) = {
        let cfg = mining_config.read().await;
        (cfg.coinbase_tag.clone(), cfg.mode)
    };
    let coinbase_tag = if coinbase_tag.len() > crate::config::MAX_COINBASE_TAG_LEN {
        warn!(
            len = coinbase_tag.len(),
            max = crate::config::MAX_COINBASE_TAG_LEN,
            "coinbase_tag exceeds maximum length; truncating"
        );
        coinbase_tag[..crate::config::MAX_COINBASE_TAG_LEN].to_vec()
    } else {
        coinbase_tag
    };

    // Fetch pool-required coinbase outputs only in Datum mode with a client.
    let pool_outputs = if mode == MiningMode::Datum {
        if let Some(dc) = datum_client {
            dc.pool_coinbase_output_specs().await
        } else {
            Vec::new()
        }
    } else {
        Vec::new()
    };

    let bits = calculate_next_bits(header_index, &prev_hash, next_height, params);

    // BIP 113: the block timestamp must be strictly greater than the MTP of the
    // previous 11 blocks. Compute the minimum valid timestamp so the job ntime
    // can never be below it (which would make our own block invalid). The same
    // MTP is the time reference for nLockTime / BIP 68 finality filtering below.
    let tip_mtp_opt = bitcoinpr_core::get_median_time_past(header_index, &prev_hash);
    let min_time = tip_mtp_opt.map(|mtp| mtp + 1).unwrap_or(0);
    let tip_mtp = tip_mtp_opt.unwrap_or(0);

    let subsidy = params.block_subsidy(next_height);

    let reserved_weight = 1168 + 4 * coinbase_max_additional_size;
    let available_weight = params.max_block_weight.saturating_sub(reserved_weight) as u64;

    let mempool_guard = mempool.read().await;

    let mut selected_txids: Vec<Txid> = Vec::new();
    let mut selected_wtxids: Vec<[u8; 32]> = Vec::new();
    let mut transactions: Vec<Vec<u8>> = Vec::new();
    let mut selected_fees: u64 = 0;
    let mut has_witness = false;

    // select_for_block enforces the weight budget, skips txs that are not
    // final at the template height (nLockTime / BIP 68 — including them would
    // make our own connect_block reject the mined block, burning the ASIC's
    // work), and orders parents before children for intra-block spends.
    for entry in mempool_guard.select_for_block(next_height, tip_mtp, available_weight, 4000) {
        selected_fees += entry.fee;
        selected_txids.push(entry.txid);
        selected_wtxids.push(*entry.tx.compute_wtxid().as_ref());
        if entry.tx.input.iter().any(|i| !i.witness.is_empty()) {
            has_witness = true;
        }
        transactions.push(bitcoin::consensus::encode::serialize(&entry.tx));
    }
    drop(mempool_guard);

    let coinbase_value = subsidy + selected_fees;

    // BIP 141: when any selected tx carries witness data, the coinbase must
    // include the witness commitment output (and, at assembly time, the 32-byte
    // coinbase witness reserved value). Without this, strict peers (Core/Knots)
    // reject the block as "mutated" and our own connect_block rejects it as
    // "missing witness commitment in coinbase", so the tx is never mined.
    let witness_commitment = if has_witness {
        Some(witness_commitment_script(&selected_wtxids))
    } else {
        None
    };

    // Merkle path: the first "txid" is a placeholder for the coinbase that the
    // miner will construct.  Position 0 ⇒ the path consists of siblings on the
    // left spine of the tree.
    let mut all_txids_for_merkle: Vec<Txid> = vec![Txid::all_zeros()];
    all_txids_for_merkle.extend(selected_txids);
    let merkle_path = compute_merkle_path(&all_txids_for_merkle);

    let mut next_id = next_template_id.write().await;
    let template_id = *next_id;
    *next_id += 1;
    drop(next_id);

    TemplateData {
        template_id,
        prev_hash,
        transactions,
        coinbase_value,
        version: bip110_signaling_version(params, header_index, &prev_hash, next_height),
        bits,
        height: next_height,
        merkle_path,
        coinbase_tag,
        pool_outputs,
        witness_commitment,
        min_time,
    }
}

/// BIP-9 base block version (`0x20000000`), with the BIP-110 signaling bit (bit
/// 4) set while the deployment is STARTED or LOCKED_IN at `next_height` (signaling
/// stops once ACTIVE/EXPIRED), mirroring Core's `ComputeBlockVersion`. The
/// deployment state is computed from on-chain signaling (a fresh, uncached
/// evaluation — templates are infrequent), or from the fixed-mode override.
fn bip110_signaling_version(
    params: &ConsensusParams,
    header_index: &HeaderIndex,
    prev_hash: &BlockHash,
    next_height: u32,
) -> u32 {
    const VERSIONBITS_TOP: u32 = 0x20000000;
    const BIP110_BIT: u32 = 1 << 4;
    let checker = params
        .bip110_deployment
        .as_ref()
        .map(|dep| bitcoinpr_core::Bip110Checker::new(dep.clone()));
    let activation = bitcoinpr_core::bip110_activation_at(
        params,
        checker.as_ref(),
        header_index,
        prev_hash,
        next_height,
    );
    match activation.state {
        bitcoinpr_core::ThresholdState::Started | bitcoinpr_core::ThresholdState::LockedIn => {
            VERSIONBITS_TOP | BIP110_BIT
        }
        _ => VERSIONBITS_TOP,
    }
}

/// Build and send a `SetNewPrevHash` + `NewTemplate` pair to a client after a
/// new block is observed on the event bus.
#[allow(clippy::too_many_arguments)]
async fn push_new_block_template(
    params: &ConsensusParams,
    header_index: &Arc<HeaderIndex>,
    mempool: &Arc<RwLock<Mempool>>,
    best_height: &Arc<RwLock<u32>>,
    best_hash: &Arc<RwLock<BlockHash>>,
    templates: &Arc<RwLock<HashMap<u64, TemplateData>>>,
    next_template_id: &Arc<RwLock<u64>>,
    coinbase_max_additional_size: u32,
    writer: &mut OwnedWriteHalf,
    mining_config: &Arc<RwLock<MiningConfig>>,
    datum_client: &Option<Arc<DatumClient>>,
) -> anyhow::Result<()> {
    let template = build_template(
        params,
        header_index,
        mempool,
        best_height,
        best_hash,
        next_template_id,
        coinbase_max_additional_size,
        mining_config,
        datum_client,
    )
    .await;

    let timestamp = (SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as u32)
        .max(template.min_time);

    let prev_hash_msg = Sv2Message::SetNewPrevHash {
        template_id: template.template_id,
        prev_hash: template.prev_hash.to_string(),
        header_timestamp: timestamp,
        n_bits: template.bits,
        target: format!("{:08x}", template.bits),
    };
    send_json(writer, &prev_hash_msg).await?;

    let new_template_msg = template_to_new_template(&template);
    templates
        .write()
        .await
        .insert(template.template_id, template);
    send_json(writer, &new_template_msg).await?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Calculate the correct nBits for the next block at `next_height`.
///
/// Handles three cases:
/// 1. Retarget boundary (every 2016 blocks) — full difficulty adjustment
/// 2. Testnet 20-minute rule — if >20 min since last block, use minimum difficulty
/// 3. Normal — inherit the previous block's bits
fn calculate_next_bits(
    header_index: &HeaderIndex,
    prev_hash: &BlockHash,
    next_height: u32,
    params: &ConsensusParams,
) -> u32 {
    let prev_header = match header_index.get_header(prev_hash).ok().flatten() {
        Some(h) => h,
        None => return 0x1d00ffff, // fallback: difficulty 1
    };

    let interval = (params.pow_target_timespan / params.pow_target_spacing) as u32; // 2016

    // Retarget boundary
    if next_height % interval == 0 && !params.pow_no_retargeting {
        // Find the first block of this retarget period
        let period_start_height = next_height - interval;
        if let Some(start_hash) = header_index
            .get_hash_at_height(period_start_height)
            .ok()
            .flatten()
        {
            if let Some(start_stored) = header_index.get_header(&start_hash).ok().flatten() {
                let new_bits =
                    calculate_next_work_required(&start_stored.header, &prev_header.header, params);
                return new_bits.to_consensus();
            }
        }
        // Fallback if we can't find the period start
        return prev_header.header.bits.to_consensus();
    }

    // Testnet 20-minute minimum difficulty rule:
    // If >20 minutes have passed since the last block, allow minimum difficulty.
    // Otherwise, walk back to find the last non-min-difficulty block and use its bits.
    if params.pow_allow_min_difficulty_blocks {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as u32;
        let time_since_last = now.saturating_sub(prev_header.header.time);

        if time_since_last > params.pow_target_spacing as u32 * 2 {
            // >20 minutes: use minimum difficulty (pow_limit)
            let pow_limit_target = Target::from_be_bytes(params.pow_limit);
            return pow_limit_target.to_compact_lossy().to_consensus();
        }

        // Otherwise, walk back to the last block that wasn't min-difficulty
        let pow_limit_bits = Target::from_be_bytes(params.pow_limit).to_compact_lossy();
        let mut scan_hash = *prev_hash;
        let mut scan_height = next_height - 1;
        loop {
            if scan_height % interval == 0 {
                break; // don't walk past a retarget boundary
            }
            if let Some(stored) = header_index.get_header(&scan_hash).ok().flatten() {
                if stored.header.bits != pow_limit_bits {
                    return stored.header.bits.to_consensus();
                }
                scan_hash = stored.header.prev_blockhash;
                scan_height -= 1;
            } else {
                break;
            }
        }
        // Walked back to a retarget boundary — use that block's bits
        if let Some(stored) = header_index.get_header(&scan_hash).ok().flatten() {
            return stored.header.bits.to_consensus();
        }
    }

    // Normal case: inherit previous block's bits
    prev_header.header.bits.to_consensus()
}

/// Compute the Merkle-proof path (sibling hashes) for the coinbase at
/// position 0 (Stratum job field). Tree construction lives in
/// `bitcoinpr_core::merkle` (M4).
fn compute_merkle_path(txids: &[Txid]) -> Vec<[u8; 32]> {
    let leaves: Vec<[u8; 32]> = txids.iter().map(|t| t.to_byte_array()).collect();
    bitcoinpr_core::merkle::branch(&leaves, 0).1
}

/// BIP 141 witness commitment scriptPubKey for the coinbase: the bytes
/// `OP_RETURN 0x24 0xaa21a9ed <32-byte commitment>`, where the commitment is
/// `SHA256d(witness_merkle_root || 32-byte zero reserved value)`. `wtxids` are
/// the wtxids of the non-coinbase transactions (the coinbase wtxid is the
/// all-zero placeholder, prepended here). Mirrors the consensus check in
/// `bitcoinpr_core::validation::validate_witness_commitment`.
fn witness_commitment_script(wtxids: &[[u8; 32]]) -> Vec<u8> {
    let mut leaves: Vec<[u8; 32]> = Vec::with_capacity(wtxids.len() + 1);
    leaves.push([0u8; 32]); // coinbase wtxid placeholder
    leaves.extend_from_slice(wtxids);

    let witness_root = bitcoinpr_core::merkle::root(&leaves);

    let mut buf = [0u8; 64];
    buf[..32].copy_from_slice(&witness_root);
    // buf[32..] stays zero — the witness reserved value.
    let commitment = sha256d::Hash::hash(&buf).to_byte_array();

    let mut script = vec![0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed];
    script.extend_from_slice(&commitment);
    script
}

/// Convert internal `TemplateData` into the on-wire `Sv2Message::NewTemplate`.
fn template_to_new_template(template: &TemplateData) -> Sv2Message {
    Sv2Message::NewTemplate {
        template_id: template.template_id,
        future_template: false,
        version: template.version,
        coinbase_tx_version: 2,
        coinbase_prefix: hex::encode(
            [
                encode_bip34_height(template.height),
                template.coinbase_tag.clone(),
            ]
            .concat(),
        ),
        coinbase_tx_input_sequence: 0xffffffff,
        coinbase_tx_value_remaining: template.coinbase_value,
        coinbase_tx_outputs_count: 0,
        coinbase_tx_outputs: String::new(),
        coinbase_tx_locktime: 0,
        merkle_path: template.merkle_path.iter().map(hex::encode).collect(),
    }
}

/// BIP 34 height encoding for the coinbase scriptSig prefix.
///
/// Returns a minimally-encoded CScript number push: `[len] [height_le_bytes]`.
/// Encode block height for the BIP34 coinbase scriptSig prefix using the same
/// convention as Bitcoin Core's `CScript() << nHeight`:
///
/// - Height 0:     OP_0   (0x00)
/// - Heights 1–16: OP_1..OP_16  (0x51..0x60) — single opcode, no length prefix
/// - Heights 17+:  minimal push-data `[<len>, <LE bytes>]`
///
/// The OP_n form for small heights is critical: Bitcoin Core's BIP34 validation
/// checks `std::equal(CScript() << nHeight, scriptSig)`, and `CScript() << 1`
/// produces `[0x51]` not `[0x01, 0x01]`.  Using push-data encoding for heights
/// 1–16 causes "bad-cb-height" rejections from Bitcoin Core and Knots.
fn encode_bip34_height(height: u32) -> Vec<u8> {
    match height {
        0 => vec![0x00],
        1..=16 => vec![0x50u8 + height as u8], // OP_1..OP_16
        _ => {
            let mut le_bytes = height.to_le_bytes().to_vec();
            while le_bytes.last() == Some(&0) {
                le_bytes.pop();
            }
            if le_bytes.last().is_some_and(|&b| b & 0x80 != 0) {
                le_bytes.push(0x00);
            }
            let mut out = vec![le_bytes.len() as u8];
            out.extend_from_slice(&le_bytes);
            out
        }
    }
}

/// Write a JSON-serialisable value as a newline-delimited message.
async fn send_json<T: serde::Serialize>(
    writer: &mut OwnedWriteHalf,
    value: &T,
) -> anyhow::Result<()> {
    let json = serde_json::to_string(value)?;
    writer.write_all(json.as_bytes()).await?;
    writer.write_all(b"\n").await?;
    writer.flush().await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Stratum V1 session handler
// ---------------------------------------------------------------------------

/// Per-client state for a Stratum V1 mining session.
struct V1Job {
    job_id: String,
    prev_hash: BlockHash,
    coinbase1: Vec<u8>,
    coinbase2: Vec<u8>,
    merkle_branches: Vec<String>,
    version: u32,
    bits: u32,
    /// Minimum valid block timestamp (MTP+1) — the notify ntime is clamped up to
    /// this so miners never mine a block our own validation would reject.
    min_time: u32,
    #[allow(dead_code)]
    template_id: u64,
}

#[allow(clippy::too_many_arguments)]
async fn handle_v1_session(
    first_msg: JsonRpcRequest,
    mut lines: tokio::io::Lines<BufReader<tokio::net::tcp::OwnedReadHalf>>,
    writer: &mut OwnedWriteHalf,
    addr: SocketAddr,
    params: &ConsensusParams,
    header_index: &Arc<HeaderIndex>,
    mempool: &Arc<RwLock<Mempool>>,
    best_height: &Arc<RwLock<u32>>,
    best_hash: &Arc<RwLock<BlockHash>>,
    templates: &Arc<RwLock<HashMap<u64, TemplateData>>>,
    next_template_id: &Arc<RwLock<u64>>,
    share_tracker: &ShareTracker,
    event_sender: &broadcast::Sender<NodeNotification>,
    new_block_rx: &mut broadcast::Receiver<()>,
    mining_config: &Arc<RwLock<MiningConfig>>,
    config_version: &mut tokio::sync::watch::Receiver<u64>,
    datum_client: &Option<Arc<DatumClient>>,
    bits_override: Option<u32>,
    // Retained for call-site symmetry; catch-up state is now derived live from
    // the header/block gap via `is_catching_up`, not this latch.
    _is_ibd: &Arc<AtomicBool>,
    chain_state: &Option<Arc<tokio::sync::Mutex<ChainState>>>,
    command_tx: &Option<tokio::sync::mpsc::Sender<PeerCommand>>,
    scripthash_index: &Option<Arc<ScripthashIndex>>,
) -> anyhow::Result<()> {
    // --- Generate extranonce ---
    // Generate random extranonce1 from timestamp + addr hash for uniqueness
    let nonce_seed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64
        ^ (addr.port() as u64);
    let extranonce1 = (nonce_seed as u32).to_le_bytes();
    let extranonce1_hex = hex::encode(extranonce1);
    let extranonce2_size: usize = 4;

    // --- Handle mining.subscribe ---
    if first_msg.method != "mining.subscribe" {
        anyhow::bail!("Expected mining.subscribe, got {}", first_msg.method);
    }

    let subscribe_resp = JsonRpcResponse {
        id: first_msg.id,
        result: json!([
            [["mining.set_difficulty", "1"], ["mining.notify", "1"]],
            extranonce1_hex,
            extranonce2_size
        ]),
        error: None,
    };
    send_json(writer, &subscribe_resp).await?;
    debug!(%addr, extranonce1 = %extranonce1_hex, "V1 subscribe complete");

    // --- Handle pre-authorize messages (configure, suggest_difficulty) then authorize ---
    // Miners may send mining.configure and/or mining.suggest_difficulty before authorize.
    let worker_name;
    let mut suggested_difficulty: Option<f64> = None;
    loop {
        let line = match lines.next_line().await? {
            Some(l) => l,
            None => return Ok(()),
        };
        let rpc: JsonRpcRequest = match serde_json::from_str(&line) {
            Ok(r) => r,
            Err(e) => {
                warn!(%addr, error = %e, "Failed to parse handshake message");
                continue;
            }
        };
        match rpc.method.as_str() {
            "mining.authorize" => {
                worker_name = rpc
                    .params
                    .as_array()
                    .and_then(|a| a.first())
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown")
                    .to_string();
                send_json(
                    writer,
                    &JsonRpcResponse {
                        id: rpc.id,
                        result: json!(true),
                        error: None,
                    },
                )
                .await?;
                info!(%addr, worker = %worker_name, "V1 worker authorized");
                break;
            }
            "mining.configure" => {
                // BIP 310 mining.configure — acknowledge version-rolling
                let mut result = json!({});
                if let Some(params) = rpc.params.as_array() {
                    if let Some(extensions) = params.first().and_then(|v| v.as_array()) {
                        for ext in extensions {
                            if ext.as_str() == Some("version-rolling") {
                                result["version-rolling"] = json!(true);
                                result["version-rolling.mask"] = json!("1fffe000");
                                result["version-rolling.min-bit-count"] = json!(0);
                            }
                        }
                    }
                }
                send_json(
                    writer,
                    &JsonRpcResponse {
                        id: rpc.id,
                        result: json!(result),
                        error: None,
                    },
                )
                .await?;
                debug!(%addr, "V1 mining.configure acknowledged");
            }
            "mining.suggest_difficulty" => {
                // Acknowledge and remember the value — it seeds vardiff's
                // starting difficulty once the session begins.
                suggested_difficulty = parse_suggested_difficulty(&rpc.params);
                send_json(
                    writer,
                    &JsonRpcResponse {
                        id: rpc.id,
                        result: json!(true),
                        error: None,
                    },
                )
                .await?;
                debug!(%addr, suggested = ?suggested_difficulty, "V1 mining.suggest_difficulty received");
            }
            other => {
                debug!(%addr, method = other, "Unexpected method during handshake, acking");
                send_json(
                    writer,
                    &JsonRpcResponse {
                        id: rpc.id,
                        result: json!(true),
                        error: None,
                    },
                )
                .await?;
            }
        }
    }

    let mut coinbase_script = {
        let cfg = mining_config.read().await;
        build_output_script(&cfg.mining_address)
    };

    // Wait until the node is caught up before sending work — mining on a stale
    // chain tip wastes hashrate and any "found" blocks would be invalid.
    //
    // "Caught up" is judged live from the header-tip-vs-block-tip gap rather
    // than the `is_ibd` latch (which can clear mid-sync and never re-arm, or get
    // stuck `true`). This also removes the old genesis special case: a fresh
    // node at height 0 has header_tip == block_tip == 0, so the gap is zero and
    // work is served immediately; when the first block arrives the
    // TemplateProvider's NewBlock handler pushes updated work as normal.
    //
    // The loop wakes on three signals:
    //   1. new_block_rx  — a block was connected (the normal catch-up path)
    //   2. ibd_poll tick — periodic fallback in case the tip advanced without a
    //      NewBlock event (e.g. local block replay)
    //   3. miner I/O     — respond to protocol messages while waiting
    if is_catching_up(header_index, *best_height.read().await) {
        info!(%addr, "Miner connected while still catching up — deferring work until sync completes");
        let mut ibd_poll = tokio::time::interval(std::time::Duration::from_millis(500));
        ibd_poll.tick().await; // consume the immediate first tick
        loop {
            tokio::select! {
                _ = new_block_rx.recv() => {
                    if !is_catching_up(header_index, *best_height.read().await) {
                        break;
                    }
                }
                _ = ibd_poll.tick() => {
                    if !is_catching_up(header_index, *best_height.read().await) {
                        break;
                    }
                }
                result = lines.next_line() => {
                    match result {
                        Ok(Some(line)) => {
                            // Handle protocol messages (authorize, configure) but don't send work
                            if let Ok(rpc) = serde_json::from_str::<JsonRpcRequest>(&line) {
                                match rpc.method.as_str() {
                                    "mining.authorize" => {
                                        send_json(writer, &JsonRpcResponse {
                                            id: rpc.id, result: json!(true), error: None,
                                        }).await?;
                                    }
                                    "mining.configure" => {
                                        send_json(writer, &JsonRpcResponse {
                                            id: rpc.id, result: json!({}), error: None,
                                        }).await?;
                                    }
                                    _ => {}
                                }
                            }
                        }
                        Ok(None) | Err(_) => return Ok(()),
                    }
                }
            }
        }
        info!(%addr, "IBD complete, starting mining work");
    }

    // --- Build first job ---
    let template = build_template(
        params,
        header_index,
        mempool,
        best_height,
        best_hash,
        next_template_id,
        100,
        mining_config,
        datum_client,
    )
    .await;

    // --- Send mining.set_difficulty ---
    // Three share-difficulty regimes (none of them ever changes the block
    // nBits — templates always carry the consensus value so peers accept
    // mined blocks):
    //   pinned  — --miningdifficulty set: fixed for the whole session
    //             (e.g. 70000 → ~1 share per 10 min at 1.5 TH/s).
    //   static  — network difficulty at or below the vardiff floor (regtest):
    //             shares ARE blocks there, nothing to ramp.
    //   vardiff — real networks: per-connection ramping toward ~1 share/15 s
    //             (vardiff.rs), seeded from the miner's suggest_difficulty
    //             when it sent one.
    let net_difficulty = compact_target_to_difficulty(template.bits);
    let mut vardiff = (bits_override.is_none() && net_difficulty > VARDIFF_MIN).then(|| {
        Vardiff::new(
            suggested_difficulty.unwrap_or(VARDIFF_START),
            net_difficulty,
            Instant::now(),
        )
    });
    let mut current_share_difficulty = match &vardiff {
        Some(v) => v.difficulty(),
        None => effective_share_difficulty(bits_override, template.bits),
    };
    if bits_override.is_some() {
        info!(
            share_difficulty = current_share_difficulty,
            block_bits = format!("{:#010x}", template.bits),
            "Using pinned share difficulty (vardiff disabled; block nBits unchanged for peer compatibility)"
        );
    } else if vardiff.is_some() {
        info!(
            %addr,
            start_difficulty = current_share_difficulty,
            "Vardiff active — ramping toward ~1 share/15s per worker"
        );
    }
    send_json(
        writer,
        &JsonRpcNotification {
            id: None,
            method: "mining.set_difficulty".to_string(),
            params: json!([current_share_difficulty]),
        },
    )
    .await?;

    let mut current_job = build_v1_job(&template, &extranonce1, extranonce2_size, &coinbase_script);
    let mut current_template = template.clone();
    templates
        .write()
        .await
        .insert(template.template_id, template);

    send_v1_notify(writer, &current_job, true).await?;
    let mut job_counter: u64 = 2;

    // Drives Vardiff::on_tick — the ramp-DOWN path. A miner too small for the
    // current difficulty may never submit a share, so rate observation alone
    // (on_share) can't lower it; this tick uses elapsed silence instead.
    let mut vardiff_tick = tokio::time::interval(Duration::from_secs(VARDIFF_TICK_SECS));
    vardiff_tick.tick().await; // consume the immediate first tick

    // --- Main loop ---
    loop {
        tokio::select! {
            result = lines.next_line() => {
                match result {
                    Ok(Some(line)) => {
                        let rpc: JsonRpcRequest = match serde_json::from_str(&line) {
                            Ok(r) => r,
                            Err(e) => {
                                warn!(%addr, error = %e, "Failed to parse V1 message");
                                continue;
                            }
                        };

                        match rpc.method.as_str() {
                            "mining.submit" => {
                                let (accepted, maybe_block, maybe_share, reject_reason) = handle_v1_submit(
                                    &rpc, &current_job, &current_template,
                                    &extranonce1,
                                    share_tracker, &worker_name, addr,
                                    event_sender, &coinbase_script,
                                    current_share_difficulty,
                                );
                                let error = if accepted {
                                    None
                                } else {
                                    let code = match reject_reason {
                                        Some("Low difficulty share") => 23,
                                        Some("Job not found") => 21,
                                        _ => 20,
                                    };
                                    Some(json!([code, reject_reason.unwrap_or("Unknown")]))
                                };
                                send_json(writer, &JsonRpcResponse {
                                    id: rpc.id,
                                    result: json!(accepted),
                                    error,
                                }).await?;

                                // If we found a valid block, submit and broadcast it
                                if let Some(block) = maybe_block {
                                    submit_mined_block(
                                        block, current_template.height,
                                        chain_state, command_tx, event_sender,
                                        best_height, best_hash, mempool,
                                        addr, scripthash_index,
                                    ).await;
                                }

                                // Forward qualifying shares to the Datum pool (kept
                                // off the hot path: only in Datum mode with a client).
                                if let (Some(share), Some(dc)) = (maybe_share, datum_client) {
                                    let is_datum = mining_config.read().await.mode == MiningMode::Datum;
                                    if is_datum {
                                        let pool_difficulty =
                                            dc.status().await.pool_difficulty.unwrap_or(0.0);
                                        if share.difficulty >= pool_difficulty {
                                            dc.submit_share(share).await;
                                        }
                                    }
                                }

                                // Vardiff ramp-up: retarget from the observed
                                // share rate and push the change with a fresh job.
                                if accepted {
                                    if let Some(new_diff) = vardiff
                                        .as_mut()
                                        .and_then(|v| v.on_share(Instant::now()))
                                    {
                                        current_share_difficulty = new_diff;
                                        current_job = send_v1_retarget(
                                            writer, new_diff, &current_template,
                                            &extranonce1, extranonce2_size,
                                            &coinbase_script, &mut job_counter,
                                        ).await?;
                                        info!(
                                            %addr, worker = %worker_name,
                                            difficulty = new_diff, job_id = %current_job.job_id,
                                            "Vardiff retarget (observed share rate)"
                                        );
                                    }
                                }
                            }
                            "mining.authorize" => {
                                send_json(writer, &JsonRpcResponse {
                                    id: rpc.id,
                                    result: json!(true),
                                    error: None,
                                }).await?;
                            }
                            "mining.extranonce.subscribe" => {
                                send_json(writer, &JsonRpcResponse {
                                    id: rpc.id,
                                    result: json!(true),
                                    error: None,
                                }).await?;
                            }
                            "mining.configure" => {
                                // BIP 310 mining.configure — acknowledge version-rolling
                                let mut result = json!({});
                                if let Some(params) = rpc.params.as_array() {
                                    if let Some(extensions) = params.first().and_then(|v| v.as_array()) {
                                        for ext in extensions {
                                            if ext.as_str() == Some("version-rolling") {
                                                result["version-rolling"] = json!(true);
                                                result["version-rolling.mask"] = json!("1fffe000");
                                                result["version-rolling.min-bit-count"] = json!(0);
                                            }
                                        }
                                    }
                                }
                                send_json(writer, &JsonRpcResponse {
                                    id: rpc.id,
                                    result: json!(result),
                                    error: None,
                                }).await?;
                            }
                            "mining.suggest_difficulty" => {
                                // Miner may re-send this after authorize; acknowledge
                                // with success so firmware doesn't stall on an error,
                                // and honor it (clamped) when vardiff is running.
                                send_json(writer, &JsonRpcResponse {
                                    id: rpc.id,
                                    result: json!(true),
                                    error: None,
                                }).await?;
                                let suggested = parse_suggested_difficulty(&rpc.params);
                                if let (Some(s), Some(v)) = (suggested, vardiff.as_mut()) {
                                    if let Some(new_diff) = v.suggest(s, Instant::now()) {
                                        current_share_difficulty = new_diff;
                                        current_job = send_v1_retarget(
                                            writer, new_diff, &current_template,
                                            &extranonce1, extranonce2_size,
                                            &coinbase_script, &mut job_counter,
                                        ).await?;
                                        info!(
                                            %addr, difficulty = new_diff,
                                            "Vardiff retarget (miner suggest_difficulty)"
                                        );
                                        continue;
                                    }
                                }
                                debug!(%addr, "V1 mining.suggest_difficulty acknowledged");
                            }
                            other => {
                                debug!(%addr, method = other, "Unknown V1 method, ignoring");
                                send_json(writer, &JsonRpcResponse {
                                    id: rpc.id,
                                    result: Value::Null,
                                    error: Some(json!([20, "Unknown method"])),
                                }).await?;
                            }
                        }
                    }
                    Ok(None) => {
                        info!(%addr, worker = %worker_name, "V1 client disconnected");
                        break;
                    }
                    Err(e) => {
                        error!(%addr, error = %e, "V1 read error");
                        break;
                    }
                }
            }

            result = new_block_rx.recv() => {
                match result {
                    Ok(()) => {
                        let template = build_template(
                            params, header_index, mempool, best_height, best_hash,
                            next_template_id, 100, mining_config, datum_client,
                        ).await;

                        // Keep vardiff's cap tracking the chain's difficulty
                        // retargets; announce if the cap forced a change.
                        if let Some(new_diff) = vardiff
                            .as_mut()
                            .and_then(|v| v.update_max(compact_target_to_difficulty(template.bits)))
                        {
                            current_share_difficulty = new_diff;
                            send_json(writer, &JsonRpcNotification {
                                id: None,
                                method: "mining.set_difficulty".to_string(),
                                params: json!([new_diff]),
                            }).await?;
                        }

                        current_job = build_v1_job(&template, &extranonce1, extranonce2_size, &coinbase_script);
                        current_job.job_id = format!("{job_counter:x}");
                        job_counter += 1;
                        current_template = template.clone();
                        templates.write().await.insert(template.template_id, template);

                        send_v1_notify(writer, &current_job, true).await?;
                        info!(%addr, job_id = %current_job.job_id, "Sent new V1 job (new block)");
                    }
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        warn!(%addr, lagged = n, "V1 new-block receiver lagged");
                    }
                    Err(broadcast::error::RecvError::Closed) => {
                        info!(%addr, "New block channel closed");
                        break;
                    }
                }
            }

            result = config_version.changed() => {
                if result.is_ok() {
                    // Mining config changed live (address, coinbase tag, mode, ...).
                    // Rebuild the coinbase output script and a fresh template, then
                    // push a clean job so subsequent shares use the new config.
                    coinbase_script = {
                        let cfg = mining_config.read().await;
                        build_output_script(&cfg.mining_address)
                    };
                    let template = build_template(
                        params, header_index, mempool, best_height, best_hash,
                        next_template_id, 100, mining_config, datum_client,
                    ).await;

                    // Vardiff state (when active) survives config changes —
                    // the miner's hashrate didn't change with the coinbase.
                    current_share_difficulty = match &vardiff {
                        Some(v) => v.difficulty(),
                        None => effective_share_difficulty(bits_override, template.bits),
                    };
                    send_json(writer, &JsonRpcNotification {
                        id: None,
                        method: "mining.set_difficulty".to_string(),
                        params: json!([current_share_difficulty]),
                    }).await?;

                    current_job = build_v1_job(&template, &extranonce1, extranonce2_size, &coinbase_script);
                    current_job.job_id = format!("{job_counter:x}");
                    job_counter += 1;
                    current_template = template.clone();
                    templates.write().await.insert(template.template_id, template);

                    send_v1_notify(writer, &current_job, true).await?;
                    info!(%addr, job_id = %current_job.job_id, "Pushed new V1 job (mining config changed)");
                }
            }

            _ = vardiff_tick.tick() => {
                if let Some(new_diff) = vardiff
                    .as_mut()
                    .and_then(|v| v.on_tick(Instant::now()))
                {
                    current_share_difficulty = new_diff;
                    current_job = send_v1_retarget(
                        writer, new_diff, &current_template,
                        &extranonce1, extranonce2_size,
                        &coinbase_script, &mut job_counter,
                    ).await?;
                    info!(
                        %addr, worker = %worker_name, difficulty = new_diff,
                        "Vardiff retarget (no shares at current difficulty)"
                    );
                }
            }
        }
    }

    Ok(())
}

/// Build the output script for coinbase transactions.
fn build_output_script(mining_address: &Option<String>) -> Vec<u8> {
    if let Some(addr_str) = mining_address {
        // Try to parse as a Bitcoin address
        if let Ok(addr) = addr_str.parse::<bitcoin::Address<bitcoin::address::NetworkUnchecked>>() {
            let addr = addr.assume_checked();
            return addr.script_pubkey().to_bytes();
        }
        warn!(address = %addr_str, "Invalid mining address, falling back to OP_TRUE");
    }
    // OP_TRUE (anyone-can-spend) — fine for testnet/regtest
    vec![0x51]
}

/// Compute the ordered coinbase outputs `(value, script_pubkey)` for a template.
///
/// In solo mode (`template.pool_outputs` empty) this returns a single output
/// paying the full `coinbase_value` to `primary_script` — byte-identical to the
/// legacy single-output behavior.
///
/// In Datum mode each pool output value is `value_fraction * coinbase_value`.
/// The miner's PRIMARY output (paid to `primary_script`) comes first and
/// receives `coinbase_value - sum(pool_values)`. If the pool outputs would meet
/// or exceed the coinbase value (primary underflows or is zero), the pool
/// outputs are skipped entirely and a single full-value miner output is emitted
/// — never an invalid coinbase. Pool outputs with invalid script hex are
/// skipped with a warning.
///
/// Shared by [`build_v1_job`] (server-side cb2) and [`assemble_mined_block`]
/// (the reconstructed block) so the two stay byte-consistent.
fn compute_coinbase_outputs(template: &TemplateData, primary_script: &[u8]) -> Vec<(u64, Vec<u8>)> {
    // Compute the value-bearing outputs (solo or Datum pool split), then append
    // the BIP 141 witness commitment output below.
    let mut outputs: Vec<(u64, Vec<u8>)> = compute_value_outputs(template, primary_script);

    // BIP 141: append the witness commitment output (value 0) last, so a strict
    // peer finds it as the final `OP_RETURN 0xaa21a9ed` output. Present only when
    // the template includes at least one witness transaction.
    if let Some(ref commitment_spk) = template.witness_commitment {
        outputs.push((0, commitment_spk.clone()));
    }

    outputs
}

/// The value-bearing coinbase outputs (miner payout + optional Datum pool split),
/// excluding the BIP 141 witness commitment. Split out so the commitment is
/// appended exactly once regardless of which branch produces the payout outputs.
fn compute_value_outputs(template: &TemplateData, primary_script: &[u8]) -> Vec<(u64, Vec<u8>)> {
    let coinbase_value = template.coinbase_value;

    if template.pool_outputs.is_empty() {
        return vec![(coinbase_value, primary_script.to_vec())];
    }

    let mut pool: Vec<(u64, Vec<u8>)> = Vec::with_capacity(template.pool_outputs.len());
    let mut pool_sum: u64 = 0;
    for spec in &template.pool_outputs {
        let script = match hex::decode(&spec.script_pubkey_hex) {
            Ok(s) => s,
            Err(e) => {
                warn!(
                    label = %spec.label,
                    script_pubkey_hex = %spec.script_pubkey_hex,
                    error = %e,
                    "skipping pool coinbase output with invalid script hex"
                );
                continue;
            }
        };
        let value = (spec.value_fraction * coinbase_value as f64) as u64;
        pool_sum = pool_sum.saturating_add(value);
        pool.push((value, script));
    }

    let primary_value = coinbase_value.saturating_sub(pool_sum);
    if primary_value == 0 || pool.is_empty() {
        warn!(
            coinbase_value,
            pool_sum,
            "pool outputs meet or exceed coinbase value (or none valid); \
             falling back to single miner output"
        );
        return vec![(coinbase_value, primary_script.to_vec())];
    }

    let mut outputs = Vec::with_capacity(1 + pool.len());
    outputs.push((primary_value, primary_script.to_vec()));
    outputs.extend(pool);
    outputs
}

/// Build a Stratum V1 job from a template.
///
/// Stratum V1 coinbase split uses **non-witness** serialization so the miner
/// computes the TXID (not WTXID) for the merkle root.  The miner reconstructs:
///   `coinbase = coinbase1 + extranonce1 + extranonce2 + coinbase2`
/// where extranonce1 was provided in the subscribe response.
fn build_v1_job(
    template: &TemplateData,
    _extranonce1: &[u8; 4],
    extranonce2_size: usize,
    output_script: &[u8],
) -> V1Job {
    let height_script = encode_bip34_height(template.height);
    // extranonce1 (4 bytes) + extranonce2 (variable) are inserted by the miner
    let extranonce_total = 4 + extranonce2_size;

    // scriptsig = bip34_height + coinbase_tag + extranonce1 + extranonce2
    let scriptsig_len = height_script.len() + template.coinbase_tag.len() + extranonce_total;

    // --- coinbase1: everything BEFORE extranonce1 (non-witness serialization) ---
    let mut cb1 = Vec::new();
    // tx version (2, little-endian)
    cb1.extend_from_slice(&2u32.to_le_bytes());
    // NO segwit marker/flag — Stratum V1 uses non-witness serialization for TXID
    // input count
    cb1.push(0x01);
    // prevout: null hash + 0xffffffff index
    cb1.extend_from_slice(&[0u8; 32]);
    cb1.extend_from_slice(&0xffffffffu32.to_le_bytes());
    // scriptsig length
    cb1.push(scriptsig_len as u8);
    // bip34 height
    cb1.extend_from_slice(&height_script);
    // coinbase tag — lives inside cb1 so the miner's reconstruction
    // (cb1 + en1 + en2 + cb2) needs no change
    cb1.extend_from_slice(&template.coinbase_tag);
    // extranonce1 + extranonce2 are appended by the miner between cb1 and cb2

    // --- coinbase2: everything after extranonce2 (non-witness serialization) ---
    let outputs = compute_coinbase_outputs(template, output_script);
    let mut cb2 = Vec::new();
    // input sequence
    cb2.extend_from_slice(&0xffffffffu32.to_le_bytes());
    // output count (always < 0xfd in practice: 1 miner output + pool outputs)
    cb2.push(outputs.len() as u8);
    for (value, script) in &outputs {
        // output value
        cb2.extend_from_slice(&value.to_le_bytes());
        // output scriptpubkey, CompactSize-prefixed
        let spk_len = script.len();
        if spk_len < 0xfd {
            cb2.push(spk_len as u8);
        } else {
            cb2.push(0xfd);
            cb2.extend_from_slice(&(spk_len as u16).to_le_bytes());
        }
        cb2.extend_from_slice(script);
    }
    // NO witness data — non-witness serialization for TXID
    // locktime
    cb2.extend_from_slice(&0u32.to_le_bytes());

    // Merkle branches from template's merkle_path
    let merkle_branches: Vec<String> = template.merkle_path.iter().map(hex::encode).collect();

    V1Job {
        job_id: format!("{:x}", template.template_id),
        prev_hash: template.prev_hash,
        coinbase1: cb1,
        coinbase2: cb2,
        merkle_branches,
        version: template.version,
        bits: template.bits,
        min_time: template.min_time,
        template_id: template.template_id,
    }
}

/// Send a `mining.notify` notification to a V1 client.
async fn send_v1_notify(
    writer: &mut OwnedWriteHalf,
    job: &V1Job,
    clean_jobs: bool,
) -> anyhow::Result<()> {
    // ntime must be strictly greater than the previous blocks' median-time-past
    // (BIP 113). After rapid mining, recent block timestamps can run ahead of
    // wall-clock, so clamp up to the template's min_time (= MTP+1).
    let timestamp = (SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as u32)
        .max(job.min_time);

    // Stratum V1 prev_hash: 32 bytes, hex, but with each 4-byte word reversed
    // (this is the standard Stratum quirk)
    let prev_hash_bytes = template_prev_hash_stratum(&job.prev_hash);

    let notify = JsonRpcNotification {
        id: None,
        method: "mining.notify".to_string(),
        params: json!([
            job.job_id,
            prev_hash_bytes,
            hex::encode(&job.coinbase1),
            hex::encode(&job.coinbase2),
            job.merkle_branches,
            format!("{:08x}", job.version),
            format!("{:08x}", job.bits),
            format!("{:08x}", timestamp),
            clean_jobs
        ]),
    };
    send_json(writer, &notify).await
}

/// Announce a changed share difficulty and immediately follow with a fresh
/// job (clean) built from the current template, so the miner applies the new
/// difficulty to work it can actually submit — `mining.set_difficulty` alone
/// only takes effect on the next job. Returns the new current job; shares for
/// the replaced job are rejected as stale, same as on any new-block job push.
#[allow(clippy::too_many_arguments)]
async fn send_v1_retarget(
    writer: &mut OwnedWriteHalf,
    difficulty: f64,
    template: &TemplateData,
    extranonce1: &[u8; 4],
    extranonce2_size: usize,
    coinbase_script: &[u8],
    job_counter: &mut u64,
) -> anyhow::Result<V1Job> {
    send_json(
        writer,
        &JsonRpcNotification {
            id: None,
            method: "mining.set_difficulty".to_string(),
            params: json!([difficulty]),
        },
    )
    .await?;
    let mut job = build_v1_job(template, extranonce1, extranonce2_size, coinbase_script);
    job.job_id = format!("{job_counter:x}");
    *job_counter += 1;
    send_v1_notify(writer, &job, true).await?;
    Ok(job)
}

/// Extract the difficulty from `mining.suggest_difficulty` params. Firmwares
/// send `[1000]`, `[1000.5]`, or occasionally the number as a string.
fn parse_suggested_difficulty(params: &Value) -> Option<f64> {
    let v = params.as_array()?.first()?;
    v.as_f64()
        .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
        .filter(|d| d.is_finite() && *d > 0.0)
}

/// Encode prev_hash in Stratum V1's quirky byte order.
///
/// Stratum V1 prevhash = the 32 internal (LE) header bytes split into 8
/// four-byte words, KEEPING word order but swapping the bytes within each
/// word.  Equivalently: the display (BE) hash's 32-bit words in reverse
/// order with bytes inside each word untouched.  Miners undo the per-word
/// swap (`swap_endian_words` in ESP-Miner, cgminer, etc.) to recover the LE
/// header bytes.  Sanity check: mainnet display hashes start with many zero
/// bytes, so a canonical Stratum prevhash always ENDS with the zero run
/// (e.g. `...0001a0f90000000000000000`), matching real pool notifies.
///
/// History: this function has been flipped twice.  The original (correct)
/// per-word-swap version was "fixed" to reversed-chunk order after miners
/// showed "BLOCK FOUND" without submitting — but that symptom was really the
/// static 65536 share-difficulty throttle (shares just never cleared it).
/// The flip went unnoticed on regtest because a wrongly reconstructed header
/// still beats the trivial regtest target ~50% of the time (and the block the
/// server then assembles uses the CORRECT prevhash, so it validates), while
/// on mainnet it rejected every share as "Low difficulty share": the miner
/// builds its header from this string, so the server's reconstruction from
/// the true prev_hash never matched (2026-07-13, bitaxe, rejected shares all
/// computed at ~4e-10 ≈ random hashes).
fn template_prev_hash_stratum(hash: &BlockHash) -> String {
    let bytes = hash.to_byte_array();
    let mut result = String::with_capacity(64);
    for chunk in bytes.chunks(4) {
        // word order follows the internal (LE) header bytes …
        for &b in chunk.iter().rev() {
            // … but bytes within each 32-bit word are swapped
            result.push_str(&format!("{b:02x}"));
        }
    }
    result
}

/// Handle a `mining.submit` from a V1 client.
///
/// Returns `(accepted, Option<Block>, Option<DatumShare>)`. If the share meets
/// the network target, the assembled block is returned for submission and
/// broadcast. For every accepted share a [`DatumShare`] is built (the caller
/// decides whether to forward it to a Datum pool).
#[allow(clippy::too_many_arguments)]
fn handle_v1_submit(
    rpc: &JsonRpcRequest,
    current_job: &V1Job,
    current_template: &TemplateData,
    extranonce1: &[u8; 4],
    share_tracker: &ShareTracker,
    worker_name: &str,
    addr: SocketAddr,
    event_sender: &broadcast::Sender<NodeNotification>,
    output_script: &[u8],
    min_share_difficulty: f64,
) -> (
    bool,
    Option<Block>,
    Option<DatumShare>,
    Option<&'static str>,
) {
    let params = match rpc.params.as_array() {
        Some(p) if p.len() >= 5 => p,
        _ => {
            warn!(%addr, "Invalid mining.submit params");
            return (false, None, None, Some("Invalid params"));
        }
    };

    let _worker = params[0].as_str().unwrap_or("");
    let job_id = params[1].as_str().unwrap_or("");
    let extranonce2_hex = params[2].as_str().unwrap_or("");
    let ntime_hex = params[3].as_str().unwrap_or("");
    let nonce_hex = params[4].as_str().unwrap_or("");

    if job_id != current_job.job_id {
        debug!(%addr, submitted = job_id, current = %current_job.job_id, "Stale job");
        share_tracker.record_share(worker_name.to_string(), 1.0, false);
        return (false, None, None, Some("Job not found"));
    }

    let extranonce2 = match hex::decode(extranonce2_hex) {
        Ok(v) => v,
        Err(_) => {
            warn!(%addr, "Invalid extranonce2 hex");
            return (false, None, None, Some("Invalid params"));
        }
    };
    let ntime = match u32::from_str_radix(ntime_hex, 16) {
        Ok(v) => v,
        Err(_) => return (false, None, None, Some("Invalid params")),
    };
    let nonce = match u32::from_str_radix(nonce_hex, 16) {
        Ok(v) => v,
        Err(_) => return (false, None, None, Some("Invalid params")),
    };

    // BIP 310 version rolling — optional 6th param is version bits to XOR
    let version_bits = if params.len() >= 6 {
        params[5]
            .as_str()
            .and_then(|s| u32::from_str_radix(s, 16).ok())
            .unwrap_or(0)
    } else {
        0
    };

    // Reconstruct coinbase (non-witness serialization for TXID)
    // Stratum V1: coinbase = coinbase1 + extranonce1 + extranonce2 + coinbase2
    let mut coinbase_raw = Vec::new();
    coinbase_raw.extend_from_slice(&current_job.coinbase1);
    coinbase_raw.extend_from_slice(extranonce1);
    coinbase_raw.extend_from_slice(&extranonce2);
    coinbase_raw.extend_from_slice(&current_job.coinbase2);

    // Hash coinbase (without witness data for txid)
    let coinbase_hash = sha256d::Hash::hash(&coinbase_raw).to_byte_array();

    // Compute merkle root
    let mut current_hash = coinbase_hash;
    for branch_hex in &current_job.merkle_branches {
        if let Ok(branch) = hex::decode(branch_hex) {
            if branch.len() == 32 {
                let mut buf = [0u8; 64];
                buf[..32].copy_from_slice(&current_hash);
                buf[32..].copy_from_slice(&branch);
                current_hash = sha256d::Hash::hash(&buf).to_byte_array();
            }
        }
    }

    // Build 80-byte block header
    let mut header_bytes = [0u8; 80];
    let rolled_version = current_job.version ^ version_bits;
    header_bytes[0..4].copy_from_slice(&rolled_version.to_le_bytes());
    header_bytes[4..36].copy_from_slice(&current_job.prev_hash.to_byte_array());
    header_bytes[36..68].copy_from_slice(&current_hash); // merkle root
    header_bytes[68..72].copy_from_slice(&ntime.to_le_bytes());
    header_bytes[72..76].copy_from_slice(&current_job.bits.to_le_bytes());
    header_bytes[76..80].copy_from_slice(&nonce.to_le_bytes());

    // Double-SHA256 the header
    let header_hash = sha256d::Hash::hash(&header_bytes).to_byte_array();

    // Compute actual share difficulty from the header hash
    let share_difficulty = hash_to_share_difficulty(&header_hash);

    // Does this submission solve the block (meets the network target)?  A real
    // block solution must always be accepted regardless of the share-difficulty
    // floor: on regtest the network difficulty (~5e-10) is far below the floor,
    // so without this short-circuit every winning share — and thus every block —
    // would be rejected as "Low difficulty share" and never submitted.
    let target = compact_to_target(current_job.bits);
    let hash_u256 = bytes_to_u256(&header_hash);
    let is_block = hash_u256 <= target;

    if !is_block && share_difficulty < min_share_difficulty {
        share_tracker.record_share(worker_name.to_string(), share_difficulty, false);
        return (false, None, None, Some("Low difficulty share"));
    }

    share_tracker.record_share(worker_name.to_string(), share_difficulty, true);

    let _ = event_sender.send(NodeNotification::MiningShare {
        worker: worker_name.to_string(),
        accepted: true,
        hashrate: share_tracker.hashrate(),
        difficulty: share_difficulty,
    });

    // Build the DatumShare for this accepted share (the caller decides whether
    // to forward it to a Datum pool based on mode + pool difficulty).
    let datum_share = DatumShare {
        template_height: current_template.height,
        header_hash: hex::encode(header_hash),
        nonce,
        ntime,
        coinbase_tx: hex::encode(&coinbase_raw),
        difficulty: share_difficulty,
    };

    // Check if meets network target
    if is_block {
        info!(
            %addr,
            hash = hex::encode(header_hash),
            difficulty = share_difficulty,
            height = current_template.height,
            "BLOCK FOUND — meets network target!"
        );
        share_tracker.record_block_found();

        // Assemble the full block for submission
        let block = assemble_mined_block(
            current_template,
            rolled_version,
            &current_hash,
            ntime,
            nonce,
            extranonce1,
            &extranonce2,
            output_script,
        );

        debug!(%addr, worker = worker_name, job_id, "Share accepted (block found)");
        return (true, Some(block), Some(datum_share), None);
    }

    debug!(%addr, worker = worker_name, job_id, "Share accepted");
    (true, None, Some(datum_share), None)
}

/// Submit a mined block: validate via `connect_block` and broadcast to peers.
///
/// After a successful connect the function updates the shared `best_height` /
/// `best_hash` Arcs (the same ones the RPC server reads), so that
/// `getblockchaininfo` immediately reflects the newly mined block rather than
/// waiting for the drain loop to run with the block a second time.
#[allow(clippy::too_many_arguments)]
async fn submit_mined_block(
    block: Block,
    height: u32,
    chain_state: &Option<Arc<tokio::sync::Mutex<ChainState>>>,
    command_tx: &Option<tokio::sync::mpsc::Sender<PeerCommand>>,
    event_sender: &broadcast::Sender<NodeNotification>,
    shared_best_height: &Arc<RwLock<u32>>,
    shared_best_hash: &Arc<RwLock<BlockHash>>,
    mempool: &Arc<RwLock<Mempool>>,
    addr: SocketAddr,
    scripthash_index: &Option<Arc<ScripthashIndex>>,
) {
    let block_hash = block.block_hash();

    // Validate and connect the block
    if let Some(ref cs) = chain_state {
        let mut cs_guard = cs.lock().await;

        // Reject stale shares: the block must extend the current canonical tip.
        // If prev_blockhash != best_hash the miner solved a stale job (the
        // chain advanced while the miner was working).  Accepting it would
        // call connect_block with mismatched height/UTXO-set state, corrupting
        // the chain state and causing empty getheaders responses to peers.
        if block.header.prev_blockhash != cs_guard.best_hash {
            warn!(
                %addr,
                height,
                hash = %block_hash,
                expected_prev = %cs_guard.best_hash,
                got_prev = %block.header.prev_blockhash,
                "Stale share rejected: block does not extend canonical tip (job built on old chain)"
            );
            return;
        }

        // Validate + connect FIRST, and only persist the header / advance the
        // header tip on success. connect_block reads the *prev* header (already
        // stored) but not this block's own header, so it doesn't need the header
        // pre-inserted. Inserting + advancing header_tip before connect (as we
        // used to) is dangerous now that connect_block can legitimately reject a
        // mined block (e.g. ntime <= median-time-past): a rejected submit would
        // leave header_tip racing ahead of the block tip, and after a few such
        // rejects `header_tip - block_tip` trips the is_catching_up() gate, which
        // makes the gateway stop sending jobs — silently freezing the miner.
        match cs_guard.connect_block(&block, height) {
            Ok(()) => {}
            Err(e) => {
                error!(
                    %addr,
                    height,
                    hash = %block_hash,
                    error = %e,
                    "Mined block failed validation — NOT broadcasting"
                );
                return;
            }
        }

        // Persist the header now that the block is connected. This is required so
        // that (1) the next block's calculate_next_bits() can read this header's
        // prev, and (2) getblockhash / blockchain.block.header height lookups
        // resolve. connect_block stored the block bytes, height index, and UTXO
        // set, but not the CF_HEADERS entry.
        let prev_hash = block.header.prev_blockhash;
        let block_work = calculate_work(&block.header.target());
        let prev_work = cs_guard
            .header_index
            .get_header(&prev_hash)
            .ok()
            .flatten()
            .map(|h| h.chain_work)
            .unwrap_or([0u8; 32]);
        let chain_work = add_chain_work(&prev_work, &block_work);
        let stored_header = StoredHeader {
            header: block.header,
            height,
            chain_work,
        };
        if let Err(e) = cs_guard
            .header_index
            .insert_header(&block_hash, &stored_header)
        {
            error!(%addr, height, hash = %block_hash, error = %e, "Failed to insert header for connected block");
        }
        if let Err(e) = cs_guard.header_index.set_header_tip(&block_hash, height) {
            warn!(%addr, height, hash = %block_hash, error = %e, "Failed to set header tip for mined block");
        }
        info!(
            %addr,
            height,
            hash = %block_hash,
            "Mined block validated and connected successfully"
        );
        drop(cs_guard);
    } else {
        warn!(%addr, "No chain state available — cannot validate mined block");
        return;
    }

    // Update the shared node state so the RPC (getblockchaininfo) and the
    // TemplateProvider's own tip-tracking both reflect the new block immediately.
    // Without this, the drain loop in main.rs never runs for locally-mined
    // blocks, leaving shared_best_height stale until a peer re-announces.
    *shared_best_height.write().await = height;
    *shared_best_hash.write().await = block_hash;

    // Evict the transactions confirmed by this block from the mempool. Stratum
    // blocks connect directly here (not via the main.rs P2P drain loop that
    // calls remove_for_block), so without this the mined txs would linger and
    // the next template would re-include already-spent inputs, making every
    // subsequent block fail connect_block and stalling mining.
    mempool.write().await.remove_for_block(&block);

    // Index block transactions inline — BEFORE publishing NewBlock — so that
    // Electrum subscription notifications include the correct up-to-date status.
    // Without this, the scripthash backfill runs ~10 seconds after the block,
    // meaning Electrum clients receive a stale "no change" notification for any
    // addresses that received coins in this block, causing unnecessary reconnects.
    if let Some(ref idx) = scripthash_index {
        if let Err(e) = idx.index_block_transactions(&block, height) {
            warn!(%addr, height, error = %e, "Scripthash indexing error for mined block");
        }
    }

    // Publish NewBlock so the TemplateProvider dispatches fresh work to all
    // connected miners.  Without this, miners re-solve the same stale job and
    // hit BIP-30 duplicate-coinbase errors on every subsequent share.
    let _ = event_sender.send(NodeNotification::NewBlock {
        hash: block_hash.to_string(),
        height,
    });

    // Broadcast to peers
    if let Some(ref tx) = command_tx {
        match tx.send(PeerCommand::BroadcastBlock(block, height)).await {
            Ok(()) => {
                info!(
                    %addr,
                    height,
                    hash = %block_hash,
                    "Mined block broadcast to peers"
                );
            }
            Err(e) => {
                error!(
                    %addr,
                    error = %e,
                    "Failed to send BroadcastBlock command"
                );
            }
        }
    } else {
        warn!(%addr, "No P2P command channel — mined block NOT broadcast");
    }
}

/// Assemble a full `Block` from the template and the miner's solution.
#[allow(clippy::too_many_arguments)]
fn assemble_mined_block(
    template: &TemplateData,
    version: u32,
    merkle_root: &[u8; 32],
    ntime: u32,
    nonce: u32,
    extranonce1: &[u8; 4],
    extranonce2: &[u8],
    output_script: &[u8],
) -> Block {
    use bitcoin::consensus::encode::deserialize;

    // Build the coinbase transaction
    let height_script = encode_bip34_height(template.height);
    let mut scriptsig_bytes = Vec::new();
    scriptsig_bytes.extend_from_slice(&height_script);
    scriptsig_bytes.extend_from_slice(&template.coinbase_tag);
    scriptsig_bytes.extend_from_slice(extranonce1);
    scriptsig_bytes.extend_from_slice(extranonce2);

    // Outputs must match build_v1_job's cb2 exactly (same ordering + values) so
    // the server-reconstructed coinbase TXID matches what the miner hashed.
    let outputs: Vec<TxOut> = compute_coinbase_outputs(template, output_script)
        .into_iter()
        .map(|(value, script)| TxOut {
            value: bitcoin::Amount::from_sat(value),
            script_pubkey: ScriptBuf::from_bytes(script),
        })
        .collect();

    // BIP 141: when the block carries a witness commitment, the coinbase input
    // must hold the 32-byte witness reserved value (all zeros). Without it the
    // block serializes as an invalid SegWit block and strict peers (Core/Knots)
    // reject it as a "mutated block". The witness is not part of the coinbase
    // txid, so it does not affect cb1/cb2 or the merkle root the miner hashed.
    let coinbase_witness = if template.witness_commitment.is_some() {
        let mut w = Witness::new();
        w.push([0u8; 32]);
        w
    } else {
        Witness::new()
    };

    let coinbase_tx = Transaction {
        version: TxVersion(2),
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: bitcoin::OutPoint::null(),
            script_sig: ScriptBuf::from_bytes(scriptsig_bytes),
            sequence: bitcoin::Sequence::MAX,
            witness: coinbase_witness,
        }],
        output: outputs,
    };

    // Deserialize template transactions
    let mut txdata = vec![coinbase_tx];
    for raw_tx in &template.transactions {
        if let Ok(tx) = deserialize::<Transaction>(raw_tx) {
            txdata.push(tx);
        }
    }

    // Build block header
    let block_header = BlockHeader {
        version: bitcoin::block::Version::from_consensus(version as i32),
        prev_blockhash: template.prev_hash,
        merkle_root: bitcoin::TxMerkleNode::from_byte_array(*merkle_root),
        time: ntime,
        bits: CompactTarget::from_consensus(template.bits),
        nonce,
    };

    Block {
        header: block_header,
        txdata,
    }
}

/// Convert a compact target (nBits) to a 256-bit target value.
fn compact_to_target(bits: u32) -> [u8; 32] {
    let exponent = ((bits >> 24) & 0xff) as usize;
    let mantissa = bits & 0x00ffffff;
    let mut target = [0u8; 32];

    if (3..=32).contains(&exponent) {
        let offset = 32 - exponent;
        if offset < 30 {
            target[offset] = ((mantissa >> 16) & 0xff) as u8;
            target[offset + 1] = ((mantissa >> 8) & 0xff) as u8;
            target[offset + 2] = (mantissa & 0xff) as u8;
        }
    }
    target
}

/// Interpret 32 bytes as a big-endian 256-bit number for comparison.
fn bytes_to_u256(bytes: &[u8; 32]) -> [u8; 32] {
    // Block hash bytes from sha256d are already in internal byte order (LE).
    // For target comparison, we need to reverse to big-endian.
    let mut be = [0u8; 32];
    for i in 0..32 {
        be[i] = bytes[31 - i];
    }
    be
}

/// Compute the bitcoin difficulty of a hash (bdiff).
///
/// difficulty = diff1_target / hash_value, where
/// diff1_target = 0x00000000FFFF0000...0000 (the target for difficulty 1).
fn hash_to_share_difficulty(hash: &[u8; 32]) -> f64 {
    let be = bytes_to_u256(hash);

    // Skip leading zero bytes
    let mut i = 0usize;
    while i < 32 && be[i] == 0 {
        i += 1;
    }
    if i >= 32 {
        return f64::MAX; // all zeros — impossible hash
    }

    // Read up to 8 significant bytes into a u64 mantissa
    let hash_start = i;
    let mut hash_mantissa: u64 = 0;
    let end = (i + 8).min(32);
    while i < end {
        hash_mantissa = (hash_mantissa << 8) | be[i] as u64;
        i += 1;
    }
    // Pad if fewer than 8 bytes were available
    let bytes_read = i - hash_start;
    if bytes_read < 8 {
        hash_mantissa <<= (8 - bytes_read) * 8;
    }

    if hash_mantissa == 0 {
        return 0.0;
    }

    // diff-1 target starts at byte offset 4: 0xFFFF000000000000 (as 8-byte mantissa)
    let diff1_mantissa: u64 = 0xFFFF_0000_0000_0000;
    let diff1_start: usize = 4;

    // difficulty = (diff1_mantissa * 2^(-diff1_start*8)) / (hash_mantissa * 2^(-hash_start*8))
    //            = (diff1_mantissa / hash_mantissa) * 2^((hash_start - diff1_start) * 8)
    let ratio = diff1_mantissa as f64 / hash_mantissa as f64;
    let exponent = ((hash_start as i32) - (diff1_start as i32)) * 8;
    ratio * 2f64.powi(exponent)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_bip34_height() {
        // OP_0 / OP_n range — must match Bitcoin Core's CScript() << n
        assert_eq!(encode_bip34_height(0), vec![0x00]); // OP_0
        assert_eq!(encode_bip34_height(1), vec![0x51]); // OP_1
        assert_eq!(encode_bip34_height(16), vec![0x60]); // OP_16
                                                         // Push-data range
        assert_eq!(encode_bip34_height(17), vec![1, 17]);
        assert_eq!(encode_bip34_height(100), vec![1, 100]);
        assert_eq!(encode_bip34_height(255), vec![2, 0xff, 0x00]); // high-bit pad
        assert_eq!(encode_bip34_height(256), vec![2, 0x00, 0x01]);
        assert_eq!(encode_bip34_height(500_000), vec![3, 0x20, 0xa1, 0x07]);
    }

    #[test]
    fn test_template_prev_hash_stratum() {
        // Regtest genesis block hash (display/BE):
        //   0f9188f1 3cb7b2c7 1f2a335e 3a4fc328 bf5beb43 6012afca 590b1a11 466e2206
        // Canonical Stratum prevhash = display-hash 32-bit words in REVERSE
        // order, bytes within each word untouched (equivalently: LE header
        // bytes with each 4-byte word byte-swapped in place):
        //   466e2206 590b1a11 6012afca bf5beb43 3a4fc328 1f2a335e 3cb7b2c7 0f9188f1
        let hash_hex = "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206";
        let hash_bytes: [u8; 32] = hex::decode(hash_hex).unwrap().try_into().unwrap();
        // bitcoin BlockHash is stored LE (reversed display)
        let mut le_bytes = hash_bytes;
        le_bytes.reverse();
        let hash = bitcoin::BlockHash::from_byte_array(le_bytes);
        let result = template_prev_hash_stratum(&hash);
        assert_eq!(
            result,
            "466e2206590b1a116012afcabf5beb433a4fc3281f2a335e3cb7b2c70f9188f1"
        );
    }

    /// Real-world regression vector for the prevhash byte order (2026-07-13).
    ///
    /// Mainnet block 957869 (display):
    ///   00000000000000000001a0f90d47e80ca66ea1d892fe1c3857f3e806fa250a64
    /// Real pool notifies for this tip carry the zero run at the END of the
    /// prevhash string. The buggy reversed-chunk encoding put it at the
    /// FRONT (`0000000000000000f9a00100...`, observed in the bitaxe rx log),
    /// making every mainnet share fail header reconstruction.
    #[test]
    fn test_template_prev_hash_stratum_mainnet_zero_run_at_end() {
        let display = "00000000000000000001a0f90d47e80ca66ea1d892fe1c3857f3e806fa250a64";
        let hash_bytes: [u8; 32] = hex::decode(display).unwrap().try_into().unwrap();
        let mut le_bytes = hash_bytes;
        le_bytes.reverse();
        let hash = bitcoin::BlockHash::from_byte_array(le_bytes);
        assert_eq!(
            template_prev_hash_stratum(&hash),
            "fa250a6457f3e80692fe1c38a66ea1d80d47e80c0001a0f90000000000000000"
        );
    }

    #[test]
    fn test_hash_to_share_difficulty() {
        // bytes_to_u256 reverses: be[i] = hash[31-i]
        // diff-1 target in BE: 00000000 FFFF0000 ...
        // So be[4]=0xFF → hash[27]=0xFF, be[5]=0xFF → hash[26]=0xFF
        let mut diff1_hash_le = [0u8; 32];
        diff1_hash_le[27] = 0xFF;
        diff1_hash_le[26] = 0xFF;
        let diff = hash_to_share_difficulty(&diff1_hash_le);
        assert!(
            (diff - 1.0).abs() < 0.01,
            "diff-1 hash should give difficulty ~1.0, got {diff}"
        );

        // Half the target value → difficulty ~2.0
        // BE: 00000000 7FFF8000 ...
        // be[4]=0x7F → hash[27]=0x7F, be[5]=0xFF → hash[26]=0xFF, be[6]=0x80 → hash[25]=0x80
        let mut half_hash = [0u8; 32];
        half_hash[27] = 0x7F;
        half_hash[26] = 0xFF;
        half_hash[25] = 0x80;
        let diff2 = hash_to_share_difficulty(&half_hash);
        assert!(
            (diff2 - 2.0).abs() < 0.1,
            "half-value hash should give difficulty ~2.0, got {diff2}"
        );
    }

    #[test]
    fn test_compact_target_to_difficulty() {
        let diff = compact_target_to_difficulty(0x1d00ffff);
        assert!((diff - 1.0).abs() < 1e-9, "difficulty 1 target => diff=1.0");

        let diff2 = compact_target_to_difficulty(0x1c00ffff);
        assert!((diff2 - 256.0).abs() < 1e-6, "one byte harder => diff≈256");
    }

    #[test]
    fn test_merkle_path_single_tx() {
        let path = compute_merkle_path(&[Txid::all_zeros()]);
        assert!(path.is_empty());
    }

    #[test]
    fn test_merkle_path_two_txs() {
        let t0 = Txid::all_zeros();
        let t1 = Txid::from_byte_array([1u8; 32]);
        let path = compute_merkle_path(&[t0, t1]);
        assert_eq!(path.len(), 1);
        assert_eq!(path[0], t1.to_byte_array());
    }

    #[test]
    fn test_merkle_path_four_txs() {
        let txids: Vec<Txid> = (0..4u8).map(|i| Txid::from_byte_array([i; 32])).collect();
        let path = compute_merkle_path(&txids);
        // depth = 2 ⇒ path has 2 siblings
        assert_eq!(path.len(), 2);
        // First sibling is txids[1]
        assert_eq!(path[0], txids[1].to_byte_array());
    }

    #[test]
    fn test_template_to_new_template() {
        let template = TemplateData {
            template_id: 42,
            prev_hash: BlockHash::all_zeros(),
            transactions: vec![],
            coinbase_value: 625_000_000,
            version: 0x20000000,
            bits: 0x1d00ffff,
            height: 840_001,
            merkle_path: vec![],
            coinbase_tag: vec![],
            pool_outputs: vec![],
            witness_commitment: None,
            min_time: 0,
        };
        let msg = template_to_new_template(&template);
        if let Sv2Message::NewTemplate {
            template_id,
            coinbase_tx_value_remaining,
            ..
        } = msg
        {
            assert_eq!(template_id, 42);
            assert_eq!(coinbase_tx_value_remaining, 625_000_000);
        } else {
            panic!("Expected NewTemplate");
        }
    }

    #[test]
    fn test_coinbase_tag_in_v1_job() {
        let tag = b"/BitcoinPR/".to_vec();
        let height: u32 = 840_001;
        let extranonce2_size: usize = 4;
        let extranonce1 = [0u8; 4];
        let output_script = vec![0x51u8]; // OP_TRUE

        let template = TemplateData {
            template_id: 7,
            prev_hash: BlockHash::all_zeros(),
            transactions: vec![],
            coinbase_value: 625_000_000,
            version: 0x20000000,
            bits: 0x207fffff,
            height,
            merkle_path: vec![],
            coinbase_tag: tag.clone(),
            pool_outputs: vec![],
            witness_commitment: None,
            min_time: 0,
        };

        let job = build_v1_job(&template, &extranonce1, extranonce2_size, &output_script);

        let height_script = encode_bip34_height(height);

        // cb1 layout: version(4) + input_count(1) + prevout_hash(32)
        //           + prevout_index(4) + scriptsig_len(1) + height_script + tag ...
        let header_len = 4 + 1 + 32 + 4;
        let scriptsig_len_byte = job.coinbase1[header_len];

        // The declared scriptSig length must account for height + tag + extranonces.
        let expected_len = height_script.len() + tag.len() + 4 + extranonce2_size;
        assert_eq!(scriptsig_len_byte as usize, expected_len);

        // The tag bytes must appear immediately after the encoded height.
        let tag_start = header_len + 1 + height_script.len();
        assert_eq!(
            &job.coinbase1[tag_start..tag_start + tag.len()],
            tag.as_slice()
        );
    }
}
