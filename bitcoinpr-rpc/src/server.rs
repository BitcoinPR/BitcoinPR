use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::{mpsc, RwLock};

use bitcoin::block::Version as BlockVersion;
use bitcoin::consensus::encode;
use bitcoin::hashes::Hash;
use bitcoin::{Address, Block, CompactTarget, Network, ScriptBuf, Transaction, TxMerkleNode};
use jsonrpsee::core::RpcResult;
use jsonrpsee::server::Server;
use jsonrpsee::types::ErrorObjectOwned;
use serde_json::{json, Value};
// `block_in_place` is used throughout the sync RPC methods to acquire async
// locks (`blocking_read`/`blocking_write`) and to fence CPU-heavy work. It
// PANICS on a `current_thread` tokio runtime — the RPC server therefore
// requires the multi-thread runtime (which `#[tokio::main]` in the binary
// provides). Keep that in mind when embedding this crate in tests.
use tokio::task::block_in_place;
use tracing::{info, warn};

use bitcoinpr_core::{
    compact_target_to_difficulty, get_median_time_past, ChainState, ConsensusParams, EventBus,
    Mempool, MempoolChainContext, NodeNotification, ScriptFlags, SigCache,
};
use bitcoinpr_p2p::{PeerCommand, PeerInfo};
use bitcoinpr_storage::{BlockStore, HeaderIndex, TxIndex, UtxoSet};

use crate::methods::BitcoinRpcServer;
use crate::types::*;
use bitcoinpr_p2p::{AddrNetwork, NetAddr};

/// Network reachability + advertised local addresses, for `getnetworkinfo`.
/// Built once from the merged proxy/onlynet config; `local_addresses` is a
/// shared handle the p2p / Tor layers update at runtime.
#[derive(Clone, Default)]
pub struct NetStatus {
    pub disable_ipv6: bool,
    pub ip_proxy: Option<String>,
    pub onion_proxy: Option<String>,
    pub proxy_randomize: bool,
    pub onlynet: std::collections::HashSet<AddrNetwork>,
    /// Whether a Tor hidden service has been established (inbound onion).
    pub onion_service: bool,
    /// Whether the I2P SAM transport is configured.
    pub i2p_enabled: bool,
    /// Addresses we advertise as our own (IP / onion / I2P), updated at runtime
    /// by the p2p / Tor layers. `std` lock so both sync and async callers write.
    pub local_addresses: Arc<std::sync::RwLock<Vec<NetAddr>>>,
}

impl NetStatus {
    fn onlynet_allows(&self, net: AddrNetwork) -> bool {
        self.onlynet.is_empty() || self.onlynet.contains(&net)
    }

    /// Build the `getnetworkinfo` `networks` array (one entry per family).
    fn networks_json(&self) -> Vec<serde_json::Value> {
        let entry = |name: &str, reachable: bool, proxy: &Option<String>| {
            serde_json::json!({
                "name": name,
                "limited": !reachable,
                "reachable": reachable,
                "proxy": proxy.clone().unwrap_or_default(),
                "proxy_randomize_credentials": proxy.is_some() && self.proxy_randomize,
            })
        };
        let onion_proxy = self.onion_proxy.clone().or_else(|| self.ip_proxy.clone());
        vec![
            entry(
                "ipv4",
                self.onlynet_allows(AddrNetwork::Ipv4),
                &self.ip_proxy,
            ),
            entry(
                "ipv6",
                !self.disable_ipv6 && self.onlynet_allows(AddrNetwork::Ipv6),
                &self.ip_proxy,
            ),
            entry(
                "onion",
                self.onlynet_allows(AddrNetwork::Onion)
                    && (onion_proxy.is_some() || self.onion_service),
                &onion_proxy,
            ),
            entry(
                "i2p",
                self.i2p_enabled && self.onlynet_allows(AddrNetwork::I2p),
                &None,
            ),
        ]
    }
}

/// Shared state accessible by RPC handlers.
pub struct RpcState {
    pub network: Network,
    pub params: ConsensusParams,
    pub header_index: Arc<HeaderIndex>,
    pub utxo_set: Option<Arc<UtxoSet>>,
    pub mempool: Arc<RwLock<Mempool>>,
    pub peers: Arc<RwLock<Vec<PeerInfo>>>,
    pub best_height: Arc<RwLock<u32>>,
    pub best_hash: Arc<RwLock<bitcoin::BlockHash>>,
    pub shutdown_tx: mpsc::Sender<()>,
    pub block_store: Option<Arc<BlockStore>>,
    pub tx_index: Option<Arc<TxIndex>>,
    /// RPC credentials for HTTP Basic auth, as raw `"user:password"`. The auth
    /// middleware base64-encodes this into the expected `Authorization` header.
    /// `None` disables authentication.
    pub auth_header: Option<String>,
    /// Server start time for uptime tracking.
    pub start_time: Instant,
    /// Signature verification cache shared with block validation (for mempool script checks).
    pub sig_cache: Arc<SigCache>,
    /// Chain state for block validation (needed for generatetoaddress/submitblock).
    pub chain_state: Option<Arc<tokio::sync::Mutex<ChainState>>>,
    /// Shared BIP-110 signaling checker (mainnet), used to evaluate the
    /// deployment state for mempool acceptance and `getblocktemplate` without
    /// locking the chain state. `None` for fixed-mode/unconfigured networks.
    pub bip110_checker: Option<Arc<bitcoinpr_core::Bip110Checker>>,
    /// Command channel to P2P layer (for broadcasting blocks).
    pub command_tx: Option<mpsc::Sender<PeerCommand>>,
    /// Atomic flag set on shutdown — checked by long-running loops.
    pub shutting_down: Arc<std::sync::atomic::AtomicBool>,
    /// Event bus for publishing node notifications (e.g. NewBlock to the Stratum template provider).
    pub event_bus: Option<Arc<EventBus>>,
    /// The node's IBD flag (gates P2P transaction acceptance in main.rs).
    /// `generate_to_address` clears it once a mined block lands on the header
    /// tip: a node that just RPC-mined to its own validated tip is by
    /// definition not in initial block download. The P2P drain/replay paths
    /// clear the flag for peer-synced nodes, but RPC mining is the only path
    /// that advances the tip without going through them — without this, a
    /// fresh node that only mines via RPC keeps rejecting relayed
    /// transactions until a periodic diagnostic tick clears the flag.
    pub is_ibd: Option<Arc<std::sync::atomic::AtomicBool>>,
    /// Current height of the scripthash (address) index, updated by the
    /// backfill task. `None` when `--index` is not enabled.
    pub scripthash_indexed_height: Option<Arc<std::sync::atomic::AtomicU32>>,
    /// Block-file prune target in bytes (`--prune <MiB>`); `None` when the
    /// node is not pruning. Drives `pruned`/`pruneheight` in
    /// `getblockchaininfo` and gates `pruneblockchain`.
    pub prune_target_bytes: Option<u64>,
    /// Network reachability + advertised local addresses for `getnetworkinfo`.
    pub net_status: NetStatus,
    /// Chain-split monitor (rival-branch tracking); drives
    /// `getchainsplitinfo`. `None` in test setups.
    pub split_monitor: Option<Arc<bitcoinpr_core::SplitMonitor>>,
}

/// The RPC server implementation.
pub struct RpcServer {
    state: Arc<RpcState>,
}

impl RpcServer {
    pub fn new(state: Arc<RpcState>) -> Self {
        RpcServer { state }
    }

    /// Start the HTTP JSON-RPC server.
    ///
    /// `health_bind` overrides where the plain-HTTP health endpoint listens
    /// (`--healthbind`). When `None`, it binds the RPC interface on
    /// `rpcport + 100` — the historical default that the docker-compose
    /// healthchecks rely on.
    pub async fn start(
        self,
        bind_addr: SocketAddr,
        health_bind: Option<SocketAddr>,
    ) -> anyhow::Result<()> {
        use crate::auth::AuthLayer;
        use jsonrpsee::server::BatchRequestConfig;

        // Enforce HTTP Basic auth at the HTTP layer (before method dispatch) so
        // every RPC method, including control-plane ones, requires credentials.
        let auth_layer = AuthLayer::new(self.state.auth_header.as_deref());
        let http_middleware = tower::ServiceBuilder::new().layer(auth_layer);

        let server = Server::builder()
            .set_batch_request_config(BatchRequestConfig::Limit(100))
            .set_http_middleware(http_middleware)
            .build(bind_addr)
            .await?;

        let addr = server.local_addr()?;
        info!(addr = %addr, "RPC server listening");

        // Spawn the plain-HTTP health check endpoint. Default: RPC interface on
        // RPC port + 100 (avoids P2P port conflicts); --healthbind overrides,
        // e.g. to pin it to 127.0.0.1 when RPC is bound to 0.0.0.0.
        let health_addr =
            health_bind.unwrap_or_else(|| (addr.ip(), addr.port().wrapping_add(100)).into());
        let health_state = self.state.clone();
        tokio::spawn(async move {
            match tokio::net::TcpListener::bind(health_addr).await {
                Ok(listener) => {
                    info!(addr = %health_addr, "Health check endpoint listening");
                    loop {
                        if let Ok((stream, _)) = listener.accept().await {
                            // One task per connection so a slow client can't
                            // stall the accept loop; the handler itself is
                            // bounded by read/write timeouts.
                            let state = health_state.clone();
                            tokio::spawn(handle_health_conn(stream, state));
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!(%health_addr, "Failed to bind health endpoint: {}", e);
                }
            }
        });

        let handle = server.start(self.into_rpc());

        // Run until stopped
        handle.stopped().await;

        Ok(())
    }
}

/// Serve one health-endpoint connection.
///
/// Slowloris guard: the client must deliver a complete (and small — ≤ 1 KiB)
/// HTTP request within 2 seconds before we compute or write anything; on
/// timeout, error, EOF, or an oversized request the connection is dropped
/// without a response. The response format is unchanged ("HTTP/1.1 200 OK"
/// status line + JSON body) — the docker-compose healthchecks grep for "OK".
async fn handle_health_conn(mut stream: tokio::net::TcpStream, state: Arc<RpcState>) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    const HEALTH_IO_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);

    let read_request = async {
        let mut buf = [0u8; 1024];
        let mut filled = 0usize;
        loop {
            if filled == buf.len() {
                return false; // request larger than any legitimate health probe
            }
            match stream.read(&mut buf[filled..]).await {
                Ok(0) | Err(_) => return false,
                Ok(n) => {
                    filled += n;
                    // Complete once the header terminator arrives (covers both
                    // "GET /health HTTP/1.0\r\n\r\n" probes and curl requests).
                    if buf[..filled].windows(4).any(|w| w == b"\r\n\r\n") {
                        return true;
                    }
                }
            }
        }
    };

    match tokio::time::timeout(HEALTH_IO_TIMEOUT, read_request).await {
        Ok(true) => {}
        // Timeout (slowloris), early close, read error, oversized: drop.
        _ => return,
    }

    let best_height = *state.best_height.read().await;
    let peers = state.peers.read().await.len();
    let uptime = state.start_time.elapsed().as_secs();
    let body = format!(
        "{{\"status\":\"ok\",\"height\":{best_height},\"peers\":{peers},\"uptime\":{uptime}}}"
    );
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        body
    );
    let _ = tokio::time::timeout(HEALTH_IO_TIMEOUT, stream.write_all(response.as_bytes())).await;
}

fn rpc_err(code: i32, msg: impl Into<String>) -> ErrorObjectOwned {
    ErrorObjectOwned::owned(code, msg.into(), None::<()>)
}

impl BitcoinRpcServer for RpcServer {
    fn get_blockchain_info(&self) -> RpcResult<Value> {
        let state = &self.state;
        let best_height = *block_in_place(|| state.best_height.blocking_read());
        let best_hash = *block_in_place(|| state.best_hash.blocking_read());

        let chain = match state.network {
            Network::Bitcoin => "main",
            Network::Testnet => "test",
            Network::Testnet4 => "testnet4",
            Network::Regtest => "regtest",
            Network::Signet => "signet",
        };

        let difficulty = state
            .header_index
            .get_header(&best_hash)
            .ok()
            .flatten()
            .map(|h| compact_target_to_difficulty(h.header.bits.to_consensus()))
            .unwrap_or(1.0);

        let header_tip_height = state
            .header_index
            .get_header_tip_height()
            .ok()
            .flatten()
            .unwrap_or(best_height);

        let verification_progress = if header_tip_height > 0 {
            (best_height as f64) / (header_tip_height as f64)
        } else {
            1.0
        };

        let is_ibd = best_height < header_tip_height;

        // Core semantics: `pruned` reflects prune *mode*; `pruneheight` (the
        // lowest-height complete block on disk) appears only when pruned.
        let pruned = self.state.prune_target_bytes.is_some();
        let pruneheight = if pruned {
            Some(
                state
                    .header_index
                    .get_pruned_height()
                    .ok()
                    .flatten()
                    .map(|h| h + 1)
                    .unwrap_or(0),
            )
        } else {
            None
        };

        let info = BlockchainInfo {
            chain: chain.to_string(),
            blocks: best_height,
            headers: header_tip_height,
            bestblockhash: best_hash.to_string(),
            difficulty,
            verification_progress,
            initialblockdownload: is_ibd,
            pruned,
            pruneheight,
            warnings: String::new(),
        };

        let mut value = serde_json::to_value(info).expect("serializes to JSON");
        // Report BIP-110 (RDTS) status under `softforks`. The deployment state is
        // evaluated for the tip (signaling-driven on mainnet, fixed-mode under the
        // override) so clients can query DEFINED/STARTED/LOCKED_IN/ACTIVE/EXPIRED.
        let bip110 = bitcoinpr_core::bip110_activation_at(
            &self.state.params,
            self.state.bip110_checker.as_deref(),
            &self.state.header_index,
            &best_hash,
            best_height,
        );
        let abandoned_at = self
            .state
            .header_index
            .get_bip110_abandoned()
            .ok()
            .flatten();
        let configured = self.state.params.bip110_activation_height.is_some()
            || self.state.params.bip110_deployment.is_some();
        if configured || abandoned_at.is_some() {
            use bitcoinpr_core::ThresholdState;
            // The persisted "abandon minority chain" decision overrides the
            // deployment state: enforcement is (or is about to be) disabled.
            let status = if abandoned_at.is_some() {
                "abandoned"
            } else {
                match bip110.state {
                    ThresholdState::Defined => "defined",
                    ThresholdState::Started => "started",
                    ThresholdState::LockedIn => "locked_in",
                    ThresholdState::Active => "active",
                    ThresholdState::Expired => "expired",
                }
            };
            if let Some(obj) = value.as_object_mut() {
                obj.insert(
                    "softforks".to_string(),
                    json!({
                        "bip110": {
                            "type": "bip9",
                            "active": bip110.enforcing() && abandoned_at.is_none(),
                            "height": bip110.activation_height,
                            "abandoned_at": abandoned_at,
                            "bip9": { "bit": 4, "status": status },
                        }
                    }),
                );
            }
        }

        Ok(value)
    }

    fn get_block(&self, blockhash: String, verbosity: Option<u8>) -> RpcResult<Value> {
        let hash: bitcoin::BlockHash = blockhash
            .parse()
            .map_err(|_| rpc_err(-8, "Invalid block hash"))?;

        let stored = self
            .state
            .header_index
            .get_header(&hash)
            .map_err(|e| rpc_err(-1, format!("Storage error: {e}")))?
            .ok_or_else(|| rpc_err(-5, "Block not found"))?;

        let verbosity = verbosity.unwrap_or(1);
        let best = *block_in_place(|| self.state.best_height.blocking_read());
        let confirmations = (best as i64) - (stored.height as i64) + 1;

        if verbosity == 0 {
            // Verbosity 0 returns the full serialized block (with witness), as
            // Bitcoin Core does. Returning just the 80-byte header makes the
            // result fail block decoding in other tools (e.g. submitblock).
            // The on-disk bytes are already the canonical serialization, so
            // return them directly rather than round-tripping through Block.
            let raw = self
                .state
                .block_store
                .as_ref()
                .and_then(|bs| {
                    self.state
                        .header_index
                        .get_block_pos(&hash)
                        .ok()
                        .flatten()
                        .and_then(|pos| bs.read_block(&pos).ok())
                })
                .ok_or_else(|| {
                    rpc_err(
                        -1,
                        "Block data not available (node may be pruned or header-only)",
                    )
                })?;
            return Ok(json!(hex::encode(raw)));
        }

        // Build base block info
        let mut result = json!({
            "hash": hash.to_string(),
            "confirmations": confirmations,
            "height": stored.height,
            "version": stored.header.version.to_consensus(),
            "versionHex": format!("{:08x}", stored.header.version.to_consensus()),
            "merkleroot": stored.header.merkle_root.to_string(),
            "time": stored.header.time,
            "nonce": stored.header.nonce,
            "bits": format!("{:x}", stored.header.bits.to_consensus()),
            "difficulty": compact_target_to_difficulty(stored.header.bits.to_consensus()),
        });

        if stored.height > 0 {
            result["previousblockhash"] = json!(stored.header.prev_blockhash.to_string());
        }

        // Try to load the full block from the block store for tx data
        let full_block = if let Some(ref block_store) = self.state.block_store {
            if let Ok(Some(pos)) = self.state.header_index.get_block_pos(&hash) {
                block_store
                    .read_block(&pos)
                    .ok()
                    .and_then(|raw| encode::deserialize::<Block>(&raw).ok())
            } else {
                None
            }
        } else {
            None
        };

        if let Some(ref block) = full_block {
            result["nTx"] = json!(block.txdata.len());
            result["size"] = json!(encode::serialize(block).len());
            result["weight"] = json!(block.weight().to_wu());

            if verbosity >= 2 {
                // Full decoded transactions
                let txs: Vec<Value> = block
                    .txdata
                    .iter()
                    .map(|tx| {
                        let txid = tx.compute_txid();
                        let raw = encode::serialize(tx);

                        let vin: Vec<Value> = tx.input.iter().map(|inp| {
                            if tx.is_coinbase() {
                                json!({ "coinbase": hex::encode(inp.script_sig.as_bytes()), "sequence": inp.sequence.0 })
                            } else {
                                json!({
                                    "txid": inp.previous_output.txid.to_string(),
                                    "vout": inp.previous_output.vout,
                                    "scriptSig": { "hex": hex::encode(inp.script_sig.as_bytes()) },
                                    "sequence": inp.sequence.0,
                                })
                            }
                        }).collect();

                        let vout: Vec<Value> = tx.output.iter().enumerate().map(|(i, out)| {
                            json!({
                                "value": out.value.to_sat() as f64 / 100_000_000.0,
                                "n": i,
                                "scriptPubKey": { "hex": hex::encode(out.script_pubkey.as_bytes()) },
                            })
                        }).collect();

                        json!({
                            "txid": txid.to_string(),
                            "hash": tx.compute_wtxid().to_string(),
                            "version": tx.version.0,
                            "size": raw.len(),
                            "weight": tx.weight().to_wu(),
                            "locktime": tx.lock_time.to_consensus_u32(),
                            "vin": vin,
                            "vout": vout,
                            "hex": hex::encode(&raw),
                        })
                    })
                    .collect();
                result["tx"] = json!(txs);
            } else {
                // verbosity=1: just txids
                let txids: Vec<String> = block
                    .txdata
                    .iter()
                    .map(|tx| tx.compute_txid().to_string())
                    .collect();
                result["tx"] = json!(txids);
            }
        } else {
            // No block data available
            result["nTx"] = json!(0);
            result["tx"] = json!([]);
        }

        Ok(result)
    }

    fn get_block_hash(&self, height: u32) -> RpcResult<Value> {
        let hash = self
            .state
            .header_index
            .get_hash_at_height(height)
            .map_err(|e| rpc_err(-1, format!("Storage error: {e}")))?
            .ok_or_else(|| rpc_err(-8, "Block height out of range"))?;

        Ok(json!(hash.to_string()))
    }

    fn get_block_count(&self) -> RpcResult<u32> {
        Ok(*block_in_place(|| self.state.best_height.blocking_read()))
    }

    fn get_difficulty(&self) -> RpcResult<f64> {
        let best_hash = *block_in_place(|| self.state.best_hash.blocking_read());
        let difficulty = self
            .state
            .header_index
            .get_header(&best_hash)
            .ok()
            .flatten()
            .map(|h| compact_target_to_difficulty(h.header.bits.to_consensus()))
            .unwrap_or(1.0);
        Ok(difficulty)
    }

    fn get_best_block_hash(&self) -> RpcResult<String> {
        Ok(block_in_place(|| self.state.best_hash.blocking_read()).to_string())
    }

    /// Chain-split monitor status: BIP-110 mode, the tracked rival branch
    /// (fork point, both tips, block/work deficit, capitulation arming), and
    /// whether the operator has abandoned BIP-110. `split` is `null` while
    /// no rival branch is tracked.
    fn get_chain_split_info(&self) -> RpcResult<Value> {
        let abandoned_at = self
            .state
            .header_index
            .get_bip110_abandoned()
            .map_err(|e| rpc_err(-32603, format!("storage error: {e}")))?;
        let mode = if abandoned_at.is_some() {
            "abandoned"
        } else if self.state.params.bip110_activation_height.is_some() {
            "fixed"
        } else if self.state.params.bip110_deployment.is_some() {
            "signaling"
        } else {
            "disabled"
        };
        let split = self
            .state
            .split_monitor
            .as_ref()
            .and_then(|m| block_in_place(|| m.snapshot()));
        Ok(serde_json::json!({
            "bip110": {
                "mode": mode,
                "activation_height": self.state.params.bip110_activation_height,
            },
            "split": split,
            "abandoned": abandoned_at.is_some(),
            "abandoned_at": abandoned_at,
            "threshold_blocks": bitcoinpr_core::CAPITULATION_THRESHOLD_BLOCKS,
        }))
    }

    /// Manual prune up to (at most) `height`. Core-compatible: requires the
    /// node to run in prune mode; returns the height of the last pruned
    /// block. The pruner's own safety window applies — the most recent 288
    /// blocks and anything above the last UTXO-flushed height are kept, so
    /// the effective ceiling may be lower than requested.
    fn prune_blockchain(&self, height: u32) -> RpcResult<u32> {
        if self.state.prune_target_bytes.is_none() {
            return Err(rpc_err(
                -1,
                "Cannot prune blocks because node is not in prune mode.",
            ));
        }
        let (Some(block_store), Some(utxo_set)) = (&self.state.block_store, &self.state.utxo_set)
        else {
            return Err(rpc_err(-1, "Block store unavailable"));
        };

        let tip = *block_in_place(|| self.state.best_height.blocking_read());
        let validated = self
            .state
            .header_index
            .get_validated_height()
            .ok()
            .flatten();
        let previously_pruned = self
            .state
            .header_index
            .get_pruned_height()
            .ok()
            .flatten()
            .unwrap_or(0);

        let Some(ceiling) = bitcoinpr_storage::prune_ceiling(tip, validated, Some(height)) else {
            return Ok(previously_pruned);
        };

        // target_bytes = 0: delete everything eligible below the ceiling.
        block_in_place(|| {
            bitcoinpr_storage::prune_block_files(
                block_store,
                &self.state.header_index,
                utxo_set,
                ceiling,
                0,
            )
        })
        .map_err(|e| rpc_err(-1, format!("prune failed: {e}")))?;

        Ok(self
            .state
            .header_index
            .get_pruned_height()
            .ok()
            .flatten()
            .unwrap_or(previously_pruned))
    }

    fn get_raw_transaction(&self, txid: String, verbose: Option<bool>) -> RpcResult<Value> {
        let txid: bitcoin::Txid = txid
            .parse()
            .map_err(|_| rpc_err(-8, "Invalid transaction ID"))?;

        // Check mempool first
        let mempool = block_in_place(|| self.state.mempool.blocking_read());
        if let Some(entry) = mempool.get(&txid) {
            let raw = encode::serialize(&entry.tx);
            return if verbose.unwrap_or(false) {
                Ok(json!({
                    "txid": txid.to_string(),
                    "size": entry.size,
                    "weight": entry.weight,
                    "fee": entry.fee as f64 / 100_000_000.0,
                    "hex": hex::encode(&raw),
                }))
            } else {
                Ok(json!(hex::encode(&raw)))
            };
        }
        drop(mempool);

        // Check tx index if available
        if let Some(ref tx_index) = self.state.tx_index {
            if let Some(idx_entry) = tx_index
                .get(&txid)
                .map_err(|e| rpc_err(-1, format!("TxIndex error: {e}")))?
            {
                let best_height = *block_in_place(|| self.state.best_height.blocking_read());
                let stored = self
                    .state
                    .header_index
                    .get_header(&idx_entry.block_hash)
                    .map_err(|e| rpc_err(-1, format!("Header error: {e}")))?;
                let confirmations = stored
                    .map(|h| best_height.saturating_sub(h.height) + 1)
                    .unwrap_or(0);

                return if verbose.unwrap_or(false) {
                    Ok(json!({
                        "txid": txid.to_string(),
                        "blockhash": idx_entry.block_hash.to_string(),
                        "confirmations": confirmations,
                        "blockindex": idx_entry.tx_pos,
                    }))
                } else {
                    // Without block store lookup, return the txid location info
                    Ok(json!({
                        "txid": txid.to_string(),
                        "blockhash": idx_entry.block_hash.to_string(),
                    }))
                };
            }
        }

        Err(rpc_err(
            -5,
            "No such mempool or blockchain transaction. Use -txindex to enable blockchain transaction queries.",
        ))
    }

    fn send_raw_transaction(&self, hexstring: String) -> RpcResult<String> {
        let raw_bytes =
            hex::decode(&hexstring).map_err(|_| rpc_err(-22, "TX decode failed: invalid hex"))?;

        let tx: Transaction = encode::deserialize(&raw_bytes)
            .map_err(|e| rpc_err(-22, format!("TX decode failed: {e}")))?;

        let txid = tx.compute_txid();

        // Validate and add to mempool
        let mut mempool = block_in_place(|| self.state.mempool.blocking_write());

        if mempool.contains(&txid) {
            return Ok(txid.to_string());
        }

        if let Some(ref utxo_set) = self.state.utxo_set {
            let flags = ScriptFlags::all();
            // Finality/sequence-lock context: the tx must be valid in the next
            // block (tip height + 1, tip MTP).
            let tip_height = *block_in_place(|| self.state.best_height.blocking_read());
            let tip_hash = *block_in_place(|| self.state.best_hash.blocking_read());
            // BIP-110 deployment state for the next block (uses the shared signaling
            // checker; no chain-state lock, avoiding lock-order issues with the
            // mempool write lock already held above).
            let bip110 = bitcoinpr_core::bip110_activation_at(
                &self.state.params,
                self.state.bip110_checker.as_deref(),
                &self.state.header_index,
                &tip_hash,
                tip_height + 1,
            );
            let chain_ctx =
                MempoolChainContext::at_tip(&self.state.header_index, tip_height, &tip_hash)
                    .with_bip110(bip110);
            // M2 (2026-07-02 review): signature verification happens inside
            // add_transaction — fence it with block_in_place so other tasks
            // queued on this worker migrate instead of stalling behind it.
            match block_in_place(|| {
                mempool.add_transaction(
                    tx.clone(),
                    utxo_set,
                    flags,
                    &self.state.params,
                    Some(self.state.sig_cache.as_ref()),
                    &chain_ctx,
                )
            }) {
                Ok(_) => {
                    // Broadcast to P2P peers
                    if let Some(ref cmd_tx) = self.state.command_tx {
                        let _ = cmd_tx.try_send(PeerCommand::BroadcastTx(tx));
                    }
                    Ok(txid.to_string())
                }
                Err(e) => Err(rpc_err(-26, format!("Transaction rejected: {e}"))),
            }
        } else {
            Err(rpc_err(-1, "UTXO set not available"))
        }
    }

    fn decode_raw_transaction(&self, hexstring: String) -> RpcResult<Value> {
        let raw_bytes =
            hex::decode(&hexstring).map_err(|_| rpc_err(-22, "TX decode failed: invalid hex"))?;

        let tx: Transaction = encode::deserialize(&raw_bytes)
            .map_err(|e| rpc_err(-22, format!("TX decode failed: {e}")))?;

        let txid = tx.compute_txid();

        let inputs: Vec<Value> = tx
            .input
            .iter()
            .map(|inp| {
                json!({
                    "txid": inp.previous_output.txid.to_string(),
                    "vout": inp.previous_output.vout,
                    "sequence": inp.sequence.0,
                })
            })
            .collect();

        let outputs: Vec<Value> = tx
            .output
            .iter()
            .enumerate()
            .map(|(n, out)| {
                json!({
                    "value": out.value.to_sat() as f64 / 100_000_000.0,
                    "n": n,
                    "scriptPubKey": {
                        "hex": hex::encode(out.script_pubkey.as_bytes()),
                    }
                })
            })
            .collect();

        Ok(json!({
            "txid": txid.to_string(),
            "version": tx.version.0,
            "locktime": tx.lock_time.to_consensus_u32(),
            "vin": inputs,
            "vout": outputs,
            "size": raw_bytes.len(),
            "weight": tx.weight().to_wu(),
        }))
    }

    fn get_tx_out(&self, txid: String, n: u32, _include_mempool: Option<bool>) -> RpcResult<Value> {
        let txid_parsed: bitcoin::Txid = txid
            .parse()
            .map_err(|_| rpc_err(-8, "Invalid transaction ID"))?;

        let outpoint = bitcoin::OutPoint::new(txid_parsed, n);

        if let Some(ref utxo_set) = self.state.utxo_set {
            match utxo_set
                .get(&outpoint)
                .map_err(|e| rpc_err(-1, format!("Storage error: {e}")))?
            {
                Some(entry) => {
                    let best_height = *block_in_place(|| self.state.best_height.blocking_read());
                    Ok(json!({
                        "bestblock": block_in_place(|| self.state.best_hash.blocking_read()).to_string(),
                        "confirmations": best_height.saturating_sub(entry.height) + 1,
                        "value": entry.amount as f64 / 100_000_000.0,
                        "scriptPubKey": {
                            "hex": hex::encode(&entry.script_pubkey),
                        },
                        "coinbase": entry.is_coinbase,
                    }))
                }
                None => Ok(Value::Null),
            }
        } else {
            Err(rpc_err(-1, "UTXO set not available"))
        }
    }

    fn get_mempool_info(&self) -> RpcResult<Value> {
        let mempool = block_in_place(|| self.state.mempool.blocking_read());
        let info = MempoolInfo {
            loaded: true,
            size: mempool.size(),
            bytes: mempool.total_bytes(),
            usage: mempool.memory_usage(),
            total_fee: mempool.total_fees() as f64 / 100_000_000.0,
        };
        Ok(serde_json::to_value(info).expect("serializes to JSON"))
    }

    fn get_raw_mempool(&self) -> RpcResult<Vec<String>> {
        let mempool = block_in_place(|| self.state.mempool.blocking_read());
        Ok(mempool
            .all_txids()
            .iter()
            .map(|id| id.to_string())
            .collect())
    }

    fn get_network_info(&self) -> RpcResult<Value> {
        let peers = block_in_place(|| self.state.peers.blocking_read());
        let inbound = peers.iter().filter(|p| p.inbound).count();
        let local_addresses: Vec<Value> = self
            .state
            .net_status
            .local_addresses
            .read()
            .map(|addrs| {
                addrs
                    .iter()
                    .map(|a| {
                        serde_json::json!({
                            "address": a.to_string(),
                            "port": a.port(),
                            "score": 1,
                        })
                    })
                    .collect()
            })
            .unwrap_or_default();
        let info = NetworkInfo {
            version: 270000,
            subversion: concat!("/bitcoinpr:", env!("CARGO_PKG_VERSION"), "/").to_string(),
            protocol_version: 70016,
            connections: peers.len(),
            connections_in: inbound,
            connections_out: peers.len() - inbound,
            timeoffset: bitcoinpr_core::time::time_offset_secs(),
            networks: self.state.net_status.networks_json(),
            local_addresses,
            warnings: String::new(),
        };
        Ok(serde_json::to_value(info).expect("serializes to JSON"))
    }

    fn get_peer_info(&self) -> RpcResult<Value> {
        let peers = block_in_place(|| self.state.peers.blocking_read());
        let entries: Vec<PeerInfoEntry> = peers
            .iter()
            .map(|p| PeerInfoEntry {
                id: p.id,
                addr: p.addr.to_string(),
                network: p.addr.network().as_str().to_string(),
                version: p.version,
                subver: p.user_agent.clone(),
                startingheight: p.start_height,
                // Best height we've seen this peer announce (headers or block
                // inv), seeded with its version start_height. We don't track
                // headers and blocks separately, so both fields report it.
                synced_headers: p.synced_height,
                synced_blocks: p.synced_height,
                inbound: p.inbound,
            })
            .collect();
        Ok(serde_json::to_value(entries).expect("serializes to JSON"))
    }

    fn get_connection_count(&self) -> RpcResult<usize> {
        Ok(block_in_place(|| self.state.peers.blocking_read()).len())
    }

    fn validate_address(&self, address: String) -> RpcResult<Value> {
        use std::str::FromStr;

        match Address::from_str(&address).map(|addr| addr.require_network(self.state.network)) {
            Ok(Ok(checked)) => {
                let script = checked.script_pubkey();
                // BIP 350 (bech32m): surface scriptPubKey and, for witness
                // outputs, the witness version + program so callers can tell
                // v0 (bech32) from v1+ taproot (bech32m) addresses apart.
                let mut result = json!({
                    "isvalid": true,
                    "address": address,
                    "scriptPubKey": hex::encode(script.to_bytes()),
                    "isscript": script.is_p2sh(),
                    "iswitness": script.is_witness_program(),
                });
                if let Some(version) = script.witness_version() {
                    result["witness_version"] = json!(version.to_num());
                    // Witness program follows the version byte and its
                    // single-byte length push: scriptPubKey[2..].
                    let bytes = script.as_bytes();
                    if bytes.len() > 2 {
                        result["witness_program"] = json!(hex::encode(&bytes[2..]));
                    }
                }
                Ok(result)
            }
            // Parse failure or wrong-network address: both are just "invalid".
            Ok(Err(_)) | Err(_) => Ok(json!({
                "isvalid": false,
                "address": address,
            })),
        }
    }

    fn estimate_smart_fee(&self, conf_target: u32) -> RpcResult<Value> {
        // Simple fee estimation based on mempool state
        let mempool = block_in_place(|| self.state.mempool.blocking_read());
        let _best_height = *block_in_place(|| self.state.best_height.blocking_read());

        if mempool.size() == 0 {
            // No mempool data — return a conservative minimum relay fee
            return Ok(json!({
                "feerate": 0.00001000, // 1 sat/vB in BTC/kB
                "blocks": conf_target,
            }));
        }

        // Collect fee rates from all mempool entries
        let total_fee = mempool.total_fees();
        let total_bytes = mempool.total_bytes().max(1);
        let avg_fee_rate_sat_vb = total_fee as f64 / total_bytes as f64;

        // Scale by confirmation target (lower target = higher fee)
        let multiplier = match conf_target {
            1 => 2.0,
            2 => 1.5,
            3..=6 => 1.2,
            7..=12 => 1.0,
            13..=25 => 0.8,
            _ => 0.5,
        };

        // Convert sat/vB to BTC/kB (1 kB = 1000 vB)
        let fee_rate_btc_kb = avg_fee_rate_sat_vb * multiplier * 1000.0 / 100_000_000.0;

        // Minimum relay fee: 1 sat/vB = 0.00001 BTC/kB
        let fee_rate = fee_rate_btc_kb.max(0.00001);

        Ok(json!({
            "feerate": fee_rate,
            "blocks": conf_target,
        }))
    }

    fn get_block_template(&self, request: Option<Value>) -> RpcResult<Value> {
        let best_height = *block_in_place(|| self.state.best_height.blocking_read());
        let best_hash = *block_in_place(|| self.state.best_hash.blocking_read());
        let next_height = best_height + 1;

        // BIP 23 (proposal mode): validate a candidate block structurally without
        // committing it to the chain. Returns Null when acceptable, otherwise a
        // short reject-reason string.
        if let Some(ref req) = request {
            if req.get("mode").and_then(|m| m.as_str()) == Some("proposal") {
                let data = req
                    .get("data")
                    .and_then(|d| d.as_str())
                    .ok_or_else(|| rpc_err(-22, "Missing block data in proposal"))?;
                let raw = hex::decode(data)
                    .map_err(|_| rpc_err(-22, "Block decode failed: invalid hex"))?;
                let block: Block = match encode::deserialize(&raw) {
                    Ok(b) => b,
                    Err(_) => return Ok(json!("bad-block-decode")),
                };

                // Must build on the current best tip.
                if block.header.prev_blockhash != best_hash {
                    return Ok(json!("inconclusive-not-best-prevblk"));
                }
                // First tx must be a coinbase.
                if !block.txdata.first().is_some_and(|tx| tx.is_coinbase()) {
                    return Ok(json!("bad-cb-missing"));
                }
                // Merkle root must commit to the supplied tx set.
                match block.compute_merkle_root() {
                    Some(root) if root == block.header.merkle_root => {}
                    _ => return Ok(json!("bad-txnmrklroot")),
                }
                // Proof-of-work must satisfy the header's own target.
                if block.header.validate_pow(block.header.target()).is_err() {
                    return Ok(json!("high-hash"));
                }
                // Structural proposal check only — do NOT connect the block.
                return Ok(Value::Null);
            }
        }

        let mempool = block_in_place(|| self.state.mempool.blocking_read());

        // Collect mempool transactions for the template. select_for_block
        // skips txs that are not final at the template height (nLockTime /
        // BIP 68 — a block carrying one would be rejected by connect_block),
        // orders parents before children, and stays within the weight budget.
        let tip_mtp = get_median_time_past(&self.state.header_index, &best_hash).unwrap_or(0);
        let reserved_weight: u64 = 4000; // coinbase + headroom
        let available_weight = self
            .state
            .params
            .max_block_weight
            .saturating_sub(reserved_weight as u32) as u64;

        let mut transactions = Vec::new();
        let mut total_fees = 0u64;
        // wtxids of the included (non-coinbase) txs, for the witness commitment.
        let mut wtxids: Vec<[u8; 32]> = Vec::new();

        for me in mempool.select_for_block(next_height, tip_mtp, available_weight, 4000) {
            let raw = encode::serialize(&me.tx);
            transactions.push(json!({
                "data": hex::encode(&raw),
                "txid": me.txid.to_string(),
                "fee": me.fee,
                "weight": me.weight,
            }));
            total_fees += me.fee;
            wtxids.push(*me.tx.compute_wtxid().as_ref());
        }
        let mempool_tx_count = transactions.len();

        let subsidy = self.state.params.block_subsidy(next_height);
        let coinbase_value = subsidy + total_fees;

        // Compute target bits from the tip header
        let tip_header = self
            .state
            .header_index
            .get_header(&best_hash)
            .map_err(|e| rpc_err(-1, format!("Storage error: {e}")))?;
        let bits = tip_header
            .map(|h| format!("{:x}", h.header.bits.to_consensus()))
            .unwrap_or_default();

        // Activated soft-fork rules at the next height. With buried deployments
        // (BIP 90) these are derived directly from height, not BIP 9 state.
        // Segwit is reported with a leading '!' to mark it as mandatory.
        let mut rules: Vec<&str> = Vec::new();
        if self.state.params.deployment_active("csv", next_height) {
            rules.push("csv");
        }
        if self.state.params.deployment_active("segwit", next_height) {
            rules.push("!segwit");
        }
        if self.state.params.deployment_active("taproot", next_height) {
            rules.push("taproot");
        }
        // BIP-110 (RDTS): once ACTIVE, advertise it as a rule so miners commit to
        // it; while STARTED/LOCKED_IN, signal availability on bit 4.
        let bip110 = bitcoinpr_core::bip110_activation_at(
            &self.state.params,
            self.state.bip110_checker.as_deref(),
            &self.state.header_index,
            &best_hash,
            next_height,
        );
        let bip110_signaling = matches!(
            bip110.state,
            bitcoinpr_core::ThresholdState::Started | bitcoinpr_core::ThresholdState::LockedIn
        );
        if bip110.enforcing() {
            rules.push("bip110");
        }
        let mut vbavailable = serde_json::Map::new();
        let mut gbt_version = 0x20000000u32;
        if bip110_signaling {
            gbt_version |= 1 << 4;
            vbavailable.insert("bip110".to_string(), json!(4));
        }

        // BIP 141 default_witness_commitment: scriptPubKey a miner must add to
        // the coinbase when segwit is active.
        let default_witness_commitment = hex::encode(witness_commitment_script(&wtxids));

        // longpollid represents template freshness: tip hash + mempool tx count.
        // This minimal implementation never blocks; if a longpollid is supplied
        // we simply return a fresh template immediately (true blocking long-poll
        // is out of scope).
        let longpollid = format!("{best_hash}{mempool_tx_count}");

        Ok(json!({
            "version": gbt_version,
            "rules": rules,
            // Historical deployments are buried (BIP 90); only BIP-110 signals here.
            "vbavailable": vbavailable,
            "vbrequired": 0,
            "capabilities": ["proposal"],
            "longpollid": longpollid,
            "previousblockhash": best_hash.to_string(),
            "transactions": transactions,
            "default_witness_commitment": default_witness_commitment,
            "coinbasevalue": coinbase_value,
            "height": next_height,
            "bits": bits,
            "curtime": std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system clock is after the Unix epoch")
                .as_secs(),
            "mintime": get_median_time_past(&self.state.header_index, &best_hash)
                .map(|mtp| mtp + 1)
                .unwrap_or(0),
            "mutable": ["time", "transactions", "prevblock"],
            "noncerange": "00000000ffffffff",
            "sigoplimit": 80000,
            "sizelimit": 4000000,
            "weightlimit": 4000000,
        }))
    }

    fn submit_block(&self, hexdata: String) -> RpcResult<Value> {
        let raw =
            hex::decode(&hexdata).map_err(|_| rpc_err(-22, "Block decode failed: invalid hex"))?;

        let block: Block = encode::deserialize(&raw)
            .map_err(|e| rpc_err(-22, format!("Block decode failed: {e}")))?;

        let chain_state = self
            .state
            .chain_state
            .as_ref()
            .ok_or_else(|| rpc_err(-1, "Chain state not available"))?;

        let mut cs = block_in_place(|| chain_state.blocking_lock());
        let expected_height = cs.best_height + 1;
        let block_hash = block.block_hash();

        cs.connect_block(&block, expected_height)
            .map_err(|e| rpc_err(-1, format!("Block validation failed: {e}")))?;

        // Update RpcState best_height/best_hash
        *block_in_place(|| self.state.best_height.blocking_write()) = expected_height;
        *block_in_place(|| self.state.best_hash.blocking_write()) = block_hash;

        // Broadcast to peers if command channel available
        if let Some(ref cmd_tx) = self.state.command_tx {
            let _ = block_in_place(|| {
                cmd_tx.blocking_send(PeerCommand::BroadcastBlock(block, expected_height))
            });
        }

        Ok(Value::Null) // null means accepted in Bitcoin Core
    }

    fn get_mining_info(&self) -> RpcResult<Value> {
        let best_height = *block_in_place(|| self.state.best_height.blocking_read());
        let best_hash = *block_in_place(|| self.state.best_hash.blocking_read());

        let difficulty = self
            .state
            .header_index
            .get_header(&best_hash)
            .ok()
            .flatten()
            .map(|h| compact_target_to_difficulty(h.header.bits.to_consensus()))
            .unwrap_or(1.0);

        // Rough network hashrate estimate: difficulty * 2^32 / 600
        let networkhashps = difficulty * 4_294_967_296.0 / 600.0;

        let chain = match self.state.network {
            Network::Bitcoin => "main",
            Network::Testnet => "test",
            Network::Testnet4 => "testnet4",
            Network::Regtest => "regtest",
            Network::Signet => "signet",
        };

        Ok(json!({
            "blocks": best_height,
            "difficulty": difficulty,
            "networkhashps": networkhashps,
            "chain": chain,
        }))
    }

    fn generate_to_address(&self, nblocks: u32, address: String) -> RpcResult<Vec<String>> {
        let chain_state = self
            .state
            .chain_state
            .as_ref()
            .ok_or_else(|| rpc_err(-1, "Chain state not available"))?;

        // Parse the address to get the scriptPubKey for the coinbase output
        let unchecked: Address<bitcoin::address::NetworkUnchecked> = address
            .parse()
            .map_err(|e| rpc_err(-5, format!("Invalid address: {e}")))?;
        let script_pubkey = unchecked.assume_checked().script_pubkey();

        let mut block_hashes = Vec::with_capacity(nblocks as usize);

        // Seed a per-call nonce from wall-clock nanoseconds so that coinbases
        // produced in different process runs never share a txid, even when the
        // same address is reused on a freshly-reset chain.
        let nonce_base = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;

        for block_idx in 0..nblocks {
            let mut cs = block_in_place(|| chain_state.blocking_lock());
            let height = cs.best_height + 1;
            let prev_hash = cs.best_hash;
            let subsidy = cs.params.block_subsidy(height);

            // Get bits from the previous block header
            let bits = cs
                .header_index
                .get_header(&prev_hash)
                .map_err(|e| rpc_err(-1, format!("Storage error: {e}")))?
                .map(|h| h.header.bits)
                .unwrap_or(CompactTarget::from_consensus(0x207fffff)); // regtest default

            // Select mempool transactions (greedy, within the consensus weight
            // budget) so that generatetoaddress confirms pending transactions
            // instead of producing empty blocks. The Stratum template path
            // (build_template) does the same; without this, a tx broadcast to the
            // mempool is never mined when the chain is advanced via RPC.
            // select_for_block also skips txs that are not final at this height
            // (nLockTime / BIP 68) and orders parents before children, so the
            // block we assemble always passes our own connect_block.
            let reserved_weight: u32 = 4000; // coinbase + headroom
            let available_weight =
                cs.params.max_block_weight.saturating_sub(reserved_weight) as u64;
            let tip_mtp = get_median_time_past(&cs.header_index, &prev_hash).unwrap_or(0);
            let mut mempool_txs: Vec<bitcoin::Transaction> = Vec::new();
            let mut selected_fees: u64 = 0;
            {
                let mempool = block_in_place(|| self.state.mempool.blocking_read());
                for entry in mempool.select_for_block(height, tip_mtp, available_weight, 4000) {
                    selected_fees += entry.fee;
                    mempool_txs.push(entry.tx.clone());
                }
            }

            // Build coinbase transaction — unique per run and per block via nonce.
            // The coinbase claims the subsidy plus the fees of the selected txs.
            let extra_nonce = nonce_base.wrapping_add(block_idx as u64);
            let coinbase_tx =
                build_coinbase_tx(height, subsidy + selected_fees, &script_pubkey, extra_nonce);

            // Block = coinbase followed by the selected mempool transactions.
            let mut txdata = vec![coinbase_tx];
            txdata.extend(mempool_txs);

            // BIP 141: if any selected transaction carries witness data, the
            // coinbase must include the witness commitment output. The validator
            // defaults the witness reserved value to 32 zero bytes when the
            // coinbase witness is empty, which matches the reserved value used by
            // witness_commitment_script — so we only need to add the output.
            let has_witness = txdata
                .iter()
                .skip(1)
                .any(|tx| tx.input.iter().any(|i| !i.witness.is_empty()));
            if has_witness {
                let wtxids: Vec<[u8; 32]> = txdata
                    .iter()
                    .skip(1)
                    .map(|tx| *tx.compute_wtxid().as_ref())
                    .collect();
                txdata[0].output.push(bitcoin::TxOut {
                    value: bitcoin::Amount::from_sat(0),
                    script_pubkey: ScriptBuf::from_bytes(witness_commitment_script(&wtxids)),
                });
                // BIP 141: the coinbase input must carry the 32-byte witness
                // reserved value. Without it the block serializes as an invalid
                // SegWit block and strict peers (Bitcoin Core/Knots) reject it as
                // a "mutated block". The all-zero reserved value matches the
                // commitment computed by witness_commitment_script above.
                let mut cb_witness = bitcoin::Witness::new();
                cb_witness.push([0u8; 32]);
                txdata[0].input[0].witness = cb_witness;
            }

            // Compute merkle root
            let tx_hashes: Vec<bitcoin::Txid> = txdata.iter().map(|tx| tx.compute_txid()).collect();
            let merkle_root = bitcoinpr_core::compute_merkle_root(&tx_hashes)
                .unwrap_or(TxMerkleNode::all_zeros());

            // Block timestamp must be strictly greater than the Median Time Past (MTP)
            // of the previous block(s). MTP = median of last ≤11 ancestor timestamps.
            // For rapid `generatetoaddress` calls, all blocks may get the same
            // wall-clock second, causing "time-too-old" on Bitcoin Core. We always
            // use max(now, prev_time + 1) to guarantee a strictly increasing sequence.
            let prev_time = cs
                .header_index
                .get_header(&prev_hash)
                .ok()
                .flatten()
                .map(|h| h.header.time)
                .unwrap_or(0);
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system clock is after the Unix epoch")
                .as_secs() as u32;
            let time = now.max(prev_time + 1);

            // Mine: find a nonce that meets the target
            // For regtest, the target is extremely easy (0x7fffffff...) so nonce=0 almost always works
            let mut header = bitcoin::block::Header {
                version: BlockVersion::from_consensus(0x20000000),
                prev_blockhash: prev_hash,
                merkle_root,
                time,
                bits,
                nonce: 0,
            };

            // Mine the block (increment nonce until hash meets target)
            let target = header.target();
            loop {
                let hash = header.block_hash();
                // block_hash is a double-SHA256 interpreted as a little-endian number.
                // It meets the target if hash <= target (comparing as 256-bit LE).
                if hash_meets_target(&hash, &target) {
                    break;
                }
                header.nonce = header.nonce.wrapping_add(1);
                if header.nonce == 0 {
                    // Exhausted nonce space, bump time
                    header.time += 1;
                }
            }

            let block = Block { header, txdata };
            let block_hash = block.block_hash();

            // Store the header in the index first (connect_block expects it)
            let block_work = bitcoinpr_core::calculate_work(&header.target());
            let prev_work = cs
                .header_index
                .get_header(&prev_hash)
                .map_err(|e| rpc_err(-1, format!("Storage error: {e}")))?
                .map(|h| h.chain_work)
                .unwrap_or([0u8; 32]);
            let chain_work = bitcoinpr_core::add_chain_work(&prev_work, &block_work);

            let stored_header = bitcoinpr_storage::StoredHeader {
                header,
                height,
                chain_work,
            };
            cs.header_index
                .insert_header(&block_hash, &stored_header)
                .map_err(|e| rpc_err(-1, format!("Storage error: {e}")))?;

            // Connect the block
            match cs.connect_block(&block, height) {
                Ok(()) => {
                    // Keep META_HEADER_TIP_HEIGHT in sync ONLY after the block
                    // actually connects, so that:
                    //   1. getblockchaininfo returns the correct `headers` value, and
                    //   2. after restart, header_sync starts from the real chain tip
                    //      instead of the last peer-synced height.
                    // Doing this before connect_block would advance the header tip
                    // past the validated block tip on a connect failure, leaving
                    // headers > blocks and pinning the node in a false IBD state.
                    // (The P2P handler's NodeEvent::Headers path also calls this, but
                    //  it only fires when peers echo blocks back — which they don't
                    //  when WE are the one broadcasting the block.)
                    cs.header_index
                        .set_header_tip(&block_hash, height)
                        .map_err(|e| rpc_err(-1, format!("Storage error: {e}")))?;

                    // Block tip == header tip by construction here, so the
                    // node is not in IBD — clear the flag that gates P2P tx
                    // acceptance (see the field doc on RpcState::is_ibd; a
                    // fresh chain advanced only by RPC mining otherwise stays
                    // "in IBD" and drops relayed txs until a diagnostic tick).
                    if let Some(ref ibd) = self.state.is_ibd {
                        if ibd.swap(false, std::sync::atomic::Ordering::Relaxed) {
                            info!(height, "IBD clear — RPC-mined block reached the header tip");
                        }
                    }

                    info!(height, hash = %block_hash, "Generated block");
                    block_hashes.push(block_hash.to_string());

                    // Evict the transactions just confirmed by this block from the
                    // mempool. generatetoaddress connects the block directly (not
                    // via the P2P drain loop that normally calls remove_for_block),
                    // so without this the mined txs would linger in the mempool and
                    // the next template would try to re-include already-spent inputs.
                    block_in_place(|| self.state.mempool.blocking_write()).remove_for_block(&block);

                    // Update RpcState best_height/best_hash so getblockcount etc. reflect the new tip
                    *block_in_place(|| self.state.best_height.blocking_write()) = height;
                    *block_in_place(|| self.state.best_hash.blocking_write()) = block_hash;

                    // Broadcast to peers
                    if let Some(ref cmd_tx) = self.state.command_tx {
                        let _ = block_in_place(|| {
                            cmd_tx.blocking_send(PeerCommand::BroadcastBlock(block, height))
                        });
                    }

                    // Notify the event bus so the Stratum template provider (and
                    // other subscribers) learn about the new tip and re-issue jobs.
                    if let Some(ref bus) = self.state.event_bus {
                        bus.publish(NodeNotification::NewBlock {
                            hash: block_hash.to_string(),
                            height,
                        });
                    }
                }
                Err(e) => {
                    warn!(height, error = %e, "Failed to connect generated block");
                    return Err(rpc_err(-1, format!("Block connection failed: {e}")));
                }
            }
        }

        Ok(block_hashes)
    }

    /// Durably mark a block invalid, as if it failed consensus validation
    /// (Bitcoin Core parity, backed by the same marker machinery the
    /// BIP-110 split monitor uses). If the block is on the active validated
    /// chain, every block from the tip down to it is disconnected and the
    /// header tip resets to its parent; the node then follows the next-best
    /// untainted chain. Fork choice never re-adopts the marked branch until
    /// `reconsiderblock`. Limitation: disconnected transactions are not
    /// returned to the mempool.
    fn invalidate_block(&self, blockhash: String) -> RpcResult<Value> {
        let hash: bitcoin::BlockHash = blockhash
            .parse()
            .map_err(|_| rpc_err(-8, "Invalid block hash"))?;
        let stored = self
            .state
            .header_index
            .get_header(&hash)
            .map_err(|e| rpc_err(-1, format!("Storage error: {e}")))?
            .ok_or_else(|| rpc_err(-5, "Block not found"))?;
        if stored.height == 0 {
            return Err(rpc_err(-8, "Cannot invalidate the genesis block"));
        }

        self.state
            .header_index
            .mark_invalid(
                &hash,
                stored.height,
                bitcoinpr_storage::INVALID_REASON_MANUAL,
            )
            .map_err(|e| rpc_err(-1, format!("Failed to persist marker: {e}")))?;
        if let Some(monitor) = &self.state.split_monitor {
            monitor.on_invalid_marked(hash, stored.height);
        }

        // If the block is on the ACTIVE validated chain, disconnect back to
        // its parent (Core semantics). Side-branch blocks only get the mark.
        let mut disconnected = 0u32;
        let (mut tip_height, mut tip_hash) = (None, None);
        if let Some(cs_arc) = &self.state.chain_state {
            let header_index = self.state.header_index.clone();
            let result: Result<(), String> = block_in_place(|| {
                let mut cs = cs_arc.blocking_lock();
                let on_active = cs.best_height >= stored.height
                    && header_index
                        .get_hash_at_height(stored.height)
                        .ok()
                        .flatten()
                        == Some(hash);
                if on_active {
                    while cs.best_height >= stored.height {
                        let bh = cs.best_hash;
                        let h = cs.best_height;
                        let pos = header_index
                            .get_block_pos(&bh)
                            .map_err(|e| format!("block position for {bh}: {e}"))?
                            .ok_or_else(|| format!("no block data for {bh} (pruned?)"))?;
                        let raw = cs
                            .block_store
                            .read_block(&pos)
                            .map_err(|e| format!("read block {bh}: {e}"))?;
                        let block: bitcoin::Block =
                            bitcoin::consensus::encode::deserialize(&raw)
                                .map_err(|e| format!("decode block {bh}: {e}"))?;
                        cs.disconnect_block(&block, h)
                            .map_err(|e| format!("disconnect {bh} at {h}: {e}"))?;
                        disconnected += 1;
                    }
                    cs.utxo_set
                        .flush_to_disk()
                        .map_err(|e| format!("UTXO flush: {e}"))?;
                    // Reset the header view to the new tip; the node loop's
                    // invalid-ancestor guard finishes reconciling its own
                    // header-sync state on the next headers event.
                    let _ = header_index.restore_branch_height_index(&cs.best_hash);
                    let _ = header_index.reset_fork_header_tip(cs.best_height, &cs.best_hash);
                    *self.state.best_height.blocking_write() = cs.best_height;
                    *self.state.best_hash.blocking_write() = cs.best_hash;
                }
                tip_height = Some(cs.best_height);
                tip_hash = Some(cs.best_hash);
                Ok(())
            });
            result.map_err(|e| {
                rpc_err(
                    -1,
                    format!(
                        "invalidateblock: disconnect failed mid-reorg ({e}); consider --reindex"
                    ),
                )
            })?;
        }

        Ok(serde_json::json!({
            "invalidated": hash.to_string(),
            "height": stored.height,
            "disconnected": disconnected,
            "tip_height": tip_height,
            "tip_hash": tip_hash.map(|h: bitcoin::BlockHash| h.to_string()),
        }))
    }

    /// Remove the invalid marker from a block and every marked descendant
    /// (Bitcoin Core parity). The cleared branch becomes adoptable again;
    /// the switch happens when fork choice next evaluates it — on its next
    /// re-announcement or new block — rather than immediately.
    fn reconsider_block(&self, blockhash: String) -> RpcResult<Value> {
        let hash: bitcoin::BlockHash = blockhash
            .parse()
            .map_err(|_| rpc_err(-8, "Invalid block hash"))?;
        let target = self
            .state
            .header_index
            .get_header(&hash)
            .map_err(|e| rpc_err(-1, format!("Storage error: {e}")))?
            .ok_or_else(|| rpc_err(-5, "Block not found"))?;

        let markers = self
            .state
            .header_index
            .iter_invalid()
            .map_err(|e| rpc_err(-1, format!("Storage error: {e}")))?;
        let mut cleared = 0u32;
        for (mhash, mheight, _) in markers {
            let clears = mhash == hash
                || (mheight > target.height
                    && block_in_place(|| {
                        self.state
                            .header_index
                            .get_ancestor(&mhash, target.height)
                            .ok()
                            .flatten()
                            .map(|a| a.header.block_hash() == hash)
                            .unwrap_or(false)
                    }));
            if clears {
                self.state
                    .header_index
                    .clear_invalid(&mhash)
                    .map_err(|e| rpc_err(-1, format!("Failed to clear marker: {e}")))?;
                cleared += 1;
            }
        }
        Ok(serde_json::json!({
            "reconsidered": hash.to_string(),
            "cleared_markers": cleared,
        }))
    }

    /// "Abandon minority chain": persist the BIP-110 capitulation flag and
    /// gracefully shut down. On the next start the node disables RDTS
    /// enforcement, clears its invalid-block markers, and reorgs onto the
    /// most-work chain. Refused while the split monitor has not armed (rival
    /// lead below threshold) unless `force` is passed.
    fn abandon_bip110(&self, force: Option<bool>) -> RpcResult<Value> {
        let force = force.unwrap_or(false);
        let armed = self
            .state
            .split_monitor
            .as_ref()
            .and_then(|m| block_in_place(|| m.snapshot()))
            .map(|s| s.capitulation_armed)
            .unwrap_or(false);
        if !armed && !force {
            return Err(rpc_err(
                -8,
                "capitulation is not armed (rival chain lead below threshold); \
                 pass force=true to abandon BIP-110 anyway",
            ));
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        self.state
            .header_index
            .set_bip110_abandoned(now)
            .map_err(|e| rpc_err(-32603, format!("failed to persist flag: {e}")))?;
        warn!("abandonbip110: minority chain abandoned by operator — shutting down");
        self.state
            .shutting_down
            .store(true, std::sync::atomic::Ordering::Relaxed);
        let tx = self.state.shutdown_tx.clone();
        tokio::spawn(async move {
            let _ = tx.send(()).await;
        });
        Ok(serde_json::json!({ "abandoned_at": now, "shutting_down": true }))
    }

    fn stop(&self) -> RpcResult<String> {
        info!("RPC stop command received");
        // Set the atomic flag immediately so long-running loops (drain loop)
        // can break out before the channel-based shutdown propagates.
        self.state
            .shutting_down
            .store(true, std::sync::atomic::Ordering::Relaxed);
        let tx = self.state.shutdown_tx.clone();
        // Send shutdown in background to avoid blocking the RPC response
        tokio::spawn(async move {
            let _ = tx.send(()).await;
        });
        Ok("bitcoinpr server stopping".to_string())
    }

    fn help(&self, command: Option<String>) -> RpcResult<String> {
        if let Some(cmd) = command {
            let help_text = match cmd.as_str() {
                "getblockchaininfo" => "getblockchaininfo\nReturns blockchain state info.",
                "getblock" => {
                    "getblock \"blockhash\" ( verbosity )\nReturns block data for given hash."
                }
                "getblockhash" => "getblockhash height\nReturns hash of block at given height.",
                "getblockcount" => "getblockcount\nReturns the height of the most-work chain.",
                "getdifficulty" => "getdifficulty\nReturns the proof-of-work difficulty.",
                "getbestblockhash" => {
                    "getbestblockhash\nReturns the hash of the best (tip) block."
                }
                "getrawtransaction" => "getrawtransaction \"txid\" ( verbose )\nReturn raw transaction data.",
                "sendrawtransaction" => "sendrawtransaction \"hexstring\"\nSubmit a raw transaction to the network.",
                "decoderawtransaction" => "decoderawtransaction \"hexstring\"\nReturn a JSON object representing the serialized transaction.",
                "gettxout" => "gettxout \"txid\" n ( include_mempool )\nReturns details about an unspent transaction output.",
                "getmempoolinfo" => "getmempoolinfo\nReturns details on the active state of the TX memory pool.",
                "getrawmempool" => "getrawmempool\nReturns all transaction ids in memory pool.",
                "getnetworkinfo" => "getnetworkinfo\nReturns network state info.",
                "getpeerinfo" => "getpeerinfo\nReturns data about each connected network node.",
                "getconnectioncount" => "getconnectioncount\nReturns the number of connections.",
                "stop" => "stop\nRequest a graceful shutdown of bitcoinpr.",
                "validateaddress" => "validateaddress \"address\"\nReturn information about the given bitcoin address.",
                "estimatesmartfee" => "estimatesmartfee conf_target\nEstimates the approximate fee per kilobyte needed for a transaction to begin confirmation within conf_target blocks.",
                "getblocktemplate" => "getblocktemplate ( {\"mode\":\"template|proposal\",\"capabilities\":[..],\"rules\":[..],\"longpollid\":\"..\",\"data\":\"hex\"} )\nReturns data needed to construct a block to work on (BIP 22/23). With mode=\"proposal\" and a hex block in \"data\", validates the block as a proposal without committing it (returns null if acceptable, else a reject reason).",
                "submitblock" => "submitblock \"hexdata\"\nAttempts to submit new block to network.",
                "help" => "help ( \"command\" )\nList all commands, or get help for a specified command.",
                _ => "Unknown command. Use 'help' for a list of commands.",
            };
            Ok(help_text.to_string())
        } else {
            Ok("== Blockchain ==\n\
                 getblockchaininfo\n\
                 getblock \"blockhash\" ( verbosity )\n\
                 getblockhash height\n\
                 getblockcount\n\
                 getdifficulty\n\
                 getbestblockhash\n\n\
                 == Rawtransactions ==\n\
                 getrawtransaction \"txid\" ( verbose )\n\
                 sendrawtransaction \"hexstring\"\n\
                 decoderawtransaction \"hexstring\"\n\n\
                 == UTXO ==\n\
                 gettxout \"txid\" n ( include_mempool )\n\n\
                 == Mempool ==\n\
                 getmempoolinfo\n\
                 getrawmempool\n\n\
                 == Network ==\n\
                 getnetworkinfo\n\
                 getpeerinfo\n\
                 getconnectioncount\n\n\
                 == Util ==\n\
                 validateaddress \"address\"\n\
                 estimatesmartfee conf_target\n\n\
                 == Mining ==\n\
                 getblocktemplate ( \"template_request\" )\n\
                 submitblock \"hexdata\"\n\n\
                 == Control ==\n\
                 stop\n\
                 help ( \"command\" )\n\
                 uptime\n\
                 getindexinfo"
                .to_string())
        }
    }

    fn get_index_info(&self) -> RpcResult<Value> {
        let mut result = json!({});
        let best_height = *block_in_place(|| self.state.best_height.blocking_read());
        if let Some(ref tx_idx) = self.state.tx_index {
            let indexed = tx_idx.get_indexed_height().unwrap_or(None).unwrap_or(0);
            result["txindex"] = json!({
                "synced": indexed >= best_height,
                "best_block_height": indexed,
            });
        }
        if let Some(ref sh_height) = self.state.scripthash_indexed_height {
            let indexed = sh_height.load(std::sync::atomic::Ordering::Relaxed);
            result["scripthash"] = json!({
                "synced": indexed >= best_height,
                "best_block_height": indexed,
            });
        }
        Ok(result)
    }

    fn uptime(&self) -> RpcResult<u64> {
        Ok(self.state.start_time.elapsed().as_secs())
    }
}

/// Encode block height as a BIP 34 script prefix for the coinbase scriptSig.
///
/// Matches Bitcoin Core's `CScript() << nHeight` convention so that BIP34
/// prefix-equality checks pass across all implementations:
///
/// - Heights 0:     OP_0 (0x00) + OP_0 pad → `[0x00, 0x00]`
/// - Heights 1..16: OP_N (0x51+n-1) + OP_0 pad → `[0x51+n-1, 0x00]`
/// - Heights 17+:   minimal push-data `[<len>, <LE bytes>]` (≥ 2 bytes)
///
/// The OP_0 padding byte for small heights ensures the total scriptSig is
/// ≥ 2 bytes as required by the `CheckTransaction` rule enforced by all
/// Bitcoin implementations (Bitcoin Core, Knots, Libbitcoin, …).
fn encode_bip34_height(height: u32) -> Vec<u8> {
    match height {
        0 => vec![0x00, 0x00], // OP_0 height + OP_0 padding
        1..=16 => {
            // OP_1..OP_16 + OP_0 padding → 2 bytes
            let op_n = 0x50u8 + height as u8; // 0x51..0x60
            vec![op_n, 0x00]
        }
        _ => {
            // Minimal push-data (always ≥ 2 bytes for height ≥ 17)
            let mut le_bytes = height.to_le_bytes().to_vec();
            while le_bytes.last() == Some(&0) {
                le_bytes.pop();
            }
            if le_bytes.last().is_some_and(|&b| b & 0x80 != 0) {
                le_bytes.push(0x00); // prevent sign bit confusion
            }
            let mut out = vec![le_bytes.len() as u8];
            out.extend_from_slice(&le_bytes);
            out
        }
    }
}

/// Build a coinbase transaction paying `subsidy` to `script_pubkey`.
///
/// `extra_nonce` is appended after the BIP 34 height push so that coinbases
/// mined in separate process runs (or after a cluster reset that leaves stale
/// UTXO data on disk) produce distinct txids even for the same height/address.
fn build_coinbase_tx(
    height: u32,
    subsidy: u64,
    script_pubkey: &ScriptBuf,
    extra_nonce: u64,
) -> Transaction {
    use bitcoin::transaction::{TxIn, TxOut, Version};
    use bitcoin::{Amount, OutPoint, Sequence, Witness};

    // BIP 34: coinbase scriptSig encodes the block height using Bitcoin Core's
    // CScript() << height convention, padded to ≥ 2 bytes (CheckTransaction).
    let mut script_bytes = encode_bip34_height(height);

    // Append extra_nonce as an 8-byte LE push so the txid is unique across runs.
    let nonce_le = extra_nonce.to_le_bytes();
    script_bytes.push(nonce_le.len() as u8); // OP_PUSHDATA for 8 bytes
    script_bytes.extend_from_slice(&nonce_le);

    let height_script = ScriptBuf::from_bytes(script_bytes);

    let coinbase_input = TxIn {
        previous_output: OutPoint::null(),
        script_sig: height_script,
        sequence: Sequence::MAX,
        witness: Witness::new(),
    };

    let coinbase_output = TxOut {
        value: Amount::from_sat(subsidy),
        script_pubkey: script_pubkey.clone(),
    };

    Transaction {
        version: Version(2),
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![coinbase_input],
        output: vec![coinbase_output],
    }
}

/// BIP 141 witness commitment scriptPubKey for a template's tx set.
///
/// The coinbase wtxid is defined as 32 zero bytes; every other tx contributes
/// its real wtxid. The commitment is `sha256d(witness_merkle_root || reserved)`
/// where `reserved` is 32 zero bytes, and the output script is
/// `OP_RETURN 0x24 0xaa21a9ed || commitment`.
fn witness_commitment_script(wtxids: &[[u8; 32]]) -> Vec<u8> {
    use bitcoin::hashes::{sha256d, Hash as _};

    let mut leaves: Vec<[u8; 32]> = Vec::with_capacity(wtxids.len() + 1);
    leaves.push([0u8; 32]); // coinbase wtxid placeholder
    leaves.extend_from_slice(wtxids);

    let witness_root = bitcoinpr_core::merkle::root(&leaves);

    let mut buf = [0u8; 64];
    buf[..32].copy_from_slice(&witness_root);
    // buf[32..] stays zero — the witness reserved value.
    let commitment = sha256d::Hash::hash(&buf);

    let mut script = vec![0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed];
    script.extend_from_slice(commitment.as_ref());
    script
}

/// Check if a block hash meets the PoW target.
/// The block hash is a double-SHA256, interpreted as a 256-bit LE number.
/// It must be <= target for the block to be valid.
fn hash_meets_target(hash: &bitcoin::BlockHash, target: &bitcoin::Target) -> bool {
    // Compare the block hash against the target
    // Both are 256-bit numbers. BlockHash bytes are in internal (LE) order.
    let hash_bytes: &[u8; 32] = hash.as_ref();
    let target_bytes = target.to_le_bytes();

    // Compare as little-endian 256-bit numbers (MSB at end)
    for i in (0..32).rev() {
        if hash_bytes[i] < target_bytes[i] {
            return true;
        }
        if hash_bytes[i] > target_bytes[i] {
            return false;
        }
    }
    true // equal
}

/// BIP 350 (bech32m) end-to-end audit for the address-decoding primitives that
/// `validate_address` relies on (`Address::from_str`, `is_valid_for_network`,
/// `script.witness_version()`). Constructing a full `RpcServer` requires a live
/// RocksDB-backed state, so these tests exercise the same rust-bitcoin building
/// blocks directly with deterministic, self-contained vectors.
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod bech32m_tests {
    use bitcoin::address::NetworkUnchecked;
    use bitcoin::{Address, Network, WitnessProgram, WitnessVersion};
    use std::str::FromStr;

    /// Mirrors the witness fields `validate_address` derives from a scriptPubKey.
    fn witness_info(script: &bitcoin::ScriptBuf) -> Option<(u8, String)> {
        let version = script.witness_version()?;
        let bytes = script.as_bytes();
        let program = if bytes.len() > 2 {
            hex::encode(&bytes[2..])
        } else {
            String::new()
        };
        Some((version.to_num(), program))
    }

    #[test]
    fn mainnet_taproot_bech32m_decodes() {
        // Known-valid mainnet taproot (witness v1) vector.
        let s = "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0";
        let addr: Address<NetworkUnchecked> = Address::from_str(s).unwrap();

        assert!(addr.is_valid_for_network(Network::Bitcoin));
        assert!(!addr.is_valid_for_network(Network::Testnet));

        let checked = addr.require_network(Network::Bitcoin).unwrap();
        let script = checked.script_pubkey();
        assert!(script.is_witness_program());
        // Taproot scriptPubKey: OP_1 (0x51) <push 0x20> <32-byte program> = 34 bytes.
        assert_eq!(script.as_bytes().len(), 34);
        assert_eq!(&script.as_bytes()[..2], &[0x51, 0x20]);

        let (version, program) = witness_info(&script).unwrap();
        assert_eq!(version, 1);
        assert_eq!(program.len(), 64); // 32 bytes as hex
    }

    #[test]
    fn signet_and_testnet_taproot_roundtrip() {
        // Deterministic 32-byte program → witness v1 (taproot) address.
        let program_bytes = [0x02u8; 32];
        let wp = WitnessProgram::new(WitnessVersion::V1, &program_bytes).unwrap();

        // Signet and testnet share the `tb` HRP, so both encode as `tb1p...`.
        for net in [Network::Signet, Network::Testnet] {
            let addr = Address::from_witness_program(wp, net);
            let s = addr.to_string();
            assert!(s.starts_with("tb1p"), "taproot must use bech32m tb1p: {s}");

            let parsed: Address<NetworkUnchecked> = Address::from_str(&s).unwrap();
            assert!(parsed.is_valid_for_network(net));
            let checked = parsed.require_network(net).unwrap();
            assert_eq!(checked, addr, "round-trip must preserve the address");

            let (version, program) = witness_info(&checked.script_pubkey()).unwrap();
            assert_eq!(version, 1);
            assert_eq!(program, hex::encode(program_bytes));
        }
    }

    #[test]
    fn segwit_v0_still_decodes_as_bech32() {
        // BIP 173 bech32 v0 p2wpkh vector — must still decode at witness v0.
        let s = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
        let addr: Address<NetworkUnchecked> = Address::from_str(s).unwrap();
        assert!(addr.is_valid_for_network(Network::Bitcoin));

        let checked = addr.require_network(Network::Bitcoin).unwrap();
        let (version, _program) = witness_info(&checked.script_pubkey()).unwrap();
        assert_eq!(version, 0);
    }
}
