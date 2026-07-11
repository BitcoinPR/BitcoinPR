use bitcoinpr_core::{ChainState, ConsensusParams, EventBus, Mempool};
use bitcoinpr_p2p::{
    is_catching_up, AddrNetwork, BlockSync, HeaderSync, NetAddr, NodeEvent, PeerCommand,
    PeerManager, ProxyConfig,
};
use bitcoinpr_rpc::{RpcServer, RpcState};
use bitcoinpr_storage::{BlockStore, HeaderIndex, TxIndex, UtxoSet};
use clap::Parser;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};
use tracing::{error, info, warn};

mod config;
mod node;
mod recovery;

// See the tikv-jemallocator entry in Cargo.toml: glibc malloc arena bloat
// OOM-killed the node during IBD; jemalloc returns freed memory to the OS.
#[cfg(not(target_env = "msvc"))]
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

use config::{
    default_rpc_port, difficulty_to_nbits, expand_datadir, load_config, net_subdir, parse_network,
    Cli,
};
use node::Node;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Raise the open file descriptor soft limit to the hard limit.
    // RocksDB opens many SST files across multiple databases; the default
    // soft limit of 1024 is far too low for a full node with txindex + index.
    #[cfg(unix)]
    {
        use std::io;
        unsafe {
            let mut rlim = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            if libc::getrlimit(libc::RLIMIT_NOFILE, &mut rlim) == 0 {
                let target = rlim.rlim_max.min(65536);
                if rlim.rlim_cur < target {
                    rlim.rlim_cur = target;
                    if libc::setrlimit(libc::RLIMIT_NOFILE, &rlim) != 0 {
                        eprintln!(
                            "Warning: failed to raise fd limit: {}",
                            io::Error::last_os_error()
                        );
                    }
                }
            }
        }
    }

    // Rayon thread pool for parallel script verification. Sized to the host's
    // available parallelism minus 2 (clamped to ≥2), leaving headroom for the
    // tokio runtime: block validation runs concurrently with the async event
    // loops, and a rayon pool sized to *all* cores oversubscribes the CPU
    // during IBD (M2, 2026-07-02 review). Falls back to 6 if the core count
    // is unavailable.
    let script_threads = std::thread::available_parallelism()
        .map(|n| n.get().saturating_sub(2))
        .unwrap_or(6)
        .max(2);
    rayon::ThreadPoolBuilder::new()
        .num_threads(script_threads)
        .build_global()
        .ok(); // ignore error if pool already initialized (e.g., in tests)

    let cli = Cli::parse();

    // Load config file from datadir (CLI args take precedence)
    let datadir_for_conf = expand_datadir(&cli.datadir);
    let conf = load_config(&datadir_for_conf.join("bitcoinpr.conf"))?;

    // Merge: CLI defaults may be overridden by config for optional fields
    let loglevel = if cli.loglevel != "info" {
        cli.loglevel.clone()
    } else {
        conf.loglevel.unwrap_or_else(|| cli.loglevel.clone())
    };

    let network_str = if cli.network != "mainnet" {
        cli.network.clone()
    } else {
        conf.network.unwrap_or_else(|| cli.network.clone())
    };
    let network = parse_network(&network_str)?;
    let mut params = ConsensusParams::for_network(network);
    // BIP-110 RDTS activation-height override (CLI wins over conf). Lets regtest
    // and other networks enable/relocate RDTS enforcement for testing.
    if let Some(h) = cli.bip110height.or(conf.bip110height) {
        params.bip110_activation_height = Some(h);
    }
    // Knots-style relay-policy knobs (CLI wins over conf; unset keeps the
    // per-network defaults in ConsensusParams). Policy only — blocks
    // containing filtered transactions still validate.
    if let Some(v) = cli.datacarrier.or(conf.datacarrier) {
        params.datacarrier = v;
    }
    if let Some(v) = cli.datacarriersize.or(conf.datacarriersize) {
        params.max_datacarrier_size = v;
    }
    if let Some(v) = cli.permitbaremultisig.or(conf.permitbaremultisig) {
        params.permit_bare_multisig = v;
    }
    if let Some(v) = cli.rejectparasites.or(conf.rejectparasites) {
        params.reject_parasites = v;
    }
    if let Some(v) = cli.rejecttokens.or(conf.rejecttokens) {
        params.reject_tokens = v;
    }
    let p2p_port = cli.port.or(conf.port).unwrap_or(params.default_port);

    // Merge index/mining flags from config (CLI flag true overrides config)
    #[cfg(feature = "indexing")]
    let index_enabled = cli.index || conf.index.unwrap_or(false);
    #[cfg(feature = "web")]
    let webport = if cli.webport != 3000 {
        cli.webport
    } else {
        conf.webport.unwrap_or(cli.webport)
    };
    #[cfg(feature = "web")]
    let web_admin_token = cli.webadmintoken.clone().or(conf.webadmintoken.clone());
    let healthbind = cli.healthbind.clone().or(conf.healthbind.clone());
    let mining_enabled = cli.mining || conf.mining.unwrap_or(false);
    let miningport = if cli.miningport != 3333 {
        cli.miningport
    } else {
        conf.miningport.unwrap_or(cli.miningport)
    };
    let miningaddress = cli.miningaddress.or(conf.miningaddress);
    let miningdifficulty = cli.miningdifficulty.or(conf.miningdifficulty);
    let coinbasetag = cli.coinbasetag.clone().or(conf.coinbasetag);
    let poolname = cli.poolname.clone().or(conf.poolname);
    let dbcache_mb = if cli.dbcache != 450 {
        Some(cli.dbcache)
    } else {
        conf.dbcache.or(Some(cli.dbcache))
    };
    // BIP 111: only serve bloom-filtered connections when explicitly enabled.
    let peerbloomfilters = cli.peerbloomfilters || conf.peerbloomfilters.unwrap_or(false);
    let blocksdir = cli.blocksdir.clone().or(conf.blocksdir);
    let txindex_enabled = cli.txindex || conf.txindex.unwrap_or(false);
    // Block-file pruning (--prune <MiB>, 0 = disabled). Incompatible with the
    // transaction / address indexes, which need historical blocks on disk.
    let prune_mib = if cli.prune != 0 {
        cli.prune
    } else {
        conf.prune.unwrap_or(0)
    };
    let prune_target_bytes = match prune_mib {
        0 => None,
        mib if mib < bitcoinpr_storage::MIN_PRUNE_TARGET_MIB => anyhow::bail!(
            "--prune={mib} is below the minimum of {} MiB",
            bitcoinpr_storage::MIN_PRUNE_TARGET_MIB
        ),
        mib => Some(mib * 1024 * 1024),
    };
    if prune_target_bytes.is_some() && txindex_enabled {
        anyhow::bail!(
            "--prune is incompatible with --txindex (the transaction index \
             needs historical blocks)"
        );
    }
    #[cfg(feature = "indexing")]
    if prune_target_bytes.is_some() && index_enabled {
        anyhow::bail!(
            "--prune is incompatible with --index (the address index needs \
             historical blocks)"
        );
    }
    let jsonlog = cli.jsonlog || conf.jsonlog.unwrap_or(false);
    let disable_ipv6 = cli.disableipv6 || conf.disableipv6.unwrap_or(false);
    // BIP 324 v2 transport: on by default (matches Core); disable with
    // --no-v2transport or `v2transport=0` in the conf file.
    let v2_transport = !cli.no_v2transport && conf.v2transport.unwrap_or(true);
    // TEST ONLY: treat private/RFC1918 addresses as routable for addr gossip.
    let gossip_private_addrs =
        cli.gossip_private_addrs || conf.gossip_private_addrs.unwrap_or(false);

    // Tor/I2P networking (CLI wins over conf). --proxy routes all networks
    // through a SOCKS5 proxy; --onion overrides it for .onion; --onlynet
    // restricts which networks are dialed.
    let resolve_proxy = |label: &str, s: &str| -> Option<SocketAddr> {
        s.parse::<SocketAddr>().ok().or_else(|| {
            use std::net::ToSocketAddrs;
            match s.to_socket_addrs() {
                Ok(mut a) => a.next(),
                Err(e) => {
                    warn!("Ignoring invalid {label} address '{s}': {e}");
                    None
                }
            }
        })
    };
    let proxy_str = cli.proxy.clone().or(conf.proxy.clone());
    let onion_str = cli.onion.clone().or(conf.onion.clone());
    let ip_proxy = proxy_str.as_deref().and_then(|s| resolve_proxy("proxy", s));
    let onion_proxy = onion_str.as_deref().and_then(|s| resolve_proxy("onion", s));
    let proxy_config = ProxyConfig {
        ip_proxy,
        onion_proxy,
        randomize_credentials: cli.proxyrandomize.or(conf.proxyrandomize).unwrap_or(true),
    };
    // Merge --onlynet from CLI and conf, parsing each into an AddrNetwork.
    let mut onlynet_strs = cli.onlynet.clone();
    for n in &conf.onlynet {
        if !onlynet_strs.contains(n) {
            onlynet_strs.push(n.clone());
        }
    }
    let onlynet: Vec<AddrNetwork> = onlynet_strs
        .iter()
        .filter_map(|s| match s.parse::<AddrNetwork>() {
            Ok(n) => Some(n),
            Err(_) => {
                warn!("Ignoring unknown -onlynet value '{s}' (expected ipv4|ipv6|onion|i2p)");
                None
            }
        })
        .collect();
    if onlynet.contains(&AddrNetwork::Onion) && !proxy_config.any() {
        warn!(
            "-onlynet=onion set but no --proxy/--onion configured; onion peers will be unreachable"
        );
    }
    // Electrum server transport options (CLI overrides conf; conf overrides defaults).
    #[cfg(feature = "indexing")]
    let electrumport = if cli.electrumport != 50001 {
        cli.electrumport
    } else {
        conf.electrumport.unwrap_or(cli.electrumport)
    };
    #[cfg(feature = "indexing")]
    let electrumsslport = cli
        .electrumsslport
        .or(conf.electrumsslport)
        .unwrap_or(electrumport + 1);
    #[cfg(feature = "indexing")]
    let electrumcert = cli.electrumcert.clone().or(conf.electrumcert);
    #[cfg(feature = "indexing")]
    let electrumkey = cli.electrumkey.clone().or(conf.electrumkey);
    #[cfg(feature = "indexing")]
    let electrumbanner = cli
        .electrumbanner
        .clone()
        .or(conf.electrumbanner)
        .unwrap_or_else(|| "BitcoinPR Electrum Server".to_string());

    // Setup data directory (before logging, so log file goes in net_dir)
    let datadir = expand_datadir(&cli.datadir);
    let net_dir = net_subdir(&datadir, network);
    std::fs::create_dir_all(&net_dir)?;

    // Rotate log files: current -> last
    let log_current = net_dir.join("bitcoinprd.log");
    let log_last = net_dir.join("bitcoinprd.log.last");
    if log_current.exists() {
        let _ = std::fs::rename(&log_current, &log_last);
    }

    // Initialize tracing/logging with both stdout and file output
    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(&loglevel));

    let log_file = std::fs::File::create(&log_current)?;
    let file_writer = std::sync::Mutex::new(log_file);

    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;
    use tracing_subscriber::Layer; // brings .boxed() into scope

    let (stdout_layer, file_layer) = if jsonlog {
        (
            tracing_subscriber::fmt::layer()
                .with_target(false)
                .json()
                .boxed(),
            tracing_subscriber::fmt::layer()
                .with_target(false)
                .with_ansi(false)
                .with_writer(file_writer)
                .json()
                .boxed(),
        )
    } else {
        (
            tracing_subscriber::fmt::layer().with_target(false).boxed(),
            tracing_subscriber::fmt::layer()
                .with_target(false)
                .with_ansi(false)
                .with_writer(file_writer)
                .boxed(),
        )
    };

    tracing_subscriber::registry()
        .with(env_filter)
        .with(stdout_layer)
        .with(file_layer)
        .init();
    info!("bitcoinprd v{}", env!("CARGO_PKG_VERSION"));
    info!("Network: {:?}", network);
    info!("Data directory: {}", net_dir.display());
    info!("Log file: {}", log_current.display());
    if jsonlog {
        info!("Structured JSON logging enabled");
    }
    if !params.datacarrier {
        info!("Relay policy: OP_RETURN outputs disabled (datacarrier=0)");
    } else if params.max_datacarrier_size != 83 {
        info!(
            "Relay policy: OP_RETURN size limit {} bytes (datacarriersize)",
            params.max_datacarrier_size
        );
    }
    if params.permit_bare_multisig {
        info!("Relay policy: bare multisig outputs permitted (permitbaremultisig=1)");
    }
    if !params.reject_parasites {
        info!("Relay policy: parasite filtering disabled (rejectparasites=0)");
    }
    if !params.reject_tokens {
        info!("Relay policy: token filtering disabled (rejecttokens=0)");
    }

    // Resolve where raw block files (blk*.dat) live; handle --migrateblocks.
    let blocks_dir =
        recovery::resolve_blocks_dir(&net_dir, &blocksdir, cli.migrateblocks, network)?;

    // Initialize storage — block store is always kept (raw block data).
    info!(blocks_dir = %blocks_dir.display(), "Block storage directory");
    let block_store = Arc::new(BlockStore::open(&blocks_dir)?);

    // Bug #4: --reindex-chainstate — wipe derived state, preserve headers + blocks.
    recovery::reindex_chainstate_wipe(&net_dir, &params, cli.reindex_chainstate)?;

    // --reindex or unrecoverable chain break: wipe derived state and rebuild
    recovery::check_integrity_and_reindex(
        &net_dir,
        dbcache_mb,
        &params,
        &block_store,
        cli.reindex,
        cli.reindex_chainstate,
    )?;

    let header_index = Arc::new(HeaderIndex::open(&net_dir.join("headers"))?);
    let utxo_set = Arc::new(UtxoSet::open(&net_dir.join("utxo"), dbcache_mb)?);

    // Start background block writer thread for async flat-file writes
    block_store.start_background_writer();

    // Load chain state from storage
    let (best_height, best_hash) = recovery::load_chain_tip(&header_index, &utxo_set, &params)?;

    // Phase A: UTXO flush height reconciliation.
    let (utxo_set, best_height, best_hash, utxo_verified) = recovery::phase_a_reconcile_utxo(
        &net_dir,
        dbcache_mb,
        &params,
        &header_index,
        utxo_set,
        best_height,
        best_hash,
    )?;

    // Verify the tip block is actually stored (block store + block pos).
    let (utxo_set, mut best_height, mut best_hash) = recovery::verify_tip_block_stored(
        &net_dir,
        dbcache_mb,
        &params,
        &header_index,
        &block_store,
        utxo_set,
        best_height,
        best_hash,
        utxo_verified,
    )?;

    // Phase C: Scan for missing/corrupt blocks in the validated range.
    let missing_blocks: Vec<u32> =
        recovery::phase_c_scan_missing_blocks(&block_store, &header_index, best_height);

    // Phase D: Repair missing height→hash entries in the header index.
    recovery::phase_d_repair_height_index(&header_index, &block_store, best_height, best_hash);

    // Initialize optional transaction index
    let tx_index = if txindex_enabled {
        let idx = Arc::new(TxIndex::open(&net_dir.join("txindex"))?);
        info!("Transaction index enabled (-txindex)");

        // Backfill tx index if it's behind the validated chain tip (skip during IBD).
        let tx_indexed_height = idx.get_indexed_height()?.unwrap_or(0);
        let header_tip_for_tx = header_index.get_header_tip_height()?.unwrap_or(best_height);
        if tx_indexed_height < best_height && !is_catching_up(best_height, header_tip_for_tx) {
            info!(
                tx_indexed_height,
                chain_height = best_height,
                blocks_to_index = best_height - tx_indexed_height,
                "TxIndex behind chain, starting background backfill..."
            );
            let backfill_idx = idx.clone();
            let backfill_hi = header_index.clone();
            let backfill_bs = block_store.clone();
            let backfill_start = tx_indexed_height + 1;
            let backfill_end = best_height;
            tokio::task::spawn_blocking(move || {
                let mut backfill_count = 0u32;
                for h in backfill_start..=backfill_end {
                    if let Ok(Some(hash)) = backfill_hi.get_hash_at_height(h) {
                        if let Ok(Some(pos)) = backfill_hi.get_block_pos(&hash) {
                            if let Ok(raw) = backfill_bs.read_block(&pos) {
                                if let Ok(block) =
                                    bitcoin::consensus::encode::deserialize::<bitcoin::Block>(&raw)
                                {
                                    let txids: Vec<bitcoin::Txid> =
                                        block.txdata.iter().map(|tx| tx.compute_txid()).collect();
                                    if let Err(e) =
                                        backfill_idx.index_block_at_height(&hash, &txids, h)
                                    {
                                        warn!(height = h, error = %e, "TxIndex backfill error");
                                    }
                                    backfill_count += 1;
                                    if backfill_count % 1000 == 0 {
                                        info!(
                                            height = h,
                                            indexed = backfill_count,
                                            total = backfill_end - backfill_start + 1,
                                            "TxIndex backfill progress"
                                        );
                                    }
                                }
                            }
                        }
                    }
                }
                info!(blocks = backfill_count, "TxIndex backfill complete");
            });
        } else if tx_indexed_height < best_height {
            info!(
                tx_indexed_height,
                chain_height = best_height,
                header_tip = header_tip_for_tx,
                "TxIndex backfill deferred until block catch-up completes"
            );
        }

        Some(idx)
    } else {
        None
    };

    // Initialize chain state for block validation
    let mut cs = ChainState::new(
        params.clone(),
        header_index.clone(),
        utxo_set.clone(),
        block_store.clone(),
        best_height,
        best_hash,
    );
    cs.tx_index = tx_index.clone();

    let chain_state = Arc::new(tokio::sync::Mutex::new(cs));
    let sig_cache = chain_state.lock().await.sig_cache.clone();

    // Local block replay: if the validated tip is behind the header chain and
    // blocks exist on disk, replay them locally instead of re-downloading from
    // peers. This fulfils the "replay from stored blocks" promise after recovery.
    let header_chain_height = header_index.get_best_height()?.unwrap_or(best_height);
    if best_height < header_chain_height {
        let gap = header_chain_height - best_height;

        // First, check if blocks on disk are missing their block_pos index
        // entries (lost during header truncation/recovery). If so, scan the
        // flat files to rebuild the index before attempting local replay.
        let next_hash = header_index.get_hash_at_height(best_height + 1);
        let next_has_pos = next_hash
            .as_ref()
            .ok()
            .and_then(|h| h.as_ref())
            .and_then(|h| header_index.get_block_pos(h).ok().flatten())
            .is_some();
        if !next_has_pos && gap > 10 {
            info!(
                validated_tip = best_height,
                header_chain_height,
                "Block position index missing — scanning block files to rebuild"
            );
            match block_store.reindex_block_files(&header_index) {
                Ok(indexed) => {
                    if indexed > 0 {
                        info!(indexed, "Block file reindex recovered block positions");
                    }
                }
                Err(e) => {
                    warn!(error = %e, "Block file reindex failed — will download from peers");
                }
            }
        }

        info!(
            validated_tip = best_height,
            header_chain_height,
            blocks_to_replay = gap,
            "Attempting local block replay from stored blocks"
        );
        let mut replay_h = best_height + 1;
        let mut replayed = 0u32;
        let mut consecutive_missing = 0u32;
        let replay_start = std::time::Instant::now();
        while replay_h <= header_chain_height {
            let hash = match header_index.get_hash_at_height(replay_h) {
                Ok(Some(h)) => h,
                _ => break,
            };
            let raw = match header_index
                .get_block_pos(&hash)
                .ok()
                .flatten()
                .and_then(|pos| block_store.read_block(&pos).ok())
            {
                Some(r) => r,
                None => {
                    consecutive_missing += 1;
                    if consecutive_missing >= 3 {
                        // Multiple consecutive missing blocks — stop replay,
                        // the rest will be fetched from peers during normal sync.
                        break;
                    }
                    replay_h += 1;
                    continue;
                }
            };
            let block: bitcoin::Block = match bitcoin::consensus::encode::deserialize(&raw) {
                Ok(b) => b,
                Err(_) => break,
            };
            consecutive_missing = 0;

            let mut cs = chain_state.lock().await;
            match cs.connect_block_with_raw(&block, replay_h, Some(&raw)) {
                Ok(()) => {
                    best_height = cs.best_height;
                    best_hash = cs.best_hash;
                    drop(cs);
                    replayed += 1;
                    if replayed % 10000 == 0 {
                        let elapsed = replay_start.elapsed().as_secs();
                        let bps = if elapsed > 0 {
                            replayed as u64 / elapsed
                        } else {
                            0
                        };
                        info!(
                            height = best_height,
                            replayed,
                            remaining = header_chain_height - best_height,
                            blocks_per_sec = bps,
                            "Local block replay progress"
                        );
                    }
                }
                Err(e) => {
                    drop(cs);
                    warn!(
                        height = replay_h,
                        error = %e,
                        "Local replay failed — remaining blocks will be fetched from peers"
                    );
                    break;
                }
            }
            replay_h += 1;
        }
        if replayed > 0 {
            let elapsed = replay_start.elapsed();
            info!(
                replayed,
                final_height = best_height,
                elapsed_secs = elapsed.as_secs(),
                "Local block replay complete"
            );
            // best_height and best_hash are updated in-place above;
            // shared state (created below) will pick up the new values.
        } else if best_height < header_chain_height {
            info!("No stored blocks available for local replay — will sync from peers");
        }
    }

    // Merge connect addresses from CLI and config file
    let mut all_connects = cli.connect.clone();
    for c in &conf.connect {
        if !all_connects.contains(c) {
            all_connects.push(c.clone());
        }
    }

    // Parse manual connect addresses. Onion/I2P literals are kept as-is;
    // IP literals parse directly; bare hostnames are DNS-resolved.
    let connect_addrs: Vec<NetAddr> = all_connects
        .iter()
        .filter_map(|s| {
            let addr_str = if s.contains(':') || s.ends_with(".i2p") {
                s.clone()
            } else {
                format!("{s}:{p2p_port}")
            };
            // Onion/I2P/IP literals go through NetAddr::parse first.
            if let Some(na) = NetAddr::parse(&addr_str, p2p_port) {
                Some(na)
            } else {
                use std::net::ToSocketAddrs;
                match addr_str.to_socket_addrs() {
                    Ok(mut addrs) => addrs.next().map(NetAddr::Ip),
                    Err(e) => {
                        warn!("Failed to resolve connect address '{}': {}", addr_str, e);
                        None
                    }
                }
            }
        })
        .collect();

    if !connect_addrs.is_empty() {
        info!("Manual connect addresses: {:?}", connect_addrs);
    }

    // Setup channels between P2P manager and node coordinator
    let (node_event_tx, node_event_rx) = mpsc::channel::<NodeEvent>(4096);
    // Dedicated channel for full blocks so headers/inv/tx traffic cannot
    // starve block ingestion during deep IBD. Capacity is deliberately small:
    // BlockSync caps global in-flight requests at 128, so 256 slots means
    // try_send never drops in normal operation while bounding buffered block
    // memory to a few hundred MB (the old 16384 cap nominally allowed ~32 GB).
    let (block_event_tx, block_event_rx) = mpsc::channel::<NodeEvent>(256);
    let (command_tx, command_rx) = mpsc::channel::<PeerCommand>(4096);

    // Setup shared state for RPC
    let (shutdown_tx, shutdown_rx) = mpsc::channel::<()>(1);

    let shared_best_height = Arc::new(RwLock::new(best_height));
    let shared_best_hash = Arc::new(RwLock::new(best_hash));
    // Separate std::sync::RwLock for PeerManager (used from sync context)
    let p2p_best_height = Arc::new(std::sync::RwLock::new(best_height as i32));
    let shared_peers = Arc::new(RwLock::new(Vec::new()));
    // Byte-budget mempool (Core's -maxmempool semantics): when the budget is
    // exceeded, the lowest-feerate entries are evicted for better-paying txs.
    let shared_mempool = Arc::new(RwLock::new(Mempool::new(
        bitcoinpr_core::DEFAULT_MAX_MEMPOOL_BYTES,
    )));

    // Shutdown flag — checked inside long-running loops (e.g., drain loop)
    // so that the node responds promptly to stop commands even mid-IBD.
    let shutting_down = Arc::new(std::sync::atomic::AtomicBool::new(false));
    #[cfg(feature = "indexing")]
    let scripthash_backfill_running = Arc::new(std::sync::atomic::AtomicBool::new(false));

    // --- Event Bus ---
    let event_bus = Arc::new(EventBus::new(1024));

    // Resolve effective RPC credentials and bind address (CLI overrides conf).
    let rpc_user = if cli.rpcuser != "bitcoinpr" {
        &cli.rpcuser
    } else {
        conf.rpcuser.as_deref().unwrap_or(&cli.rpcuser)
    };
    let rpc_password = if cli.rpcpassword != "bitcoinpr" {
        &cli.rpcpassword
    } else {
        conf.rpcpassword.as_deref().unwrap_or(&cli.rpcpassword)
    };

    let rpc_port = cli
        .rpcport
        .or(conf.rpcport)
        .unwrap_or_else(|| default_rpc_port(network));
    let rpc_bind_addr = if cli.rpcbind != "127.0.0.1" {
        &cli.rpcbind
    } else {
        conf.rpcbind.as_deref().unwrap_or(&cli.rpcbind)
    };
    let rpc_bind: SocketAddr = format!("{rpc_bind_addr}:{rpc_port}").parse()?;

    // Optional override for the plain-HTTP health endpoint (default: RPC bind
    // IP on rpcport+100, resolved inside RpcServer::start). Lets an operator
    // keep health on loopback while RPC is bound to 0.0.0.0.
    let health_bind: Option<SocketAddr> =
        match &healthbind {
            Some(s) => Some(s.parse().map_err(|e| {
                anyhow::anyhow!("invalid --healthbind '{s}': {e} (expected ip:port)")
            })?),
            None => None,
        };

    // Refuse to expose an unauthenticated-by-default control plane to the network:
    // a non-loopback RPC bind combined with the built-in default password would let
    // anyone who can reach the port call `stop`, `sendrawtransaction`, etc.
    if !rpc_bind.ip().is_loopback() && rpc_password == "bitcoinpr" {
        anyhow::bail!(
            "Refusing to start: RPC is bound to a non-loopback address ({rpc_bind}) with the default \
             rpcpassword. Set a strong --rpcpassword (and --rpcuser) before exposing RPC to the network."
        );
    }

    // Shared IBD flag — true until the node catches up to peer-reported
    // height. Gates P2P tx acceptance, suppresses rapid-fire notifications to
    // Electrum/WebSocket clients, and defers scripthash indexing. Declared
    // before RpcState so generate_to_address can clear it when RPC mining
    // reaches the header tip (see RpcState::is_ibd).
    let is_ibd = Arc::new(std::sync::atomic::AtomicBool::new(true));

    // Shared scripthash indexed height — RPC reads this for getindexinfo.
    // Initialised to 0; updated once the scripthash index is opened (below) and
    // then kept in sync by the backfill task + block drain loop.
    #[cfg(feature = "indexing")]
    let scripthash_indexed_height = if index_enabled {
        Some(Arc::new(std::sync::atomic::AtomicU32::new(0)))
    } else {
        None
    };
    #[cfg(not(feature = "indexing"))]
    let scripthash_indexed_height: Option<Arc<std::sync::atomic::AtomicU32>> = None;

    // Share the BIP-110 signaling checker (mainnet) with the RPC layer so
    // mempool acceptance and getblocktemplate evaluate the same cached state.
    let bip110_checker = chain_state.lock().await.bip110_checker();

    // Create RPC state and server
    // Tor hidden service (-listenonion, default on): create a v3 `.onion` via
    // the Tor control port so the node is reachable inbound over Tor, forwarding
    // to our local P2P listener. Best-effort — a missing/unreachable control
    // port is logged and skipped, never fatal. The returned handle must live for
    // the process lifetime (dropping it tears the ephemeral service down).
    let listen_onion = cli.listenonion.or(conf.listenonion).unwrap_or(true);
    let mut onion_addr: Option<NetAddr> = None;
    let _hidden_service = if listen_onion {
        let torcontrol = cli
            .torcontrol
            .clone()
            .or(conf.torcontrol.clone())
            .unwrap_or_else(|| "127.0.0.1:9051".to_string());
        match torcontrol.parse::<SocketAddr>() {
            Ok(control_addr) => {
                let tor_cfg = bitcoinpr_p2p::TorConfig {
                    control_addr,
                    password: cli.torpassword.clone().or(conf.torpassword.clone()),
                    virtual_port: p2p_port,
                    target_port: p2p_port,
                    key_path: net_dir.join("onion_v3_key"),
                };
                match bitcoinpr_p2p::create_hidden_service(&tor_cfg).await {
                    Ok(hs) => {
                        onion_addr = Some(hs.onion);
                        Some(hs)
                    }
                    Err(e) => {
                        info!("Tor hidden service not established ({e}); continuing without inbound onion");
                        None
                    }
                }
            }
            Err(e) => {
                warn!("Invalid --torcontrol '{torcontrol}': {e}");
                None
            }
        }
    } else {
        None
    };

    // I2P transport (-i2psam): create a SAM STREAM session so the node can reach
    // and be reached over I2P. Best-effort like Tor — a missing/unreachable SAM
    // bridge is logged and skipped, never fatal. The Arc keeps the session (and
    // its .b32.i2p destination) alive for the process lifetime.
    let i2psam = cli.i2psam.clone().or(conf.i2psam.clone());
    let i2p_accept = cli
        .i2pacceptincoming
        .or(conf.i2pacceptincoming)
        .unwrap_or(true);
    let mut i2p_addr: Option<NetAddr> = None;
    let i2p_session = if let Some(sam_str) = i2psam {
        match sam_str.parse::<SocketAddr>() {
            Ok(sam_addr) => {
                let i2p_cfg = bitcoinpr_p2p::I2pConfig {
                    sam_addr,
                    key_path: net_dir.join("i2p_private_key"),
                };
                match bitcoinpr_p2p::create_session(&i2p_cfg).await {
                    Ok(sess) => {
                        i2p_addr = Some(sess.my_addr);
                        Some(Arc::new(sess))
                    }
                    Err(e) => {
                        info!("I2P SAM session not established ({e}); continuing without I2P");
                        None
                    }
                }
            }
            Err(e) => {
                warn!("Invalid --i2psam '{sam_str}': {e}");
                None
            }
        }
    } else {
        None
    };

    // Shared list of our advertised addresses (the IP discovered at runtime,
    // plus the Tor `.onion` / I2P `.b32.i2p` when those transports are up) for
    // getnetworkinfo.
    let local_addresses = Arc::new(std::sync::RwLock::new(Vec::<NetAddr>::new()));
    let onion_service = onion_addr.is_some();
    let i2p_enabled = i2p_session.is_some();
    {
        let mut la = local_addresses.write().expect("lock poisoned");
        if let Some(oa) = onion_addr {
            la.push(oa);
        }
        if let Some(ia) = i2p_addr {
            la.push(ia);
        }
    }
    let net_status = bitcoinpr_rpc::NetStatus {
        disable_ipv6,
        ip_proxy: proxy_config.ip_proxy.map(|a| a.to_string()),
        onion_proxy: proxy_config.onion_proxy.map(|a| a.to_string()),
        proxy_randomize: proxy_config.randomize_credentials,
        onlynet: onlynet.iter().copied().collect(),
        onion_service,
        i2p_enabled,
        local_addresses: local_addresses.clone(),
    };

    let rpc_state = Arc::new(RpcState {
        network,
        params: params.clone(),
        header_index: header_index.clone(),
        utxo_set: Some(utxo_set.clone()),
        mempool: shared_mempool.clone(),
        peers: shared_peers.clone(),
        best_height: shared_best_height.clone(),
        best_hash: shared_best_hash.clone(),
        shutdown_tx: shutdown_tx.clone(),
        block_store: Some(block_store.clone()),
        tx_index: tx_index.clone(),
        auth_header: Some(format!("{rpc_user}:{rpc_password}")),
        start_time: std::time::Instant::now(),
        sig_cache: sig_cache.clone(),
        chain_state: Some(chain_state.clone()),
        bip110_checker,
        command_tx: Some(command_tx.clone()),
        shutting_down: shutting_down.clone(),
        event_bus: Some(event_bus.clone()),
        is_ibd: Some(is_ibd.clone()),
        scripthash_indexed_height: scripthash_indexed_height.clone(),
        prune_target_bytes,
        net_status,
    });

    let rpc_server = RpcServer::new(rpc_state);
    tokio::spawn(async move {
        if let Err(e) = rpc_server.start(rpc_bind, health_bind).await {
            error!("RPC server error: {}", e);
        }
    });

    // Create P2P manager
    let mut peer_manager = PeerManager::with_port(
        network,
        p2p_port,
        params.clone(),
        node_event_tx,
        block_event_tx,
        command_rx,
        connect_addrs,
        shared_mempool.clone(),
        p2p_best_height.clone(),
    );
    // Attach storage so we can serve getheaders / getdata(block) to inbound peers.
    peer_manager.set_chain_storage(header_index.clone(), block_store.clone());
    // BIP 37 / BIP 111: enable serving bloom-filtered connections if requested.
    peer_manager.set_peer_bloom_filters(peerbloomfilters);
    // BIP 159: a pruning node advertises NODE_NETWORK_LIMITED, not NODE_NETWORK.
    peer_manager.set_network_limited(prune_target_bytes.is_some());
    if peerbloomfilters {
        tracing::info!("BIP 37 peer bloom filters enabled (NODE_BLOOM advertised)");
    }
    peer_manager.set_disable_ipv6(disable_ipv6);
    peer_manager.set_v2_transport(v2_transport);
    peer_manager.set_proxy(proxy_config);
    peer_manager.set_onlynet(onlynet);
    peer_manager.set_local_addresses(local_addresses.clone());
    if let Some(sess) = &i2p_session {
        peer_manager.set_i2p_session(sess.clone(), i2p_accept);
    }
    peer_manager.set_gossip_private_addrs(gossip_private_addrs);
    // Load persisted peer state (address book, active bans, anchor peers)
    // before the P2P connect loop starts. Anchors — the outbound peers we
    // were connected to at last shutdown — are re-dialed first on startup,
    // closing the restart-time eclipse window where the node would otherwise
    // bootstrap trust from DNS seeds alone. The state is saved back to
    // <net_dir>/peers.dat + banlist.json periodically and on graceful
    // shutdown (PeerCommand::Shutdown). Corrupt files warn and start fresh.
    peer_manager.load_peer_state(&net_dir);

    // Create header sync — start from header chain tip (may be ahead of validated tip)
    let mut header_tip_height = header_index.get_header_tip_height()?.unwrap_or(best_height);
    let mut header_tip_hash = header_index.get_header_tip()?.unwrap_or(best_hash);

    // Reconcile stored header tip with validated chain state.
    if best_height > header_tip_height {
        // Validated chain is ahead of the stored header tip (e.g. blocks were
        // mined via RPC in a prior session without calling set_header_tip).
        // Advance the stored tip so peers receive correct headers immediately
        // and getblockchaininfo reports the right `headers` value.
        info!(
            chain_height = best_height,
            stored_header_tip = header_tip_height,
            "Startup: validated chain ahead of stored header tip — \
             persisting correct header tip"
        );
        header_index.set_header_tip(&best_hash, best_height)?;
        header_tip_height = best_height;
        header_tip_hash = best_hash;
    } else if header_tip_height > best_height {
        // Stored header tip is ahead of the validated chain.  This is normal
        // during IBD, BUT it can also happen when a peer on a minority fork
        // advertised headers with more cumulative work (e.g. a stale node that
        // is 6 blocks ahead on a different chain).  In that case the
        // height_index entry at `best_height` will have been overwritten with
        // the fork peer's hash, and is_ibd will be permanently stuck `true`
        // because those blocks can never be validated.
        //
        // Detect fork contamination: if the height_index entry at our validated
        // tip does NOT match our validated best_hash, a fork peer has corrupted
        // the header index.  Reset the header tip to our validated chain tip.
        let indexed_at_tip = header_index.get_hash_at_height(best_height);
        let is_fork_contamination = match indexed_at_tip {
            Ok(Some(ref h)) => h != &best_hash,
            // Missing or error — treat conservatively as contaminated only when
            // we are at a non-trivial height (genesis can be missing on first run)
            Ok(None) => best_height > 0,
            Err(_) => false,
        };

        if is_fork_contamination {
            warn!(
                best_height,
                best_hash = %best_hash,
                stored_header_tip = header_tip_height,
                "Startup: header index tip is on a fork chain — \
                 purging fork headers and resetting to validated chain tip"
            );
            header_index
                .reset_fork_header_tip(best_height, &best_hash)
                .map_err(|e| anyhow::anyhow!("reset_fork_header_tip failed: {e}"))?;
            header_tip_height = best_height;
            header_tip_hash = best_hash;
        } else {
            info!(
                chain_height = best_height,
                header_tip = header_tip_height,
                "Startup: header tip is ahead of validated chain (normal IBD)"
            );
        }
    }

    let header_sync = HeaderSync::new(
        params.clone(),
        header_index.clone(),
        header_tip_height,
        header_tip_hash,
    );

    // Create block sync
    let block_sync = BlockSync::new();

    // --- Scripthash Index (optional, requires "indexing" feature) ---
    #[cfg(feature = "indexing")]
    let scripthash_index = if index_enabled {
        let mut idx = bitcoinpr_index::ScripthashIndex::open(&net_dir.join("index"))?;
        // Enable cross-block spend indexing: spends of outputs created in
        // earlier blocks must appear in the spending address's history, else
        // Electrum clients keep treating already-spent coins as UTXOs (and
        // never confirm send-only txs). Requires the tx index to recover the
        // spent prevout's scriptPubKey.
        if let Some(ref tx_idx) = tx_index {
            idx.set_prevout_resolver(tx_idx.clone(), header_index.clone(), block_store.clone());
        } else {
            warn!("Address indexing without --txindex: cross-block spends will not appear in scripthash history; enable --txindex for correct Electrum behaviour");
        }
        let idx = Arc::new(idx);
        info!("Address indexing enabled (--index)");

        // Backfill only when caught up — during IBD the index writes are deferred
        // anyway, and the blocking task keeps the process alive after RPC stop.
        let indexed_height = idx.get_indexed_height()?.unwrap_or(0);
        // Seed the shared atomic so getindexinfo shows the current state immediately.
        if let Some(ref sh) = scripthash_indexed_height {
            sh.store(indexed_height, std::sync::atomic::Ordering::Relaxed);
        }
        let header_tip_for_index = header_index.get_header_tip_height()?.unwrap_or(best_height);
        if indexed_height < best_height && !is_catching_up(best_height, header_tip_for_index) {
            info!(
                indexed_height,
                chain_height = best_height,
                blocks_to_index = best_height - indexed_height,
                "Scripthash index behind chain, starting background backfill..."
            );
            node::spawn_scripthash_backfill(
                idx.clone(),
                header_index.clone(),
                block_store.clone(),
                indexed_height + 1,
                best_height,
                shutting_down.clone(),
                Some(scripthash_backfill_running.clone()),
                scripthash_indexed_height.clone(),
            );
        } else if indexed_height < best_height {
            info!(
                indexed_height,
                chain_height = best_height,
                header_tip = header_tip_for_index,
                "Scripthash backfill deferred until block catch-up completes"
            );
        }

        Some(idx)
    } else {
        None
    };

    // --- Mining Dashboard & Template Provider (optional) ---
    let share_tracker = bitcoinpr_mining::ShareTracker::new();

    // Runtime mining configuration: load mining.toml, then apply CLI/conf overrides
    // (CLI takes precedence). Persist the merged result so the file always exists.
    let mut mining_cfg = bitcoinpr_mining::MiningConfig::load(&net_dir);
    if let Some(addr) = miningaddress.clone() {
        mining_cfg.mining_address = Some(addr);
    }
    mining_cfg.stratum_port = miningport;
    if let Some(tag) = coinbasetag {
        mining_cfg.coinbase_tag = tag.into_bytes();
    }
    if let Some(pn) = poolname {
        mining_cfg.pool_name = pn;
    }
    if let Err(e) = mining_cfg.validate() {
        warn!(
            "Invalid mining config ({e}); continuing with adjusted/default values where possible"
        );
    }
    if mining_enabled {
        if let Err(e) = mining_cfg.save(&net_dir) {
            warn!("Failed to persist mining.toml: {e}");
        }
    }
    let datum_mode = mining_cfg.mode == bitcoinpr_mining::MiningMode::Datum;
    let mining_config = std::sync::Arc::new(tokio::sync::RwLock::new(mining_cfg));
    // Monotonic config-version channel. The Sender is held for the whole daemon
    // lifetime (also handed to the web layer to trigger live reloads via POST
    // /api/mining/config). Keeping it bound prevents watch receivers from seeing a
    // closed channel (which would busy-loop the template provider's select arm).
    let (config_tx, config_rx) = tokio::sync::watch::channel::<u64>(0);
    #[cfg(not(feature = "web"))]
    let _ = &config_tx;

    let datum_client: Option<std::sync::Arc<bitcoinpr_mining::DatumClient>> =
        if mining_enabled && datum_mode {
            let client = std::sync::Arc::new(bitcoinpr_mining::DatumClient::new(
                mining_config.clone(),
                config_rx.clone(),
                share_tracker.clone(),
                event_bus.sender(),
            ));
            let run_client = client.clone();
            tokio::spawn(async move {
                if let Err(e) = run_client.run().await {
                    error!("Datum client error: {}", e);
                }
            });
            info!("Datum protocol client started (template-sovereign pool mining)");
            Some(client)
        } else {
            None
        };

    let mining_dashboard = if mining_enabled {
        Some(Arc::new(bitcoinpr_mining::MiningDashboard::new(
            share_tracker.clone(),
            datum_client.clone(),
        )))
    } else {
        None
    };

    // Note: the "deferred until catch-up completes" message is logged at line
    // 714 (inside the scripthash setup block) only when the backfill is
    // actually deferred. No additional log needed here.
    let shutting_down_ctrl_c = shutting_down.clone();

    // Start Electrum server if indexing is enabled
    #[cfg(feature = "indexing")]
    if let Some(ref idx) = scripthash_index {
        let electrum_state = bitcoinpr_index::electrum::ElectrumState {
            index: idx.clone(),
            header_index: header_index.clone(),
            block_store: block_store.clone(),
            tx_index: tx_index.clone(),
            mempool: shared_mempool.clone(),
            utxo_set: Some(utxo_set.clone()),
            sig_cache: sig_cache.clone(),
            best_height: shared_best_height.clone(),
            params: params.clone(),
            command_tx: Some(command_tx.clone()),
            is_ibd: is_ibd.clone(),
            banner: electrumbanner.clone(),
        };
        let electrum = bitcoinpr_index::ElectrumServer::new(
            electrum_state,
            event_bus.sender(),
            bitcoinpr_index::ElectrumConfig {
                tcp_port: electrumport,
                ssl_port: electrumsslport,
                tls_cert_path: electrumcert.clone().map(std::path::PathBuf::from),
                tls_key_path: electrumkey.clone().map(std::path::PathBuf::from),
                // Persist the auto-generated self-signed keypair next to the
                // other datadir files so TOFU clients keep a stable cert.
                tls_datadir: Some(net_dir.clone()),
            },
        );
        tokio::spawn(async move {
            if let Err(e) = electrum.run().await {
                error!("Electrum server error: {}", e);
            }
        });
    }

    // Start mining gateway if enabled
    if mining_enabled {
        let worker_count = mining_dashboard
            .as_ref()
            .map(|d| d.worker_count())
            .unwrap_or_default();
        // Convert optional difficulty override to compact nBits used for
        // Stratum share-difficulty throttling (mining.set_difficulty).
        // NOTE: this does NOT change the block nBits — templates always use
        // consensus nBits so that all peers (Bitcoin Core, Knots, etc.) accept
        // mined blocks.  The share target controls how often miners submit
        // solutions (e.g. difficulty=70000 → ~1 share per 10 min at 1.5 TH/s).
        let bits_override = miningdifficulty.map(difficulty_to_nbits);
        if let Some(nbits) = bits_override {
            info!(
                difficulty = miningdifficulty.unwrap(),
                share_target_nbits = format!("{:#010x}", nbits),
                "Share difficulty throttle active (block nBits unchanged for peer compatibility)"
            );
        }
        let template_provider = bitcoinpr_mining::TemplateProvider::new(
            params.clone(),
            header_index.clone(),
            shared_mempool.clone(),
            // Pass the shared Arcs directly so submit_mined_block can update
            // getblockchaininfo immediately when a block is mined (the drain loop
            // in main.rs never runs for locally-mined blocks).
            shared_best_height.clone(),
            shared_best_hash.clone(),
            event_bus.sender(),
            share_tracker.clone(),
            miningport,
            mining_config.clone(),
            config_rx.clone(),
            bits_override,
            worker_count,
            is_ibd.clone(),
            Some(chain_state.clone()),
            Some(command_tx.clone()),
            #[cfg(feature = "indexing")]
            scripthash_index.clone(),
            #[cfg(not(feature = "indexing"))]
            None,
            datum_client.clone(),
        );
        if let Some(ref dash) = mining_dashboard {
            let dash = dash.clone();
            tokio::spawn(async move {
                dash.set_gateway_running(true).await;
            });
        }
        tokio::spawn(async move {
            if let Err(e) = template_provider.run().await {
                error!("Mining gateway error: {}", e);
            }
        });
        info!(port = miningport, "Datum mining gateway enabled");
    }

    // Start web server (requires "web" feature)
    #[cfg(feature = "web")]
    let web_peers = {
        let web_state = bitcoinpr_web::WebState {
            network,
            params: params.clone(),
            header_index: header_index.clone(),
            block_store: block_store.clone(),
            utxo_set: utxo_set.clone(),
            tx_index: tx_index.clone(),
            mempool: shared_mempool.clone(),
            scripthash_index: scripthash_index.clone(),
            mining_dashboard: mining_dashboard.clone(),
            event_bus: event_bus.clone(),
            best_height: shared_best_height.clone(),
            best_hash: shared_best_hash.clone(),
            mempool_history: std::sync::Arc::new(tokio::sync::RwLock::new(
                std::collections::VecDeque::new(),
            )),
            peers: Arc::new(tokio::sync::RwLock::new(Vec::new())),
            start_time: std::time::Instant::now(),
            is_ibd: is_ibd.clone(),
            mining_enabled,
            mining_config: Some(mining_config.clone()),
            mining_config_tx: Some(config_tx.clone()),
            datadir: Some(net_dir.clone()),
            blocks_dir: Some(blocks_dir.clone()),
            services: {
                let svc =
                    |name: &str, port: Option<u16>, enabled: bool| bitcoinpr_web::ServiceEntry {
                        name: name.to_string(),
                        port,
                        enabled,
                    };
                let electrum_enabled = scripthash_index.is_some();
                vec![
                    svc("P2P", Some(p2p_port), true),
                    svc("JSON-RPC", Some(rpc_port), true),
                    svc("Web Explorer", Some(webport), true),
                    svc("Electrum TCP", Some(electrumport), electrum_enabled),
                    svc("Electrum SSL", Some(electrumsslport), electrum_enabled),
                    svc("Stratum Mining", Some(miningport), mining_enabled),
                    svc("Transaction Index", None, tx_index.is_some()),
                    svc("Address Index", None, scripthash_index.is_some()),
                ]
            },
            web_admin_token: web_admin_token.clone(),
        };
        let web_peers = web_state.peers.clone();
        let web_server = bitcoinpr_web::WebServer::new(web_state, webport);
        tokio::spawn(async move {
            if let Err(e) = web_server.run().await {
                error!("Web server error: {}", e);
            }
        });
        web_peers
    };

    // Start P2P manager in background
    tokio::spawn(async move {
        peer_manager.run().await;
    });

    // Setup shutdown signal handling: SIGINT (Ctrl-C) and, on unix, SIGTERM.
    // Docker stop/restart sends SIGTERM; without handling it the graceful
    // shutdown block (mempool save, UTXO flush, block-store fsync) never runs.
    let ctrl_c_shutdown = shutdown_tx.clone();
    tokio::spawn(async move {
        #[cfg(unix)]
        {
            use tokio::signal::unix::{signal, SignalKind};
            let mut sigterm = match signal(SignalKind::terminate()) {
                Ok(s) => s,
                Err(e) => {
                    warn!(error = %e, "Failed to install SIGTERM handler; only Ctrl-C will trigger shutdown");
                    // Fall back to waiting on Ctrl-C only.
                    tokio::signal::ctrl_c().await.ok();
                    info!("Received shutdown signal (SIGINT)");
                    shutting_down_ctrl_c.store(true, std::sync::atomic::Ordering::Relaxed);
                    let _ = ctrl_c_shutdown.send(()).await;
                    return;
                }
            };
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {
                    info!("Received shutdown signal (SIGINT)");
                }
                _ = sigterm.recv() => {
                    info!("Received shutdown signal (SIGTERM)");
                }
            }
        }
        #[cfg(not(unix))]
        {
            tokio::signal::ctrl_c().await.ok();
            info!("Received shutdown signal");
        }
        shutting_down_ctrl_c.store(true, std::sync::atomic::Ordering::Relaxed);
        let _ = ctrl_c_shutdown.send(()).await;
    });

    info!(rpc = %rpc_bind, p2p_port, "Node started, waiting for peers");

    let node = Node {
        chain_state,
        header_index,
        block_store,
        utxo_set,
        tx_index,
        shared_mempool,
        sig_cache,
        event_bus,
        shared_best_height,
        shared_best_hash,
        p2p_best_height,
        shared_peers,
        is_ibd,
        shutting_down,
        command_tx,
        params,
        net_dir,
        best_height,
        header_sync,
        block_sync,
        missing_blocks,
        node_event_rx,
        block_event_rx,
        shutdown_rx,
        #[cfg(feature = "indexing")]
        scripthash_index,
        #[cfg(feature = "indexing")]
        scripthash_backfill_running,
        #[cfg(feature = "indexing")]
        scripthash_indexed_height,
        #[cfg(feature = "web")]
        web_peers,
        prune_target_bytes,
    };
    node.run().await
}
