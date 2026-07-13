//! Node event loop: owns the long-lived handles, sync engines, and channel
//! receivers, and drives the headers -> blocks -> replay -> relay pipeline plus
//! periodic maintenance. Extracted verbatim from `main.rs` (decomposition D3).

use bitcoin::p2p::ServiceFlags;
use bitcoinpr_core::{ChainState, ConsensusParams, EventBus, Mempool, NodeNotification};
use bitcoinpr_p2p::{
    count_eligible_download_peers, eligible_download_peer_ids, is_catching_up, stale_base_timeout,
    BlockSync, HeaderSync, NodeEvent, PeerCommand,
};
use bitcoinpr_storage::{BlockStore, HeaderIndex, TxIndex, UtxoSet};
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};
use tracing::{debug, error, info, warn};

/// Max block height span queued in one download batch. Caps how far ahead we
/// request when the chain tip is stalled, reducing orphan pile-up.
const BLOCK_FETCH_HEIGHT_SPAN: u32 = 96;

/// Blocks that arrived before their predecessor was connected, keyed by
/// `prev_blockhash` (the parent each buffered block is waiting for). The
/// optional bytes are the raw wire encoding, kept for cheap re-serialization.
type PendingBlocks = HashMap<bitcoin::BlockHash, VecDeque<(bitcoin::Block, Option<Vec<u8>>)>>;

/// Outcome of one drain-loop block-connect attempt, produced on a blocking
/// thread (M2, 2026-07-02 review) and consumed back on the event loop.
enum DrainStep {
    /// The block is not the next one on the best header chain — skip it.
    Stale {
        expected_height: u32,
        expected_hash: Option<bitcoin::BlockHash>,
    },
    /// Connected; the block comes back for post-connect work (mempool
    /// removal, indexing, relay) along with the new tip.
    Connected {
        block: bitcoin::Block,
        connected_height: u32,
        connected_hash: bitcoin::BlockHash,
    },
    /// Validation failed.
    Failed { expected_height: u32, error: String },
}

/// Byte cap for the pending-block buffer: the old 2048-block count cap
/// allowed 3-6 GB of buffered blocks (plus raw shadows) on a 15 GiB host —
/// a prime OOM contributor.
const MAX_PENDING_BYTES: usize = 256 * 1024 * 1024;

/// Approximate memory footprint of one pending-block entry. Raw wire bytes
/// give the size for free; total_size() (a per-tx walk) is only needed for
/// the rare entry without a raw shadow.
fn pending_entry_size(block: &bitcoin::Block, raw: &Option<Vec<u8>>) -> usize {
    raw.as_ref()
        .map(|r| r.len())
        .unwrap_or_else(|| block.total_size())
}

/// Total bytes currently held in the pending-block buffer.
/// Resident set size of this process in MB, read from `/proc/self/statm`.
/// Returns 0 if the read fails (non-Linux or procfs unavailable).
///
/// Added for the OOM hunt: four IBD runs were OOM-killed at ~15GB anon RSS
/// while every byte-tracked subsystem accounted for <5GB, so the heartbeat
/// now logs whole-process RSS alongside the tracked numbers to expose the
/// untracked growth.
fn process_rss_mb() -> u64 {
    std::fs::read_to_string("/proc/self/statm")
        .ok()
        .and_then(|s| {
            s.split_whitespace()
                .nth(1)
                .and_then(|pages| pages.parse::<u64>().ok())
        })
        // Pages are PAGE_SIZE (4096 on this platform's kernels).
        .map(|pages| pages * 4096 / (1024 * 1024))
        .unwrap_or(0)
}

fn pending_total_bytes(pending: &PendingBlocks) -> usize {
    pending
        .values()
        .flat_map(|q| q.iter())
        .map(|(b, raw)| pending_entry_size(b, raw))
        .sum()
}

/// Handle a full block received from a peer (dedicated block-ingestion path).
#[allow(clippy::too_many_arguments)]
async fn handle_received_block(
    peer_id: u64,
    block: bitcoin::Block,
    raw_bytes: Option<Vec<u8>>,
    block_sync: &mut BlockSync,
    chain_state: &Arc<tokio::sync::Mutex<ChainState>>,
    header_index: &Arc<HeaderIndex>,
    header_sync: &HeaderSync,
    command_tx: &mpsc::Sender<PeerCommand>,
    pending_blocks: &mut PendingBlocks,
    last_orphan_getheaders: &mut std::time::Instant,
) {
    let hash = block.block_hash();
    debug!(peer_id, %hash, "Received block");
    let block_size = raw_bytes.as_ref().map(|b| b.len() as u64).unwrap_or(0);
    block_sync.block_received(&hash, peer_id, block_size);

    let prev = block.header.prev_blockhash;
    let (tip, tip_height) = {
        let cs = chain_state.lock().await;
        (cs.best_hash, cs.best_height)
    };
    if prev != tip {
        debug!(
            %hash,
            block_prev = %prev,
            chain_tip = %tip,
            "Block prev_blockhash != chain tip (buffering)"
        );

        let header_tip = header_index
            .get_header_tip_height()
            .ok()
            .flatten()
            .unwrap_or(header_sync.best_height);
        if header_sync.synced
            && !is_catching_up(tip_height, header_tip)
            && last_orphan_getheaders.elapsed() > std::time::Duration::from_secs(5)
        {
            let cmd = header_sync.build_getheaders_command_from(peer_id, tip, tip_height);
            let _ = command_tx.try_send(cmd);
            *last_orphan_getheaders = std::time::Instant::now();
            info!(
                peer_id,
                block_prev = %prev,
                chain_tip = %tip,
                "Orphan block while synced — fetching headers for reorg detection"
            );
        }
    }
    // Drop blocks that are already connected: the tip+1 shotgun and stale
    // re-requests fetch the same block from several peers, and every copy
    // that arrives after the tip has moved past it would sit in the buffer
    // under a prev-hash key that can never become tip again — dead weight
    // that accumulated until the byte cap evicted LIVE lookahead instead.
    // "Already connected" = its header height is at or below the validated
    // tip AND it lies on the active header chain (both checks together are
    // reorg-safe: a competing side-chain block fails the second test).
    if let Ok(Some(sh)) = header_index.get_header(&hash) {
        if sh.height <= tip_height
            && header_index
                .get_hash_at_height(sh.height)
                .ok()
                .flatten()
                .map(|h| h == hash)
                .unwrap_or(false)
        {
            debug!(%hash, height = sh.height, tip_height, "Dropping already-connected block copy");
            return;
        }
    }

    let queue = pending_blocks.entry(prev).or_default();
    // Dedup: multi-peer shotgun deliveries buffered N copies of the same
    // block, inflating the buffer toward its byte cap for no benefit.
    if queue.iter().any(|(b, _)| b.block_hash() == hash) {
        debug!(%hash, "Duplicate pending block copy dropped");
        return;
    }
    queue.push_back((block, raw_bytes));

    let total_bytes = pending_total_bytes(pending_blocks);
    if total_bytes > MAX_PENDING_BYTES {
        let (cs_tip, cs_tip_height) = {
            let cs = chain_state.lock().await;
            (cs.best_hash, cs.best_height)
        };
        // Evict until back under 75% of the budget (hysteresis so the very
        // next block doesn't immediately re-trigger eviction).
        //
        // Eviction order matters: entries are keyed by prev_blockhash, so
        // during IBD nearly ALL keys are "non-tip" — the buffer is one long
        // chain of lookahead. Priority:
        //   1. keys at or below the validated tip — the tip can never move
        //      back to them, so their blocks are dead weight (late duplicate
        //      deliveries); pure garbage collection
        //   2. keys not in the header index — unconnectable junk
        //   3. keys FURTHEST above the tip — needed last, cheapest to
        //      re-download
        // (Evicting in HashMap iteration order punched random holes in the
        // imminent lookahead; evicting live blocks while dead ones survived
        // collapsed IBD into an eviction/re-download spiral.)
        let target = MAX_PENDING_BYTES * 3 / 4;
        let mut remaining = total_bytes;
        let mut evicted_blocks = 0usize;
        let mut keys: Vec<(bitcoin::BlockHash, Option<u32>)> = pending_blocks
            .keys()
            .copied()
            .filter(|k| *k != cs_tip)
            .map(|k| {
                let height = header_index.get_header(&k).ok().flatten().map(|h| h.height);
                (k, height)
            })
            .collect();
        keys.sort_unstable_by_key(|(_, h)| match h {
            // A key's height is the PREV block's height; blocks under it sit
            // at height+1. Key height < tip height means block <= tip: dead.
            Some(h) if *h < cs_tip_height => (0u8, 0u32),
            None => (1u8, 0u32),
            Some(h) => (2u8, u32::MAX - h),
        });
        for (k, _) in keys {
            if remaining <= target {
                break;
            }
            if let Some(q) = pending_blocks.remove(&k) {
                for (b, raw) in &q {
                    remaining = remaining.saturating_sub(pending_entry_size(b, raw));
                    // CRITICAL: un-mark the evicted block as received.
                    // schedule() skips anything in `received`, and the only
                    // other recovery path (the 120s deep-stall received
                    // clear) never fires while the tip+1 shotgun keeps
                    // connecting a block every ~5s — so leaving the hash in
                    // `received` made evicted blocks permanently
                    // unschedulable and collapsed IBD to shotgun pace
                    // (~12 blocks/min).
                    block_sync.received.remove(&b.block_hash());
                }
                evicted_blocks += q.len();
            }
        }
        warn!(
            evicted_blocks,
            pending_bytes = total_bytes,
            budget_bytes = MAX_PENDING_BYTES,
            "Pending block buffer over byte budget — evicted non-tip chains"
        );
    }
}

/// Spawn a background thread to backfill the scripthash index from
/// `from_height` to `to_height` (inclusive). Reads blocks from the
/// block store and indexes each one. Progress is logged every 1000 blocks.
/// If `running_flag` is provided it is set to `true` on entry and cleared
/// on completion so that the periodic catch-up task can avoid overlapping.
#[cfg(feature = "indexing")]
#[allow(clippy::too_many_arguments)]
pub(crate) fn spawn_scripthash_backfill(
    idx: Arc<bitcoinpr_index::ScripthashIndex>,
    header_index: Arc<HeaderIndex>,
    block_store: Arc<BlockStore>,
    from_height: u32,
    to_height: u32,
    shutting_down: Arc<std::sync::atomic::AtomicBool>,
    running_flag: Option<Arc<std::sync::atomic::AtomicBool>>,
    shared_indexed_height: Option<Arc<std::sync::atomic::AtomicU32>>,
) {
    if let Some(ref flag) = running_flag {
        flag.store(true, std::sync::atomic::Ordering::Relaxed);
    }
    tokio::task::spawn_blocking(move || {
        let mut backfill_count = 0u32;
        let mut skip_count = 0u32;
        let total = to_height - from_height + 1;
        for h in from_height..=to_height {
            if shutting_down.load(std::sync::atomic::Ordering::Relaxed) {
                info!(height = h, indexed = backfill_count, "Scripthash backfill interrupted by shutdown — will resume from last indexed height on next start");
                break;
            }
            let hash = match header_index.get_hash_at_height(h) {
                Ok(Some(hash)) => hash,
                Ok(None) => {
                    warn!(height = h, "Backfill: no header hash at height, skipping");
                    skip_count += 1;
                    continue;
                }
                Err(e) => {
                    warn!(height = h, error = %e, "Backfill: header lookup failed, skipping");
                    skip_count += 1;
                    continue;
                }
            };
            let pos = match header_index.get_block_pos(&hash) {
                Ok(Some(pos)) => pos,
                Ok(None) => {
                    warn!(height = h, %hash, "Backfill: no block position for hash, skipping");
                    skip_count += 1;
                    continue;
                }
                Err(e) => {
                    warn!(height = h, %hash, error = %e, "Backfill: block pos lookup failed, skipping");
                    skip_count += 1;
                    continue;
                }
            };
            let raw = match block_store.read_block(&pos) {
                Ok(raw) => raw,
                Err(e) => {
                    warn!(height = h, %hash, error = %e, "Backfill: block read failed, skipping");
                    skip_count += 1;
                    continue;
                }
            };
            let block = match bitcoin::consensus::encode::deserialize::<bitcoin::Block>(&raw) {
                Ok(block) => block,
                Err(e) => {
                    warn!(height = h, %hash, error = %e, "Backfill: block deserialization failed, skipping");
                    skip_count += 1;
                    continue;
                }
            };
            if let Err(e) = idx.index_block_transactions(&block, h) {
                warn!(height = h, error = %e, "Backfill indexing error");
            }
            if let Some(ref sh) = shared_indexed_height {
                sh.store(h, std::sync::atomic::Ordering::Relaxed);
            }
            backfill_count += 1;
            if backfill_count % 1000 == 0 {
                info!(
                    height = h,
                    indexed = backfill_count,
                    skipped = skip_count,
                    total,
                    "Index backfill progress"
                );
            }
        }
        idx.clear_resolver_cache();
        info!(
            blocks_indexed = backfill_count,
            blocks_skipped = skip_count,
            "Scripthash index backfill complete"
        );
        if let Some(flag) = running_flag {
            flag.store(false, std::sync::atomic::Ordering::Relaxed);
        }
    });
}

/// Handle `NodeEvent::PeerConnected`: register the peer, seed peer-height
/// tracking, and start header sync if nobody is driving it yet.
#[allow(clippy::too_many_arguments)]
async fn handle_peer_connected(
    info: bitcoinpr_p2p::PeerInfo,
    shared_peers: &Arc<RwLock<Vec<bitcoinpr_p2p::PeerInfo>>>,
    chain_state: &Arc<tokio::sync::Mutex<ChainState>>,
    command_tx: &mpsc::Sender<PeerCommand>,
    header_sync: &HeaderSync,
    header_sync_peer: &mut Option<u64>,
    getheaders_in_flight: &mut bool,
    #[cfg(feature = "web")] web_peers: &Arc<RwLock<Vec<bitcoinpr_web::PeerEntry>>>,
) {
    let is_archive = info.services.has(ServiceFlags::NETWORK);
    debug!(
        peer_id = info.id,
        addr = %info.addr,
        height = info.start_height,
        user_agent = %info.user_agent,
        archive = is_archive,
        services = %info.services,
        "Peer connected"
    );

    // Update shared peer list
    shared_peers.write().await.push(info.clone());

    // Track best peer height for sync progress display.
    // Guard against peers with non-positive or bogus start_height (e.g. -1 → u32::MAX).
    // Only trust peer claims BEFORE header sync completes: start_height is an
    // unauthenticated version-message field, and a single lying peer (observed
    // claiming ~2× the real chain height) poisons the progress denominator for
    // the whole run. Once synced, the PoW-backed header tip is authoritative
    // and the main loop keeps peer_best_height pinned to it.
    if !header_sync.synced && info.start_height > 0 {
        let mut cs = chain_state.lock().await;
        let current_best = cs.peer_best_height.unwrap_or(0);
        if (info.start_height as u32) > current_best {
            cs.peer_best_height = Some(info.start_height as u32);
        }
    }

    // Update web peers list
    #[cfg(feature = "web")]
    {
        let mut wp = web_peers.write().await;
        wp.push(bitcoinpr_web::PeerEntry {
            id: info.id,
            addr: info.addr.to_string(),
            network: info.addr.network().as_str().to_string(),
            version: info.version,
            subver: info.user_agent.clone(),
            start_height: info.start_height,
            synced_height: info.start_height,
        });
    }

    // Start header sync if no peer is currently driving it.
    // Only pick peers that report a height AT OR ABOVE our current header
    // tip — peers with height=0 are pruned/light clients, and peers below
    // our tip (e.g. other IBD nodes) have no headers to give us. A peer at
    // exactly our height is fine: when we restart already at the network
    // tip, every peer reports our height, and its empty headers reply
    // truthfully completes sync (further guarded by the min-chain-work
    // check). Requiring strictly-above left sync driverless at the tip,
    // spamming the 30s stall detector for minutes after startup.
    if header_sync_peer.is_none()
        && !header_sync.synced
        && info.start_height > 0
        && (info.start_height as i64) >= header_sync.best_height as i64
    {
        let cmd = header_sync.build_getheaders_command(info.id);
        let _ = command_tx.try_send(cmd);
        *header_sync_peer = Some(info.id);
        *getheaders_in_flight = true;
        info!(
            peer_id = info.id,
            height = info.start_height,
            "Starting header sync"
        );
    }
}

/// Handle `NodeEvent::PeerDisconnected`: drop the peer, reassign its in-flight
/// blocks, and release the header-sync slot if it was the sync driver.
#[allow(clippy::too_many_arguments)]
async fn handle_peer_disconnected(
    peer_id: u64,
    shared_peers: &Arc<RwLock<Vec<bitcoinpr_p2p::PeerInfo>>>,
    chain_state: &Arc<tokio::sync::Mutex<ChainState>>,
    header_index: &Arc<HeaderIndex>,
    command_tx: &mpsc::Sender<PeerCommand>,
    block_sync: &mut BlockSync,
    header_sync: &mut HeaderSync,
    header_sync_peer: &mut Option<u64>,
    #[cfg(feature = "web")] web_peers: &Arc<RwLock<Vec<bitcoinpr_web::PeerEntry>>>,
) {
    debug!(peer_id, "Peer disconnected");
    // Drop any unconnecting-headers strike counter so the map only tracks
    // connected peers.
    header_sync.reset_unconnecting(peer_id);
    shared_peers.write().await.retain(|p| p.id != peer_id);
    #[cfg(feature = "web")]
    web_peers.write().await.retain(|p| p.id != peer_id);
    // Re-queue any blocks assigned to this peer so they can
    // be reassigned to remaining healthy peers.
    block_sync.peer_disconnected(peer_id);
    if !block_sync.queue.is_empty() {
        let peers = shared_peers.read().await;
        let block_h = chain_state.lock().await.best_height;
        let header_tip = header_index
            .get_header_tip_height()
            .ok()
            .flatten()
            .unwrap_or(block_h);
        let peer_ids = eligible_download_peer_ids(&peers, block_h, header_tip);
        drop(peers);
        if !peer_ids.is_empty() {
            let cmds = block_sync.assign_to_peers(&peer_ids);
            for cmd in cmds {
                let _ = command_tx.try_send(cmd);
            }
        }
    }
    // If the header-sync peer left before sync finished, allow
    // the next connected peer to take over.
    if *header_sync_peer == Some(peer_id) && !header_sync.synced {
        info!(
            peer_id,
            "Header sync peer disconnected, will retry with next peer"
        );
        *header_sync_peer = None;
    }
}

/// Handle `NodeEvent::NotFound`: re-queue best-chain blocks a peer could not
/// serve, abandon truly-orphaned ones, and reassign to other peers.
#[allow(clippy::too_many_arguments)]
async fn handle_notfound(
    peer_id: u64,
    inv: Vec<bitcoin::p2p::message_blockdata::Inventory>,
    shared_peers: &Arc<RwLock<Vec<bitcoinpr_p2p::PeerInfo>>>,
    chain_state: &Arc<tokio::sync::Mutex<ChainState>>,
    header_index: &Arc<HeaderIndex>,
    command_tx: &mpsc::Sender<PeerCommand>,
    block_sync: &mut BlockSync,
    pending_blocks: &mut PendingBlocks,
) {
    use bitcoin::p2p::message_blockdata::Inventory;
    let block_hashes: Vec<bitcoin::BlockHash> = inv
        .iter()
        .filter_map(|i| match i {
            Inventory::Block(h) | Inventory::WitnessBlock(h) => Some(*h),
            _ => None,
        })
        .collect();
    if !block_hashes.is_empty() {
        let live_peers = {
            let p = shared_peers.read().await;
            let block_h = chain_state.lock().await.best_height;
            let header_tip = header_index
                .get_header_tip_height()
                .ok()
                .flatten()
                .unwrap_or(block_h);
            count_eligible_download_peers(&p, block_h, header_tip)
        };
        let (requeued, abandoned) = block_sync.blocks_not_found(peer_id, &block_hashes, live_peers);
        // Abandonment is for truly-orphaned blocks (a peer's
        // block at height H superseded by our chain). But a
        // block that sits on our current best-HEADER chain is
        // one we genuinely need: it must never be dropped just
        // because the lone carrier (e.g. core during a churn
        // window) was briefly the only eligible peer. Re-queue
        // those for retry; only drop hashes not on the best chain.
        let mut rescheduled_on_chain = false;
        for hash in &abandoned {
            let on_best_chain = match header_index.get_header(hash) {
                Ok(Some(stored)) => {
                    header_index
                        .get_hash_at_height(stored.height)
                        .ok()
                        .flatten()
                        == Some(*hash)
                }
                _ => false,
            };
            if on_best_chain {
                block_sync.schedule(vec![*hash]);
                rescheduled_on_chain = true;
                debug!(
                    block = %hash,
                    "notfound for best-chain block — re-queuing instead of abandoning"
                );
            } else {
                pending_blocks.remove(hash);
                warn!(
                    peer_id,
                    block = %hash,
                    "Abandoning orphaned block — notfound by all peers, \
                     removing from pipeline"
                );
            }
        }
        if requeued > abandoned.len() || rescheduled_on_chain {
            warn!(
                peer_id,
                requeued,
                abandoned = abandoned.len(),
                "Peer sent notfound for blocks, re-queuing"
            );
            // Immediately reassign to other peers (exclude the notfound peer)
            let peers = shared_peers.read().await;
            let block_h = chain_state.lock().await.best_height;
            let header_tip = header_index
                .get_header_tip_height()
                .ok()
                .flatten()
                .unwrap_or(block_h);
            let peer_ids: Vec<u64> = eligible_download_peer_ids(&peers, block_h, header_tip)
                .into_iter()
                .filter(|id| *id != peer_id)
                .collect();
            drop(peers);
            if !peer_ids.is_empty() {
                let cmds = block_sync.assign_to_peers(&peer_ids);
                for cmd in cmds {
                    let _ = command_tx.try_send(cmd);
                }
            }
        }
    }
}

/// Handle `NodeEvent::BlockInv`: refresh the announcing peer's synced height
/// from the inv'd block hashes (peers that relay via inv, not headers).
async fn handle_block_inv(
    peer_id: u64,
    block_hashes: Vec<bitcoin::BlockHash>,
    header_index: &Arc<HeaderIndex>,
    shared_peers: &Arc<RwLock<Vec<bitcoinpr_p2p::PeerInfo>>>,
    #[cfg(feature = "web")] web_peers: &Arc<RwLock<Vec<bitcoinpr_web::PeerEntry>>>,
) {
    // A peer announcing block hashes via inv signals it has
    // those blocks, even when it never sends a `headers`
    // announcement (e.g. a peer that received a block FROM us
    // and echoes it back via inv).  Resolve the announced
    // hashes to heights and refresh the web peer's synced
    // height so the dashboard reflects reality.
    let mut best_h: i32 = -1;
    for hash in &block_hashes {
        if let Ok(Some(stored)) = header_index.get_header(hash) {
            let h = stored.height as i32;
            if h > best_h {
                best_h = h;
            }
        }
    }
    if best_h >= 0 {
        let mut peers = shared_peers.write().await;
        if let Some(entry) = peers.iter_mut().find(|p| p.id == peer_id) {
            if best_h > entry.synced_height {
                entry.synced_height = best_h;
            }
        }
    }
    #[cfg(feature = "web")]
    if best_h >= 0 {
        let mut wp = web_peers.write().await;
        if let Some(entry) = wp.iter_mut().find(|e| e.id == peer_id) {
            if best_h > entry.synced_height {
                entry.synced_height = best_h;
            }
        }
    }
}

/// Handle `NodeEvent::Transaction`: validate inputs/finality and admit the tx
/// to the mempool (and relay it) when not in IBD.
#[allow(clippy::too_many_arguments)]
async fn handle_transaction(
    peer_id: u64,
    tx: bitcoin::Transaction,
    is_ibd: &Arc<std::sync::atomic::AtomicBool>,
    shared_mempool: &Arc<RwLock<Mempool>>,
    utxo_set: &Arc<UtxoSet>,
    chain_state: &Arc<tokio::sync::Mutex<ChainState>>,
    header_index: &Arc<HeaderIndex>,
    params: &ConsensusParams,
    sig_cache: &Arc<bitcoinpr_core::SigCache>,
    event_bus: &Arc<EventBus>,
    command_tx: &mpsc::Sender<PeerCommand>,
) {
    let txid = tx.compute_txid();
    debug!(peer_id, %txid, "Received transaction");

    if is_ibd.load(std::sync::atomic::Ordering::Relaxed) {
        debug!(peer_id, %txid, "tx rejected: node is in IBD (not accepting mempool txs yet)");
    } else {
        // Resolve each input from the chain UTXO set first, then
        // fall back to outputs created by another unconfirmed tx
        // already in our mempool (chained / package relay). A tx
        // whose parent we haven't seen is dropped — but with a
        // logged reason, never silently.
        let mut missing_input: Option<bitcoin::OutPoint> = None;
        {
            let mempool = shared_mempool.read().await;
            for input in &tx.input {
                let in_chain = matches!(utxo_set.get(&input.previous_output), Ok(Some(_)));
                if in_chain {
                    continue;
                }
                // Is the prevout an output of a tx already in the mempool?
                let in_mempool = mempool
                    .get(&input.previous_output.txid)
                    .map(|e| (input.previous_output.vout as usize) < e.tx.output.len())
                    .unwrap_or(false);
                if !in_mempool {
                    missing_input = Some(input.previous_output);
                    break;
                }
            }
        }
        if let Some(prevout) = missing_input {
            debug!(
                peer_id, %txid,
                prevout = %prevout,
                "tx rejected: input not found in chain UTXO set or mempool \
                 (missing-inputs / orphan tx)"
            );
        } else {
            // Finality/sequence-lock context: the tx must
            // be valid in the next block (tip+1, tip MTP).
            let (tip_height, tip_hash, bip110) = {
                let cs = chain_state.lock().await;
                // BIP-110 deployment state for the next block, so the mempool
                // rejects transactions our own block validation would reject.
                let bip110 = cs.bip110_activation(&cs.best_hash, cs.best_height + 1);
                (cs.best_height, cs.best_hash, bip110)
            };
            // M2 (2026-07-02 review): add_transaction does ECDSA/Schnorr
            // verification (rayon-parallel for multi-input txs) while
            // holding the mempool write lock — run it on a blocking thread
            // so RPC/Electrum/web consumers of the lock stall behind a
            // blocking-pool thread, not a pinned tokio worker.
            let mempool_arc = shared_mempool.clone();
            let utxo = utxo_set.clone();
            let hi = header_index.clone();
            let params_owned = params.clone();
            let sig_cache_arc = sig_cache.clone();
            let tx_for_task = tx.clone();
            let added = tokio::task::spawn_blocking(move || {
                let chain_ctx =
                    bitcoinpr_core::MempoolChainContext::at_tip(&hi, tip_height, &tip_hash)
                        .with_bip110(bip110);
                let mut mempool = mempool_arc.blocking_write();
                if mempool.contains(&txid) {
                    return Ok(false);
                }
                let flags = bitcoinpr_core::ScriptFlags::all();
                mempool
                    .add_transaction(
                        tx_for_task,
                        &utxo,
                        flags,
                        &params_owned,
                        Some(sig_cache_arc.as_ref()),
                        &chain_ctx,
                    )
                    .map(|_| true)
            })
            .await
            .expect("mempool accept task panicked");

            match added {
                Ok(true) => {
                    debug!(%txid, "Added to mempool");
                    event_bus.publish(NodeNotification::NewTx {
                        txid: txid.to_string(),
                    });
                    let _ = command_tx.try_send(PeerCommand::BroadcastTx(tx));
                }
                Ok(false) => {} // already in mempool
                Err(e) => {
                    debug!(peer_id, %txid, "tx rejected: {}", e);
                }
            }
        }
    }
}

/// How the node is currently acquiring blocks for the validated chain.
///
/// Replaces the loop-local `replay_active: bool` + `replay_end_height: u32`
/// pair (decomposition step D4). The end height is only meaningful while a
/// replay is in progress, so encoding it inside the `Replay` variant makes the
/// illegal "inactive but with a stale end height" state unrepresentable.
///
/// This models only the block-acquisition phase. Header sync is tracked
/// separately by `header_sync.synced` (a field on the p2p `HeaderSync`), and
/// "caught up to the network" by the cross-crate `is_ibd` latch; both remain
/// the authoritative signals they already were — this enum does not subsume
/// them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SyncState {
    /// Acquiring blocks from peers (the normal path), or fully caught up.
    Download,
    /// Replaying blocks already on local disk, up to and including
    /// `end_height`, instead of re-downloading them from peers.
    Replay { end_height: u32 },
}

impl SyncState {
    /// True while a local-disk replay is in progress (the old `replay_active`).
    fn is_replaying(self) -> bool {
        matches!(self, SyncState::Replay { .. })
    }
}

/// Owns every long-lived handle, sync engine, and channel receiver the main
/// event loop needs. Built once in `main()` after service wiring; `run()`
/// consumes it, unpacks the fields into loop-locals, and drives the node until
/// shutdown. Fields are unpacked verbatim so the loop body matches the original
/// `main()` line for line (decomposition step D3 — no behaviour change).
pub(crate) struct Node {
    pub(crate) chain_state: Arc<tokio::sync::Mutex<ChainState>>,
    pub(crate) header_index: Arc<HeaderIndex>,
    pub(crate) block_store: Arc<BlockStore>,
    pub(crate) utxo_set: Arc<UtxoSet>,
    pub(crate) tx_index: Option<Arc<TxIndex>>,
    pub(crate) shared_mempool: Arc<RwLock<Mempool>>,
    pub(crate) sig_cache: Arc<bitcoinpr_core::SigCache>,
    pub(crate) event_bus: Arc<EventBus>,
    pub(crate) shared_best_height: Arc<RwLock<u32>>,
    pub(crate) shared_best_hash: Arc<RwLock<bitcoin::BlockHash>>,
    pub(crate) p2p_best_height: Arc<std::sync::RwLock<i32>>,
    pub(crate) shared_peers: Arc<RwLock<Vec<bitcoinpr_p2p::PeerInfo>>>,
    pub(crate) is_ibd: Arc<std::sync::atomic::AtomicBool>,
    pub(crate) shutting_down: Arc<std::sync::atomic::AtomicBool>,
    pub(crate) command_tx: mpsc::Sender<PeerCommand>,
    pub(crate) params: ConsensusParams,
    pub(crate) net_dir: std::path::PathBuf,
    /// Validated tip height at startup; seeds the header-progress stall tracker.
    pub(crate) best_height: u32,
    pub(crate) header_sync: HeaderSync,
    pub(crate) block_sync: BlockSync,
    pub(crate) missing_blocks: Vec<u32>,
    pub(crate) node_event_rx: mpsc::Receiver<NodeEvent>,
    pub(crate) block_event_rx: mpsc::Receiver<NodeEvent>,
    pub(crate) shutdown_rx: mpsc::Receiver<()>,
    #[cfg(feature = "indexing")]
    pub(crate) scripthash_index: Option<Arc<bitcoinpr_index::ScripthashIndex>>,
    #[cfg(feature = "indexing")]
    pub(crate) scripthash_backfill_running: Arc<std::sync::atomic::AtomicBool>,
    #[cfg(feature = "indexing")]
    pub(crate) scripthash_indexed_height: Option<Arc<std::sync::atomic::AtomicU32>>,
    #[cfg(feature = "web")]
    pub(crate) web_peers: Arc<RwLock<Vec<bitcoinpr_web::PeerEntry>>>,
    /// Block-file prune target in bytes (`--prune <MiB>`); `None` disables
    /// pruning. See `bitcoinpr_storage::prune`.
    pub(crate) prune_target_bytes: Option<u64>,
}

impl Node {
    /// Drive the node event loop to completion (until shutdown is signalled),
    /// then run the graceful-shutdown flush sequence. The body below is moved
    /// verbatim from the original `main()`; the only change is that the handles
    /// arrive as struct fields and are unpacked into locals here.
    pub(crate) async fn run(self) -> anyhow::Result<()> {
        let Node {
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
            mut header_sync,
            mut block_sync,
            mut missing_blocks,
            mut node_event_rx,
            mut block_event_rx,
            mut shutdown_rx,
            #[cfg(feature = "indexing")]
            scripthash_index,
            #[cfg(feature = "indexing")]
            scripthash_backfill_running,
            #[cfg(feature = "indexing")]
            scripthash_indexed_height,
            #[cfg(feature = "web")]
            web_peers,
            prune_target_bytes,
        } = self;

        // `tx_index` is consumed only by the indexing-gated catch-up below, so
        // it reads as unused when the `indexing` feature is off.
        #[cfg(not(feature = "indexing"))]
        let _ = &tx_index;

        // Load persisted mempool
        let mempool_path = net_dir.join("mempool.dat");
        if mempool_path.exists() {
            if let Ok(data) = std::fs::read(&mempool_path) {
                let flags = bitcoinpr_core::ScriptFlags::all();
                // Re-check nLockTime / BIP 68 finality against the current tip:
                // a tx persisted before shutdown may still not be final now.
                let (tip_height, tip_hash) = {
                    let cs = chain_state.lock().await;
                    (cs.best_height, cs.best_hash)
                };
                let chain_ctx = bitcoinpr_core::MempoolChainContext::at_tip(
                    &header_index,
                    tip_height,
                    &tip_hash,
                );
                let mut mempool = tokio::task::block_in_place(|| shared_mempool.blocking_write());
                mempool.load_from_bytes(&data, &utxo_set, flags, &params, &chain_ctx);
            }
        }

        // Track which peer is currently driving header sync.
        // Reset to None when that peer disconnects so the next peer takes over.
        let mut header_sync_peer: Option<u64> = None;
        // True after we've sent getheaders and received at least one batch of headers.
        // Used to distinguish a getheaders "caught up" empty response from a
        // sendheaders acknowledgment (which also sends empty headers).
        let mut getheaders_in_flight: bool = false;
        let mut blocks_validated: u64 = 0;
        let mut last_block_connect = std::time::Instant::now();
        let mut last_stale_clear = std::time::Instant::now();
        // Consecutive stale-clear cycles with no block delivered in between.
        // Drives exponential backoff of the stale-clear debounce so a
        // genuinely dead pipeline doesn't hammer peers with re-requests.
        let mut consecutive_stale_clears: u32 = 0;
        let mut last_diagnostic = std::time::Instant::now();
        let mut last_block_rerequest =
            std::time::Instant::now() - std::time::Duration::from_secs(60);
        let mut last_hol_rerequest = std::time::Instant::now();
        // Rate-limit getheaders requests triggered by orphan blocks.
        // Initialised to 30 s in the past so the first orphan fires immediately.
        let mut last_orphan_getheaders =
            std::time::Instant::now() - std::time::Duration::from_secs(30);

        let mut last_expiry_check = std::time::Instant::now();
        let mut last_ping = std::time::Instant::now();
        // Prune tick bookkeeping (only consulted when --prune is set).
        let mut last_prune_check = std::time::Instant::now();
        let prune_running = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        // Track whether an index catch-up is running so we don't start a second one.
        let index_catchup_running = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        // Rate-limits the index catch-up scan below; only the indexing build
        // reads it (cfg-gated so featureless builds see no unused variable).
        // Initialised 10 s in the past so the first check fires immediately.
        #[cfg(feature = "indexing")]
        let mut last_index_catchup = std::time::Instant::now() - std::time::Duration::from_secs(10);
        // Buffer for blocks that arrived before their predecessor was connected.
        // Key: prev_blockhash (what this block needs as its parent).
        let mut pending_blocks: PendingBlocks = HashMap::new();

        // Async block-acquisition phase: Replay { end_height } streams blocks
        // already on local disk in small batches (100 per tick) so P2P messages
        // keep flowing; Download acquires them from peers. See SyncState.
        let mut sync_state = SyncState::Download;
        // Counts consecutive catch-up cycles where header sync completed at the
        // same height despite peers claiming a higher chain.  After a few rounds
        // we clamp those peers' start_height down so the loop stops.
        let mut catchup_stall_count: u32 = 0;
        let mut catchup_stall_height: u32 = 0;
        // Last validated tip we broadcast a post-replay getheaders for.  Used to
        // suppress repeat broadcasts when replay ends at the same height twice in
        // a row (which otherwise produces a tight CPU-spinning loop during deep
        // IBD: every getheaders response triggers another replay → another
        // broadcast → another response → ...).
        let mut last_post_replay_getheaders_height: Option<u32> = None;
        // Guard: only run block file reindex once per session to avoid repeated
        // 17-minute scans on every header sync completion.
        let mut reindex_done_this_session = false;
        // Debounce replay scheduling when local replay finds no on-disk blocks.
        let mut last_zero_replay_end =
            std::time::Instant::now() - std::time::Duration::from_secs(120);
        let mut last_aggressive_peer_refresh =
            std::time::Instant::now() - std::time::Duration::from_secs(120);
        let mut last_hol_escalation =
            std::time::Instant::now() - std::time::Duration::from_secs(300);
        // Debounce for slow-circuit eviction (relatively-slow block deliverers
        // are disconnected during deep IBD so the redial can draw a fresh —
        // hopefully faster — Tor circuit via proxyrandomize).
        let mut last_slow_circuit_evict =
            std::time::Instant::now() - std::time::Duration::from_secs(120);

        // Track per-block failure counts to break infinite retry loops when a
        // block keeps failing validation. After MAX_BLOCK_RETRIES failures we
        // drop the block, ban the sender, and wait for the chain to resolve.
        let mut block_failure_counts: HashMap<bitcoin::BlockHash, u32> = HashMap::new();
        const MAX_BLOCK_RETRIES: u32 = 5;

        // Periodic tick so the loop wakes up even when no P2P events arrive.
        // This ensures keepalive pings and header sync retries always fire.
        let mut maintenance_interval =
            tokio::time::interval(tokio::time::Duration::from_millis(100));
        maintenance_interval.tick().await; // consume the immediate first tick

        // Track header sync progress so we can detect and recover from stalls.
        let mut last_header_height = best_height;
        let mut last_header_progress = std::time::Instant::now();
        // Last header-tip value pinned into ChainState::peer_best_height (the
        // sync-progress denominator). Shadow copy so the maintenance loop only
        // takes the chain-state lock when the header tip actually changes.
        let mut last_progress_denominator: u32 = 0;

        // Sync heartbeat: a detached task that logs once a minute regardless
        // of event-loop state. It distinguishes three situations that used to
        // be indistinguishable log silence: (a) normal sync between 1000-block
        // milestones (heartbeat with height + rate, debug level), (b) a long
        // validation / UTXO flush holding the chain-state lock ("busy"
        // heartbeat, warn level), and (c) a wedged runtime (no heartbeat at
        // all). Run with --loglevel debug to see the periodic line.
        // Approximate bytes held by `pending_blocks`, mirrored into an atomic
        // by the main loop so the detached heartbeat task can report it.
        let pending_bytes_gauge = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        {
            let chain_state = chain_state.clone();
            let shutting_down = shutting_down.clone();
            let pending_bytes_gauge = pending_bytes_gauge.clone();
            tokio::spawn(async move {
                let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(60));
                interval.tick().await; // consume the immediate first tick
                let mut last_height: Option<u32> = None;
                loop {
                    interval.tick().await;
                    if shutting_down.load(std::sync::atomic::Ordering::Relaxed) {
                        break;
                    }
                    // RSS is read and logged in BOTH branches: memory peaks
                    // during flush/validation, which is exactly when the
                    // chain-state lock times out — the busy branch must not
                    // go blind.
                    let rss_mb = process_rss_mb();
                    let pending_mb = pending_bytes_gauge.load(std::sync::atomic::Ordering::Relaxed)
                        / (1024 * 1024);
                    match tokio::time::timeout(
                        tokio::time::Duration::from_secs(1),
                        chain_state.lock(),
                    )
                    .await
                    {
                        Ok(cs) => {
                            let height = cs.best_height;
                            let utxo_set = cs.utxo_set.clone();
                            drop(cs);
                            // memory_stats never blocks: write-buffer fields
                            // come back None if a flush holds the mutex.
                            let stats = utxo_set.memory_stats();
                            let (wb_mb, wb_inserts, wb_deletions) = match stats.write_buffer {
                                Some((bytes, ins, del)) => {
                                    (Some(bytes / (1024 * 1024)), Some(ins), Some(del))
                                }
                                None => (None, None, None),
                            };
                            let blocks_per_min = last_height.map(|h| height.saturating_sub(h));
                            debug!(
                                height,
                                blocks_per_min,
                                rss_mb,
                                pending_mb,
                                wb_mb,
                                wb_inserts,
                                wb_deletions,
                                utxo_cache_entries = stats.cache_entries,
                                memtables_mb = stats.memtable_bytes / (1024 * 1024),
                                block_cache_mb = stats.block_cache_bytes / (1024 * 1024),
                                "Sync heartbeat"
                            );
                            last_height = Some(height);
                        }
                        Err(_) => {
                            warn!(
                                rss_mb,
                                pending_mb,
                                "Sync heartbeat: chain state busy >1s (validation or flush in progress)"
                            );
                        }
                    }
                }
            });
        }

        // Main event loop
        loop {
            // Check shutdown flag before entering select — the RPC `stop`
            // command sets this atomically, so we catch it even if the
            // channel-based shutdown_rx was missed on a prior select iteration.
            if shutting_down.load(std::sync::atomic::Ordering::Relaxed) {
                info!("Shutting down...");
                let _ = command_tx.try_send(PeerCommand::Shutdown);
                break;
            }

            // While header sync is active, keep the sync peer's connection
            // free of block downloads: a getheaders response queued behind
            // ~50MB of in-flight block data stalls header sync for the whole
            // transfer. Refreshed every loop iteration so it tracks sync-peer
            // rotation. BlockSync ignores this if it's the only peer.
            block_sync.excluded_peer = if header_sync.synced {
                None
            } else {
                header_sync_peer
            };

            // Defer block download until the best header chain has the
            // network's minimum chain work (Bitcoin Core's nMinimumChainWork):
            // headers then sync on quiet connections in minutes instead of
            // competing with ~50MB block batches. Monotonic — the gate only
            // ever opens here (initial state is set at startup). Re-pausing
            // on a work drop wedged the node once: a header stored with
            // corrupt (near-zero) cumulative work collapsed best_chain_work
            // mid-run, silently re-closed the gate, and block download froze
            // at the tip with a full queue.
            if block_sync.download_paused && header_sync.has_min_chain_work() {
                info!(
                    height = header_sync.best_height,
                    "Minimum chain work reached — starting block download"
                );
                block_sync.download_paused = false;
            }

            tokio::select! {
                biased;
                _ = shutdown_rx.recv() => {
                    info!("Shutting down...");
                    shutting_down.store(true, std::sync::atomic::Ordering::Relaxed);
                    let _ = command_tx.try_send(PeerCommand::Shutdown);
                    break;
                }
                _ = maintenance_interval.tick() => {
                    // Periodic wakeup — maintenance runs below.
                }
                Some(event) = block_event_rx.recv() => {
                    if let NodeEvent::Block(peer_id, block, raw_bytes) = event {
                        handle_received_block(
                            peer_id,
                            block,
                            raw_bytes,
                            &mut block_sync,
                            &chain_state,
                            &header_index,
                            &header_sync,
                            &command_tx,
                            &mut pending_blocks,
                            &mut last_orphan_getheaders,
                        )
                        .await;
                    }
                }
                Some(event) = node_event_rx.recv() => {
                    match event {
                        NodeEvent::PeerConnected(info) => {
                            handle_peer_connected(
                                info,
                                &shared_peers,
                                &chain_state,
                                &command_tx,
                                &header_sync,
                                &mut header_sync_peer,
                                &mut getheaders_in_flight,
                                #[cfg(feature = "web")]
                                &web_peers,
                            )
                            .await;
                        }
                        NodeEvent::PeerDisconnected(peer_id) => {
                            handle_peer_disconnected(
                                peer_id,
                                &shared_peers,
                                &chain_state,
                                &header_index,
                                &command_tx,
                                &mut block_sync,
                                &mut header_sync,
                                &mut header_sync_peer,
                                #[cfg(feature = "web")]
                                &web_peers,
                            )
                            .await;
                        }
                        NodeEvent::Headers(peer_id, headers) => {
                            // Ignore empty headers from non-sync peers — but DON'T
                            // use `continue` here as it skips the maintenance/drain
                            // section below the select!, which can cause stalls.
                            if headers.is_empty() && header_sync_peer != Some(peer_id) {
                                debug!(peer_id, "Ignoring empty headers from non-sync peer");
                            } else {
                            // Empty headers from sync peer: only mark synced if we
                            // had a getheaders in flight (not a sendheaders ack).
                            if headers.is_empty() && header_sync_peer == Some(peer_id) {
                                if getheaders_in_flight {
                                    // Cross-check against the peer's claimed height before
                                    // declaring completion. A peer whose best-known height is
                                    // far ABOVE our tip yet answers our getheaders with an
                                    // empty message is either broken or was picked while
                                    // itself syncing — trusting it falsely completes header
                                    // sync hundreds of thousands of blocks early. Release the
                                    // sync slot so another peer takes over instead.
                                    let peer_claimed_height = {
                                        let peers = shared_peers.read().await;
                                        peers
                                            .iter()
                                            .find(|p| p.id == peer_id)
                                            .map(|p| p.start_height as i64)
                                            .unwrap_or(0)
                                    };
                                    if peer_claimed_height > header_sync.best_height as i64 + 2 {
                                        warn!(
                                            peer_id,
                                            peer_claimed_height,
                                            height = header_sync.best_height,
                                            "Sync peer claims higher chain but sent empty headers — rotating sync peer"
                                        );
                                        header_sync_peer = None;
                                        getheaders_in_flight = false;
                                    } else if !header_sync.has_min_chain_work() {
                                        // Never complete header sync below the network's
                                        // minimum chain work — the peer is on a low-work
                                        // chain or lying. Rotate to another peer.
                                        warn!(
                                            peer_id,
                                            height = header_sync.best_height,
                                            "Sync peer sent empty headers below minimum chain work — rotating sync peer"
                                        );
                                        header_sync_peer = None;
                                        getheaders_in_flight = false;
                                    } else {
                                    header_sync.synced = true;
                                    getheaders_in_flight = false;
                                    info!(height = header_sync.best_height, "Header sync complete");
                                    // The peer responded to our getheaders meaning they are at
                                    // least at our current tip.  Refresh start_height so
                                    // block-fetch assignment (which filters start_height > 0)
                                    // can immediately use this peer.  This handles the common
                                    // regtest startup case where both nodes start at genesis
                                    // and the peer's handshake height was 0.
                                    let new_h = header_sync.best_height as i32;
                                    let mut peers = shared_peers.write().await;
                                    if let Some(peer) = peers.iter_mut().find(|p| p.id == peer_id) {
                                        if new_h > peer.start_height {
                                            peer.start_height = new_h;
                                        }
                                    }
                                    }
                                } else {
                                    debug!(peer_id, "Ignoring empty headers (sendheaders ack)");
                                }
                                // Fall through to process_headers which returns Ok(0)
                            }
                            // Update the announcing peer's known height from any
                            // non-empty headers message (feeds getpeerinfo
                            // synced_headers/synced_blocks and the web Peers page).
                            // Must run before process_headers because the headers vec
                            // is moved into it; do the index lookup on the last hash.
                            if let Some(last) = headers.last() {
                                let last_hash = last.block_hash();
                                if let Ok(Some(stored)) = header_index.get_header(&last_hash) {
                                    let announced_h = stored.height as i32;
                                    {
                                        let mut peers = shared_peers.write().await;
                                        if let Some(entry) =
                                            peers.iter_mut().find(|p| p.id == peer_id)
                                        {
                                            if announced_h > entry.synced_height {
                                                entry.synced_height = announced_h;
                                            }
                                        }
                                    }
                                    #[cfg(feature = "web")]
                                    {
                                        let mut wp = web_peers.write().await;
                                        if let Some(entry) =
                                            wp.iter_mut().find(|e| e.id == peer_id)
                                        {
                                            if announced_h > entry.synced_height {
                                                entry.synced_height = announced_h;
                                            }
                                        }
                                    }
                                }
                            }

                            let block_height = chain_state.lock().await.best_height;
                            let prev_best_height = header_sync.best_height;
                            let was_synced = header_sync.synced;
                            match header_sync.process_headers(&headers, block_height) {
                                Ok(accepted) => {
                                    let tip_advanced = header_sync.best_height > prev_best_height;
                                    if accepted > 0 {
                                        // The peer's headers connect — clear its
                                        // unconnecting-headers strike counter.
                                        header_sync.reset_unconnecting(peer_id);
                                        // Update the peer's known height in shared_peers.
                                        // start_height from the version handshake is stale
                                        // (reflects height at connect time, not now).  Every
                                        // block-fetch and "good peer" filter gates on
                                        // start_height > 0, so a peer that was at genesis
                                        // when we connected is permanently excluded unless
                                        // we refresh it here.
                                        {
                                            let new_h = header_sync.best_height as i32;
                                            let mut peers = shared_peers.write().await;
                                            if let Some(peer) = peers.iter_mut().find(|p| p.id == peer_id) {
                                                if new_h > peer.start_height {
                                                    peer.start_height = new_h;
                                                }
                                            }
                                        }

                                        getheaders_in_flight = false;
                                        if tip_advanced {
                                            // Real progress — reset catch-up stall counter.
                                            catchup_stall_count = 0;
                                            last_header_height = header_sync.best_height;
                                            last_header_progress = std::time::Instant::now();
                                        }
                                        info!(
                                            accepted,
                                            height = header_sync.best_height,
                                            "Headers synced"
                                        );

                                        // Check if we need to reorg the validated chain.
                                        // If header_sync switched to a fork, the chain_state
                                        // tip may no longer be on the best header chain.
                                        let mut cs = chain_state.lock().await;
                                        let cs_height = cs.best_height;
                                        let cs_hash = cs.best_hash;

                                        // ── LOCAL-MINING SYNC ──────────────────────────
                                        // When blocks are mined locally via RPC
                                        // (e.g. `generatetoaddress`), chain_state advances
                                        // but header_sync.best_height is NOT updated because
                                        // no NodeEvent::Headers was processed for those blocks.
                                        //
                                        // When peers later echo those blocks back as `headers`
                                        // announcements, process_headers() accepts them but only
                                        // advances header_sync to the peer's highest reported
                                        // height — which may be less than cs_height. The reorg
                                        // check below would then see cs_height >
                                        // header_sync.best_height and declare we are "not on the
                                        // best chain", triggering a reorg that disconnects all
                                        // locally-mined blocks.
                                        //
                                        // Fix: before the reorg check, advance header_sync to
                                        // match chain_state whenever the chain has pulled ahead
                                        // via local mining. This is safe — it only skips a
                                        // spurious reorg; a genuine competing chain (more work)
                                        // would still be taller than cs_height and would still
                                        // trigger the correct reorg path below.
                                        if cs_height > header_sync.best_height {
                                            info!(
                                                cs_height,
                                                prev_header_sync_height = header_sync.best_height,
                                                "Local chain tip ahead of header_sync (RPC mining) \
                                                 — syncing header_sync to chain tip to prevent false reorg"
                                            );
                                            header_sync.best_height = cs_height;
                                            header_sync.best_hash = cs_hash;
                                            // Persist so restart recovery picks up the right tip
                                            let _ = header_index.set_header_tip(&cs_hash, cs_height);
                                        }

                                        // Walk back from header tip through prev_blockhash
                                        // links to check if chain_state tip is an ancestor.
                                        // This is more reliable than the height-to-hash mapping
                                        // which can be stale after forks on testnet4.
                                        let on_best_chain = if cs_height <= header_sync.best_height {
                                            let mut walk_hash = header_sync.best_hash;
                                            let mut walk_height = header_sync.best_height;
                                            let mut found = false;
                                            while walk_height >= cs_height {
                                                if walk_height == cs_height {
                                                    found = walk_hash == cs_hash;
                                                    if !found {
                                                        let height_mapped = header_index.get_hash_at_height(cs_height).ok().flatten();
                                                        warn!(
                                                            cs_height,
                                                            cs_hash = %cs_hash,
                                                            walk_hash = %walk_hash,
                                                            height_mapped_hash = ?height_mapped.map(|h| h.to_string()),
                                                            "on_best_chain mismatch: chain tip hash differs from header ancestry"
                                                        );
                                                    }
                                                    break;
                                                }
                                                match header_index.get_header(&walk_hash) {
                                                    Ok(Some(stored)) => {
                                                        walk_hash = stored.header.prev_blockhash;
                                                        walk_height -= 1;
                                                    }
                                                    _ => break,
                                                }
                                            }
                                            found
                                        } else {
                                            false
                                        };

                                        if !on_best_chain && cs_height > 0 {
                                            // Clear any in-flight requests for the old chain —
                                            // they will never connect and must be discarded before
                                            // we reorg to the new best chain.
                                            if !block_sync.in_flight.is_empty() {
                                                info!(
                                                    chain_height = cs_height,
                                                    in_flight = block_sync.in_flight.len(),
                                                    "Reorg needed — clearing stale in-flight requests for old chain"
                                                );
                                                block_sync.in_flight.clear();
                                            }
                                            {
                                            // Need to reorg: disconnect blocks back to fork point
                                            info!(
                                                chain_height = cs_height,
                                                chain_tip = %cs_hash,
                                                header_height = header_sync.best_height,
                                                "Chain tip not on best header chain, initiating reorg"
                                            );

                                            // Build the set of hashes on the best header chain
                                            // by walking prev_blockhash links from the tip.
                                            // We can't use get_hash_at_height() because the
                                            // height→hash mapping may be stale after a deep
                                            // fork that wasn't fully re-indexed.
                                            let mut best_chain_hashes = std::collections::HashMap::new();
                                            {
                                                let mut wh = header_sync.best_hash;
                                                let mut wht = header_sync.best_height;
                                                while wht >= cs_height.saturating_sub(100) && wht > 0 {
                                                    best_chain_hashes.insert(wht, wh);
                                                    match header_index.get_header(&wh) {
                                                        Ok(Some(stored)) => {
                                                            wh = stored.header.prev_blockhash;
                                                            wht -= 1;
                                                        }
                                                        _ => break,
                                                    }
                                                }
                                                // Include the final height we walked to
                                                best_chain_hashes.insert(wht, wh);
                                            }

                                            // Also fix the stale height→hash mappings so
                                            // future get_hash_at_height calls return correct
                                            // hashes and block requests use the right hashes.
                                            for (&h, &hash) in &best_chain_hashes {
                                                let current = header_index.get_hash_at_height(h).ok().flatten();
                                                if current != Some(hash) {
                                                    if let Ok(Some(stored)) = header_index.get_header(&hash) {
                                                        let _ = header_index.insert_headers_batch(&[(hash, stored)]);
                                                        debug!(height = h, %hash, "Fixed stale height→hash mapping");
                                                    }
                                                }
                                            }

                                            // Find fork point by walking back from chain_state tip.
                                            // First try disconnect_block (uses full block data).
                                            // If block data is unavailable, fall back to undo-data
                                            // rollback which only needs the block hash + undo entries.

                                            // Flush undo buffer before reorg so all undo data is
                                            // available on disk for disconnect/rollback operations.
                                            cs.utxo_set.flush_to_disk()
                                                .map_err(|e| error!("UTXO flush before reorg failed: {}", e)).ok();

                                            let mut reorg_height = cs_height;
                                            let mut reorg_ok = true;
                                            while reorg_height > 0 {
                                                let hash_on_best = best_chain_hashes.get(&reorg_height);
                                                if hash_on_best == Some(&cs.best_hash) {
                                                    break; // Found fork point
                                                }
                                                let block_hash = cs.best_hash;
                                                let disconnect_height = cs.best_height;

                                                // Try full-block disconnect first
                                                let mut disconnected = false;
                                                if let Ok(Some(_stored)) = header_index.get_header(&block_hash) {
                                                    if let Ok(Some(pos)) = header_index.get_block_pos(&block_hash) {
                                                        if let Ok(raw) = cs.block_store.read_block(&pos) {
                                                            if let Ok(block) = bitcoin::consensus::encode::deserialize::<bitcoin::Block>(&raw) {
                                                                match cs.disconnect_block(&block, disconnect_height) {
                                                                    Ok(()) => {
                                                                        info!(height = disconnect_height, hash = %block_hash, "Disconnected block during reorg");
                                                                        disconnected = true;
                                                                    }
                                                                    Err(e) => {
                                                                        warn!(height = disconnect_height, error = %e, "disconnect_block failed, trying undo rollback");
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    }
                                                }

                                                // Fallback: undo-data rollback (no full block needed)
                                                if !disconnected {
                                                    let hash_bytes: [u8; 32] = *AsRef::<[u8; 32]>::as_ref(&block_hash);
                                                    match cs.utxo_set.rollback_block(&hash_bytes) {
                                                        Ok(prev_hash) => {
                                                            let prev_block_hash = {
                                                                use bitcoin::hashes::Hash;
                                                                bitcoin::BlockHash::from_byte_array(prev_hash)
                                                            };
                                                            cs.best_height = disconnect_height.saturating_sub(1);
                                                            cs.best_hash = prev_block_hash;
                                                            // Update flush metadata to match
                                                            cs.utxo_set.set_pending_flush_height(
                                                                cs.best_height,
                                                                &prev_hash,
                                                            );
                                                            info!(
                                                                height = disconnect_height,
                                                                hash = %block_hash,
                                                                new_tip = %prev_block_hash,
                                                                "Rolled back block via undo data (no full block needed)"
                                                            );
                                                        }
                                                        Err(e) => {
                                                            error!(
                                                                hash = %block_hash,
                                                                height = disconnect_height,
                                                                error = %e,
                                                                "Cannot disconnect or rollback block — reorg aborted. \
                                                                 Consider --reindex to rebuild."
                                                            );
                                                            reorg_ok = false;
                                                            break;
                                                        }
                                                    }
                                                }
                                                reorg_height = cs.best_height;
                                            }

                                            if reorg_ok {
                                            // Flush UTXO set to disk to ensure undo
                                            // changes are persisted before reconnecting
                                            cs.utxo_set.flush_to_disk()
                                                .map_err(|e| error!("UTXO flush failed after reorg: {}", e)).ok();

                                            *shared_best_height.write().await = cs.best_height;
                                            *shared_best_hash.write().await = cs.best_hash;
                                            *p2p_best_height.write().unwrap() = cs.best_height as i32;
                                            pending_blocks.clear();
                                            // Clear stale block requests from the old chain
                                            block_sync.queue.clear();
                                            block_sync.in_flight.clear();

                                            // Schedule blocks on the new chain from fork point,
                                            // distributed across all connected peers.
                                            let reorg_start = cs.best_height + 1;
                                            let reorg_end = header_sync.best_height;
                                            if reorg_start <= reorg_end {
                                                let mut new_hashes = Vec::new();
                                                for h in reorg_start..=reorg_end.min(reorg_start + BLOCK_FETCH_HEIGHT_SPAN) {
                                                    // Prefer the height→hash index, but fall back to the
                                                    // header-walk map (best_chain_hashes) when the index has a
                                                    // hole at this height. The index can lag the header chain
                                                    // mid-reorg; relying on it alone would silently skip the
                                                    // missing intermediate block and strand the download.
                                                    if let Ok(Some(hash)) = header_index.get_hash_at_height(h) {
                                                        new_hashes.push(hash);
                                                    } else if let Some(&hash) = best_chain_hashes.get(&h) {
                                                        new_hashes.push(hash);
                                                    }
                                                }
                                                if !new_hashes.is_empty() {
                                                    block_sync.schedule(new_hashes);
                                                    let peers = shared_peers.read().await;
                                                    let block_h = chain_state.lock().await.best_height;
                                let header_tip = header_index.get_header_tip_height().ok().flatten().unwrap_or(block_h);
                                let peer_ids = eligible_download_peer_ids(&peers, block_h, header_tip);
                                                    drop(peers);
                                                    let cmds = block_sync.assign_to_peers(&peer_ids);
                                                    for cmd in cmds {
                                                        let _ = command_tx.try_send(cmd);
                                                    }
                                                }
                                            }

                                            info!(
                                                fork_height = cs.best_height,
                                                fork_hash = %cs.best_hash,
                                                new_chain_height = header_sync.best_height,
                                                "Reorg complete, requesting blocks on new chain"
                                            );
                                            } else {
                                                error!(
                                                    height = cs.best_height,
                                                    hash = %cs.best_hash,
                                                    "Reorg aborted — block disconnect failed. \
                                                     Node will continue on current chain. \
                                                     Consider --reindex to rebuild from stored blocks."
                                                );
                                            }
                                        drop(cs);
                                        } // reorg block
                                        } // if !on_best_chain
                                    }
                                    if !header_sync.synced && tip_advanced {
                                        let cmd = header_sync.build_getheaders_command(peer_id);
                                        let _ = command_tx.try_send(cmd);
                                        getheaders_in_flight = true;
                                    } else if !header_sync.synced && accepted > 0 && !tip_advanced {
                                        // Stale/duplicate headers: the peer sent headers
                                        // we already have (e.g. a response to an earlier
                                        // getheaders that arrived after the tip advanced).
                                        // Don't send a follow-up getheaders — it would
                                        // create a self-sustaining loop of stale responses
                                        // that block real progress. Release the sync peer
                                        // so the stall detector can pick a new one.
                                        debug!(
                                            accepted,
                                            height = header_sync.best_height,
                                            peer_id,
                                            "Ignoring stale headers response — tip unchanged"
                                        );
                                        header_sync_peer = None;
                                    } else if header_sync.synced {
                                        header_sync_peer = None;
                                        // When a new block is announced, every connected
                                        // peer sends the same 1-header message. Only the
                                        // sync-complete TRANSITION (or a message that
                                        // actually advanced the header tip) should log and
                                        // kick replay/scheduling — the ~23 duplicates were
                                        // spamming the log and re-running replay checks +
                                        // a 96-block schedule/assign pass each, bypassing
                                        // the pending-buffer back-pressure gate.
                                        let kick = !was_synced || tip_advanced;
                                        if !was_synced {
                                            info!(
                                                height = header_sync.best_height,
                                                "Header sync complete, requesting blocks"
                                            );
                                        } else if tip_advanced {
                                            debug!(
                                                height = header_sync.best_height,
                                                peer_id,
                                                "Header tip advanced while synced — scheduling new blocks"
                                            );
                                        }

                                        // Before requesting blocks from peers, try to
                                        // replay blocks already on disk. Block data and
                                        // block_pos entries may survive recovery/truncation
                                        // even though the validated tip was reset.
                                        // NOTE: Replay now runs in chunked batches (100 blocks
                                        // per event loop tick) to avoid blocking the event loop
                                        // and starving P2P message processing.
                                        let replay_start = chain_state.lock().await.best_height + 1;
                                        let replay_end = header_sync.best_height;
                                        if kick && replay_start + 100 < replay_end {
                                            // If block_pos entries are missing, rebuild them
                                            // from the flat files in a background task (once per session).
                                            let next_has_pos = header_index.get_hash_at_height(replay_start)
                                                .ok().flatten()
                                                .and_then(|h| header_index.get_block_pos(&h).ok().flatten())
                                                .is_some();
                                            if !next_has_pos && !reindex_done_this_session {
                                                // During normal IBD the next block simply hasn't
                                                // been downloaded yet — missing block_pos is NOT
                                                // evidence of a lost index, and a full block-file
                                                // scan would hammer disk I/O and tank block
                                                // connect times. Only scan when the flat files
                                                // actually contain data beyond the validated
                                                // tip's indexed position (recovery/truncation).
                                                let tip_pos = header_index
                                                    .get_hash_at_height(replay_start - 1)
                                                    .ok().flatten()
                                                    .and_then(|h| header_index.get_block_pos(&h).ok().flatten());
                                                let unindexed_bytes: u64 = match (&tip_pos, block_store.list_block_files()) {
                                                    (Some(pos), Ok(files)) => files
                                                        .iter()
                                                        .map(|(num, size)| {
                                                            if *num > pos.file_num {
                                                                *size
                                                            } else if *num == pos.file_num {
                                                                size.saturating_sub(pos.offset + pos.size as u64)
                                                            } else {
                                                                0
                                                            }
                                                        })
                                                        .sum(),
                                                    // Tip position itself is lost: treat all
                                                    // block file data as unindexed.
                                                    (None, Ok(files)) => files.iter().map(|(_, s)| *s).sum(),
                                                    (_, Err(_)) => 0,
                                                };
                                                // Allow slack for async writes still in flight.
                                                const REINDEX_MIN_UNINDEXED_BYTES: u64 = 16 * 1024 * 1024;
                                                if unindexed_bytes >= REINDEX_MIN_UNINDEXED_BYTES {
                                                    reindex_done_this_session = true;
                                                    info!(
                                                        validated_tip = replay_start - 1,
                                                        header_height = replay_end,
                                                        unindexed_mb = unindexed_bytes / (1024 * 1024),
                                                        "Block positions missing — scanning block files in background"
                                                    );
                                                    let bs = block_store.clone();
                                                    let hi = header_index.clone();
                                                    let sd = shutting_down.clone();
                                                    tokio::task::spawn_blocking(move || {
                                                        if let Err(e) = bs.reindex_block_files_cancellable(&hi, Some(sd)) {
                                                            tracing::warn!(error = %e, "Block file reindex failed");
                                                        } else {
                                                            tracing::info!("Block file reindex complete (background)");
                                                        }
                                                    });
                                                }
                                            }

                                            // Activate chunked replay only when the next
                                            // height has a known on-disk position. Without
                                            // block_pos, replay is a no-op and re-triggers
                                            // every header-sync cycle (~6 s).
                                            if !sync_state.is_replaying() && next_has_pos {
                                                info!(
                                                    from = replay_start,
                                                    to = replay_end,
                                                    "Attempting local block replay from stored blocks (chunked)"
                                                );
                                                sync_state = SyncState::Replay { end_height: replay_end };
                                            } else if !next_has_pos {
                                                debug!(
                                                    replay_start,
                                                    "Skipping local replay — block_pos missing for next height"
                                                );
                                            }
                                        }

                                        // Queue blocks for download — distribute across
                                        // all connected peers for parallel downloads.
                                        // Skip if replay is active (blocks will come from disk).
                                        if kick
                                            && !sync_state.is_replaying()
                                            && last_zero_replay_end.elapsed()
                                                > std::time::Duration::from_secs(30)
                                        {
                                            let start = chain_state.lock().await.best_height + 1;
                                            let end = header_sync.best_height;
                                            if start <= end {
                                                let mut hashes = Vec::new();
                                                let batch_end = end.min(start + BLOCK_FETCH_HEIGHT_SPAN);
                                                for h in start..=batch_end {
                                                    if let Ok(Some(hash)) = header_index.get_hash_at_height(h) {
                                                        hashes.push(hash);
                                                    }
                                                }
                                                if !hashes.is_empty() {
                                                    block_sync.schedule(hashes);
                                                    let peers = shared_peers.read().await;
                                                    let block_h = chain_state.lock().await.best_height;
                                let header_tip = header_index.get_header_tip_height().ok().flatten().unwrap_or(block_h);
                                let peer_ids = eligible_download_peer_ids(&peers, block_h, header_tip);
                                                    drop(peers);
                                                    let cmds = block_sync.assign_to_peers(&peer_ids);
                                                    for cmd in cmds {
                                                        let _ = command_tx.try_send(cmd);
                                                    }
                                                }
                                            }
                                        }

                                        // Phase C: re-download missing/corrupt blocks found at startup.
                                        // Only download blocks near the tip (needed for UTXO consistency
                                        // checks on restart). Defer deep historical gaps to avoid clogging
                                        // the download pipeline during IBD.
                                        if kick && !missing_blocks.is_empty() {
                                            let cs = chain_state.lock().await;
                                            let tip_height = cs.best_height;
                                            drop(cs);
                                            // Download blocks within 100 of the tip; defer the rest
                                            let near_tip: Vec<u32> = missing_blocks.iter()
                                                .copied()
                                                .filter(|&h| h + 100 >= tip_height)
                                                .collect();
                                            let deferred = missing_blocks.len() - near_tip.len();

                                            let mut repair_hashes = Vec::new();
                                            for &h in &near_tip {
                                                if let Ok(Some(hash)) = header_index.get_hash_at_height(h) {
                                                    repair_hashes.push(hash);
                                                }
                                            }
                                            if !repair_hashes.is_empty() {
                                                info!(
                                                    count = repair_hashes.len(),
                                                    deferred,
                                                    "Requesting re-download of missing blocks near tip"
                                                );
                                                block_sync.schedule(repair_hashes);
                                                let peers = shared_peers.read().await;
                                                let block_h = chain_state.lock().await.best_height;
                                let header_tip = header_index.get_header_tip_height().ok().flatten().unwrap_or(block_h);
                                let peer_ids = eligible_download_peer_ids(&peers, block_h, header_tip);
                                                drop(peers);
                                                let cmds = block_sync.assign_to_peers(&peer_ids);
                                                for cmd in cmds {
                                                    let _ = command_tx.try_send(cmd);
                                                }
                                            } else if deferred > 0 {
                                                info!(
                                                    deferred,
                                                    "Deferring re-download of deep historical missing blocks"
                                                );
                                            }
                                            missing_blocks.clear();
                                        }
                                    }
                                }
                                Err(bitcoinpr_p2p::HeaderSyncError::Unconnected(msg)) => {
                                    // A tip announcement we can't connect — we're
                                    // missing the blocks between our tip and it
                                    // (e.g. we missed earlier announcements while
                                    // the peer was catching up, or across our own
                                    // restart). Ask the peer for headers from our
                                    // tip so the gap fills; this is a normal relay
                                    // race (Core's unconnecting-headers handling).
                                    //
                                    // But a peer on a foreign chain answers that
                                    // getheaders with headers that don't connect
                                    // either, turning the exchange into an
                                    // unbounded ping-pong (observed 2026-07-12 at
                                    // ~7 msgs/sec). So count consecutive
                                    // unconnecting messages per peer: past the
                                    // cap, stop re-requesting and penalize every
                                    // cap-multiple so a persistent offender walks
                                    // itself to a ban. The counter resets as soon
                                    // as one of the peer's headers connects.
                                    let count = header_sync.note_unconnecting(peer_id);
                                    if count < bitcoinpr_p2p::MAX_UNCONNECTING_HEADERS {
                                        info!(peer_id, %msg, count, "Unconnecting header announcement — sending getheaders to fill the gap");
                                        let cmd = header_sync.build_getheaders_command(peer_id);
                                        let _ = command_tx.try_send(cmd);
                                    } else {
                                        warn!(
                                            peer_id,
                                            %msg,
                                            count,
                                            "Too many consecutive unconnecting headers — not re-requesting"
                                        );
                                        if count % bitcoinpr_p2p::MAX_UNCONNECTING_HEADERS == 0 {
                                            let _ = command_tx.try_send(PeerCommand::Misbehaving {
                                                peer_id,
                                                reason: bitcoinpr_p2p::Misbehavior::UnconnectingHeaders,
                                            });
                                        }
                                    }
                                }
                                Err(e) => {
                                    warn!(peer_id, "Header sync error: {}", e);
                                    // Consensus-invalid headers (bad PoW, wrong
                                    // nBits) are the peer's fault — score it so
                                    // repeat offenders get banned. Storage errors
                                    // are local and carry no penalty.
                                    if matches!(e, bitcoinpr_p2p::HeaderSyncError::Invalid(_)) {
                                        let _ = command_tx.try_send(PeerCommand::Misbehaving {
                                            peer_id,
                                            reason: bitcoinpr_p2p::Misbehavior::InvalidHeader,
                                        });
                                    }
                                }
                            }
                            } // else (non-empty headers or from sync peer)
                        }
                        NodeEvent::Block(..) => {
                            // Blocks are delivered on the dedicated block_event channel.
                        }
                        NodeEvent::NotFound(peer_id, inv) => {
                            handle_notfound(
                                peer_id,
                                inv,
                                &shared_peers,
                                &chain_state,
                                &header_index,
                                &command_tx,
                                &mut block_sync,
                                &mut pending_blocks,
                            )
                            .await;
                        }
                        NodeEvent::BlockInv(peer_id, block_hashes) => {
                            handle_block_inv(
                                peer_id,
                                block_hashes,
                                &header_index,
                                &shared_peers,
                                #[cfg(feature = "web")]
                                &web_peers,
                            )
                            .await;
                        }
                        NodeEvent::Transaction(peer_id, tx) => {
                            handle_transaction(
                                peer_id,
                                tx,
                                &is_ibd,
                                &shared_mempool,
                                &utxo_set,
                                &chain_state,
                                &header_index,
                                &params,
                                &sig_cache,
                                &event_bus,
                                &command_tx,
                            )
                            .await;
                        }
                    }
                }
            }

            // Chunked local replay: connect up to 100 blocks per tick from local
            // disk. This keeps the event loop responsive so P2P messages (including
            // incoming blocks from peers) are processed between batches.
            if let SyncState::Replay { end_height } = sync_state {
                let mut replayed_this_tick = 0u32;
                const REPLAY_BATCH: u32 = 100;

                while replayed_this_tick < REPLAY_BATCH {
                    if shutting_down.load(std::sync::atomic::Ordering::Relaxed) {
                        break;
                    }
                    // M2 (2026-07-02 review): the whole read+deserialize+
                    // validate step runs on a blocking thread — RocksDB
                    // reads and script validation would otherwise pin a
                    // tokio worker for the duration. The ChainState lock is
                    // acquired *inside* the task so the height read and the
                    // connect stay atomic, exactly as when it ran inline.
                    let cs_arc = chain_state.clone();
                    let hi = header_index.clone();
                    let bs = block_store.clone();
                    let step: Result<Option<(u32, bitcoin::BlockHash)>, String> =
                        tokio::task::spawn_blocking(move || {
                            let mut cs = cs_arc.blocking_lock();
                            let h = cs.best_height + 1;
                            if h > end_height {
                                return Ok(None);
                            }
                            let hash = match hi.get_hash_at_height(h) {
                                Ok(Some(hash)) => hash,
                                _ => return Ok(None),
                            };
                            // Missing block data: stop replaying and fall
                            // through to download from peers.
                            let raw = match hi
                                .get_block_pos(&hash)
                                .ok()
                                .flatten()
                                .and_then(|pos| bs.read_block(&pos).ok())
                            {
                                Some(r) => r,
                                None => return Ok(None),
                            };
                            let block: bitcoin::Block =
                                match bitcoin::consensus::encode::deserialize(&raw) {
                                    Ok(b) => b,
                                    Err(_) => return Ok(None),
                                };
                            cs.connect_block_with_raw(&block, h, Some(&raw))
                                .map(|()| Some((cs.best_height, cs.best_hash)))
                                .map_err(|e| format!("height {h}: {e}"))
                        })
                        .await
                        .unwrap_or_else(|e| Err(format!("replay task panicked: {e}")));

                    match step {
                        Ok(Some((connected_height, connected_hash))) => {
                            replayed_this_tick += 1;
                            last_block_connect = std::time::Instant::now();
                            *shared_best_height.write().await = connected_height;
                            *shared_best_hash.write().await = connected_hash;
                            *p2p_best_height.write().unwrap() = connected_height as i32;
                            if replayed_this_tick % 100 == 0 {
                                info!(
                                    height = connected_height,
                                    remaining = end_height.saturating_sub(connected_height),
                                    "Local block replay progress (chunked)"
                                );
                            }
                        }
                        Ok(None) => break,
                        Err(e) => {
                            warn!(error = %e, "Local replay stopped");
                            break;
                        }
                    }
                }

                // Check if replay is done (either completed or hit missing blocks)
                let current_h = chain_state.lock().await.best_height;
                if replayed_this_tick == 0 || current_h >= end_height {
                    if current_h >= end_height {
                        info!(height = current_h, "Local block replay complete");

                        // Replay completed at the header tip — the node is fully
                        // caught up without going through the peer block drain path,
                        // so the IBD flag would never be cleared there.  Clear it
                        // here instead, mirroring the logic in the drain path.
                        if header_sync.synced {
                            let was_ibd = is_ibd.swap(false, std::sync::atomic::Ordering::Relaxed);
                            if was_ibd {
                                info!(height = current_h, "IBD complete after local replay");

                                // Publish a NewBlock event so the TemplateProvider
                                // updates its best_height/best_hash to the real chain
                                // tip.  Without this, the provider keeps whatever
                                // height it was initialized with at startup (which can
                                // be 0 after a UTXO wipe + replay), and miners would
                                // build on the wrong tip until the next external block.
                                let tip_hash = *shared_best_hash.read().await;
                                event_bus.publish(NodeNotification::NewBlock {
                                    hash: tip_hash.to_string(),
                                    height: current_h,
                                });

                                #[cfg(feature = "indexing")]
                                if let Some(ref idx) = scripthash_index {
                                    let indexed =
                                        idx.get_indexed_height().unwrap_or(None).unwrap_or(0);
                                    if indexed < current_h {
                                        info!(
                                            indexed_height = indexed,
                                            chain_height = current_h,
                                            "IBD complete — starting scripthash index backfill"
                                        );
                                        spawn_scripthash_backfill(
                                            idx.clone(),
                                            header_index.clone(),
                                            block_store.clone(),
                                            indexed + 1,
                                            current_h,
                                            shutting_down.clone(),
                                            Some(index_catchup_running.clone()),
                                            scripthash_indexed_height.clone(),
                                        );
                                    }
                                }
                            }
                        }
                    } else {
                        info!(
                            height = current_h,
                            "Local replay ended — will download remaining from peers"
                        );
                        if replayed_this_tick == 0 {
                            last_zero_replay_end = std::time::Instant::now();
                        }

                        // The replay end height may have been set by a peer that is on
                        // a longer or different chain whose blocks we cannot download
                        // (e.g. a stale node advertising an incompatible fork).  Re-check
                        // whether our UTXO tip already matches the VALIDATED header-index
                        // tip — if so, we are fully caught up and IBD should end now
                        // rather than waiting for blocks that will never arrive.
                        let actual_header_tip = header_index
                            .get_header_tip_height()
                            .ok()
                            .flatten()
                            .unwrap_or(0);
                        if current_h >= actual_header_tip && actual_header_tip > 0 {
                            let was_ibd = is_ibd.swap(false, std::sync::atomic::Ordering::Relaxed);
                            if was_ibd {
                                info!(
                                    height = current_h,
                                    header_tip = actual_header_tip,
                                    "IBD complete — block tip matches validated header index after partial replay"
                                );
                                let tip_hash = *shared_best_hash.read().await;
                                event_bus.publish(NodeNotification::NewBlock {
                                    hash: tip_hash.to_string(),
                                    height: current_h,
                                });
                                #[cfg(feature = "indexing")]
                                if let Some(ref idx) = scripthash_index {
                                    let indexed =
                                        idx.get_indexed_height().unwrap_or(None).unwrap_or(0);
                                    if indexed < current_h {
                                        info!(
                                            indexed_height = indexed,
                                            chain_height = current_h,
                                            "IBD complete — starting scripthash index backfill"
                                        );
                                        spawn_scripthash_backfill(
                                            idx.clone(),
                                            header_index.clone(),
                                            block_store.clone(),
                                            indexed + 1,
                                            current_h,
                                            shutting_down.clone(),
                                            Some(index_catchup_running.clone()),
                                            scripthash_indexed_height.clone(),
                                        );
                                    }
                                }
                            }
                        }
                    }
                    sync_state = SyncState::Download;

                    // Now that replay is done, queue remaining blocks for peer download
                    let start = current_h + 1;
                    let end = header_sync.best_height;
                    if start <= end
                        && header_sync.synced
                        && last_zero_replay_end.elapsed() > std::time::Duration::from_secs(30)
                    {
                        let mut hashes = Vec::new();
                        let batch_end = end.min(start + BLOCK_FETCH_HEIGHT_SPAN);
                        for h in start..=batch_end {
                            if let Ok(Some(hash)) = header_index.get_hash_at_height(h) {
                                hashes.push(hash);
                            }
                        }
                        if !hashes.is_empty() {
                            info!(
                                count = hashes.len(),
                                from = start,
                                "Queueing blocks for peer download after replay"
                            );
                            block_sync.schedule(hashes);
                            let peers = shared_peers.read().await;
                            let block_h = chain_state.lock().await.best_height;
                            let header_tip = header_index
                                .get_header_tip_height()
                                .ok()
                                .flatten()
                                .unwrap_or(block_h);
                            let peer_ids = eligible_download_peer_ids(&peers, block_h, header_tip);
                            drop(peers);
                            let cmds = block_sync.assign_to_peers(&peer_ids);
                            for cmd in cmds {
                                let _ = command_tx.try_send(cmd);
                            }
                        }
                    }

                    // After replay, send getheaders to the single best peer to
                    // discover chain extensions beyond our current known headers.
                    // Peer start_height in the version message is stale (reflects
                    // the peer's height at handshake time, not now), so the post-
                    // sync catch-up block that checks best_peer_height cannot be
                    // relied on. Triggering a fresh header sync here ensures we
                    // find new blocks that the peer connected after we originally
                    // handshook with it.
                    //
                    // Three guards prevent a CPU-spinning loop during deep IBD,
                    // where each header response triggers another replay → another
                    // broadcast (observed at ~55 Hz on testnet4):
                    //   1. Skip if block downloads are already queued or in
                    //      flight — the next replay will only advance once those
                    //      blocks land, so there is nothing new to discover yet.
                    //   2. Skip if we already broadcast getheaders at this exact
                    //      tip — replay ending at the same height means no
                    //      progress, and re-asking the same peers will return the
                    //      same answer.
                    //   3. Send to the single highest peer rather than fanning
                    //      out to all peers (which N-multiplies the loop rate).
                    {
                        let downloads_pending =
                            !block_sync.queue.is_empty() || !block_sync.in_flight.is_empty();
                        let already_asked_at_tip =
                            last_post_replay_getheaders_height == Some(current_h);

                        if downloads_pending {
                            debug!(
                                queued = block_sync.queue.len(),
                                in_flight = block_sync.in_flight.len(),
                                height = current_h,
                                "Skipping post-replay getheaders — block downloads still pending"
                            );
                        } else if already_asked_at_tip {
                            debug!(
                                height = current_h,
                                "Skipping post-replay getheaders — already broadcast at this tip"
                            );
                        } else {
                            let peers_snapshot = shared_peers.read().await;
                            let best_peer = peers_snapshot
                                .iter()
                                .max_by_key(|p| p.start_height)
                                .map(|p| (p.id, p.start_height));
                            drop(peers_snapshot);
                            if let Some((pid, peer_height)) = best_peer {
                                header_sync.synced = false;
                                let cmd = header_sync.build_getheaders_command(pid);
                                let _ = command_tx.try_send(cmd);
                                header_sync_peer = Some(pid);
                                getheaders_in_flight = true;
                                last_post_replay_getheaders_height = Some(current_h);
                                info!(
                                    peer_id = pid,
                                    peer_height,
                                    height = current_h,
                                    "Replay complete — sending getheaders to best peer to discover chain extensions"
                                );
                            }
                        }
                    }
                }
            }

            // Drain pending blocks that connect to the current tip.
            // Process up to 32 blocks per loop iteration so the event loop stays
            // responsive to new peer messages, downloads, and keepalives.
            // The maintenance_interval tick (100ms) ensures we re-enter promptly
            // when more pending blocks remain.
            {
                let mut drain_count = 0u32;
                const MAX_DRAIN_PER_TICK: u32 = 32;

                while drain_count < MAX_DRAIN_PER_TICK {
                    if shutting_down.load(std::sync::atomic::Ordering::Relaxed) {
                        break;
                    }

                    let cs = chain_state.lock().await;
                    let current_tip = cs.best_hash;
                    drop(cs);

                    let next_block = pending_blocks
                        .get_mut(&current_tip)
                        .and_then(|q| q.pop_front());

                    let (block, raw_block_bytes) = match next_block {
                        Some(b) => b,
                        None => break,
                    };

                    let block_hash = block.block_hash();
                    // Clean up empty queues
                    if pending_blocks
                        .get(&current_tip)
                        .is_none_or(|q| q.is_empty())
                    {
                        pending_blocks.remove(&current_tip);
                    }

                    // M2 (2026-07-02 review): validation runs on a blocking
                    // thread instead of `block_in_place` (which stalls every
                    // other task queued on the current worker and silently
                    // requires a multi-thread runtime). The ChainState lock
                    // is acquired inside the task, so the height read, the
                    // stale-block check, and the connect stay atomic exactly
                    // as before.
                    let cs_arc = chain_state.clone();
                    let hi = header_index.clone();
                    let step = tokio::task::spawn_blocking(move || {
                        let mut cs = cs_arc.blocking_lock();
                        let expected_height = cs.best_height + 1;

                        // Verify block belongs to the best header chain.
                        let expected_hash = hi.get_hash_at_height(expected_height).ok().flatten();
                        if expected_hash.is_some() && expected_hash != Some(block_hash) {
                            return DrainStep::Stale {
                                expected_height,
                                expected_hash,
                            };
                        }

                        match cs.connect_block_with_raw(
                            &block,
                            expected_height,
                            raw_block_bytes.as_deref(),
                        ) {
                            Ok(()) => DrainStep::Connected {
                                block,
                                connected_height: cs.best_height,
                                connected_hash: cs.best_hash,
                            },
                            Err(e) => DrainStep::Failed {
                                expected_height,
                                error: e.to_string(),
                            },
                        }
                    })
                    .await
                    .expect("block-connect task panicked");

                    match step {
                        DrainStep::Stale {
                            expected_height,
                            expected_hash,
                        } => {
                            debug!(
                                height = expected_height,
                                expected = ?expected_hash,
                                got = %block_hash,
                                "Skipping stale block not on best header chain"
                            );
                            continue;
                        }
                        DrainStep::Connected {
                            block,
                            connected_height,
                            connected_hash,
                        } => {
                            blocks_validated += 1;
                            last_block_connect = std::time::Instant::now();
                            block_sync.block_connected(&block_hash);
                            let end = header_sync.best_height;

                            // Keep header_sync tip aligned with the validated chain.
                            //
                            // Blocks received via BroadcastBlock (raw `block` messages,
                            // e.g. from the mining peer) bypass the normal headers-first
                            // pipeline, so header_sync.best_height is never updated for
                            // them. Without this sync:
                            //   • getblockchaininfo reports stale `headers` (< `blocks`)
                            //   • META_HEADER_TIP_HEIGHT is not updated on disk, causing
                            //     header_sync to start from an old tip on the next restart
                            if connected_height > header_sync.best_height {
                                header_sync.best_height = connected_height;
                                header_sync.best_hash = connected_hash;
                                let _ =
                                    header_index.set_header_tip(&connected_hash, connected_height);
                            }

                            // Update shared state immediately, but skip
                            // pipeline refill if we're shutting down.
                            *shared_best_height.write().await = connected_height;
                            *shared_best_hash.write().await = connected_hash;
                            *p2p_best_height.write().unwrap() = connected_height as i32;

                            if shutting_down.load(std::sync::atomic::Ordering::Relaxed) {
                                break;
                            }

                            if connected_height >= end && header_sync.synced {
                                let _was_ibd =
                                    is_ibd.swap(false, std::sync::atomic::Ordering::Relaxed);

                                // Trigger scripthash backfill now that IBD is done
                                #[cfg(feature = "indexing")]
                                if _was_ibd {
                                    if let Some(ref idx) = scripthash_index {
                                        let indexed =
                                            idx.get_indexed_height().unwrap_or(None).unwrap_or(0);
                                        if indexed < connected_height {
                                            info!(
                                                indexed_height = indexed,
                                                chain_height = connected_height,
                                                "IBD complete — starting scripthash index backfill"
                                            );
                                            spawn_scripthash_backfill(
                                                idx.clone(),
                                                header_index.clone(),
                                                block_store.clone(),
                                                indexed + 1,
                                                connected_height,
                                                shutting_down.clone(),
                                                Some(index_catchup_running.clone()),
                                                scripthash_indexed_height.clone(),
                                            );
                                        }
                                    }
                                }

                                // After catching up to known headers via peer download,
                                // re-request headers from all connected peers. Peer
                                // start_height (from the version handshake) may be stale;
                                // peers may have advanced their chain while we were doing
                                // IBD. Without this, we remain stuck until a new block
                                // announcement arrives.
                                if _was_ibd {
                                    let peers_snap = shared_peers.read().await;
                                    let ibd_done_peers: Vec<u64> =
                                        peers_snap.iter().map(|p| p.id).collect();
                                    drop(peers_snap);
                                    if !ibd_done_peers.is_empty() {
                                        header_sync.synced = false;
                                        for &pid in &ibd_done_peers {
                                            let cmd = header_sync.build_getheaders_command(pid);
                                            let _ = command_tx.try_send(cmd);
                                        }
                                        header_sync_peer = Some(ibd_done_peers[0]);
                                        getheaders_in_flight = true;
                                        info!(
                                            peers = ibd_done_peers.len(),
                                            height = connected_height,
                                            "IBD complete — re-syncing headers from all peers to discover chain extensions"
                                        );
                                    }
                                }
                            }

                            shared_mempool.write().await.remove_for_block(&block);

                            // Index scripthash inline with every connected block —
                            // but NOT during IBD. Each input needs resolve_spent_output
                            // (txindex point-get + block read on cache miss), thousands
                            // per block, executed here on the event-loop thread. During
                            // the 2026-07 mainnet IBD this was measured at ~61MB/s of
                            // txindex SST reads at 83% CPU on the main thread, starving
                            // block connection down to single-digit b/min. The
                            // IBD-complete backfill (spawn_scripthash_backfill above)
                            // covers the gap when IBD finishes. Also skip if a backfill
                            // task is still covering historical blocks — updating the
                            // shared height while a gap exists would make getindexinfo
                            // report synced prematurely.
                            #[cfg(feature = "indexing")]
                            if let Some(ref idx) = scripthash_index {
                                let backfill_active = scripthash_backfill_running
                                    .load(std::sync::atomic::Ordering::Relaxed)
                                    || index_catchup_running
                                        .load(std::sync::atomic::Ordering::Relaxed);
                                let in_ibd = is_ibd.load(std::sync::atomic::Ordering::Relaxed);
                                if !backfill_active && !in_ibd {
                                    if let Err(e) =
                                        idx.index_block_transactions(&block, connected_height)
                                    {
                                        warn!("Scripthash indexing error: {}", e);
                                    } else if let Some(ref sh) = scripthash_indexed_height {
                                        sh.store(
                                            connected_height,
                                            std::sync::atomic::Ordering::Relaxed,
                                        );
                                    }
                                }
                            }

                            event_bus.publish(NodeNotification::NewBlock {
                                hash: block_hash.to_string(),
                                height: connected_height,
                            });

                            // Relay peer-received blocks onward to our other peers.
                            //
                            // Locally-mined blocks (RPC generatetoaddress / Stratum)
                            // announce themselves via PeerCommand::BroadcastBlock in their
                            // own code paths. But a block that ARRIVES from a peer and
                            // connects here was never re-announced, so the peers of THIS
                            // node never learned about a block some OTHER node mined — the
                            // root cause of the "non-seed block propagates unreliably"
                            // finding. Re-announce via inv/headers now.
                            //
                            // Safe against the getheaders→getdata→notfound livelock: the
                            // block is already written to our block store by
                            // connect_block_with_raw above, so any follow-up getdata is
                            // servable. Gated on !IBD so we don't announce every historical
                            // block while catching up (peers don't want a flood, and the
                            // blocks aren't "new").
                            if !is_ibd.load(std::sync::atomic::Ordering::Relaxed) {
                                let _ = command_tx.try_send(PeerCommand::BroadcastBlock(
                                    block.clone(),
                                    connected_height,
                                ));
                            }

                            if blocks_validated % 1000 == 0 {
                                info!(
                                    blocks_validated,
                                    height = connected_height,
                                    "Block validation progress"
                                );
                                // Log per-peer bandwidth stats
                                let mut bw_stats: Vec<_> = block_sync
                                    .peer_bandwidth
                                    .iter()
                                    .map(|(pid, bw)| (*pid, bw.ewma_bps, bw.blocks_delivered))
                                    .collect();
                                bw_stats.sort_by(|a, b| {
                                    b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal)
                                });
                                for (pid, bps, delivered) in &bw_stats {
                                    info!(
                                        peer_id = pid,
                                        ewma_kbps = format!("{:.0}", bps / 1024.0),
                                        blocks_delivered = delivered,
                                        "Peer bandwidth"
                                    );
                                }
                            }

                            drain_count += 1;
                        }
                        DrainStep::Failed {
                            expected_height,
                            error,
                        } => {
                            let count = block_failure_counts
                                .entry(block_hash)
                                .and_modify(|c| *c += 1)
                                .or_insert(1);

                            if *count >= MAX_BLOCK_RETRIES {
                                error!(
                                    height = expected_height,
                                    hash = %block_hash,
                                    attempts = *count,
                                    error = %error,
                                    "Block repeatedly failed validation; giving up. \
                                     UTXO set may be inconsistent — consider resyncing \
                                     from scratch (delete the data directory)."
                                );
                                break;
                            }

                            warn!(
                                height = expected_height,
                                hash = %block_hash,
                                attempts = *count,
                                max_attempts = MAX_BLOCK_RETRIES,
                                error = %error,
                                "Block validation failed"
                            );

                            // Re-request the failed block from a different peer
                            // (skipped while block download is paused for
                            // minimum-chain-work header sync).
                            let peers = shared_peers.read().await;
                            let retry_peer = peers.first().map(|p| p.id);
                            drop(peers);
                            if block_sync.download_paused {
                                // Leave it queued; retried once the gate opens.
                            } else if let Some(pid) = retry_peer {
                                block_sync.in_flight.insert(block_hash, pid);
                                let _ = command_tx.try_send(PeerCommand::GetBlocks {
                                    peer_id: pid,
                                    hashes: vec![block_hash],
                                });
                            }
                            break;
                        }
                    }

                    // While this drain loop runs, select! isn't polling
                    // block_event_rx — with the small (256) channel capacity the
                    // P2P manager's try_send would drop incoming blocks, forcing
                    // stale-timeout re-requests. Drain queued block events into
                    // pending_blocks (byte-capped) between validations instead.
                    while let Ok(event) = block_event_rx.try_recv() {
                        if let NodeEvent::Block(peer_id, block, raw_bytes) = event {
                            handle_received_block(
                                peer_id,
                                block,
                                raw_bytes,
                                &mut block_sync,
                                &chain_state,
                                &header_index,
                                &header_sync,
                                &command_tx,
                                &mut pending_blocks,
                                &mut last_orphan_getheaders,
                            )
                            .await;
                        }
                    }
                }

                // Pipeline refill: schedule new blocks ONCE after the drain batch
                // (not per-block, to avoid flooding the command channel).
                //
                // Back-pressure: when validation lags downloads, the pending
                // buffer fills to its byte cap and evicts lookahead blocks
                // that must then be re-downloaded — pure waste. Pause the
                // refill while buffered bytes PLUS the projected size of
                // blocks already in flight would exceed the budget (a plain
                // 75%-of-budget gate still overshot: up to 128 in-flight
                // blocks of ~1.4MB kept landing after the gate closed). The
                // drain loop keeps consuming from the tip and scheduling
                // resumes once there's room. Stall-recovery paths are
                // unaffected.
                let refill_ok = {
                    let pending_bytes = pending_total_bytes(&pending_blocks);
                    // Mirror for the heartbeat task (refreshed every loop
                    // iteration, i.e. at least every 100ms maintenance tick).
                    pending_bytes_gauge.store(pending_bytes, std::sync::atomic::Ordering::Relaxed);
                    let pending_count: usize = pending_blocks.values().map(|q| q.len()).sum();
                    // Estimate in-flight block size from what's buffered
                    // (adapts to the current chain era); 1MB fallback.
                    let avg_block = if pending_count > 0 {
                        pending_bytes / pending_count
                    } else {
                        1024 * 1024
                    };
                    pending_bytes + block_sync.in_flight.len() * avg_block < MAX_PENDING_BYTES
                };
                if drain_count > 0 && header_sync.synced && refill_ok {
                    let cs = chain_state.lock().await;
                    let next_start = cs.best_height + 1;
                    let end = header_sync.best_height;
                    drop(cs);
                    if next_start <= end {
                        let in_pipeline = block_sync.in_flight.len() + block_sync.queue.len();
                        let slots_available = block_sync.max_in_flight.saturating_sub(in_pipeline);
                        if slots_available > 32 {
                            // Schedule from chain tip, not tip+pipeline. Most peers
                            // are pruned and silently ignore old-block getdata, so
                            // scheduling far ahead just wastes in-flight slots on
                            // blocks that buffer uselessly in pending_blocks.
                            let capped_slots =
                                slots_available.min(BLOCK_FETCH_HEIGHT_SPAN as usize);
                            let sched_end = end.min(next_start + capped_slots as u32 - 1);
                            let mut hashes = Vec::new();
                            for h in next_start..=sched_end {
                                if let Ok(Some(hash)) = header_index.get_hash_at_height(h) {
                                    if !block_sync.in_flight.contains_key(&hash) {
                                        hashes.push(hash);
                                    }
                                }
                            }
                            if !hashes.is_empty() {
                                block_sync.schedule(hashes);
                                let peers = shared_peers.read().await;
                                let block_h = chain_state.lock().await.best_height;
                                let header_tip = header_index
                                    .get_header_tip_height()
                                    .ok()
                                    .flatten()
                                    .unwrap_or(block_h);
                                let peer_ids =
                                    eligible_download_peer_ids(&peers, block_h, header_tip);
                                drop(peers);
                                let cmds = block_sync.assign_to_peers(&peer_ids);
                                for cmd in cmds {
                                    let _ = command_tx.try_send(cmd);
                                }
                            }
                        }
                    }
                }
            }

            // Next-block shotgun: request `tip+1` from multiple peers concurrently.
            // Fires 5s after the last block connection or last shotgun attempt — see
            // timers below. Bookkeeping registers every targeted peer so stale
            // clearing does not re-queue while other peers still owe the hash.
            if header_sync.synced
                && !block_sync.download_paused
                && !sync_state.is_replaying()
                && last_block_connect.elapsed() > std::time::Duration::from_secs(5)
                && last_hol_rerequest.elapsed() > std::time::Duration::from_secs(5)
            {
                let cs = chain_state.lock().await;
                let next_height = cs.best_height + 1;
                drop(cs);
                if next_height <= header_sync.best_height {
                    if let Ok(Some(next_hash)) = header_index.get_hash_at_height(next_height) {
                        // Gather eligible peers
                        let peers = shared_peers.read().await;
                        let block_h = chain_state.lock().await.best_height;
                        let header_tip = header_index
                            .get_header_tip_height()
                            .ok()
                            .flatten()
                            .unwrap_or(block_h);
                        let eligible = eligible_download_peer_ids(&peers, block_h, header_tip);
                        drop(peers);

                        // Clear prior requests for this hash so a new shotgun is self-consistent.
                        block_sync.in_flight.remove(&next_hash);
                        for set in block_sync.peer_requests.values_mut() {
                            set.remove(&next_hash);
                        }
                        block_sync.queue.retain(|h| *h != next_hash);

                        // Prefer peers that have delivered full blocks recently; supplement
                        // with random archive peers so we do not collapse to a single supplier.
                        const MIN_SHOTGUN_FANOUT: usize = 8;
                        const MAX_SHOTGUN_FANOUT: usize = 24;

                        let delivered_peers: Vec<u64> = eligible
                            .iter()
                            .filter(|&&pid| {
                                block_sync
                                    .peer_bandwidth
                                    .get(&pid)
                                    .map(|bw| bw.blocks_delivered > 0)
                                    .unwrap_or(false)
                                    && block_sync.peer_stale_cycles.get(&pid).copied().unwrap_or(0)
                                        == 0
                            })
                            .copied()
                            .collect();

                        let mut target_peers: Vec<u64> = if delivered_peers.is_empty() {
                            eligible.clone()
                        } else {
                            let mut t = delivered_peers.clone();
                            let want = MIN_SHOTGUN_FANOUT.min(eligible.len().max(1));
                            if t.len() < want {
                                let mut filler: Vec<u64> = eligible
                                    .iter()
                                    .copied()
                                    .filter(|p| !t.contains(p))
                                    .collect();
                                use rand::seq::SliceRandom;
                                filler.shuffle(&mut rand::thread_rng());
                                for p in filler.into_iter().take(want - t.len()) {
                                    t.push(p);
                                }
                            }
                            t
                        };

                        if target_peers.len() > MAX_SHOTGUN_FANOUT {
                            use rand::seq::SliceRandom;
                            target_peers.shuffle(&mut rand::thread_rng());
                            target_peers.truncate(MAX_SHOTGUN_FANOUT);
                        }

                        if !target_peers.is_empty() {
                            let now = std::time::Instant::now();
                            for &pid in &target_peers {
                                block_sync
                                    .peer_requests
                                    .entry(pid)
                                    .or_default()
                                    .insert(next_hash);
                                block_sync.peer_last_recv.entry(pid).or_insert(now);
                            }
                            block_sync.in_flight.insert(next_hash, target_peers[0]);

                            for &pid in &target_peers {
                                let _ = command_tx.try_send(PeerCommand::GetBlocks {
                                    peer_id: pid,
                                    hashes: vec![next_hash],
                                });
                            }
                            debug!(
                                height = next_height,
                                peers_requested = target_peers.len(),
                                "Next-block shotgun: requesting from all peers"
                            );
                            last_hol_rerequest = std::time::Instant::now();
                        }
                    }
                }
            }

            // Head-of-line escalation: when tip+1 is stalled >60s despite shotgun,
            // clear stale peer assignments and force emergency re-request to all peers.
            if header_sync.synced
                && !block_sync.download_paused
                && !sync_state.is_replaying()
                && last_block_connect.elapsed() > std::time::Duration::from_secs(60)
                && last_hol_escalation.elapsed() > std::time::Duration::from_secs(120)
            {
                let next_height = chain_state.lock().await.best_height + 1;
                if next_height <= header_sync.best_height {
                    if let Ok(Some(next_hash)) = header_index.get_hash_at_height(next_height) {
                        let peers_snapshot = shared_peers.read().await;
                        let block_h = chain_state.lock().await.best_height;
                        let header_tip = header_index
                            .get_header_tip_height()
                            .ok()
                            .flatten()
                            .unwrap_or(block_h);
                        let emergency_ids =
                            eligible_download_peer_ids(&peers_snapshot, block_h, header_tip);
                        drop(peers_snapshot);

                        if !emergency_ids.is_empty() {
                            warn!(
                                height = next_height,
                                hash = %next_hash,
                                peers = emergency_ids.len(),
                                secs_since_block = last_block_connect.elapsed().as_secs(),
                                "Head-of-line block stalled — escalating to all eligible peers"
                            );

                            block_sync.in_flight.remove(&next_hash);
                            for set in block_sync.peer_requests.values_mut() {
                                set.remove(&next_hash);
                            }
                            block_sync.queue.retain(|h| *h != next_hash);
                            block_sync.queue.push_front(next_hash);

                            let cmds = block_sync.assign_to_peers_emergency(&emergency_ids);
                            for cmd in cmds {
                                let _ = command_tx.try_send(cmd);
                            }

                            let stale_disconnects = block_sync
                                .chronic_non_deliverers(10, 2)
                                .into_iter()
                                .filter(|pid| emergency_ids.contains(pid))
                                .collect::<Vec<_>>();
                            for pid in stale_disconnects {
                                warn!(
                                    peer_id = pid,
                                    "Disconnecting stale peer during head-of-line escalation"
                                );
                                let _ = command_tx
                                    .try_send(PeerCommand::DisconnectPeer { peer_id: pid });
                                block_sync.peer_disconnected(pid);
                            }

                            last_hol_escalation = std::time::Instant::now();
                            last_hol_rerequest = std::time::Instant::now();
                        }
                    }
                }
            }

            // Early exit if shutdown was signaled
            if shutting_down.load(std::sync::atomic::Ordering::Relaxed) {
                let _ = command_tx.try_send(PeerCommand::Shutdown);
                break;
            }

            // Skip all maintenance when shutting down — go straight to select!
            // so the shutdown_rx branch fires immediately.
            if shutting_down.load(std::sync::atomic::Ordering::Relaxed) {
                let _ = command_tx.try_send(PeerCommand::Shutdown);
                break;
            }

            // Reconcile header_sync with the locally-validated tip. Local mining
            // (Stratum submit_mined_block / RPC generate_to_address) advances chain_state
            // and the header_index tip but never updates this loop's header_sync, leaving
            // it stale — the root of false reorgs and sticky IBD after local mining.
            let cs_height = *shared_best_height.read().await;
            if cs_height > header_sync.best_height {
                let cs_hash = *shared_best_hash.read().await;
                info!(
                    from = header_sync.best_height,
                    to = cs_height,
                    "Reconciling header_sync to locally-mined chain tip"
                );
                header_sync.best_height = cs_height;
                header_sync.best_hash = cs_hash;
                header_sync.best_chain_work = header_index
                    .get_header(&cs_hash)
                    .ok()
                    .flatten()
                    .map(|h| h.chain_work)
                    .unwrap_or(header_sync.best_chain_work);
                if header_sync.has_min_chain_work() {
                    header_sync.synced = true;
                }
            }

            // Keep the sync-progress denominator honest: once headers are
            // synced, our PoW-backed header tip is authoritative — overwrite
            // (don't max) peer_best_height so any bogus peer start_height
            // claim accepted before sync completed self-heals here.
            if header_sync.synced && header_sync.best_height != last_progress_denominator {
                chain_state.lock().await.peer_best_height = Some(header_sync.best_height);
                last_progress_denominator = header_sync.best_height;
            }

            // Header sync stall detection: if no progress for 30 s, re-request.
            if !header_sync.synced {
                if header_sync.best_height > last_header_height {
                    last_header_height = header_sync.best_height;
                    last_header_progress = std::time::Instant::now();
                } else if last_header_progress.elapsed() > std::time::Duration::from_secs(30) {
                    // Rotate to a DIFFERENT random peer on stall.
                    // Prefer peers whose claimed height is above our header tip —
                    // random selection kept landing on height=0 spy nodes and
                    // behind-peers (other IBD nodes) that answer with nothing,
                    // burning a full 30 s stall cycle each time. Fall back to any
                    // peer if none claim a higher chain (heights can be stale).
                    let peers = shared_peers.read().await;
                    // Prefer peers at or above our tip (>= so at-tip restarts
                    // can still confirm completion); height-0 spy nodes only
                    // as a last resort via the fallback below.
                    let ahead: Vec<u64> = peers
                        .iter()
                        .filter(|p| {
                            Some(p.id) != header_sync_peer
                                && p.start_height > 0
                                && (p.start_height as i64) >= header_sync.best_height as i64
                        })
                        .map(|p| p.id)
                        .collect();
                    let mut candidates: Vec<u64> = if ahead.is_empty() {
                        peers
                            .iter()
                            .filter(|p| Some(p.id) != header_sync_peer)
                            .map(|p| p.id)
                            .collect()
                    } else {
                        ahead
                    };
                    drop(peers);
                    if !candidates.is_empty() {
                        use rand::seq::SliceRandom;
                        candidates.shuffle(&mut rand::thread_rng());
                        // Send getheaders to up to 3 random peers to increase
                        // chance of getting a response.
                        let targets: Vec<u64> = candidates.iter().copied().take(3).collect();
                        let pid = targets[0];
                        for &t in &targets {
                            let cmd = header_sync.build_getheaders_command(t);
                            let _ = command_tx.try_send(cmd);
                        }
                        // During IBD a header-sync stall is a real problem;
                        // once synced it's a routine re-poll after a quiet spell.
                        if header_sync.synced {
                            info!(
                                peer_id = pid,
                                peers_tried = targets.len(),
                                old_peer = ?header_sync_peer,
                                height = header_sync.best_height,
                                "Header sync stalled, sending getheaders to multiple peers"
                            );
                        } else {
                            warn!(
                                peer_id = pid,
                                peers_tried = targets.len(),
                                old_peer = ?header_sync_peer,
                                height = header_sync.best_height,
                                "Header sync stalled, sending getheaders to multiple peers"
                            );
                        }
                        header_sync_peer = Some(pid);
                        getheaders_in_flight = true;
                        last_header_progress = std::time::Instant::now();
                    }
                }
            }

            // Post-sync catch-up: if we think sync is complete but peers report
            // a higher height, periodically retry getheaders with a different peer.
            // This handles the case where the initial sync peer had stale data or
            // where new blocks arrived while we were syncing.
            if header_sync.synced && block_sync.in_flight.is_empty() {
                let cs_height = chain_state.lock().await.best_height;
                let peers = shared_peers.read().await;
                let best_peer_height = peers
                    .iter()
                    .filter(|p| p.start_height > 0)
                    .map(|p| p.start_height as u32)
                    .max()
                    .unwrap_or(0);
                // Pick a peer different from the last sync peer if possible
                let retry_peer = peers
                    .iter()
                    .filter(|p| Some(p.id) != header_sync_peer && p.start_height > 0)
                    .max_by_key(|p| p.start_height)
                    .or_else(|| peers.first())
                    .map(|p| p.id);
                drop(peers);
                if best_peer_height > header_sync.best_height && cs_height < best_peer_height {
                    // Track consecutive catch-up failures at the same height.
                    if header_sync.best_height == catchup_stall_height {
                        catchup_stall_count += 1;
                    } else {
                        catchup_stall_height = header_sync.best_height;
                        catchup_stall_count = 1;
                    }

                    // After 3 failed rounds, no peer could provide headers beyond
                    // our tip.  The peer(s) claiming a higher chain are lying or
                    // stale (common with monitoring/crawler nodes).  Clamp their
                    // start_height to our tip so the loop stops.
                    if catchup_stall_count >= 3 {
                        let our_tip = header_sync.best_height as i32;
                        let mut peers = shared_peers.write().await;
                        for peer in peers.iter_mut() {
                            if peer.start_height > our_tip {
                                info!(
                                    peer_id = peer.id,
                                    claimed_height = peer.start_height,
                                    our_height = our_tip,
                                    user_agent = %peer.user_agent,
                                    "Clamping peer start_height — peer could not provide headers above our tip"
                                );
                                peer.start_height = our_tip;
                                // Claiming a chain it cannot serve is the same
                                // offense as serving unconnecting headers —
                                // score it so repeat offenders get banned.
                                let _ = command_tx.try_send(PeerCommand::Misbehaving {
                                    peer_id: peer.id,
                                    reason: bitcoinpr_p2p::Misbehavior::UnconnectingHeaders,
                                });
                            }
                        }
                        drop(peers);
                        catchup_stall_count = 0;
                    } else if let Some(pid) = retry_peer {
                        info!(
                            our_height = header_sync.best_height,
                            peer_height = best_peer_height,
                            peer_id = pid,
                            "Peers report higher chain — retrying header sync"
                        );
                        header_sync.synced = false;
                        let cmd = header_sync.build_getheaders_command(pid);
                        let _ = command_tx.try_send(cmd);
                        header_sync_peer = Some(pid);
                        getheaders_in_flight = true;
                    }
                }
            }

            // Periodic mempool expiry (every 10 minutes)
            if last_expiry_check.elapsed() > std::time::Duration::from_secs(600) {
                shared_mempool.write().await.expire_old_transactions();
                last_expiry_check = std::time::Instant::now();
            }

            // Block-file pruning (Phase 3, 2026-07-02 review): every 5 minutes
            // when enabled, delete the oldest block files beyond the prune
            // target. The pruner itself enforces the safety window (288 recent
            // blocks, nothing above the last UTXO-flushed height). Runs on a
            // blocking thread — it is index walks and file deletion.
            if let Some(target_bytes) = prune_target_bytes {
                if last_prune_check.elapsed() > std::time::Duration::from_secs(300)
                    && !prune_running.load(std::sync::atomic::Ordering::Relaxed)
                {
                    last_prune_check = std::time::Instant::now();
                    let tip = *shared_best_height.read().await;
                    let bs = block_store.clone();
                    let hi = header_index.clone();
                    let us = utxo_set.clone();
                    let running = prune_running.clone();
                    running.store(true, std::sync::atomic::Ordering::Relaxed);
                    tokio::task::spawn_blocking(move || {
                        let validated = hi.get_validated_height().ok().flatten();
                        if let Some(ceiling) =
                            bitcoinpr_storage::prune_ceiling(tip, validated, None)
                        {
                            match bitcoinpr_storage::prune_block_files(
                                &bs,
                                &hi,
                                &us,
                                ceiling,
                                target_bytes,
                            ) {
                                Ok(Some(report)) => {
                                    info!(
                                        files = report.files_deleted,
                                        bytes = report.bytes_freed,
                                        pruned_height = report.pruned_height,
                                        "Prune pass complete"
                                    );
                                }
                                Ok(None) => {}
                                Err(e) => warn!(error = %e, "Prune pass failed"),
                            }
                        }
                        running.store(false, std::sync::atomic::Ordering::Relaxed);
                    });
                }
            }

            // Index catch-up: scripthash and tx indexes may fall behind when blocks
            // are connected outside the drain loop (e.g. generatetoaddress, Stratum).
            // Every 10 s, if not in IBD and not already catching up, check for gaps
            // and spawn a background backfill to close them.
            #[cfg(feature = "indexing")]
            if !is_ibd.load(std::sync::atomic::Ordering::Relaxed)
                && !sync_state.is_replaying()
                && last_index_catchup.elapsed() > std::time::Duration::from_secs(10)
                && !index_catchup_running.load(std::sync::atomic::Ordering::Relaxed)
            {
                let best = *shared_best_height.read().await;

                // Scripthash index catch-up
                if let Some(ref idx) = scripthash_index {
                    let indexed = idx.get_indexed_height().ok().flatten().unwrap_or(0);
                    if indexed < best {
                        spawn_scripthash_backfill(
                            idx.clone(),
                            header_index.clone(),
                            block_store.clone(),
                            indexed + 1,
                            best,
                            shutting_down.clone(),
                            Some(index_catchup_running.clone()),
                            scripthash_indexed_height.clone(),
                        );
                    }
                }

                // Tx index catch-up
                if let Some(ref ti) = tx_index {
                    let indexed = ti.get_indexed_height().ok().flatten().unwrap_or(0);
                    if indexed < best {
                        let from = indexed + 1;
                        let ti2 = ti.clone();
                        let hi2 = header_index.clone();
                        let bs2 = block_store.clone();
                        tokio::task::spawn_blocking(move || {
                            let mut n = 0u32;
                            for h in from..=best {
                                if let Ok(Some(hash)) = hi2.get_hash_at_height(h) {
                                    if let Ok(Some(pos)) = hi2.get_block_pos(&hash) {
                                        if let Ok(raw) = bs2.read_block(&pos) {
                                            if let Ok(block) =
                                                bitcoin::consensus::encode::deserialize::<
                                                    bitcoin::Block,
                                                >(
                                                    &raw
                                                )
                                            {
                                                let txids: Vec<bitcoin::Txid> = block
                                                    .txdata
                                                    .iter()
                                                    .map(|tx| tx.compute_txid())
                                                    .collect();
                                                if let Err(e) =
                                                    ti2.index_block_at_height(&hash, &txids, h)
                                                {
                                                    tracing::warn!(height = h, error = %e, "Index catch-up: tx index error");
                                                } else {
                                                    n += 1;
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                            if n > 0 {
                                tracing::info!(
                                    from,
                                    to = best,
                                    blocks = n,
                                    "Index catch-up: tx index updated"
                                );
                            }
                        });
                    }
                }

                last_index_catchup = std::time::Instant::now();
            }

            // Diagnostic: log pipeline state every 60s when stalled to aid debugging
            if last_block_connect.elapsed() > std::time::Duration::from_secs(60)
                && last_diagnostic.elapsed() > std::time::Duration::from_secs(60)
            {
                let peers = shared_peers.read().await;
                let peer_count = peers.len();
                let block_tip = chain_state.lock().await.best_height;
                let header_tip = header_index
                    .get_header_tip_height()
                    .ok()
                    .flatten()
                    .unwrap_or(block_tip);
                let good_peers = count_eligible_download_peers(&peers, block_tip, header_tip);
                drop(peers);
                let total_pending: usize = pending_blocks.values().map(|q| q.len()).sum();
                debug!(
                    in_flight = block_sync.in_flight.len(),
                    queue = block_sync.queue.len(),
                    pending = total_pending,
                    received_set = block_sync.received.len(),
                    peers = peer_count,
                    good_peers,
                    secs_since_block = last_block_connect.elapsed().as_secs(),
                    "Pipeline diagnostic"
                );
                last_diagnostic = std::time::Instant::now();

                // Proactive recovery when the peer pool has collapsed during deep IBD.
                // Skipped while download is paused for min-chain-work header sync:
                // no blocks arriving is expected then, not a collapse.
                if !block_sync.download_paused
                    && good_peers <= 2
                    && block_sync.queue.len() > 5_000
                    && last_block_connect.elapsed() > std::time::Duration::from_secs(60)
                    && last_aggressive_peer_refresh.elapsed() > std::time::Duration::from_secs(120)
                {
                    warn!(
                        good_peers,
                        queue = block_sync.queue.len(),
                        block_tip,
                        header_tip,
                        "Pipeline collapsed — aggressive peer refresh and emergency assignment"
                    );
                    let _ = command_tx.try_send(PeerCommand::RefreshPeerConnections {
                        disconnect_zero_height_inbound: true,
                        target_outbound: 24,
                    });
                    last_aggressive_peer_refresh = std::time::Instant::now();

                    let peers_snapshot = shared_peers.read().await;
                    let emergency_ids =
                        eligible_download_peer_ids(&peers_snapshot, block_tip, header_tip);
                    drop(peers_snapshot);
                    if !emergency_ids.is_empty() {
                        let cmds = block_sync.assign_to_peers_emergency(&emergency_ids);
                        for cmd in cmds {
                            let _ = command_tx.try_send(cmd);
                        }
                    }

                    if good_peers == 1 {
                        if let Some((worst_peer, cycles)) = block_sync
                            .peer_stale_cycles
                            .iter()
                            .max_by_key(|(_, c)| *c)
                            .map(|(pid, c)| (*pid, *c))
                        {
                            if cycles >= 2 {
                                warn!(
                                    peer_id = worst_peer,
                                    stale_cycles = cycles,
                                    "Disconnecting worst stale-cycle peer to force rotation"
                                );
                                let _ = command_tx.try_send(PeerCommand::DisconnectPeer {
                                    peer_id: worst_peer,
                                });
                                block_sync.peer_disconnected(worst_peer);
                            }
                        }
                    }
                }

                // Safety net A: if is_ibd is still set but block tip already
                // matches the validated header-index tip, clear IBD now.  This
                // catches the case where replay_end_height was inflated by a peer
                // on a different chain and those blocks were never downloaded,
                // leaving the AtomicBool stuck at true indefinitely.
                if !sync_state.is_replaying() && is_ibd.load(std::sync::atomic::Ordering::Relaxed) {
                    let block_tip = chain_state.lock().await.best_height;
                    let header_tip = header_index
                        .get_header_tip_height()
                        .ok()
                        .flatten()
                        .unwrap_or(0);
                    if block_tip >= header_tip && header_tip > 0 {
                        let was_ibd = is_ibd.swap(false, std::sync::atomic::Ordering::Relaxed);
                        if was_ibd {
                            info!(
                                height = block_tip,
                                header_tip,
                                "IBD clear (pipeline diagnostic) — block tip matches validated header index"
                            );
                            let tip_hash = *shared_best_hash.read().await;
                            event_bus.publish(NodeNotification::NewBlock {
                                hash: tip_hash.to_string(),
                                height: block_tip,
                            });
                        }
                    }
                    // Safety net B: IBD has been stuck for >5 minutes with no block
                    // progress — the header tip is almost certainly pointing at an
                    // unreachable fork chain (a minority-fork peer pushed headers with
                    // more cumulative work, those blocks can never be validated).
                    //
                    // Reset the header tip to our validated chain tip and trigger a
                    // fresh header sync.  We do NOT clear is_ibd here — instead we let
                    // the normal flow clear it once the correct headers arrive from
                    // live peers and the missing blocks are downloaded and connected.
                    // This avoids a race where mining starts on a stale block before
                    // the P2P engine finishes filling the gap.
                    else if block_tip < header_tip
                        && last_block_connect.elapsed() > std::time::Duration::from_secs(300)
                        && good_peers > 0
                    {
                        let block_tip_hash = *shared_best_hash.read().await;
                        warn!(
                            block_tip,
                            header_tip,
                            secs_without_block = last_block_connect.elapsed().as_secs(),
                            "IBD stuck for >5 min — resetting fork-contaminated header tip and \
                             triggering fresh header sync"
                        );
                        if let Err(e) =
                            header_index.reset_fork_header_tip(block_tip, &block_tip_hash)
                        {
                            warn!("reset_fork_header_tip failed: {}", e);
                        } else {
                            header_sync.best_height = block_tip;
                            header_sync.best_hash = block_tip_hash;
                            header_sync.synced = false;
                            block_sync.queue.clear();
                            block_sync.in_flight.clear();
                            block_sync.received.clear();
                            pending_blocks.clear();
                            // Reset the debounce timer so this fires at most once every
                            // 5 minutes even if block download stalls again.
                            last_block_connect = std::time::Instant::now();
                            last_diagnostic = std::time::Instant::now();
                            info!(
                                height = block_tip,
                                "Fork-tip reset complete — awaiting corrected headers from peers"
                            );
                        }
                    }
                }

                // Safety net C: post-IBD orphaned pipeline.
                // After IBD completes and local mining takes over, peer-downloaded
                // blocks can get stuck in the pipeline if r1 mined a competing block
                // at the same height (different hash), orphaning all downloaded blocks
                // that extend from the peer's version of that height.
                // Symptom: in_flight=1/queue=0/pending=N with no block progress for
                // >120 s while the block tip already matches the header tip.
                //
                // Condition: NOT in IBD, block_tip matches header_tip (chain is fully
                // connected), but block_sync still has stale entries from the old peer
                // chain branch and the pipeline has been stuck for >120 s.
                if !is_ibd.load(std::sync::atomic::Ordering::Relaxed)
                    && last_block_connect.elapsed() > std::time::Duration::from_secs(120)
                    && (block_sync.in_flight.len() + block_sync.queue.len() > 0
                        || !pending_blocks.is_empty())
                {
                    let c_block_tip = chain_state.lock().await.best_height;
                    let c_header_tip = header_index
                        .get_header_tip_height()
                        .ok()
                        .flatten()
                        .unwrap_or(0);
                    if c_block_tip >= c_header_tip && c_header_tip > 0 {
                        let stale_inflight = block_sync.in_flight.len();
                        let stale_queued = block_sync.queue.len();
                        let stale_pending = pending_blocks.values().map(|q| q.len()).sum::<usize>();
                        warn!(
                            block_tip = c_block_tip,
                            header_tip = c_header_tip,
                            stale_inflight,
                            stale_queued,
                            stale_pending,
                            "Post-IBD orphaned pipeline — chain is synced but sync state has \
                             stale entries from an old peer chain branch; clearing"
                        );
                        block_sync.queue.clear();
                        block_sync.in_flight.clear();
                        block_sync
                            .peer_requests
                            .values_mut()
                            .for_each(|s| s.clear());
                        block_sync.block_notfound_peers.clear();
                        pending_blocks.clear();
                        last_block_connect = std::time::Instant::now();
                        last_diagnostic = std::time::Instant::now();
                    }
                }

                // If deeply stalled (>120s), clear the received set.  Blocks in
                // `received` are supposed to be in pending_blocks, but the OOM
                // eviction may have dropped them.  Clearing lets them be
                // re-scheduled so they can be fetched again.
                if last_block_connect.elapsed() > std::time::Duration::from_secs(120)
                    && !block_sync.received.is_empty()
                {
                    let cleared = block_sync.received.len();
                    block_sync.received.clear();
                    info!(cleared, "Cleared stale received set to allow re-scheduling");

                    // Force reschedule: the blocks just cleared from `received`
                    // are now eligible for schedule() again.
                    let cs_h = chain_state.lock().await.best_height;
                    let _in_pipe = block_sync.in_flight.len() + block_sync.queue.len();
                    let sched_start = cs_h + 1;
                    let sched_end = header_sync
                        .best_height
                        .min(sched_start + BLOCK_FETCH_HEIGHT_SPAN);
                    let mut hashes = Vec::new();
                    for h in sched_start..=sched_end {
                        if let Ok(Some(hash)) = header_index.get_hash_at_height(h) {
                            if !block_sync.in_flight.contains_key(&hash) {
                                hashes.push(hash);
                            }
                        }
                    }
                    if !hashes.is_empty() {
                        info!(
                            count = hashes.len(),
                            "Re-scheduling blocks after received set clear"
                        );
                        block_sync.schedule(hashes);
                    }
                }
            }

            // Per-peer stale timeout: clear in-flight requests only for peers that
            // haven't delivered within a graduated timeout. With NODE_NETWORK
            // filtering, we only assign to archive peers, so timeouts can be
            // much tighter (Bitcoin Core uses 2s base). We use 10s base + 200ms
            // per assigned block, firing after 15s stall with 10s debounce.
            // Skip during replay — we're not expecting blocks from peers.
            let stale_block_height = chain_state.lock().await.best_height;
            let stale_base = stale_base_timeout(stale_block_height);
            // Exponential backoff: each consecutive clear that yields no
            // delivery doubles the debounce (capped at 8x).
            let stale_debounce = std::time::Duration::from_secs((stale_base.as_secs() / 3).max(10))
                * 2u32.pow(consecutive_stale_clears.min(3));
            let stale_connect_gate =
                std::time::Duration::from_secs((stale_base.as_secs() / 2).max(15));
            // Network idle = no block received from ANY peer within the gate
            // period. If blocks are still arriving, the bottleneck is local
            // validation — clearing and re-requesting would only download the
            // same blocks twice. Only clear when the network itself is silent.
            let network_idle = block_sync
                .since_last_recv()
                .is_none_or(|d| d > stale_connect_gate);
            if !network_idle {
                consecutive_stale_clears = 0;
            }
            if !sync_state.is_replaying()
                && !block_sync.in_flight.is_empty()
                && network_idle
                && last_block_connect.elapsed() > stale_connect_gate
                && last_stale_clear.elapsed() > stale_debounce
            {
                let (stale_count, stale_peers) = block_sync.clear_stale_peers(
                    stale_base, true, // track stale cycles for peer eviction
                );
                last_stale_clear = std::time::Instant::now();
                if stale_count > 0 {
                    consecutive_stale_clears += 1;
                    warn!(
                        stale_count,
                        stale_peers,
                        secs_since_last_block = last_block_connect.elapsed().as_secs(),
                        secs_since_last_recv = block_sync.since_last_recv().map(|d| d.as_secs()),
                        backoff_factor = 2u32.pow(consecutive_stale_clears.min(3)),
                        "Cleared stale per-peer block requests, reassigning"
                    );
                    // Reassign re-queued blocks to remaining healthy peers
                    let peers = shared_peers.read().await;
                    let block_h = chain_state.lock().await.best_height;
                    let header_tip = header_index
                        .get_header_tip_height()
                        .ok()
                        .flatten()
                        .unwrap_or(block_h);
                    let peer_ids = eligible_download_peer_ids(&peers, block_h, header_tip);
                    drop(peers);
                    if !peer_ids.is_empty() {
                        let cmds = block_sync.assign_to_peers(&peer_ids);
                        for cmd in cmds {
                            let _ = command_tx.try_send(cmd);
                        }
                    }
                }

                // Disconnect peers that are chronic non-deliverers:
                // - >50 notfound blocks (pruned peers), OR
                // - 3+ stale-clear cycles without delivering any blocks (silent non-deliverers)
                let non_deliverers = block_sync.chronic_non_deliverers(50, 3);
                for pid in non_deliverers {
                    warn!(
                        peer_id = pid,
                        "Disconnecting non-delivering peer (pruned or silent)"
                    );
                    let _ = command_tx.try_send(PeerCommand::DisconnectPeer { peer_id: pid });
                    block_sync.peer_disconnected(pid);
                }
            }

            // Individual stale-peer eviction (above) handles non-delivering peers.
            // A prior "nuclear reset" that disconnected ALL peers was removed because
            // it caused a rapid connect/disconnect cycle that triggers Bitcoin Core's
            // anti-DoS protections (discouragement/ban). The root cause of stalls is
            // event loop blocking, not bad peers.

            // Re-request missing blocks when we're behind the header tip and
            // the download pipeline has stalled (no block connected in 30s).
            // This covers two cases:
            //   1. in_flight is empty — nothing was requested at all
            //   2. in_flight is non-empty but requests went to dead/slow peers
            //      and the stale-clear cycle hasn't recovered them yet
            // In case 2 we flush stale in-flight entries first, then schedule
            // fresh requests to currently-connected peers.
            // Fire on its own 30s debounce — don't gate on last_block_connect
            // because head-of-line trickle resets it, preventing bulk recovery.
            // Use chain-advancing metric, not blocks_arriving (blocks arriving
            // at wrong heights don't help and shouldn't suppress recovery).
            // Recover faster when the download pipeline is *idle* (nothing in flight
            // or queued). An idle pipeline with the block tip behind the header tip
            // means we're stuck — typically a reorg/gap where the fork blocks need
            // (re)requesting — not a slow large-block IBD download in progress. In
            // that case there's no reason to wait the full minute, so drop the
            // debounce to ~15 s. Keep the conservative 60 s when actively
            // downloading so we don't spam peers mid-IBD.
            let pipeline_idle = block_sync.in_flight.is_empty() && block_sync.queue.is_empty();
            let rerequest_debounce = if pipeline_idle { 15 } else { 60 };
            let stall_debounce = if pipeline_idle { 10 } else { 30 };

            // Stuck-with-orphans recovery: if the pipeline is idle but we're holding
            // buffered orphan blocks (received but un-connectable because an ancestor
            // is missing or we're on a losing fork), the per-arrival orphan getheaders
            // above won't re-fire — it only triggers when a NEW orphan lands. Re-ask
            // the best peer for headers anchored at our connected block tip so it
            // re-serves the correct chain forward and heals the gap/reorg without
            // waiting for the (post-IBD-disabled) IBD safety nets. ~10 s debounce via
            // last_orphan_getheaders.
            // Recovery trigger: an idle pipeline that is nonetheless behind. Two
            // ways to be stuck:
            //   (a) holding buffered orphan blocks (pending_blocks non-empty) whose
            //       ancestor never connected, or
            //   (b) connected tip strictly below the header tip with nothing in
            //       flight — e.g. a reorg disconnected to the fork point and cleared
            //       pending_blocks, so no buffered orphan remains to key on. This is
            //       the case that permanently stranded the hub: connected at the
            //       fork point, header tip ahead, pipeline empty, no signal to retry.
            let (tip, tip_height) = {
                let cs = chain_state.lock().await;
                (cs.best_hash, cs.best_height)
            };
            let recovery_header_tip = header_index
                .get_header_tip_height()
                .ok()
                .flatten()
                .unwrap_or(header_sync.best_height);
            let behind_header_tip = tip_height < recovery_header_tip;
            // NOTE: deliberately NOT gated on header_sync.synced. A reorg onto a
            // chain whose headers are not yet fully synced leaves synced=false; if
            // a peer then announces a header that does not connect (gap to the new
            // tip) the header chain wedges with no getheaders follow-up, and a
            // synced-gated recovery would never re-trigger it. Re-issuing getheaders
            // anchored at the block tip is idempotent and safe; is_catching_up below
            // still suppresses it during deep IBD.
            if pipeline_idle
                && (!pending_blocks.is_empty() || behind_header_tip)
                && last_orphan_getheaders.elapsed() > std::time::Duration::from_secs(10)
            {
                let header_tip = recovery_header_tip;
                if is_catching_up(tip_height, header_tip) {
                    // Deep block catch-up: out-of-order arrivals are expected.
                } else {
                    let best_peer = {
                        let peers = shared_peers.read().await;
                        {
                            let block_h = chain_state.lock().await.best_height;
                            let header_tip = header_index
                                .get_header_tip_height()
                                .ok()
                                .flatten()
                                .unwrap_or(block_h);
                            peers
                                .iter()
                                .filter(|p| {
                                    bitcoinpr_p2p::peer_eligible_for_download(
                                        p, block_h, header_tip,
                                    )
                                })
                                .max_by_key(|p| p.start_height)
                                .map(|p| p.id)
                        }
                    };
                    if let Some(pid) = best_peer {
                        let cmd = header_sync.build_getheaders_command_from(pid, tip, tip_height);
                        let _ = command_tx.try_send(cmd);
                        last_orphan_getheaders = std::time::Instant::now();
                        let pending: usize = pending_blocks.values().map(|q| q.len()).sum();
                        info!(
                        peer_id = pid,
                        tip_height,
                        pending,
                        "Stuck with buffered orphans + idle pipeline — re-requesting headers anchored at block tip"
                    );
                    }
                }
            }

            // Aggressive peer maintenance when far behind with too few download peers.
            {
                let block_tip = chain_state.lock().await.best_height;
                let header_tip = header_index
                    .get_header_tip_height()
                    .ok()
                    .flatten()
                    .unwrap_or(block_tip);
                if header_tip.saturating_sub(block_tip) > 10_000
                    && last_aggressive_peer_refresh.elapsed() > std::time::Duration::from_secs(60)
                {
                    let peers_snapshot = shared_peers.read().await;
                    let good =
                        count_eligible_download_peers(&peers_snapshot, block_tip, header_tip);
                    drop(peers_snapshot);
                    if good <= 2 {
                        info!(
                            good_peers = good,
                            block_tip,
                            header_tip,
                            "Few download peers while far behind — refreshing peer pool"
                        );
                        let _ = command_tx.try_send(PeerCommand::RefreshPeerConnections {
                            disconnect_zero_height_inbound: true,
                            target_outbound: 24,
                        });
                        last_aggressive_peer_refresh = std::time::Instant::now();
                    }
                }

                // Slow-circuit eviction: during deep IBD, disconnect peers whose
                // measured delivery bandwidth is far below the pool median. Each
                // redial draws a fresh Tor circuit (proxyrandomize), so culling
                // the slowest tail steadily accumulates fast circuits. The
                // relative gate means a uniformly slow pool (ISP shaping,
                // all-onion ceiling) evicts nobody.
                if header_tip.saturating_sub(block_tip) > 10_000
                    && last_slow_circuit_evict.elapsed() > std::time::Duration::from_secs(60)
                {
                    last_slow_circuit_evict = std::time::Instant::now();
                    for pid in block_sync.slow_deliverers(8, 0.25, 8, 2) {
                        warn!(
                            peer_id = pid,
                            "Evicting persistently slow block deliverer — redial draws a fresh circuit"
                        );
                        let _ = command_tx.try_send(PeerCommand::DisconnectPeer { peer_id: pid });
                        block_sync.peer_disconnected(pid);
                    }
                }
            }

            if !block_sync.download_paused
                && last_block_rerequest.elapsed()
                    > std::time::Duration::from_secs(rerequest_debounce)
                && last_block_connect.elapsed() > std::time::Duration::from_secs(stall_debounce)
            {
                let cs_height = chain_state.lock().await.best_height;
                // Use the validated header *index* tip, not just the in-memory
                // header-sync cursor. After a reorg the cursor (header_sync.best_height)
                // can lag the index tip; gating on the cursor alone would leave the
                // node stranded below a header chain it already knows about, never
                // re-requesting the missing blocks. Take whichever is higher.
                let effective_header_tip = header_sync.best_height.max(
                    header_index
                        .get_header_tip_height()
                        .ok()
                        .flatten()
                        .unwrap_or(0),
                );
                // Not gated on header_sync.synced or gap size. The stall signal is
                // "behind the header chain with no recent block connect" — already
                // enforced by the last_block_connect/last_block_rerequest debounces
                // above. A reorg deeper than IBD_CATCH_UP_MARGIN must still recover;
                // gating on is_catching_up would strand exactly those deep reorgs.
                // Healthy IBD keeps last_block_connect fresh, so this won't fire and
                // double-drive the normal download path.
                if cs_height < effective_header_tip {
                    // Flush any in-flight requests that haven't delivered — they're
                    // likely assigned to peers that silently dropped our getdata.
                    if !block_sync.in_flight.is_empty() {
                        let (stale_count, _) = block_sync.clear_stale_peers(
                            stale_base,
                            false, // don't track cycles — pipeline stall fires too frequently
                        );
                        if stale_count > 0 {
                            warn!(
                                stale_count,
                                "Pipeline stall: cleared stale in-flight requests"
                            );
                        }
                    }

                    // Note: peer eviction only runs in the main stale clear path (120s
                    // debounce) which properly tracks stale cycles. The pipeline stall
                    // path fires too frequently (30s) to count cycles accurately.

                    let peers = shared_peers.read().await;
                    let block_h = chain_state.lock().await.best_height;
                    let header_tip = header_index
                        .get_header_tip_height()
                        .ok()
                        .flatten()
                        .unwrap_or(block_h);
                    let peer_ids = eligible_download_peer_ids(&peers, block_h, header_tip);
                    drop(peers);
                    if !peer_ids.is_empty() {
                        // Always reschedule from chain tip when stalled. The old
                        // condition (queue.is_empty && in_flight.is_empty) almost
                        // never held because stale-clear puts blocks back in queue.
                        let start = cs_height + 1;
                        let end = effective_header_tip;
                        let batch_end = end.min(start + BLOCK_FETCH_HEIGHT_SPAN);
                        let mut hashes = Vec::new();
                        // Lazily-built fallback map for heights where the height→hash
                        // index has a hole. Mid-reorg the index can lag the header
                        // chain; relying on get_hash_at_height alone would silently
                        // skip the missing intermediate block and strand the download
                        // (the node sticks one block behind forever). When a hole is
                        // hit, walk back from the header tip via prev_blockhash to
                        // recover the canonical hash at each height in the batch.
                        let mut gap_map: Option<
                            std::collections::HashMap<u32, bitcoin::BlockHash>,
                        > = None;
                        for h in start..=batch_end {
                            if let Ok(Some(hash)) = header_index.get_hash_at_height(h) {
                                hashes.push(hash);
                                continue;
                            }
                            let map = gap_map.get_or_insert_with(|| {
                                let mut m = std::collections::HashMap::new();
                                // Anchor the walk at the header *index* tip, not the
                                // header-sync cursor which can lag after a reorg.
                                let (mut wh, mut wht) = match (
                                    header_index.get_header_tip().ok().flatten(),
                                    header_index.get_header_tip_height().ok().flatten(),
                                ) {
                                    (Some(h), Some(ht)) => (h, ht),
                                    _ => (header_sync.best_hash, header_sync.best_height),
                                };
                                while wht >= start && wht > 0 {
                                    m.insert(wht, wh);
                                    match header_index.get_header(&wh) {
                                        Ok(Some(stored)) => {
                                            wh = stored.header.prev_blockhash;
                                            wht -= 1;
                                        }
                                        _ => break,
                                    }
                                }
                                m
                            });
                            if let Some(&hash) = map.get(&h) {
                                hashes.push(hash);
                            }
                        }
                        if !hashes.is_empty() {
                            info!(
                                start,
                                count = hashes.len(),
                                num_peers = peer_ids.len(),
                                "Re-requesting blocks from chain tip"
                            );
                            block_sync.schedule(hashes);
                        }
                        // Assign any queued blocks (from stale clearing or fresh schedule)
                        let cmds = block_sync.assign_to_peers(&peer_ids);
                        for cmd in cmds {
                            let _ = command_tx.try_send(cmd);
                        }
                        last_block_rerequest = std::time::Instant::now();
                    }
                }
            }

            // Keepalive: ping all peers every 2 minutes to prevent inactivity disconnects.
            if last_ping.elapsed() > std::time::Duration::from_secs(120) {
                let nonce = rand::random::<u64>();
                let ping_peers = shared_peers
                    .read()
                    .await
                    .iter()
                    .map(|p| p.id)
                    .collect::<Vec<_>>();
                for pid in ping_peers {
                    let _ = command_tx.try_send(PeerCommand::SendPing {
                        peer_id: pid,
                        nonce,
                    });
                }
                last_ping = std::time::Instant::now();
            }
        }

        // Graceful shutdown: save mempool and flush caches.
        // shutting_down is already set by the event loop; ensure background tasks see it.
        shutting_down.store(true, std::sync::atomic::Ordering::Relaxed);
        let _ = command_tx.try_send(PeerCommand::Shutdown);
        info!("Shutting down — please stand by while caches are flushed...");
        info!("Saving mempool to disk...");
        let mempool_data = shared_mempool.read().await.save_to_bytes();
        if let Err(e) = std::fs::write(&mempool_path, &mempool_data) {
            warn!("Failed to save mempool: {}", e);
        } else {
            info!(size = mempool_data.len(), "Mempool saved");
        }

        info!("Flushing UTXO cache...");
        // Set the final flush height so it's persisted atomically with the last UTXO flush
        let final_height = *shared_best_height.read().await;
        let final_hash = *shared_best_hash.read().await;
        let final_hash_bytes: &[u8; 32] = AsRef::<[u8; 32]>::as_ref(&final_hash);
        utxo_set.set_pending_flush_height(final_height, final_hash_bytes);
        utxo_set.flush_cache();

        // Drain any in-flight block writes and fsync the current blk*.dat file.
        // Without this, the most-recent block bytes may sit in the page cache and
        // a hard crash leaves a half-written record whose 4-byte size prefix reads
        // back as garbage on the next startup (the "block size mismatch: expected
        // N, got 4294967124" symptom that triggered the May-30 chain wipe).
        if let Err(e) = block_store.flush() {
            warn!("Block store flush on shutdown failed: {}", e);
        }

        // Persist the final chain tip now that UTXO is flushed to disk.
        // During normal operation, set_best_tip only advances on UTXO flushes
        // to maintain crash consistency.
        if let Err(e) = header_index.set_best_tip(&final_hash, final_height) {
            warn!("Failed to persist final chain tip: {}", e);
        }

        // Record last validated height for clean-shutdown detection on next startup
        if let Err(e) = header_index.set_validated_height(final_height) {
            warn!("Failed to record validated height: {}", e);
        } else {
            info!(
                height = final_height,
                "Recorded validated height for next startup"
            );
        }

        info!(
            blocks_validated,
            "Shutdown complete — cleaning up resources, please wait..."
        );

        // Wait briefly for background blocking tasks so RPC stop returns promptly.
        let wait_start = std::time::Instant::now();
        loop {
            #[cfg(feature = "indexing")]
            let backfill_busy =
                scripthash_backfill_running.load(std::sync::atomic::Ordering::Relaxed);
            #[cfg(not(feature = "indexing"))]
            let backfill_busy = false;
            let index_busy = index_catchup_running.load(std::sync::atomic::Ordering::Relaxed);
            if !backfill_busy && !index_busy {
                break;
            }
            if wait_start.elapsed() > std::time::Duration::from_secs(30) {
                warn!(
                    scripthash_backfill = backfill_busy,
                    index_catchup = index_busy,
                    "Background tasks still running after 30s — exiting anyway"
                );
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }

        Ok(())
    }
}
