use bitcoin::block::Header;
use bitcoin::hashes::Hash;
use bitcoin::BlockHash;
use bitcoinpr_core::ConsensusParams;
use bitcoinpr_storage::{HeaderIndex, StoredHeader};
use std::collections::VecDeque;
use std::sync::Arc;
use tracing::{debug, info, warn};

use crate::ibd::is_catching_up;
use crate::manager::PeerCommand;
use crate::peer::PeerId;

/// Why `process_headers` rejected a headers batch.
///
/// The distinction matters to the caller: `Invalid` means the *peer* sent
/// consensus-invalid headers (bad PoW, wrong nBits) and should be penalized;
/// `Storage` is a local failure that is not the peer's fault.
#[derive(Debug)]
pub enum HeaderSyncError {
    /// The peer sent a consensus-invalid header — penalize the peer.
    Invalid(String),
    /// Local storage failure — not attributable to the peer.
    Storage(String),
    /// The first header of the message doesn't connect to anything we know —
    /// typically a tip *announcement* (1-header `headers` message, Core-style
    /// block relay) that arrived while we're missing one or more blocks
    /// between our tip and it. Not the peer's fault and not ignorable: the
    /// caller must reply with a `getheaders` anchored at our tip so the peer
    /// fills the gap (Core's unconnecting-headers handling) — otherwise a
    /// node that misses one announcement is stranded until a block happens
    /// to build directly on its stale tip.
    Unconnected(String),
}

impl std::fmt::Display for HeaderSyncError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HeaderSyncError::Invalid(msg) => write!(f, "invalid header: {msg}"),
            HeaderSyncError::Storage(msg) => write!(f, "storage error: {msg}"),
            HeaderSyncError::Unconnected(msg) => write!(f, "unconnecting header: {msg}"),
        }
    }
}

impl std::error::Error for HeaderSyncError {}

/// Consecutive unconnecting-header messages from one peer before we stop
/// replying with `getheaders` and start scoring it (Core's
/// `MAX_NUM_UNCONNECTING_HEADERS_MSGS`). Without a cap, a peer serving
/// headers from a foreign chain locks the node in a getheaders ping-pong:
/// every unconnecting announcement triggers an unconditional re-request,
/// whose response doesn't connect either (observed 2026-07-12: ~7 msgs/sec
/// for ~2 min from a bogus /Satoshi:0.12.0/ peer).
pub const MAX_UNCONNECTING_HEADERS: u32 = 10;

/// Manages header-first synchronization.
pub struct HeaderSync {
    params: ConsensusParams,
    header_index: Arc<HeaderIndex>,
    /// Current best header height we know about.
    pub best_height: u32,
    /// Current best header hash.
    pub best_hash: BlockHash,
    /// Cumulative chain work of the best header (big-endian 256-bit).
    pub best_chain_work: [u8; 32],
    /// Whether we've completed initial header sync.
    pub synced: bool,
    /// Consecutive unconnecting-header messages per peer. Entries are
    /// removed when a peer's headers connect or it disconnects, so the map
    /// only holds currently-misbehaving peers.
    unconnecting: std::collections::HashMap<PeerId, u32>,
}

impl HeaderSync {
    pub fn new(
        params: ConsensusParams,
        header_index: Arc<HeaderIndex>,
        best_height: u32,
        best_hash: BlockHash,
    ) -> Self {
        let best_chain_work = header_index
            .get_header(&best_hash)
            .ok()
            .flatten()
            .map(|h| h.chain_work)
            .unwrap_or([0u8; 32]);
        HeaderSync {
            params,
            header_index,
            best_height,
            best_hash,
            best_chain_work,
            synced: false,
            unconnecting: std::collections::HashMap::new(),
        }
    }

    /// Record one more unconnecting-header message from `peer_id` and return
    /// the new consecutive count. The caller should stop re-requesting
    /// headers once the count reaches `MAX_UNCONNECTING_HEADERS` and apply a
    /// misbehavior penalty on every multiple of it.
    pub fn note_unconnecting(&mut self, peer_id: PeerId) -> u32 {
        let count = self.unconnecting.entry(peer_id).or_insert(0);
        *count = count.saturating_add(1);
        *count
    }

    /// Clear the unconnecting-header counter for `peer_id` — call when a
    /// headers message from that peer connects, or when it disconnects.
    pub fn reset_unconnecting(&mut self, peer_id: PeerId) {
        self.unconnecting.remove(&peer_id);
    }

    /// Whether the best header chain's cumulative work meets the network's
    /// hardcoded minimum (`ConsensusParams::min_chain_work`). Below this,
    /// block download is deferred and header sync is never marked complete.
    /// Big-endian byte comparison == numeric comparison.
    pub fn has_min_chain_work(&self) -> bool {
        self.best_chain_work >= self.params.min_chain_work
    }

    /// Build a getheaders command to send to a peer.
    pub fn build_getheaders_command(&self, peer_id: PeerId) -> PeerCommand {
        let locator_hashes = self.build_locator();
        PeerCommand::GetHeaders {
            peer_id,
            locator_hashes,
            stop_hash: BlockHash::all_zeros(),
        }
    }

    /// Build a getheaders command whose locator is anchored at a specific
    /// (connected) block tip rather than at `self.best_height` (the header tip).
    ///
    /// `build_getheaders_command` anchors the locator at the header-sync tip,
    /// which is correct during normal headers-first IBD. But when the header
    /// tip has run *ahead* of what we have actually connected — e.g. we accepted
    /// fork headers we can't yet connect, or an intermediate block went missing
    /// so later blocks buffer as orphans — the header-tip-anchored locator's
    /// top hash is a height the peer recognises as its own tip, so it answers
    /// with **zero headers** and the gap/reorg never heals. Anchoring at the
    /// connected block tip guarantees the peer finds a common ancestor at or
    /// below our real tip and serves everything forward (including a more-work
    /// fork, which it returns from the fork point). `tip_hash` is placed first
    /// so it is matched ahead of any stale height→hash entries.
    pub fn build_getheaders_command_from(
        &self,
        peer_id: PeerId,
        tip_hash: BlockHash,
        tip_height: u32,
    ) -> PeerCommand {
        let mut locator = vec![tip_hash];
        let mut height = tip_height as i64 - 1;
        let mut step: i64 = 1;
        while height >= 0 {
            if let Ok(Some(hash)) = self.header_index.get_hash_at_height(height as u32) {
                if hash != tip_hash {
                    locator.push(hash);
                }
            }
            if locator.len() >= 10 {
                step *= 2;
            }
            height -= step;
        }
        let genesis_hash = self.params.genesis_block.block_hash();
        if locator.last() != Some(&genesis_hash) {
            locator.push(genesis_hash);
        }
        PeerCommand::GetHeaders {
            peer_id,
            locator_hashes: locator,
            stop_hash: BlockHash::all_zeros(),
        }
    }

    /// Process received headers. Returns the number of new headers accepted.
    ///
    /// If headers don't connect to our current tip but DO connect to a known
    /// ancestor, they are accepted on a fork. The caller can compare chain work
    /// to decide whether to reorganise.
    pub fn process_headers(
        &mut self,
        headers: &[Header],
        block_height: u32,
    ) -> Result<u32, HeaderSyncError> {
        if headers.is_empty() {
            // Don't set synced here — let the caller decide based on context.
            // Empty headers can be a sendheaders acknowledgment, not a getheaders response.
            return Ok(0);
        }

        let mut accepted = 0u32;
        let mut batch: Vec<(BlockHash, StoredHeader)> = Vec::new();
        // Hash → StoredHeader view of `batch` so the nBits check can resolve
        // ancestors that haven't been flushed to the index yet.
        let mut batch_map: std::collections::HashMap<BlockHash, StoredHeader> =
            std::collections::HashMap::new();
        let mut prev_hash = self.best_hash;
        let mut height = self.best_height;

        for header in headers {
            // Fast-skip headers we already have stored at or below our tip.
            // Without this, duplicate batches from multiple peers (responding
            // to the same locator) are re-validated and counted as `accepted`,
            // which tricks the caller into thinking real work happened —
            // releasing the sync peer and stalling header progress for minutes.
            //
            // Headers ABOVE the current tip must NOT be skipped even if stored
            // by hash (e.g. from a prior session that synced further) — they
            // still need to go through the normal path so the tip advances.
            let hash = header.block_hash();
            if let Ok(Some(stored)) = self.header_index.get_header(&hash) {
                if stored.height <= self.best_height {
                    prev_hash = hash;
                    height = stored.height;
                    continue;
                }
            }

            // Verify this header connects to our chain or a known fork
            if header.prev_blockhash != prev_hash {
                // Check if we already have this header
                if let Ok(Some(stored)) = self.header_index.get_header(&hash) {
                    // We already have this header by hash — but the height→hash
                    // index can be missing or stale for its height (a prior crash
                    // or reorg can leave CF_HEADERS populated while CF_HEIGHT_INDEX
                    // has a gap). That gap strands block download: the re-request
                    // loop walks `for h in start..=tip { get_hash_at_height(h) }`
                    // and silently skips any height whose index entry is absent,
                    // so the missing block is never requested and the node sticks
                    // one block behind forever. Repair the index entry here, and
                    // advance the walk from this known header so the next header
                    // chains cleanly instead of taking the fork path.
                    let known_hash = header.block_hash();
                    let known_height = stored.height;
                    if self
                        .header_index
                        .get_hash_at_height(known_height)
                        .ok()
                        .flatten()
                        != Some(known_hash)
                    {
                        if let Err(e) = self
                            .header_index
                            .insert_headers_batch(&[(known_hash, stored.clone())])
                        {
                            warn!(height = known_height, error = %e, "Failed to repair height→hash index");
                        } else {
                            debug!(height = known_height, hash = %known_hash, "Repaired missing height→hash index entry");
                        }
                    }
                    prev_hash = known_hash;
                    height = known_height;
                    continue;
                }
                // Check if it connects to a known header (fork)
                if let Ok(Some(fork_parent)) = self.header_index.get_header(&header.prev_blockhash)
                {
                    if is_catching_up(block_height, self.best_height) {
                        debug!(
                            fork_height = fork_parent.height,
                            block_height,
                            header_tip = self.best_height,
                            "Skipping fork headers during deep block catch-up"
                        );
                        break;
                    }
                    info!(
                        fork_height = fork_parent.height,
                        fork_parent = %header.prev_blockhash,
                        "Headers fork from known block, accepting fork headers"
                    );
                    height = fork_parent.height;
                } else if batch.is_empty() && accepted == 0 {
                    // Nothing in this message connected: most likely a tip
                    // announcement for a block whose ancestors we're missing
                    // (we missed an earlier announcement, e.g. while the
                    // announcing peer was catching up or we were restarting).
                    // Signal the caller to getheaders-anchor at our tip so
                    // the gap gets filled — silently dropping this wedges the
                    // node at its current height until a block happens to
                    // build directly on it.
                    warn!(
                        expected = %prev_hash,
                        got = %header.prev_blockhash,
                        "Header doesn't connect to any known block — requesting gap fill"
                    );
                    return Err(HeaderSyncError::Unconnected(format!(
                        "header with prev {} doesn't connect (our tip {})",
                        header.prev_blockhash, prev_hash
                    )));
                } else {
                    // Later headers of a partially-accepted batch don't
                    // connect — store what we validated and stop here; the
                    // next getheaders round continues from the new tip.
                    warn!(
                        expected = %prev_hash,
                        got = %header.prev_blockhash,
                        "Header doesn't connect mid-batch — keeping accepted prefix"
                    );
                    break;
                }
            }

            height += 1;
            // `hash` already computed at the top of the loop (fast-skip check).

            // PoW validation
            let target = header.target();
            if header.validate_pow(target).is_err() {
                warn!(height, hash = %hash, "Invalid proof of work");
                return Err(HeaderSyncError::Invalid(format!(
                    "invalid PoW at height {height}"
                )));
            }

            // Difficulty: the header's nBits must equal the consensus-required
            // target for its height — the same rule connect_block enforces.
            // Rejecting here (at every height, not just retarget boundaries)
            // stops a peer from inflating header_sync with a long, cheaply
            // mined min-difficulty header chain, which would stall mining via
            // the is_catching_up() header/block-tip gap. Skipped for signet,
            // whose block validity comes from the challenge signature rather
            // than PoW; get_next_work_required itself short-circuits regtest
            // (pow_no_retargeting) and handles the testnet 20-minute
            // minimum-difficulty rule.
            if self.params.signet_challenge.is_none() {
                let header_index = &self.header_index;
                let lookup = |h: &BlockHash| {
                    batch_map
                        .get(h)
                        .cloned()
                        .or_else(|| header_index.get_header(h).ok().flatten())
                };
                match bitcoinpr_core::validation::get_next_work_required_with(
                    &lookup,
                    &self.params,
                    &header.prev_blockhash,
                    height - 1,
                    header.time,
                ) {
                    Some(expected_bits) => {
                        let got_bits = header.bits.to_consensus();
                        if got_bits != expected_bits {
                            warn!(
                                height,
                                hash = %hash,
                                expected = format_args!("{:#010x}", expected_bits),
                                got = format_args!("{:#010x}", got_bits),
                                "Header nBits mismatch — rejecting headers batch"
                            );
                            return Err(HeaderSyncError::Invalid(format!(
                                "nBits mismatch at height {height}: expected {expected_bits:#010x}, got {got_bits:#010x}"
                            )));
                        }
                    }
                    None => {
                        // Ancestor headers missing. During headers-first sync
                        // ancestors are always present (headers arrive in order
                        // and parents land in the batch/index before children),
                        // so this is a transient local-context gap, not peer
                        // misbehavior. Unlike connect_block (which fails closed
                        // and retries the block later), hard-failing here could
                        // permanently wedge header sync — so skip the nBits
                        // check for this header only and keep going.
                        warn!(
                            height,
                            hash = %hash,
                            "Cannot compute required nBits (ancestor headers missing) — skipping difficulty check for this header"
                        );
                    }
                }
            }

            // Calculate chain work: cumulative work up to this header
            let block_work = bitcoinpr_core::calculate_work(&header.target());
            let prev_work = if height == 1 {
                // Genesis block has zero work in our store
                [0u8; 32]
            } else if let Some(prev_stored) = batch.last() {
                prev_stored.1.chain_work
            } else if let Ok(Some(prev_stored)) =
                self.header_index.get_header(&header.prev_blockhash)
            {
                prev_stored.chain_work
            } else {
                // Never fall back to zero prev work. Storing this header with
                // a from-zero cumulative work poisons every descendant: the
                // tip's chain work collapses below nMinimumChainWork, which
                // permanently wedges header sync and block download (observed
                // on mainnet after a crash left a header's data missing while
                // its hash stayed known). Treat it like an unconnected header
                // so the caller re-anchors getheaders at our tip and the gap
                // gets refetched with full data.
                warn!(
                    height,
                    hash = %hash,
                    prev = %header.prev_blockhash,
                    "Prev header data missing — cannot compute chain work, requesting gap fill"
                );
                return Err(HeaderSyncError::Unconnected(format!(
                    "prev header {} of height {} has no stored data",
                    header.prev_blockhash, height
                )));
            };
            let chain_work = bitcoinpr_core::add_chain_work(&prev_work, &block_work);

            let stored = StoredHeader {
                header: *header,
                height,
                chain_work,
            };
            batch_map.insert(hash, stored.clone());
            batch.push((hash, stored));

            prev_hash = hash;
            accepted += 1;
        }

        if !batch.is_empty() {
            // Store headers by hash first — don't update the height→hash
            // index yet.  Fork/stale headers must not overwrite the index
            // for heights that belong to the current best chain; the index
            // is updated below only if this chain turns out to have the
            // most cumulative work.
            self.header_index
                .insert_headers_hash_only(&batch)
                .map_err(|e| HeaderSyncError::Storage(format!("failed to store headers: {e}")))?;

            // Only update the best tip if this chain has more work
            let new_chain_work = batch
                .last()
                .expect("batch is non-empty, checked above")
                .1
                .chain_work;
            let current_best_work = self
                .header_index
                .get_header(&self.best_hash)
                .ok()
                .flatten()
                .map(|h| h.chain_work)
                .unwrap_or([0u8; 32]);

            if new_chain_work >= current_best_work {
                // This chain has the most work — update the height→hash index.
                self.header_index
                    .update_height_index_batch(&batch)
                    .map_err(|e| {
                        HeaderSyncError::Storage(format!("failed to update height index: {e}"))
                    })?;
                if height != self.best_height || prev_hash != self.best_hash {
                    info!(
                        old_height = self.best_height,
                        new_height = height,
                        old_tip = %self.best_hash,
                        new_tip = %prev_hash,
                        "Switching to chain with more work"
                    );
                }
                self.best_height = height;
                self.best_hash = prev_hash;
                self.best_chain_work = new_chain_work;

                self.header_index
                    .set_header_tip(&self.best_hash, self.best_height)
                    .map_err(|e| {
                        HeaderSyncError::Storage(format!("failed to update header tip: {e}"))
                    })?;
            } else if !is_catching_up(block_height, self.best_height) {
                info!(
                    fork_height = height,
                    fork_tip = %prev_hash,
                    "Stored fork headers (less work than current best)"
                );
            } else {
                debug!(
                    fork_height = height,
                    fork_tip = %prev_hash,
                    block_height,
                    "Skipped storing minority-fork headers during deep block catch-up"
                );
            }

            if self.best_height % 1000 == 0 || accepted < 2000 {
                info!(
                    height = self.best_height,
                    accepted,
                    hash = %self.best_hash,
                    "Headers progress"
                );
            }
        }

        // If we got fewer than 2000 headers, sync is likely complete — but
        // never declare completion below the network's minimum chain work:
        // a short batch from a peer that is itself syncing (or lying) must
        // not end header sync hundreds of thousands of blocks early.
        if headers.len() < 2000 {
            if self.has_min_chain_work() {
                // Log only on the transition — once synced, every new-block
                // announcement from every peer is a short headers batch, and
                // re-logging produced a burst of ~24 identical lines per block.
                if !self.synced {
                    self.synced = true;
                    info!(height = self.best_height, "Header sync complete");
                }
            } else {
                warn!(
                    height = self.best_height,
                    "Short headers batch below minimum chain work — not marking sync complete"
                );
            }
        }

        Ok(accepted)
    }

    /// Build block locator hashes for getheaders.
    /// Uses exponentially spaced heights: tip, tip-1, tip-2, tip-4, tip-8, ...
    fn build_locator(&self) -> Vec<BlockHash> {
        let mut locator = Vec::new();
        let mut height = self.best_height as i64;
        let mut step: i64 = 1;

        while height >= 0 {
            if let Ok(Some(hash)) = self.header_index.get_hash_at_height(height as u32) {
                locator.push(hash);
            }

            if locator.len() >= 10 {
                step *= 2;
            }
            height -= step;
        }

        // Always include genesis
        let genesis_hash = self.params.genesis_block.block_hash();
        if locator.last() != Some(&genesis_hash) {
            locator.push(genesis_hash);
        }

        locator
    }
}

/// Per-peer bandwidth statistics for weighted block assignment.
pub struct PeerBandwidth {
    /// EWMA bytes-per-second (smoothed over recent deliveries).
    pub ewma_bps: f64,
    /// Total blocks delivered by this peer.
    pub blocks_delivered: u32,
    /// Timestamp of last delivery.
    pub last_delivery: std::time::Instant,
}

impl PeerBandwidth {
    /// Default EWMA for new peers (500 KB/s) so they get a fair initial share.
    const DEFAULT_BPS: f64 = 500_000.0;
    /// Smoothing factor for EWMA updates.
    const ALPHA: f64 = 0.3;

    fn new() -> Self {
        PeerBandwidth {
            ewma_bps: Self::DEFAULT_BPS,
            blocks_delivered: 0,
            last_delivery: std::time::Instant::now(),
        }
    }

    fn record_delivery(&mut self, block_size: u64) {
        let now = std::time::Instant::now();
        let elapsed = now.duration_since(self.last_delivery).as_secs_f64();
        if elapsed > 0.001 {
            let instantaneous_bps = block_size as f64 / elapsed;
            self.ewma_bps = Self::ALPHA * instantaneous_bps + (1.0 - Self::ALPHA) * self.ewma_bps;
        }
        self.last_delivery = now;
        self.blocks_delivered += 1;
    }
}

/// Manages parallel block downloads.
pub struct BlockSync {
    /// Blocks we need to download, in order.
    pub queue: VecDeque<BlockHash>,
    /// Currently in-flight block requests.
    pub in_flight: std::collections::HashMap<BlockHash, PeerId>,
    /// Reverse index: blocks assigned to each peer, for O(1) per-peer cleanup.
    pub peer_requests: std::collections::HashMap<PeerId, std::collections::HashSet<BlockHash>>,
    /// Maximum concurrent requests across all peers.
    pub max_in_flight: usize,
    /// Last time we received a block from each peer (for per-peer stale detection).
    pub peer_last_recv: std::collections::HashMap<PeerId, std::time::Instant>,
    /// Per-peer bandwidth tracking for weighted assignment.
    pub peer_bandwidth: std::collections::HashMap<PeerId, PeerBandwidth>,
    /// Count of notfound responses per peer (evidence of pruned/unavailable blocks).
    pub peer_notfound_count: std::collections::HashMap<PeerId, u32>,
    /// Count of stale-clear cycles per peer without any delivery.
    /// Incremented each time a peer is found stale; reset on block delivery.
    pub peer_stale_cycles: std::collections::HashMap<PeerId, u32>,
    /// Set of distinct peers that have said notfound for each block hash.
    /// A block is abandoned only once EVERY currently-eligible peer has
    /// declined it — never on a raw count. This is critical for single-source
    /// blocks (e.g. a reorg chain mined on one node): the sibling peers that
    /// legitimately don't carry it would otherwise rack up notfounds and
    /// abandon a block the one source would happily serve, permanently
    /// stranding the reorg.
    pub block_notfound_peers:
        std::collections::HashMap<BlockHash, std::collections::HashSet<PeerId>>,
    /// Blocks already received (sitting in pending_blocks on the caller side).
    /// Prevents stale-clear from re-queuing blocks that peers already delivered.
    pub received: std::collections::HashSet<BlockHash>,
    /// Peer excluded from block download assignment (the active header-sync
    /// peer during IBD). Headers responses share the peer's TCP connection
    /// with block data; ~50MB of queued blocks ahead of a headers message
    /// stalls header sync for the whole transfer. Ignored if it would leave
    /// zero download peers.
    pub excluded_peer: Option<PeerId>,
    /// When true, no block download assignments are made (queue still
    /// accumulates). Set while the best header chain is below the network's
    /// minimum chain work so header sync gets all peer bandwidth (mirrors
    /// Bitcoin Core, which defers block download until nMinimumChainWork).
    pub download_paused: bool,
    /// Last time ANY block was received from the network. Distinguishes a
    /// genuine network stall (nothing arriving) from validation backpressure
    /// (blocks arriving faster than they can be connected).
    pub last_recv: Option<std::time::Instant>,
}

impl Default for BlockSync {
    fn default() -> Self {
        Self::new()
    }
}

impl BlockSync {
    /// Refresh `in_flight` ownership after bookkeeping changed for `hash`.
    /// Designates some peer still in `peer_requests` as primary, else drops reservation.
    fn refresh_primary_in_flight(&mut self, hash: &BlockHash) {
        for (&pid, set) in &self.peer_requests {
            if set.contains(hash) {
                self.in_flight.insert(*hash, pid);
                return;
            }
        }
        self.in_flight.remove(hash);
    }

    pub fn new() -> Self {
        BlockSync {
            queue: VecDeque::new(),
            in_flight: std::collections::HashMap::new(),
            peer_requests: std::collections::HashMap::new(),
            max_in_flight: 128,
            peer_last_recv: std::collections::HashMap::new(),
            peer_bandwidth: std::collections::HashMap::new(),
            peer_notfound_count: std::collections::HashMap::new(),
            peer_stale_cycles: std::collections::HashMap::new(),
            block_notfound_peers: std::collections::HashMap::new(),
            received: std::collections::HashSet::new(),
            excluded_peer: None,
            download_paused: false,
            last_recv: None,
        }
    }

    /// Time since the last block was received from any peer, if one has been.
    pub fn since_last_recv(&self) -> Option<std::time::Duration> {
        self.last_recv.map(|t| t.elapsed())
    }

    /// Add blocks to the download queue.
    pub fn schedule(&mut self, hashes: Vec<BlockHash>) {
        for hash in hashes {
            if !self.in_flight.contains_key(&hash) && !self.received.contains(&hash) {
                self.queue.push_back(hash);
            }
        }
    }

    /// Assign queued blocks to available peers weighted by bandwidth, returning
    /// commands to send. Proven peers (>0 blocks delivered) get the bulk allocation;
    /// unproven peers get at most 2 blocks as a probe to avoid wasting in-flight slots.
    pub fn assign_to_peers(&mut self, peer_ids: &[PeerId]) -> Vec<PeerCommand> {
        self.assign_to_peers_inner(peer_ids, false)
    }

    /// Emergency assignment: treat every eligible peer as proven so a collapsed
    /// peer pool can still parallelize downloads.
    pub fn assign_to_peers_emergency(&mut self, peer_ids: &[PeerId]) -> Vec<PeerCommand> {
        self.assign_to_peers_inner(peer_ids, true)
    }

    fn assign_to_peers_inner(
        &mut self,
        peer_ids: &[PeerId],
        force_all_proven: bool,
    ) -> Vec<PeerCommand> {
        let mut commands = Vec::new();

        // Block download deferred until minimum chain work is reached.
        if self.download_paused {
            return commands;
        }

        // Keep the header-sync peer's connection clear of bulk block traffic,
        // unless it is the only eligible peer.
        let filtered: Vec<PeerId>;
        let peer_ids: &[PeerId] = match self.excluded_peer {
            Some(ex) if peer_ids.len() > 1 && peer_ids.contains(&ex) => {
                filtered = peer_ids.iter().copied().filter(|&p| p != ex).collect();
                &filtered
            }
            _ => peer_ids,
        };

        if peer_ids.is_empty() || self.queue.is_empty() {
            return commands;
        }

        let available_slots = self.max_in_flight.saturating_sub(self.in_flight.len());

        if available_slots == 0 {
            return commands;
        }

        let max_per_peer: usize = 16;
        let probe_per_peer: usize = 2;

        // Split peers into proven (delivered ≥1 block AND not stale-cleared),
        // stale (delivered before but failed recent batches), and unproven.
        // Stale peers are likely pruned — don't waste in-flight slots on them.
        let mut proven: Vec<(PeerId, f64)> = Vec::new();
        let mut unproven: Vec<PeerId> = Vec::new();
        for &pid in peer_ids {
            if !force_all_proven {
                // Skip peers that have been stale-cleared — they accepted blocks
                // but didn't deliver. Likely pruned for the heights we need.
                let stale_cycles = self.peer_stale_cycles.get(&pid).copied().unwrap_or(0);
                if stale_cycles > 0 {
                    continue;
                }
            }
            let delivered = self
                .peer_bandwidth
                .get(&pid)
                .map(|bw| bw.blocks_delivered)
                .unwrap_or(0);
            if delivered > 0 || force_all_proven {
                let bps = self
                    .peer_bandwidth
                    .get(&pid)
                    .map(|bw| bw.ewma_bps)
                    .unwrap_or(PeerBandwidth::DEFAULT_BPS);
                proven.push((pid, bps));
            } else {
                unproven.push(pid);
            }
        }

        // Reserve slots for probing unproven peers (2 blocks each, capped)
        let probe_slots = (unproven.len() * probe_per_peer).min(available_slots / 4);
        let bulk_slots = available_slots.saturating_sub(probe_slots);

        // If no proven peers exist, give everyone equal small batches
        let mut allocations: Vec<(PeerId, usize)> = if proven.is_empty() {
            let per_peer = (available_slots / peer_ids.len()).max(1).min(max_per_peer);
            peer_ids.iter().map(|&pid| (pid, per_peer)).collect()
        } else {
            // Allocate bulk slots proportionally to proven peers by bandwidth
            let total_weight: f64 = proven.iter().map(|(_, w)| w).sum();
            let mut allocs: Vec<(PeerId, usize)> = proven
                .iter()
                .map(|(pid, w)| {
                    let share = (w / total_weight * bulk_slots as f64).floor() as usize;
                    (*pid, share.max(1).min(max_per_peer))
                })
                .collect();

            // Give unproven peers a small probe allocation
            for pid in &unproven {
                allocs.push((*pid, probe_per_peer));
            }
            allocs
        };

        // Trim total allocation to available_slots
        let total_alloc: usize = allocations.iter().map(|(_, n)| n).sum();
        if total_alloc > available_slots {
            let mut excess = total_alloc - available_slots;
            allocations.sort_by(|a, b| a.1.cmp(&b.1));
            for alloc in &mut allocations {
                if excess == 0 {
                    break;
                }
                let reduce = (alloc.1 - 1).min(excess);
                alloc.1 -= reduce;
                excess -= reduce;
            }
        }

        // Pop blocks from queue and batch to each peer
        let now = std::time::Instant::now();
        for (peer_id, count) in &allocations {
            if self.queue.is_empty() {
                break;
            }
            let mut batch: Vec<BlockHash> = Vec::with_capacity(*count);
            // Blocks this peer already declined (notfound): don't re-assign them
            // to the same peer — that livelocks a single-source block on a
            // persistent notfounder and never routes it to the one carrier.
            // Defer them back to the queue for a different peer.
            let mut deferred: Vec<BlockHash> = Vec::new();
            for _ in 0..*count {
                if let Some(hash) = self.queue.pop_front() {
                    let declined = self
                        .block_notfound_peers
                        .get(&hash)
                        .is_some_and(|s| s.contains(peer_id));
                    if declined {
                        deferred.push(hash);
                        continue;
                    }
                    self.in_flight.insert(hash, *peer_id);
                    self.peer_requests.entry(*peer_id).or_default().insert(hash);
                    batch.push(hash);
                } else {
                    break;
                }
            }
            // Return deferred blocks so a later peer in this pass (or a future
            // pass) can pick them up.
            for hash in deferred.into_iter().rev() {
                self.queue.push_front(hash);
            }
            if !batch.is_empty() {
                self.peer_last_recv.entry(*peer_id).or_insert(now);
                commands.push(PeerCommand::GetBlocks {
                    peer_id: *peer_id,
                    hashes: batch,
                });
            }
        }

        commands
    }

    /// Mark a block as received, record delivery time, and update bandwidth stats.
    pub fn block_received(&mut self, hash: &BlockHash, peer_id: PeerId, block_size: u64) {
        self.in_flight.remove(hash);
        for set in self.peer_requests.values_mut() {
            set.remove(hash);
        }
        self.received.insert(*hash);
        self.block_notfound_peers.remove(hash);
        let now = std::time::Instant::now();
        self.last_recv = Some(now);
        self.peer_last_recv.insert(peer_id, now);
        self.peer_stale_cycles.remove(&peer_id);
        self.peer_bandwidth
            .entry(peer_id)
            .or_insert_with(PeerBandwidth::new)
            .record_delivery(block_size);
    }

    /// Handle notfound: remove blocks from this peer's in-flight set and
    /// re-queue them for assignment to other peers. Returns `(requeued, abandoned)` where
    /// `abandoned` lists hashes that have been notfound by enough peers to be considered
    /// permanently unavailable (orphaned blocks no peer carries any more). Callers should
    /// remove abandoned hashes from any downstream state (e.g. pending_blocks).
    pub fn blocks_not_found(
        &mut self,
        peer_id: PeerId,
        hashes: &[BlockHash],
        live_peer_count: usize,
    ) -> (usize, Vec<BlockHash>) {
        let mut requeued = 0;
        let mut abandoned = Vec::new();
        // A block is abandoned only when EVERY currently-eligible peer has
        // declined it — tracked as a set of distinct notfounding peers, never
        // a raw count. A single-source block (e.g. a reorg chain mined on one
        // node) is carried by only one peer; the other eligible peers
        // legitimately notfound it. Counting those toward abandonment would
        // drop a block the one source would serve, permanently stranding the
        // reorg. Requiring the notfound set to cover all live peers means the
        // sole carrier (which never notfounds) keeps the block alive for retry.
        let abandon_threshold = live_peer_count.max(1);

        for hash in hashes {
            let had = self
                .peer_requests
                .get_mut(&peer_id)
                .is_some_and(|s| s.remove(hash));
            if !had {
                continue;
            }
            requeued += 1;

            // Record this peer in the per-block notfound set.
            let nf_peers = self.block_notfound_peers.entry(*hash).or_default();
            nf_peers.insert(peer_id);
            let distinct_nf = nf_peers.len();

            if self.received.contains(hash) {
                continue;
            }

            // Abandon only once the number of distinct peers that have said
            // notfound covers every live eligible peer — i.e. no peer is left
            // that might still serve it.
            if distinct_nf >= abandon_threshold {
                self.in_flight.remove(hash);
                self.queue.retain(|h| h != hash);
                // Remove from all peer_requests so it won't be reassigned.
                for set in self.peer_requests.values_mut() {
                    set.remove(hash);
                }
                self.block_notfound_peers.remove(hash);
                abandoned.push(*hash);
                continue;
            }

            let outstanding = self.peer_requests.values().any(|set| set.contains(hash));
            if outstanding {
                self.refresh_primary_in_flight(hash);
            } else {
                self.in_flight.remove(hash);
                self.queue.push_front(*hash);
            }
        }
        *self.peer_notfound_count.entry(peer_id).or_insert(0) += requeued as u32;
        (requeued, abandoned)
    }

    /// Returns peers that are chronic non-deliverers: either sent notfound for
    /// more than `nf_threshold` blocks, or have been stale-cleared `stale_threshold`+
    /// times without delivering any blocks (silent non-deliverers).
    pub fn chronic_non_deliverers(&self, nf_threshold: u32, stale_threshold: u32) -> Vec<PeerId> {
        let mut result: std::collections::HashSet<PeerId> = self
            .peer_notfound_count
            .iter()
            .filter(|(_, &count)| count >= nf_threshold)
            .map(|(pid, _)| *pid)
            .collect();
        for (&pid, &cycles) in &self.peer_stale_cycles {
            if cycles >= stale_threshold {
                result.insert(pid);
            }
        }
        result.into_iter().collect()
    }

    /// Proven-but-crawling peers — eviction candidates so a redial draws a
    /// fresh connection (and, through a Tor/SOCKS proxy with per-connection
    /// credentials, a brand-new circuit: a "circuit lottery" that accumulates
    /// fast paths over time). The gate is *relative* — slower than `frac` of
    /// the median proven rate — so a uniformly slow pool (ISP shaping, or Tor
    /// in general) evicts nobody; only genuine stragglers in a mixed pool are
    /// culled. Peers must have delivered `min_delivered` blocks first (the
    /// EWMA starts at an optimistic default; a new circuit needs deliveries
    /// before its measured rate means anything), at least `min_keep` proven
    /// peers always remain, and at most `max_evict` are returned, slowest
    /// first.
    pub fn slow_deliverers(
        &self,
        min_delivered: u32,
        frac: f64,
        min_keep: usize,
        max_evict: usize,
    ) -> Vec<PeerId> {
        let mut proven: Vec<(PeerId, f64)> = self
            .peer_bandwidth
            .iter()
            .filter(|(_, bw)| bw.blocks_delivered >= min_delivered)
            .map(|(&pid, bw)| (pid, bw.ewma_bps))
            .collect();
        if proven.len() <= min_keep {
            return Vec::new();
        }
        proven.sort_by(|a, b| a.1.total_cmp(&b.1));
        let median = proven[proven.len() / 2].1;
        let threshold = median * frac;
        let evictable = proven.len() - min_keep;
        proven
            .iter()
            .take_while(|(_, bps)| *bps < threshold)
            .take(max_evict.min(evictable))
            .map(|(pid, _)| *pid)
            .collect()
    }

    /// Clear in-flight requests for peers that haven't delivered a block within
    /// a graduated timeout (base timeout + 200ms per assigned block). Returns
    /// the stale hashes (re-queued for reassignment) and the number of stale
    /// peers found.
    pub fn clear_stale_peers(
        &mut self,
        base_timeout: std::time::Duration,
        track_cycles: bool,
    ) -> (usize, usize) {
        let now = std::time::Instant::now();

        // Find stale peers using graduated timeout: peers with more assigned
        // blocks get more time before being marked stale.
        let stale_peers: Vec<PeerId> = self
            .peer_requests
            .iter()
            .filter(|(_, hashes)| !hashes.is_empty())
            .filter(|(pid, hashes)| {
                let graduated =
                    base_timeout + std::time::Duration::from_millis(200) * hashes.len() as u32;
                match self.peer_last_recv.get(pid) {
                    Some(t) => now.duration_since(*t) > graduated,
                    None => true,
                }
            })
            .map(|(pid, _)| *pid)
            .collect();

        if stale_peers.is_empty() {
            return (0, 0);
        }

        let num_stale_peers = stale_peers.len();
        let mut num_stale = 0;

        // Re-queue blocks from stale peers, skipping already-received blocks
        for pid in &stale_peers {
            if let Some(hashes) = self.peer_requests.remove(pid) {
                for hash in &hashes {
                    if self.received.contains(hash) {
                        continue;
                    }
                    let outstanding = self.peer_requests.values().any(|set| set.contains(hash));
                    if outstanding {
                        self.refresh_primary_in_flight(hash);
                    } else {
                        self.in_flight.remove(hash);
                        self.queue.push_back(*hash);
                    }
                }
                num_stale += hashes.len();
            }
            self.peer_last_recv.remove(pid);
            if track_cycles {
                *self.peer_stale_cycles.entry(*pid).or_insert(0) += 1;
            }
            // Keep peer_bandwidth — historical EWMA is still useful for
            // weighted assignment even after a stale-clear cycle.
        }

        (num_stale, num_stale_peers)
    }

    /// Remove a disconnected peer: re-queue its in-flight blocks and clean up tracking.
    pub fn peer_disconnected(&mut self, peer_id: PeerId) {
        if let Some(hashes) = self.peer_requests.remove(&peer_id) {
            for hash in &hashes {
                if self.received.contains(hash) {
                    continue;
                }
                let outstanding = self.peer_requests.values().any(|set| set.contains(hash));
                if outstanding {
                    self.refresh_primary_in_flight(hash);
                } else {
                    self.in_flight.remove(hash);
                    self.queue.push_back(*hash);
                }
            }
        }
        self.peer_last_recv.remove(&peer_id);
        self.peer_bandwidth.remove(&peer_id);
        self.peer_notfound_count.remove(&peer_id);
        self.peer_stale_cycles.remove(&peer_id);
    }

    /// Remove a block from the received set after it's been connected to the chain.
    pub fn block_connected(&mut self, hash: &BlockHash) {
        self.received.remove(hash);
    }

    /// Check if there are pending downloads.
    pub fn has_pending(&self) -> bool {
        !self.queue.is_empty() || !self.in_flight.is_empty()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod header_sync_tests {
    use super::*;
    use bitcoin::block::Version;
    use bitcoin::{CompactTarget, TxMerkleNode};

    /// Regtest-derived params with retargeting ENABLED so the nBits check is
    /// active, and the min-difficulty rule off so within-period headers must
    /// inherit the previous block's bits exactly. The regtest pow_limit stays,
    /// keeping test headers trivially mineable.
    fn retargeting_params() -> ConsensusParams {
        let mut params = ConsensusParams::regtest();
        params.pow_no_retargeting = false;
        params.pow_allow_min_difficulty_blocks = false;
        params
    }

    fn open_index() -> (tempfile::TempDir, Arc<HeaderIndex>) {
        let dir = tempfile::tempdir().unwrap();
        let index = Arc::new(HeaderIndex::open(dir.path()).unwrap());
        (dir, index)
    }

    /// Build a header on `prev` and grind the nonce until it satisfies its own
    /// (regtest-level, ~50% of hashes) target.
    fn mine_header(prev: BlockHash, bits: CompactTarget, time: u32) -> Header {
        let mut header = Header {
            version: Version::TWO,
            prev_blockhash: prev,
            merkle_root: TxMerkleNode::all_zeros(),
            time,
            bits,
            nonce: 0,
        };
        while header.validate_pow(header.target()).is_err() {
            header.nonce += 1;
        }
        header
    }

    /// Insert genesis into the index and return a HeaderSync anchored on it.
    fn sync_at_genesis(params: &ConsensusParams, index: &Arc<HeaderIndex>) -> HeaderSync {
        let genesis = params.genesis_block.header;
        let genesis_hash = genesis.block_hash();
        index
            .insert_headers_batch(&[(
                genesis_hash,
                StoredHeader {
                    header: genesis,
                    height: 0,
                    chain_work: [0u8; 32],
                },
            )])
            .unwrap();
        HeaderSync::new(params.clone(), Arc::clone(index), 0, genesis_hash)
    }

    #[test]
    fn off_schedule_bits_within_period_rejected() {
        let params = retargeting_params();
        let (_dir, index) = open_index();
        let mut sync = sync_at_genesis(&params, &index);
        let genesis = params.genesis_block.header;

        // Bits differ from the previous block's bits mid-period — invalid on a
        // non-min-difficulty network — but still trivially mineable.
        let bad_bits = CompactTarget::from_consensus(0x207f_fffe);
        assert_ne!(bad_bits, genesis.bits);
        let bad = mine_header(genesis.block_hash(), bad_bits, genesis.time + 600);

        let err = sync.process_headers(&[bad], 0).unwrap_err();
        assert!(
            matches!(err, HeaderSyncError::Invalid(_)),
            "expected Invalid rejection, got: {err}"
        );
        // Header state must not advance and the header must not be stored.
        assert_eq!(sync.best_height, 0);
        assert_eq!(sync.best_hash, genesis.block_hash());
        assert!(index.get_header(&bad.block_hash()).unwrap().is_none());
        assert!(index.get_hash_at_height(1).unwrap().is_none());
    }

    #[test]
    fn correct_within_period_headers_accepted() {
        let params = retargeting_params();
        let (_dir, index) = open_index();
        let mut sync = sync_at_genesis(&params, &index);
        let genesis = params.genesis_block.header;

        // Two headers in one batch: the second's parent lives only in the
        // in-flight batch, exercising the batch-aware ancestor lookup.
        let h1 = mine_header(genesis.block_hash(), genesis.bits, genesis.time + 600);
        let h2 = mine_header(h1.block_hash(), genesis.bits, genesis.time + 1200);

        let accepted = sync.process_headers(&[h1, h2], 0).unwrap();
        assert_eq!(accepted, 2);
        assert_eq!(sync.best_height, 2);
        assert_eq!(sync.best_hash, h2.block_hash());
    }

    /// A short (<2000) headers batch must NOT complete header sync while the
    /// chain's cumulative work is below `min_chain_work` — that is exactly the
    /// false-completion failure mode from behind/lying sync peers.
    #[test]
    fn short_batch_below_min_chain_work_not_marked_synced() {
        let mut params = retargeting_params();
        params.min_chain_work = [0xff; 32]; // unreachably high
        let (_dir, index) = open_index();
        let mut sync = sync_at_genesis(&params, &index);
        let genesis = params.genesis_block.header;

        let h1 = mine_header(genesis.block_hash(), genesis.bits, genesis.time + 600);
        let accepted = sync.process_headers(&[h1], 0).unwrap();
        assert_eq!(accepted, 1);
        assert!(!sync.has_min_chain_work());
        assert!(!sync.synced, "sync must not complete below min chain work");
    }

    /// With a zero minimum (regtest default) a short batch completes sync,
    /// preserving pre-gate behavior on local networks.
    #[test]
    fn short_batch_with_zero_min_chain_work_completes_sync() {
        let params = retargeting_params();
        assert_eq!(params.min_chain_work, [0u8; 32]);
        let (_dir, index) = open_index();
        let mut sync = sync_at_genesis(&params, &index);
        let genesis = params.genesis_block.header;

        let h1 = mine_header(genesis.block_hash(), genesis.bits, genesis.time + 600);
        sync.process_headers(&[h1], 0).unwrap();
        assert!(sync.has_min_chain_work());
        assert!(sync.synced);
    }

    /// A header that connects to our tip hash while the tip's header *data*
    /// is missing from the index (crash artifact) must fail as Unconnected —
    /// the old code silently computed its cumulative chain work from zero,
    /// poisoning every descendant and collapsing the tip's work below
    /// nMinimumChainWork (observed wedging mainnet sync at height 957639).
    #[test]
    fn missing_prev_header_data_errors_instead_of_zero_work() {
        let params = retargeting_params();
        let (_dir, index) = open_index();
        let mut sync = sync_at_genesis(&params, &index);
        let genesis = params.genesis_block.header;

        // Tip is h1, but h1's header data was never durably written.
        let h1 = mine_header(genesis.block_hash(), genesis.bits, genesis.time + 600);
        sync.best_height = 1;
        sync.best_hash = h1.block_hash();

        let h2 = mine_header(h1.block_hash(), genesis.bits, genesis.time + 1200);
        let err = sync.process_headers(&[h2], 0).unwrap_err();
        assert!(
            matches!(err, HeaderSyncError::Unconnected(_)),
            "expected Unconnected, got {err:?}"
        );
        // The header must not have been stored with bogus chain work.
        assert!(index.get_header(&h2.block_hash()).unwrap().is_none());
    }

    /// `download_paused` must gate every assignment path (normal + emergency);
    /// the queue is preserved so downloads resume once the gate opens.
    #[test]
    fn download_paused_gates_block_assignment() {
        let params = retargeting_params();
        let hash = params.genesis_block.block_hash();
        let mut bs = BlockSync::new();
        bs.schedule(vec![hash]);
        bs.download_paused = true;
        assert!(bs.assign_to_peers(&[1, 2]).is_empty());
        assert!(bs.assign_to_peers_emergency(&[1, 2]).is_empty());
        assert_eq!(bs.queue.len(), 1, "queue must be preserved while paused");
        bs.download_paused = false;
        assert!(!bs.assign_to_peers(&[1, 2]).is_empty());
    }

    /// A tip announcement whose ancestors we don't have (we missed an earlier
    /// announcement) must surface as `Unconnected` so the caller getheaders-
    /// anchors at our tip — silently dropping it wedges the node at its
    /// current height (the bitcoinpr2-stuck-at-239 incident).
    #[test]
    fn unconnecting_announcement_signals_gap_fill() {
        let params = retargeting_params();
        let (_dir, index) = open_index();
        let mut sync = sync_at_genesis(&params, &index);
        let genesis = params.genesis_block.header;

        // Peer's chain: genesis <- h1 <- h2, but we only get h2 announced.
        let h1 = mine_header(genesis.block_hash(), genesis.bits, genesis.time + 600);
        let h2 = mine_header(h1.block_hash(), genesis.bits, genesis.time + 1200);

        let err = sync.process_headers(&[h2], 0).unwrap_err();
        assert!(
            matches!(err, HeaderSyncError::Unconnected(_)),
            "expected Unconnected, got: {err}"
        );
        // State must not advance; the header must not be stored.
        assert_eq!(sync.best_height, 0);
        assert!(index.get_header(&h2.block_hash()).unwrap().is_none());

        // Once the gap fills (h1+h2 together), both connect normally.
        let accepted = sync.process_headers(&[h1, h2], 0).unwrap();
        assert_eq!(accepted, 2);
        assert_eq!(sync.best_height, 2);
    }

    /// The per-peer unconnecting-headers counter must increment per strike,
    /// track peers independently, and clear on reset — the node.rs handler
    /// relies on it to break the getheaders ping-pong with foreign-chain
    /// peers (2026-07-12 incident).
    #[test]
    fn unconnecting_counter_tracks_per_peer_and_resets() {
        let params = retargeting_params();
        let (_dir, index) = open_index();
        let mut sync = sync_at_genesis(&params, &index);

        for expected in 1..=MAX_UNCONNECTING_HEADERS {
            assert_eq!(sync.note_unconnecting(7), expected);
        }
        // Independent counter for another peer.
        assert_eq!(sync.note_unconnecting(8), 1);
        // Reset clears only the targeted peer.
        sync.reset_unconnecting(7);
        assert_eq!(sync.note_unconnecting(7), 1);
        assert_eq!(sync.note_unconnecting(8), 2);
    }

    /// Build and insert an unmined chain of `count` headers on top of genesis
    /// (PoW is not validated on direct index inserts). Returns the tip hash.
    fn insert_chain(params: &ConsensusParams, index: &Arc<HeaderIndex>, count: u32) -> BlockHash {
        let genesis = params.genesis_block.header;
        let spacing = params.pow_target_spacing as u32;
        let mut batch = Vec::with_capacity(count as usize);
        let mut prev_hash = genesis.block_hash();
        for i in 1..=count {
            let header = Header {
                version: Version::TWO,
                prev_blockhash: prev_hash,
                merkle_root: TxMerkleNode::all_zeros(),
                time: genesis.time + i * spacing,
                bits: genesis.bits,
                nonce: 0,
            };
            prev_hash = header.block_hash();
            batch.push((
                prev_hash,
                StoredHeader {
                    header,
                    height: i,
                    chain_work: [0u8; 32],
                },
            ));
        }
        index.insert_headers_batch(&batch).unwrap();
        prev_hash
    }

    #[test]
    fn retarget_boundary_enforced() {
        let params = retargeting_params();
        let (_dir, index) = open_index();
        let mut sync = sync_at_genesis(&params, &index);
        let interval = params.difficulty_adjustment_interval();

        // Chain up to the last block of the first period (height interval-1).
        let tip_hash = insert_chain(&params, &index, interval - 1);
        let tip = index.get_header(&tip_hash).unwrap().unwrap();
        sync.best_height = tip.height;
        sync.best_hash = tip_hash;

        // The period spans interval-1 blocks of spacing instead of interval,
        // so the retarget must tighten the target: expected bits differ from
        // the period's bits.
        let candidate_time = tip.header.time + params.pow_target_spacing as u32;
        let expected_bits = bitcoinpr_core::validation::get_next_work_required(
            &index,
            &params,
            &tip_hash,
            tip.height,
            candidate_time,
        )
        .expect("ancestors present");
        assert_ne!(expected_bits, tip.header.bits.to_consensus());

        // Wrong bits at the boundary (inheriting the old period's bits) → reject.
        let wrong = mine_header(tip_hash, tip.header.bits, candidate_time);
        let err = sync.process_headers(&[wrong], 0).unwrap_err();
        assert!(matches!(err, HeaderSyncError::Invalid(_)));
        assert_eq!(sync.best_height, tip.height);

        // Correct retargeted bits → accept.
        let right = mine_header(
            tip_hash,
            CompactTarget::from_consensus(expected_bits),
            candidate_time,
        );
        let accepted = sync.process_headers(&[right], 0).unwrap();
        assert_eq!(accepted, 1);
        assert_eq!(sync.best_height, interval);
        assert_eq!(sync.best_hash, right.block_hash());
    }

    #[test]
    fn missing_ancestors_skip_check_without_rejection() {
        // A boundary header whose period-start ancestor is absent from the
        // index must NOT be rejected (transient context gap, not peer fault):
        // the difficulty check is skipped and the header accepted.
        let params = retargeting_params();
        let (_dir, index) = open_index();
        let mut sync = sync_at_genesis(&params, &index);
        let interval = params.difficulty_adjustment_interval();
        let genesis = params.genesis_block.header;

        // Insert ONLY the period's last header — its prev link dangles, so the
        // walk to the period start fails and get_next_work_required is None.
        let dangling_prev = BlockHash::all_zeros();
        let orphan_tip = Header {
            version: Version::TWO,
            prev_blockhash: dangling_prev,
            merkle_root: TxMerkleNode::all_zeros(),
            time: genesis.time + (interval - 1) * params.pow_target_spacing as u32,
            bits: genesis.bits,
            nonce: 0,
        };
        let orphan_hash = orphan_tip.block_hash();
        index
            .insert_headers_batch(&[(
                orphan_hash,
                StoredHeader {
                    header: orphan_tip,
                    height: interval - 1,
                    chain_work: [0u8; 32],
                },
            )])
            .unwrap();
        sync.best_height = interval - 1;
        sync.best_hash = orphan_hash;

        let candidate = mine_header(
            orphan_hash,
            genesis.bits,
            orphan_tip.time + params.pow_target_spacing as u32,
        );
        let accepted = sync.process_headers(&[candidate], 0).unwrap();
        assert_eq!(accepted, 1);
        assert_eq!(sync.best_height, interval);
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod block_sync_multi_peer_tests {
    use super::*;
    use std::time::{Duration, Instant};

    fn hash_byte(b: u8) -> BlockHash {
        let mut a = [0u8; 32];
        a[0] = b;
        BlockHash::from_byte_array(a)
    }

    #[test]
    fn notfound_does_not_requeue_while_other_peer_still_claims() {
        let mut bs = BlockSync::new();
        let h = hash_byte(9);
        bs.peer_requests.entry(1u64).or_default().insert(h);
        bs.peer_requests.entry(2u64).or_default().insert(h);
        bs.in_flight.insert(h, 1);

        let (requeued, abandoned) = bs.blocks_not_found(1, &[h], 2);
        assert_eq!(requeued, 1);
        assert!(abandoned.is_empty());
        assert!(bs.peer_requests.get(&2).is_some_and(|s| s.contains(&h)));
        assert!(bs.queue.is_empty());
        assert_eq!(bs.in_flight.get(&h), Some(&2));
    }

    #[test]
    fn block_received_updates_last_recv() {
        let mut bs = BlockSync::new();
        assert!(bs.last_recv.is_none());
        assert!(bs.since_last_recv().is_none());

        let h = hash_byte(7);
        bs.in_flight.insert(h, 1);
        bs.block_received(&h, 1, 1_000);

        assert!(bs.last_recv.is_some());
        assert!(bs.since_last_recv().unwrap() < Duration::from_secs(1));
    }

    #[test]
    fn stale_clear_one_claimant_refreshes_primary() {
        let mut bs = BlockSync::new();
        let h = hash_byte(11);
        bs.peer_requests.entry(1u64).or_default().insert(h);
        bs.peer_requests.entry(2u64).or_default().insert(h);
        bs.in_flight.insert(h, 1);
        bs.peer_last_recv
            .insert(1u64, Instant::now() - Duration::from_secs(3600));
        bs.peer_last_recv.insert(2u64, Instant::now());

        let (_, stale_peers) = bs.clear_stale_peers(Duration::from_secs(1), false);
        assert_eq!(stale_peers, 1);
        assert!(bs.queue.is_empty());
        assert_eq!(bs.in_flight.get(&h), Some(&2));
    }

    #[test]
    fn single_source_block_not_abandoned_when_siblings_notfound() {
        // 3 eligible peers; only peer 3 carries the block. Peers 1 and 2
        // notfound it. It must NOT be abandoned — peer 3 would still serve it.
        let mut bs = BlockSync::new();
        let h = hash_byte(33);
        bs.peer_requests.entry(1u64).or_default().insert(h);
        bs.in_flight.insert(h, 1);
        let (_, abandoned1) = bs.blocks_not_found(1, &[h], 3);
        assert!(abandoned1.is_empty(), "1 of 3 notfound must not abandon");

        // Re-assign to peer 2, which also notfounds.
        bs.peer_requests.entry(2u64).or_default().insert(h);
        bs.in_flight.insert(h, 2);
        let (_, abandoned2) = bs.blocks_not_found(2, &[h], 3);
        assert!(abandoned2.is_empty(), "2 of 3 notfound must not abandon");
        // Block stays alive (queued or in-flight) for peer 3 to serve.
        assert!(
            bs.queue.contains(&h)
                || bs.in_flight.contains_key(&h)
                || bs.block_notfound_peers.contains_key(&h),
            "single-source block must remain retryable"
        );
    }

    #[test]
    fn block_abandoned_once_all_peers_notfound() {
        // 2 eligible peers, both notfound -> genuinely unavailable -> abandon.
        let mut bs = BlockSync::new();
        let h = hash_byte(44);
        bs.peer_requests.entry(1u64).or_default().insert(h);
        bs.peer_requests.entry(2u64).or_default().insert(h);
        bs.in_flight.insert(h, 1);
        let (_, a1) = bs.blocks_not_found(1, &[h], 2);
        assert!(a1.is_empty());
        let (_, a2) = bs.blocks_not_found(2, &[h], 2);
        assert_eq!(a2, vec![h], "all peers declined -> abandon");
        assert!(!bs.in_flight.contains_key(&h));
        assert!(!bs.queue.contains(&h));
    }

    #[test]
    fn assign_skips_peer_that_already_notfound() {
        // A block declined by peer 1 must not be re-assigned to peer 1.
        let mut bs = BlockSync::new();
        let h = hash_byte(55);
        bs.block_notfound_peers.entry(h).or_default().insert(1u64);
        bs.queue.push_back(h);
        bs.peer_last_recv.insert(1u64, Instant::now());
        let cmds = bs.assign_to_peers(&[1u64]);
        // Only peer 1 available and it already declined -> no assignment;
        // block stays queued for a future (different) peer.
        assert!(cmds.is_empty(), "must not re-assign to the declining peer");
        assert!(bs.queue.contains(&h));
        assert!(!bs.in_flight.contains_key(&h));
    }

    #[test]
    fn block_received_clears_all_claimants() {
        let mut bs = BlockSync::new();
        let h = hash_byte(22);
        bs.peer_requests.entry(1u64).or_default().insert(h);
        bs.peer_requests.entry(3u64).or_default().insert(h);
        bs.in_flight.insert(h, 1);
        bs.block_received(&h, 3, 1000);
        assert!(!bs.in_flight.contains_key(&h));
        assert!(bs.peer_requests.get(&1).is_some_and(|s| s.is_empty()));
        assert!(bs.peer_requests.get(&3).is_some_and(|s| s.is_empty()));
    }

    fn set_bw(bs: &mut BlockSync, pid: PeerId, bps: f64, delivered: u32) {
        bs.peer_bandwidth.insert(
            pid,
            PeerBandwidth {
                ewma_bps: bps,
                blocks_delivered: delivered,
                last_delivery: Instant::now(),
            },
        );
    }

    #[test]
    fn slow_deliverers_uniform_pool_evicts_nobody() {
        // A uniformly slow pool (ISP shaping, all-Tor) has no relative
        // stragglers — the relative gate must return nothing.
        let mut bs = BlockSync::new();
        for pid in 0..12u64 {
            set_bw(&mut bs, pid, 20_000.0, 50);
        }
        assert!(bs.slow_deliverers(8, 0.25, 8, 2).is_empty());
    }

    #[test]
    fn slow_deliverers_culls_slowest_first_capped_by_max_evict() {
        let mut bs = BlockSync::new();
        // 10 healthy peers at 400 KB/s, 3 crawlers well below 25% of median.
        for pid in 0..10u64 {
            set_bw(&mut bs, pid, 400_000.0, 50);
        }
        set_bw(&mut bs, 100, 3_000.0, 50);
        set_bw(&mut bs, 101, 5_000.0, 50);
        set_bw(&mut bs, 102, 8_000.0, 50);
        let evicted = bs.slow_deliverers(8, 0.25, 8, 2);
        assert_eq!(
            evicted,
            vec![100, 101],
            "slowest first, capped at max_evict"
        );
    }

    #[test]
    fn slow_deliverers_respects_min_keep_floor() {
        let mut bs = BlockSync::new();
        // Only 4 proven peers, one crawling — but min_keep=8 means the pool
        // is too small to shrink at all.
        for pid in 0..3u64 {
            set_bw(&mut bs, pid, 400_000.0, 50);
        }
        set_bw(&mut bs, 9, 1_000.0, 50);
        assert!(bs.slow_deliverers(8, 0.25, 8, 2).is_empty());

        // With 9 proven peers and min_keep=8, at most one may go even if
        // more are below the threshold.
        let mut bs = BlockSync::new();
        for pid in 0..7u64 {
            set_bw(&mut bs, pid, 400_000.0, 50);
        }
        set_bw(&mut bs, 100, 1_000.0, 50);
        set_bw(&mut bs, 101, 2_000.0, 50);
        let evicted = bs.slow_deliverers(8, 0.25, 8, 2);
        assert_eq!(evicted, vec![100], "min_keep floor limits evictions");
    }

    #[test]
    fn slow_deliverers_ignores_unproven_peers() {
        let mut bs = BlockSync::new();
        for pid in 0..10u64 {
            set_bw(&mut bs, pid, 400_000.0, 50);
        }
        // Crawling but hasn't delivered min_delivered blocks yet — EWMA is
        // still warming up from the optimistic default, so it's exempt.
        set_bw(&mut bs, 100, 1_000.0, 3);
        assert!(bs.slow_deliverers(8, 0.25, 8, 2).is_empty());
    }
}
