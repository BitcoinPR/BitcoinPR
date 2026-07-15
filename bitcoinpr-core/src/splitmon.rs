//! Chain-split monitor.
//!
//! Tracks rival branches that contain a consensus-invalid block (e.g. a
//! BIP-110-violating majority chain) as they grow next to our valid chain.
//! Fork choice never adopts these branches (see the taint gate in
//! `bitcoinpr-p2p`), but their headers keep arriving and are stored
//! hash-only — this module turns them into an operator-facing picture:
//! fork point, both tips, block/work deficit, and whether the deficit has
//! crossed the capitulation threshold ("abandon minority chain" becomes
//! available).
//!
//! State is in-memory and rebuilt organically after a restart: the next
//! rival-branch header batch re-seeds the tracked tip via `on_tainted_tip`.

use bitcoin::BlockHash;
use serde::Serialize;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use tokio::sync::broadcast;
use tracing::{debug, info, warn};

use crate::events::NodeNotification;
use crate::validation::calculate_work;
use bitcoinpr_storage::{cmp_work, sub_work, HeaderIndex};

/// Rival lead (in blocks AND the equivalent chain work) at which the
/// "abandon minority chain" action is offered to the operator.
pub const CAPITULATION_THRESHOLD_BLOCKS: u32 = 6;

/// Bound on prev-link walks when resolving a fork point.
const FORK_WALK_MAX: u32 = 100_000;

/// A chain tip (ours or a rival's).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TipInfo {
    pub hash: BlockHash,
    pub height: u32,
    pub work: [u8; 32],
}

fn work_hex(work: &[u8; 32]) -> String {
    let mut s = String::with_capacity(66);
    s.push_str("0x");
    for b in work {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// JSON view of a tip.
#[derive(Debug, Clone, Serialize)]
pub struct TipJson {
    pub hash: String,
    pub height: u32,
    pub work: String,
}

impl From<&TipInfo> for TipJson {
    fn from(t: &TipInfo) -> Self {
        TipJson {
            hash: t.hash.to_string(),
            height: t.height,
            work: work_hex(&t.work),
        }
    }
}

/// The first (lowest) invalid block found on the rival branch.
#[derive(Debug, Clone, Serialize)]
pub struct InvalidBlockJson {
    pub hash: String,
    pub height: u32,
    /// `bitcoinpr_storage::INVALID_REASON_*` rendered as a label.
    pub reason: String,
}

/// Per-period BIP-110 signaling stats for the rival branch (populated in
/// signaling mode only).
#[derive(Debug, Clone, Serialize)]
pub struct SignalStats {
    pub period_start: u32,
    pub signals: u32,
    pub period: u32,
    pub threshold: u32,
}

/// Operator-facing picture of an ongoing chain split.
#[derive(Debug, Clone, Serialize)]
pub struct SplitSnapshot {
    pub fork_height: u32,
    pub fork_hash: String,
    pub ours: TipJson,
    pub rival: TipJson,
    /// `rival.height - ours.height` (positive = we are behind).
    pub block_deficit: i64,
    /// Work by which the rival branch leads ours (zero when we lead).
    pub work_deficit: String,
    pub rival_first_invalid: Option<InvalidBlockJson>,
    pub rival_signaling: Option<SignalStats>,
    /// Both deficit criteria met — the "abandon minority chain" action is
    /// offered.
    pub capitulation_armed: bool,
    pub threshold_blocks: u32,
    pub updated_at: u64,
}

#[derive(Default)]
struct MonitorState {
    /// Tips of tracked rival branches. Extended in place as batches arrive.
    rival_tips: HashMap<BlockHash, TipInfo>,
    /// Cached fork point per rival tip hash.
    fork_cache: HashMap<BlockHash, (u32, BlockHash)>,
    /// Last published (rival_height, our_height, armed) — publish on change.
    last_published: Option<(u32, u32, bool)>,
    /// Live validated tip, pushed by the node tick via [`SplitMonitor::set_our_tip`].
    /// The best-tip metadata in storage is only written at UTXO-flush
    /// boundaries and shutdown, so it lags far behind on a running node.
    our_tip: Option<TipInfo>,
}

/// See module docs.
pub struct SplitMonitor {
    header_index: Arc<HeaderIndex>,
    event_tx: broadcast::Sender<NodeNotification>,
    state: RwLock<MonitorState>,
    /// Deployment parameters for rival-branch signaling stats (set when the
    /// network defines a BIP-110 deployment).
    bip110_deployment: RwLock<Option<crate::bip110::Bip110Deployment>>,
}

/// Bytes per persisted rival tip: 32 hash + 4 height LE + 32 work.
const RIVAL_TIP_BYTES: usize = 68;

impl SplitMonitor {
    pub fn new(
        header_index: Arc<HeaderIndex>,
        event_tx: broadcast::Sender<NodeNotification>,
    ) -> Self {
        let monitor = SplitMonitor {
            header_index,
            event_tx,
            state: RwLock::new(MonitorState::default()),
            bip110_deployment: RwLock::new(None),
        };
        monitor.load_persisted_rivals();
        monitor
    }

    /// Restore rival tips persisted by a previous run, so a restart
    /// mid-split resumes with the split visible instead of waiting for the
    /// next rival header batch. Tips whose headers are gone are dropped.
    fn load_persisted_rivals(&self) {
        let Some(blob) = self.header_index.get_split_rival_tips().ok().flatten() else {
            return;
        };
        let mut st = self.state.write().expect("splitmon lock poisoned");
        for chunk in blob.chunks_exact(RIVAL_TIP_BYTES) {
            let Ok(hash) =
                bitcoin::hashes::Hash::from_slice(&chunk[..32]).map(BlockHash::from_raw_hash)
            else {
                continue;
            };
            let height = u32::from_le_bytes(chunk[32..36].try_into().expect("chunk size fixed"));
            let mut work = [0u8; 32];
            work.copy_from_slice(&chunk[36..68]);
            // Only resurrect tips whose headers still exist.
            if self.header_index.get_header(&hash).ok().flatten().is_some() {
                st.rival_tips.insert(hash, TipInfo { hash, height, work });
            }
        }
        if !st.rival_tips.is_empty() {
            info!(
                count = st.rival_tips.len(),
                "Split monitor: restored persisted rival tips"
            );
        }
    }

    /// Write the current rival-tip set to storage (caller holds the state
    /// lock). Persistence is best-effort — losing it costs only the brief
    /// post-restart gap it exists to close.
    fn persist_rivals(&self, st: &MonitorState) {
        if st.rival_tips.is_empty() {
            let _ = self.header_index.clear_split_rival_tips();
            return;
        }
        let mut blob = Vec::with_capacity(st.rival_tips.len() * RIVAL_TIP_BYTES);
        for t in st.rival_tips.values() {
            blob.extend_from_slice(AsRef::<[u8]>::as_ref(&t.hash));
            blob.extend_from_slice(&t.height.to_le_bytes());
            blob.extend_from_slice(&t.work);
        }
        let _ = self.header_index.set_split_rival_tips(&blob);
    }

    /// Provide deployment parameters so snapshots include rival-branch
    /// signaling stats.
    pub fn set_bip110_deployment(&self, dep: crate::bip110::Bip110Deployment) {
        *self
            .bip110_deployment
            .write()
            .expect("splitmon lock poisoned") = Some(dep);
    }

    /// Signal count over the rival branch's current period (walked via prev
    /// links on the rival branch itself).
    fn signal_stats(&self, rival: &TipInfo) -> Option<SignalStats> {
        let dep = self
            .bip110_deployment
            .read()
            .expect("splitmon lock poisoned")
            .clone()?;
        let period = dep.period.max(1);
        let period_start = rival.height - (rival.height % period);
        let mut signals = 0u32;
        let mut hash = rival.hash;
        loop {
            let stored = self.header_index.get_header(&hash).ok().flatten()?;
            if stored.height < period_start {
                break;
            }
            if dep.signals(stored.header.version.to_consensus() as u32) {
                signals += 1;
            }
            if stored.height == 0 {
                break;
            }
            hash = stored.header.prev_blockhash;
        }
        Some(SignalStats {
            period_start,
            signals,
            period,
            threshold: dep.threshold,
        })
    }

    /// Whether any rival branch is currently tracked. Cheap (no DB access) —
    /// safe on hot paths like `/api/stats`.
    pub fn has_rival(&self) -> bool {
        !self
            .state
            .read()
            .expect("splitmon lock poisoned")
            .rival_tips
            .is_empty()
    }

    /// Whether the network is genuinely contested: a tracked rival branch
    /// matches or exceeds our chain work. False once we out-work every rival
    /// (the split is resolved in our favor — a dead branch stays tracked for
    /// the status page but is no longer a live threat) and false with no
    /// rivals at all. Cheap (state-only reads) — safe on `/api/stats`.
    ///
    /// Conservative during startup: if our tip has not been pushed yet but a
    /// rival is tracked, report contested rather than hiding a real split.
    pub fn rival_leads(&self) -> bool {
        let st = self.state.read().expect("splitmon lock poisoned");
        if st.rival_tips.is_empty() {
            return false;
        }
        let Some(ours) = st.our_tip else {
            return true;
        };
        st.rival_tips
            .values()
            .any(|t| cmp_work(&t.work, &ours.work).is_ge())
    }

    /// A tainted branch grew: `tip` is its new tip, `extended_from` the
    /// previous tip it replaced (when the batch extended a tracked branch).
    pub fn on_tainted_tip(&self, tip: TipInfo, extended_from: Option<BlockHash>) {
        let mut st = self.state.write().expect("splitmon lock poisoned");
        if let Some(prev) = extended_from {
            // Carry the fork point forward — extending a branch can't move
            // its fork point.
            if let Some(fp) = st.fork_cache.remove(&prev) {
                st.fork_cache.insert(tip.hash, fp);
            }
            st.rival_tips.remove(&prev);
        }
        debug!(tip = %tip.hash, height = tip.height, "Split monitor: rival branch tip updated");
        st.rival_tips.insert(tip.hash, tip);
        self.persist_rivals(&st);
    }

    /// A block was durably marked invalid at `height`. Seeds a rival branch
    /// (the marked block is its tip until headers extend it).
    pub fn on_invalid_marked(&self, hash: BlockHash, height: u32) {
        let work = self
            .header_index
            .get_header(&hash)
            .ok()
            .flatten()
            .map(|s| s.chain_work)
            .unwrap_or([0u8; 32]);
        let mut st = self.state.write().expect("splitmon lock poisoned");
        // If a tracked tip already descends from this block, keep it — the
        // marked block is an ancestor, not a new branch.
        if st.rival_tips.contains_key(&hash) {
            return;
        }
        info!(%hash, height, "Split monitor: tracking rival branch from invalid block");
        st.rival_tips.insert(hash, TipInfo { hash, height, work });
        self.persist_rivals(&st);
    }

    /// Current split picture, or `None` when no rival branch is tracked (or
    /// every tracked branch became canonical/stale). Reads our tip from the
    /// validated-chain metadata, so it is self-contained for RPC/web use.
    pub fn snapshot(&self) -> Option<SplitSnapshot> {
        let ours = self.our_tip()?;
        self.snapshot_against(&ours)
    }

    /// Like [`snapshot`], and publishes a `ChainSplit` notification when the
    /// picture changed since the last publish. Called from the node's
    /// periodic tick.
    pub fn refresh(&self) -> Option<SplitSnapshot> {
        let snap = self.snapshot();
        let mut st = self.state.write().expect("splitmon lock poisoned");
        match &snap {
            Some(s) => {
                let key = (s.rival.height, s.ours.height, s.capitulation_armed);
                if st.last_published != Some(key) {
                    st.last_published = Some(key);
                    let _ = self.event_tx.send(NodeNotification::ChainSplit {
                        fork_height: s.fork_height,
                        our_height: s.ours.height,
                        rival_height: s.rival.height,
                        block_deficit: s.block_deficit,
                        capitulation_armed: s.capitulation_armed,
                    });
                    if s.capitulation_armed {
                        warn!(
                            our_height = s.ours.height,
                            rival_height = s.rival.height,
                            block_deficit = s.block_deficit,
                            "Chain split: rival chain leads beyond threshold — 'abandon minority chain' is available"
                        );
                    }
                }
            }
            None => st.last_published = None,
        }
        snap
    }

    /// Push the live validated tip (from the node's shared height/hash state).
    /// Called from the periodic tick before `refresh`.
    pub fn set_our_tip(&self, hash: BlockHash, height: u32) {
        let work = self
            .header_index
            .get_header(&hash)
            .ok()
            .flatten()
            .map(|s| s.chain_work)
            .unwrap_or([0u8; 32]);
        self.state.write().expect("splitmon lock poisoned").our_tip =
            Some(TipInfo { hash, height, work });
    }

    fn our_tip(&self) -> Option<TipInfo> {
        if let Some(t) = self.state.read().expect("splitmon lock poisoned").our_tip {
            return Some(t);
        }
        // Fallback (first seconds after boot): validated-tip metadata. Stale
        // between UTXO flushes, but only used until the first tick pushes the
        // live tip.
        let hash = self.header_index.get_best_tip().ok().flatten()?;
        let stored = self.header_index.get_header(&hash).ok().flatten()?;
        Some(TipInfo {
            hash,
            height: stored.height,
            work: stored.chain_work,
        })
    }

    fn snapshot_against(&self, ours: &TipInfo) -> Option<SplitSnapshot> {
        // Pick the max-work live rival; drop branches that became canonical
        // (post-capitulation reorg) or that we cannot resolve anymore.
        let mut st = self.state.write().expect("splitmon lock poisoned");
        if st.rival_tips.is_empty() {
            return None;
        }

        let mut stale: Vec<BlockHash> = Vec::new();
        let mut best: Option<(TipInfo, (u32, BlockHash))> = None;
        let tips: Vec<TipInfo> = st.rival_tips.values().copied().collect();
        for tip in tips {
            // A rival tip that is the canonical hash at its height AND within
            // our validated chain means the branch was adopted (or never
            // really diverged) — stop tracking it. The height bound matters:
            // the headers index-repair path can re-write rival hashes into
            // the height index ABOVE our validated tip when stored fork
            // headers are re-announced, and those entries must not be read
            // as adoption.
            if tip.height <= ours.height
                && self
                    .header_index
                    .get_hash_at_height(tip.height)
                    .ok()
                    .flatten()
                    == Some(tip.hash)
            {
                stale.push(tip.hash);
                continue;
            }
            let fork = match st.fork_cache.get(&tip.hash).copied() {
                Some(f) => Some(f),
                None => {
                    let f = self.find_fork_point(&tip, ours.height);
                    if let Some(f) = f {
                        st.fork_cache.insert(tip.hash, f);
                    }
                    f
                }
            };
            let Some(fork) = fork else {
                stale.push(tip.hash);
                continue;
            };
            match &best {
                Some((b, _)) if cmp_work(&tip.work, &b.work).is_le() => {}
                _ => best = Some((tip, fork)),
            }
        }
        if !stale.is_empty() {
            for h in &stale {
                st.rival_tips.remove(h);
                st.fork_cache.remove(h);
            }
            self.persist_rivals(&st);
        }
        let (rival, (fork_height, fork_hash)) = best?;
        drop(st);

        let block_deficit = rival.height as i64 - ours.height as i64;
        let work_deficit = sub_work(&rival.work, &ours.work);

        // Arm on blocks AND work: the block count is the operator-intuitive
        // trigger, the work comparison keeps it honest once the branches'
        // difficulties diverge across a retarget boundary.
        let rival_block_work = self
            .header_index
            .get_header(&rival.hash)
            .ok()
            .flatten()
            .map(|s| calculate_work(&s.header.target()))
            .unwrap_or([0u8; 32]);
        let mut work_threshold = [0u8; 32];
        for _ in 0..CAPITULATION_THRESHOLD_BLOCKS {
            work_threshold = crate::validation::add_chain_work(&work_threshold, &rival_block_work);
        }
        let capitulation_armed = block_deficit >= CAPITULATION_THRESHOLD_BLOCKS as i64
            && cmp_work(&work_deficit, &work_threshold).is_ge();

        let rival_first_invalid = self.first_invalid_on(&rival, fork_height);

        Some(SplitSnapshot {
            fork_height,
            fork_hash: fork_hash.to_string(),
            ours: TipJson::from(ours),
            rival: TipJson::from(&rival),
            block_deficit,
            work_deficit: work_hex(&work_deficit),
            rival_first_invalid,
            rival_signaling: self.signal_stats(&rival),
            capitulation_armed,
            threshold_blocks: CAPITULATION_THRESHOLD_BLOCKS,
            updated_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
        })
    }

    /// Walk the rival branch back until it lands on the canonical chain.
    ///
    /// A height-index match only counts at or below `trust_height` (our
    /// validated tip): the headers index-repair path can write rival hashes
    /// into the index above it, and those entries must not be read as "on
    /// our chain".
    fn find_fork_point(&self, tip: &TipInfo, trust_height: u32) -> Option<(u32, BlockHash)> {
        let mut hash = tip.hash;
        let mut walked = 0u32;
        loop {
            if walked >= FORK_WALK_MAX {
                warn!(tip = %tip.hash, "Fork-point walk bound hit");
                return None;
            }
            let stored = self.header_index.get_header(&hash).ok().flatten()?;
            if stored.height <= trust_height
                && self
                    .header_index
                    .get_hash_at_height(stored.height)
                    .ok()
                    .flatten()
                    == Some(hash)
            {
                return Some((stored.height, hash));
            }
            if stored.height == 0 {
                return None;
            }
            hash = stored.header.prev_blockhash;
            walked += 1;
        }
    }

    /// Earliest marked-invalid block on the rival branch, rendered for JSON.
    fn first_invalid_on(&self, rival: &TipInfo, fork_height: u32) -> Option<InvalidBlockJson> {
        let (hash, height) = self
            .header_index
            .first_invalid_ancestor(&rival.hash, fork_height, FORK_WALK_MAX)
            .ok()
            .flatten()?;
        let reason = match self.header_index.get_invalid(&hash).ok().flatten() {
            Some((_, bitcoinpr_storage::INVALID_REASON_BIP110)) => "consensus-bip110",
            Some((_, bitcoinpr_storage::INVALID_REASON_SIGNALING)) => "mandatory-signaling",
            Some(_) => "consensus",
            None => "consensus",
        };
        Some(InvalidBlockJson {
            hash: hash.to_string(),
            height,
            reason: reason.to_string(),
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use bitcoin::hashes::Hash;
    use bitcoinpr_storage::StoredHeader;

    fn mk_header(prev: BlockHash, nonce: u32) -> bitcoin::block::Header {
        bitcoin::block::Header {
            version: bitcoin::block::Version::from_consensus(0x2000_0000),
            prev_blockhash: prev,
            merkle_root: bitcoin::TxMerkleNode::all_zeros(),
            time: 1_700_000_000 + nonce,
            bits: bitcoin::CompactTarget::from_consensus(0x207f_ffff),
            nonce,
        }
    }

    fn unit_work(n: u32) -> [u8; 32] {
        // Regtest block work is 2 per block at 0x207fffff; any consistent
        // per-block unit works for these tests.
        let header = mk_header(BlockHash::all_zeros(), 0);
        let one = calculate_work(&header.target());
        let mut acc = [0u8; 32];
        for _ in 0..n {
            acc = crate::validation::add_chain_work(&acc, &one);
        }
        acc
    }

    struct Fixture {
        _dir: tempfile::TempDir,
        index: Arc<HeaderIndex>,
        monitor: SplitMonitor,
        canon: Vec<bitcoin::block::Header>,
        rival: Vec<bitcoin::block::Header>,
    }

    /// Canonical chain c1..c3 (height-indexed, best tip set) and rival
    /// branch r2..r8 forking off c1 (hash-only, like real fork headers).
    fn fixture(rival_len: u32) -> Fixture {
        let dir = tempfile::tempdir().unwrap();
        let index = Arc::new(HeaderIndex::open(dir.path()).unwrap());

        let mut canon = Vec::new();
        let mut prev = BlockHash::all_zeros();
        for i in 1..=3u32 {
            let h = mk_header(prev, i);
            index
                .insert_header(
                    &h.block_hash(),
                    &StoredHeader {
                        header: h,
                        height: i,
                        chain_work: unit_work(i),
                    },
                )
                .unwrap();
            prev = h.block_hash();
            canon.push(h);
        }
        index.set_best_tip(&prev, 3).unwrap();

        let mut rival = Vec::new();
        let mut prev = canon[0].block_hash();
        for i in 0..rival_len {
            let h = mk_header(prev, 100 + i);
            index
                .insert_headers_hash_only(&[(
                    h.block_hash(),
                    StoredHeader {
                        header: h,
                        height: 2 + i,
                        chain_work: unit_work(2 + i),
                    },
                )])
                .unwrap();
            prev = h.block_hash();
            rival.push(h);
        }

        let (tx, _rx) = broadcast::channel(16);
        let monitor = SplitMonitor::new(index.clone(), tx);
        Fixture {
            _dir: dir,
            index,
            monitor,
            canon,
            rival,
        }
    }

    fn tip_of(index: &HeaderIndex, h: &bitcoin::block::Header) -> TipInfo {
        let stored = index.get_header(&h.block_hash()).unwrap().unwrap();
        TipInfo {
            hash: h.block_hash(),
            height: stored.height,
            work: stored.chain_work,
        }
    }

    #[test]
    fn no_split_without_rivals() {
        let f = fixture(0);
        assert!(f.monitor.snapshot().is_none());
        assert!(f.monitor.refresh().is_none());
    }

    #[test]
    fn snapshot_math_and_arming() {
        // Rival r2..r9 (8 blocks from height 2): rival tip height 9,
        // ours 3 → deficit 6 blocks and 6 block-works → armed.
        let f = fixture(8);
        f.index
            .mark_invalid(
                &f.rival[0].block_hash(),
                2,
                bitcoinpr_storage::INVALID_REASON_BIP110,
            )
            .unwrap();
        f.monitor
            .on_tainted_tip(tip_of(&f.index, f.rival.last().unwrap()), None);

        let s = f.monitor.snapshot().expect("split must be visible");
        assert_eq!(s.fork_height, 1);
        assert_eq!(s.fork_hash, f.canon[0].block_hash().to_string());
        assert_eq!(s.ours.height, 3);
        assert_eq!(s.rival.height, 9);
        assert_eq!(s.block_deficit, 6);
        assert!(s.capitulation_armed);
        assert_eq!(s.threshold_blocks, CAPITULATION_THRESHOLD_BLOCKS);
        let inv = s.rival_first_invalid.expect("invalid marker visible");
        assert_eq!(inv.height, 2);
        assert_eq!(inv.reason, "consensus-bip110");
    }

    #[test]
    fn below_threshold_not_armed() {
        // Rival tip height 7, ours 3 → deficit 4 → not armed.
        let f = fixture(6);
        f.monitor
            .on_tainted_tip(tip_of(&f.index, f.rival.last().unwrap()), None);
        let s = f.monitor.snapshot().unwrap();
        assert_eq!(s.block_deficit, 4);
        assert!(!s.capitulation_armed);
    }

    #[test]
    fn extension_carries_fork_point_and_replaces_tip() {
        let f = fixture(8);
        let mid = tip_of(&f.index, &f.rival[3]);
        f.monitor.on_tainted_tip(mid, None);
        let s1 = f.monitor.snapshot().unwrap();
        assert_eq!(s1.rival.height, 5);

        let tip = tip_of(&f.index, f.rival.last().unwrap());
        f.monitor.on_tainted_tip(tip, Some(mid.hash));
        let s2 = f.monitor.snapshot().unwrap();
        assert_eq!(s2.rival.height, 9);
        assert_eq!(s2.fork_height, 1, "fork point carried across extension");
    }

    #[test]
    fn refresh_publishes_on_change_only() {
        let f = fixture(8);
        let mut rx = f.monitor.event_tx.subscribe();
        f.monitor
            .on_tainted_tip(tip_of(&f.index, f.rival.last().unwrap()), None);

        assert!(f.monitor.refresh().is_some());
        match rx.try_recv() {
            Ok(NodeNotification::ChainSplit {
                capitulation_armed, ..
            }) => assert!(capitulation_armed),
            other => panic!("expected ChainSplit event, got {other:?}"),
        }
        // Unchanged picture → no second publish.
        assert!(f.monitor.refresh().is_some());
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn rival_tips_persist_across_monitor_restart() {
        let f = fixture(4); // rival tip height 5, canonical tip 3
        let tip = tip_of(&f.index, f.rival.last().unwrap());
        f.monitor.on_tainted_tip(tip, None);

        // A new monitor over the same index (simulated restart) resumes the
        // split immediately — no rival header batch needed.
        let (tx, _rx) = broadcast::channel(4);
        let m2 = SplitMonitor::new(f.index.clone(), tx);
        assert!(m2.has_rival(), "persisted rival must be restored");
        assert_eq!(m2.snapshot().expect("split visible").rival.height, 5);

        // Once the rival branch is adopted the tracker prunes it AND clears
        // the persisted record, so a third restart starts clean.
        for (i, h) in f.rival.iter().enumerate() {
            f.index
                .set_height_hash(2 + i as u32, &h.block_hash())
                .unwrap();
        }
        let rival_tip = f.rival.last().unwrap().block_hash();
        f.index.set_best_tip(&rival_tip, 5).unwrap();
        m2.set_our_tip(rival_tip, 5);
        assert!(m2.snapshot().is_none());
        let (tx3, _rx3) = broadcast::channel(4);
        let m3 = SplitMonitor::new(f.index.clone(), tx3);
        assert!(!m3.has_rival(), "adopted rival must not be resurrected");
    }

    #[test]
    fn rival_leads_tracks_the_work_race() {
        let f = fixture(4); // rival tip height 5 (work 5 units), canonical tip 3
        assert!(!f.monitor.rival_leads(), "no rivals tracked yet");

        f.monitor
            .on_tainted_tip(tip_of(&f.index, f.rival.last().unwrap()), None);
        // Our tip not pushed yet → conservative: contested.
        assert!(f.monitor.rival_leads());

        // Ours behind on work → contested.
        f.monitor.set_our_tip(f.canon[2].block_hash(), 3);
        assert!(f.monitor.rival_leads());

        // Extend the canonical chain past the rival's work → resolved.
        let mut prev = f.canon[2].block_hash();
        for i in 4..=6u32 {
            let h = mk_header(prev, i);
            f.index
                .insert_header(
                    &h.block_hash(),
                    &StoredHeader {
                        header: h,
                        height: i,
                        chain_work: unit_work(i),
                    },
                )
                .unwrap();
            prev = h.block_hash();
        }
        f.index.set_best_tip(&prev, 6).unwrap();
        f.monitor.set_our_tip(prev, 6);
        assert!(!f.monitor.rival_leads(), "out-worked rival is not live");
        // …but it stays tracked for the status page.
        assert!(f.monitor.has_rival());
        assert_eq!(f.monitor.snapshot().unwrap().block_deficit, -1);
    }

    #[test]
    fn repair_polluted_height_index_does_not_drop_rival() {
        // The headers index-repair path can write rival hashes into the
        // height index ABOVE our validated tip; that must not read as
        // "branch adopted", must not move the fork point, and must not
        // hide the first invalid rival block.
        let f = fixture(8); // rival tip height 9, ours 3
        f.index
            .mark_invalid(
                &f.rival[0].block_hash(),
                2,
                bitcoinpr_storage::INVALID_REASON_BIP110,
            )
            .unwrap();
        let tip = tip_of(&f.index, f.rival.last().unwrap());
        f.monitor.on_tainted_tip(tip, None);

        // Simulate repair pollution: rival entries indexed above our tip.
        for (i, h) in f.rival.iter().enumerate() {
            let height = 2 + i as u32;
            if height > 3 {
                f.index.set_height_hash(height, &h.block_hash()).unwrap();
            }
        }

        let s = f.monitor.snapshot().expect("rival must stay tracked");
        assert_eq!(s.rival.height, 9);
        assert_eq!(s.fork_height, 1, "fork point must ignore polluted entries");
        assert_eq!(
            s.rival_first_invalid.expect("invalid block visible").height,
            2
        );
        assert!(f.monitor.has_rival());
    }

    #[test]
    fn signal_stats_count_rival_period() {
        let f = fixture(4); // rival r2..r5 (mk_header version 0x20000000: not signaling)
        f.monitor
            .set_bip110_deployment(crate::bip110::Bip110Deployment {
                period: 2,
                bit: 4,
                start_time: 0,
                threshold: 2,
                lock_in_floor_height: 1_000,
                mandatory_window: (0, 0),
                active_duration: 100,
            });
        f.monitor
            .on_tainted_tip(tip_of(&f.index, f.rival.last().unwrap()), None);
        let s = f.monitor.snapshot().unwrap();
        let sig = s.rival_signaling.expect("stats when deployment set");
        // Rival tip height 5, period 2 → period_start 4, blocks 4..=5 on the
        // rival branch, none signaling.
        assert_eq!(sig.period_start, 4);
        assert_eq!(sig.period, 2);
        assert_eq!(sig.signals, 0);
        assert_eq!(sig.threshold, 2);
    }

    #[test]
    fn adopted_rival_branch_stops_tracking() {
        let f = fixture(4);
        let tip = tip_of(&f.index, f.rival.last().unwrap());
        f.monitor.on_tainted_tip(tip, None);
        assert!(f.monitor.snapshot().is_some());

        // Simulate post-capitulation adoption: the rival branch becomes the
        // canonical chain.
        for (i, h) in f.rival.iter().enumerate() {
            f.index
                .set_height_hash(2 + i as u32, &h.block_hash())
                .unwrap();
        }
        f.index
            .set_best_tip(&f.rival.last().unwrap().block_hash(), 5)
            .unwrap();
        assert!(f.monitor.snapshot().is_none());
        // And the tracked entry is gone for good.
        assert!(f.monitor.state.read().unwrap().rival_tips.is_empty());
    }
}
