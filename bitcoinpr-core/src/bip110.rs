//! BIP-110 (Reduced Data Temporary Softfork) — signaling-driven activation.
//!
//! Unlike the buried historical deployments, BIP-110 activates dynamically from
//! on-chain miner signaling. This module computes the deployment's threshold
//! state for any block from its *ancestor chain* (so it is reorg-safe), using a
//! BIP-8-style, height-based state machine:
//!
//! ```text
//!   DEFINED  → STARTED    when MTP(period boundary) >= start_time
//!   STARTED  → LOCKED_IN  when a 2016-block period has >= threshold bit-N signals,
//!                         or the period starting at lock_in_floor_height is reached
//!   LOCKED_IN → ACTIVE    one retarget period later (activation_height)
//!   ACTIVE   → EXPIRED    active_duration blocks after activation (rules then cease)
//! ```
//!
//! The activation height — the grandfathering cutoff for the seven RDTS rules —
//! is therefore a multiple of the 2016-block retarget period, determined by when
//! signaling locks the deployment in. Results are cached per period-boundary
//! block hash (the hash commits to the whole ancestor chain, so cached entries
//! stay correct across reorgs).

use std::collections::HashMap;
use std::sync::Mutex;

use bitcoin::BlockHash;
use bitcoinpr_storage::{HeaderIndex, StoredHeader};

use crate::validation::get_median_time_past;

/// Blocks per retarget period / signaling window on mainnet.
pub const RETARGET_PERIOD: u32 = 2016;

/// Parameters of the BIP-110 versionbits deployment for a network.
#[derive(Debug, Clone)]
pub struct Bip110Deployment {
    /// Blocks per signaling/retarget period (mainnet: 2016). Configurable so the
    /// state machine can be exercised on short synthetic chains in tests.
    pub period: u32,
    /// nVersion bit signaled by miners (BIP-110 uses bit 4).
    pub bit: u8,
    /// Median-time-past at/after which the deployment leaves DEFINED for STARTED.
    pub start_time: u64,
    /// Signaling blocks required in a period to lock in (BIP-110: 1109 = 55%).
    pub threshold: u32,
    /// If the deployment is still STARTED when the period starting at this height
    /// is reached, it is forced to LOCKED_IN (mandatory-signaling floor). The
    /// mandatory-signaling window guarantees this anyway; the floor makes the
    /// state machine deterministic even without re-counting. BIP-110: 963648.
    pub lock_in_floor_height: u32,
    /// Inclusive height window during which, while the deployment is STARTED,
    /// blocks that do not signal `bit` are invalid. BIP-110: (961632, 963647).
    pub mandatory_window: (u32, u32),
    /// Blocks the deployment stays ACTIVE before transitioning to EXPIRED, after
    /// which the rules cease to be enforced. BIP-110: 52416 (~1 year).
    pub active_duration: u32,
}

impl Bip110Deployment {
    /// Mainnet BIP-110 parameters.
    pub fn mainnet() -> Self {
        Bip110Deployment {
            period: RETARGET_PERIOD,
            bit: 4,
            start_time: 1_764_547_200, // ~2025-12-01
            threshold: 1109,           // 55% of 2016
            lock_in_floor_height: 963_648,
            mandatory_window: (961_632, 963_647),
            active_duration: 52_416,
        }
    }

    /// Does `version` signal this deployment (BIP-9 top bits `001` + `bit` set)?
    pub fn signals(&self, version: u32) -> bool {
        const TOP_MASK: u32 = 0xE000_0000;
        const TOP_BITS: u32 = 0x2000_0000;
        (version & TOP_MASK) == TOP_BITS && (version & (1u32 << self.bit)) != 0
    }
}

/// BIP-8/9 threshold states for a deployment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThresholdState {
    Defined,
    Started,
    LockedIn,
    Active,
    Expired,
}

/// The deployment's state as seen by a specific block, plus the activation height
/// once it is known (LOCKED_IN onward).
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bip110Activation {
    pub state: ThresholdState,
    /// Height at which the deployment becomes ACTIVE (a multiple of the retarget
    /// period). `Some` once LOCKED_IN; `None` while DEFINED/STARTED.
    pub activation_height: Option<u32>,
}

impl Bip110Activation {
    /// Never-configured / never-active result.
    pub const INACTIVE: Bip110Activation = Bip110Activation {
        state: ThresholdState::Defined,
        activation_height: None,
    };

    /// A fixed-mode activation (testing override): ACTIVE from `height` with no
    /// expiry. Used for the `--bip110height` regtest override.
    pub fn fixed(activation_height: u32, block_height: u32) -> Bip110Activation {
        Bip110Activation {
            state: if block_height >= activation_height {
                ThresholdState::Active
            } else {
                ThresholdState::Started
            },
            activation_height: Some(activation_height),
        }
    }

    /// Are the seven RDTS rules enforced at this block? Only while ACTIVE.
    pub fn enforcing(&self) -> bool {
        self.state == ThresholdState::Active
    }
}

/// Evaluate the BIP-110 deployment for a block at `height` whose parent is
/// `prev_hash`, picking the right mode: the fixed-mode override
/// (`ConsensusParams::bip110_activation_height`, e.g. `--bip110height`) takes
/// precedence; otherwise the signaling `checker` computes the result from the
/// ancestor chain; otherwise the deployment is inactive. Shared by chain
/// validation, mempool acceptance, mining, and RPC so they agree.
pub fn activation_at(
    params: &crate::consensus::ConsensusParams,
    checker: Option<&Bip110Checker>,
    header_index: &HeaderIndex,
    prev_hash: &BlockHash,
    height: u32,
) -> Bip110Activation {
    if let Some(activation) = params.bip110_activation_height {
        return Bip110Activation::fixed(activation, height);
    }
    match checker {
        Some(c) => c.activation_for(header_index, prev_hash, height),
        None => Bip110Activation::INACTIVE,
    }
}

/// Computes (and caches) BIP-110 deployment state for blocks from their ancestor
/// chain. The cache is keyed by period-boundary block hash (the last block of a
/// retarget period), which commits to the entire ancestor chain — so cached
/// entries remain valid across reorgs.
pub struct Bip110Checker {
    dep: Bip110Deployment,
    /// boundary block hash → (state of the period *after* the boundary,
    /// activation height if known).
    cache: Mutex<HashMap<BlockHash, (ThresholdState, Option<u32>)>>,
}

impl Bip110Checker {
    pub fn new(dep: Bip110Deployment) -> Self {
        Bip110Checker {
            dep,
            cache: Mutex::new(HashMap::new()),
        }
    }

    pub fn deployment(&self) -> &Bip110Deployment {
        &self.dep
    }

    /// State for the block at `height` whose parent is `prev_hash`. Returns
    /// `INACTIVE` when the chain context needed to evaluate it is unavailable
    /// (a missing ancestor header), which is the conservative answer — no
    /// enforcement — and matches how the rest of validation fails closed by
    /// retrying once headers are present.
    pub fn activation_for(
        &self,
        header_index: &HeaderIndex,
        prev_hash: &BlockHash,
        height: u32,
    ) -> Bip110Activation {
        let period = self.dep.period;
        let period_index = height / period;
        if period_index == 0 {
            // Genesis period can never have transitioned out of DEFINED.
            return Bip110Activation::INACTIVE;
        }
        // Fast path: a block whose median-time-past precedes start_time is
        // necessarily DEFINED. MTP is non-decreasing along the chain, so the
        // earlier period boundary's MTP is also below start_time. This avoids the
        // ancestor walk and signal counting for the bulk of pre-deployment
        // history (this is called per block on the consensus path).
        if let Some(mtp) = get_median_time_past(header_index, prev_hash) {
            if (mtp as u64) < self.dep.start_time {
                return Bip110Activation::INACTIVE;
            }
        }
        // The block's state is the state computed at the boundary ending the
        // previous period (last block of period `period_index - 1`).
        let boundary_height = period_index * period - 1;
        let boundary = match header_index.get_ancestor(prev_hash, boundary_height) {
            Ok(Some(h)) => h,
            _ => return Bip110Activation::INACTIVE,
        };
        let (state, activation_height) = self.state_at_boundary(header_index, boundary);
        Bip110Activation {
            state,
            activation_height,
        }
    }

    /// State for the period immediately *after* `boundary` (the last block of a
    /// period). Memoized by boundary hash; the walk back to a base case stops at
    /// the first boundary whose MTP precedes `start_time` (DEFINED), bounding the
    /// cold-start cost to periods after the deployment could have started.
    fn state_at_boundary(
        &self,
        header_index: &HeaderIndex,
        boundary: StoredHeader,
    ) -> (ThresholdState, Option<u32>) {
        let period = self.dep.period;
        let mut to_compute: Vec<StoredHeader> = Vec::new();
        let mut cur = boundary;

        let base = loop {
            let cur_hash = cur.header.block_hash();
            if let Some(cached) = self
                .cache
                .lock()
                .expect("bip110 cache poisoned")
                .get(&cur_hash)
            {
                break *cached;
            }
            // A boundary whose MTP precedes start_time is DEFINED — and so is
            // every earlier boundary, so we can stop walking back here.
            let mtp = get_median_time_past(header_index, &cur_hash).unwrap_or(0) as u64;
            if mtp < self.dep.start_time {
                break (ThresholdState::Defined, None);
            }
            // Find the previous period boundary (an ancestor of cur's parent).
            let prev_boundary_height = match cur.height.checked_sub(period) {
                Some(h) => h,
                None => {
                    // No earlier boundary: the period `cur` ends is the genesis
                    // period (always DEFINED). Still transition `cur` from DEFINED.
                    to_compute.push(cur);
                    break (ThresholdState::Defined, None);
                }
            };
            let parent = cur.header.prev_blockhash;
            to_compute.push(cur);
            match header_index.get_ancestor(&parent, prev_boundary_height) {
                Ok(Some(pb)) => cur = pb,
                _ => break (ThresholdState::Defined, None),
            }
        };

        let (mut state, mut activation) = base;
        while let Some(b) = to_compute.pop() {
            let (next_state, next_activation) =
                self.transition(header_index, state, activation, &b);
            self.cache
                .lock()
                .expect("bip110 cache poisoned")
                .insert(b.header.block_hash(), (next_state, next_activation));
            state = next_state;
            activation = next_activation;
        }
        (state, activation)
    }

    /// Compute the state of the period *after* boundary `b` from the state of the
    /// period `b` ends (`state`/`activation`).
    fn transition(
        &self,
        header_index: &HeaderIndex,
        state: ThresholdState,
        activation: Option<u32>,
        b: &StoredHeader,
    ) -> (ThresholdState, Option<u32>) {
        // Period after b starts at b.height + 1 (b is the last block of its period).
        let next_period_start = b.height + 1;
        match state {
            ThresholdState::Defined => {
                let mtp =
                    get_median_time_past(header_index, &b.header.block_hash()).unwrap_or(0) as u64;
                if mtp >= self.dep.start_time {
                    (ThresholdState::Started, None)
                } else {
                    (ThresholdState::Defined, None)
                }
            }
            ThresholdState::Started => {
                let signals = self.count_signals(header_index, b);
                let mandatory = next_period_start >= self.dep.lock_in_floor_height;
                if signals >= self.dep.threshold || mandatory {
                    // ACTIVE one period after the LOCKED_IN period begins.
                    (
                        ThresholdState::LockedIn,
                        Some(next_period_start + self.dep.period),
                    )
                } else {
                    (ThresholdState::Started, None)
                }
            }
            ThresholdState::LockedIn => (ThresholdState::Active, activation),
            ThresholdState::Active => match activation {
                Some(a) if next_period_start >= a.saturating_add(self.dep.active_duration) => {
                    (ThresholdState::Expired, activation)
                }
                _ => (ThresholdState::Active, activation),
            },
            ThresholdState::Expired => (ThresholdState::Expired, activation),
        }
    }

    /// Count blocks in the retarget period ending at boundary `b` that signal the
    /// deployment bit. Walks the 2016 block headers via prev pointers.
    fn count_signals(&self, header_index: &HeaderIndex, b: &StoredHeader) -> u32 {
        let period_start = b.height + 1 - self.dep.period;
        let mut count = 0u32;
        let mut cur = b.clone();
        loop {
            if self.dep.signals(cur.header.version.to_consensus() as u32) {
                count += 1;
            }
            if cur.height <= period_start {
                break;
            }
            match header_index.get_header(&cur.header.prev_blockhash) {
                Ok(Some(p)) if p.height < cur.height => cur = p,
                _ => break,
            }
        }
        count
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use bitcoin::block::{Header, Version};
    use bitcoin::hashes::Hash;
    use bitcoin::{Network, TxMerkleNode};

    const SIGNAL: i32 = 0x2000_0010u32 as i32; // BIP-9 top bits + bit 4
    const NO_SIGNAL: i32 = 0x2000_0000u32 as i32;

    /// Small deployment for short synthetic chains: period 4, lock in at 3/4
    /// signals, ACTIVE for 2 periods (8 blocks). No mandatory floor/window.
    fn test_dep() -> Bip110Deployment {
        Bip110Deployment {
            period: 4,
            bit: 4,
            start_time: 1000,
            threshold: 3,
            lock_in_floor_height: 1_000_000,
            mandatory_window: (0, 0),
            active_duration: 8,
        }
    }

    /// Build a header index from per-height `(version, time)` for heights 1..=N on
    /// top of the regtest genesis. Returns the index and `hashes[height]`.
    fn build_chain(blocks: &[(i32, u32)]) -> (tempfile::TempDir, HeaderIndex, Vec<BlockHash>) {
        let dir = tempfile::tempdir().unwrap();
        let hi = HeaderIndex::open(&dir.path().join("headers")).unwrap();
        let genesis = bitcoin::constants::genesis_block(Network::Regtest);
        let mut prev = genesis.block_hash();
        hi.insert_header(
            &prev,
            &StoredHeader {
                header: genesis.header,
                height: 0,
                chain_work: [0u8; 32],
            },
        )
        .unwrap();
        let mut hashes = vec![prev];
        for (i, &(version, time)) in blocks.iter().enumerate() {
            let header = Header {
                version: Version::from_consensus(version),
                prev_blockhash: prev,
                merkle_root: TxMerkleNode::all_zeros(),
                time,
                bits: genesis.header.bits,
                nonce: 0,
            };
            let hash = header.block_hash();
            hi.insert_header(
                &hash,
                &StoredHeader {
                    header,
                    height: (i + 1) as u32,
                    chain_work: [0u8; 32],
                },
            )
            .unwrap();
            prev = hash;
            hashes.push(hash);
        }
        (dir, hi, hashes)
    }

    /// Activation as seen by the block at `height` (parent = hashes[height-1]).
    fn at(
        checker: &Bip110Checker,
        hi: &HeaderIndex,
        hashes: &[BlockHash],
        height: u32,
    ) -> Bip110Activation {
        checker.activation_for(hi, &hashes[(height - 1) as usize], height)
    }

    #[test]
    fn full_lifecycle_signaling_lockin() {
        // Heights 4-7 (period 1) signal; lock-in at boundary 7 → ACTIVE at 12,
        // EXPIRED at 12 + active_duration(8) = 20.
        let mut blocks = Vec::new();
        for h in 1..=21u32 {
            let v = if (4..=7).contains(&h) {
                SIGNAL
            } else {
                NO_SIGNAL
            };
            blocks.push((v, 2000)); // MTP 2000 >= start_time, so STARTED early
        }
        let (_d, hi, hashes) = build_chain(&blocks);
        let checker = Bip110Checker::new(test_dep());

        // Period 1 (heights 4-7): STARTED, not yet locked in.
        let s = at(&checker, &hi, &hashes, 5);
        assert_eq!(s.state, ThresholdState::Started);
        assert_eq!(s.activation_height, None);

        // Period 2 (heights 8-11): LOCKED_IN, activation known (12), not enforcing.
        let l = at(&checker, &hi, &hashes, 8);
        assert_eq!(l.state, ThresholdState::LockedIn);
        assert_eq!(l.activation_height, Some(12));
        assert!(!l.enforcing());

        // Period 3 (heights 12-15): ACTIVE.
        let a = at(&checker, &hi, &hashes, 12);
        assert_eq!(a.state, ThresholdState::Active);
        assert_eq!(a.activation_height, Some(12));
        assert!(a.enforcing());
        assert!(at(&checker, &hi, &hashes, 15).enforcing());

        // Period 5 (heights 20+): EXPIRED — rules cease.
        let e = at(&checker, &hi, &hashes, 20);
        assert_eq!(e.state, ThresholdState::Expired);
        assert_eq!(e.activation_height, Some(12));
        assert!(!e.enforcing());
    }

    #[test]
    fn mandatory_floor_locks_in_without_signals() {
        // Threshold unreachable (100) and no block signals, but the lock-in floor
        // at height 8 forces LOCKED_IN for the period starting there → ACTIVE 12.
        let mut dep = test_dep();
        dep.threshold = 100;
        dep.lock_in_floor_height = 8;
        let blocks: Vec<(i32, u32)> = (1..=13).map(|_| (NO_SIGNAL, 2000)).collect();
        let (_d, hi, hashes) = build_chain(&blocks);
        let checker = Bip110Checker::new(dep);

        assert_eq!(at(&checker, &hi, &hashes, 7).state, ThresholdState::Started);
        let l = at(&checker, &hi, &hashes, 8);
        assert_eq!(l.state, ThresholdState::LockedIn);
        assert_eq!(l.activation_height, Some(12));
        assert_eq!(at(&checker, &hi, &hashes, 12).state, ThresholdState::Active);
    }

    #[test]
    fn defined_before_start_time() {
        // MTP below start_time keeps the deployment DEFINED regardless of signals.
        let blocks: Vec<(i32, u32)> = (1..=12).map(|_| (SIGNAL, 100)).collect(); // time 100 < 1000
        let (_d, hi, hashes) = build_chain(&blocks);
        let checker = Bip110Checker::new(test_dep());
        for h in [4u32, 8, 12] {
            let s = at(&checker, &hi, &hashes, h);
            assert_eq!(s.state, ThresholdState::Defined, "height {h}");
            assert_eq!(s.activation_height, None);
        }
    }

    #[test]
    fn reorg_safety_two_forks_diverge() {
        // Shared prefix heights 0-3; fork A signals in period 1 (locks in), fork B
        // does not (stays STARTED). The same checker must report different states
        // for the two tips — proving the per-boundary-hash cache is reorg-safe.
        let dir = tempfile::tempdir().unwrap();
        let hi = HeaderIndex::open(&dir.path().join("headers")).unwrap();
        let genesis = bitcoin::constants::genesis_block(Network::Regtest);
        let mut prev = genesis.block_hash();
        hi.insert_header(
            &prev,
            &StoredHeader {
                header: genesis.header,
                height: 0,
                chain_work: [0u8; 32],
            },
        )
        .unwrap();

        let mk = |prev: BlockHash, height: u32, version: i32| {
            let header = Header {
                version: Version::from_consensus(version),
                prev_blockhash: prev,
                merkle_root: TxMerkleNode::from_byte_array([height as u8; 32]),
                time: 2000,
                bits: genesis.header.bits,
                nonce: 0,
            };
            (header.block_hash(), header)
        };

        // Shared prefix heights 1-3 (period 0).
        for h in 1..=3u32 {
            let (hash, header) = mk(prev, h, NO_SIGNAL);
            hi.insert_header(
                &hash,
                &StoredHeader {
                    header,
                    height: h,
                    chain_work: [0u8; 32],
                },
            )
            .unwrap();
            prev = hash;
        }
        let fork_point = prev;

        // Build a fork from the shared tip; the two forks differ in version bits so
        // their block hashes differ even at matching heights.
        let build_fork = |start: BlockHash, signal_period1: bool| -> Vec<BlockHash> {
            let mut prev = start;
            let mut hashes = vec![BlockHash::all_zeros(); 4]; // pad indices 0..3 (unused)
            for h in 4..=13u32 {
                let sig = if signal_period1 && (4..=7).contains(&h) {
                    SIGNAL
                } else {
                    NO_SIGNAL
                };
                let version = if signal_period1 { sig } else { sig | 0x100 };
                let (hash, header) = mk(prev, h, version);
                hi.insert_header(
                    &hash,
                    &StoredHeader {
                        header,
                        height: h,
                        chain_work: [0u8; 32],
                    },
                )
                .unwrap();
                prev = hash;
                hashes.push(hash);
            }
            hashes
        };
        let fork_a = build_fork(fork_point, true); // signals → locks in
        let fork_b = build_fork(fork_point, false); // never signals (no floor)

        let checker = Bip110Checker::new(test_dep());
        let a = checker.activation_for(&hi, &fork_a[11], 12);
        let b = checker.activation_for(&hi, &fork_b[11], 12);
        assert_eq!(a.state, ThresholdState::Active, "fork A should activate");
        assert_eq!(a.activation_height, Some(12));
        assert_eq!(
            b.state,
            ThresholdState::Started,
            "fork B should not activate"
        );
        assert_eq!(b.activation_height, None);
    }

    #[test]
    fn fixed_mode_activation() {
        // The fixed-mode override: ACTIVE from the height, STARTED before, no expiry.
        let a = Bip110Activation::fixed(200, 199);
        assert_eq!(a.state, ThresholdState::Started);
        assert!(!a.enforcing());
        let b = Bip110Activation::fixed(200, 200);
        assert_eq!(b.state, ThresholdState::Active);
        assert!(b.enforcing());
        assert_eq!(b.activation_height, Some(200));
    }
}
