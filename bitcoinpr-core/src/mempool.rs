use bitcoin::{BlockHash, OutPoint, Transaction, Txid};
use rayon::prelude::*;
use std::collections::{HashMap, HashSet};
use tracing::{debug, info};

use crate::consensus::ConsensusParams;
use crate::error::{CoreError, CoreResult};
use crate::script::{self, ScriptFlags, SigCache};
use crate::validation;
use bitcoinpr_storage::{HeaderIndex, UtxoSet};

/// Maximum number of transactions evicted by a single RBF replacement.
const MAX_RBF_REPLACEMENTS: usize = 100;
/// Default mempool expiry time: 2 weeks (in seconds).
const DEFAULT_MEMPOOL_EXPIRY: u64 = 14 * 24 * 60 * 60;
/// Maximum ancestor count for a single transaction.
const MAX_ANCESTORS: usize = 25;
/// Maximum descendant count for a single transaction.
const MAX_DESCENDANTS: usize = 25;
/// Default mempool memory budget in bytes, measured against
/// [`Mempool::memory_usage`] (Core's `-maxmempool`, default 300 MB there).
/// This node targets small single-box deployments, so 64 MB — still tens of
/// thousands of typical transactions.
pub const DEFAULT_MAX_MEMPOOL_BYTES: usize = 64 * 1024 * 1024;
/// Minimum relay feerate in sat/vB (Core's `-minrelaytxfee`, 1000 sat/kvB).
/// Transactions below this are rejected outright — policy only, never applied
/// to block validation.
const MIN_RELAY_FEE_RATE: f64 = 1.0;
/// Feerate step added on top of an evicted entry's feerate when raising the
/// dynamic acceptance floor (Core's `-incrementalrelayfee`, 1000 sat/kvB).
const INCREMENTAL_RELAY_FEE_RATE: f64 = 1.0;
/// Half-life of the dynamic eviction fee floor: it halves every 12 hours
/// (Core's ROLLING_FEE_HALFLIFE) until it falls back to the min relay rate.
const EVICTION_FLOOR_HALFLIFE_SECS: u64 = 12 * 60 * 60;
/// Per-entry overhead of `std::collections::HashMap` (hashbrown): control
/// byte, capacity slack (~1/8 load-factor headroom), and allocator metadata,
/// rounded to a simple documented constant. Used by the memory accounting.
const HASHMAP_ENTRY_OVERHEAD: usize = 56;
/// Dust threshold feerate in sat/vB (Core's `-dustrelayfee`, 3000 sat/kvB):
/// an output is dust if spending it at this rate would cost more than its
/// value.
const DUST_RELAY_FEE_RATE: u64 = 3;

/// A transaction entry in the mempool.
#[derive(Debug, Clone)]
pub struct MempoolEntry {
    pub tx: Transaction,
    pub txid: Txid,
    pub fee: u64,
    pub size: usize,
    pub weight: u64,
    /// Fee rate in satoshis per virtual byte (sat/vB).
    pub fee_rate: f64,
    /// Unix timestamp when this transaction was added.
    pub time: u64,
    /// BIP 68 lock point: minimum block height at which every height-based
    /// relative lock is satisfied (0 = none). Computed at acceptance from the
    /// inputs' confirmation heights (Bitcoin Core's `LockPoints`).
    pub lock_height: u32,
    /// BIP 68 lock point: minimum block median-time-past at which every
    /// time-based relative lock is satisfied (0 = none).
    pub lock_time: u32,
}

impl MempoolEntry {
    /// Whether this transaction may be included in a block at `height` whose
    /// BIP 113 time reference (the previous block's median-time-past) is `mtp`.
    /// Mirrors `connect_block`'s nLockTime + BIP 68 enforcement so templates
    /// never include a transaction our own validation would reject.
    pub fn final_for_block(&self, height: u32, mtp: u32) -> bool {
        validation::is_final_tx(&self.tx, height, mtp)
            && height >= self.lock_height
            && mtp >= self.lock_time
    }
}

/// Chain context required for mempool acceptance (nLockTime / BIP 113 finality
/// and BIP 68 sequence locks). A transaction admitted to the mempool must be
/// valid in the *next* block, so checks evaluate at height `tip_height + 1`
/// using the current tip's median-time-past — exactly Bitcoin Core's
/// `CheckFinalTxAtTip` / `CheckSequenceLocksAtTip`.
pub struct MempoolChainContext<'a> {
    /// Height of the current validated chain tip.
    pub tip_height: u32,
    /// Median-time-past of the current chain tip (BIP 113 time reference).
    pub tip_mtp: u32,
    /// Header index, used to resolve the per-input MTPs that time-based
    /// BIP 68 locks measure from.
    pub header_index: &'a HeaderIndex,
    /// BIP-110 deployment state for the *next* block (height `tip_height + 1`),
    /// so the mempool rejects transactions that block validation would reject.
    /// `INACTIVE` when RDTS is not active.
    pub bip110: crate::bip110::Bip110Activation,
}

impl<'a> MempoolChainContext<'a> {
    /// Build a context from the validated chain tip, computing the tip's
    /// median-time-past from the header index. Missing headers degrade to an
    /// MTP of 0, which fails time-locked txs CLOSED for nLockTime finality
    /// (mtp 0 means "no time has passed", so time locks are not yet
    /// satisfied) — acceptable for this policy path. (`connect_block`, by
    /// contrast, errors outright on a failed MTP lookup.)
    pub fn at_tip(header_index: &'a HeaderIndex, tip_height: u32, tip_hash: &BlockHash) -> Self {
        let tip_mtp = validation::get_median_time_past(header_index, tip_hash).unwrap_or(0);
        MempoolChainContext {
            tip_height,
            tip_mtp,
            header_index,
            // Default to inactive; callers with a ChainState set this from the
            // BIP-110 deployment state via `with_bip110`.
            bip110: crate::bip110::Bip110Activation::INACTIVE,
        }
    }

    /// Attach the BIP-110 deployment state evaluated for the next block.
    pub fn with_bip110(mut self, bip110: crate::bip110::Bip110Activation) -> Self {
        self.bip110 = bip110;
        self
    }
}

/// Check if a transaction signals BIP 125 replace-by-fee.
fn signals_rbf(tx: &Transaction) -> bool {
    tx.input.iter().any(|input| input.sequence.0 < 0xfffffffe)
}

/// Dust threshold in satoshis for an output (Core's `GetDustThreshold`):
/// 3 sat/vB times the cost of creating *and later spending* the output —
/// the output's serialized size plus an input-size estimate (148 bytes for
/// non-segwit, 67 vbytes for segwit, Core's integer math: 32+4+1+107/4+4).
/// Yields the canonical 546 sats for P2PKH and 294 for P2WPKH.
///
/// OP_RETURN outputs are exempt (returns 0): provably unspendable outputs
/// are never spent, so they cannot be dust — the datacarrier rule limits
/// them instead.
fn dust_threshold(output: &bitcoin::TxOut) -> u64 {
    let spk = &output.script_pubkey;
    if spk.is_op_return() {
        return 0;
    }
    // Serialized TxOut: 8-byte amount + compact-size script length + script.
    let script_len_prefix: usize = if spk.len() < 253 {
        1
    } else if spk.len() < 0x10000 {
        3
    } else {
        5
    };
    let mut spend_size = 8 + script_len_prefix + spk.len();
    // Plus the estimated size of the input that would spend it.
    if spk.is_witness_program() {
        spend_size += 32 + 4 + 1 + 107 / 4 + 4; // 67 vbytes (witness discounted)
    } else {
        spend_size += 32 + 4 + 1 + 107 + 4; // 148 bytes
    }
    DUST_RELAY_FEE_RATE * spend_size as u64
}

/// Per-output relay policy (a subset of Core/Knots standardness): the
/// datacarrier and datacarriersize rules for OP_RETURN outputs, the
/// permitbaremultisig rule, and the dust rule for everything else. Policy
/// only — block validation never runs through here, so blocks containing
/// these outputs still validate.
fn check_output_policy(tx: &Transaction, txid: Txid, params: &ConsensusParams) -> CoreResult<()> {
    for (vout, output) in tx.output.iter().enumerate() {
        if output.script_pubkey.is_op_return() {
            if !params.datacarrier {
                return Err(CoreError::InvalidTransaction(format!(
                    "datacarrier disabled: output {vout} of tx {txid} is OP_RETURN"
                )));
            }
            if output.script_pubkey.len() > params.max_datacarrier_size {
                return Err(CoreError::InvalidTransaction(format!(
                    "OP_RETURN output size {} exceeds datacarriersize limit {}",
                    output.script_pubkey.len(),
                    params.max_datacarrier_size
                )));
            }
        } else {
            if !params.permit_bare_multisig && output.script_pubkey.is_multisig() {
                return Err(CoreError::InvalidTransaction(format!(
                    "bare multisig output {vout} of tx {txid} rejected (permitbaremultisig=0)"
                )));
            }
            let threshold = dust_threshold(output);
            if output.value.to_sat() < threshold {
                return Err(CoreError::InvalidTransaction(format!(
                    "dust: output {} of tx {} pays {} sat, below dust threshold {}",
                    vout,
                    txid,
                    output.value.to_sat(),
                    threshold
                )));
            }
        }
    }
    Ok(())
}

/// Knots-style relay policy for a whole transaction: the per-output rules
/// ([`check_output_policy`]) plus the parasite (inscription-envelope) and
/// token-protocol filters. Policy only — block validation never runs through
/// here, so blocks containing filtered transactions still validate.
fn check_relay_policy(tx: &Transaction, txid: Txid, params: &ConsensusParams) -> CoreResult<()> {
    check_output_policy(tx, txid, params)?;
    if params.reject_parasites {
        if let Some(i) = script::tx_first_inscription_input(tx) {
            return Err(CoreError::InvalidTransaction(format!(
                "parasite: input {i} of tx {txid} carries an inscription envelope (rejectparasites=1)"
            )));
        }
    }
    if params.reject_tokens {
        if let Some(proto) = script::tx_token_protocol(tx) {
            return Err(CoreError::InvalidTransaction(format!(
                "token: tx {txid} carries a {proto} marker (rejecttokens=1)"
            )));
        }
    }
    Ok(())
}

/// Transaction mempool: holds unconfirmed transactions.
pub struct Mempool {
    /// All transactions indexed by txid.
    txs: HashMap<Txid, MempoolEntry>,
    /// Track which outpoints are spent by mempool transactions.
    spent_outpoints: bitcoinpr_storage::FastHashMap<OutPoint, Txid>,
    /// Memory budget in bytes, measured against [`Mempool::memory_usage`]
    /// (Core's `-maxmempool` semantics). When a new tx would exceed it, the
    /// lowest-feerate entries (with their descendants) are evicted to make
    /// room — or the new tx is rejected if its feerate doesn't beat theirs.
    max_memory_bytes: usize,
    /// Running total of serialized tx sizes, maintained incrementally on
    /// insert/remove so `memory_usage()` is O(1) instead of iterating.
    total_tx_bytes: usize,
    /// Dynamic acceptance fee floor (sat/vB) raised by budget evictions
    /// (Core's rolling minimum fee). Decays by half every
    /// [`EVICTION_FLOOR_HALFLIFE_SECS`]; the effective floor never drops
    /// below [`MIN_RELAY_FEE_RATE`].
    eviction_fee_floor: f64,
    /// Unix time the eviction floor was last raised (decay reference).
    eviction_floor_time: u64,
}

impl Mempool {
    pub fn new(max_memory_bytes: usize) -> Self {
        Mempool {
            txs: HashMap::new(),
            spent_outpoints: bitcoinpr_storage::FastHashMap::default(),
            max_memory_bytes,
            total_tx_bytes: 0,
            eviction_fee_floor: 0.0,
            eviction_floor_time: 0,
        }
    }

    /// Estimated memory cost of one entry in `memory_usage()` terms: hash-map
    /// bookkeeping for the entry itself, one `spent_outpoints` slot per input,
    /// and the serialized transaction bytes.
    fn entry_cost(n_inputs: usize, serialized_size: usize) -> usize {
        std::mem::size_of::<Txid>()
            + std::mem::size_of::<MempoolEntry>()
            + HASHMAP_ENTRY_OVERHEAD
            + n_inputs * (std::mem::size_of::<(OutPoint, Txid)>() + HASHMAP_ENTRY_OVERHEAD)
            + serialized_size
    }

    /// Current acceptance fee floor in sat/vB: the static min-relay rate, or
    /// the decaying eviction floor if higher (Core's `CTxMemPool::GetMinFee`).
    fn fee_floor(&self, now: u64) -> f64 {
        if self.eviction_fee_floor <= MIN_RELAY_FEE_RATE {
            return MIN_RELAY_FEE_RATE;
        }
        let elapsed = now.saturating_sub(self.eviction_floor_time);
        let halvings = (elapsed / EVICTION_FLOOR_HALFLIFE_SECS).min(63) as i32;
        (self.eviction_fee_floor / f64::powi(2.0, halvings)).max(MIN_RELAY_FEE_RATE)
    }

    /// Add a transaction to the mempool after validation.
    ///
    /// When `sig_cache` is [`Some`], script checks run in parallel for multi-input txs and
    /// successful verifications are recorded in the cache (same cache as block validation).
    ///
    /// `chain` supplies the tip height and tip MTP against which nLockTime
    /// finality (BIP 113) and BIP 68 sequence locks are enforced: the tx must
    /// be valid in the next block (height `tip_height + 1`, time reference =
    /// tip MTP), or it would end up in a block template that our own
    /// `connect_block` rejects.
    pub fn add_transaction(
        &mut self,
        tx: Transaction,
        utxo_set: &UtxoSet,
        flags: ScriptFlags,
        params: &ConsensusParams,
        sig_cache: Option<&SigCache>,
        chain: &MempoolChainContext,
    ) -> CoreResult<Txid> {
        let txid = tx.compute_txid();

        // Check if already in mempool
        if self.txs.contains_key(&txid) {
            return Ok(txid);
        }

        // Validate: no coinbase
        if tx.is_coinbase() {
            return Err(CoreError::InvalidTransaction(
                "coinbase transactions cannot be in mempool".into(),
            ));
        }

        // Context-free sanity checks (empty vin/vout, value range, duplicate
        // inputs, null prevouts) — Bitcoin Core's CheckTransaction.
        crate::validation::check_transaction(&tx)?;

        // Relay policy: datacarrier / datacarriersize, bare multisig, dust,
        // parasite (inscription) and token filters.
        check_relay_policy(&tx, txid, params)?;

        // nLockTime finality (BIP 65/113): the tx must be includable in the
        // *next* block — evaluated at height tip+1 with the tip's MTP, like
        // Core's CheckFinalTxAtTip. connect_block enforces the same rule, so
        // admitting a non-final tx here would feed templates our own block
        // validation rejects (burning the miner's work).
        let next_height = chain.tip_height + 1;

        // BIP-110 rule 1: while RDTS is ACTIVE for the next block, new output
        // scriptPubKeys over 34 bytes are invalid (OP_RETURN may reach 83).
        // connect_block enforces the same rule, so rejecting here keeps our
        // templates valid under our own block validation.
        if chain.bip110.enforcing() {
            script::check_bip110_output_scripts(&tx)?;
        }

        if !validation::is_final_tx(&tx, next_height, chain.tip_mtp) {
            return Err(CoreError::InvalidTransaction(format!(
                "non-final: tx {} is not final at next height {} (mtp {})",
                txid, next_height, chain.tip_mtp
            )));
        }

        // Validate inputs and calculate fee, checking for RBF conflicts.
        // Collect prevouts here too (one lookup per input) — needed later for
        // Taproot sighash. A second pass would re-read the UTXO set and could
        // race a concurrent block connect that spends these outputs.
        let mut input_sum: u64 = 0;
        let mut conflicts: Vec<Txid> = Vec::new();
        let mut all_prevouts: Vec<bitcoin::TxOut> = Vec::with_capacity(tx.input.len());
        // Confirmation height of each input's prevout, for BIP 68. Inputs that
        // spend an unconfirmed (in-mempool) parent count as confirming in the
        // next block — Core uses tip-height + 1 for mempool inputs.
        let mut input_heights: Vec<u32> = Vec::with_capacity(tx.input.len());

        for input in &tx.input {
            let outpoint = input.previous_output;

            // Check for double-spend against mempool
            if let Some(existing_txid) = self.spent_outpoints.get(&outpoint) {
                let existing_txid = *existing_txid;
                // BIP 125: if the conflicting tx signals RBF, allow replacement
                if let Some(existing_entry) = self.txs.get(&existing_txid) {
                    if signals_rbf(&existing_entry.tx) {
                        if !conflicts.contains(&existing_txid) {
                            conflicts.push(existing_txid);
                        }
                    } else {
                        return Err(CoreError::DoubleSpend(format!(
                            "outpoint {}:{} already spent by non-RBF tx {}",
                            outpoint.txid, outpoint.vout, existing_txid
                        )));
                    }
                } else {
                    return Err(CoreError::DoubleSpend(format!(
                        "outpoint {}:{} already spent by mempool tx {}",
                        outpoint.txid, outpoint.vout, existing_txid
                    )));
                }
            }

            // Look up the prevout: chain UTXO set first, then fall back to an
            // output of another unconfirmed tx already in the mempool (chained
            // spends — the P2P handler in main.rs pre-screens with the same
            // two-tier rule).
            let (amount, script_pubkey, prev_height) = match utxo_set.get(&outpoint)? {
                Some(utxo) => (utxo.amount, utxo.script_pubkey, utxo.height),
                None => {
                    let parent_out = self
                        .txs
                        .get(&outpoint.txid)
                        .and_then(|parent| parent.tx.output.get(outpoint.vout as usize))
                        .ok_or_else(|| {
                            CoreError::MissingUtxo(format!("{}:{}", outpoint.txid, outpoint.vout))
                        })?;
                    // Unconfirmed parent: for BIP 68 the prevout counts as
                    // confirming in the next block (Core's tip-height + 1).
                    (
                        parent_out.value.to_sat(),
                        parent_out.script_pubkey.to_bytes(),
                        next_height,
                    )
                }
            };

            input_sum += amount;
            input_heights.push(prev_height);
            all_prevouts.push(bitcoin::TxOut {
                value: bitcoin::Amount::from_sat(amount),
                script_pubkey: bitcoin::ScriptBuf::from_bytes(script_pubkey),
            });
        }

        // BIP 68 relative lock-times, evaluated as if the tx were mined in the
        // next block (Core's CheckSequenceLocksAtTip) — mirrors connect_block's
        // enforcement. The per-input MTP lookups only happen for genuine
        // time-based relative locks (rare); final/RBF sequences are skipped by
        // validate_sequence_locks itself.
        let mut input_times: Vec<u32> = vec![0u32; tx.input.len()];
        if next_height >= params.csv_height {
            let needs_time_mtp = tx.version.0 >= 2
                && tx.input.iter().any(|inp| {
                    let s = inp.sequence.0;
                    s & (1 << 31) == 0 && s & (1 << 22) != 0
                });
            if needs_time_mtp {
                input_times = input_heights
                    .iter()
                    .map(|&coin_height| {
                        if coin_height > chain.tip_height {
                            // Unconfirmed parent: it would confirm at tip+1, so
                            // its BIP 68 time reference is the tip's MTP.
                            Ok(chain.tip_mtp)
                        } else {
                            // BIP 68 time reference is the MTP of the block
                            // BEFORE the prevout's confirmation block. A failed
                            // lookup must reject, not default to 0: an MTP of 0
                            // makes the required time tiny, treating an
                            // unsatisfied time lock as satisfied (fail-open).
                            let h = coin_height.saturating_sub(1);
                            chain
                                .header_index
                                .get_hash_at_height(h)
                                .ok()
                                .flatten()
                                .and_then(|hash| {
                                    validation::get_median_time_past(chain.header_index, &hash)
                                })
                                .ok_or_else(|| {
                                    CoreError::InvalidTransaction(format!(
                                        "bip68-time-reference-unavailable: cannot compute MTP at height {h} for tx {txid} input prevout confirmed at height {coin_height}"
                                    ))
                                })
                        }
                    })
                    .collect::<CoreResult<Vec<u32>>>()?;
            }
            validation::validate_sequence_locks(
                &tx,
                &input_heights,
                &input_times,
                next_height,
                chain.tip_mtp,
            )
            .map_err(|e| match e {
                CoreError::InvalidTransaction(msg) => {
                    CoreError::InvalidTransaction(format!("non-BIP68-final: {msg}"))
                }
                other => other,
            })?;
        }
        // Lock point (Core's LockPoints): stored on the entry so block-template
        // assembly can re-check BIP 68 finality at any later tip. Because the
        // checks above passed at tip+1, these lock points stay satisfied as the
        // chain advances (heights and MTP are monotonic).
        let (lock_height, lock_time) =
            validation::sequence_lock_points(&tx, &input_heights, &input_times);

        // Full eviction set: the conflicting txs plus all their in-mempool
        // descendants, which would be left spending non-existent outputs once
        // their ancestor is evicted.
        let mut evict: Vec<Txid> = Vec::new();
        let mut evict_set: HashSet<Txid> = HashSet::new();
        let mut queue = conflicts.clone();
        while let Some(id) = queue.pop() {
            if !evict_set.insert(id) {
                continue;
            }
            evict.push(id);
            if let Some(entry) = self.txs.get(&id) {
                for vout in 0..entry.tx.output.len() {
                    if let Some(&child) = self.spent_outpoints.get(&OutPoint::new(id, vout as u32))
                    {
                        queue.push(child);
                    }
                }
            }
        }

        // A replacement must not spend an output of a tx it evicts: that
        // prevout would vanish with the eviction, leaving this tx permanently
        // unminable in the pool (Core rejects this the same way).
        if !evict_set.is_empty()
            && tx
                .input
                .iter()
                .any(|i| evict_set.contains(&i.previous_output.txid))
        {
            return Err(CoreError::InvalidTransaction(format!(
                "bad-txns-spends-conflicting-tx: tx {txid} spends an output of a tx it replaces"
            )));
        }

        // Limit the number of replacements
        if evict.len() > MAX_RBF_REPLACEMENTS {
            return Err(CoreError::InvalidTransaction(format!(
                "RBF: too many conflicts ({}), max {}",
                evict.len(),
                MAX_RBF_REPLACEMENTS
            )));
        }

        let output_sum: u64 = tx.output.iter().map(|o| o.value.to_sat()).sum();
        if output_sum > input_sum {
            return Err(CoreError::InvalidTransaction(format!(
                "outputs ({output_sum}) exceed inputs ({input_sum})"
            )));
        }

        let fee = input_sum - output_sum;
        let weight = tx.weight().to_wu();
        let vsize = weight.div_ceil(4); // virtual size
        let size = bitcoin::consensus::encode::serialize(&tx).len();
        let fee_rate = fee as f64 / vsize as f64;

        // unwrap_or_default: don't panic in the accept path if the system
        // clock is before the unix epoch; entry.time = 0 is harmless.
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Policy fee floors (mempool only, never block validation). Static
        // min relay rate first, then the dynamic floor left behind by budget
        // evictions — txs below it are rejected rather than admitted only to
        // be trimmed straight back out.
        if fee_rate < MIN_RELAY_FEE_RATE {
            return Err(CoreError::InvalidTransaction(format!(
                "min relay fee not met: {fee_rate:.2} sat/vB < {MIN_RELAY_FEE_RATE:.2} sat/vB"
            )));
        }
        let floor = self.fee_floor(now);
        if fee_rate < floor {
            return Err(CoreError::InvalidTransaction(format!(
                "mempool min fee not met: {fee_rate:.2} sat/vB < {floor:.2} sat/vB"
            )));
        }

        // BIP 125: replacement must pay higher absolute fee and higher fee
        // rate than everything it evicts (conflicts and their descendants).
        if !evict.is_empty() {
            let total_conflicting_fee: u64 = evict
                .iter()
                .filter_map(|cid| self.txs.get(cid))
                .map(|e| e.fee)
                .sum();
            let max_conflicting_fee_rate: f64 = evict
                .iter()
                .filter_map(|cid| self.txs.get(cid))
                .map(|e| e.fee_rate)
                .fold(0.0f64, f64::max);

            if fee <= total_conflicting_fee {
                return Err(CoreError::InvalidTransaction(format!(
                    "RBF: replacement fee {fee} must exceed conflicting fees {total_conflicting_fee}"
                )));
            }
            if fee_rate <= max_conflicting_fee_rate {
                return Err(CoreError::InvalidTransaction(format!(
                    "RBF: replacement fee rate {fee_rate:.1} must exceed conflicting rate {max_conflicting_fee_rate:.1}"
                )));
            }
        }

        // Check ancestor limits BEFORE mutating the pool. Doing this after the
        // RBF eviction below would drop the conflicting (paid) transactions and
        // then reject the replacement, leaving the mempool worse off for nothing.
        // The set is also reused by the budget eviction planner below.
        let ancestors = self.in_mempool_ancestors(&tx);
        if ancestors.len() > MAX_ANCESTORS {
            return Err(CoreError::InvalidTransaction(format!(
                "too many ancestors: {} > {}",
                ancestors.len(),
                MAX_ANCESTORS
            )));
        }

        // Descendant limit, mirror image of the ancestor check: admitting this
        // tx gives every one of its in-mempool ancestors one more descendant.
        // (To-be-replaced RBF conflicts still count toward an ancestor's tally
        // here — a rare false rejection accepted for simplicity, like Core
        // before the replacement carve-out.)
        for ancestor in &ancestors {
            let descendants = self.count_descendants(ancestor);
            if descendants + 1 > MAX_DESCENDANTS {
                return Err(CoreError::InvalidTransaction(format!(
                    "too many descendants: ancestor {} would have {} > {}",
                    ancestor,
                    descendants + 1,
                    MAX_DESCENDANTS
                )));
            }
        }

        // Script verification (parallel when multiple inputs — mirrors ChainState validation).
        // The sig cache is keyed by wtxid (commits to witness) + flags, so verifying
        // here under mempool flags never short-circuits a later block-validation check.
        let wtxid = tx.compute_wtxid();
        let verify_one = |vin: usize| -> CoreResult<()> {
            // BIP-110 rules 2-7 apply only while the deployment is ACTIVE for the
            // next block AND the spent UTXO was created at/after activation
            // (grandfathering by prevout height). Mirrors connect_block's per-input
            // flag so the sig cache stays consistent between the two paths.
            let mut flags = flags;
            flags.verify_bip110 = chain.bip110.enforcing()
                && chain
                    .bip110
                    .activation_height
                    .is_some_and(|a| input_heights[vin] >= a);
            if let Some(cache) = sig_cache {
                if cache.contains(&wtxid, vin, flags) {
                    return Ok(());
                }
            }
            script::verify_script(&tx, vin, &all_prevouts, flags)?;
            if let Some(cache) = sig_cache {
                cache.insert(&wtxid, vin, flags);
            }
            Ok(())
        };

        if tx.input.len() <= 1 {
            for vin in 0..tx.input.len() {
                verify_one(vin)?;
            }
        } else {
            let verify_result: CoreResult<()> =
                (0..tx.input.len()).into_par_iter().try_for_each(verify_one);
            verify_result?;
        }

        // --- Memory budget (Core's TrimToSize, planned before any mutation
        // so a rejection here leaves the pool untouched). The RBF conflicts
        // already count as freed; if the new tx still doesn't fit, repeatedly
        // pick the lowest-feerate entry (linear scan — fine at this node's
        // scale) and slate it plus its descendants for eviction. Core rules:
        //   * the incoming tx must pay a strictly higher feerate than every
        //     eviction victim, or it is rejected — jamming the pool with
        //     low-fee txs then costs real fees;
        //   * never evict an ancestor of the incoming tx (it would orphan
        //     the very tx we're admitting) — reject instead.
        let new_entry_cost = Self::entry_cost(tx.input.len(), size);
        let mut planned_freed: usize = evict
            .iter()
            .filter_map(|id| self.txs.get(id))
            .map(|e| Self::entry_cost(e.tx.input.len(), e.size))
            .sum();
        // Everything slated for removal: RBF conflicts (already closed under
        // descendants) plus budget victims found below.
        let mut victim_set: HashSet<Txid> = evict_set.clone();
        let mut trimmed: Vec<Txid> = Vec::new();
        let mut new_floor = self.eviction_fee_floor;
        while self.memory_usage() + new_entry_cost > self.max_memory_bytes + planned_freed {
            let victim = self
                .txs
                .values()
                .filter(|e| !victim_set.contains(&e.txid))
                .min_by(|a, b| a.fee_rate.total_cmp(&b.fee_rate));
            let victim = match victim {
                Some(v) => v,
                // Nothing left to evict: the tx alone exceeds the budget.
                None => {
                    return Err(CoreError::InvalidTransaction(format!(
                        "mempool full: tx {txid} ({size} bytes) exceeds the mempool budget"
                    )));
                }
            };
            if fee_rate <= victim.fee_rate {
                return Err(CoreError::InvalidTransaction(format!(
                    "mempool full: fee rate {:.2} sat/vB does not exceed the cheapest \
                     mempool entry ({:.2} sat/vB)",
                    fee_rate, victim.fee_rate
                )));
            }
            // If the victim is an ancestor of the incoming tx, evicting it
            // (with descendants) would also remove the incoming tx's parents
            // and orphan it. Checking the root suffices: any descendant of
            // the victim that is an ancestor of the incoming tx would make
            // the victim itself an ancestor too (ancestry is transitive).
            if ancestors.contains(&victim.txid) {
                return Err(CoreError::InvalidTransaction(format!(
                    "mempool full: making room would evict an in-mempool ancestor \
                     of tx {txid}"
                )));
            }
            new_floor = new_floor.max(victim.fee_rate + INCREMENTAL_RELAY_FEE_RATE);
            // Slate the victim and all its descendants (they'd be orphaned).
            let mut queue = vec![victim.txid];
            while let Some(id) = queue.pop() {
                if !victim_set.insert(id) {
                    continue;
                }
                trimmed.push(id);
                if let Some(e) = self.txs.get(&id) {
                    planned_freed += Self::entry_cost(e.tx.input.len(), e.size);
                    for vout in 0..e.tx.output.len() {
                        if let Some(&child) =
                            self.spent_outpoints.get(&OutPoint::new(id, vout as u32))
                        {
                            queue.push(child);
                        }
                    }
                }
            }
        }

        // All checks passed — now mutate. Remove conflicting transactions and
        // their descendants (RBF). `evict` is already closed under descendants,
        // so plain removal suffices.
        for conflict_txid in &evict {
            if self.remove_entry(conflict_txid).is_some() {
                debug!(txid = %conflict_txid, "Evicted conflicting tx (RBF)");
            }
        }

        // Then the budget victims, raising the dynamic fee floor so follow-up
        // low-fee txs get rejected up front instead of churning the pool.
        if !trimmed.is_empty() {
            for victim_txid in &trimmed {
                if self.remove_entry(victim_txid).is_some() {
                    debug!(txid = %victim_txid, "Evicted tx for mempool size limit");
                }
            }
            self.eviction_fee_floor = new_floor;
            self.eviction_floor_time = now;
            info!(
                evicted = trimmed.len(),
                floor = format!("{:.2}", new_floor),
                "Mempool over budget: evicted lowest-feerate txs"
            );
        }

        // Record spent outpoints BEFORE moving `tx` into the entry, so the
        // transaction is not deep-copied just to keep this loop alive (M8,
        // 2026-07-02 review).
        for input in &tx.input {
            self.spent_outpoints.insert(input.previous_output, txid);
        }

        // Add to mempool
        let entry = MempoolEntry {
            tx,
            txid,
            fee,
            size,
            weight,
            fee_rate,
            time: now,
            lock_height,
            lock_time,
        };

        self.total_tx_bytes += size;
        self.txs.insert(txid, entry);
        debug!(txid = %txid, fee, fee_rate = format!("{:.1}", fee_rate), "Added tx to mempool");

        Ok(txid)
    }

    /// Remove a single entry, clearing its spent-outpoint records and the
    /// running byte total. All removal paths funnel through here so the
    /// incremental memory accounting can never drift.
    fn remove_entry(&mut self, txid: &Txid) -> Option<MempoolEntry> {
        let entry = self.txs.remove(txid)?;
        for input in &entry.tx.input {
            self.spent_outpoints.remove(&input.previous_output);
        }
        self.total_tx_bytes = self.total_tx_bytes.saturating_sub(entry.size);
        Some(entry)
    }

    /// Remove a transaction from the mempool.
    pub fn remove_transaction(&mut self, txid: &Txid) {
        self.remove_entry(txid);
    }

    /// Remove a transaction and all of its in-mempool descendants.
    ///
    /// Used when a tx is evicted (block conflict, expiry) rather than
    /// confirmed: any child spending its outputs would otherwise be left in
    /// the pool with a prevout that no longer exists anywhere, and could end
    /// up in a block template that our own validation rejects.
    pub fn remove_with_descendants(&mut self, txid: &Txid) -> usize {
        let mut removed = 0;
        let mut queue = vec![*txid];
        while let Some(current) = queue.pop() {
            if let Some(entry) = self.remove_entry(&current) {
                // Queue any children spending this tx's outputs.
                for vout in 0..entry.tx.output.len() {
                    if let Some(&child) = self
                        .spent_outpoints
                        .get(&OutPoint::new(current, vout as u32))
                    {
                        queue.push(child);
                    }
                }
                removed += 1;
            }
        }
        removed
    }

    /// Remove all transactions that are confirmed in a block.
    ///
    /// `txids` are the block's precomputed txids (`txids[i]` for
    /// `block.txdata[i]`), as returned by `ChainState::connect_block` — the
    /// connect path already paid for them, so don't recompute here.
    pub fn remove_for_block(&mut self, block: &bitcoin::Block, txids: &[Txid]) {
        // During IBD the mempool is empty for every connected block; skip the
        // per-tx removal/conflict scan entirely (Core #32827 analogue).
        if self.txs.is_empty() && self.spent_outpoints.is_empty() {
            return;
        }
        debug_assert_eq!(block.txdata.len(), txids.len());
        let mut removed = 0;
        for (tx, &txid) in block.txdata.iter().zip(txids) {
            if self.remove_entry(&txid).is_some() {
                removed += 1;
            }

            // Also remove any mempool txs that conflict (double-spend) with block txs.
            // Use remove_transaction so ALL of the conflicting tx's outpoints are
            // cleared — removing only the colliding outpoint here would leave the
            // conflicting tx's other inputs dangling in spent_outpoints, pointing
            // at a tx that no longer exists, which causes spurious double-spend
            // rejections later.
            for input in &tx.input {
                if let Some(&conflicting_txid) = self.spent_outpoints.get(&input.previous_output) {
                    if conflicting_txid != txid {
                        // Evict descendants too: their prevouts vanish with
                        // the conflicting ancestor.
                        removed += self.remove_with_descendants(&conflicting_txid);
                    }
                }
            }
        }

        if removed > 0 {
            info!(removed, remaining = self.txs.len(), "Removed txs for block");
        }
    }

    /// Get a transaction from the mempool.
    pub fn get(&self, txid: &Txid) -> Option<&MempoolEntry> {
        self.txs.get(txid)
    }

    /// Get all transaction IDs in the mempool.
    pub fn all_txids(&self) -> Vec<Txid> {
        self.txs.keys().copied().collect()
    }

    /// Iterate over all mempool entries.
    pub fn entries(&self) -> impl Iterator<Item = &MempoolEntry> {
        self.txs.values()
    }

    /// Get all transactions in the mempool.
    pub fn all_transactions(&self) -> Vec<&Transaction> {
        self.txs.values().map(|e| &e.tx).collect()
    }

    /// Select transactions for a block template at `height`, whose BIP 113
    /// time reference (the previous block's median-time-past) is `mtp`, up to
    /// `max_weight` total weight and `max_count` transactions.
    ///
    /// Transactions that are not final at that height/MTP are skipped — they
    /// stay in the pool and may become final later. Parents always precede
    /// children in the returned order (required for intra-block spends), and a
    /// child whose in-mempool parent didn't make the template is skipped.
    pub fn select_for_block(
        &self,
        height: u32,
        mtp: u32,
        max_weight: u64,
        max_count: usize,
    ) -> Vec<&MempoolEntry> {
        let mut selected: Vec<&MempoolEntry> = Vec::new();
        let mut selected_ids: HashSet<Txid> = HashSet::new();
        let mut total_weight: u64 = 0;

        let mut candidates: Vec<&MempoolEntry> = self
            .txs
            .values()
            .filter(|e| e.final_for_block(height, mtp))
            .collect();

        // H2 (2026-07-02 review): greedy admission by descending feerate, so
        // that when the pool exceeds the block budget high-paying transactions
        // win. Ties broken by arrival time (older first) to keep the order
        // deterministic. This is plain per-tx feerate — no ancestor-package
        // scoring — so child-pays-for-parent is NOT supported: a high-fee
        // child cannot pull in its low-fee parent (the parent is considered
        // on its own feerate alone, and the child is skipped if the parent
        // misses the template).
        candidates.sort_by(|a, b| {
            b.fee_rate
                .total_cmp(&a.fee_rate)
                .then_with(|| a.time.cmp(&b.time))
        });

        // Multi-pass: each pass admits txs whose in-mempool parents were
        // selected in an earlier pass, so chains come out in spendable order.
        // Bounded by the ancestor limit, so this terminates quickly.
        loop {
            let before = selected.len();
            candidates.retain(|entry| {
                if selected.len() >= max_count || total_weight + entry.weight > max_weight {
                    // Over budget — out of the running entirely.
                    return false;
                }
                let parents_ready = entry.tx.input.iter().all(|i| {
                    let parent = i.previous_output.txid;
                    !self.txs.contains_key(&parent) || selected_ids.contains(&parent)
                });
                if parents_ready {
                    total_weight += entry.weight;
                    selected_ids.insert(entry.txid);
                    selected.push(entry);
                    false
                } else {
                    true // parent not selected yet — retry next pass
                }
            });
            if selected.len() == before || candidates.is_empty() {
                break;
            }
        }
        selected
    }

    /// Number of transactions in the mempool.
    pub fn size(&self) -> usize {
        self.txs.len()
    }

    /// Total size in bytes of all mempool transactions (maintained
    /// incrementally on insert/remove).
    pub fn total_bytes(&self) -> usize {
        self.total_tx_bytes
    }

    /// Total fees of all mempool transactions.
    pub fn total_fees(&self) -> u64 {
        self.txs.values().map(|e| e.fee).sum()
    }

    /// Estimated memory usage of the mempool data structures (bytes).
    ///
    /// Approximation in the spirit of Bitcoin Core's `DynamicMemoryUsage`:
    /// per entry we count the inline key+value sizes, a fixed constant for
    /// the hash map's per-entry bookkeeping, and the serialized transaction
    /// size as a proxy for the tx's heap allocations (input/output vectors,
    /// scripts, witnesses). Deterministic for a given mempool content, O(1)
    /// (the byte total is maintained incrementally), and the quantity the
    /// `max_memory_bytes` budget is enforced against.
    pub fn memory_usage(&self) -> usize {
        let txs_usage = self.txs.len()
            * (std::mem::size_of::<Txid>()
                + std::mem::size_of::<MempoolEntry>()
                + HASHMAP_ENTRY_OVERHEAD);
        let spent_usage = self.spent_outpoints.len()
            * (std::mem::size_of::<(OutPoint, Txid)>() + HASHMAP_ENTRY_OVERHEAD);
        txs_usage + spent_usage + self.total_tx_bytes
    }

    /// Check if a transaction is in the mempool.
    pub fn contains(&self, txid: &Txid) -> bool {
        self.txs.contains_key(txid)
    }

    /// Collect every in-mempool ancestor of a (not yet admitted) transaction:
    /// its in-mempool parents, their parents, and so on. The set size is the
    /// ancestor count enforced against [`MAX_ANCESTORS`].
    fn in_mempool_ancestors(&self, tx: &Transaction) -> HashSet<Txid> {
        let mut visited: HashSet<Txid> = HashSet::new();
        let mut ancestors: HashSet<Txid> = HashSet::new();
        let mut queue: Vec<Txid> = tx.input.iter().map(|i| i.previous_output.txid).collect();

        while let Some(parent_txid) = queue.pop() {
            if !visited.insert(parent_txid) {
                continue;
            }
            if let Some(parent) = self.txs.get(&parent_txid) {
                ancestors.insert(parent_txid);
                for input in &parent.tx.input {
                    queue.push(input.previous_output.txid);
                }
            }
        }
        ancestors
    }

    /// Count descendants of an in-mempool transaction (children, grand-
    /// children, ...), excluding the transaction itself. Walks the
    /// `spent_outpoints` index — one lookup per output — rather than scanning
    /// the whole pool.
    fn count_descendants(&self, txid: &Txid) -> usize {
        let mut visited: HashSet<Txid> = HashSet::new();
        visited.insert(*txid);
        let mut count = 0;
        let mut queue = vec![*txid];

        while let Some(current) = queue.pop() {
            if let Some(entry) = self.txs.get(&current) {
                for vout in 0..entry.tx.output.len() {
                    if let Some(&child) = self
                        .spent_outpoints
                        .get(&OutPoint::new(current, vout as u32))
                    {
                        if visited.insert(child) {
                            count += 1;
                            queue.push(child);
                        }
                    }
                }
            }
        }
        count
    }

    /// Remove expired transactions from the mempool.
    pub fn expire_old_transactions(&mut self) {
        // unwrap_or_default: a pre-1970 clock yields now=0; with saturating_sub
        // below nothing expires (fail-safe) instead of panicking.
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let expired: Vec<Txid> = self
            .txs
            .iter()
            // saturating_sub: if the wall clock steps backwards past an entry's
            // insertion time, `now - entry.time` would underflow and expire
            // everything; saturate to 0 (not expired) instead.
            .filter(|(_, entry)| now.saturating_sub(entry.time) > DEFAULT_MEMPOOL_EXPIRY)
            .map(|(txid, _)| *txid)
            .collect();

        let mut count = 0;
        for txid in expired {
            // Children of an expired parent become unminable — drop them too.
            count += self.remove_with_descendants(&txid);
        }
        if count > 0 {
            info!(count, "Expired old mempool transactions");
        }
    }

    /// Serialize the mempool to bytes for persistence.
    pub fn save_to_bytes(&self) -> Vec<u8> {
        let txs: Vec<Vec<u8>> = self
            .txs
            .values()
            .map(|entry| bitcoin::consensus::encode::serialize(&entry.tx))
            .collect();

        let mut buf = Vec::new();
        buf.extend_from_slice(&(txs.len() as u32).to_le_bytes());
        for tx_bytes in &txs {
            buf.extend_from_slice(&(tx_bytes.len() as u32).to_le_bytes());
            buf.extend_from_slice(tx_bytes);
        }
        buf
    }

    /// Parse the length-prefixed persisted-mempool byte format into a list of
    /// transactions, skipping any that fail to deserialize. Bounds are checked
    /// at every step so truncated/garbage input yields a (possibly short) list
    /// rather than panicking. Exposed `#[doc(hidden)]` for fuzzing the parser.
    #[doc(hidden)]
    pub fn parse_persisted_txs(data: &[u8]) -> Vec<Transaction> {
        if data.len() < 4 {
            return Vec::new();
        }
        let count =
            u32::from_le_bytes(data[0..4].try_into().expect("length checked above")) as usize;
        let mut offset = 4;
        // `count` is attacker-controlled, so cap the pre-allocation.
        let mut pending: Vec<Transaction> = Vec::with_capacity(count.min(1024));
        for _ in 0..count {
            if offset + 4 > data.len() {
                break;
            }
            let tx_len = u32::from_le_bytes(
                data[offset..offset + 4]
                    .try_into()
                    .expect("length checked above"),
            ) as usize;
            offset += 4;
            if offset + tx_len > data.len() {
                break;
            }
            if let Ok(tx) = bitcoin::consensus::encode::deserialize::<Transaction>(
                &data[offset..offset + tx_len],
            ) {
                pending.push(tx);
            }
            offset += tx_len;
        }
        pending
    }

    /// Load transactions from persisted bytes, re-validating each.
    ///
    /// `chain` carries the tip height/MTP for the finality and sequence-lock
    /// re-checks (see [`Mempool::add_transaction`]). Every tx goes back
    /// through full acceptance, so entries persisted under older (or no)
    /// policy rules — below min-relay, dust-creating, over budget — are
    /// simply filtered out; the on-disk format needs no versioning for
    /// policy changes.
    pub fn load_from_bytes(
        &mut self,
        data: &[u8],
        utxo_set: &UtxoSet,
        flags: ScriptFlags,
        params: &ConsensusParams,
        chain: &MempoolChainContext,
    ) -> usize {
        let mut loaded = 0;

        // Parse everything first: persistence order is arbitrary, so a child
        // may be serialized before its in-mempool parent. Retry rejected txs
        // until a full pass makes no progress.
        let mut pending = Self::parse_persisted_txs(data);
        let total = pending.len();

        loop {
            let before = loaded;
            pending.retain(|tx| {
                if self
                    .add_transaction(tx.clone(), utxo_set, flags, params, None, chain)
                    .is_ok()
                {
                    loaded += 1;
                    false
                } else {
                    true // parent may not be loaded yet — retry next pass
                }
            });
            if loaded == before || pending.is_empty() {
                break;
            }
        }
        info!(loaded, total, "Loaded mempool from disk");
        loaded
    }
}

/// Bucket boundaries for fee estimation (sat/vB).
/// Each bucket covers a range: [boundary[i], boundary[i+1])
const FEE_BUCKETS: &[f64] = &[
    1.0, 2.0, 3.0, 5.0, 7.0, 10.0, 15.0, 20.0, 30.0, 50.0, 75.0, 100.0, 150.0, 200.0, 300.0, 500.0,
    1000.0, 2000.0, 5000.0, 10000.0,
];

/// A fee rate bucket for estimation.
#[derive(Debug, Clone)]
struct FeeBucket {
    /// Fee rate lower bound (sat/vB).
    fee_rate: f64,
    /// Number of transactions confirmed within target blocks at this fee rate.
    confirmed_count: u64,
    /// Total number of transactions observed at this fee rate.
    total_count: u64,
}

/// Bucket-based fee estimator.
/// Tracks which fee rates are sufficient for confirmation within N blocks.
pub struct FeeEstimator {
    buckets: Vec<FeeBucket>,
    /// Rolling count of blocks processed.
    blocks_processed: u32,
}

impl Default for FeeEstimator {
    fn default() -> Self {
        Self::new()
    }
}

impl FeeEstimator {
    pub fn new() -> Self {
        let buckets = FEE_BUCKETS
            .iter()
            .map(|&fee_rate| FeeBucket {
                fee_rate,
                confirmed_count: 0,
                total_count: 0,
            })
            .collect();
        FeeEstimator {
            buckets,
            blocks_processed: 0,
        }
    }

    /// Find the bucket index for a given fee rate.
    fn bucket_index(fee_rate: f64) -> usize {
        for (i, &boundary) in FEE_BUCKETS.iter().enumerate().rev() {
            if fee_rate >= boundary {
                return i;
            }
        }
        0
    }

    /// Record a transaction that entered the mempool.
    pub fn record_mempool_tx(&mut self, fee_rate: f64) {
        let idx = Self::bucket_index(fee_rate);
        if idx < self.buckets.len() {
            self.buckets[idx].total_count += 1;
        }
    }

    /// Record transactions that were confirmed in a block.
    /// Call this when a block is connected, passing the fee rates of confirmed txs.
    pub fn process_block(&mut self, confirmed_fee_rates: &[f64]) {
        self.blocks_processed += 1;
        for &fee_rate in confirmed_fee_rates {
            let idx = Self::bucket_index(fee_rate);
            if idx < self.buckets.len() {
                self.buckets[idx].confirmed_count += 1;
            }
        }
    }

    /// Estimate the fee rate (sat/vB) needed for confirmation within `target` blocks.
    /// Returns None if insufficient data.
    pub fn estimate_fee(&self, target: u32) -> Option<f64> {
        if self.blocks_processed < 2 {
            return None; // Not enough data
        }

        // Walk buckets from highest fee to lowest, accumulating the confirmation rate.
        // Find the lowest bucket where the confirmation rate exceeds the threshold.
        let adjusted_threshold = if target <= 2 {
            0.95
        } else if target <= 6 {
            0.85
        } else {
            0.60
        };

        let mut cumulative_confirmed = 0u64;
        let mut cumulative_total = 0u64;
        let mut best_fee = None;

        for bucket in self.buckets.iter().rev() {
            cumulative_confirmed += bucket.confirmed_count;
            cumulative_total += bucket.total_count;

            if cumulative_total >= 10 {
                // Need at least 10 samples
                let rate = cumulative_confirmed as f64 / cumulative_total as f64;
                if rate >= adjusted_threshold {
                    best_fee = Some(bucket.fee_rate);
                }
            }
        }

        best_fee
    }

    /// Build a fee rate histogram from the current mempool.
    /// Returns pairs of (fee_rate_sat_vb, cumulative_vsize).
    pub fn mempool_histogram(mempool: &Mempool) -> Vec<(f64, u64)> {
        let mut buckets: Vec<(f64, u64)> = FEE_BUCKETS.iter().map(|&rate| (rate, 0u64)).collect();

        for entry in mempool.txs.values() {
            let idx = Self::bucket_index(entry.fee_rate);
            if idx < buckets.len() {
                buckets[idx].1 += entry.weight / 4; // Convert weight to vsize
            }
        }

        // Return only non-empty buckets
        buckets
            .into_iter()
            .filter(|(_, vsize)| *vsize > 0)
            .collect()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use bitcoin::hashes::Hash;
    use bitcoin::transaction::Version;
    use bitcoin::{Amount, ScriptBuf, Sequence, TxIn, TxOut, Witness};
    use bitcoinpr_storage::UtxoEntry;

    /// Open temp-backed stores for acceptance tests.
    fn test_stores() -> (tempfile::TempDir, UtxoSet, HeaderIndex) {
        let dir = tempfile::tempdir().unwrap();
        let utxo_set = UtxoSet::open(&dir.path().join("utxo"), None).unwrap();
        let header_index = HeaderIndex::open(&dir.path().join("headers")).unwrap();
        (dir, utxo_set, header_index)
    }

    /// Insert an anyone-can-spend (OP_TRUE) UTXO confirmed at `height`.
    fn fund_utxo(utxo_set: &UtxoSet, txid_byte: u8, height: u32) -> OutPoint {
        let txid = Txid::from_byte_array([txid_byte; 32]);
        let outpoint = OutPoint::new(txid, 0);
        let entry = UtxoEntry {
            amount: 50_000,
            script_pubkey: vec![0x51], // OP_TRUE
            height,
            is_coinbase: false,
        };
        utxo_set.insert(&outpoint, &entry).unwrap();
        outpoint
    }

    /// Build a 1-in/1-out spend of `outpoint` paying to OP_TRUE.
    fn spend_tx(outpoint: OutPoint, sequence: u32, lock_time: u32, version: i32) -> Transaction {
        Transaction {
            version: Version(version),
            lock_time: bitcoin::absolute::LockTime::from_consensus(lock_time),
            input: vec![TxIn {
                previous_output: outpoint,
                script_sig: ScriptBuf::new(),
                sequence: Sequence(sequence),
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(40_000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            }],
        }
    }

    /// Sequence with the BIP 68 disable bit set (no relative lock), non-final
    /// so nLockTime applies.
    const SEQ_NO_BIP68: u32 = 0xfffffffd;

    #[test]
    fn test_locktime_future_height_rejected() {
        let (_dir, utxo_set, header_index) = test_stores();
        let params = ConsensusParams::regtest();
        let mut pool = Mempool::new(1 << 20);

        let outpoint = fund_utxo(&utxo_set, 1, 5);
        // nLockTime = 20, but the next block is height 11 — not final yet.
        let tx = spend_tx(outpoint, SEQ_NO_BIP68, 20, 2);

        let ctx = MempoolChainContext {
            tip_height: 10,
            tip_mtp: 1_700_000_000,
            header_index: &header_index,
            bip110: crate::bip110::Bip110Activation::INACTIVE,
        };
        let err = pool
            .add_transaction(tx, &utxo_set, ScriptFlags::all(), &params, None, &ctx)
            .unwrap_err();
        assert!(
            err.to_string().contains("non-final"),
            "expected non-final rejection, got: {err}"
        );
        assert_eq!(pool.size(), 0);
    }

    #[test]
    fn test_locktime_below_next_height_accepted() {
        let (_dir, utxo_set, header_index) = test_stores();
        let params = ConsensusParams::regtest();
        let mut pool = Mempool::new(1 << 20);

        let outpoint = fund_utxo(&utxo_set, 1, 5);
        // nLockTime = 10 < next height 11 — final.
        let tx = spend_tx(outpoint, SEQ_NO_BIP68, 10, 2);

        let ctx = MempoolChainContext {
            tip_height: 10,
            tip_mtp: 1_700_000_000,
            header_index: &header_index,
            bip110: crate::bip110::Bip110Activation::INACTIVE,
        };
        let txid = pool
            .add_transaction(tx, &utxo_set, ScriptFlags::all(), &params, None, &ctx)
            .expect("final tx should be accepted");
        assert!(pool.contains(&txid));
    }

    #[test]
    fn test_bip68_height_lock_unsatisfied_rejected() {
        let (_dir, utxo_set, header_index) = test_stores();
        let params = ConsensusParams::regtest();
        let mut pool = Mempool::new(1 << 20);

        // Prevout confirmed at height 5; sequence 10 ⇒ spendable at height 15+.
        let outpoint = fund_utxo(&utxo_set, 1, 5);
        let tx = spend_tx(outpoint, 10, 0, 2);

        // Next block is height 11 < 15 — lock not satisfied.
        let ctx = MempoolChainContext {
            tip_height: 10,
            tip_mtp: 1_700_000_000,
            header_index: &header_index,
            bip110: crate::bip110::Bip110Activation::INACTIVE,
        };
        let err = pool
            .add_transaction(tx, &utxo_set, ScriptFlags::all(), &params, None, &ctx)
            .unwrap_err();
        assert!(
            err.to_string().contains("non-BIP68-final"),
            "expected non-BIP68-final rejection, got: {err}"
        );
    }

    #[test]
    fn test_bip68_height_lock_satisfied_accepted() {
        let (_dir, utxo_set, header_index) = test_stores();
        let params = ConsensusParams::regtest();
        let mut pool = Mempool::new(1 << 20);

        // Prevout confirmed at height 5; sequence 10 ⇒ spendable at height 15+.
        let outpoint = fund_utxo(&utxo_set, 1, 5);
        let tx = spend_tx(outpoint, 10, 0, 2);

        // Next block is height 15 — lock satisfied.
        let ctx = MempoolChainContext {
            tip_height: 14,
            tip_mtp: 1_700_000_000,
            header_index: &header_index,
            bip110: crate::bip110::Bip110Activation::INACTIVE,
        };
        let txid = pool
            .add_transaction(tx, &utxo_set, ScriptFlags::all(), &params, None, &ctx)
            .expect("satisfied BIP 68 height lock should be accepted");

        // Lock point recorded for template-time re-checks.
        let entry = pool.get(&txid).unwrap();
        assert_eq!(entry.lock_height, 15);
        assert_eq!(entry.lock_time, 0);
    }

    #[test]
    fn test_bip68_time_lock() {
        let (_dir, utxo_set, header_index) = test_stores();
        let params = ConsensusParams::regtest();

        // Insert the regtest genesis header at height 0 so the prevout
        // (confirmed at height 1) has a time reference: MTP(height 0) =
        // genesis time.
        let genesis = params.genesis_block.clone();
        let genesis_time = genesis.header.time;
        header_index
            .insert_header(
                &genesis.block_hash(),
                &bitcoinpr_storage::StoredHeader {
                    header: genesis.header,
                    height: 0,
                    chain_work: [0u8; 32],
                },
            )
            .unwrap();

        let outpoint = fund_utxo(&utxo_set, 1, 1);
        // Time-based lock (bit 22): 2 * 512 = 1024 seconds past the prevout's MTP.
        let tx = spend_tx(outpoint, (1 << 22) | 2, 0, 2);

        // Tip MTP only 100 s past genesis — lock not satisfied.
        let mut pool = Mempool::new(1 << 20);
        let ctx = MempoolChainContext {
            tip_height: 10,
            tip_mtp: genesis_time + 100,
            header_index: &header_index,
            bip110: crate::bip110::Bip110Activation::INACTIVE,
        };
        let err = pool
            .add_transaction(
                tx.clone(),
                &utxo_set,
                ScriptFlags::all(),
                &params,
                None,
                &ctx,
            )
            .unwrap_err();
        assert!(
            err.to_string().contains("non-BIP68-final"),
            "expected non-BIP68-final rejection, got: {err}"
        );

        // Tip MTP 1024 s past genesis — lock satisfied.
        let ctx = MempoolChainContext {
            tip_height: 10,
            tip_mtp: genesis_time + 1024,
            header_index: &header_index,
            bip110: crate::bip110::Bip110Activation::INACTIVE,
        };
        let txid = pool
            .add_transaction(tx, &utxo_set, ScriptFlags::all(), &params, None, &ctx)
            .expect("satisfied BIP 68 time lock should be accepted");
        assert_eq!(pool.get(&txid).unwrap().lock_time, genesis_time + 1024);
    }

    #[test]
    fn test_chained_unconfirmed_parent() {
        let (_dir, utxo_set, header_index) = test_stores();
        let params = ConsensusParams::regtest();
        let mut pool = Mempool::new(1 << 20);
        let ctx = MempoolChainContext {
            tip_height: 10,
            tip_mtp: 1_700_000_000,
            header_index: &header_index,
            bip110: crate::bip110::Bip110Activation::INACTIVE,
        };

        // Parent spends a confirmed UTXO and creates two outputs.
        let outpoint = fund_utxo(&utxo_set, 1, 5);
        let mut parent = spend_tx(outpoint, SEQ_NO_BIP68, 0, 2);
        parent.output = vec![
            TxOut {
                value: Amount::from_sat(20_000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            },
            TxOut {
                value: Amount::from_sat(20_000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            },
        ];
        let parent_txid = pool
            .add_transaction(parent, &utxo_set, ScriptFlags::all(), &params, None, &ctx)
            .expect("parent should be accepted");

        // Child without a relative lock: accepted via the in-mempool prevout.
        let mut child = spend_tx(OutPoint::new(parent_txid, 0), SEQ_NO_BIP68, 0, 2);
        child.output[0].value = Amount::from_sat(15_000);
        pool.add_transaction(child, &utxo_set, ScriptFlags::all(), &params, None, &ctx)
            .expect("child of unconfirmed parent should be accepted");

        // Child with a 1-block BIP 68 lock on the unconfirmed parent: the
        // parent counts as confirming at tip+1, so the lock cannot be
        // satisfied in the next block — rejected.
        let mut locked_child = spend_tx(OutPoint::new(parent_txid, 1), 1, 0, 2);
        locked_child.output[0].value = Amount::from_sat(15_000);
        let err = pool
            .add_transaction(
                locked_child,
                &utxo_set,
                ScriptFlags::all(),
                &params,
                None,
                &ctx,
            )
            .unwrap_err();
        assert!(
            err.to_string().contains("non-BIP68-final"),
            "expected non-BIP68-final rejection, got: {err}"
        );
    }

    #[test]
    fn test_select_for_block_filters_and_orders() {
        let (_dir, utxo_set, header_index) = test_stores();
        let params = ConsensusParams::regtest();
        let mut pool = Mempool::new(1 << 20);
        let ctx = MempoolChainContext {
            tip_height: 10,
            tip_mtp: 1_700_000_000,
            header_index: &header_index,
            bip110: crate::bip110::Bip110Activation::INACTIVE,
        };

        // Chained parent → child (both final).
        let outpoint = fund_utxo(&utxo_set, 1, 5);
        let parent = spend_tx(outpoint, SEQ_NO_BIP68, 0, 2);
        let parent_txid = pool
            .add_transaction(parent, &utxo_set, ScriptFlags::all(), &params, None, &ctx)
            .unwrap();
        let mut child = spend_tx(OutPoint::new(parent_txid, 0), SEQ_NO_BIP68, 0, 2);
        child.output[0].value = Amount::from_sat(30_000);
        let child_txid = pool
            .add_transaction(child, &utxo_set, ScriptFlags::all(), &params, None, &ctx)
            .unwrap();

        // Simulate an entry whose BIP 68 lock point lies beyond the template
        // height (e.g. accepted before a reorg moved the tip back).
        let locked_tx = spend_tx(
            OutPoint::new(Txid::from_byte_array([9u8; 32]), 0),
            SEQ_NO_BIP68,
            0,
            2,
        );
        let locked_txid = locked_tx.compute_txid();
        let weight = locked_tx.weight().to_wu();
        pool.txs.insert(
            locked_txid,
            MempoolEntry {
                tx: locked_tx,
                txid: locked_txid,
                fee: 1_000,
                size: 100,
                weight,
                fee_rate: 10.0,
                time: 0,
                lock_height: 15, // not satisfied at template height 11
                lock_time: 0,
            },
        );

        // Template at height 11: parent before child, locked tx excluded.
        let selected = pool.select_for_block(11, 1_700_000_000, u64::MAX, 4000);
        let ids: Vec<Txid> = selected.iter().map(|e| e.txid).collect();
        assert_eq!(ids.len(), 2, "locked tx must be excluded: {ids:?}");
        assert_eq!(ids[0], parent_txid, "parent must precede child");
        assert_eq!(ids[1], child_txid);

        // Template at height 15: the lock point is now satisfied.
        let selected = pool.select_for_block(15, 1_700_000_000, u64::MAX, 4000);
        assert_eq!(selected.len(), 3);
    }

    /// H2 (2026-07-02 review): when the pool exceeds the block budget, the
    /// template must fill by descending feerate — the cheapest transaction is
    /// the one excluded, and the selected set comes out feerate-ordered.
    #[test]
    fn test_select_for_block_prefers_high_feerate_when_over_budget() {
        let mut pool = Mempool::new(1 << 20);

        // Three independent txs, identical weight, distinct feerates.
        let mut txs = Vec::new();
        for (i, fee_rate) in [(1u8, 1.0f64), (2, 500.0), (3, 50.0)] {
            let tx = spend_tx(
                OutPoint::new(Txid::from_byte_array([i; 32]), 0),
                SEQ_NO_BIP68,
                0,
                2,
            );
            let txid = tx.compute_txid();
            let weight = tx.weight().to_wu();
            pool.txs.insert(
                txid,
                MempoolEntry {
                    tx,
                    txid,
                    fee: (fee_rate * 100.0) as u64,
                    size: 100,
                    weight,
                    fee_rate,
                    time: i as u64,
                    lock_height: 0,
                    lock_time: 0,
                },
            );
            txs.push((txid, fee_rate, weight));
        }
        let per_tx_weight = txs[0].2;

        // Budget for exactly two of the three txs: the 1 sat/vB tx must lose.
        let selected = pool.select_for_block(
            11,
            1_700_000_000,
            per_tx_weight * 2 + per_tx_weight / 2,
            100,
        );
        let rates: Vec<f64> = selected.iter().map(|e| e.fee_rate).collect();
        assert_eq!(
            rates,
            vec![500.0, 50.0],
            "template must fill in descending feerate order, excluding the cheapest tx"
        );
    }

    #[test]
    fn test_mempool_new() {
        let pool = Mempool::new(1 << 20);
        assert_eq!(pool.size(), 0);
        assert_eq!(pool.total_bytes(), 0);
        assert!(pool.all_txids().is_empty());
    }

    #[test]
    fn test_datacarrier_size_default() {
        let params = ConsensusParams::mainnet();
        assert_eq!(params.max_datacarrier_size, 83);
    }

    #[test]
    fn test_signals_rbf() {
        use bitcoin::transaction::Version;
        use bitcoin::TxIn;

        // Sequence 0xffffffff -> no RBF
        let tx = Transaction {
            version: Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![TxIn {
                sequence: bitcoin::Sequence::MAX,
                ..Default::default()
            }],
            output: vec![],
        };
        assert!(!signals_rbf(&tx));

        // Sequence 0xfffffffd -> RBF signaled
        let tx = Transaction {
            version: Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![TxIn {
                sequence: bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME,
                ..Default::default()
            }],
            output: vec![],
        };
        assert!(signals_rbf(&tx));
    }

    #[test]
    fn test_mempool_persistence_roundtrip() {
        let pool = Mempool::new(1 << 20);
        let bytes = pool.save_to_bytes();
        assert_eq!(bytes.len(), 4); // just the count (0)
        assert_eq!(&bytes[0..4], &[0, 0, 0, 0]);
    }

    #[test]
    fn test_datacarrier_size_enforced() {
        use bitcoin::opcodes::all::OP_RETURN;
        use bitcoin::ScriptBuf;

        let params = ConsensusParams::mainnet();

        // Build a tx with an OP_RETURN output that exceeds 83 bytes
        // OP_RETURN + 83 bytes of data = 84 bytes total script > 83 limit
        let mut script_bytes = vec![OP_RETURN.to_u8()];
        script_bytes.push(0x4c); // OP_PUSHDATA1
        script_bytes.push(82); // push 82 bytes
        script_bytes.extend_from_slice(&[0xab; 82]); // 82 bytes of data
                                                     // Total script: 1 (OP_RETURN) + 1 (OP_PUSHDATA1) + 1 (length) + 82 (data) = 85 bytes

        let script = ScriptBuf::from_bytes(script_bytes);
        assert!(script.is_op_return());
        assert!(script.len() > params.max_datacarrier_size);

        // Build a tx with an OP_RETURN output within the limit
        let mut small_script_bytes = vec![OP_RETURN.to_u8()];
        small_script_bytes.push(0x4c); // OP_PUSHDATA1
        small_script_bytes.push(40); // push 40 bytes
        small_script_bytes.extend_from_slice(&[0xab; 40]);
        // Total: 1 + 1 + 1 + 40 = 43 bytes, well within 83

        let small_script = ScriptBuf::from_bytes(small_script_bytes);
        assert!(small_script.is_op_return());
        assert!(small_script.len() <= params.max_datacarrier_size);
    }

    /// One-input one-output tx wrapper for exercising check_output_policy.
    fn tx_with_outputs(outputs: Vec<bitcoin::TxOut>) -> Transaction {
        Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![bitcoin::TxIn::default()],
            output: outputs,
        }
    }

    #[test]
    fn test_datacarrier_disabled_rejects_op_return() {
        use bitcoin::ScriptBuf;

        let mut params = ConsensusParams::regtest();
        // Small OP_RETURN, well within the datacarriersize limit.
        let tx = tx_with_outputs(vec![bitcoin::TxOut {
            value: bitcoin::Amount::ZERO,
            script_pubkey: ScriptBuf::from_bytes(vec![0x6a, 0x04, 0xde, 0xad, 0xbe, 0xef]),
        }]);
        let txid = tx.compute_txid();

        // Default (datacarrier=1): accepted by output policy.
        check_output_policy(&tx, txid, &params).expect("OP_RETURN standard by default");

        // datacarrier=0: rejected regardless of size.
        params.datacarrier = false;
        let err = check_output_policy(&tx, txid, &params)
            .expect_err("OP_RETURN must be rejected with datacarrier disabled")
            .to_string();
        assert!(err.contains("datacarrier disabled"), "got: {err}");
    }

    #[test]
    fn test_datacarriersize_configurable() {
        use bitcoin::ScriptBuf;

        // 43-byte OP_RETURN script (OP_RETURN + direct push of 41 bytes):
        // over a Knots-style 42-byte limit, within the default 83.
        let mut spk = vec![0x6a, 0x29];
        spk.extend_from_slice(&[0xab; 41]);
        let spk = ScriptBuf::from_bytes(spk);
        assert!(spk.is_op_return());
        assert_eq!(spk.len(), 43);

        let tx = tx_with_outputs(vec![bitcoin::TxOut {
            value: bitcoin::Amount::ZERO,
            script_pubkey: spk,
        }]);
        let txid = tx.compute_txid();

        let mut params = ConsensusParams::regtest();
        check_output_policy(&tx, txid, &params).expect("43 bytes within default 83 limit");

        params.max_datacarrier_size = 42;
        let err = check_output_policy(&tx, txid, &params)
            .expect_err("43 bytes must exceed a 42-byte datacarriersize")
            .to_string();
        assert!(err.contains("datacarriersize"), "got: {err}");
    }

    #[test]
    fn test_parasite_and_token_relay_policy() {
        use bitcoin::ScriptBuf;

        // Inscription-envelope witness: OP_FALSE OP_IF "ord" <body> OP_ENDIF
        // leaf plus a shape-valid control block (taproot script path).
        let witness_for = |body: &[u8]| {
            let mut leaf = vec![0x00, 0x63, 0x03];
            leaf.extend_from_slice(b"ord");
            leaf.push(body.len() as u8);
            leaf.extend_from_slice(body);
            leaf.push(0x68);
            let mut control = vec![0xc0];
            control.extend_from_slice(&[0x02; 32]);
            let mut w = bitcoin::Witness::new();
            w.push([0u8; 64]);
            w.push(&leaf);
            w.push(&control);
            w
        };
        let spend_output = bitcoin::TxOut {
            value: bitcoin::Amount::from_sat(100_000),
            script_pubkey: ScriptBuf::new_p2wpkh(&bitcoin::WPubkeyHash::from_byte_array(
                [0x11; 20],
            )),
        };

        // Plain inscription: rejected as parasite by default, accepted once
        // rejectparasites is off (it is not a token).
        let mut tx = tx_with_outputs(vec![spend_output.clone()]);
        tx.input[0].witness = witness_for(b"just a picture");
        let txid = tx.compute_txid();
        let mut params = ConsensusParams::regtest();
        let err = check_relay_policy(&tx, txid, &params)
            .expect_err("inscription must be rejected by default")
            .to_string();
        assert!(err.contains("parasite"), "got: {err}");
        params.reject_parasites = false;
        check_relay_policy(&tx, txid, &params).expect("clean with rejectparasites=0");

        // BRC-20 inscription: with parasites off it is still caught as a token.
        let mut tx = tx_with_outputs(vec![spend_output]);
        tx.input[0].witness = witness_for(br#"{"p":"brc-20","op":"mint"}"#);
        let txid = tx.compute_txid();
        let err = check_relay_policy(&tx, txid, &params)
            .expect_err("brc-20 must be rejected as a token")
            .to_string();
        assert!(
            err.contains("token") && err.contains("brc-20"),
            "got: {err}"
        );
        params.reject_tokens = false;
        check_relay_policy(&tx, txid, &params).expect("clean with both filters off");

        // Runes runestone output: rejected by default params.
        let runes = tx_with_outputs(vec![bitcoin::TxOut {
            value: bitcoin::Amount::ZERO,
            script_pubkey: ScriptBuf::from_bytes(vec![0x6a, 0x5d, 0x02, 0xaa, 0xbb]),
        }]);
        let txid = runes.compute_txid();
        let err = check_relay_policy(&runes, txid, &ConsensusParams::regtest())
            .expect_err("runestone must be rejected by default")
            .to_string();
        assert!(err.contains("runes"), "got: {err}");
    }

    #[test]
    fn test_bare_multisig_policy() {
        use bitcoin::ScriptBuf;

        // 1-of-1 bare multisig: OP_1 <33-byte pubkey> OP_1 OP_CHECKMULTISIG.
        let mut spk = vec![0x51, 0x21];
        spk.push(0x02);
        spk.extend_from_slice(&[0xab; 32]);
        spk.extend_from_slice(&[0x51, 0xae]);
        let spk = ScriptBuf::from_bytes(spk);
        assert!(spk.is_multisig());

        let tx = tx_with_outputs(vec![bitcoin::TxOut {
            value: bitcoin::Amount::from_sat(100_000), // far above dust
            script_pubkey: spk,
        }]);
        let txid = tx.compute_txid();

        // Default (permitbaremultisig=0, the Knots default): rejected.
        let mut params = ConsensusParams::regtest();
        let err = check_output_policy(&tx, txid, &params)
            .expect_err("bare multisig must be rejected by default")
            .to_string();
        assert!(err.contains("bare multisig"), "got: {err}");

        // permitbaremultisig=1 (the Core default): accepted.
        params.permit_bare_multisig = true;
        check_output_policy(&tx, txid, &params)
            .expect("bare multisig standard when explicitly permitted");
    }

    #[test]
    fn test_fee_estimator_basic() {
        let mut estimator = FeeEstimator::new();

        // Not enough data yet
        assert!(estimator.estimate_fee(1).is_none());

        // Simulate activity: record mempool txs and confirm most of them
        for _ in 0..50 {
            estimator.record_mempool_tx(10.0);
            estimator.record_mempool_tx(50.0);
        }

        // Process several blocks confirming at these fee rates
        for _ in 0..5 {
            let confirmed: Vec<f64> = vec![10.0; 10].into_iter().chain(vec![50.0; 10]).collect();
            estimator.process_block(&confirmed);
        }

        // Now we should get estimates at various targets
        let est = estimator.estimate_fee(6);
        assert!(est.is_some());
        // Higher fee bucket should be returned for low targets
        let fast = estimator.estimate_fee(1);
        assert!(fast.is_some());
    }

    #[test]
    fn test_fee_bucket_index() {
        assert_eq!(FeeEstimator::bucket_index(0.5), 0); // Below minimum -> bucket 0
        assert_eq!(FeeEstimator::bucket_index(1.0), 0); // Exact match
        assert_eq!(FeeEstimator::bucket_index(1.5), 0); // Between 1 and 2
        assert_eq!(FeeEstimator::bucket_index(10.0), 5); // 10 sat/vB
        assert_eq!(FeeEstimator::bucket_index(10000.0), FEE_BUCKETS.len() - 1);
    }

    /// Memory cost of a tx in `memory_usage()` terms, for sizing test budgets.
    fn cost_of(tx: &Transaction) -> usize {
        Mempool::entry_cost(
            tx.input.len(),
            bitcoin::consensus::encode::serialize(tx).len(),
        )
    }

    #[test]
    fn test_eviction_lowest_feerate_with_descendants() {
        let (_dir, utxo_set, header_index) = test_stores();
        let params = ConsensusParams::regtest();
        let ctx = MempoolChainContext {
            tip_height: 10,
            tip_mtp: 1_700_000_000,
            header_index: &header_index,
            bip110: crate::bip110::Bip110Activation::INACTIVE,
        };
        let flags = ScriptFlags::all();

        // cheap (~2 sat/vB) with a child (~2.5), and mid (~5 sat/vB).
        let mut cheap = spend_tx(fund_utxo(&utxo_set, 1, 5), SEQ_NO_BIP68, 0, 2);
        cheap.output[0].value = Amount::from_sat(49_880); // fee 120
        let cheap_txid = cheap.compute_txid();
        let mut child = spend_tx(OutPoint::new(cheap_txid, 0), SEQ_NO_BIP68, 0, 2);
        child.output[0].value = Amount::from_sat(49_730); // fee 150
        let child_txid = child.compute_txid();
        let mut mid = spend_tx(fund_utxo(&utxo_set, 2, 5), SEQ_NO_BIP68, 0, 2);
        mid.output[0].value = Amount::from_sat(49_700); // fee 300
        let mid_txid = mid.compute_txid();
        // high (~100 sat/vB) arrives once the pool is at its budget.
        let mut high = spend_tx(fund_utxo(&utxo_set, 3, 5), SEQ_NO_BIP68, 0, 2);
        high.output[0].value = Amount::from_sat(44_000); // fee 6000
        let high_txid = high.compute_txid();

        // Budget: exactly the three resident txs — `high` forces an eviction.
        let budget = cost_of(&cheap) + cost_of(&child) + cost_of(&mid);
        let mut pool = Mempool::new(budget);
        pool.add_transaction(cheap, &utxo_set, flags, &params, None, &ctx)
            .unwrap();
        pool.add_transaction(child, &utxo_set, flags, &params, None, &ctx)
            .unwrap();
        pool.add_transaction(mid, &utxo_set, flags, &params, None, &ctx)
            .unwrap();
        assert_eq!(pool.size(), 3);

        pool.add_transaction(high, &utxo_set, flags, &params, None, &ctx)
            .expect("high-feerate tx must evict its way in");

        // Lowest-feerate entry AND its descendant got evicted; mid survived.
        assert!(!pool.contains(&cheap_txid), "cheapest tx must be evicted");
        assert!(!pool.contains(&child_txid), "descendant must go with it");
        assert!(pool.contains(&mid_txid));
        assert!(pool.contains(&high_txid));
        assert_eq!(pool.size(), 2);
    }

    #[test]
    fn test_mempool_full_equal_feerate_rejected() {
        let (_dir, utxo_set, header_index) = test_stores();
        let params = ConsensusParams::regtest();
        let ctx = MempoolChainContext {
            tip_height: 10,
            tip_mtp: 1_700_000_000,
            header_index: &header_index,
            bip110: crate::bip110::Bip110Activation::INACTIVE,
        };
        let flags = ScriptFlags::all();

        // Three identical-feerate txs, budget for two.
        let mut txs = Vec::new();
        for i in 1..=3u8 {
            let mut tx = spend_tx(fund_utxo(&utxo_set, i, 5), SEQ_NO_BIP68, 0, 2);
            tx.output[0].value = Amount::from_sat(49_700); // fee 300 each
            txs.push(tx);
        }
        let budget = cost_of(&txs[0]) + cost_of(&txs[1]);
        let mut pool = Mempool::new(budget);
        let id_a = pool
            .add_transaction(txs[0].clone(), &utxo_set, flags, &params, None, &ctx)
            .unwrap();
        let id_b = pool
            .add_transaction(txs[1].clone(), &utxo_set, flags, &params, None, &ctx)
            .unwrap();

        // Equal (not higher) feerate: rejected, nothing evicted — jamming the
        // pool buys nothing.
        let err = pool
            .add_transaction(txs[2].clone(), &utxo_set, flags, &params, None, &ctx)
            .unwrap_err();
        assert!(
            err.to_string().contains("mempool full"),
            "expected mempool-full rejection, got: {err}"
        );
        assert_eq!(pool.size(), 2);
        assert!(pool.contains(&id_a));
        assert!(pool.contains(&id_b));
    }

    #[test]
    fn test_eviction_protects_incoming_ancestry() {
        let (_dir, utxo_set, header_index) = test_stores();
        let params = ConsensusParams::regtest();
        let ctx = MempoolChainContext {
            tip_height: 10,
            tip_mtp: 1_700_000_000,
            header_index: &header_index,
            bip110: crate::bip110::Bip110Activation::INACTIVE,
        };
        let flags = ScriptFlags::all();

        // Cheap parent (~2 sat/vB) and a better-paying unrelated tx (~5).
        let mut parent = spend_tx(fund_utxo(&utxo_set, 1, 5), SEQ_NO_BIP68, 0, 2);
        parent.output[0].value = Amount::from_sat(49_880); // fee 120
        let parent_txid = parent.compute_txid();
        let mut unrelated = spend_tx(fund_utxo(&utxo_set, 2, 5), SEQ_NO_BIP68, 0, 2);
        unrelated.output[0].value = Amount::from_sat(49_700); // fee 300
        let unrelated_txid = unrelated.compute_txid();

        let budget = cost_of(&parent) + cost_of(&unrelated);
        let mut pool = Mempool::new(budget);
        pool.add_transaction(parent, &utxo_set, flags, &params, None, &ctx)
            .unwrap();
        pool.add_transaction(unrelated, &utxo_set, flags, &params, None, &ctx)
            .unwrap();

        // High-feerate child of `parent`: the eviction candidate would be
        // `parent` itself (lowest feerate), which would orphan the child —
        // so the child is rejected and the pool is left untouched.
        let mut child = spend_tx(OutPoint::new(parent_txid, 0), SEQ_NO_BIP68, 0, 2);
        child.output[0].value = Amount::from_sat(43_880); // fee 6000
        let child_txid = child.compute_txid();
        let err = pool
            .add_transaction(child, &utxo_set, flags, &params, None, &ctx)
            .unwrap_err();
        assert!(
            err.to_string().contains("mempool full"),
            "expected mempool-full rejection, got: {err}"
        );
        assert!(pool.contains(&parent_txid), "ancestor must not be evicted");
        assert!(pool.contains(&unrelated_txid));
        assert!(!pool.contains(&child_txid));
        assert_eq!(pool.size(), 2);
    }

    #[test]
    fn test_descendant_limit_enforced() {
        let (_dir, utxo_set, header_index) = test_stores();
        let params = ConsensusParams::regtest();
        let mut pool = Mempool::new(1 << 20);
        let ctx = MempoolChainContext {
            tip_height: 10,
            tip_mtp: 1_700_000_000,
            header_index: &header_index,
            bip110: crate::bip110::Bip110Activation::INACTIVE,
        };
        let flags = ScriptFlags::all();

        // Fan-out parent with MAX_DESCENDANTS + 1 outputs (a chain would trip
        // the ancestor limit at the same depth and mask this check).
        let mut parent = spend_tx(fund_utxo(&utxo_set, 1, 5), SEQ_NO_BIP68, 0, 2);
        parent.output = (0..=MAX_DESCENDANTS)
            .map(|_| TxOut {
                value: Amount::from_sat(1_500),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            })
            .collect();
        let parent_txid = pool
            .add_transaction(parent, &utxo_set, flags, &params, None, &ctx)
            .unwrap();

        // MAX_DESCENDANTS children are fine...
        for vout in 0..MAX_DESCENDANTS {
            let mut child = spend_tx(OutPoint::new(parent_txid, vout as u32), SEQ_NO_BIP68, 0, 2);
            child.output[0].value = Amount::from_sat(600); // fee 900
            pool.add_transaction(child, &utxo_set, flags, &params, None, &ctx)
                .unwrap_or_else(|e| panic!("child {vout} should be accepted: {e}"));
        }

        // ...the next one pushes the parent past the limit.
        let mut overflow = spend_tx(
            OutPoint::new(parent_txid, MAX_DESCENDANTS as u32),
            SEQ_NO_BIP68,
            0,
            2,
        );
        overflow.output[0].value = Amount::from_sat(600);
        let err = pool
            .add_transaction(overflow, &utxo_set, flags, &params, None, &ctx)
            .unwrap_err();
        assert!(
            err.to_string().contains("too many descendants"),
            "expected descendant-limit rejection, got: {err}"
        );
        assert_eq!(pool.size(), 1 + MAX_DESCENDANTS);
    }

    #[test]
    fn test_min_relay_fee_rejected() {
        let (_dir, utxo_set, header_index) = test_stores();
        let params = ConsensusParams::regtest();
        let mut pool = Mempool::new(1 << 20);
        let ctx = MempoolChainContext {
            tip_height: 10,
            tip_mtp: 1_700_000_000,
            header_index: &header_index,
            bip110: crate::bip110::Bip110Activation::INACTIVE,
        };

        // Fee 20 sats on a ~60 vB tx: ~0.33 sat/vB, below the 1 sat/vB floor.
        let mut tx = spend_tx(fund_utxo(&utxo_set, 1, 5), SEQ_NO_BIP68, 0, 2);
        tx.output[0].value = Amount::from_sat(49_980);
        let err = pool
            .add_transaction(tx, &utxo_set, ScriptFlags::all(), &params, None, &ctx)
            .unwrap_err();
        assert!(
            err.to_string().contains("min relay fee not met"),
            "expected min-relay rejection, got: {err}"
        );
        assert_eq!(pool.size(), 0);
    }

    #[test]
    fn test_dust_output_rejected() {
        let (_dir, utxo_set, header_index) = test_stores();
        let params = ConsensusParams::regtest();
        let mut pool = Mempool::new(1 << 20);
        let ctx = MempoolChainContext {
            tip_height: 10,
            tip_mtp: 1_700_000_000,
            header_index: &header_index,
            bip110: crate::bip110::Bip110Activation::INACTIVE,
        };

        // P2PKH script (25 bytes): dust threshold is the canonical 546 sats.
        let mut p2pkh = vec![0x76, 0xa9, 0x14]; // OP_DUP OP_HASH160 PUSH20
        p2pkh.extend_from_slice(&[0xab; 20]);
        p2pkh.extend_from_slice(&[0x88, 0xac]); // OP_EQUALVERIFY OP_CHECKSIG

        // 545-sat P2PKH output: dust.
        let mut tx = spend_tx(fund_utxo(&utxo_set, 1, 5), SEQ_NO_BIP68, 0, 2);
        tx.output.push(TxOut {
            value: Amount::from_sat(545),
            script_pubkey: ScriptBuf::from_bytes(p2pkh.clone()),
        });
        let err = pool
            .add_transaction(tx, &utxo_set, ScriptFlags::all(), &params, None, &ctx)
            .unwrap_err();
        assert!(
            err.to_string().contains("dust"),
            "expected dust rejection, got: {err}"
        );
        assert_eq!(pool.size(), 0);

        // 546-sat P2PKH output: exactly at the threshold, accepted.
        let mut tx = spend_tx(fund_utxo(&utxo_set, 2, 5), SEQ_NO_BIP68, 0, 2);
        tx.output.push(TxOut {
            value: Amount::from_sat(546),
            script_pubkey: ScriptBuf::from_bytes(p2pkh),
        });
        pool.add_transaction(tx, &utxo_set, ScriptFlags::all(), &params, None, &ctx)
            .expect("546-sat P2PKH output is not dust");
        assert_eq!(pool.size(), 1);
    }

    #[test]
    fn test_op_return_exempt_from_dust() {
        let (_dir, utxo_set, header_index) = test_stores();
        let params = ConsensusParams::regtest();
        let mut pool = Mempool::new(1 << 20);
        let ctx = MempoolChainContext {
            tip_height: 10,
            tip_mtp: 1_700_000_000,
            header_index: &header_index,
            bip110: crate::bip110::Bip110Activation::INACTIVE,
        };

        // Zero-value OP_RETURN: provably unspendable, never dust.
        let mut tx = spend_tx(fund_utxo(&utxo_set, 1, 5), SEQ_NO_BIP68, 0, 2);
        tx.output.push(TxOut {
            value: Amount::from_sat(0),
            script_pubkey: ScriptBuf::from_bytes(vec![0x6a]), // OP_RETURN
        });
        pool.add_transaction(tx, &utxo_set, ScriptFlags::all(), &params, None, &ctx)
            .expect("zero-value OP_RETURN output must be exempt from dust");
        assert_eq!(pool.size(), 1);
    }

    #[test]
    fn test_dust_threshold_values() {
        // Canonical Core values: 546 (P2PKH), 294 (P2WPKH).
        let mut p2pkh = vec![0x76, 0xa9, 0x14];
        p2pkh.extend_from_slice(&[0xab; 20]);
        p2pkh.extend_from_slice(&[0x88, 0xac]);
        let out = TxOut {
            value: Amount::from_sat(0),
            script_pubkey: ScriptBuf::from_bytes(p2pkh),
        };
        assert_eq!(dust_threshold(&out), 546);

        let mut p2wpkh = vec![0x00, 0x14]; // OP_0 PUSH20
        p2wpkh.extend_from_slice(&[0xab; 20]);
        let out = TxOut {
            value: Amount::from_sat(0),
            script_pubkey: ScriptBuf::from_bytes(p2wpkh),
        };
        assert_eq!(dust_threshold(&out), 294);

        let out = TxOut {
            value: Amount::from_sat(0),
            script_pubkey: ScriptBuf::from_bytes(vec![0x6a]), // OP_RETURN
        };
        assert_eq!(dust_threshold(&out), 0);
    }
}
