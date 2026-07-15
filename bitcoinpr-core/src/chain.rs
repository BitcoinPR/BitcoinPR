use bitcoin::blockdata::block::Block;
use bitcoin::{BlockHash, OutPoint, Transaction, TxOut};
use rayon::prelude::*;
use std::collections::{HashMap, HashSet};
use tracing::{debug, info, warn};

use crate::consensus::ConsensusParams;
use crate::error::{CoreError, CoreResult};
use crate::script::{self, count_sigops, ScriptFlags, SigCache};
use crate::validation;

use bitcoinpr_storage::{
    BlockStore, HeaderIndex, SpentUtxo, TxIndex, UtxoBatch, UtxoEntry, UtxoSet,
};

/// A deferred script-verification task queued during `validate_transactions`
/// and executed on the rayon pool: (tx, input_index, all prevouts of the tx,
/// wtxid for the sig cache, per-input BIP-110 enforcement). The spent prevout
/// is `all_prevouts[input_index]` — indexed at verification time rather than
/// cloned per input (M8, 2026-07-02 review).
type ScriptCheck<'a> = (
    &'a Transaction,
    usize,
    std::sync::Arc<Vec<TxOut>>,
    bitcoin::Wtxid,
    bool,
);

/// Manages the chain state: validates blocks, maintains UTXO set, tracks best tip.
///
/// INVARIANT (L3, 2026-07-02 review): `best_height`/`best_hash` mirror
/// on-disk state maintained by `connect_block`/`disconnect_block`. The only
/// sanctioned external writer is the node's undo-rollback reorg fallback,
/// which re-establishes the same invariant by hand. Do not mutate them from
/// new call sites — desyncing them from the storage layer corrupts recovery.
pub struct ChainState {
    pub params: ConsensusParams,
    pub header_index: std::sync::Arc<HeaderIndex>,
    pub utxo_set: std::sync::Arc<UtxoSet>,
    pub block_store: std::sync::Arc<BlockStore>,
    pub tx_index: Option<std::sync::Arc<TxIndex>>,
    pub sig_cache: std::sync::Arc<SigCache>,
    pub best_height: u32,
    pub best_hash: BlockHash,
    /// Best height reported by peers, used for sync progress display.
    pub peer_best_height: Option<u32>,
    /// BIP-110 signaling-deployment state machine (mainnet). `None` when the
    /// network has no RDTS deployment or uses the fixed-mode override. Shared
    /// (`Arc`) so the mempool-acceptance path can reuse the same cache without
    /// locking the chain state.
    bip110_checker: Option<std::sync::Arc<crate::bip110::Bip110Checker>>,
}

impl ChainState {
    pub fn new(
        params: ConsensusParams,
        header_index: std::sync::Arc<HeaderIndex>,
        utxo_set: std::sync::Arc<UtxoSet>,
        block_store: std::sync::Arc<BlockStore>,
        best_height: u32,
        best_hash: BlockHash,
    ) -> Self {
        // Build the BIP-110 signaling state machine when this network defines a
        // deployment and no fixed-mode override is in effect.
        let bip110_checker = match (&params.bip110_deployment, params.bip110_activation_height) {
            (Some(dep), None) => Some(std::sync::Arc::new(crate::bip110::Bip110Checker::new(
                dep.clone(),
            ))),
            _ => None,
        };
        ChainState {
            params,
            header_index,
            utxo_set,
            block_store,
            tx_index: None,
            sig_cache: std::sync::Arc::new(SigCache::new(100_000)),
            best_height,
            best_hash,
            peer_best_height: None,
            bip110_checker,
        }
    }

    /// Evaluate the BIP-110 deployment for a block at `height` whose parent is
    /// `prev_hash`. The fixed-mode override (`--bip110height`) wins; otherwise the
    /// signaling state machine computes the result from the ancestor chain.
    pub fn bip110_activation(
        &self,
        prev_hash: &BlockHash,
        height: u32,
    ) -> crate::bip110::Bip110Activation {
        crate::bip110::activation_at(
            &self.params,
            self.bip110_checker.as_deref(),
            &self.header_index,
            prev_hash,
            height,
        )
    }

    /// The shared BIP-110 signaling checker, if this network runs one. Lets other
    /// subsystems (mempool acceptance, mining, RPC) reuse the same cache.
    pub fn bip110_checker(&self) -> Option<std::sync::Arc<crate::bip110::Bip110Checker>> {
        self.bip110_checker.clone()
    }

    /// Connect a block to the chain: validate, update UTXO set, store block.
    pub fn connect_block(&mut self, block: &Block, height: u32) -> CoreResult<()> {
        self.connect_block_with_raw(block, height, None)
    }

    /// Connect a block with optional pre-serialized raw bytes to skip re-serialization.
    pub fn connect_block_with_raw(
        &mut self,
        block: &Block,
        height: u32,
        raw_bytes: Option<&[u8]>,
    ) -> CoreResult<()> {
        let connect_start = std::time::Instant::now();
        let hash = block.block_hash();

        // 1. Validate block header
        let prev_header = if height > 0 {
            self.header_index
                .get_header(&block.header.prev_blockhash)?
                .map(|sh| sh.header)
        } else {
            None
        };

        validation::validate_block_header(
            &block.header,
            height,
            prev_header.as_ref(),
            &self.params,
        )?;

        // 2. Pre-compute all txids once (avoids redundant double-SHA256 in
        //    merkle root verification, validate_transactions, and tx index).
        let txids: Vec<bitcoin::Txid> = block.txdata.iter().map(|tx| tx.compute_txid()).collect();

        // 3. Verify merkle root using pre-computed txids
        validation::verify_merkle_root_with_txids(block, &txids)?;

        // 4. Validate block weight
        validation::validate_block_weight(block, &self.params)?;

        // 5. Validate coinbase
        validation::validate_coinbase(block, height, &self.params)?;

        // 6. Validate SegWit witness commitment (BIP 141)
        if height >= self.params.segwit_height {
            validation::validate_witness_commitment(block)?;
        }

        // 6b. Median-time-past (BIP 113): the block timestamp must be strictly
        //     greater than the MTP of the previous 11 blocks. This is also the
        //     time reference used for nLockTime finality and BIP 68 sequence
        //     locks below. Genesis has no ancestors, so it's exempt.
        //
        //     A failed MTP lookup (prev header missing from the index) must
        //     fail CLOSED: defaulting to 0 would let any timestamp — and any
        //     time-locked transaction — pass. The block can be retried once
        //     the headers are available.
        let block_mtp = if height > 0 {
            validation::get_median_time_past(&self.header_index, &block.header.prev_blockhash)
                .ok_or_else(|| CoreError::ChainContext(format!(
                    "cannot compute median-time-past for block {} at height {} (prev header {} missing)",
                    hash, height, block.header.prev_blockhash
                )))?
        } else {
            0
        };
        if height > 0 && block.header.time <= block_mtp {
            return Err(CoreError::InvalidTimestamp(format!(
                "block time {} is not after median-time-past {}",
                block.header.time, block_mtp
            )));
        }

        // 6c. Difficulty: the block's nBits must equal the consensus-required
        //     target for its height (proof-of-work retarget on schedule, plus the
        //     testnet minimum-difficulty rule). Skipped for signet, whose block
        //     validity comes from the challenge signature rather than PoW.
        //     `get_next_work_required` returns `None` only when ancestor
        //     headers are missing — that must fail CLOSED too (no nBits check
        //     at all is the wrong failure direction for consensus).
        if height > 0 && self.params.signet_challenge.is_none() {
            let expected_bits = validation::get_next_work_required(
                &self.header_index,
                &self.params,
                &block.header.prev_blockhash,
                height - 1,
                block.header.time,
            )
            .ok_or_else(|| CoreError::ChainContext(format!(
                "cannot compute required nBits for block {hash} at height {height} (ancestor headers missing)"
            )))?;
            let got_bits = block.header.bits.to_consensus();
            if got_bits != expected_bits {
                return Err(CoreError::InvalidDifficultyTarget(format!(
                    "nBits mismatch at height {height}: expected {expected_bits:#010x}, got {got_bits:#010x}"
                )));
            }
        }

        // 7. Validate all transactions and build UTXO batch
        let script_flags = ScriptFlags::for_height(
            height,
            block.header.time,
            self.params.bip16_time,
            self.params.segwit_height,
            self.params.bip65_height,
            self.params.csv_height,
            self.params.bip66_height,
            self.params.taproot_height,
        );

        // Skip script verification for blocks at or before the assume-valid block.
        // Once we connect the assume-valid block itself, we've validated the
        // header chain's PoW all the way up, so all prior scripts are trusted.
        let verify_scripts = match &self.params.assume_valid {
            Some(assume_hash) => {
                // Check if we've already passed the assume-valid point
                if hash == *assume_hash {
                    false // The assume-valid block itself is trusted
                } else {
                    // Check if the assume-valid block is in our header chain
                    match self.header_index.get_header(assume_hash) {
                        Ok(Some(av_header)) => height > av_header.height,
                        _ => true, // If we can't find it, verify everything
                    }
                }
            }
            None => true,
        };

        // BIP-110 deployment state for this block (dynamic, signaling-driven on
        // mainnet; fixed-mode on the --bip110height override). Computed once and
        // reused for the mandatory-signaling check and per-tx enforcement.
        let bip110 = self.bip110_activation(&block.header.prev_blockhash, height);

        // BIP-110 mandatory signaling: while the deployment is STARTED, blocks in
        // the mandatory-signaling window that do not signal the bit are invalid.
        // Only applies to the signaling deployment (not the fixed-mode override).
        if let Some(checker) = &self.bip110_checker {
            let dep = checker.deployment();
            let (lo, hi) = dep.mandatory_window;
            if bip110.state == crate::bip110::ThresholdState::Started
                && height >= lo
                && height <= hi
                && !dep.signals(block.header.version.to_consensus() as u32)
            {
                return Err(CoreError::InvalidBlock(format!(
                    "BIP-110: block at height {} in the mandatory-signaling window must signal bit {}",
                    height, dep.bit
                )));
            }
        }

        let utxo_batch = self.validate_transactions(
            block,
            height,
            &txids,
            script_flags,
            verify_scripts,
            block_mtp,
            bip110,
        )?;

        // 8. Store the block and record its position (async write to background thread)
        // Use raw bytes from P2P when available to skip re-serialization.
        let serialized;
        let raw_block = match raw_bytes {
            Some(bytes) => bytes,
            None => {
                serialized = bitcoin::consensus::encode::serialize(block);
                &serialized
            }
        };
        let block_pos = self.block_store.store_block_async(raw_block)?;
        self.header_index.set_block_pos(&hash, &block_pos)?;

        // Keep the canonical height → hash index pointed at the *active* chain.
        // Header-first sync and RPC `generate` already write this when they
        // insert headers, but a reorg connects the new chain's blocks through
        // here without re-inserting their headers — so without this write the
        // intermediate reorged heights keep pointing at the orphaned chain,
        // and `get_hash_at_height` (getheaders serving, getblockhash) returns
        // stale hashes that strand peers on the losing chain.
        self.header_index.set_height_hash(height, &hash)?;

        // Ensure the connected block's HEADER is stored with cumulative chain
        // work. Blocks can arrive and connect through the raw-block broadcast
        // path before header sync ever stored their headers (fresh IBD from a
        // single peer that pushes blocks): without a stored header, the next
        // headers batch cannot compute chain work from this block as parent
        // ("prev header has no stored data") and header sync wedges at the
        // tip. The parent header exists by induction — genesis is seeded at
        // datadir init and every connect passes through here.
        if self.header_index.get_header(&hash)?.is_none() {
            if let Some(parent) = self.header_index.get_header(&block.header.prev_blockhash)? {
                let chain_work = crate::validation::add_chain_work(
                    &parent.chain_work,
                    &crate::validation::calculate_work(&block.header.target()),
                );
                self.header_index.insert_header(
                    &hash,
                    &bitcoinpr_storage::StoredHeader {
                        header: block.header,
                        height,
                        chain_work,
                    },
                )?;
            }
        }

        // 9. Store undo data for reorg/rollback support.
        //    Includes spent UTXOs (to re-insert), created outpoints (to remove),
        //    and prev_block_hash (to walk the chain backward without the block store).
        {
            let hash_bytes: &[u8; 32] = AsRef::<[u8; 32]>::as_ref(&hash);
            let prev_hash_bytes: &[u8; 32] =
                AsRef::<[u8; 32]>::as_ref(&block.header.prev_blockhash);
            let created_outpoints: Vec<OutPoint> =
                utxo_batch.inserts.iter().map(|(op, _)| *op).collect();
            self.utxo_set.store_undo(
                hash_bytes,
                &utxo_batch.spent_utxos,
                &created_outpoints,
                prev_hash_bytes,
            )?;
        }

        // 10. Apply UTXO changes (returns true if buffer was flushed to disk)
        //     Set the pending flush height first so it's persisted atomically
        //     with the UTXO data, making the UTXO set self-describing.
        let hash_bytes_for_meta: &[u8; 32] = AsRef::<[u8; 32]>::as_ref(&hash);
        self.utxo_set
            .set_pending_flush_height(height, hash_bytes_for_meta);
        let flushed = self.utxo_set.apply_batch(&utxo_batch)?;

        // 11. Update transaction index if enabled (reuses pre-computed txids)
        if let Some(ref tx_index) = self.tx_index {
            tx_index.index_block_at_height(&hash, &txids, height)?;
        }

        // 12. Update chain tip (in-memory always, on-disk only when UTXO is flushed)
        self.best_height = height;
        self.best_hash = hash;

        // Only persist best_tip to disk when the UTXO buffer flushed, so the
        // on-disk tip always corresponds to a consistent UTXO set. On crash,
        // blocks between the persisted tip and the true tip get re-validated.
        if flushed {
            self.header_index.set_best_tip(&hash, height)?;
            // Persist validated height with each flush so crash recovery knows
            // the last consistent UTXO state without relying on clean shutdown.
            self.header_index.set_validated_height(height)?;
            // Force a fsync of the header_index WAL so every height→hash entry
            // written during this batch is durable before best_tip advances.
            // Without this, a power loss can leave best_tip referencing heights
            // whose index entries are still buffered, producing a gap that
            // `verify_chain_integrity` will trip on at the next startup and
            // trigger a full forward-recovery re-sync. Cost: one fsync per
            // UTXO flush boundary (≈ every 500 blocks during IBD).
            self.header_index.flush_wal()?;
        }

        // Periodically clear sig cache to bound memory growth
        if height % 10_000 == 0 {
            self.sig_cache.clear();
        }

        if height % 1000 == 0 {
            if let Some(peer_best) = self.peer_best_height {
                let progress = if peer_best > 0 {
                    (height as f64 / peer_best as f64) * 100.0
                } else {
                    100.0
                };
                info!(height, hash = %hash, progress = format!("{:.2}%", progress), "Connected block");
            } else {
                info!(height, hash = %hash, "Connected block");
            }
        } else {
            debug!(height, hash = %hash, "Connected block");
        }

        // Surface pathological single-block connect times (long UTXO flush,
        // RocksDB write stall, or a very expensive block) at WARN so slow
        // stretches of IBD are attributable without debug logging.
        let connect_ms = connect_start.elapsed().as_millis() as u64;
        if connect_ms > 5_000 {
            warn!(height, hash = %hash, connect_ms, flushed, "Slow block connect");
        }

        Ok(())
    }

    /// Disconnect a block from the chain tip, reversing UTXO changes.
    /// The block must be the current tip.
    pub fn disconnect_block(&mut self, block: &Block, height: u32) -> CoreResult<()> {
        let hash = block.block_hash();

        if hash != self.best_hash {
            return Err(CoreError::InvalidTransaction(format!(
                "cannot disconnect block {} — not the current tip {}",
                hash, self.best_hash
            )));
        }

        if height != self.best_height {
            return Err(CoreError::InvalidTransaction(format!(
                "height mismatch: expected {}, got {}",
                self.best_height, height
            )));
        }

        // Load undo data for this block. Missing undo data fails CLOSED, like
        // every other chain-context lookup here: proceeding with an empty undo
        // record would delete the block's outputs while restoring none of its
        // spends, silently corrupting the UTXO set (the damage only surfaces
        // later as spurious MissingUtxo rejections of valid blocks). The
        // forward re-sync recovery path is the correct fallback for a lost
        // undo record.
        let hash_bytes: &[u8; 32] = AsRef::<[u8; 32]>::as_ref(&hash);
        let undo = self
            .utxo_set
            .load_undo(hash_bytes)?
            .ok_or(CoreError::UndoMissing { hash, height })?;

        let mut batch = UtxoBatch::new();

        // Remove all outputs created by this block (reverse order)
        for tx in block.txdata.iter().rev() {
            let txid = tx.compute_txid();
            for (vout, output) in tx.output.iter().enumerate() {
                if !output.script_pubkey.is_op_return() {
                    let outpoint = OutPoint::new(txid, vout as u32);
                    batch.removals.push(outpoint);
                }
            }
        }

        // Re-add all spent UTXOs from undo data
        for spent in &undo.spent_utxos {
            batch.inserts.push((spent.outpoint, spent.entry.clone()));
        }

        // Apply the reverse batch — set pending flush height to the new
        // (rolled-back) tip so it's persisted atomically with the UTXO data.
        let prev_height = height.saturating_sub(1);
        let prev_hash_bytes: &[u8; 32] = AsRef::<[u8; 32]>::as_ref(&block.header.prev_blockhash);
        self.utxo_set
            .set_pending_flush_height(prev_height, prev_hash_bytes);
        self.utxo_set.apply_batch(&batch)?;

        // Clean up undo data
        self.utxo_set.delete_undo(hash_bytes)?;

        // Remove from transaction index if enabled
        if let Some(ref tx_index) = self.tx_index {
            let txids: Vec<bitcoin::Txid> =
                block.txdata.iter().map(|tx| tx.compute_txid()).collect();
            tx_index.deindex_block(&txids)?;
        }

        // Update chain tip to the previous block
        self.best_height = height.saturating_sub(1);
        self.best_hash = block.header.prev_blockhash;

        // Remove the canonical height → hash entry for the disconnected block,
        // but ONLY if it still names the block we just disconnected. During a
        // reorg the new (winning) chain's height→hash entry for this height may
        // already have been written (by header-sync repair or the reorg
        // pre-walk). Unconditionally deleting here would clobber that newer
        // entry, leaving a hole at `height` while a stray entry survives one
        // height up — which strands block download (the re-request loop walks
        // `get_hash_at_height(h)` and silently skips the missing height, so the
        // intermediate block is never requested and the node sticks forever).
        // Only delete when the index still points at the orphaned hash.
        match self.header_index.get_hash_at_height(height) {
            Ok(Some(h)) if h != hash => {
                // Index already advanced to a different (new-chain) block at this
                // height — leave it; it will be reaffirmed when that block connects.
            }
            _ => {
                self.header_index.delete_height_entry(height)?;
            }
        }

        // Flush UTXO to disk and persist tip atomically — reorgs must leave
        // a consistent on-disk state in case of crash.
        self.utxo_set.flush_to_disk()?;
        self.header_index
            .set_best_tip(&self.best_hash, self.best_height)?;

        info!(height, hash = %hash, new_tip = %self.best_hash, "Disconnected block");

        Ok(())
    }

    /// Validate all transactions in a block and produce a UTXO batch.
    /// Script verification is parallelized using rayon.
    #[allow(clippy::too_many_arguments)]
    fn validate_transactions(
        &self,
        block: &Block,
        height: u32,
        txids: &[bitcoin::Txid],
        script_flags: ScriptFlags,
        verify_scripts: bool,
        block_mtp: u32,
        bip110: crate::bip110::Bip110Activation,
    ) -> CoreResult<UtxoBatch> {
        let mut batch = UtxoBatch::new();
        let mut spent_in_block = HashSet::new();
        let mut total_fees: u64 = 0;
        // Block sigop *cost* (Bitcoin Core's MAX_BLOCK_SIGOPS_COST). Legacy and
        // P2SH sigops are scaled by the witness factor (×4); witness sigops ×1.
        let mut total_sigop_cost: u64 = 0;
        const MAX_BLOCK_SIGOPS_COST: u64 = 80_000;
        const WITNESS_SCALE_FACTOR: u64 = 4;

        // Pre-fetch all input UTXOs from disk into cache in a single batch read.
        // This avoids individual RocksDB point lookups during the sequential
        // validation pass, turning N random reads into one batched multi_get.
        {
            let all_inputs: Vec<OutPoint> = block
                .txdata
                .iter()
                .skip(1) // skip coinbase
                .flat_map(|tx| tx.input.iter().map(|inp| inp.previous_output))
                .collect();
            self.utxo_set.prefetch(&all_inputs)?;
        }

        // Fast index for outputs created earlier in this block (intra-block spending).
        let mut intra_block_utxos: HashMap<OutPoint, UtxoEntry> = HashMap::new();

        // Collect script verification tasks: (tx, input_index, prev_output, all_prevouts, wtxid)
        // all_prevouts is shared across inputs of the same tx (needed for Taproot BIP 341 sighash).
        // wtxid keys the sig cache so it commits to witness data (see SigCache docs).
        // The trailing bool is BIP-110 enforcement for this input, decided from
        // the spent UTXO's creation height (pre-activation coins are grandfathered).
        let mut script_checks: Vec<ScriptCheck> = Vec::new();

        for (tx_idx, tx) in block.txdata.iter().enumerate() {
            let txid = txids[tx_idx];

            // Context-free sanity: empty vin/vout, value range, duplicate inputs,
            // null non-coinbase prevouts (Bitcoin Core's CheckTransaction).
            validation::check_transaction(tx)?;

            // BIP-110 rule 1: while the softfork is ACTIVE, new output scriptPubKeys
            // over 34 bytes are invalid (OP_RETURN outputs may reach 83 bytes).
            // Gated on the block's deployment state — this governs newly created
            // outputs, not the grandfathered coins being spent.
            if bip110.enforcing() {
                script::check_bip110_output_scripts(tx)?;
            }

            // BIP 30: Check that this txid doesn't already have unspent outputs.
            // After BIP 34 activation, coinbase txs include the block height,
            // making txid collisions impossible — skip the expensive per-output
            // UTXO lookup. Exception: the two known duplicate coinbase txids.
            let bip30_exception = (height == 91842 || height == 91880)
                && self.params.network == bitcoin::Network::Bitcoin;
            let skip_bip30 = height >= self.params.bip34_height;

            if !bip30_exception && !skip_bip30 {
                for vout in 0..tx.output.len() {
                    let outpoint = OutPoint::new(txid, vout as u32);
                    if self.utxo_set.contains(&outpoint)? {
                        return Err(CoreError::InvalidTransaction(format!(
                            "BIP 30: duplicate txid {txid} has unspent outputs"
                        )));
                    }
                }
            }

            // Legacy sigop cost (inaccurate count, ×4 witness scale) — counts all
            // output scriptPubKeys and input scriptSigs. P2SH redeem-script and
            // witness sigops are added per-input below where prevouts are known.
            let mut legacy_sigops: u32 = 0;
            for output in &tx.output {
                legacy_sigops += count_sigops(&output.script_pubkey, false);
            }
            for input in &tx.input {
                legacy_sigops += count_sigops(&input.script_sig, false);
            }
            total_sigop_cost += legacy_sigops as u64 * WITNESS_SCALE_FACTOR;

            if tx_idx == 0 {
                // Coinbase transaction - just add outputs to UTXO set
                for (vout, output) in tx.output.iter().enumerate() {
                    if !output.script_pubkey.is_op_return() {
                        let outpoint = OutPoint::new(txid, vout as u32);
                        let entry = UtxoEntry {
                            amount: output.value.to_sat(),
                            script_pubkey: output.script_pubkey.to_bytes(),
                            height,
                            is_coinbase: true,
                        };
                        intra_block_utxos.insert(outpoint, entry.clone());
                        batch.inserts.push((outpoint, entry));
                    }
                }
                continue;
            }

            // Non-coinbase transaction

            // nLockTime finality check.  BIP 113 (activated at csv_height)
            // switched the time reference from the block's own timestamp to
            // median-time-past.  Before that height we must use block.header.time
            // so that pre-BIP-113 blocks with time-locked transactions validate
            // correctly.
            let locktime_time = if height >= self.params.csv_height {
                block_mtp
            } else {
                block.header.time
            };
            if !validation::is_final_tx(tx, height, locktime_time) {
                return Err(CoreError::InvalidTransaction(format!(
                    "bad-txns-nonfinal: tx {txid} is not final at height {height} (locktime_time {locktime_time})"
                )));
            }

            let mut input_sum: u64 = 0;
            // Collect all previous outputs for this tx (needed for Taproot sighash).
            let mut tx_prevouts: Vec<TxOut> = Vec::with_capacity(tx.input.len());
            // Confirmation heights of each input's prevout (for BIP 68).
            let mut input_heights: Vec<u32> = Vec::with_capacity(tx.input.len());

            for (vin, input) in tx.input.iter().enumerate() {
                let outpoint = input.previous_output;

                // Check for double-spend within this block
                if !spent_in_block.insert(outpoint) {
                    return Err(CoreError::DoubleSpend(format!(
                        "outpoint {}:{} spent twice in block",
                        outpoint.txid, outpoint.vout
                    )));
                }

                // Look up the UTXO — check DB/write-buffer first, then fall back to
                // outputs created earlier in this same block (intra-block spending).
                let utxo = self
                    .utxo_set
                    .get(&outpoint)?
                    .or_else(|| intra_block_utxos.get(&outpoint).cloned())
                    .ok_or_else(|| {
                        CoreError::MissingUtxo(format!("{}:{}", outpoint.txid, outpoint.vout))
                    })?;

                // Check coinbase maturity
                if utxo.is_coinbase
                    && height.saturating_sub(utxo.height) < self.params.coinbase_maturity
                {
                    return Err(CoreError::InvalidTransaction(format!(
                        "tx {} input {}: spending immature coinbase at height {} (coinbase height={}, age={}, required={})",
                        txid, vin, height, utxo.height,
                        height.saturating_sub(utxo.height),
                        self.params.coinbase_maturity,
                    )));
                }

                input_sum += utxo.amount;
                input_heights.push(utxo.height);

                // Build prev_output for script verification and prevouts collection
                let prev_output = TxOut {
                    value: bitcoin::Amount::from_sat(utxo.amount),
                    script_pubkey: bitcoin::ScriptBuf::from_bytes(utxo.script_pubkey.clone()),
                };

                // P2SH and witness sigop cost (need the prevout scriptPubKey).
                if script_flags.verify_p2sh && prev_output.script_pubkey.is_p2sh() {
                    if let Some(redeem) = script::p2sh_redeem_script(&input.script_sig) {
                        let redeem = bitcoin::ScriptBuf::from_bytes(redeem);
                        total_sigop_cost +=
                            count_sigops(&redeem, true) as u64 * WITNESS_SCALE_FACTOR;
                    }
                }
                if script_flags.verify_witness {
                    total_sigop_cost += script::witness_sigop_cost(
                        &prev_output.script_pubkey,
                        &input.script_sig,
                        &input.witness,
                    );
                }

                tx_prevouts.push(prev_output);

                // Record spent UTXO for undo data
                batch.spent_utxos.push(SpentUtxo {
                    outpoint,
                    entry: utxo,
                });

                // Mark as spent
                batch.removals.push(outpoint);
            }

            // BIP 68 relative lock-times (gated on the CSV buried activation,
            // same height as BIP 112/113). validate_sequence_locks no-ops for
            // version < 2 txs and inputs with the disable bit set, so the
            // per-input MTP lookups below only happen for genuine time-based
            // relative locks (rare) — the common final/RBF sequences are skipped.
            if height >= self.params.csv_height {
                let needs_time_mtp = tx.version.0 >= 2
                    && tx.input.iter().any(|inp| {
                        let s = inp.sequence.0;
                        s & (1 << 31) == 0 && s & (1 << 22) != 0
                    });
                let input_times: Vec<u32> = if needs_time_mtp {
                    input_heights
                        .iter()
                        .map(|&coin_height| {
                            // BIP 68 time reference is the MTP of the block BEFORE
                            // the prevout's confirmation block. A failed lookup must
                            // fail CLOSED: defaulting to 0 makes the required time
                            // tiny (0 + value*512), treating an unsatisfied time
                            // lock as satisfied.
                            let h = coin_height.saturating_sub(1);
                            self.header_index
                                .get_hash_at_height(h)
                                .ok()
                                .flatten()
                                .and_then(|hash| validation::get_median_time_past(&self.header_index, &hash))
                                .ok_or_else(|| CoreError::ChainContext(format!(
                                    "cannot compute BIP 68 time reference (MTP at height {h}) for tx {txid} input prevout confirmed at height {coin_height}"
                                )))
                        })
                        .collect::<CoreResult<Vec<u32>>>()?
                } else {
                    vec![0u32; tx.input.len()]
                };
                validation::validate_sequence_locks(
                    tx,
                    &input_heights,
                    &input_times,
                    height,
                    block_mtp,
                )?;
            }

            // Queue script verifications now that we have all prevouts for this tx
            if verify_scripts {
                let wtxid = tx.compute_wtxid();
                let prevouts_arc = std::sync::Arc::new(tx_prevouts);
                for (vin, &input_height) in input_heights.iter().enumerate() {
                    // BIP-110 rules 2-7 apply only while the deployment is ACTIVE
                    // for this block AND the spent UTXO was created at/after the
                    // activation height (pre-activation coins are grandfathered).
                    let enforce_bip110 = bip110.enforcing()
                        && bip110.activation_height.is_some_and(|a| input_height >= a);
                    script_checks.push((tx, vin, prevouts_arc.clone(), wtxid, enforce_bip110));
                }
            }

            // Check output values
            let output_sum: u64 = tx.output.iter().map(|o| o.value.to_sat()).sum();
            if output_sum > input_sum {
                return Err(CoreError::InvalidTransaction(format!(
                    "outputs ({output_sum}) exceed inputs ({input_sum})"
                )));
            }

            total_fees += input_sum - output_sum;

            // Add new outputs to UTXO set
            for (vout, output) in tx.output.iter().enumerate() {
                if !output.script_pubkey.is_op_return() {
                    let outpoint = OutPoint::new(txid, vout as u32);
                    let entry = UtxoEntry {
                        amount: output.value.to_sat(),
                        script_pubkey: output.script_pubkey.to_bytes(),
                        height,
                        is_coinbase: false,
                    };
                    intra_block_utxos.insert(outpoint, entry.clone());
                    batch.inserts.push((outpoint, entry));
                }
            }
        }

        // Block-wide sigop cost limit (Bitcoin Core's MAX_BLOCK_SIGOPS_COST).
        if total_sigop_cost > MAX_BLOCK_SIGOPS_COST {
            return Err(CoreError::InvalidTransaction(format!(
                "block sigop cost {total_sigop_cost} exceeds limit {MAX_BLOCK_SIGOPS_COST}"
            )));
        }

        // Verify coinbase value doesn't exceed subsidy + fees
        if !block.txdata.is_empty() {
            let coinbase_value: u64 = block.txdata[0]
                .output
                .iter()
                .map(|o| o.value.to_sat())
                .sum();
            let subsidy = self.params.block_subsidy(height);
            let max_value = subsidy + total_fees;
            if coinbase_value > max_value {
                // Log first 3 non-coinbase tx fee details for debugging
                let mut fee_samples = Vec::new();
                for (i, tx) in block.txdata.iter().enumerate().skip(1).take(3) {
                    let in_total: u64 = tx
                        .input
                        .iter()
                        .filter_map(|inp| {
                            self.utxo_set
                                .get(&inp.previous_output)
                                .ok()
                                .flatten()
                                .map(|u| u.amount)
                        })
                        .sum();
                    let out_total: u64 = tx.output.iter().map(|o| o.value.to_sat()).sum();
                    fee_samples.push(format!("tx{i}:in={in_total},out={out_total}"));
                }
                warn!(
                    height,
                    num_txs = block.txdata.len(),
                    subsidy,
                    total_fees,
                    coinbase_value,
                    max_value,
                    samples = fee_samples.join("; "),
                    block_bytes = bitcoin::consensus::encode::serialize(block).len(),
                    "Coinbase exceeds limit"
                );
                return Err(CoreError::InvalidSubsidy {
                    expected: max_value,
                    got: coinbase_value,
                });
            }
        }

        // Run script verifications in parallel using rayon (with sig cache)
        if !script_checks.is_empty() {
            let cache = &self.sig_cache;
            let result: Result<(), CoreError> = script_checks.par_iter().try_for_each(
                |(tx, vin, all_prevouts, wtxid, enforce_bip110)| {
                    // Per-input flags: BIP-110 enforcement rides on the flag set
                    // (and is part of the sig-cache key) so a grandfathered input
                    // and a non-grandfathered input are cached independently.
                    let mut flags = script_flags;
                    flags.verify_bip110 = *enforce_bip110;
                    if cache.contains(wtxid, *vin, flags) {
                        return Ok(());
                    }
                    script::verify_script(tx, *vin, all_prevouts, flags).map_err(|e| {
                        warn!(
                            wtxid = %wtxid,
                            vin = vin,
                            script_pubkey = %all_prevouts[*vin].script_pubkey,
                            script_sig = %tx.input[*vin].script_sig,
                            "Script verification failed: {}",
                            e
                        );
                        e
                    })?;
                    cache.insert(wtxid, *vin, flags);
                    Ok(())
                },
            );
            result.map_err(|e| CoreError::InvalidScript(format!("script check failed: {e}")))?;
        }

        Ok(batch)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use bitcoin::constants::genesis_block;
    use bitcoin::Network;

    /// Finding 1.2: connect_block must fail CLOSED when the chain context for
    /// the BIP 113 MTP check cannot be loaded (prev header missing from the
    /// index), instead of degrading the timestamp / lock-time checks to
    /// "anything passes". The block can be retried once headers arrive.
    #[test]
    fn test_connect_block_errors_when_mtp_context_missing() {
        let dir = tempfile::tempdir().unwrap();
        let header_index =
            std::sync::Arc::new(HeaderIndex::open(&dir.path().join("headers")).unwrap());
        let utxo_set = std::sync::Arc::new(UtxoSet::open(&dir.path().join("utxo"), None).unwrap());
        let block_store =
            std::sync::Arc::new(BlockStore::open(&dir.path().join("blocks")).unwrap());

        let params = ConsensusParams::regtest();
        let genesis = genesis_block(Network::Regtest);
        let genesis_hash = genesis.block_hash();

        // Deliberately do NOT insert the genesis header: the block connected
        // at height 1 then has no prev header, so the MTP lookup must fail.
        let mut chain =
            ChainState::new(params, header_index, utxo_set, block_store, 0, genesis_hash);

        // Minimal valid coinbase: BIP34 height-1 push (OP_1), padded with
        // OP_0 to the 2-byte scriptSig minimum.
        let coinbase = Transaction {
            version: bitcoin::transaction::Version::ONE,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![bitcoin::TxIn {
                previous_output: OutPoint::null(),
                script_sig: bitcoin::ScriptBuf::from_bytes(vec![0x51, 0x00]),
                sequence: bitcoin::Sequence::MAX,
                witness: bitcoin::Witness::new(),
            }],
            output: vec![TxOut {
                value: bitcoin::Amount::from_sat(50 * 100_000_000),
                script_pubkey: bitcoin::ScriptBuf::new(),
            }],
        };
        let txid = coinbase.compute_txid();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock before unix epoch")
            .as_secs() as u32;
        let mut block = Block {
            header: bitcoin::block::Header {
                version: bitcoin::block::Version::from_consensus(4),
                prev_blockhash: genesis_hash,
                merkle_root: bitcoin::TxMerkleNode::from_raw_hash(txid.to_raw_hash()),
                time: now,
                bits: genesis.header.bits,
                nonce: 0,
            },
            txdata: vec![coinbase],
        };
        // Regtest difficulty: a valid nonce is found within a few tries.
        while block.header.validate_pow(block.header.target()).is_err() {
            block.header.nonce += 1;
        }

        let err = chain
            .connect_block(&block, 1)
            .expect_err("connect_block must error when the MTP context cannot be loaded");
        match err {
            CoreError::ChainContext(msg) => assert!(
                msg.contains("median-time-past"),
                "unexpected storage error message: {msg}"
            ),
            other => panic!("expected CoreError::ChainContext, got {other:?}"),
        }
    }

    /// H1 (2026-07-02 review): disconnect_block must fail CLOSED when the
    /// block's undo record is missing. Treating missing undo as an empty
    /// record removes every output the block created while restoring nothing
    /// it spent — silent UTXO corruption that only surfaces later as spurious
    /// MissingUtxo rejections of valid blocks. The disconnect must error with
    /// the typed `UndoMissing` variant and leave both the UTXO set and the
    /// in-memory tip untouched.
    #[test]
    fn test_disconnect_block_fails_closed_when_undo_missing() {
        let dir = tempfile::tempdir().unwrap();
        let header_index =
            std::sync::Arc::new(HeaderIndex::open(&dir.path().join("headers")).unwrap());
        let utxo_set = std::sync::Arc::new(UtxoSet::open(&dir.path().join("utxo"), None).unwrap());
        let block_store =
            std::sync::Arc::new(BlockStore::open(&dir.path().join("blocks")).unwrap());

        let params = ConsensusParams::regtest();
        let genesis = genesis_block(Network::Regtest);
        let genesis_hash = genesis.block_hash();

        // Insert the genesis header so the height-1 block has MTP context.
        header_index
            .insert_header(
                &genesis_hash,
                &bitcoinpr_storage::StoredHeader {
                    header: genesis.header,
                    height: 0,
                    chain_work: [0u8; 32],
                },
            )
            .unwrap();
        header_index.set_height_hash(0, &genesis_hash).unwrap();

        let mut chain = ChainState::new(
            params,
            header_index,
            utxo_set.clone(),
            block_store,
            0,
            genesis_hash,
        );

        let coinbase = Transaction {
            version: bitcoin::transaction::Version::ONE,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![bitcoin::TxIn {
                previous_output: OutPoint::null(),
                script_sig: bitcoin::ScriptBuf::from_bytes(vec![0x51, 0x00]),
                sequence: bitcoin::Sequence::MAX,
                witness: bitcoin::Witness::new(),
            }],
            output: vec![TxOut {
                value: bitcoin::Amount::from_sat(50 * 100_000_000),
                script_pubkey: bitcoin::ScriptBuf::new(),
            }],
        };
        let txid = coinbase.compute_txid();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock before unix epoch")
            .as_secs() as u32;
        let mut block = Block {
            header: bitcoin::block::Header {
                version: bitcoin::block::Version::from_consensus(4),
                prev_blockhash: genesis_hash,
                merkle_root: bitcoin::TxMerkleNode::from_raw_hash(txid.to_raw_hash()),
                time: now,
                bits: genesis.header.bits,
                nonce: 0,
            },
            txdata: vec![coinbase],
        };
        while block.header.validate_pow(block.header.target()).is_err() {
            block.header.nonce += 1;
        }
        let block_hash = block.block_hash();

        chain
            .connect_block(&block, 1)
            .expect("height-1 block must connect");
        let coinbase_outpoint = OutPoint::new(txid, 0);
        assert!(
            utxo_set.get(&coinbase_outpoint).unwrap().is_some(),
            "coinbase output must be in the UTXO set after connect"
        );

        // Simulate a lost undo record (crash between buffer and flush, manual
        // DB surgery, pre-v2 format edge).
        let hash_bytes: &[u8; 32] = AsRef::<[u8; 32]>::as_ref(&block_hash);
        utxo_set.delete_undo(hash_bytes).unwrap();

        let err = chain
            .disconnect_block(&block, 1)
            .expect_err("disconnect_block must fail closed when undo data is missing");
        match err {
            CoreError::UndoMissing { hash, height } => {
                assert_eq!(hash, block_hash);
                assert_eq!(height, 1);
            }
            other => panic!("expected CoreError::UndoMissing, got {other:?}"),
        }

        // The failed disconnect must not have touched the UTXO set or the tip.
        assert!(
            utxo_set.get(&coinbase_outpoint).unwrap().is_some(),
            "UTXO set must be untouched after a failed disconnect"
        );
        assert_eq!(chain.best_height, 1, "tip height must be unchanged");
        assert_eq!(chain.best_hash, block_hash, "tip hash must be unchanged");
    }
}
