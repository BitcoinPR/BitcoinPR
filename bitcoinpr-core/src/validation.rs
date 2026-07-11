use bitcoin::block::Header;
use bitcoin::blockdata::block::Block;
use bitcoin::hashes::Hash;
use bitcoin::{BlockHash, CompactTarget, Target, Transaction};

use bitcoinpr_storage::{HeaderIndex, StoredHeader};

use crate::consensus::ConsensusParams;
use crate::error::{CoreError, CoreResult};

/// Calculate the work represented by a block header's target.
///
/// Uses Bitcoin Core's exact formula (`GetBlockProof`):
///   work = (~target / (target + 1)) + 1
/// which equals `floor(2^256 / (target + 1))` and always fits in 256 bits.
/// Returns a 32-byte big-endian representation.
///
/// The previous implementation approximated this with u128 limbs (it discarded
/// the low 128 bits of the target in one branch), which could order two chains
/// of near-equal work incorrectly during fork choice. This version is exact.
pub fn calculate_work(target: &Target) -> [u8; 32] {
    let t = target.to_be_bytes();

    // Zero target is not a real PoW target; treat as maximum work.
    if t == [0u8; 32] {
        return [0xff; 32];
    }

    // target + 1. If this overflows, target was 2^256-1 (all 0xff): then
    // ~target == 0, so work = 0/(2^256) + 1 = 1.
    let (t_plus_one, overflow) = u256_add_one(&t);
    if overflow {
        return u256_one();
    }

    // ~target (bitwise NOT over the full 256 bits).
    let mut not_t = [0u8; 32];
    for i in 0..32 {
        not_t[i] = !t[i];
    }

    // quotient = floor(~target / (target + 1)), then + 1.
    let quotient = u256_div(&not_t, &t_plus_one);
    let (work, _) = u256_add_one(&quotient);
    work
}

/// The 256-bit value 1, big-endian.
fn u256_one() -> [u8; 32] {
    let mut v = [0u8; 32];
    v[31] = 1;
    v
}

/// Add 1 to a 256-bit big-endian number. Returns (sum, overflow).
fn u256_add_one(a: &[u8; 32]) -> ([u8; 32], bool) {
    let mut r = *a;
    let mut carry = 1u16;
    for i in (0..32).rev() {
        let sum = r[i] as u16 + carry;
        r[i] = sum as u8;
        carry = sum >> 8;
        if carry == 0 {
            break;
        }
    }
    (r, carry != 0)
}

/// Subtract `b` from `a` (256-bit big-endian), assuming `a >= b`.
fn u256_sub(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut r = [0u8; 32];
    let mut borrow = 0i16;
    for i in (0..32).rev() {
        let diff = a[i] as i16 - b[i] as i16 - borrow;
        if diff < 0 {
            r[i] = (diff + 256) as u8;
            borrow = 1;
        } else {
            r[i] = diff as u8;
            borrow = 0;
        }
    }
    r
}

/// Exact floor division of two 256-bit big-endian numbers via bitwise long
/// division. Returns `floor(num / den)`; if `den` is zero, returns all-0xff.
fn u256_div(num: &[u8; 32], den: &[u8; 32]) -> [u8; 32] {
    if *den == [0u8; 32] {
        return [0xff; 32];
    }
    let mut quotient = [0u8; 32];
    let mut rem = [0u8; 32];

    // Process numerator bits from most-significant to least-significant.
    for bit in (0..256).rev() {
        // rem <<= 1
        let mut carry = 0u8;
        for i in (0..32).rev() {
            let new = (rem[i] << 1) | carry;
            carry = rem[i] >> 7;
            rem[i] = new;
        }
        // Bring in the current numerator bit (bit 0 of rem).
        let nbit = (num[31 - bit / 8] >> (bit % 8)) & 1;
        rem[31] |= nbit;

        // If rem >= den, subtract and set the quotient bit.
        if u256_cmp(&rem, den) != std::cmp::Ordering::Less {
            rem = u256_sub(&rem, den);
            quotient[31 - bit / 8] |= 1 << (bit % 8);
        }
    }
    quotient
}

/// Compare two 256-bit big-endian numbers numerically.
fn u256_cmp(a: &[u8; 32], b: &[u8; 32]) -> std::cmp::Ordering {
    a.cmp(b)
}

/// Add two 256-bit big-endian numbers, returning the sum.
pub fn add_chain_work(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut result = [0u8; 32];
    let mut carry = 0u16;
    for i in (0..32).rev() {
        let sum = a[i] as u16 + b[i] as u16 + carry;
        result[i] = sum as u8;
        carry = sum >> 8;
    }
    result
}

/// Validate a block header against consensus rules.
///
/// Checks: PoW, timestamps, prev_blockhash linkage.
/// Does NOT check difficulty retarget (that requires chain context).
pub fn validate_block_header(
    header: &Header,
    height: u32,
    prev_header: Option<&Header>,
    params: &ConsensusParams,
) -> CoreResult<()> {
    // Signet uses signed blocks (BIP 325), not proof-of-work
    let is_signet = params.signet_challenge.is_some();

    // Check proof of work (skip for signet — block validity comes from challenge script)
    let target = header.target();
    if !is_signet && header.validate_pow(target).is_err() {
        return Err(CoreError::InvalidProofOfWork);
    }

    // Check that target doesn't exceed the PoW limit
    let pow_limit = Target::from_be_bytes(params.pow_limit);
    if target > pow_limit {
        return Err(CoreError::InvalidDifficultyTarget(format!(
            "target {target:?} exceeds pow limit {pow_limit:?}"
        )));
    }

    // Check prev_blockhash
    if let Some(prev) = prev_header {
        let expected_prev_hash = prev.block_hash();
        if header.prev_blockhash != expected_prev_hash {
            return Err(CoreError::InvalidBlockHash {
                expected: expected_prev_hash,
                got: header.prev_blockhash,
            });
        }
    } else if height == 0 {
        // Genesis block - prev_blockhash should be all zeros
        if header.prev_blockhash != BlockHash::all_zeros() {
            return Err(CoreError::InvalidBlockHash {
                expected: BlockHash::all_zeros(),
                got: header.prev_blockhash,
            });
        }
    }

    // Check timestamp: not more than 2 hours in the future, measured against
    // network-adjusted time (Core's GetAdjustedTime). Using the peer-median
    // offset rather than the raw local clock keeps a node with a modestly-wrong
    // clock from rejecting (or over-accepting) otherwise-valid headers. The
    // offset is clamped to ±70 min, so this stays fail-closed: a pre-1970 or
    // far-off clock yields a small/zero `now`, rejecting future-dated blocks.
    let now = crate::time::adjusted_time_secs().max(0) as u32;
    let max_future_time = now + 2 * 60 * 60;
    if header.time > max_future_time {
        return Err(CoreError::InvalidTimestamp(format!(
            "block time {} is more than 2 hours in the future (adjusted now: {})",
            header.time, now
        )));
    }

    Ok(())
}

/// Compute the merkle root from a list of transaction hashes.
pub fn compute_merkle_root(tx_hashes: &[bitcoin::Txid]) -> Option<bitcoin::TxMerkleNode> {
    if tx_hashes.is_empty() {
        return None;
    }
    let leaves: Vec<[u8; 32]> = tx_hashes.iter().map(|txid| *txid.as_ref()).collect();
    Some(bitcoin::TxMerkleNode::from_byte_array(crate::merkle::root(
        &leaves,
    )))
}

/// Verify that a block's merkle root matches its transactions.
pub fn verify_merkle_root(block: &Block) -> CoreResult<()> {
    let tx_hashes: Vec<bitcoin::Txid> = block.txdata.iter().map(|tx| tx.compute_txid()).collect();
    verify_merkle_root_with_txids(block, &tx_hashes)
}

/// Verify merkle root using pre-computed txids (avoids redundant hashing).
///
/// Also enforces the CVE-2012-2459 defense: rejects blocks whose merkle tree is
/// "mutated" (duplicate transactions arranged to leave the root unchanged).
pub fn verify_merkle_root_with_txids(block: &Block, txids: &[bitcoin::Txid]) -> CoreResult<()> {
    let leaves: Vec<[u8; 32]> = txids.iter().map(|t| *t.as_ref()).collect();
    let (computed, mutated) = crate::merkle::root_detecting_mutation(&leaves);
    let computed = computed.ok_or(CoreError::InvalidMerkleRoot)?;

    // CVE-2012-2459: a mutated tree has the right root but duplicate txs.
    if mutated {
        return Err(CoreError::InvalidTransaction(
            "bad-txns-duplicate (CVE-2012-2459: mutated merkle tree)".into(),
        ));
    }

    if bitcoin::TxMerkleNode::from_byte_array(computed) != block.header.merkle_root {
        return Err(CoreError::InvalidMerkleRoot);
    }

    Ok(())
}

/// Maximum money supply in satoshis (21,000,000 BTC). Used for value range checks.
pub const MAX_MONEY: u64 = 21_000_000 * 100_000_000;

/// Context-free transaction sanity checks (Bitcoin Core's `CheckTransaction`).
/// Catches malformed transactions that other validation paths assume away:
/// empty input/output vectors, value overflow / out-of-range amounts, duplicate
/// inputs within one transaction, and null prevouts on non-coinbase inputs.
pub fn check_transaction(tx: &Transaction) -> CoreResult<()> {
    if tx.input.is_empty() {
        return Err(CoreError::InvalidTransaction("bad-txns-vin-empty".into()));
    }
    if tx.output.is_empty() {
        return Err(CoreError::InvalidTransaction("bad-txns-vout-empty".into()));
    }

    // Output values must each be in [0, MAX_MONEY], and so must their sum.
    let mut total: u64 = 0;
    for out in &tx.output {
        let v = out.value.to_sat();
        if v > MAX_MONEY {
            return Err(CoreError::InvalidTransaction(
                "bad-txns-vout-toolarge".into(),
            ));
        }
        total = total
            .checked_add(v)
            .filter(|t| *t <= MAX_MONEY)
            .ok_or_else(|| CoreError::InvalidTransaction("bad-txns-txouttotal-toolarge".into()))?;
    }

    // No duplicate inputs within the same transaction.
    let mut seen = std::collections::HashSet::with_capacity(tx.input.len());
    for inp in &tx.input {
        if !seen.insert(inp.previous_output) {
            return Err(CoreError::InvalidTransaction(
                "bad-txns-inputs-duplicate".into(),
            ));
        }
    }

    // Non-coinbase inputs must reference a real prevout (not null).
    if !tx.is_coinbase() {
        let null = bitcoin::OutPoint::null();
        for inp in &tx.input {
            if inp.previous_output == null {
                return Err(CoreError::InvalidTransaction(
                    "bad-txns-prevout-null".into(),
                ));
            }
        }
    }

    Ok(())
}

/// Validate the block weight doesn't exceed the limit.
pub fn validate_block_weight(block: &Block, params: &ConsensusParams) -> CoreResult<()> {
    let weight = block.weight().to_wu();
    if weight > params.max_block_weight as u64 {
        return Err(CoreError::BlockWeightExceeded {
            weight,
            limit: params.max_block_weight,
        });
    }
    Ok(())
}

/// Calculate the required difficulty target for a block at the given height.
/// This implements the Bitcoin difficulty adjustment algorithm.
pub fn calculate_next_work_required(
    last_retarget_header: &Header,
    current_header: &Header,
    params: &ConsensusParams,
) -> CompactTarget {
    if params.pow_no_retargeting {
        return current_header.bits;
    }

    // Compute the timespan in signed 64-bit: block timestamps may legally go
    // backwards, so `current - last` can be negative. A u32 subtraction would
    // wrap to a huge value (clamped to max_timespan), silently computing the
    // wrong target. Bitcoin Core does this in signed 64-bit, then clamps.
    let min_timespan = params.pow_target_timespan / 4;
    let max_timespan = params.pow_target_timespan * 4;
    let actual_timespan = (current_header.time as i64 - last_retarget_header.time as i64)
        .clamp(min_timespan as i64, max_timespan as i64) as u64;

    // new_target = old_target * actual_timespan / target_timespan
    let old_target = current_header.target();
    let pow_limit = Target::from_be_bytes(params.pow_limit);

    // Use big integer arithmetic via the Target type
    // We work with the raw bytes
    let old_bytes = old_target.to_be_bytes();

    // 256-bit multiply and divide using u64 limbs with carry propagation
    let new_target =
        multiply_target_by_ratio(&old_bytes, actual_timespan, params.pow_target_timespan);

    let new_target = Target::from_be_bytes(new_target);

    // Don't exceed PoW limit
    let final_target = if new_target > pow_limit {
        pow_limit
    } else {
        new_target
    };

    final_target.to_compact_lossy()
}

/// Compute the consensus-required nBits for the block following `prev_hash`
/// (Bitcoin Core's `GetNextWorkRequired`), returning the expected compact target.
///
/// Handles all cases: no-retargeting (regtest), the testnet/testnet4 20-minute
/// minimum-difficulty rule (using `candidate_time`), within-period inheritance of
/// the previous block's bits, and the 2016-block retarget at period boundaries.
/// Returns `None` only when required ancestor headers are missing.
pub fn get_next_work_required(
    header_index: &HeaderIndex,
    params: &ConsensusParams,
    prev_hash: &BlockHash,
    prev_height: u32,
    candidate_time: u32,
) -> Option<u32> {
    get_next_work_required_with(
        &|hash| header_index.get_header(hash).ok().flatten(),
        params,
        prev_hash,
        prev_height,
        candidate_time,
    )
}

/// Like [`get_next_work_required`], but resolves ancestor headers through a
/// caller-supplied lookup instead of the on-disk index. Header sync validates
/// headers in batches before inserting them, so ancestors of a candidate may
/// live in the in-memory batch rather than the `HeaderIndex`; the lookup lets
/// the caller layer the batch over the index.
pub fn get_next_work_required_with(
    lookup: &dyn Fn(&BlockHash) -> Option<StoredHeader>,
    params: &ConsensusParams,
    prev_hash: &BlockHash,
    prev_height: u32,
    candidate_time: u32,
) -> Option<u32> {
    let prev = lookup(prev_hash)?;
    let next_height = prev_height + 1;

    if params.pow_no_retargeting {
        return Some(prev.header.bits.to_consensus());
    }

    let interval = params.difficulty_adjustment_interval();

    // Not on a retarget boundary.
    if next_height % interval != 0 {
        if params.pow_allow_min_difficulty_blocks {
            // Testnet rule: if the candidate is >2× the target spacing after the
            // previous block, the minimum-difficulty (pow_limit) target is allowed.
            let pow_limit_bits = Target::from_be_bytes(params.pow_limit).to_compact_lossy();
            if candidate_time > prev.header.time + (params.pow_target_spacing as u32) * 2 {
                return Some(pow_limit_bits.to_consensus());
            }
            // Otherwise inherit the bits of the last block that was NOT a
            // min-difficulty block, walking back but never across a retarget
            // boundary (mirrors Core's GetNextWorkRequired testnet branch).
            let mut scan = prev;
            while scan.height % interval != 0 && scan.header.bits == pow_limit_bits {
                match lookup(&scan.header.prev_blockhash) {
                    Some(h) => scan = h,
                    // A missing header here is deliberately NOT fatal: this
                    // scan only chooses WHICH already-accepted bits to
                    // inherit on a min-difficulty network. Breaking early
                    // inherits `scan`'s bits (pow_limit, by the loop
                    // condition) — a target this network already permits
                    // outright via the 20-minute rule — so the fallback
                    // can't admit work the network considers invalid.
                    None => break,
                }
            }
            return Some(scan.header.bits.to_consensus());
        }
        // Non-min-difficulty network: bits are unchanged within a period.
        return Some(prev.header.bits.to_consensus());
    }

    // Retarget boundary: recompute from the first and last blocks of the period.
    // The period-start header is resolved by walking prev links back from
    // `prev` (Core's pindexLast->GetAncestor), NOT via the active chain's
    // height → hash index: when validating a side-chain block during a reorg
    // whose fork point predates the retarget boundary, the height index still
    // points at the OLD chain's block at that height, which would compute the
    // expected bits from the wrong header.
    let period_start_height = next_height - interval;
    let mut start = prev.clone();
    while start.height > period_start_height {
        match lookup(&start.header.prev_blockhash) {
            // Defensive: stored heights must strictly decrease along prev
            // links; a corrupt index could otherwise loop forever (mirrors
            // HeaderIndex::get_ancestor).
            Some(parent) if parent.height < start.height => start = parent,
            _ => return None,
        }
    }
    if start.height != period_start_height {
        return None;
    }
    Some(calculate_next_work_required(&start.header, &prev.header, params).to_consensus())
}

/// Convert a compact target (nBits) to a floating-point difficulty value.
/// Difficulty 1.0 corresponds to the easiest target (0x1d00ffff on mainnet).
pub fn compact_target_to_difficulty(bits: u32) -> f64 {
    let exponent = ((bits >> 24) & 0xff) as i32;
    let mantissa = (bits & 0x00ffffff) as f64;
    if mantissa == 0.0 || exponent == 0 {
        return 1.0;
    }
    let diff1_mantissa: f64 = 0x00ffff_u32 as f64;
    let diff1_exp: i32 = 0x1d;

    let ratio = diff1_mantissa / mantissa;
    let exp_diff = diff1_exp - exponent;
    ratio * (256.0_f64).powi(exp_diff)
}

/// Multiply a 256-bit target by a ratio (numerator/denominator).
fn multiply_target_by_ratio(target: &[u8; 32], numerator: u64, denominator: u64) -> [u8; 32] {
    // Convert target to a big integer represented as u64 limbs (little-endian)
    let mut limbs = [0u64; 4];
    for (i, limb) in limbs.iter_mut().enumerate() {
        let offset = 32 - (i + 1) * 8;
        *limb = u64::from_be_bytes(
            target[offset..offset + 8]
                .try_into()
                .expect("fixed-size slice"),
        );
    }

    // Multiply by numerator (can overflow into next limb)
    let mut carry = 0u128;
    for limb in limbs.iter_mut() {
        let product = (*limb as u128) * (numerator as u128) + carry;
        *limb = product as u64;
        carry = product >> 64;
    }

    // Divide by denominator
    let mut remainder = 0u128;
    for limb in limbs.iter_mut().rev() {
        let dividend = (remainder << 64) | (*limb as u128);
        *limb = (dividend / denominator as u128) as u64;
        remainder = dividend % denominator as u128;
    }

    // Convert back to big-endian bytes
    let mut result = [0u8; 32];
    for (i, limb) in limbs.iter().enumerate() {
        let offset = 32 - (i + 1) * 8;
        result[offset..offset + 8].copy_from_slice(&limb.to_be_bytes());
    }
    result
}

/// Validate that a coinbase transaction is correctly formed.
pub fn validate_coinbase(block: &Block, height: u32, params: &ConsensusParams) -> CoreResult<()> {
    if block.txdata.is_empty() {
        return Err(CoreError::InvalidCoinbase(
            "block has no transactions".into(),
        ));
    }

    let coinbase = &block.txdata[0];

    // Coinbase must have exactly one input with null outpoint
    if !coinbase.is_coinbase() {
        return Err(CoreError::InvalidCoinbase(
            "first transaction is not coinbase".into(),
        ));
    }

    // CheckTransaction rule (always active, independent of BIP34):
    // coinbase scriptSig must be 2–100 bytes.
    // This is enforced by Bitcoin Core and Libbitcoin regardless of BIP34 height.
    let script_len = coinbase.input[0].script_sig.as_bytes().len();
    if !(2..=100).contains(&script_len) {
        return Err(CoreError::InvalidCoinbase(format!(
            "coinbase script too small or large: {script_len} bytes (must be 2–100)"
        )));
    }

    // BIP 34: coinbase must include block height (after activation)
    if height >= params.bip34_height {
        let script = &coinbase.input[0].script_sig;
        let script_bytes = script.as_bytes();
        if script_bytes.is_empty() {
            return Err(CoreError::InvalidCoinbase(
                "BIP 34: coinbase scriptSig is empty".into(),
            ));
        }

        // BIP 34 height encoding follows Bitcoin Core's `CScript() << height`:
        //   OP_0 (0x00)               → height 0
        //   OP_1..OP_16 (0x51..0x60)  → heights 1..16
        //   push-data 0x01..0x09 + LE → heights 17+
        //
        // All implementations also pad small heights to ≥ 2 bytes with OP_0 (0x00),
        // but the BIP34 check only looks at the PREFIX (first element), so additional
        // trailing bytes are ignored here.
        let first = script_bytes[0];
        let encoded_height = if first == 0x00 {
            // OP_0 → height 0
            0u32
        } else if (0x51..=0x60).contains(&first) {
            // OP_1..OP_16 → heights 1..16
            (first - 0x50) as u32
        } else if (0x01..=0x09).contains(&first) {
            // Push-data: first byte is push length, then LE height bytes
            let push_len = first as usize;
            if script_bytes.len() < 1 + push_len {
                return Err(CoreError::InvalidCoinbase(
                    "BIP 34: invalid height encoding (truncated push)".into(),
                ));
            }
            // High bit of last data byte signals positive sign extension (0x00 pad).
            let data = &script_bytes[1..1 + push_len];
            let value_bytes = if data.last().copied() == Some(0x00) && push_len > 1 {
                &data[..push_len - 1]
            } else {
                data
            };
            if value_bytes.len() > 4 {
                return Err(CoreError::InvalidCoinbase(
                    "BIP 34: height too large".into(),
                ));
            }
            let mut height_bytes = [0u8; 4];
            height_bytes[..value_bytes.len()].copy_from_slice(value_bytes);
            u32::from_le_bytes(height_bytes)
        } else {
            return Err(CoreError::InvalidCoinbase(format!(
                "BIP 34: unsupported height encoding (first byte 0x{first:02x})"
            )));
        };

        if encoded_height != height {
            return Err(CoreError::InvalidCoinbase(format!(
                "BIP 34: height mismatch: encoded={encoded_height}, expected={height}"
            )));
        }
    }

    // Note: coinbase value vs subsidy+fees is checked in validate_transactions()
    // after all transaction fees have been computed.

    Ok(())
}

/// BIP 141: Validate witness commitment in a SegWit block.
/// BIP 144: witness data is carried in the segregated-witness block
/// serialization that this commitment binds.
///
/// The coinbase transaction must contain an output whose scriptPubKey is:
///   OP_RETURN <0xaa21a9ed> <32-byte commitment>
///
/// The commitment is SHA256d(witness_root || witness_nonce), where:
/// - witness_root is the merkle root of all wtxids (coinbase wtxid = 0x00..00)
/// - witness_nonce is the coinbase's first witness item (32 bytes)
pub fn validate_witness_commitment(block: &Block) -> CoreResult<()> {
    // A block needs a witness commitment only if any transaction has witness data
    let has_witness = block
        .txdata
        .iter()
        .skip(1)
        .any(|tx| tx.input.iter().any(|input| !input.witness.is_empty()));

    if !has_witness {
        return Ok(()); // No witness data → no commitment needed
    }

    let coinbase = &block.txdata[0];

    // Find the witness commitment output (last OP_RETURN starting with 0xaa21a9ed)
    let commitment_output = coinbase.output.iter().rev().find(|output| {
        let script = output.script_pubkey.as_bytes();
        script.len() >= 38
                && script[0] == 0x6a // OP_RETURN
                && script[1] == 0x24 // push 36 bytes
                && script[2..6] == [0xaa, 0x21, 0xa9, 0xed]
    });

    let commitment_output = match commitment_output {
        Some(o) => o,
        None => {
            return Err(CoreError::InvalidTransaction(
                "BIP 141: missing witness commitment in coinbase".into(),
            ));
        }
    };

    let expected_commitment = &commitment_output.script_pubkey.as_bytes()[6..38];

    // Get the witness nonce from coinbase (first witness item, must be 32 bytes)
    let witness_nonce = if !coinbase.input.is_empty()
        && !coinbase.input[0].witness.is_empty()
        && coinbase.input[0].witness[0].len() == 32
    {
        coinbase.input[0].witness[0].to_vec()
    } else {
        vec![0u8; 32] // default nonce
    };

    // Compute witness root: merkle tree of wtxids, with coinbase wtxid = 0
    let mut wtxids: Vec<[u8; 32]> = Vec::with_capacity(block.txdata.len());
    wtxids.push([0u8; 32]); // Coinbase wtxid is always 0x00..00

    for tx in block.txdata.iter().skip(1) {
        let wtxid = tx.compute_wtxid();
        wtxids.push(*AsRef::<[u8; 32]>::as_ref(&wtxid));
    }

    // Build merkle tree from wtxids
    let witness_root = crate::merkle::root(&wtxids);

    // Compute commitment: SHA256d(witness_root || witness_nonce)
    use bitcoin::hashes::{sha256d, Hash as _};
    let mut preimage = [0u8; 64];
    preimage[..32].copy_from_slice(&witness_root);
    preimage[32..].copy_from_slice(&witness_nonce);
    let commitment = sha256d::Hash::hash(&preimage);

    if AsRef::<[u8]>::as_ref(&commitment) != expected_commitment {
        return Err(CoreError::InvalidTransaction(
            "BIP 141: witness commitment mismatch".into(),
        ));
    }

    Ok(())
}

/// Compute the median time of the previous 11 blocks (BIP 113).
/// Used for lock-time validation instead of the block's own timestamp.
pub fn get_median_time_past(header_index: &HeaderIndex, tip_hash: &BlockHash) -> Option<u32> {
    let mut times = Vec::with_capacity(11);
    let mut current_hash = *tip_hash;

    for _ in 0..11 {
        match header_index.get_header(&current_hash) {
            Ok(Some(stored)) => {
                times.push(stored.header.time);
                current_hash = stored.header.prev_blockhash;
            }
            _ => break,
        }
    }

    if times.is_empty() {
        return None;
    }

    times.sort_unstable();
    Some(times[times.len() / 2])
}

/// Check whether a transaction is final (BIP 113: `block_time` is the
/// median-time-past). A tx is final if its nLockTime is zero, the locktime
/// threshold (by height or time) has passed, or every input sequence is final.
/// Mirrors Bitcoin Core's `IsFinalTx`.
pub fn is_final_tx(tx: &Transaction, height: u32, block_time: u32) -> bool {
    let lt = tx.lock_time.to_consensus_u32();
    if lt == 0 {
        return true;
    }
    // Below the threshold nLockTime is a block height; at/above it, a unix time.
    const LOCKTIME_THRESHOLD: u32 = 500_000_000;
    let threshold = if lt < LOCKTIME_THRESHOLD {
        height
    } else {
        block_time
    };
    if lt < threshold {
        return true;
    }
    // Locktime not yet satisfied: final only if every input opted out via a
    // final sequence number (0xffffffff).
    tx.input.iter().all(|i| i.sequence.0 == 0xffff_ffff)
}

/// Validate BIP 68 relative lock-time for a transaction's inputs.
/// Returns an error if any input's relative lock-time hasn't been satisfied.
///
/// For each input with a relative lock-time (sequence bit 31 not set):
/// - If bit 22 is set: time-based, value is in 512-second units
/// - If bit 22 is clear: block-based, value is number of blocks
pub fn validate_sequence_locks(
    tx: &Transaction,
    input_heights: &[u32], // height at which each input's prev output was confirmed
    input_times: &[u32],   // MTP at which each input's prev output was confirmed
    block_height: u32,
    block_mtp: u32,
) -> CoreResult<()> {
    // BIP 68: version 2+ transactions only
    if tx.version.0 < 2 {
        return Ok(());
    }

    for (i, input) in tx.input.iter().enumerate() {
        let sequence = input.sequence.0;

        // If disable flag (bit 31) is set, skip this input
        if sequence & (1 << 31) != 0 {
            continue;
        }

        let masked_value = sequence & 0xffff;
        let is_time_based = sequence & (1 << 22) != 0;

        if is_time_based {
            // Time-based: value is in 512-second units
            let required_time = input_times.get(i).copied().unwrap_or(0) + masked_value * 512;
            if block_mtp < required_time {
                return Err(CoreError::InvalidTransaction(format!(
                    "BIP 68: input {i} time lock not satisfied (need MTP >= {required_time}, have {block_mtp})"
                )));
            }
        } else {
            // Block-based: value is number of blocks
            let required_height = input_heights.get(i).copied().unwrap_or(0) + masked_value;
            if block_height < required_height {
                return Err(CoreError::InvalidTransaction(format!(
                    "BIP 68: input {i} height lock not satisfied (need >= {required_height}, have {block_height})"
                )));
            }
        }
    }

    Ok(())
}

/// Compute the BIP 68 lock point of a transaction: the minimum block height
/// and minimum median-time-past at which every relative lock-time is
/// satisfied. Returns `(0, 0)` for transactions with no active relative locks
/// (version < 2, or all inputs carry the disable bit).
///
/// `input_heights` / `input_times` use the same per-input semantics as
/// [`validate_sequence_locks`]. The mempool stores the result on each entry
/// (Bitcoin Core's `LockPoints`) so block-template assembly can re-check
/// BIP 68 finality at any later tip without re-reading the UTXO set.
pub fn sequence_lock_points(
    tx: &Transaction,
    input_heights: &[u32],
    input_times: &[u32],
) -> (u32, u32) {
    if tx.version.0 < 2 {
        return (0, 0);
    }

    let mut min_height = 0u32;
    let mut min_time = 0u32;
    for (i, input) in tx.input.iter().enumerate() {
        let sequence = input.sequence.0;
        if sequence & (1 << 31) != 0 {
            continue;
        }
        let masked_value = sequence & 0xffff;
        if sequence & (1 << 22) != 0 {
            // Time-based: value is in 512-second units past the prevout's MTP.
            let required = input_times.get(i).copied().unwrap_or(0) + masked_value * 512;
            min_time = min_time.max(required);
        } else {
            // Block-based: value is a number of blocks past the prevout's height.
            let required = input_heights.get(i).copied().unwrap_or(0) + masked_value;
            min_height = min_height.max(required);
        }
    }
    (min_height, min_time)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use bitcoin::constants::genesis_block;
    use bitcoin::Network;

    #[test]
    fn test_validate_genesis_header() {
        let params = ConsensusParams::mainnet();
        let genesis = genesis_block(Network::Bitcoin);

        let result = validate_block_header(&genesis.header, 0, None, &params);
        assert!(result.is_ok(), "Genesis header should be valid: {result:?}");
    }

    #[test]
    fn test_verify_genesis_merkle_root() {
        let genesis = genesis_block(Network::Bitcoin);
        let result = verify_merkle_root(&genesis);
        assert!(
            result.is_ok(),
            "Genesis merkle root should be valid: {result:?}"
        );
    }

    #[test]
    fn test_validate_genesis_weight() {
        let params = ConsensusParams::mainnet();
        let genesis = genesis_block(Network::Bitcoin);
        let result = validate_block_weight(&genesis, &params);
        assert!(result.is_ok());
    }

    #[test]
    fn test_compute_merkle_root_single() {
        use bitcoin::hashes::Hash;
        let txid = bitcoin::Txid::all_zeros();
        let root = compute_merkle_root(&[txid]).unwrap();
        // For a single tx, merkle root equals the txid
        assert_eq!(AsRef::<[u8]>::as_ref(&root), AsRef::<[u8]>::as_ref(&txid));
    }

    #[test]
    fn test_multiply_target_by_ratio() {
        // Simple test: multiply by 1 (identity)
        let target = [0u8; 32];
        let result = multiply_target_by_ratio(&target, 1, 1);
        assert_eq!(result, target);

        // Multiply by 2
        let mut target = [0u8; 32];
        target[31] = 100;
        let result = multiply_target_by_ratio(&target, 2, 1);
        assert_eq!(result[31], 200);

        // Divide by 2
        let result = multiply_target_by_ratio(&target, 1, 2);
        assert_eq!(result[31], 50);
    }

    #[test]
    fn test_validate_coinbase_genesis() {
        let params = ConsensusParams::mainnet();
        let genesis = genesis_block(Network::Bitcoin);
        // Genesis block is before BIP34, so height check is skipped
        let result = validate_coinbase(&genesis, 0, &params);
        assert!(
            result.is_ok(),
            "Genesis coinbase should be valid: {result:?}"
        );
    }

    #[test]
    fn test_calculate_work() {
        // Genesis block target (== mainnet pow_limit == the difficulty-1 target).
        let genesis = genesis_block(Network::Bitcoin);
        let work = calculate_work(&genesis.header.target());
        assert_ne!(work, [0u8; 32]);

        // Genesis target equals the pow_limit, so their work is identical.
        let pow_limit = Target::from_be_bytes(ConsensusParams::mainnet().pow_limit);
        assert_eq!(work, calculate_work(&pow_limit));

        // A harder (smaller) target than difficulty-1 must produce more work.
        let harder = Target::from_compact(bitcoin::CompactTarget::from_consensus(0x1c00ffff));
        assert!(
            calculate_work(&harder) > work,
            "harder target should have more work"
        );
    }

    #[test]
    fn test_calculate_work_difficulty_one() {
        // The difficulty-1 target is the genesis block's target (0xFFFF·2^208,
        // i.e. compact 0x1d00ffff). Its exact chain work is the well-known
        // 0x100010001 (== 4295032833) — the value Bitcoin Core reports as the
        // genesis block's chainwork. This precisely checks the 256-bit division
        // is exact, not approximate. (Note: this is NOT pow_limit, which is the
        // maximum target 2^224-1 and has work exactly 2^32.)
        let genesis = genesis_block(Network::Bitcoin);
        let work = calculate_work(&genesis.header.target());
        let mut expected = [0u8; 32];
        // 0x1_0001_0001, big-endian in the low 5 bytes.
        expected[27] = 0x01;
        expected[29] = 0x01;
        expected[31] = 0x01;
        assert_eq!(
            work, expected,
            "difficulty-1 work must be exactly 0x100010001"
        );

        // Mainnet pow_limit IS the difficulty-1 target, so its work matches.
        let pow_limit = Target::from_be_bytes(ConsensusParams::mainnet().pow_limit);
        assert_eq!(
            calculate_work(&pow_limit),
            expected,
            "pow_limit == diff1 target"
        );

        // Sanity: the target 2^224-1 has work exactly 2^32 (= 2^256 / 2^224).
        let mut big = [0u8; 32];
        for b in big.iter_mut().skip(4) {
            *b = 0xff;
        }
        let big_work = calculate_work(&Target::from_be_bytes(big));
        let mut two_pow_32 = [0u8; 32];
        two_pow_32[27] = 0x01;
        assert_eq!(big_work, two_pow_32, "work(2^224-1) must be exactly 2^32");
    }

    #[test]
    fn test_u256_div_basic() {
        // 10 / 3 == 3
        let mut a = [0u8; 32];
        a[31] = 10;
        let mut b = [0u8; 32];
        b[31] = 3;
        let q = u256_div(&a, &b);
        let mut three = [0u8; 32];
        three[31] = 3;
        assert_eq!(q, three);

        // (2^128) / (2^64) == 2^64 — exercises cross-limb shifting.
        let mut num = [0u8; 32];
        num[15] = 1; // 2^128
        let mut den = [0u8; 32];
        den[23] = 1; // 2^64
        let q = u256_div(&num, &den);
        let mut expected = [0u8; 32];
        expected[23] = 1; // 2^64
        assert_eq!(q, expected);
    }

    #[test]
    fn test_calculate_next_work_required_clamps() {
        use bitcoin::block::Version as BVer;
        use bitcoin::hashes::Hash as _;
        use bitcoin::CompactTarget;
        let params = ConsensusParams::mainnet();
        let mk = |time: u32, bits: u32| Header {
            version: BVer::from_consensus(0x20000000),
            prev_blockhash: BlockHash::all_zeros(),
            merkle_root: bitcoin::TxMerkleNode::all_zeros(),
            time,
            bits: CompactTarget::from_consensus(bits),
            nonce: 0,
        };
        // Start from a target much harder than difficulty-1 so the ×4 easing in
        // the long-timespan case stays below the pow_limit cap and is observable.
        let start_bits = 0x1b0404cb; // a real historical mainnet difficulty
        let start_target = Target::from_compact(CompactTarget::from_consensus(start_bits));
        let first = mk(0, start_bits);

        // Exact target timespan ⇒ difficulty unchanged.
        let last_exact = mk(params.pow_target_timespan as u32, start_bits);
        let nb = calculate_next_work_required(&first, &last_exact, &params);
        assert_eq!(nb.to_consensus(), start_bits);

        // Very short timespan ⇒ clamped to ×4 difficulty ⇒ harder (smaller target).
        let last_short = mk(1, start_bits);
        let nb_short = calculate_next_work_required(&first, &last_short, &params);
        assert!(
            Target::from_compact(nb_short) < start_target,
            "short timespan must raise difficulty"
        );

        // Very long timespan ⇒ easier (bigger target), but never above pow_limit.
        let last_long = mk(params.pow_target_timespan as u32 * 100, start_bits);
        let nb_long = calculate_next_work_required(&first, &last_long, &params);
        assert!(
            Target::from_compact(nb_long) > start_target,
            "long timespan must lower difficulty"
        );
        assert!(
            Target::from_compact(nb_long) <= Target::from_be_bytes(params.pow_limit),
            "long timespan must not exceed pow_limit"
        );
    }

    #[test]
    fn test_merkle_mutation_detection() {
        let a = [1u8; 32];
        let b = [2u8; 32];
        let c = [3u8; 32];

        // Honest 3-leaf tree: not mutated.
        let (root3, m3) = crate::merkle::root_detecting_mutation(&[a, b, c]);
        assert!(!m3);

        // CVE-2012-2459: presenting the odd trailing leaf as two real leaves
        // [a,b,c,c] yields the SAME root but must be flagged as mutated.
        let (root4, m4) = crate::merkle::root_detecting_mutation(&[a, b, c, c]);
        assert!(m4, "duplicated trailing pair must be flagged mutated");
        assert_eq!(root3, root4, "mutated tree reproduces the honest root");

        // Even tree of distinct leaves: not mutated.
        let (_, m2) = crate::merkle::root_detecting_mutation(&[a, b]);
        assert!(!m2);

        // Single leaf: root == leaf, not mutated.
        let (r1, m1) = crate::merkle::root_detecting_mutation(&[a]);
        assert_eq!(r1, Some(a));
        assert!(!m1);
    }

    #[test]
    fn test_check_transaction() {
        use bitcoin::absolute::LockTime;
        use bitcoin::hashes::Hash as _;
        use bitcoin::transaction::Version;
        use bitcoin::{
            Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness,
        };

        let op = OutPoint::new(Txid::from_byte_array([7u8; 32]), 0);
        let good_in = TxIn {
            previous_output: op,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        };
        let good_out = TxOut {
            value: Amount::from_sat(1000),
            script_pubkey: ScriptBuf::new(),
        };
        let mk = |input: Vec<TxIn>, output: Vec<TxOut>| Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input,
            output,
        };

        assert!(
            check_transaction(&mk(vec![], vec![good_out.clone()])).is_err(),
            "empty vin"
        );
        assert!(
            check_transaction(&mk(vec![good_in.clone()], vec![])).is_err(),
            "empty vout"
        );
        assert!(
            check_transaction(&mk(
                vec![good_in.clone(), good_in.clone()],
                vec![good_out.clone()]
            ))
            .is_err(),
            "duplicate inputs"
        );
        let big = TxOut {
            value: Amount::from_sat(MAX_MONEY + 1),
            script_pubkey: ScriptBuf::new(),
        };
        assert!(
            check_transaction(&mk(vec![good_in.clone()], vec![big])).is_err(),
            "value > MAX_MONEY"
        );
        // A lone null input makes a tx a coinbase (which is allowed). To exercise
        // the non-coinbase null-prevout rule, use a second (non-null) input so the
        // tx isn't classified as coinbase.
        let null_in = TxIn {
            previous_output: OutPoint::null(),
            ..good_in.clone()
        };
        let in2 = TxIn {
            previous_output: OutPoint::new(Txid::from_byte_array([8u8; 32]), 0),
            ..good_in.clone()
        };
        assert!(
            check_transaction(&mk(vec![null_in, in2], vec![good_out.clone()])).is_err(),
            "null prevout"
        );
        assert!(
            check_transaction(&mk(vec![good_in], vec![good_out])).is_ok(),
            "valid tx"
        );
    }

    #[test]
    fn test_add_chain_work() {
        let a = [0u8; 32];
        let b = [0u8; 32];
        let result = add_chain_work(&a, &b);
        assert_eq!(result, [0u8; 32]);

        let mut a = [0u8; 32];
        a[31] = 100;
        let mut b = [0u8; 32];
        b[31] = 50;
        let result = add_chain_work(&a, &b);
        assert_eq!(result[31], 150);

        // Test carry
        let mut a = [0u8; 32];
        a[31] = 200;
        let mut b = [0u8; 32];
        b[31] = 100;
        let result = add_chain_work(&a, &b);
        assert_eq!(result[31], 44); // (200+100) % 256 = 44
        assert_eq!(result[30], 1); // carry
    }

    #[test]
    fn test_validate_sequence_locks_v1_tx() {
        // Version 1 transactions skip BIP 68 checks
        let tx = bitcoin::Transaction {
            version: bitcoin::transaction::Version(1),
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![bitcoin::TxIn {
                previous_output: bitcoin::OutPoint::null(),
                script_sig: bitcoin::ScriptBuf::new(),
                sequence: bitcoin::Sequence(0), // would fail BIP 68 if checked
                witness: bitcoin::Witness::new(),
            }],
            output: vec![],
        };
        let result = validate_sequence_locks(&tx, &[0], &[0], 100, 1000);
        assert!(result.is_ok(), "v1 tx should skip BIP 68");
    }

    #[test]
    fn test_validate_sequence_locks_height_based() {
        let tx = bitcoin::Transaction {
            version: bitcoin::transaction::Version(2),
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![bitcoin::TxIn {
                previous_output: bitcoin::OutPoint::null(),
                script_sig: bitcoin::ScriptBuf::new(),
                sequence: bitcoin::Sequence(10), // 10 blocks relative lock
                witness: bitcoin::Witness::new(),
            }],
            output: vec![],
        };

        // Input confirmed at height 100, need height >= 110
        let result = validate_sequence_locks(&tx, &[100], &[0], 109, 0);
        assert!(result.is_err(), "should fail: 109 < 110");

        let result = validate_sequence_locks(&tx, &[100], &[0], 110, 0);
        assert!(result.is_ok(), "should pass: 110 >= 110");
    }

    #[test]
    fn test_validate_sequence_locks_disabled() {
        let tx = bitcoin::Transaction {
            version: bitcoin::transaction::Version(2),
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![bitcoin::TxIn {
                previous_output: bitcoin::OutPoint::null(),
                script_sig: bitcoin::ScriptBuf::new(),
                sequence: bitcoin::Sequence(0x80000000), // disable flag set
                witness: bitcoin::Witness::new(),
            }],
            output: vec![],
        };
        let result = validate_sequence_locks(&tx, &[0], &[0], 0, 0);
        assert!(result.is_ok(), "disabled sequence lock should pass");
    }

    // ---- get_next_work_required: retarget ancestry / missing context ------

    /// Build a minimal header linking to `prev`.
    fn mk_header(prev: BlockHash, time: u32, bits: u32, nonce: u32) -> Header {
        Header {
            version: bitcoin::block::Version::from_consensus(4),
            prev_blockhash: prev,
            merkle_root: bitcoin::TxMerkleNode::all_zeros(),
            time,
            bits: CompactTarget::from_consensus(bits),
            nonce,
        }
    }

    /// Insert a 7-block chain (heights 1..=7) anchored at `anchor`, with block
    /// times `t0 + i * spacing`. Returns the (hash, header) of each block.
    /// `insert_header` also writes the height → hash index, so the chain
    /// inserted LAST owns the index (i.e. is the "active" chain).
    fn insert_chain(
        index: &HeaderIndex,
        anchor: BlockHash,
        t0: u32,
        spacing: u32,
        bits: u32,
        nonce_base: u32,
    ) -> Vec<(BlockHash, Header)> {
        let mut prev = anchor;
        let mut out = Vec::new();
        for i in 1..=7u32 {
            let header = mk_header(prev, t0 + i * spacing, bits, nonce_base + i);
            let hash = header.block_hash();
            index
                .insert_header(
                    &hash,
                    &bitcoinpr_storage::StoredHeader {
                        header,
                        height: i,
                        chain_work: [0u8; 32],
                    },
                )
                .unwrap();
            prev = hash;
            out.push((hash, header));
        }
        out
    }

    /// Mainnet-style params with a 4-block difficulty adjustment interval.
    fn small_interval_params() -> ConsensusParams {
        let mut params = ConsensusParams::mainnet();
        params.pow_target_timespan = 4 * 600; // interval = 2400 / 600 = 4
        assert_eq!(params.difficulty_adjustment_interval(), 4);
        params
    }

    /// Finding 1.3: at a retarget boundary the period-start header must be the
    /// ancestor of the chain being VALIDATED, not whatever the active chain's
    /// height → hash index points at — they diverge when a side-chain block's
    /// fork point predates the boundary (reorg validation).
    #[test]
    fn test_get_next_work_required_uses_validated_chains_own_ancestor() {
        let dir = tempfile::tempdir().unwrap();
        let index = HeaderIndex::open(dir.path()).unwrap();
        let params = small_interval_params();

        let anchor = BlockHash::all_zeros();
        let t0 = 1_700_000_000u32;
        let bits = 0x1c00ffffu32;

        // Side chain B (the chain being validated), forked at the anchor.
        let chain_b = insert_chain(&index, anchor, t0, 600, bits, 1000);
        // Active chain A inserted second, so the height index points at it.
        let chain_a = insert_chain(&index, anchor, t0, 60, bits, 2000);

        let (b7_hash, b7) = chain_b[6];
        let (_, b4) = chain_b[3];
        let (a4_hash, a4) = chain_a[3];

        // Sanity: the height index resolves the period-start height (4) to
        // chain A's block — the WRONG header from chain B's perspective.
        assert_eq!(index.get_hash_at_height(4).unwrap().unwrap(), a4_hash);

        // Validate the block at height 8 on chain B: a retarget boundary
        // (interval 4), period start at height 4.
        let got = get_next_work_required(&index, &params, &b7_hash, 7, b7.time + 600)
            .expect("chain context is fully available");
        let expected = calculate_next_work_required(&b4, &b7, &params).to_consensus();
        let wrong = calculate_next_work_required(&a4, &b7, &params).to_consensus();
        assert_ne!(
            expected, wrong,
            "test setup must make the two period-start candidates disagree"
        );
        assert_eq!(
            got, expected,
            "expected bits must come from the validated chain's own ancestor"
        );
    }

    /// Finding 1.2/1.3: missing ancestor headers must yield `None` (which the
    /// connect_block caller turns into an error), never a silently-skipped or
    /// wrongly-computed check.
    #[test]
    fn test_get_next_work_required_missing_ancestors_returns_none() {
        let dir = tempfile::tempdir().unwrap();
        let index = HeaderIndex::open(dir.path()).unwrap();
        let params = small_interval_params();

        // Unknown prev header → None.
        assert!(
            get_next_work_required(&index, &params, &BlockHash::all_zeros(), 7, 0).is_none(),
            "unknown prev header must yield None"
        );

        // Chain with a hole: heights 5..=7 present, but the period-start
        // ancestor at height 4 was never inserted. The ancestor walk for the
        // boundary at height 8 must propagate None instead of falling back.
        let t0 = 1_700_000_000u32;
        let bits = 0x1c00ffffu32;
        let missing_h4 = mk_header(BlockHash::all_zeros(), t0, bits, 999).block_hash();
        let mut prev = missing_h4;
        for i in 5..=7u32 {
            let header = mk_header(prev, t0 + i * 600, bits, i);
            let hash = header.block_hash();
            index
                .insert_header(
                    &hash,
                    &bitcoinpr_storage::StoredHeader {
                        header,
                        height: i,
                        chain_work: [0u8; 32],
                    },
                )
                .unwrap();
            prev = hash;
        }
        assert!(
            get_next_work_required(&index, &params, &prev, 7, t0 + 8 * 600).is_none(),
            "a hole below the retarget boundary must yield None"
        );
    }
}

/// Property tests (Phase 6, 2026-07-02 review): the hand-rolled u256
/// arithmetic is deliberate (exact Core-parity chainwork) — these pin it
/// against `num-bigint` as an independent oracle.
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod u256_proptests {
    use super::*;
    use num_bigint::BigUint;
    use proptest::prelude::*;

    fn to_big(bytes: &[u8; 32]) -> BigUint {
        BigUint::from_bytes_be(bytes)
    }

    fn from_big(v: &BigUint) -> [u8; 32] {
        let bytes = v.to_bytes_be();
        assert!(bytes.len() <= 32, "oracle value exceeds 256 bits");
        let mut out = [0u8; 32];
        out[32 - bytes.len()..].copy_from_slice(&bytes);
        out
    }

    proptest! {
        #[test]
        fn add_one_matches_bigint(a in proptest::array::uniform32(any::<u8>())) {
            let (sum, overflow) = u256_add_one(&a);
            let expected = to_big(&a) + 1u32;
            let wrapped = expected.clone() % (BigUint::from(1u8) << 256);
            prop_assert_eq!(to_big(&sum), wrapped);
            prop_assert_eq!(overflow, expected.bits() > 256);
        }

        #[test]
        fn sub_matches_bigint(a in proptest::array::uniform32(any::<u8>()),
                              b in proptest::array::uniform32(any::<u8>())) {
            // u256_sub requires a >= b — order the operands.
            let (hi, lo) = if to_big(&a) >= to_big(&b) { (a, b) } else { (b, a) };
            let diff = u256_sub(&hi, &lo);
            prop_assert_eq!(to_big(&diff), to_big(&hi) - to_big(&lo));
        }

        #[test]
        fn div_matches_bigint(num in proptest::array::uniform32(any::<u8>()),
                              den in proptest::array::uniform32(any::<u8>())) {
            prop_assume!(to_big(&den) != BigUint::ZERO);
            let q = u256_div(&num, &den);
            prop_assert_eq!(to_big(&q), to_big(&num) / to_big(&den));
        }

        #[test]
        fn mul_ratio_matches_bigint(mut target in proptest::array::uniform32(any::<u8>()),
                                    num in 1u64..=1_000_000,
                                    den in 1u64..=1_000_000) {
            // The 4-limb multiply drops a carry out of the top limb, and the
            // retarget call sites guarantee it never occurs (the ratio is
            // clamped to [1/4, 4] and real targets sit below the ~2^224 pow
            // limit) — model that domain by zeroing the top 4 bytes, keeping
            // target*num comfortably under 2^256.
            target[0] = 0;
            target[1] = 0;
            target[2] = 0;
            target[3] = 0;
            let expected = from_big(&((to_big(&target) * num) / den));
            let got = multiply_target_by_ratio(&target, num, den);
            prop_assert_eq!(got, expected);
        }

        /// calculate_work == floor(2^256 / (target+1)) for nonzero targets
        /// (Core's GetBlockProof formula, which the limb code implements as
        /// (~target / (target+1)) + 1).
        #[test]
        fn calculate_work_matches_formula(raw in proptest::array::uniform32(any::<u8>())) {
            prop_assume!(raw != [0u8; 32]);
            let target = Target::from_be_bytes(raw);
            let work = calculate_work(&target);
            let expected = (BigUint::from(1u8) << 256) / (to_big(&raw) + 1u8);
            prop_assert_eq!(to_big(&work), expected);
        }

        #[test]
        fn add_chain_work_matches_bigint(a in proptest::array::uniform32(any::<u8>()),
                                         b in proptest::array::uniform32(any::<u8>())) {
            let sum = add_chain_work(&a, &b);
            let expected = (to_big(&a) + to_big(&b)) % (BigUint::from(1u8) << 256);
            prop_assert_eq!(to_big(&sum), expected);
        }
    }
}
