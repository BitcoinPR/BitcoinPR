use bitcoin::blockdata::opcodes;
use bitcoin::blockdata::script::Instruction;
use bitcoin::hashes::{hash160, ripemd160, sha1, sha256, sha256d, Hash};
use bitcoin::secp256k1::{self, Message, PublicKey, Secp256k1, XOnlyPublicKey};
use bitcoin::sighash::{Annex, Prevouts, SighashCache, TapSighash, TapSighashType};
use bitcoin::taproot::{ControlBlock, LeafVersion, TapLeafHash};
use bitcoin::{EcdsaSighashType, Script, ScriptBuf, Transaction, TxOut};
use std::collections::HashSet;
use std::sync::{Mutex, OnceLock};

use crate::error::{CoreError, CoreResult};

/// Long-lived secp256k1 verification context shared by every signature check.
///
/// `Secp256k1::verification_only()` allocates and randomizes a fresh context;
/// constructing one per signature check (up to 5x for a 3-of-5 multisig input)
/// is pure overhead. Core and libbitcoin both use a single static context.
fn secp_ctx() -> &'static Secp256k1<secp256k1::VerifyOnly> {
    static CTX: OnceLock<Secp256k1<secp256k1::VerifyOnly>> = OnceLock::new();
    CTX.get_or_init(Secp256k1::verification_only)
}

/// Cache of verified script results to avoid redundant verification.
///
/// The key is `(wtxid, input_index, flags)`:
/// - **wtxid** (not txid) so the key commits to the witness. A txid-keyed cache
///   is exploitable: an attacker relays a valid tx (caching its txid), then mines
///   a block carrying the same txid with a *malleated/invalid witness*; a
///   txid-only lookup would hit and skip verification of the bad witness,
///   accepting an invalid block. wtxid differs when the witness differs, so the
///   malleated copy misses the cache and is verified (and rejected).
/// - **flags** so a verification performed under one rule set (e.g. relaxed
///   mempool/standardness or pre-fork consensus flags) never vouches for a
///   lookup under a different rule set.
pub struct SigCache {
    /// 64-way sharded set (M1, 2026-07-02 review): every rayon worker takes
    /// this lock twice per input (`contains` then `insert`), so a single
    /// global mutex serialized script-heavy blocks exactly when parallelism
    /// mattered most. Shard selection uses the first key byte — the wtxid is
    /// uniformly distributed. Bitcoin Core shards its sigcache for the same
    /// reason.
    shards: [Mutex<HashSet<[u8; 40]>>; SIG_CACHE_SHARDS],
    /// Per-shard entry cap (total cache size / shard count).
    max_per_shard: usize,
}

const SIG_CACHE_SHARDS: usize = 64;

impl SigCache {
    /// Create a new signature cache with the given maximum entry count.
    pub fn new(max_size: usize) -> Self {
        let max_per_shard = (max_size / SIG_CACHE_SHARDS).max(1);
        SigCache {
            shards: std::array::from_fn(|_| {
                Mutex::new(HashSet::with_capacity(max_per_shard.min(100_000 / 64)))
            }),
            max_per_shard,
        }
    }

    /// Build a cache key from wtxid, input index, and the active script flags.
    fn key(wtxid: &bitcoin::Wtxid, input_index: usize, flags: ScriptFlags) -> [u8; 40] {
        let mut k = [0u8; 40];
        k[..32].copy_from_slice(AsRef::<[u8; 32]>::as_ref(wtxid));
        k[32..36].copy_from_slice(&(input_index as u32).to_le_bytes());
        k[36..40].copy_from_slice(&flags.bits().to_le_bytes());
        k
    }

    fn shard(&self, key: &[u8; 40]) -> &Mutex<HashSet<[u8; 40]>> {
        &self.shards[key[0] as usize % SIG_CACHE_SHARDS]
    }

    /// Check if a script verification result is cached.
    pub fn contains(&self, wtxid: &bitcoin::Wtxid, input_index: usize, flags: ScriptFlags) -> bool {
        let k = Self::key(wtxid, input_index, flags);
        self.shard(&k).lock().expect("lock poisoned").contains(&k)
    }

    /// Record a successful script verification. When the shard is full a
    /// pseudo-random resident entry is evicted (keyed off the new entry's
    /// bytes — uniformly distributed) instead of silently dropping the
    /// insert: the old stop-inserting policy meant that late in a clear
    /// window the cache stopped admitting entirely.
    pub fn insert(&self, wtxid: &bitcoin::Wtxid, input_index: usize, flags: ScriptFlags) {
        let k = Self::key(wtxid, input_index, flags);
        let mut set = self.shard(&k).lock().expect("lock poisoned");
        if set.len() >= self.max_per_shard {
            // Evict an arbitrary resident entry. HashSet iteration order is
            // seeded per-map, and the victim position is derived from the
            // uniformly-distributed new key, so this is effectively random
            // replacement without extra bookkeeping.
            let idx = u32::from_le_bytes([k[1], k[2], k[3], k[4]]) as usize % set.len();
            if let Some(victim) = set.iter().nth(idx).copied() {
                set.remove(&victim);
            }
        }
        set.insert(k);
    }

    /// Number of cached entries.
    pub fn len(&self) -> usize {
        self.shards
            .iter()
            .map(|s| s.lock().expect("lock poisoned").len())
            .sum()
    }

    /// Whether the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Clear the cache.
    pub fn clear(&self) {
        for shard in &self.shards {
            shard.lock().expect("lock poisoned").clear();
        }
    }
}

/// Script verification flags controlling which rules to enforce.
#[must_use]
#[derive(Debug, Clone, Copy)]
pub struct ScriptFlags {
    pub verify_p2sh: bool,
    pub verify_witness: bool,
    pub verify_strictenc: bool,
    pub verify_checklocktimeverify: bool,
    pub verify_checksequenceverify: bool,
    pub verify_taproot: bool,
    /// BIP 147 (NULLDUMMY): the extra element CHECKMULTISIG/CHECKMULTISIGVERIFY
    /// consume (Bitcoin's off-by-one bug) must be an empty byte vector. Became a
    /// consensus rule when SegWit activated, so `for_height` gates it on the
    /// segwit activation height.
    pub verify_nulldummy: bool,
    /// BIP-110 (Reduced Data Temporary Softfork) rules 2-7. Unlike the other
    /// flags this is decided *per input* from the spent UTXO's creation height
    /// (pre-activation coins are grandfathered), so it is set by the caller for
    /// each input rather than by `for_height`. See [`crate::consensus::ConsensusParams::bip110_active`].
    pub verify_bip110: bool,
}

impl ScriptFlags {
    pub fn all() -> Self {
        ScriptFlags {
            verify_p2sh: true,
            verify_witness: true,
            verify_strictenc: true,
            verify_checklocktimeverify: true,
            verify_checksequenceverify: true,
            verify_taproot: true,
            verify_nulldummy: true,
            // BIP-110 is a per-input runtime decision (grandfathering by prevout
            // height), not part of the "all rules" baseline — callers set it.
            verify_bip110: false,
        }
    }

    pub fn none() -> Self {
        ScriptFlags {
            verify_p2sh: false,
            verify_witness: false,
            verify_strictenc: false,
            verify_checklocktimeverify: false,
            verify_checksequenceverify: false,
            verify_taproot: false,
            verify_nulldummy: false,
            verify_bip110: false,
        }
    }

    /// Pack the flags into a compact bitmask, used as part of the [`SigCache`] key
    /// so cached verifications are scoped to the exact rule set they were checked under.
    pub fn bits(&self) -> u32 {
        (self.verify_p2sh as u32)
            | (self.verify_witness as u32) << 1
            | (self.verify_strictenc as u32) << 2
            | (self.verify_checklocktimeverify as u32) << 3
            | (self.verify_checksequenceverify as u32) << 4
            | (self.verify_taproot as u32) << 5
            | (self.verify_bip110 as u32) << 6
            | (self.verify_nulldummy as u32) << 7
    }

    #[allow(clippy::too_many_arguments)]
    pub fn for_height(
        height: u32,
        block_time: u32,
        bip16_time: u32,
        segwit_height: u32,
        bip65_height: u32,
        csv_height: u32,
        bip66_height: u32,
        taproot_height: u32,
    ) -> Self {
        ScriptFlags {
            verify_p2sh: block_time >= bip16_time,
            verify_witness: height >= segwit_height,
            verify_strictenc: height >= bip66_height,
            verify_checklocktimeverify: height >= bip65_height,
            // BIP 68/112/113 (CSV): gated on its own buried activation height.
            verify_checksequenceverify: height >= csv_height,
            verify_taproot: height >= taproot_height,
            // BIP 147 (NULLDUMMY) co-activated with SegWit.
            verify_nulldummy: height >= segwit_height,
            // Set per-input by the caller from the prevout's creation height.
            verify_bip110: false,
        }
    }
}

// ─── BIP-110 (Reduced Data Temporary Softfork) limits ──────────────────────────

/// Rule 1: maximum non-OP_RETURN output scriptPubKey size.
pub const BIP110_MAX_SCRIPTPUBKEY_SIZE: usize = 34;
/// Rule 1: maximum OP_RETURN output scriptPubKey size.
pub const BIP110_MAX_OP_RETURN_SIZE: usize = 83;
/// Rule 2: maximum OP_PUSHDATA payload / script-argument witness-item size.
pub const BIP110_MAX_PUSH_SIZE: usize = 256;
/// Rule 5: maximum Taproot control-block size (33 + 32*7 ≈ 128 script leaves).
pub const BIP110_MAX_CONTROL_BLOCK_SIZE: usize = 257;
/// The P2A (pay-to-anchor) witness program: witness v1, 2-byte program `0x4e73`.
/// It is a *defined* witness program (anyone-can-spend) and thus exempt from
/// BIP-110 rule 3.
const P2A_WITNESS_PROGRAM: [u8; 2] = [0x4e, 0x73];

/// BIP-110 rule 1: reject any transaction output whose scriptPubKey exceeds the
/// RDTS size limits — 34 bytes in general, or 83 bytes when the first opcode is
/// OP_RETURN. Callers gate this on the *spending block* height (it governs newly
/// created outputs, not the grandfathered coins being spent).
pub fn check_bip110_output_scripts(tx: &Transaction) -> CoreResult<()> {
    for output in &tx.output {
        let spk = output.script_pubkey.as_bytes();
        // "first opcode is OP_RETURN" (0x6a) — matches the BIP wording exactly.
        let is_op_return = spk.first() == Some(&0x6a);
        let limit = if is_op_return {
            BIP110_MAX_OP_RETURN_SIZE
        } else {
            BIP110_MAX_SCRIPTPUBKEY_SIZE
        };
        if spk.len() > limit {
            return Err(CoreError::InvalidScript(format!(
                "BIP-110: output scriptPubKey of {} bytes exceeds {} ({})",
                spk.len(),
                limit,
                if is_op_return {
                    "OP_RETURN"
                } else {
                    "non-OP_RETURN"
                }
            )));
        }
    }
    Ok(())
}

/// BIP-110 rule 2: reject any OP_PUSHDATA payload larger than 256 bytes in
/// `script`. When `exempt_last_push` is set — a BIP-16 P2SH scriptSig — the final
/// push (the serialized redeemScript, which may legitimately be up to
/// `MAX_SCRIPT_ELEMENT_SIZE`) is exempt. Pure static scan; the script must decode.
fn bip110_check_pushes(script: &Script, exempt_last_push: bool) -> CoreResult<()> {
    // Lengths of each push in order, so we can identify and exempt the last one.
    let mut push_lens: Vec<usize> = Vec::new();
    for instruction in script.instructions() {
        let instruction = instruction
            .map_err(|e| CoreError::InvalidScript(format!("script parse error: {e}")))?;
        if let Instruction::PushBytes(data) = instruction {
            push_lens.push(data.len());
        }
    }
    let last = push_lens.len().wrapping_sub(1);
    for (i, &len) in push_lens.iter().enumerate() {
        if exempt_last_push && i == last {
            continue;
        }
        if len > BIP110_MAX_PUSH_SIZE {
            return Err(CoreError::InvalidScript(format!(
                "BIP-110: push of {len} bytes exceeds {BIP110_MAX_PUSH_SIZE}"
            )));
        }
    }
    Ok(())
}

/// BIP-110 rule 2: reject any script-argument witness item larger than 256 bytes.
/// Callers pass only the *argument* items (witness scripts, Tapleaf scripts,
/// control blocks, and annexes are excluded — see rules 4 and 5).
fn bip110_check_witness_items<'a>(items: impl Iterator<Item = &'a [u8]>) -> CoreResult<()> {
    for item in items {
        if item.len() > BIP110_MAX_PUSH_SIZE {
            return Err(CoreError::InvalidScript(format!(
                "BIP-110: witness item of {} bytes exceeds {}",
                item.len(),
                BIP110_MAX_PUSH_SIZE
            )));
        }
    }
    Ok(())
}

// ─── Knots-style relay-policy pattern detection (rejectparasites/rejecttokens) ──
//
// Policy only — never consulted by block validation. Detection is structural:
// the mempool has no prevouts at this point, so a taproot script-path spend is
// recognized by witness shape (leaf script + control block), the same
// heuristic level Knots applies for relay filtering.

/// Taproot script-path leaf script of a witness, recognized structurally:
/// after excluding a BIP 341 annex (last element starting 0x50 when there are
/// at least two elements), a script-path witness is `[args…, leaf script,
/// control block]` where the control block is `33 + 32m` bytes with leaf
/// version `0xc0`. Returns `None` for key-path spends and non-taproot inputs.
fn taproot_leaf_script(witness: &bitcoin::Witness) -> Option<&[u8]> {
    let mut n = witness.len();
    if n >= 2 && witness.nth(n - 1)?.first() == Some(&0x50) {
        n -= 1; // annex
    }
    if n < 2 {
        return None;
    }
    let control = witness.nth(n - 1)?;
    if control.len() < 33 || (control.len() - 33) % 32 != 0 || control[0] & 0xfe != 0xc0 {
        return None;
    }
    witness.nth(n - 2)
}

/// Concatenated payload pushes inside the first inscription envelope
/// (`OP_FALSE OP_IF … OP_ENDIF`) in `script`, or `None` when the script has no
/// envelope. The empty push makes the IF branch dead code, so everything
/// pushed inside rides the witness discount without ever executing — the
/// ordinals/inscription data-embedding pattern.
fn inscription_envelope_payload(script: &Script) -> Option<Vec<u8>> {
    let mut instructions = script.instructions();
    let mut prev_push_empty = false;
    while let Some(Ok(inst)) = instructions.next() {
        match inst {
            Instruction::PushBytes(data) if data.is_empty() => prev_push_empty = true,
            Instruction::Op(op) if prev_push_empty && op == opcodes::all::OP_IF => {
                let mut payload = Vec::new();
                for inst in instructions.by_ref() {
                    match inst {
                        Ok(Instruction::PushBytes(data)) => {
                            payload.extend_from_slice(data.as_bytes())
                        }
                        Ok(Instruction::Op(op)) if op == opcodes::all::OP_ENDIF => break,
                        Ok(_) => {}
                        Err(_) => return None,
                    }
                }
                return Some(payload);
            }
            _ => prev_push_empty = false,
        }
    }
    None
}

/// Index of the first input whose tapscript carries an inscription envelope —
/// Knots' parasite marker (`-rejectparasites`). `None` when the transaction is
/// clean.
pub fn tx_first_inscription_input(tx: &Transaction) -> Option<usize> {
    tx.input.iter().position(|input| {
        taproot_leaf_script(&input.witness)
            .map(Script::from_bytes)
            .and_then(inscription_envelope_payload)
            .is_some()
    })
}

// ─── Covert opcode-choice encoding (OP_PLENTY-style, BIP-110-era) ──────────
//
// A post-BIP-110 data-embedding technique that performs no data push at all:
// each payload nibble is represented by *which* opcode appears at a given
// position, drawn from a small set of stack-arithmetic/comparison opcodes.
// The alphabet is chosen so no member falls in a BIP342 OP_SUCCESSx range
// (BIP-110 makes rejecting those mandatory) and none require OP_IF/OP_NOTIF
// (BIP-110 disables those in tapscript). A depth-tracking state machine on
// the encoder side keeps the scratch stack inside {5,6,7} items so the
// script always validates; decoding is stateless (opcode % 22 == nibble).
// Public reference: the "OP_PLENTY" gist (stevenrabinow-hash, 2026-07-22).

/// The 28-opcode alphabet OP_PLENTY draws payload/length nibbles from: every
/// opcode whose numeric value is congruent to a nibble (0x0-0xf) modulo 22,
/// selected by the encoder for depth-steering behavior and BIP-110/BIP-342
/// safety. Does not include the footer opcodes (`OP_2DROP`, `OP_DROP`) or the
/// `OP_5` magic/preamble byte, which the encoder never uses to carry a
/// nibble — those are checked separately.
const OP_PLENTY_ALPHABET: [u8; 28] = [
    0x51, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f, 0x60, 0x61,
    0x78, // growing/hold reps
    0x77, 0x87, 0x93, 0x9a, 0x9b, 0x9c, 0x9e, 0x9f, 0xa0, 0xa1, 0xa2, 0xa4, // shrinking reps
    0x8f, 0x90, 0x91, 0x92, // depth-neutral unary reps
];

/// The three 3-opcode footers that collapse the scratch stack back to its
/// truthy anchor, one per exit depth (5, 6, 7). Every OP_PLENTY encoding ends
/// with exactly one of these — it's the only way the construction can leave
/// a clean stack, independent of alphabet or framing choices.
const OP_PLENTY_FOOTERS: [[u8; 3]; 3] = [
    [0x6d, 0x6d, 0x61], // OP_2DROP OP_2DROP OP_NOP   (depth 5)
    [0x6d, 0x6d, 0x75], // OP_2DROP OP_2DROP OP_DROP  (depth 6)
    [0x6d, 0x6d, 0x6d], // OP_2DROP OP_2DROP OP_2DROP (depth 7)
];

/// Minimum length, in opcodes, of an alphabet-only run before it's treated as
/// a plausible covert payload rather than incidental use of a handful of
/// comparison/arithmetic opcodes in an ordinary script. 24 is conservative:
/// past the (optional) 8-nibble v2 length header, it still requires roughly a
/// dozen encoded payload bytes — well past anything a normal spending
/// condition chains together with zero data pushes and zero branching.
const OP_PLENTY_MIN_RUN: usize = 24;

/// Detects the OP_PLENTY covert opcode-choice encoding in a taproot leaf
/// script: a contiguous run of at least [`OP_PLENTY_MIN_RUN`] opcodes drawn
/// only from [`OP_PLENTY_ALPHABET`] (no data pushes, no branching),
/// immediately followed by one of the [`OP_PLENTY_FOOTERS`].
///
/// Deliberately independent of the `OP_5`×7 v2 magic marker and the length
/// header: both are optional framing per the encoder's own design ("the core
/// codec does not require any particular marker or length format"), so a
/// detector keyed on the marker alone would miss an unframed variant. The
/// run-length + footer shape is structural to the construction itself — any
/// encoder in this family must steer a small stack through a bounded depth
/// walk and then collapse it, which is what the footer exists to do.
fn has_op_plenty_encoding(script: &Script) -> bool {
    // Flatten to one byte per instruction: the opcode's numeric value for a
    // plain op, or a sentinel for a data push (0xff — not a member of the
    // alphabet or any footer), which can never be part of the covert body.
    let ops: Vec<u8> = script
        .instructions()
        .map(|inst| match inst {
            Ok(Instruction::Op(op)) => op.to_u8(),
            _ => 0xff,
        })
        .collect();

    let mut run_start = 0;
    for (i, &b) in ops.iter().enumerate() {
        if OP_PLENTY_ALPHABET.contains(&b) {
            continue;
        }
        if i - run_start >= OP_PLENTY_MIN_RUN {
            if let Some(next3) = ops.get(i..i + 3) {
                if OP_PLENTY_FOOTERS.iter().any(|f| f.as_slice() == next3) {
                    return true;
                }
            }
        }
        run_start = i + 1;
    }
    false
}

/// Index of the first input whose tapscript carries an OP_PLENTY-style covert
/// opcode-choice encoding — see [`has_op_plenty_encoding`]. `None` when the
/// transaction is clean.
pub fn tx_first_covert_opcode_input(tx: &Transaction) -> Option<usize> {
    tx.input.iter().position(|input| {
        taproot_leaf_script(&input.witness)
            .map(Script::from_bytes)
            .is_some_and(has_op_plenty_encoding)
    })
}

/// First data push of an OP_RETURN script (the datacarrier payload), or `None`
/// when there is none or the script doesn't decode.
fn op_return_payload(script: &Script) -> Option<Vec<u8>> {
    for inst in script.instructions() {
        match inst {
            Ok(Instruction::PushBytes(data)) if !data.is_empty() => {
                return Some(data.as_bytes().to_vec())
            }
            Ok(_) => {}
            Err(_) => return None,
        }
    }
    None
}

/// Token-protocol classification for relay policy (Knots `-rejecttokens`).
/// Returns the protocol name when the transaction carries a recognized token
/// marker: a Runes runestone (`OP_RETURN OP_13`), an Omni Layer or
/// Counterparty OP_RETURN payload prefix, or a BRC-20 payload inside an
/// inscription envelope. The pattern table is policy and expected to grow;
/// keep all detection in this module.
pub fn tx_token_protocol(tx: &Transaction) -> Option<&'static str> {
    for output in &tx.output {
        let spk = output.script_pubkey.as_bytes();
        if spk.first() != Some(&0x6a) {
            continue;
        }
        // Runes runestone magic: OP_RETURN immediately followed by OP_13.
        if spk.get(1) == Some(&0x5d) {
            return Some("runes");
        }
        if let Some(payload) = op_return_payload(&output.script_pubkey) {
            if payload.starts_with(b"omni") {
                return Some("omni");
            }
            if payload.starts_with(b"CNTRPRTY") {
                return Some("counterparty");
            }
        }
    }
    for input in &tx.input {
        if let Some(payload) = taproot_leaf_script(&input.witness)
            .map(Script::from_bytes)
            .and_then(inscription_envelope_payload)
        {
            if payload.windows(6).any(|w| w == b"brc-20") {
                return Some("brc-20");
            }
        }
    }
    None
}

/// Verify a transaction input's script against the corresponding output's scriptPubKey.
/// `all_prevouts` must contain the previous outputs for ALL inputs of the transaction
/// (required for Taproot BIP 341 sighash computation); the spent prevout is
/// `all_prevouts[input_index]` — indexed internally so callers cannot pass a
/// mismatched prevout (L3, 2026-07-02 review: the old separate `prev_output`
/// parameter was an invariant the compiler could enforce instead).
pub fn verify_script(
    tx: &Transaction,
    input_index: usize,
    all_prevouts: &[TxOut],
    flags: ScriptFlags,
) -> CoreResult<()> {
    let prev_output = &all_prevouts[input_index];
    let script_pubkey = &prev_output.script_pubkey;
    let input = &tx.input[input_index];
    let script_sig = &input.script_sig;
    let witness = &input.witness;
    let amount = prev_output.value;
    // BIP-110 rules 2-7 apply to this input only when the spent UTXO was created
    // at/after the activation height (the caller encodes that in the flag).
    let bip110 = flags.verify_bip110;

    // One sighash cache per input check: every signature verification for this
    // input reuses the memoized midstate hashes (BIP 143/341 sha_prevouts,
    // sha_sequences, sha_outputs), instead of rebuilding the cache per signature
    // (a large win for multisig inputs).
    let mut sighash_cache = SighashCache::new(tx);

    // Check for witness program (SegWit)
    if flags.verify_witness {
        if let Some((version, program)) = parse_witness_program(script_pubkey) {
            // A native witness program must be spent with an empty scriptSig;
            // any scriptSig is witness malleability (BIP 141).
            if !script_sig.is_empty() {
                return Err(CoreError::InvalidScript("witness malleated".into()));
            }
            if version == 0 {
                return verify_witness_v0(
                    tx,
                    input_index,
                    amount,
                    program,
                    witness,
                    bip110,
                    &mut sighash_cache,
                );
            }
            if version == 1 && flags.verify_taproot && program.len() == 32 {
                return verify_witness_v1(
                    tx,
                    input_index,
                    all_prevouts,
                    program,
                    witness,
                    bip110,
                    &mut sighash_cache,
                );
            }
            // Unknown witness versions or non-standard program lengths are
            // treated as anyone-can-spend for forward compat (BIP 141/341) —
            // except BIP-110 rule 3 makes *spending* an undefined witness
            // version invalid (P2A, v1 program 0x4e73, stays defined).
            if bip110 && !(version == 1 && program == P2A_WITNESS_PROGRAM) {
                return Err(CoreError::InvalidScript(
                    "BIP-110: spending undefined witness version".into(),
                ));
            }
            return Ok(());
        }
    }

    let is_p2sh_spend = flags.verify_p2sh && is_p2sh(script_pubkey);

    // BIP-110 rule 2: scriptSig OP_PUSHDATA payloads are limited to 256 bytes,
    // except the final push of a P2SH scriptSig (the redeemScript). The scriptSig
    // is checked statically here and executed below with the in-loop check off.
    if bip110 {
        bip110_check_pushes(script_sig, is_p2sh_spend)?;
    }
    let mut sig_flags = flags;
    sig_flags.verify_bip110 = false;

    // Execute scriptSig to produce the initial stack
    let mut stack = Vec::new();
    execute_script(
        script_sig,
        &mut stack,
        tx,
        input_index,
        amount,
        sig_flags,
        &mut sighash_cache,
    )?;

    // Save stack for P2SH evaluation
    let stack_copy = if is_p2sh_spend {
        Some(stack.clone())
    } else {
        None
    };

    // Execute scriptPubKey with the stack from scriptSig
    execute_script(
        script_pubkey,
        &mut stack,
        tx,
        input_index,
        amount,
        flags,
        &mut sighash_cache,
    )?;

    // Check final stack
    if stack.is_empty() || !cast_to_bool(&stack[stack.len() - 1]) {
        return Err(CoreError::InvalidScript("script evaluation failed".into()));
    }

    // P2SH evaluation
    if let Some(saved_stack) = stack_copy {
        if !saved_stack.is_empty() {
            let redeem_script =
                ScriptBuf::from_bytes(saved_stack.last().expect("non-empty checked above").clone());

            // Verify the hash
            let script_hash = hash160::Hash::hash(redeem_script.as_bytes());
            let expected_hash = &script_pubkey.as_bytes()[2..22];
            if AsRef::<[u8]>::as_ref(&script_hash) != expected_hash {
                return Err(CoreError::InvalidScript("P2SH hash mismatch".into()));
            }

            // Execute the redeem script
            let mut p2sh_stack: Vec<Vec<u8>> = saved_stack[..saved_stack.len() - 1].to_vec();

            // Check for witness-in-P2SH (P2SH-P2WPKH, P2SH-P2WSH)
            if flags.verify_witness {
                if let Some((version, program)) = parse_witness_program(&redeem_script) {
                    if version == 0 {
                        return verify_witness_v0(
                            tx,
                            input_index,
                            amount,
                            program,
                            witness,
                            bip110,
                            &mut sighash_cache,
                        );
                    }
                    // BIP-110 rule 3: spending an undefined witness version
                    // (here nested in P2SH) is invalid; P2A stays defined.
                    if bip110 && !(version == 1 && program == P2A_WITNESS_PROGRAM) {
                        return Err(CoreError::InvalidScript(
                            "BIP-110: spending undefined witness version".into(),
                        ));
                    }
                    return Ok(());
                }
            }

            execute_script(
                &redeem_script,
                &mut p2sh_stack,
                tx,
                input_index,
                amount,
                flags,
                &mut sighash_cache,
            )?;

            if p2sh_stack.is_empty() || !cast_to_bool(&p2sh_stack[p2sh_stack.len() - 1]) {
                return Err(CoreError::InvalidScript(
                    "P2SH script evaluation failed".into(),
                ));
            }
        }
    }

    // We only reach here on the non-witness path (every witness program returns
    // early above). If a witness was supplied but nothing consumed it, the input
    // is malleable — reject it (BIP 141 cleanstack-for-witness).
    if flags.verify_witness && !witness.is_empty() {
        return Err(CoreError::InvalidScript("witness unexpected".into()));
    }

    Ok(())
}

/// Verify a SegWit v0 witness program.
#[allow(clippy::too_many_arguments)]
fn verify_witness_v0(
    tx: &Transaction,
    input_index: usize,
    amount: bitcoin::Amount,
    program: &[u8],
    witness: &bitcoin::Witness,
    enforce_bip110: bool,
    sighash_cache: &mut SighashCache<&Transaction>,
) -> CoreResult<()> {
    match program.len() {
        20 => {
            // P2WPKH
            if witness.len() != 2 {
                return Err(CoreError::InvalidScript(
                    "P2WPKH requires exactly 2 witness items".into(),
                ));
            }

            let sig = &witness[0];
            let pubkey = &witness[1];

            // BIP-110 rule 2: both witness items are script arguments (<=256 bytes).
            if enforce_bip110 {
                bip110_check_witness_items([sig, pubkey].into_iter())?;
            }

            // Verify pubkey hash matches program
            let pubkey_hash = hash160::Hash::hash(pubkey);
            if AsRef::<[u8]>::as_ref(&pubkey_hash) != program {
                return Err(CoreError::InvalidScript(
                    "P2WPKH pubkey hash mismatch".into(),
                ));
            }

            // Verify signature using BIP 143 sighash
            verify_ecdsa_signature(input_index, amount, sig, pubkey, sighash_cache)?;

            Ok(())
        }
        32 => {
            // P2WSH
            if witness.is_empty() {
                return Err(CoreError::InvalidScript("P2WSH: empty witness".into()));
            }

            let witness_script_bytes = &witness[witness.len() - 1];
            let witness_script = Script::from_bytes(witness_script_bytes);

            // Verify script hash matches program
            let script_hash = sha256::Hash::hash(witness_script_bytes);
            if AsRef::<[u8]>::as_ref(&script_hash) != program {
                return Err(CoreError::InvalidScript(
                    "P2WSH script hash mismatch".into(),
                ));
            }

            // BIP-110 rule 2: every witness item except the witness script (the
            // last item, exempt) is a script argument limited to 256 bytes.
            if enforce_bip110 {
                bip110_check_witness_items(witness.iter().take(witness.len() - 1))?;
            }

            // Execute witness script with witness stack (using BIP 143 segwit sighash)
            let mut stack: Vec<Vec<u8>> = witness
                .iter()
                .take(witness.len() - 1)
                .map(|w| w.to_vec())
                .collect();

            // BIP-110 rule 2: in-script pushes in the witness script are also
            // limited to 256 bytes (the witness script itself is exempt above).
            let mut flags = ScriptFlags::all();
            flags.verify_bip110 = enforce_bip110;
            execute_script_segwit(
                witness_script,
                &mut stack,
                tx,
                input_index,
                amount,
                flags,
                sighash_cache,
            )?;

            if stack.is_empty() || !cast_to_bool(&stack[stack.len() - 1]) {
                return Err(CoreError::InvalidScript(
                    "P2WSH script evaluation failed".into(),
                ));
            }

            Ok(())
        }
        _ => Err(CoreError::InvalidScript(format!(
            "invalid witness program length: {}",
            program.len()
        ))),
    }
}

/// Verify a SegWit v1 (Taproot) witness program (BIP 341).
///
/// Two spending paths:
/// 1. Key path: witness = [signature] — verify Schnorr signature against output key
/// 2. Script path: witness = [..stack, script, control_block] — verify merkle proof + execute tapscript
#[allow(clippy::too_many_arguments)]
fn verify_witness_v1(
    tx: &Transaction,
    input_index: usize,
    all_prevouts: &[TxOut],
    program: &[u8],
    witness: &bitcoin::Witness,
    enforce_bip110: bool,
    sighash_cache: &mut SighashCache<&Transaction>,
) -> CoreResult<()> {
    debug_assert_eq!(
        program.len(),
        32,
        "caller must check program length before calling"
    );

    if witness.is_empty() {
        return Err(CoreError::InvalidScript("Taproot: empty witness".into()));
    }

    // Check for annex (last witness item starting with 0x50)
    let has_annex = witness.len() >= 2 && witness.last().is_some_and(|w| w.first() == Some(&0x50));
    // BIP-110 rule 4: a Taproot annex is invalid.
    if enforce_bip110 && has_annex {
        return Err(CoreError::InvalidScript(
            "BIP-110: Taproot annex is invalid".into(),
        ));
    }
    let effective_len = if has_annex {
        witness.len() - 1
    } else {
        witness.len()
    };
    let annex = if has_annex {
        let annex_bytes = witness
            .last()
            .expect("has_annex implies witness is non-empty");
        Some(
            Annex::new(annex_bytes)
                .map_err(|e| CoreError::InvalidScript(format!("invalid annex: {e}")))?,
        )
    } else {
        None
    };

    let output_key = XOnlyPublicKey::from_slice(program)
        .map_err(|e| CoreError::InvalidScript(format!("invalid taproot output key: {e}")))?;

    if effective_len == 1 {
        // Key path spend: witness = [signature]
        // BIP-110 rule 2: the signature is a script-argument witness item.
        if enforce_bip110 {
            bip110_check_witness_items(std::iter::once(witness[0].as_ref()))?;
        }
        verify_taproot_key_spend(
            input_index,
            all_prevouts,
            &output_key,
            &witness[0],
            annex,
            sighash_cache,
        )
    } else {
        // Script path spend: witness = [..stack, script, control_block]
        let control_bytes = &witness[effective_len - 1];
        let script_bytes = &witness[effective_len - 2];

        // BIP-110 rule 5: control blocks larger than 257 bytes are invalid.
        if enforce_bip110 && control_bytes.len() > BIP110_MAX_CONTROL_BLOCK_SIZE {
            return Err(CoreError::InvalidScript(format!(
                "BIP-110: control block of {} bytes exceeds {}",
                control_bytes.len(),
                BIP110_MAX_CONTROL_BLOCK_SIZE
            )));
        }

        // Parse control block
        let control_block = ControlBlock::decode(control_bytes)
            .map_err(|e| CoreError::InvalidScript(format!("invalid control block: {e}")))?;

        // Verify the taproot merkle proof
        let tap_script = ScriptBuf::from_bytes(script_bytes.to_vec());
        let secp = secp_ctx();
        if !control_block.verify_taproot_commitment(secp, output_key, &tap_script) {
            return Err(CoreError::InvalidScript(
                "Taproot script path merkle proof verification failed".into(),
            ));
        }

        // Execute tapscript (BIP 342)
        if control_block.leaf_version == LeafVersion::TapScript {
            let tap_leaf = TapLeafHash::from_script(&tap_script, LeafVersion::TapScript);

            // BIP-110 rule 2: every witness item before the script and control
            // block (the Tapleaf script and control block are exempt) is a
            // script argument limited to 256 bytes.
            if enforce_bip110 {
                bip110_check_witness_items(witness.iter().take(effective_len - 2))?;
            }

            // Build the witness stack (everything before script and control block)
            let mut stack: Vec<Vec<u8>> = witness
                .iter()
                .take(effective_len - 2)
                .map(|w| w.to_vec())
                .collect();

            execute_tapscript(
                &tap_script,
                &mut stack,
                tx,
                input_index,
                all_prevouts,
                tap_leaf,
                annex.as_ref(),
                enforce_bip110,
                sighash_cache,
            )?;

            if stack.is_empty() || !cast_to_bool(&stack[stack.len() - 1]) {
                return Err(CoreError::InvalidScript(
                    "Tapscript evaluation failed".into(),
                ));
            }

            Ok(())
        } else if enforce_bip110 {
            // BIP-110 rule 3: spending an undefined Tapleaf version is invalid
            // (only the BIP-342 TapScript leaf version 0xc0 is defined).
            Err(CoreError::InvalidScript(
                "BIP-110: spending undefined Tapleaf version".into(),
            ))
        } else {
            // Unknown leaf version — treat as anyone-can-spend for forward compat
            Ok(())
        }
    }
}

/// Verify a Taproot key-path spend (BIP 340 Schnorr signature).
/// The transaction is carried by `sighash_cache` (created once per input check
/// in `verify_script`).
#[allow(clippy::too_many_arguments)]
fn verify_taproot_key_spend(
    input_index: usize,
    all_prevouts: &[TxOut],
    output_key: &XOnlyPublicKey,
    sig_bytes: &[u8],
    annex: Option<Annex>,
    sighash_cache: &mut SighashCache<&Transaction>,
) -> CoreResult<()> {
    let (sig, sighash_type) = parse_schnorr_sig(sig_bytes)?;

    let secp = secp_ctx();

    let prevouts = Prevouts::All(all_prevouts);

    // Use low-level API to include annex in sighash when present (BIP 341).
    let mut eng = TapSighash::engine();
    sighash_cache
        .taproot_encode_signing_data_to(
            &mut eng,
            input_index,
            &prevouts,
            annex,
            None, // no leaf/codeseparator for key-path spend
            sighash_type,
        )
        .map_err(|e| CoreError::InvalidScript(format!("taproot sighash error: {e}")))?;
    let sighash = TapSighash::from_engine(eng);

    let msg = Message::from_digest(*AsRef::<[u8; 32]>::as_ref(&sighash));

    secp.verify_schnorr(&sig, &msg, output_key).map_err(|e| {
        CoreError::InvalidScript(format!("Schnorr signature verification failed: {e}"))
    })?;

    Ok(())
}

/// Verify a Schnorr signature for a tapscript input (script-path spend).
/// `codesep_pos` is the position of the last executed OP_CODESEPARATOR, or
/// `0xFFFFFFFF` if none was executed (BIP 342).
#[allow(clippy::too_many_arguments)]
fn verify_taproot_script_sig(
    input_index: usize,
    all_prevouts: &[TxOut],
    pubkey: &XOnlyPublicKey,
    sig_bytes: &[u8],
    tap_leaf: TapLeafHash,
    codesep_pos: u32,
    annex: Option<Annex>,
    sighash_cache: &mut SighashCache<&Transaction>,
) -> CoreResult<()> {
    let (sig, sighash_type) = parse_schnorr_sig(sig_bytes)?;

    let secp = secp_ctx();

    let prevouts = Prevouts::All(all_prevouts);

    // Use the low-level API to pass codesep_pos and annex (BIP 341/342).
    let mut eng = TapSighash::engine();
    sighash_cache
        .taproot_encode_signing_data_to(
            &mut eng,
            input_index,
            &prevouts,
            annex,
            Some((tap_leaf, codesep_pos)),
            sighash_type,
        )
        .map_err(|e| CoreError::InvalidScript(format!("tapscript sighash error: {e}")))?;
    let sighash = TapSighash::from_engine(eng);

    let msg = Message::from_digest(*AsRef::<[u8; 32]>::as_ref(&sighash));

    secp.verify_schnorr(&sig, &msg, pubkey).map_err(|e| {
        CoreError::InvalidScript(format!("Schnorr signature verification failed: {e}"))
    })?;

    Ok(())
}

/// Parse a Schnorr signature (64 or 65 bytes).
/// 64 bytes = signature with default sighash (SIGHASH_DEFAULT = 0x00)
/// 65 bytes = signature + 1 byte sighash type
fn parse_schnorr_sig(
    sig_bytes: &[u8],
) -> CoreResult<(secp256k1::schnorr::Signature, TapSighashType)> {
    match sig_bytes.len() {
        64 => {
            let sig = secp256k1::schnorr::Signature::from_slice(sig_bytes)
                .map_err(|e| CoreError::InvalidScript(format!("invalid Schnorr signature: {e}")))?;
            Ok((sig, TapSighashType::Default))
        }
        65 => {
            let sighash_type = TapSighashType::from_consensus_u8(sig_bytes[64]).map_err(|e| {
                CoreError::InvalidScript(format!("invalid taproot sighash type: {e}"))
            })?;
            // Empty signature with non-default sighash is invalid
            let sig = secp256k1::schnorr::Signature::from_slice(&sig_bytes[..64])
                .map_err(|e| CoreError::InvalidScript(format!("invalid Schnorr signature: {e}")))?;
            Ok((sig, sighash_type))
        }
        0 => Err(CoreError::InvalidScript("empty signature".into())),
        _ => Err(CoreError::InvalidScript(format!(
            "invalid Schnorr signature length: {} (expected 64 or 65)",
            sig_bytes.len()
        ))),
    }
}

/// Parse a witness program from a scriptPubKey.
/// Returns (version, program) if the script is a witness program.
fn parse_witness_program(script: &Script) -> Option<(u8, &[u8])> {
    let bytes = script.as_bytes();
    if bytes.len() < 4 || bytes.len() > 42 {
        return None;
    }

    // First byte is the version opcode (OP_0 = 0x00, OP_1..OP_16 = 0x51..0x60)
    let version = match bytes[0] {
        0x00 => 0,
        v @ 0x51..=0x60 => v - 0x50,
        _ => return None,
    };

    // Second byte is the push length
    let prog_len = bytes[1] as usize;
    if bytes.len() != 2 + prog_len {
        return None;
    }
    if !(2..=40).contains(&prog_len) {
        return None;
    }

    Some((version, &bytes[2..]))
}

/// Check if a script is P2SH (OP_HASH160 <20 bytes> OP_EQUAL).
fn is_p2sh(script: &Script) -> bool {
    let bytes = script.as_bytes();
    bytes.len() == 23
        && bytes[0] == opcodes::all::OP_HASH160.to_u8()
        && bytes[1] == 0x14 // push 20 bytes
        && bytes[22] == opcodes::all::OP_EQUAL.to_u8()
}

/// Verify an ECDSA signature for a transaction input.
/// The transaction is carried by `sighash_cache`.
fn verify_ecdsa_signature(
    input_index: usize,
    amount: bitcoin::Amount,
    sig_bytes: &[u8],
    pubkey_bytes: &[u8],
    sighash_cache: &mut SighashCache<&Transaction>,
) -> CoreResult<()> {
    if sig_bytes.is_empty() {
        return Err(CoreError::InvalidScript("empty signature".into()));
    }

    let secp = secp_ctx();

    let pubkey = PublicKey::from_slice(pubkey_bytes)
        .map_err(|e| CoreError::InvalidScript(format!("invalid pubkey: {e}")))?;

    // Last byte of signature is the sighash type
    let sighash_type_byte = sig_bytes[sig_bytes.len() - 1];
    let sig_der = &sig_bytes[..sig_bytes.len() - 1];

    let sighash_type = EcdsaSighashType::from_consensus(sighash_type_byte as u32);

    let signature = secp256k1::ecdsa::Signature::from_der(sig_der)
        .map_err(|e| CoreError::InvalidScript(format!("invalid DER signature: {e}")))?;

    // Compute BIP 143 sighash for SegWit
    let sighash = sighash_cache
        .p2wpkh_signature_hash(
            input_index,
            &ScriptBuf::new_p2wpkh(&bitcoin::WPubkeyHash::from_byte_array(
                hash160::Hash::hash(pubkey_bytes).to_byte_array(),
            )),
            amount,
            sighash_type,
        )
        .map_err(|e| CoreError::InvalidScript(format!("sighash error: {e}")))?;

    let msg = Message::from_digest(*AsRef::<[u8; 32]>::as_ref(&sighash));

    secp.verify_ecdsa(&msg, &signature, &pubkey)
        .map_err(|e| CoreError::InvalidScript(format!("signature verification failed: {e}")))?;

    Ok(())
}

/// Execute a Bitcoin script on the stack.
/// Maximum combined stack + alt-stack size.
const MAX_STACK_SIZE: usize = 1000;
/// Maximum size of a single script element.
const MAX_SCRIPT_ELEMENT_SIZE: usize = 520;
/// Maximum serialized script size in bytes (legacy / SegWit v0). Removed in
/// Tapscript, which has its own path.
const MAX_SCRIPT_SIZE: usize = 10_000;

/// Opcodes disabled since CVE-2010-5137. They make a script invalid even when
/// they appear inside a non-executed `OP_IF` branch (Core rejects them before
/// the execution-state check), so this is consulted regardless of `fExec`.
fn is_disabled_opcode(op_byte: u8) -> bool {
    matches!(
        op_byte,
        // OP_CAT OP_SUBSTR OP_LEFT OP_RIGHT
        0x7e | 0x7f | 0x80 | 0x81
        // OP_INVERT OP_AND OP_OR OP_XOR
        | 0x83 | 0x84 | 0x85 | 0x86
        // OP_2MUL OP_2DIV
        | 0x8d | 0x8e
        // OP_MUL OP_DIV OP_MOD OP_LSHIFT OP_RSHIFT
        | 0x95 | 0x96 | 0x97 | 0x98 | 0x99
    )
}

/// Count the signature operations in a script (for block sigop limit).
pub fn count_sigops(script: &Script, accurate: bool) -> u32 {
    let mut count = 0u32;
    let mut last_op = 0u8;

    for instruction in script.instructions() {
        match instruction {
            Ok(Instruction::Op(op)) => {
                let op_byte = op.to_u8();
                match op_byte {
                    0xac | 0xad => count += 1, // OP_CHECKSIG, OP_CHECKSIGVERIFY
                    0xae | 0xaf => {
                        // OP_CHECKMULTISIG, OP_CHECKMULTISIGVERIFY
                        if accurate && (0x51..=0x60).contains(&last_op) {
                            // OP_1 through OP_16 — use actual key count
                            count += (last_op - 0x50) as u32;
                        } else {
                            count += 20; // MAX_PUBKEYS_PER_MULTISIG
                        }
                    }
                    _ => {}
                }
                last_op = op_byte;
            }
            Ok(Instruction::PushBytes(_)) => {
                last_op = 0;
            }
            Err(_) => break,
        }
    }
    count
}

/// Recover the P2SH redeem script (the last data push) from a scriptSig, as
/// Bitcoin Core's `GetSigOpCount` does for P2SH inputs. Returns `None` if the
/// scriptSig is not push-only (in which case Core counts zero P2SH sigops).
pub fn p2sh_redeem_script(script_sig: &Script) -> Option<Vec<u8>> {
    let mut last: Option<Vec<u8>> = None;
    for ins in script_sig.instructions() {
        match ins {
            Ok(Instruction::PushBytes(b)) => last = Some(b.as_bytes().to_vec()),
            Ok(Instruction::Op(op)) => {
                // Number-push opcodes (OP_1NEGATE, OP_1..OP_16; ≤ 0x60) are allowed
                // in a push-only scriptSig but don't themselves form the redeem
                // script. Any larger opcode means the scriptSig isn't push-only.
                if op.to_u8() > 0x60 {
                    return None;
                }
            }
            Err(_) => return None,
        }
    }
    last
}

/// Witness sigop cost for one input (Bitcoin Core's `CountWitnessSigOps`):
/// 1 for P2WPKH, the accurate sigop count of the witness script for P2WSH, and
/// 0 for Taproot / non-witness. Handles P2SH-wrapped witness programs.
pub fn witness_sigop_cost(
    script_pubkey: &Script,
    script_sig: &Script,
    witness: &bitcoin::Witness,
) -> u64 {
    // Determine the witness program: directly from the scriptPubKey, or from the
    // P2SH redeem script when the prevout is P2SH-wrapped.
    let program: ScriptBuf = if script_pubkey.is_p2sh() {
        match p2sh_redeem_script(script_sig) {
            Some(r) => ScriptBuf::from_bytes(r),
            None => return 0,
        }
    } else {
        script_pubkey.to_owned()
    };

    if program.is_p2wpkh() {
        return 1;
    }
    if program.is_p2wsh() {
        // The witness script is the last witness stack element.
        if let Some(ws) = witness.last() {
            return count_sigops(Script::from_bytes(ws), true) as u64;
        }
        return 0;
    }
    0
}

#[allow(clippy::too_many_arguments)]
fn execute_script(
    script: &Script,
    stack: &mut Vec<Vec<u8>>,
    tx: &Transaction,
    input_index: usize,
    amount: bitcoin::Amount,
    flags: ScriptFlags,
    sighash_cache: &mut SighashCache<&Transaction>,
) -> CoreResult<()> {
    execute_script_inner(
        script,
        stack,
        tx,
        input_index,
        amount,
        flags,
        false,
        sighash_cache,
    )
}

/// Like `execute_script`, but with a `segwit` flag indicating that OP_CHECKSIG
/// should use the BIP 143 segwit v0 sighash instead of the legacy sighash.
#[allow(clippy::too_many_arguments)]
fn execute_script_segwit(
    script: &Script,
    stack: &mut Vec<Vec<u8>>,
    tx: &Transaction,
    input_index: usize,
    amount: bitcoin::Amount,
    flags: ScriptFlags,
    sighash_cache: &mut SighashCache<&Transaction>,
) -> CoreResult<()> {
    execute_script_inner(
        script,
        stack,
        tx,
        input_index,
        amount,
        flags,
        true,
        sighash_cache,
    )
}

// ── M5 (2026-07-02 review): CONSENSUS DUPLICATION WARNING ──────────────────
// This legacy/segwit interpreter and `execute_tapscript` below duplicate the
// body of every opcode whose semantics did not change under BIP 342 (stack
// manipulation, arithmetic, hashing, flow control). Unifying them is deferred
// as consensus-critical surgery — until then, ANY fix to a shared opcode MUST
// be applied to BOTH interpreters, gated on the Core vector corpus
// (core_vectors.rs), the bitcoinconsensus differential test, and fuzz_script.
#[allow(clippy::too_many_arguments)]
fn execute_script_inner(
    script: &Script,
    stack: &mut Vec<Vec<u8>>,
    tx: &Transaction,
    input_index: usize,
    amount: bitcoin::Amount,
    flags: ScriptFlags,
    segwit: bool,
    sighash_cache: &mut SighashCache<&Transaction>,
) -> CoreResult<()> {
    let script_bytes = script.as_bytes();
    // Legacy / SegWit v0 scripts over 10,000 bytes are invalid (Core's
    // MAX_SCRIPT_SIZE, enforced at the top of EvalScript). Tapscript uses a
    // separate execution path and is not subject to this limit.
    if script_bytes.len() > MAX_SCRIPT_SIZE {
        return Err(CoreError::InvalidScript(format!(
            "script size {} exceeds {}",
            script_bytes.len(),
            MAX_SCRIPT_SIZE
        )));
    }

    let mut alt_stack: Vec<Vec<u8>> = Vec::new();
    let mut exec_stack: Vec<bool> = Vec::new(); // IF/ELSE/ENDIF nesting
    let mut op_count = 0u32;
    // Track OP_CODESEPARATOR position for sighash script_code.
    // After each executed OP_CODESEPARATOR, the script_code used by
    // OP_CHECKSIG starts from the byte AFTER the separator.
    let mut codesep_pos: usize = 0; // start of current script_code within script_bytes
    let mut byte_pos: usize = 0; // current read position in script_bytes

    for instruction in script.instructions() {
        let instruction = instruction
            .map_err(|e| CoreError::InvalidScript(format!("script parse error: {e}")))?;

        let executing = exec_stack.iter().all(|&b| b);

        // Track byte position for OP_CODESEPARATOR support.
        let _instr_start = byte_pos;
        match &instruction {
            Instruction::PushBytes(data) => {
                let len = data.len();
                // Encoding: OP_0=1byte; 1..75=1+len; 76=2+len(OP_PUSHDATA1);
                // 77=3+len(OP_PUSHDATA2); 78=5+len(OP_PUSHDATA4)
                byte_pos += match len {
                    0 => 1,
                    1..=75 => 1 + len,
                    76..=255 => 2 + len,
                    256..=65535 => 3 + len,
                    _ => 5 + len,
                };
            }
            Instruction::Op(_) => {
                byte_pos += 1;
            }
        }

        match instruction {
            Instruction::PushBytes(data) => {
                // The push-size limit is enforced for every push, even inside a
                // non-executed IF branch (Core checks it before the fExec gate).
                if data.len() > MAX_SCRIPT_ELEMENT_SIZE {
                    return Err(CoreError::InvalidScript(format!(
                        "push data size {} exceeds limit {}",
                        data.len(),
                        MAX_SCRIPT_ELEMENT_SIZE
                    )));
                }
                // BIP-110 rule 2: OP_PUSHDATA payloads over 256 bytes are invalid.
                // The redeemScript push of a P2SH scriptSig is exempt and is
                // checked separately (with the in-loop check disabled) in
                // `verify_script`, so the flag is never set for that execution.
                if flags.verify_bip110 && data.len() > BIP110_MAX_PUSH_SIZE {
                    return Err(CoreError::InvalidScript(format!(
                        "BIP-110: push of {} bytes exceeds {}",
                        data.len(),
                        BIP110_MAX_PUSH_SIZE
                    )));
                }
                if executing {
                    stack.push(data.as_bytes().to_vec());
                    if stack.len() + alt_stack.len() > MAX_STACK_SIZE {
                        return Err(CoreError::InvalidScript("stack size exceeded".into()));
                    }
                }
            }
            Instruction::Op(op) => {
                let op_byte = op.to_u8();

                // Only opcodes above OP_16 count toward the 201-op limit
                // (OP_RESERVED and the push-number opcodes are exempt). The
                // tally runs regardless of execution state, matching Core.
                if op_byte > 0x60 {
                    op_count += 1;
                    if op_count > 201 {
                        return Err(CoreError::InvalidScript("op count exceeded".into()));
                    }
                }

                // OP_VERIF / OP_VERNOTIF are illegal everywhere — they sit in
                // the OP_IF..=OP_ENDIF range Core always evaluates — and the
                // disabled opcodes (CVE-2010-5137) likewise fail even in a
                // non-executed branch. Both are checked before the fExec gate.
                if matches!(op_byte, 0x65 | 0x66) {
                    return Err(CoreError::InvalidScript(format!(
                        "bad opcode: 0x{op_byte:02x}"
                    )));
                }
                if is_disabled_opcode(op_byte) {
                    return Err(CoreError::InvalidScript(format!(
                        "disabled opcode: 0x{op_byte:02x}"
                    )));
                }

                // Handle IF/ELSE/ENDIF regardless of execution state
                match op_byte {
                    0x63 => {
                        // OP_IF
                        if executing {
                            let val = stack_pop(stack)?;
                            exec_stack.push(cast_to_bool(&val));
                        } else {
                            exec_stack.push(false);
                        }
                        continue;
                    }
                    0x64 => {
                        // OP_NOTIF
                        if executing {
                            let val = stack_pop(stack)?;
                            exec_stack.push(!cast_to_bool(&val));
                        } else {
                            exec_stack.push(false);
                        }
                        continue;
                    }
                    0x67 => {
                        // OP_ELSE
                        if let Some(last) = exec_stack.last_mut() {
                            *last = !*last;
                        } else {
                            return Err(CoreError::InvalidScript("OP_ELSE without OP_IF".into()));
                        }
                        continue;
                    }
                    0x68 => {
                        // OP_ENDIF
                        if exec_stack.pop().is_none() {
                            return Err(CoreError::InvalidScript("OP_ENDIF without OP_IF".into()));
                        }
                        continue;
                    }
                    _ => {}
                }

                if !executing {
                    continue;
                }

                match op_byte {
                    // Push number opcodes
                    0x00 => stack.push(vec![]),     // OP_0 / OP_FALSE
                    0x4f => stack.push(vec![0x81]), // OP_1NEGATE
                    0x51..=0x60 => stack.push(vec![op_byte - 0x50]), // OP_1..OP_16

                    // Stack operations
                    0x69 => {
                        // OP_VERIFY
                        let val = stack_pop(stack)?;
                        if !cast_to_bool(&val) {
                            return Err(CoreError::InvalidScript("OP_VERIFY failed".into()));
                        }
                    }
                    0x6a => {
                        // OP_RETURN
                        return Err(CoreError::InvalidScript("OP_RETURN".into()));
                    }
                    0x6b => {
                        // OP_TOALTSTACK
                        let val = stack_pop(stack)?;
                        alt_stack.push(val);
                    }
                    0x6c => {
                        // OP_FROMALTSTACK
                        let val = alt_stack
                            .pop()
                            .ok_or_else(|| CoreError::InvalidScript("alt stack empty".into()))?;
                        stack.push(val);
                    }
                    0x6d => {
                        // OP_2DROP
                        stack_pop(stack)?;
                        stack_pop(stack)?;
                    }
                    0x6e => {
                        // OP_2DUP
                        let len = stack.len();
                        if len < 2 {
                            return Err(CoreError::InvalidScript(
                                "stack too small for 2DUP".into(),
                            ));
                        }
                        stack.push(stack[len - 2].clone());
                        stack.push(stack[len - 1].clone());
                    }
                    0x6f => {
                        // OP_3DUP
                        let len = stack.len();
                        if len < 3 {
                            return Err(CoreError::InvalidScript(
                                "stack too small for 3DUP".into(),
                            ));
                        }
                        stack.push(stack[len - 3].clone());
                        stack.push(stack[len - 2].clone());
                        stack.push(stack[len - 1].clone());
                    }
                    0x70 => {
                        // OP_2OVER
                        let len = stack.len();
                        if len < 4 {
                            return Err(CoreError::InvalidScript(
                                "stack too small for 2OVER".into(),
                            ));
                        }
                        stack.push(stack[len - 4].clone());
                        stack.push(stack[len - 3].clone());
                    }
                    0x71 => {
                        // OP_2ROT
                        let len = stack.len();
                        if len < 6 {
                            return Err(CoreError::InvalidScript(
                                "stack too small for 2ROT".into(),
                            ));
                        }
                        let a = stack.remove(len - 6);
                        let b = stack.remove(len - 6); // shifted by 1 after first remove
                        stack.push(a);
                        stack.push(b);
                    }
                    0x72 => {
                        // OP_2SWAP
                        let len = stack.len();
                        if len < 4 {
                            return Err(CoreError::InvalidScript(
                                "stack too small for 2SWAP".into(),
                            ));
                        }
                        stack.swap(len - 4, len - 2);
                        stack.swap(len - 3, len - 1);
                    }
                    0x73 => {
                        // OP_IFDUP
                        let top = stack
                            .last()
                            .ok_or_else(|| CoreError::InvalidScript("empty stack".into()))?;
                        if cast_to_bool(top) {
                            let val = top.clone();
                            stack.push(val);
                        }
                    }
                    0x74 => {
                        // OP_DEPTH
                        let depth = stack.len() as i64;
                        stack.push(encode_num(depth));
                    }
                    0x75 => {
                        // OP_DROP
                        stack_pop(stack)?;
                    }
                    0x76 => {
                        // OP_DUP
                        let val = stack
                            .last()
                            .ok_or_else(|| CoreError::InvalidScript("empty stack for DUP".into()))?
                            .clone();
                        stack.push(val);
                    }
                    0x77 => {
                        // OP_NIP
                        if stack.len() < 2 {
                            return Err(CoreError::InvalidScript("stack too small for NIP".into()));
                        }
                        let len = stack.len();
                        stack.remove(len - 2);
                    }
                    0x78 => {
                        // OP_OVER
                        if stack.len() < 2 {
                            return Err(CoreError::InvalidScript(
                                "stack too small for OVER".into(),
                            ));
                        }
                        let val = stack[stack.len() - 2].clone();
                        stack.push(val);
                    }
                    0x79 => {
                        // OP_PICK
                        let n = decode_num(&stack_pop(stack)?)? as usize;
                        if n >= stack.len() {
                            return Err(CoreError::InvalidScript(
                                "stack too small for PICK".into(),
                            ));
                        }
                        let val = stack[stack.len() - 1 - n].clone();
                        stack.push(val);
                    }
                    0x7a => {
                        // OP_ROLL
                        let n = decode_num(&stack_pop(stack)?)? as usize;
                        if n >= stack.len() {
                            return Err(CoreError::InvalidScript(
                                "stack too small for ROLL".into(),
                            ));
                        }
                        let idx = stack.len() - 1 - n;
                        let val = stack.remove(idx);
                        stack.push(val);
                    }
                    0x7b => {
                        // OP_ROT
                        let len = stack.len();
                        if len < 3 {
                            return Err(CoreError::InvalidScript("stack too small for ROT".into()));
                        }
                        let val = stack.remove(len - 3);
                        stack.push(val);
                    }
                    0x7c => {
                        // OP_SWAP
                        let len = stack.len();
                        if len < 2 {
                            return Err(CoreError::InvalidScript(
                                "stack too small for SWAP".into(),
                            ));
                        }
                        stack.swap(len - 1, len - 2);
                    }
                    0x7d => {
                        // OP_TUCK
                        if stack.len() < 2 {
                            return Err(CoreError::InvalidScript(
                                "stack too small for TUCK".into(),
                            ));
                        }
                        let top = stack[stack.len() - 1].clone();
                        let len = stack.len();
                        stack.insert(len - 2, top);
                    }
                    0x82 => {
                        // OP_SIZE
                        let top = stack.last().ok_or_else(|| {
                            CoreError::InvalidScript("empty stack for SIZE".into())
                        })?;
                        let size = top.len() as i64;
                        stack.push(encode_num(size));
                    }

                    // Equality
                    0x87 => {
                        // OP_EQUAL
                        let b = stack_pop(stack)?;
                        let a = stack_pop(stack)?;
                        stack.push(if a == b { vec![1] } else { vec![] });
                    }
                    0x88 => {
                        // OP_EQUALVERIFY
                        let b = stack_pop(stack)?;
                        let a = stack_pop(stack)?;
                        if a != b {
                            return Err(CoreError::InvalidScript("OP_EQUALVERIFY failed".into()));
                        }
                    }

                    // Arithmetic
                    0x8b => {
                        // OP_1ADD
                        let a = decode_num(&stack_pop(stack)?)?;
                        stack.push(encode_num(a + 1));
                    }
                    0x8c => {
                        // OP_1SUB
                        let a = decode_num(&stack_pop(stack)?)?;
                        stack.push(encode_num(a - 1));
                    }
                    0x8f => {
                        // OP_NEGATE
                        let a = decode_num(&stack_pop(stack)?)?;
                        stack.push(encode_num(-a));
                    }
                    0x90 => {
                        // OP_ABS
                        let a = decode_num(&stack_pop(stack)?)?;
                        stack.push(encode_num(a.abs()));
                    }
                    0x91 => {
                        // OP_NOT
                        let a = decode_num(&stack_pop(stack)?)?;
                        stack.push(encode_num(if a == 0 { 1 } else { 0 }));
                    }
                    0x92 => {
                        // OP_0NOTEQUAL
                        let a = decode_num(&stack_pop(stack)?)?;
                        stack.push(encode_num(if a != 0 { 1 } else { 0 }));
                    }
                    0x93 => {
                        // OP_ADD
                        let b = decode_num(&stack_pop(stack)?)?;
                        let a = decode_num(&stack_pop(stack)?)?;
                        stack.push(encode_num(a + b));
                    }
                    0x94 => {
                        // OP_SUB
                        let b = decode_num(&stack_pop(stack)?)?;
                        let a = decode_num(&stack_pop(stack)?)?;
                        stack.push(encode_num(a - b));
                    }
                    0x9a => {
                        // OP_BOOLAND
                        let b = decode_num(&stack_pop(stack)?)?;
                        let a = decode_num(&stack_pop(stack)?)?;
                        stack.push(encode_num(if a != 0 && b != 0 { 1 } else { 0 }));
                    }
                    0x9b => {
                        // OP_BOOLOR
                        let b = decode_num(&stack_pop(stack)?)?;
                        let a = decode_num(&stack_pop(stack)?)?;
                        stack.push(encode_num(if a != 0 || b != 0 { 1 } else { 0 }));
                    }
                    0x9c => {
                        // OP_NUMEQUAL
                        let b = decode_num(&stack_pop(stack)?)?;
                        let a = decode_num(&stack_pop(stack)?)?;
                        stack.push(encode_num(if a == b { 1 } else { 0 }));
                    }
                    0x9d => {
                        // OP_NUMEQUALVERIFY
                        let b = decode_num(&stack_pop(stack)?)?;
                        let a = decode_num(&stack_pop(stack)?)?;
                        if a != b {
                            return Err(CoreError::InvalidScript(
                                "OP_NUMEQUALVERIFY failed".into(),
                            ));
                        }
                    }
                    0x9e => {
                        // OP_NUMNOTEQUAL
                        let b = decode_num(&stack_pop(stack)?)?;
                        let a = decode_num(&stack_pop(stack)?)?;
                        stack.push(encode_num(if a != b { 1 } else { 0 }));
                    }
                    0x9f => {
                        // OP_LESSTHAN
                        let b = decode_num(&stack_pop(stack)?)?;
                        let a = decode_num(&stack_pop(stack)?)?;
                        stack.push(encode_num(if a < b { 1 } else { 0 }));
                    }
                    0xa0 => {
                        // OP_GREATERTHAN
                        let b = decode_num(&stack_pop(stack)?)?;
                        let a = decode_num(&stack_pop(stack)?)?;
                        stack.push(encode_num(if a > b { 1 } else { 0 }));
                    }
                    0xa1 => {
                        // OP_LESSTHANOREQUAL
                        let b = decode_num(&stack_pop(stack)?)?;
                        let a = decode_num(&stack_pop(stack)?)?;
                        stack.push(encode_num(if a <= b { 1 } else { 0 }));
                    }
                    0xa2 => {
                        // OP_GREATERTHANOREQUAL
                        let b = decode_num(&stack_pop(stack)?)?;
                        let a = decode_num(&stack_pop(stack)?)?;
                        stack.push(encode_num(if a >= b { 1 } else { 0 }));
                    }
                    0xa3 => {
                        // OP_MIN
                        let b = decode_num(&stack_pop(stack)?)?;
                        let a = decode_num(&stack_pop(stack)?)?;
                        stack.push(encode_num(a.min(b)));
                    }
                    0xa4 => {
                        // OP_MAX
                        let b = decode_num(&stack_pop(stack)?)?;
                        let a = decode_num(&stack_pop(stack)?)?;
                        stack.push(encode_num(a.max(b)));
                    }
                    0xa5 => {
                        // OP_WITHIN
                        let max = decode_num(&stack_pop(stack)?)?;
                        let min = decode_num(&stack_pop(stack)?)?;
                        let x = decode_num(&stack_pop(stack)?)?;
                        stack.push(encode_num(if x >= min && x < max { 1 } else { 0 }));
                    }

                    // Crypto
                    0xa6 => {
                        // OP_RIPEMD160
                        let data = stack_pop(stack)?;
                        let hash = ripemd160::Hash::hash(&data);
                        stack.push(AsRef::<[u8]>::as_ref(&hash).to_vec());
                    }
                    0xa7 => {
                        // OP_SHA1
                        let data = stack_pop(stack)?;
                        let hash = sha1::Hash::hash(&data);
                        stack.push(AsRef::<[u8]>::as_ref(&hash).to_vec());
                    }
                    0xa8 => {
                        // OP_SHA256
                        let data = stack_pop(stack)?;
                        let hash = sha256::Hash::hash(&data);
                        stack.push(AsRef::<[u8]>::as_ref(&hash).to_vec());
                    }
                    0xa9 => {
                        // OP_HASH160
                        let data = stack_pop(stack)?;
                        let hash = hash160::Hash::hash(&data);
                        stack.push(AsRef::<[u8]>::as_ref(&hash).to_vec());
                    }
                    0xaa => {
                        // OP_HASH256
                        let data = stack_pop(stack)?;
                        let hash = sha256d::Hash::hash(&data);
                        stack.push(AsRef::<[u8]>::as_ref(&hash).to_vec());
                    }
                    0xac => {
                        // OP_CHECKSIG
                        let pubkey_data = stack_pop(stack)?;
                        let sig_data = stack_pop(stack)?;

                        // FindAndDelete: remove sig from script_code for legacy sighash
                        let cleaned_checksig = if !segwit && !sig_data.is_empty() {
                            let pattern = serialize_script_push(&sig_data);
                            Some(find_and_delete(&script_bytes[codesep_pos..], &pattern))
                        } else {
                            None
                        };
                        let sc = cleaned_checksig
                            .as_deref()
                            .unwrap_or(&script_bytes[codesep_pos..]);
                        let result = check_sig(
                            input_index,
                            amount,
                            &sig_data,
                            &pubkey_data,
                            Script::from_bytes(sc),
                            flags,
                            segwit,
                            sighash_cache,
                        );
                        stack.push(if result { vec![1] } else { vec![] });
                    }
                    0xad => {
                        // OP_CHECKSIGVERIFY
                        let pubkey_data = stack_pop(stack)?;
                        let sig_data = stack_pop(stack)?;

                        // FindAndDelete: remove sig from script_code for legacy sighash
                        let cleaned_csv = if !segwit && !sig_data.is_empty() {
                            let pattern = serialize_script_push(&sig_data);
                            Some(find_and_delete(&script_bytes[codesep_pos..], &pattern))
                        } else {
                            None
                        };
                        let sc = cleaned_csv
                            .as_deref()
                            .unwrap_or(&script_bytes[codesep_pos..]);
                        if !check_sig(
                            input_index,
                            amount,
                            &sig_data,
                            &pubkey_data,
                            Script::from_bytes(sc),
                            flags,
                            segwit,
                            sighash_cache,
                        ) {
                            return Err(CoreError::InvalidScript(
                                "OP_CHECKSIGVERIFY failed".into(),
                            ));
                        }
                    }
                    0xae => {
                        // OP_CHECKMULTISIG
                        let n_keys = decode_num(&stack_pop(stack)?)? as usize;
                        if n_keys > 20 {
                            return Err(CoreError::InvalidScript("too many keys".into()));
                        }
                        // Each pubkey checked counts toward the 201-op limit.
                        op_count += n_keys as u32;
                        if op_count > 201 {
                            return Err(CoreError::InvalidScript("op count exceeded".into()));
                        }

                        let mut keys = Vec::with_capacity(n_keys);
                        for _ in 0..n_keys {
                            keys.push(stack_pop(stack)?);
                        }

                        let n_sigs = decode_num(&stack_pop(stack)?)? as usize;
                        if n_sigs > n_keys {
                            return Err(CoreError::InvalidScript("more sigs than keys".into()));
                        }

                        let mut sigs = Vec::with_capacity(n_sigs);
                        for _ in 0..n_sigs {
                            sigs.push(stack_pop(stack)?);
                        }

                        // Pop the dummy element (Bitcoin's CHECKMULTISIG off-by-one
                        // bug). BIP 147 (NULLDUMMY) — a consensus rule since SegWit
                        // activation — requires it to be an empty byte vector; a
                        // non-null dummy is invalid.
                        let dummy = stack_pop(stack)?;
                        if flags.verify_nulldummy && !dummy.is_empty() {
                            return Err(CoreError::InvalidScript(
                                "BIP 147: CHECKMULTISIG dummy element must be empty (NULLDUMMY)"
                                    .into(),
                            ));
                        }

                        // FindAndDelete: for legacy (non-segwit) scripts, remove each
                        // signature's serialized push from the script_code before sighash.
                        let cleaned_script = if !segwit {
                            let mut sc = script_bytes[codesep_pos..].to_vec();
                            for sig in &sigs {
                                let pattern = serialize_script_push(sig);
                                sc = find_and_delete(&sc, &pattern);
                            }
                            Some(sc)
                        } else {
                            None
                        };

                        let mut key_idx = 0;
                        let mut success = true;
                        for sig in &sigs {
                            let mut matched = false;
                            while key_idx < n_keys {
                                let sc = cleaned_script
                                    .as_deref()
                                    .unwrap_or(&script_bytes[codesep_pos..]);
                                let script_code = Script::from_bytes(sc);
                                if check_sig(
                                    input_index,
                                    amount,
                                    sig,
                                    &keys[key_idx],
                                    script_code,
                                    flags,
                                    segwit,
                                    sighash_cache,
                                ) {
                                    matched = true;
                                    key_idx += 1;
                                    break;
                                }
                                key_idx += 1;
                            }
                            if !matched {
                                success = false;
                                break;
                            }
                        }
                        stack.push(if success { vec![1] } else { vec![] });
                    }
                    0xaf => {
                        // OP_CHECKMULTISIGVERIFY
                        // Same as CHECKMULTISIG + VERIFY
                        let n_keys = decode_num(&stack_pop(stack)?)? as usize;
                        if n_keys > 20 {
                            return Err(CoreError::InvalidScript("too many keys".into()));
                        }
                        op_count += n_keys as u32;
                        if op_count > 201 {
                            return Err(CoreError::InvalidScript("op count exceeded".into()));
                        }
                        let mut keys = Vec::with_capacity(n_keys);
                        for _ in 0..n_keys {
                            keys.push(stack_pop(stack)?);
                        }
                        let n_sigs = decode_num(&stack_pop(stack)?)? as usize;
                        // Bound n_sigs before allocating: a negative value casts
                        // to a huge usize, so an unbounded with_capacity here is a
                        // DoS (capacity overflow). Matches OP_CHECKMULTISIG.
                        if n_sigs > n_keys {
                            return Err(CoreError::InvalidScript("more sigs than keys".into()));
                        }
                        let mut sigs = Vec::with_capacity(n_sigs);
                        for _ in 0..n_sigs {
                            sigs.push(stack_pop(stack)?);
                        }
                        // BIP 147 (NULLDUMMY): the popped dummy must be empty when the
                        // rule is active (co-activated with SegWit).
                        let dummy = stack_pop(stack)?;
                        if flags.verify_nulldummy && !dummy.is_empty() {
                            return Err(CoreError::InvalidScript(
                                "BIP 147: CHECKMULTISIGVERIFY dummy element must be empty (NULLDUMMY)".into(),
                            ));
                        }

                        // FindAndDelete: for legacy (non-segwit) scripts, remove each
                        // signature's serialized push from the script_code before sighash.
                        let cleaned_script = if !segwit {
                            let mut sc = script_bytes[codesep_pos..].to_vec();
                            for sig in &sigs {
                                let pattern = serialize_script_push(sig);
                                sc = find_and_delete(&sc, &pattern);
                            }
                            Some(sc)
                        } else {
                            None
                        };

                        let mut key_idx = 0;
                        let mut success = true;
                        for sig in &sigs {
                            let mut matched = false;
                            while key_idx < n_keys {
                                let sc = cleaned_script
                                    .as_deref()
                                    .unwrap_or(&script_bytes[codesep_pos..]);
                                let script_code = Script::from_bytes(sc);
                                if check_sig(
                                    input_index,
                                    amount,
                                    sig,
                                    &keys[key_idx],
                                    script_code,
                                    flags,
                                    segwit,
                                    sighash_cache,
                                ) {
                                    matched = true;
                                    key_idx += 1;
                                    break;
                                }
                                key_idx += 1;
                            }
                            if !matched {
                                success = false;
                                break;
                            }
                        }
                        if !success {
                            return Err(CoreError::InvalidScript(
                                "OP_CHECKMULTISIGVERIFY failed".into(),
                            ));
                        }
                    }

                    // Locktime
                    0xb1 => {
                        // OP_CHECKLOCKTIMEVERIFY (BIP 65)
                        if flags.verify_checklocktimeverify {
                            // BIP 65 / BIP 112: 5-byte CScriptNum for lock-time values (matches Core's nMaxNumSize=5)
                            let locktime = decode_num_bounded(
                                stack.last().ok_or_else(|| {
                                    CoreError::InvalidScript("empty stack for CLTV".into())
                                })?,
                                5,
                            )?;
                            if locktime < 0 {
                                return Err(CoreError::InvalidScript("negative locktime".into()));
                            }
                            let locktime = locktime as u64;
                            let tx_locktime = tx.lock_time.to_consensus_u32() as u64;

                            // Both must be the same type (block height or time)
                            // Height < 500_000_000, time >= 500_000_000
                            let script_is_time = locktime >= 500_000_000;
                            let tx_is_time = tx_locktime >= 500_000_000;
                            if script_is_time != tx_is_time {
                                return Err(CoreError::InvalidScript(
                                    "CLTV: locktime type mismatch".into(),
                                ));
                            }

                            if locktime > tx_locktime {
                                return Err(CoreError::InvalidScript(format!(
                                    "CLTV: locktime {locktime} > tx locktime {tx_locktime}"
                                )));
                            }

                            // Input sequence must not be 0xffffffff (final)
                            if tx.input[input_index].sequence.0 == 0xffffffff {
                                return Err(CoreError::InvalidScript(
                                    "CLTV: input sequence is final".into(),
                                ));
                            }
                        }
                        // NOP2 behavior: don't pop the stack
                    }
                    0xb2 => {
                        // OP_CHECKSEQUENCEVERIFY (BIP 112)
                        if flags.verify_checksequenceverify {
                            // BIP 65 / BIP 112: 5-byte CScriptNum for lock-time values (matches Core's nMaxNumSize=5)
                            let sequence = decode_num_bounded(
                                stack.last().ok_or_else(|| {
                                    CoreError::InvalidScript("empty stack for CSV".into())
                                })?,
                                5,
                            )?;
                            if sequence < 0 {
                                return Err(CoreError::InvalidScript("negative sequence".into()));
                            }
                            let sequence = sequence as u32;

                            // If bit 31 (disable flag) is set, CSV is a NOP
                            if sequence & (1 << 31) == 0 {
                                let tx_sequence = tx.input[input_index].sequence.0;

                                // tx sequence must also not have disable flag set
                                if tx_sequence & (1 << 31) != 0 {
                                    return Err(CoreError::InvalidScript(
                                        "CSV: tx sequence has disable flag".into(),
                                    ));
                                }

                                // Both must be the same type (blocks or time)
                                // Bit 22 = type flag (0=blocks, 1=time)
                                let script_is_time = sequence & (1 << 22) != 0;
                                let tx_is_time = tx_sequence & (1 << 22) != 0;
                                if script_is_time != tx_is_time {
                                    return Err(CoreError::InvalidScript(
                                        "CSV: sequence type mismatch".into(),
                                    ));
                                }

                                // Mask to get the value (lower 16 bits)
                                let script_value = sequence & 0xffff;
                                let tx_value = tx_sequence & 0xffff;

                                if script_value > tx_value {
                                    return Err(CoreError::InvalidScript(format!(
                                        "CSV: required {script_value} > tx sequence {tx_value}"
                                    )));
                                }
                            }
                        }
                        // NOP3 behavior: don't pop the stack
                    }

                    // OP_CODESEPARATOR — update the script_code for sighash.
                    // Everything before (and including) this opcode is excluded
                    // from the script_code used by OP_CHECKSIG.
                    0xab => {
                        codesep_pos = byte_pos; // byte_pos is already past this opcode
                    }

                    // OP_NOP and OP_NOP1..OP_NOP10 - do nothing
                    0x61 | 0xb0 | 0xb3..=0xb9 => {}

                    // (Disabled opcodes and OP_VERIF/OP_VERNOTIF are rejected
                    // before the execution gate above.)
                    _ => {
                        // Unknown opcodes
                        return Err(CoreError::InvalidScript(format!(
                            "unsupported opcode: 0x{op_byte:02x}"
                        )));
                    }
                }

                // After any executed opcode the combined stack must stay within
                // the global limit (e.g. OP_3DUP can grow it without a push).
                if stack.len() + alt_stack.len() > MAX_STACK_SIZE {
                    return Err(CoreError::InvalidScript("stack size exceeded".into()));
                }
            }
        }
    }

    if !exec_stack.is_empty() {
        return Err(CoreError::InvalidScript("unbalanced IF/ENDIF".into()));
    }

    Ok(())
}

/// Tapscript execution engine (BIP 342).
///
/// Key differences from legacy script:
/// - OP_CHECKSIG/OP_CHECKSIGVERIFY use Schnorr signatures (BIP 340) instead of ECDSA
/// - OP_CHECKMULTISIG/OP_CHECKMULTISIGVERIFY are disabled
/// - OP_CHECKSIGADD (0xba) replaces multisig patterns: pops (sig, n, pubkey), pushes n+1 if valid, n if not
/// - Signature validation uses tapscript sighash
/// - Success opcodes (BIP 342: 0x50, 0x62, 0x7e-0x81, 0x83-0x86, 0x89-0x8a, 0x8d-0x8e, 0x95-0x99, 0xbb-0xfe) cause immediate success
/// - op_count limit is based on the actual number of non-push opcodes in the script
// ── M5 (2026-07-02 review): CONSENSUS DUPLICATION WARNING ──────────────────
// This tapscript interpreter and `execute_script_inner` above duplicate every
// opcode unchanged by BIP 342. ANY fix to a shared opcode MUST be applied to
// BOTH interpreters — see the matching comment on `execute_script_inner`.
#[allow(clippy::too_many_arguments)]
fn execute_tapscript(
    script: &Script,
    stack: &mut Vec<Vec<u8>>,
    tx: &Transaction,
    input_index: usize,
    all_prevouts: &[TxOut],
    tap_leaf: TapLeafHash,
    annex: Option<&Annex>,
    enforce_bip110: bool,
    sighash_cache: &mut SighashCache<&Transaction>,
) -> CoreResult<()> {
    // BIP-110 structural pre-scan over the whole Tapleaf script (rules apply even
    // to unexecuted opcodes): rule 6 rejects any OP_SUCCESS* opcode, and rule 2
    // rejects any OP_PUSHDATA payload over 256 bytes. Done before execution so an
    // OP_SUCCESS that would otherwise short-circuit to success is rejected instead.
    if enforce_bip110 {
        for instruction in script.instructions() {
            let instruction = instruction
                .map_err(|e| CoreError::InvalidScript(format!("tapscript parse error: {e}")))?;
            match instruction {
                Instruction::PushBytes(data) => {
                    if data.len() > BIP110_MAX_PUSH_SIZE {
                        return Err(CoreError::InvalidScript(format!(
                            "BIP-110: tapscript push of {} bytes exceeds {}",
                            data.len(),
                            BIP110_MAX_PUSH_SIZE
                        )));
                    }
                }
                Instruction::Op(op) => {
                    if is_tapscript_success_opcode(op.to_u8()) {
                        return Err(CoreError::InvalidScript(
                            "BIP-110: tapscript contains OP_SUCCESS opcode".into(),
                        ));
                    }
                }
            }
        }
    }

    let mut alt_stack: Vec<Vec<u8>> = Vec::new();
    let mut exec_stack: Vec<bool> = Vec::new();
    // BIP 342: no opcode count limit in tapscript.
    // Instead, signature validation budget = 50 + total witness byte size.
    // Each signature check (OP_CHECKSIG[VERIFY], OP_CHECKSIGADD) costs 50.
    let witness = &tx.input[input_index].witness;
    let witness_bytes: usize = witness.iter().map(|w| w.len()).sum();
    let mut sigops_budget: i64 = 50 + witness_bytes as i64;

    // BIP 342: track OP_CODESEPARATOR position for sighash.
    // 0xFFFFFFFF means no OP_CODESEPARATOR has been executed yet.
    // The position is the opcode position (instruction index), NOT the byte offset.
    // Bitcoin Core increments a counter after each instruction (including push data ops).
    let mut codesep_pos: u32 = 0xFFFFFFFF;
    let mut opcode_pos: u32 = 0;

    for instruction in script.instructions() {
        let instruction = instruction
            .map_err(|e| CoreError::InvalidScript(format!("tapscript parse error: {e}")))?;

        let executing = exec_stack.iter().all(|&b| b);

        match instruction {
            Instruction::PushBytes(data) => {
                if executing {
                    if data.len() > MAX_SCRIPT_ELEMENT_SIZE {
                        return Err(CoreError::InvalidScript(format!(
                            "push data size {} exceeds limit {}",
                            data.len(),
                            MAX_SCRIPT_ELEMENT_SIZE
                        )));
                    }
                    stack.push(data.as_bytes().to_vec());
                    if stack.len() + alt_stack.len() > MAX_STACK_SIZE {
                        return Err(CoreError::InvalidScript("stack size exceeded".into()));
                    }
                }
            }
            Instruction::Op(op) => {
                let op_byte = op.to_u8();

                // Check for OP_SUCCESS opcodes (BIP 342) — cause immediate success
                if is_tapscript_success_opcode(op_byte) {
                    return Ok(());
                }

                // BIP-110 rule 7: executing OP_IF or OP_NOTIF in a Tapscript is
                // invalid (regardless of the branch taken). Only fires when the
                // opcode is actually reached in an executing branch.
                if enforce_bip110 && executing && (op_byte == 0x63 || op_byte == 0x64) {
                    return Err(CoreError::InvalidScript(
                        "BIP-110: tapscript executes OP_IF/OP_NOTIF".into(),
                    ));
                }

                // Handle IF/ELSE/ENDIF (same as legacy)
                match op_byte {
                    0x63 => {
                        // OP_IF
                        if executing {
                            let val = stack_pop(stack)?;
                            exec_stack.push(cast_to_bool(&val));
                        } else {
                            exec_stack.push(false);
                        }
                        continue;
                    }
                    0x64 => {
                        // OP_NOTIF
                        if executing {
                            let val = stack_pop(stack)?;
                            exec_stack.push(!cast_to_bool(&val));
                        } else {
                            exec_stack.push(false);
                        }
                        continue;
                    }
                    0x67 => {
                        // OP_ELSE
                        if let Some(last) = exec_stack.last_mut() {
                            *last = !*last;
                        } else {
                            return Err(CoreError::InvalidScript("OP_ELSE without OP_IF".into()));
                        }
                        continue;
                    }
                    0x68 => {
                        // OP_ENDIF
                        if exec_stack.pop().is_none() {
                            return Err(CoreError::InvalidScript("OP_ENDIF without OP_IF".into()));
                        }
                        continue;
                    }
                    _ => {}
                }

                if !executing {
                    continue;
                }

                match op_byte {
                    // OP_CHECKSIG in tapscript — BIP 342 Schnorr
                    0xac => {
                        let pubkey_data = stack_pop(stack)?;
                        let sig_data = stack_pop(stack)?;

                        // BIP 342: 0-byte pubkey always fails immediately
                        if pubkey_data.is_empty() {
                            return Err(CoreError::InvalidScript("tapscript: empty pubkey".into()));
                        }

                        if sig_data.is_empty() {
                            // Empty sig → push false (no sigops charge)
                            stack.push(vec![]);
                        } else {
                            sigops_budget -= 50;
                            if sigops_budget < 0 {
                                return Err(CoreError::InvalidScript(
                                    "tapscript sigops budget exceeded".into(),
                                ));
                            }
                            if pubkey_data.len() != 32 {
                                // Unknown pubkey type: validation considered successful
                                stack.push(vec![1]);
                            } else {
                                // 32-byte key: actual Schnorr verification
                                // BIP 342: non-empty sig that fails = immediate script failure
                                if tapscript_check_sig(
                                    input_index,
                                    all_prevouts,
                                    &sig_data,
                                    &pubkey_data,
                                    tap_leaf,
                                    codesep_pos,
                                    annex.cloned(),
                                    sighash_cache,
                                ) {
                                    stack.push(vec![1]);
                                } else {
                                    return Err(CoreError::InvalidScript(
                                        "OP_CHECKSIG: Schnorr signature verification failed".into(),
                                    ));
                                }
                            }
                        }
                    }
                    // OP_CHECKSIGVERIFY in tapscript — BIP 342 Schnorr
                    0xad => {
                        let pubkey_data = stack_pop(stack)?;
                        let sig_data = stack_pop(stack)?;

                        // BIP 342: 0-byte pubkey always fails immediately
                        if pubkey_data.is_empty() {
                            return Err(CoreError::InvalidScript("tapscript: empty pubkey".into()));
                        }

                        if sig_data.is_empty() {
                            // BIP 342: CHECKSIG with empty sig pushes false;
                            // VERIFY then pops false and fails.
                            return Err(CoreError::InvalidScript(
                                "OP_CHECKSIGVERIFY failed: empty signature".into(),
                            ));
                        } else {
                            sigops_budget -= 50;
                            if sigops_budget < 0 {
                                return Err(CoreError::InvalidScript(
                                    "tapscript sigops budget exceeded".into(),
                                ));
                            }
                            if pubkey_data.len() != 32 {
                                // Unknown pubkey type: validation considered successful
                            } else {
                                // 32-byte key: actual Schnorr verification
                                if !tapscript_check_sig(
                                    input_index,
                                    all_prevouts,
                                    &sig_data,
                                    &pubkey_data,
                                    tap_leaf,
                                    codesep_pos,
                                    annex.cloned(),
                                    sighash_cache,
                                ) {
                                    return Err(CoreError::InvalidScript(
                                        "OP_CHECKSIGVERIFY failed in tapscript".into(),
                                    ));
                                }
                            }
                        }
                    }
                    // OP_CHECKMULTISIG/OP_CHECKMULTISIGVERIFY are disabled in tapscript
                    0xae | 0xaf => {
                        return Err(CoreError::InvalidScript(
                            "OP_CHECKMULTISIG disabled in tapscript (use OP_CHECKSIGADD)".into(),
                        ));
                    }
                    // OP_CHECKSIGADD (0xba) — BIP 342
                    0xba => {
                        let pubkey_data = stack_pop(stack)?;
                        let n_data = stack_pop(stack)?;
                        let sig_data = stack_pop(stack)?;

                        let n = decode_num(&n_data)?;

                        // BIP 342: 0-byte pubkey always fails immediately
                        if pubkey_data.is_empty() {
                            return Err(CoreError::InvalidScript("tapscript: empty pubkey".into()));
                        }

                        if sig_data.is_empty() {
                            // Empty signature: push n (skip this key)
                            stack.push(encode_num(n));
                        } else {
                            sigops_budget -= 50;
                            if sigops_budget < 0 {
                                return Err(CoreError::InvalidScript(
                                    "tapscript sigops budget exceeded".into(),
                                ));
                            }
                            if pubkey_data.len() != 32 {
                                // Unknown pubkey type: validation considered successful
                                stack.push(encode_num(n + 1));
                            } else {
                                // 32-byte key: actual Schnorr verification
                                if tapscript_check_sig(
                                    input_index,
                                    all_prevouts,
                                    &sig_data,
                                    &pubkey_data,
                                    tap_leaf,
                                    codesep_pos,
                                    annex.cloned(),
                                    sighash_cache,
                                ) {
                                    stack.push(encode_num(n + 1));
                                } else {
                                    return Err(CoreError::InvalidScript(
                                        "OP_CHECKSIGADD: non-empty signature failed verification"
                                            .into(),
                                    ));
                                }
                            }
                        }
                    }
                    // Constants
                    0x00 => stack.push(vec![]),
                    0x4f => stack.push(encode_num(-1)), // OP_1NEGATE
                    v @ 0x51..=0x60 => stack.push(encode_num((v - 0x50) as i64)),

                    // Stack ops — full parity with legacy
                    0x69 => {
                        // OP_VERIFY
                        let val = stack_pop(stack)?;
                        if !cast_to_bool(&val) {
                            return Err(CoreError::InvalidScript("OP_VERIFY failed".into()));
                        }
                    }
                    0x6a => return Err(CoreError::InvalidScript("OP_RETURN".into())),
                    0x6b => {
                        // OP_TOALTSTACK
                        let val = stack_pop(stack)?;
                        alt_stack.push(val);
                    }
                    0x6c => {
                        // OP_FROMALTSTACK
                        let val = alt_stack
                            .pop()
                            .ok_or_else(|| CoreError::InvalidScript("alt stack empty".into()))?;
                        stack.push(val);
                    }
                    0x6d => {
                        // OP_2DROP
                        stack_pop(stack)?;
                        stack_pop(stack)?;
                    }
                    0x6e => {
                        // OP_2DUP
                        let len = stack.len();
                        if len < 2 {
                            return Err(CoreError::InvalidScript(
                                "stack too small for 2DUP".into(),
                            ));
                        }
                        stack.push(stack[len - 2].clone());
                        stack.push(stack[len - 1].clone());
                    }
                    0x6f => {
                        // OP_3DUP
                        let len = stack.len();
                        if len < 3 {
                            return Err(CoreError::InvalidScript(
                                "stack too small for 3DUP".into(),
                            ));
                        }
                        stack.push(stack[len - 3].clone());
                        stack.push(stack[len - 2].clone());
                        stack.push(stack[len - 1].clone());
                    }
                    0x70 => {
                        // OP_2OVER
                        let len = stack.len();
                        if len < 4 {
                            return Err(CoreError::InvalidScript(
                                "stack too small for 2OVER".into(),
                            ));
                        }
                        stack.push(stack[len - 4].clone());
                        stack.push(stack[len - 3].clone());
                    }
                    0x71 => {
                        // OP_2ROT
                        let len = stack.len();
                        if len < 6 {
                            return Err(CoreError::InvalidScript(
                                "stack too small for 2ROT".into(),
                            ));
                        }
                        let a = stack.remove(len - 6);
                        let b = stack.remove(len - 6);
                        stack.push(a);
                        stack.push(b);
                    }
                    0x72 => {
                        // OP_2SWAP
                        let len = stack.len();
                        if len < 4 {
                            return Err(CoreError::InvalidScript(
                                "stack too small for 2SWAP".into(),
                            ));
                        }
                        stack.swap(len - 4, len - 2);
                        stack.swap(len - 3, len - 1);
                    }
                    0x73 => {
                        // OP_IFDUP
                        let top = stack
                            .last()
                            .ok_or_else(|| CoreError::InvalidScript("empty stack".into()))?;
                        if cast_to_bool(top) {
                            let val = top.clone();
                            stack.push(val);
                        }
                    }
                    0x74 => {
                        // OP_DEPTH
                        let depth = stack.len() as i64;
                        stack.push(encode_num(depth));
                    }
                    0x75 => {
                        stack_pop(stack)?;
                    } // OP_DROP
                    0x76 => {
                        // OP_DUP
                        let val = stack
                            .last()
                            .ok_or_else(|| CoreError::InvalidScript("stack underflow".into()))?
                            .clone();
                        stack.push(val);
                    }
                    0x77 => {
                        // OP_NIP
                        if stack.len() < 2 {
                            return Err(CoreError::InvalidScript("stack too small for NIP".into()));
                        }
                        let len = stack.len();
                        stack.remove(len - 2);
                    }
                    0x78 => {
                        // OP_OVER
                        if stack.len() < 2 {
                            return Err(CoreError::InvalidScript(
                                "stack too small for OVER".into(),
                            ));
                        }
                        let val = stack[stack.len() - 2].clone();
                        stack.push(val);
                    }
                    0x79 => {
                        // OP_PICK
                        let n = decode_num(&stack_pop(stack)?)? as usize;
                        if n >= stack.len() {
                            return Err(CoreError::InvalidScript(
                                "stack too small for PICK".into(),
                            ));
                        }
                        let val = stack[stack.len() - 1 - n].clone();
                        stack.push(val);
                    }
                    0x7a => {
                        // OP_ROLL
                        let n = decode_num(&stack_pop(stack)?)? as usize;
                        if n >= stack.len() {
                            return Err(CoreError::InvalidScript(
                                "stack too small for ROLL".into(),
                            ));
                        }
                        let idx = stack.len() - 1 - n;
                        let val = stack.remove(idx);
                        stack.push(val);
                    }
                    0x7b => {
                        // OP_ROT
                        let len = stack.len();
                        if len < 3 {
                            return Err(CoreError::InvalidScript("stack too small for ROT".into()));
                        }
                        let val = stack.remove(len - 3);
                        stack.push(val);
                    }
                    0x7c => {
                        // OP_SWAP
                        let len = stack.len();
                        if len < 2 {
                            return Err(CoreError::InvalidScript(
                                "stack too small for SWAP".into(),
                            ));
                        }
                        stack.swap(len - 1, len - 2);
                    }
                    0x7d => {
                        // OP_TUCK
                        if stack.len() < 2 {
                            return Err(CoreError::InvalidScript(
                                "stack too small for TUCK".into(),
                            ));
                        }
                        let top = stack[stack.len() - 1].clone();
                        let len = stack.len();
                        stack.insert(len - 2, top);
                    }
                    0x82 => {
                        // OP_SIZE
                        let top = stack.last().ok_or_else(|| {
                            CoreError::InvalidScript("empty stack for SIZE".into())
                        })?;
                        let size = top.len() as i64;
                        stack.push(encode_num(size));
                    }

                    // Equality
                    0x87 => {
                        // OP_EQUAL
                        let b = stack_pop(stack)?;
                        let a = stack_pop(stack)?;
                        stack.push(if a == b { vec![1] } else { vec![] });
                    }
                    0x88 => {
                        // OP_EQUALVERIFY
                        let b = stack_pop(stack)?;
                        let a = stack_pop(stack)?;
                        if a != b {
                            return Err(CoreError::InvalidScript("OP_EQUALVERIFY failed".into()));
                        }
                    }

                    // Arithmetic — full parity
                    0x8b => {
                        // OP_1ADD
                        let a = decode_num(&stack_pop(stack)?)?;
                        stack.push(encode_num(a + 1));
                    }
                    0x8c => {
                        // OP_1SUB
                        let a = decode_num(&stack_pop(stack)?)?;
                        stack.push(encode_num(a - 1));
                    }
                    0x8f => {
                        // OP_NEGATE
                        let a = decode_num(&stack_pop(stack)?)?;
                        stack.push(encode_num(-a));
                    }
                    0x90 => {
                        // OP_ABS
                        let a = decode_num(&stack_pop(stack)?)?;
                        stack.push(encode_num(a.abs()));
                    }
                    0x91 => {
                        // OP_NOT
                        let a = decode_num(&stack_pop(stack)?)?;
                        stack.push(encode_num(if a == 0 { 1 } else { 0 }));
                    }
                    0x92 => {
                        // OP_0NOTEQUAL
                        let a = decode_num(&stack_pop(stack)?)?;
                        stack.push(encode_num(if a != 0 { 1 } else { 0 }));
                    }
                    0x93 => {
                        // OP_ADD
                        let b = decode_num(&stack_pop(stack)?)?;
                        let a = decode_num(&stack_pop(stack)?)?;
                        stack.push(encode_num(a + b));
                    }
                    0x94 => {
                        // OP_SUB
                        let b = decode_num(&stack_pop(stack)?)?;
                        let a = decode_num(&stack_pop(stack)?)?;
                        stack.push(encode_num(a - b));
                    }
                    0x9a => {
                        // OP_BOOLAND
                        let b = decode_num(&stack_pop(stack)?)?;
                        let a = decode_num(&stack_pop(stack)?)?;
                        stack.push(encode_num(if a != 0 && b != 0 { 1 } else { 0 }));
                    }
                    0x9b => {
                        // OP_BOOLOR
                        let b = decode_num(&stack_pop(stack)?)?;
                        let a = decode_num(&stack_pop(stack)?)?;
                        stack.push(encode_num(if a != 0 || b != 0 { 1 } else { 0 }));
                    }
                    0x9c => {
                        // OP_NUMEQUAL
                        let b = decode_num(&stack_pop(stack)?)?;
                        let a = decode_num(&stack_pop(stack)?)?;
                        stack.push(if a == b { vec![1] } else { vec![] });
                    }
                    0x9d => {
                        // OP_NUMEQUALVERIFY
                        let b = decode_num(&stack_pop(stack)?)?;
                        let a = decode_num(&stack_pop(stack)?)?;
                        if a != b {
                            return Err(CoreError::InvalidScript(
                                "OP_NUMEQUALVERIFY failed".into(),
                            ));
                        }
                    }
                    0x9e => {
                        // OP_NUMNOTEQUAL
                        let b = decode_num(&stack_pop(stack)?)?;
                        let a = decode_num(&stack_pop(stack)?)?;
                        stack.push(encode_num(if a != b { 1 } else { 0 }));
                    }
                    0x9f => {
                        // OP_LESSTHAN
                        let b = decode_num(&stack_pop(stack)?)?;
                        let a = decode_num(&stack_pop(stack)?)?;
                        stack.push(encode_num(if a < b { 1 } else { 0 }));
                    }
                    0xa0 => {
                        // OP_GREATERTHAN
                        let b = decode_num(&stack_pop(stack)?)?;
                        let a = decode_num(&stack_pop(stack)?)?;
                        stack.push(encode_num(if a > b { 1 } else { 0 }));
                    }
                    0xa1 => {
                        // OP_LESSTHANOREQUAL
                        let b = decode_num(&stack_pop(stack)?)?;
                        let a = decode_num(&stack_pop(stack)?)?;
                        stack.push(encode_num(if a <= b { 1 } else { 0 }));
                    }
                    0xa2 => {
                        // OP_GREATERTHANOREQUAL
                        let b = decode_num(&stack_pop(stack)?)?;
                        let a = decode_num(&stack_pop(stack)?)?;
                        stack.push(encode_num(if a >= b { 1 } else { 0 }));
                    }
                    0xa3 => {
                        // OP_MIN
                        let b = decode_num(&stack_pop(stack)?)?;
                        let a = decode_num(&stack_pop(stack)?)?;
                        stack.push(encode_num(a.min(b)));
                    }
                    0xa4 => {
                        // OP_MAX
                        let b = decode_num(&stack_pop(stack)?)?;
                        let a = decode_num(&stack_pop(stack)?)?;
                        stack.push(encode_num(a.max(b)));
                    }
                    0xa5 => {
                        // OP_WITHIN
                        let max = decode_num(&stack_pop(stack)?)?;
                        let min = decode_num(&stack_pop(stack)?)?;
                        let x = decode_num(&stack_pop(stack)?)?;
                        stack.push(encode_num(if x >= min && x < max { 1 } else { 0 }));
                    }

                    // Crypto — full hash opcodes
                    0xa6 => {
                        // OP_RIPEMD160
                        let data = stack_pop(stack)?;
                        let hash = ripemd160::Hash::hash(&data);
                        stack.push(AsRef::<[u8]>::as_ref(&hash).to_vec());
                    }
                    0xa7 => {
                        // OP_SHA1
                        let data = stack_pop(stack)?;
                        let hash = sha1::Hash::hash(&data);
                        stack.push(AsRef::<[u8]>::as_ref(&hash).to_vec());
                    }
                    0xa8 => {
                        // OP_SHA256
                        let data = stack_pop(stack)?;
                        let hash = sha256::Hash::hash(&data);
                        stack.push(AsRef::<[u8]>::as_ref(&hash).to_vec());
                    }
                    0xa9 => {
                        // OP_HASH160
                        let data = stack_pop(stack)?;
                        let hash = hash160::Hash::hash(&data);
                        stack.push(AsRef::<[u8]>::as_ref(&hash).to_vec());
                    }
                    0xaa => {
                        // OP_HASH256
                        let data = stack_pop(stack)?;
                        let hash = sha256d::Hash::hash(&data);
                        stack.push(AsRef::<[u8]>::as_ref(&hash).to_vec());
                    }
                    // OP_CODESEPARATOR in tapscript — updates the code separator position
                    // BIP 342: codesep_pos is the opcode position (instruction index)
                    0xab => {
                        codesep_pos = opcode_pos;
                    }

                    // NOP opcodes
                    0x61 | 0xb0 | 0xb3..=0xb9 => {} // OP_NOP, OP_NOP1, OP_NOP4-10
                    // OP_CHECKLOCKTIMEVERIFY (BIP 65) in tapscript
                    0xb1 => {
                        // BIP 65 / BIP 112: 5-byte CScriptNum for lock-time values (matches Core's nMaxNumSize=5)
                        let locktime = decode_num_bounded(
                            stack.last().ok_or_else(|| {
                                CoreError::InvalidScript("empty stack for CLTV".into())
                            })?,
                            5,
                        )?;
                        if locktime < 0 {
                            return Err(CoreError::InvalidScript("negative locktime".into()));
                        }
                        let locktime = locktime as u64;
                        let tx_locktime = tx.lock_time.to_consensus_u32() as u64;

                        let script_is_time = locktime >= 500_000_000;
                        let tx_is_time = tx_locktime >= 500_000_000;
                        if script_is_time != tx_is_time {
                            return Err(CoreError::InvalidScript(
                                "CLTV: locktime type mismatch".into(),
                            ));
                        }

                        if locktime > tx_locktime {
                            return Err(CoreError::InvalidScript(format!(
                                "CLTV: locktime {locktime} > tx locktime {tx_locktime}"
                            )));
                        }

                        if tx.input[input_index].sequence.0 == 0xffffffff {
                            return Err(CoreError::InvalidScript(
                                "CLTV: input sequence is final".into(),
                            ));
                        }
                    }
                    // OP_CHECKSEQUENCEVERIFY (BIP 112) in tapscript
                    0xb2 => {
                        // BIP 65 / BIP 112: 5-byte CScriptNum for lock-time values (matches Core's nMaxNumSize=5)
                        let sequence = decode_num_bounded(
                            stack.last().ok_or_else(|| {
                                CoreError::InvalidScript("empty stack for CSV".into())
                            })?,
                            5,
                        )?;
                        if sequence < 0 {
                            return Err(CoreError::InvalidScript("negative sequence".into()));
                        }
                        let sequence = sequence as u32;

                        if sequence & (1 << 31) == 0 {
                            let tx_sequence = tx.input[input_index].sequence.0;

                            if tx_sequence & (1 << 31) != 0 {
                                return Err(CoreError::InvalidScript(
                                    "CSV: tx sequence has disable flag".into(),
                                ));
                            }

                            let script_is_time = sequence & (1 << 22) != 0;
                            let tx_is_time = tx_sequence & (1 << 22) != 0;
                            if script_is_time != tx_is_time {
                                return Err(CoreError::InvalidScript(
                                    "CSV: sequence type mismatch".into(),
                                ));
                            }

                            let script_value = sequence & 0xffff;
                            let tx_value = tx_sequence & 0xffff;

                            if script_value > tx_value {
                                return Err(CoreError::InvalidScript(format!(
                                    "CSV: required {script_value} > tx sequence {tx_value}"
                                )));
                            }
                        }
                    }
                    _ => {
                        // Unknown opcode in tapscript — fail
                        return Err(CoreError::InvalidScript(format!(
                            "unknown tapscript opcode: 0x{op_byte:02x}"
                        )));
                    }
                }

                // Check stack size limits
                if stack.len() + alt_stack.len() > MAX_STACK_SIZE {
                    return Err(CoreError::InvalidScript("stack size exceeded".into()));
                }
            }
        }

        // BIP 342: opcode_pos counts every instruction (push data and opcodes alike),
        // incremented AFTER processing so OP_CODESEPARATOR records its 0-based position.
        opcode_pos += 1;
    }

    if !exec_stack.is_empty() {
        return Err(CoreError::InvalidScript(
            "unbalanced IF/ENDIF in tapscript".into(),
        ));
    }

    Ok(())
}

/// Serialize data as a Bitcoin script push operation (for FindAndDelete).
/// Returns the bytes that would appear in a script to push `data`.
fn serialize_script_push(data: &[u8]) -> Vec<u8> {
    let mut result = Vec::with_capacity(data.len() + 5);
    let len = data.len();
    if len < 76 {
        result.push(len as u8);
    } else if len < 256 {
        result.push(0x4c); // OP_PUSHDATA1
        result.push(len as u8);
    } else if len < 65536 {
        result.push(0x4d); // OP_PUSHDATA2
        result.push((len & 0xff) as u8);
        result.push(((len >> 8) & 0xff) as u8);
    } else {
        result.push(0x4e); // OP_PUSHDATA4
        result.push((len & 0xff) as u8);
        result.push(((len >> 8) & 0xff) as u8);
        result.push(((len >> 16) & 0xff) as u8);
        result.push(((len >> 24) & 0xff) as u8);
    }
    result.extend_from_slice(data);
    result
}

/// Remove all non-overlapping occurrences of `pattern` from `script`.
/// This implements Bitcoin Core's FindAndDelete for CHECKMULTISIG sighash.
fn find_and_delete(script: &[u8], pattern: &[u8]) -> Vec<u8> {
    if pattern.is_empty() || pattern.len() > script.len() {
        return script.to_vec();
    }
    let mut result = Vec::with_capacity(script.len());
    let mut i = 0;
    while i < script.len() {
        if i + pattern.len() <= script.len() && &script[i..i + pattern.len()] == pattern {
            i += pattern.len(); // Skip the pattern
        } else {
            result.push(script[i]);
            i += 1;
        }
    }
    result
}

/// Remove every `OP_CODESEPARATOR` (0xab) from a subscript, walking it one
/// opcode at a time so that a 0xab byte occurring *inside* a data push (e.g. a
/// pubkey or signature payload) is left untouched. This mirrors Bitcoin Core's
/// `CTransactionSignatureSerializer::SerializeScriptCode`, which omits the
/// separator bytes from the legacy sighash preimage. On a malformed/truncated
/// push the remaining bytes are copied verbatim (matching `GetOp` bailing out).
fn remove_codeseparators(script: &[u8]) -> Vec<u8> {
    let mut result = Vec::with_capacity(script.len());
    let mut i = 0;
    while i < script.len() {
        let op = script[i];
        // Determine the length of an immediate data push so its payload is
        // copied opaquely and never scanned for 0xab.
        let (extra_len_bytes, payload_len) = match op {
            0x01..=0x4b => (0usize, op as usize),
            0x4c => {
                // OP_PUSHDATA1
                if i + 1 >= script.len() {
                    result.extend_from_slice(&script[i..]);
                    break;
                }
                (1, script[i + 1] as usize)
            }
            0x4d => {
                // OP_PUSHDATA2
                if i + 2 >= script.len() {
                    result.extend_from_slice(&script[i..]);
                    break;
                }
                (
                    2,
                    u16::from_le_bytes([script[i + 1], script[i + 2]]) as usize,
                )
            }
            0x4e => {
                // OP_PUSHDATA4
                if i + 4 >= script.len() {
                    result.extend_from_slice(&script[i..]);
                    break;
                }
                (
                    4,
                    u32::from_le_bytes([script[i + 1], script[i + 2], script[i + 3], script[i + 4]])
                        as usize,
                )
            }
            _ => {
                // Non-push opcode. Drop OP_CODESEPARATOR; copy everything else.
                if op != 0xab {
                    result.push(op);
                }
                i += 1;
                continue;
            }
        };
        let total = 1 + extra_len_bytes + payload_len;
        if i + total > script.len() {
            // Truncated push — copy the remainder and stop, as GetOp would.
            result.extend_from_slice(&script[i..]);
            break;
        }
        result.extend_from_slice(&script[i..i + total]);
        i += total;
    }
    result
}

/// Check if an opcode is a tapscript OP_SUCCESS (BIP 342).
/// These opcodes cause immediate script success when encountered.
/// Full list per BIP 342: 80, 98, 126-129, 131-134, 137-138, 141-142, 149-153, 187-254
fn is_tapscript_success_opcode(op: u8) -> bool {
    matches!(
        op,
        0x50 | 0x62 | 0x7e..=0x81 | 0x83..=0x86 | 0x89 | 0x8a | 0x8d | 0x8e | 0x95..=0x99 | 0xbb..=0xfe
    )
}

/// Verify a Schnorr signature in tapscript context.
/// Caller must ensure sig_data is non-empty and pubkey_data is 32 bytes.
#[allow(clippy::too_many_arguments)]
fn tapscript_check_sig(
    input_index: usize,
    all_prevouts: &[TxOut],
    sig_data: &[u8],
    pubkey_data: &[u8],
    tap_leaf: TapLeafHash,
    codesep_pos: u32,
    annex: Option<Annex>,
    sighash_cache: &mut SighashCache<&Transaction>,
) -> bool {
    if sig_data.is_empty() || pubkey_data.len() != 32 {
        return false;
    }

    let pubkey = match XOnlyPublicKey::from_slice(pubkey_data) {
        Ok(pk) => pk,
        Err(_) => return false,
    };

    verify_taproot_script_sig(
        input_index,
        all_prevouts,
        &pubkey,
        sig_data,
        tap_leaf,
        codesep_pos,
        annex,
        sighash_cache,
    )
    .is_ok()
}

/// Check a signature against a public key for a transaction input.
/// The transaction is carried by `sighash_cache` (one per input check, so the
/// memoized BIP 143 midstates are shared across every signature in the input).
#[allow(clippy::too_many_arguments)]
fn check_sig(
    input_index: usize,
    amount: bitcoin::Amount,
    sig_data: &[u8],
    pubkey_data: &[u8],
    script_code: &Script,
    flags: ScriptFlags,
    segwit: bool,
    sighash_cache: &mut SighashCache<&Transaction>,
) -> bool {
    if sig_data.is_empty() || pubkey_data.is_empty() {
        return false;
    }

    let secp = secp_ctx();

    let pubkey = match PublicKey::from_slice(pubkey_data) {
        Ok(pk) => pk,
        Err(_) => return false,
    };

    let sighash_type_byte = sig_data[sig_data.len() - 1];
    let sig_der = &sig_data[..sig_data.len() - 1];

    // Pre-BIP66 blocks allow non-standard DER encodings; use lax parsing for those.
    let mut signature = if flags.verify_strictenc {
        match secp256k1::ecdsa::Signature::from_der(sig_der) {
            Ok(sig) => sig,
            Err(_) => return false,
        }
    } else {
        match secp256k1::ecdsa::Signature::from_der_lax(sig_der) {
            Ok(sig) => sig,
            Err(_) => return false,
        }
    };

    // Normalize s to low-S form. libsecp256k1's verify requires low-S; pre-BIP62
    // Bitcoin allowed high-S signatures, so we normalize rather than reject them.
    signature.normalize_s();

    let sighash_type = EcdsaSighashType::from_consensus(sighash_type_byte as u32);

    if segwit {
        // BIP 143: segwit v0 sighash
        let sighash = match sighash_cache.p2wsh_signature_hash(
            input_index,
            script_code,
            amount,
            sighash_type,
        ) {
            Ok(hash) => hash,
            Err(_) => return false,
        };
        let msg = Message::from_digest(*AsRef::<[u8; 32]>::as_ref(&sighash));
        secp.verify_ecdsa(&msg, &signature, &pubkey).is_ok()
    } else {
        // Core's `CTransactionSignatureSerializer::SerializeScriptCode` strips
        // every OP_CODESEPARATOR from the subscript before hashing (the caller
        // has already FindAndDelete'd the signature pushes). rust-bitcoin's
        // `legacy_signature_hash` does not do this, so a script with an
        // OP_CODESEPARATOR remaining after `codesep_pos` (e.g. an unexecuted or
        // trailing separator) would hash differently from Core. Strip them here,
        // at opcode boundaries so a 0xab byte inside a push payload is preserved.
        let stripped = remove_codeseparators(script_code.as_bytes());
        // Pass the *raw* hashtype byte, not the masked `EcdsaSighashType`:
        // Core's SignatureHash appends the original nHashType to the preimage,
        // so a non-standard type (e.g. 0x05, valid without STRICTENC) must hash
        // as 0x05 — masking it to ALL would change the digest and spuriously
        // fail an otherwise-valid signature.
        let sighash = match sighash_cache.legacy_signature_hash(
            input_index,
            Script::from_bytes(&stripped),
            sighash_type_byte as u32,
        ) {
            Ok(hash) => hash,
            Err(_) => return false,
        };
        let msg = Message::from_digest(*AsRef::<[u8; 32]>::as_ref(&sighash));
        secp.verify_ecdsa(&msg, &signature, &pubkey).is_ok()
    }
}

/// Pop the top element from the stack.
fn stack_pop(stack: &mut Vec<Vec<u8>>) -> CoreResult<Vec<u8>> {
    stack
        .pop()
        .ok_or_else(|| CoreError::InvalidScript("stack underflow".into()))
}

/// Cast a stack element to a boolean.
fn cast_to_bool(data: &[u8]) -> bool {
    for (i, &byte) in data.iter().enumerate() {
        if byte != 0 {
            // Negative zero: last byte is 0x80 and all others are 0
            if i == data.len() - 1 && byte == 0x80 {
                return false;
            }
            return true;
        }
    }
    false
}

/// Decode a script number from stack data using the default 4-byte limit.
fn decode_num(data: &[u8]) -> CoreResult<i64> {
    decode_num_bounded(data, 4)
}

/// Decode a script number from stack data, allowing up to `max_size` bytes.
/// Bitcoin Core's `CScriptNum` uses `nMaxNumSize = 4` by default, but allows
/// 5 bytes for OP_CHECKLOCKTIMEVERIFY/OP_CHECKSEQUENCEVERIFY lock-time values.
fn decode_num_bounded(data: &[u8], max_size: usize) -> CoreResult<i64> {
    if data.is_empty() {
        return Ok(0);
    }
    if data.len() > max_size {
        return Err(CoreError::InvalidScript("number too large".into()));
    }

    let negative = data[data.len() - 1] & 0x80 != 0;
    let mut result: i64 = 0;

    for (i, &byte) in data.iter().enumerate() {
        result |= (byte as i64) << (8 * i);
    }

    // Remove the sign bit from the result
    if negative {
        result &= !(0x80i64 << (8 * (data.len() - 1)));
        result = -result;
    }

    Ok(result)
}

/// Encode a number as script number bytes.
fn encode_num(value: i64) -> Vec<u8> {
    if value == 0 {
        return vec![];
    }

    let negative = value < 0;
    let mut abs_value = value.unsigned_abs();
    let mut result = Vec::new();

    while abs_value > 0 {
        result.push((abs_value & 0xff) as u8);
        abs_value >>= 8;
    }

    // If the top bit is set, add an extra byte for the sign
    if result.last().is_some_and(|&b| b & 0x80 != 0) {
        result.push(if negative { 0x80 } else { 0x00 });
    } else if negative {
        let last = result
            .last_mut()
            .expect("value < 0 implies abs_value > 0, so result is non-empty");
        *last |= 0x80;
    }

    result
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode_num() {
        for val in [-100, -1, 0, 1, 100, 127, 128, 255, 256, 1000, -1000] {
            let encoded = encode_num(val);
            let decoded = decode_num(&encoded).unwrap();
            assert_eq!(decoded, val, "failed for value {val}");
        }
    }

    #[test]
    fn test_decode_num_bounded_five_bytes() {
        // 0x7fffffffff = 549755813887 needs 5 bytes to encode (BIP 65/112 lock-times).
        let value: i64 = 0x7fffffffff;
        let encoded = encode_num(value);
        assert_eq!(encoded.len(), 5, "value should require 5 bytes");
        let decoded = decode_num_bounded(&encoded, 5).unwrap();
        assert_eq!(decoded, value);
    }

    #[test]
    fn test_decode_num_default_rejects_five_bytes() {
        // The default 4-byte limit must still reject a 5-byte input.
        let value: i64 = 0x7fffffffff;
        let encoded = encode_num(value);
        assert_eq!(encoded.len(), 5);
        let err = decode_num(&encoded).unwrap_err();
        assert!(
            err.to_string().contains("number too large"),
            "expected 'number too large', got: {err}"
        );
    }

    #[test]
    fn test_cast_to_bool() {
        assert!(!cast_to_bool(&[]));
        assert!(!cast_to_bool(&[0]));
        assert!(!cast_to_bool(&[0, 0, 0]));
        assert!(!cast_to_bool(&[0x80])); // negative zero
        assert!(cast_to_bool(&[1]));
        assert!(cast_to_bool(&[0, 0, 1]));
    }

    #[test]
    fn test_is_p2sh() {
        // Standard P2SH script: OP_HASH160 <20 bytes> OP_EQUAL
        let mut bytes = vec![0xa9, 0x14]; // OP_HASH160, push 20
        bytes.extend_from_slice(&[0u8; 20]); // 20 zero bytes
        bytes.push(0x87); // OP_EQUAL
        let script = Script::from_bytes(&bytes);
        assert!(is_p2sh(script));
    }

    #[test]
    fn test_parse_witness_program() {
        // P2WPKH: OP_0 <20 bytes>
        let mut bytes = vec![0x00, 0x14]; // OP_0, push 20
        bytes.extend_from_slice(&[0u8; 20]);
        let script = Script::from_bytes(&bytes);
        let (version, program) = parse_witness_program(script).unwrap();
        assert_eq!(version, 0);
        assert_eq!(program.len(), 20);

        // P2WSH: OP_0 <32 bytes>
        let mut bytes = vec![0x00, 0x20]; // OP_0, push 32
        bytes.extend_from_slice(&[0u8; 32]);
        let script = Script::from_bytes(&bytes);
        let (version, program) = parse_witness_program(script).unwrap();
        assert_eq!(version, 0);
        assert_eq!(program.len(), 32);
    }

    #[test]
    fn test_bip147_nulldummy_checkmultisig() {
        // BIP 147 (NULLDUMMY): the extra element CHECKMULTISIG consumes must be an
        // empty byte vector once the rule is active (co-activated with SegWit, so
        // gated on `verify_witness`). Use a bare 0-of-0 multisig so no real
        // signatures are needed: scriptPubKey = OP_0 OP_0 OP_CHECKMULTISIG; the
        // scriptSig supplies the dummy element.
        let spk = ScriptBuf::from_bytes(vec![0x00, 0x00, 0xae]); // OP_0 OP_0 OP_CHECKMULTISIG
        let prevout = TxOut {
            value: bitcoin::Amount::from_sat(0),
            script_pubkey: spk,
        };

        let mk_tx = |scriptsig: Vec<u8>| Transaction {
            version: bitcoin::transaction::Version(2),
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![bitcoin::TxIn {
                previous_output: bitcoin::OutPoint::null(),
                script_sig: ScriptBuf::from_bytes(scriptsig),
                sequence: bitcoin::Sequence::MAX,
                witness: bitcoin::Witness::new(),
            }],
            output: vec![],
        };
        let run = |scriptsig: Vec<u8>, flags: ScriptFlags| {
            let tx = mk_tx(scriptsig);
            verify_script(&tx, 0, std::slice::from_ref(&prevout), flags)
        };

        // Empty dummy (OP_0 pushes an empty vector): valid under NULLDUMMY.
        assert!(run(vec![0x00], ScriptFlags::all()).is_ok());

        // Non-empty dummy (OP_1 pushes [0x01]): rejected once NULLDUMMY is active.
        let err = run(vec![0x51], ScriptFlags::all()).unwrap_err().to_string();
        assert!(
            err.contains("NULLDUMMY"),
            "expected NULLDUMMY rejection, got: {err}"
        );

        // The same non-empty dummy is accepted with NULLDUMMY off (pre-SegWit
        // semantics — the dummy is simply ignored). Witness stays on to prove the
        // gate is the dedicated NULLDUMMY flag, not witness.
        let mut no_nulldummy = ScriptFlags::all();
        no_nulldummy.verify_nulldummy = false;
        assert!(run(vec![0x51], no_nulldummy).is_ok());

        // CHECKMULTISIGVERIFY (0xaf) is gated identically. OP_0 OP_0 OP_CMSV OP_1
        // leaves a truthy stack after the VERIFY; a non-null dummy still rejects.
        let spk_v = ScriptBuf::from_bytes(vec![0x00, 0x00, 0xaf, 0x51]);
        let prevout_v = TxOut {
            value: bitcoin::Amount::from_sat(0),
            script_pubkey: spk_v,
        };
        let tx_v = mk_tx(vec![0x51]);
        let err_v = verify_script(
            &tx_v,
            0,
            std::slice::from_ref(&prevout_v),
            ScriptFlags::all(),
        )
        .unwrap_err()
        .to_string();
        assert!(
            err_v.contains("NULLDUMMY"),
            "expected CMSV NULLDUMMY rejection, got: {err_v}"
        );
    }

    #[test]
    fn test_count_sigops() {
        // Empty script: 0 sigops
        let script = ScriptBuf::new();
        assert_eq!(count_sigops(&script, true), 0);

        // Single OP_CHECKSIG: 1 sigop
        let script = ScriptBuf::from_bytes(vec![0xac]);
        assert_eq!(count_sigops(&script, true), 1);

        // OP_CHECKSIG + OP_CHECKSIGVERIFY: 2 sigops
        let script = ScriptBuf::from_bytes(vec![0xac, 0xad]);
        assert_eq!(count_sigops(&script, true), 2);

        // OP_2 OP_CHECKMULTISIG (accurate): 2 sigops
        let script = ScriptBuf::from_bytes(vec![0x52, 0xae]);
        assert_eq!(count_sigops(&script, true), 2);

        // OP_CHECKMULTISIG without preceding number (accurate): 20 sigops
        let script = ScriptBuf::from_bytes(vec![0xae]);
        assert_eq!(count_sigops(&script, true), 20);
    }

    #[test]
    fn test_parse_schnorr_sig_64_bytes() {
        // 64-byte Schnorr sig should parse as default sighash
        let sig = [0u8; 64]; // All zeros won't be a valid sig, but it should parse
        let result = parse_schnorr_sig(&sig);
        assert!(result.is_ok());
        let (_, sighash_type) = result.unwrap();
        assert_eq!(sighash_type, TapSighashType::Default);
    }

    #[test]
    fn test_parse_schnorr_sig_65_bytes() {
        // 65-byte Schnorr sig should parse sighash from last byte
        let mut sig = [0u8; 65];
        sig[64] = 0x01; // SIGHASH_ALL
        let result = parse_schnorr_sig(&sig);
        assert!(result.is_ok());
        let (_, sighash_type) = result.unwrap();
        assert_eq!(sighash_type, TapSighashType::All);
    }

    #[test]
    fn test_parse_schnorr_sig_empty() {
        let result = parse_schnorr_sig(&[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_schnorr_sig_bad_length() {
        let result = parse_schnorr_sig(&[0u8; 32]);
        assert!(result.is_err());
    }

    #[test]
    fn test_is_tapscript_success_opcode() {
        // Known success opcodes
        assert!(is_tapscript_success_opcode(0x50));
        assert!(is_tapscript_success_opcode(0x62));
        assert!(is_tapscript_success_opcode(0x7e)); // OP_CAT — was missing, caused block 856182 failure
        assert!(is_tapscript_success_opcode(0x7f));
        assert!(is_tapscript_success_opcode(0x80));
        assert!(is_tapscript_success_opcode(0x81));
        assert!(is_tapscript_success_opcode(0x83)); // OP_INVERT
        assert!(is_tapscript_success_opcode(0x84));
        assert!(is_tapscript_success_opcode(0x85));
        assert!(is_tapscript_success_opcode(0x86));
        assert!(is_tapscript_success_opcode(0x89));
        assert!(is_tapscript_success_opcode(0x8a));
        assert!(is_tapscript_success_opcode(0x8d));
        assert!(is_tapscript_success_opcode(0x8e));
        assert!(is_tapscript_success_opcode(0x95));
        assert!(is_tapscript_success_opcode(0x99));
        assert!(is_tapscript_success_opcode(0xbb));
        assert!(is_tapscript_success_opcode(0xc0));
        assert!(is_tapscript_success_opcode(0xfe));
        // Non-success opcodes
        assert!(!is_tapscript_success_opcode(0xac)); // OP_CHECKSIG
        assert!(!is_tapscript_success_opcode(0xba)); // OP_CHECKSIGADD
        assert!(!is_tapscript_success_opcode(0x00)); // OP_0
        assert!(!is_tapscript_success_opcode(0x76)); // OP_DUP
        assert!(!is_tapscript_success_opcode(0x82)); // gap between 0x81 and 0x83 (OP_SIZE)
        assert!(!is_tapscript_success_opcode(0x87)); // OP_EQUAL — not OP_SUCCESS
    }

    #[test]
    fn test_tapscript_disables_checkmultisig() {
        // Verify that OP_CHECKMULTISIG (0xae) fails in tapscript context
        let tx = Transaction {
            version: bitcoin::transaction::Version(2),
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![bitcoin::TxIn::default()],
            output: vec![],
        };
        let prev_output = TxOut {
            value: bitcoin::Amount::from_sat(0),
            script_pubkey: ScriptBuf::new(),
        };
        let tap_leaf = TapLeafHash::from_byte_array([0u8; 32]);
        let script = ScriptBuf::from_bytes(vec![0x51, 0x51, 0xae]); // OP_1 OP_1 OP_CHECKMULTISIG

        let mut stack = vec![];
        let result = execute_tapscript(
            &script,
            &mut stack,
            &tx,
            0,
            std::slice::from_ref(&prev_output),
            tap_leaf,
            None,
            false,
            &mut SighashCache::new(&tx),
        );
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("OP_CHECKMULTISIG disabled"));
    }

    #[test]
    fn test_tapscript_success_opcode() {
        // OP_SUCCESS opcodes should cause immediate success
        let tx = Transaction {
            version: bitcoin::transaction::Version(2),
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![bitcoin::TxIn::default()],
            output: vec![],
        };
        let prev_output = TxOut {
            value: bitcoin::Amount::from_sat(0),
            script_pubkey: ScriptBuf::new(),
        };
        let tap_leaf = TapLeafHash::from_byte_array([0u8; 32]);
        // Script with OP_SUCCESS (0xc0) should succeed immediately
        let script = ScriptBuf::from_bytes(vec![0xc0]);

        let mut stack = vec![];
        let result = execute_tapscript(
            &script,
            &mut stack,
            &tx,
            0,
            std::slice::from_ref(&prev_output),
            tap_leaf,
            None,
            false,
            &mut SighashCache::new(&tx),
        );
        assert!(result.is_ok());
    }

    // ─── BIP-110 (Reduced Data Temporary Softfork) rule tests ───────────────

    fn bip110_tapscript_fixture() -> (Transaction, TxOut, TapLeafHash) {
        let tx = Transaction {
            version: bitcoin::transaction::Version(2),
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![bitcoin::TxIn::default()],
            output: vec![],
        };
        let prev_output = TxOut {
            value: bitcoin::Amount::from_sat(0),
            script_pubkey: ScriptBuf::new(),
        };
        (tx, prev_output, TapLeafHash::from_byte_array([0u8; 32]))
    }

    #[test]
    fn test_bip110_rule1_output_scripts() {
        let mk = |spk: Vec<u8>| Transaction {
            version: bitcoin::transaction::Version(2),
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![bitcoin::TxIn::default()],
            output: vec![TxOut {
                value: bitcoin::Amount::from_sat(1),
                script_pubkey: ScriptBuf::from_bytes(spk),
            }],
        };
        // Non-OP_RETURN: 34 bytes OK, 35 bytes invalid.
        assert!(check_bip110_output_scripts(&mk(vec![0x00; 34])).is_ok());
        assert!(check_bip110_output_scripts(&mk(vec![0x00; 35])).is_err());
        // OP_RETURN (first byte 0x6a): up to 83 bytes OK, 84 invalid.
        let mut op_return_83 = vec![0x6au8];
        op_return_83.extend(std::iter::repeat_n(0x00, 82));
        assert_eq!(op_return_83.len(), 83);
        assert!(check_bip110_output_scripts(&mk(op_return_83)).is_ok());
        let mut op_return_84 = vec![0x6au8];
        op_return_84.extend(std::iter::repeat_n(0x00, 83));
        assert!(check_bip110_output_scripts(&mk(op_return_84)).is_err());
    }

    #[test]
    fn test_bip110_rule2_pushes() {
        // A 256-byte push is OK; 257 is invalid.
        let mut ok = ScriptBuf::new();
        ok.push_slice(bitcoin::script::PushBytesBuf::try_from(vec![0u8; 256]).unwrap());
        assert!(bip110_check_pushes(&ok, false).is_ok());
        let mut bad = ScriptBuf::new();
        bad.push_slice(bitcoin::script::PushBytesBuf::try_from(vec![0u8; 257]).unwrap());
        assert!(bip110_check_pushes(&bad, false).is_err());

        // P2SH scriptSig: the final push (redeemScript) is exempt, earlier ones not.
        let big = bitcoin::script::PushBytesBuf::try_from(vec![0u8; 300]).unwrap();
        let small = bitcoin::script::PushBytesBuf::try_from(vec![0u8; 10]).unwrap();
        // [small_arg, big_redeemScript] — exempting last push passes.
        let mut sig = ScriptBuf::new();
        sig.push_slice(&small);
        sig.push_slice(&big);
        assert!(bip110_check_pushes(&sig, true).is_ok());
        assert!(bip110_check_pushes(&sig, false).is_err());
        // [big_arg, small_redeemScript] — big non-final push is not exempt.
        let mut sig2 = ScriptBuf::new();
        sig2.push_slice(&big);
        sig2.push_slice(&small);
        assert!(bip110_check_pushes(&sig2, true).is_err());
    }

    #[test]
    fn test_bip110_rule2_witness_items() {
        let ok = vec![0u8; 256];
        let bad = vec![0u8; 257];
        assert!(bip110_check_witness_items(std::iter::once(ok.as_slice())).is_ok());
        assert!(bip110_check_witness_items(std::iter::once(bad.as_slice())).is_err());
    }

    /// One-input transaction carrying `witness`, for the relay-policy
    /// pattern detectors.
    fn tx_with_witness(witness: bitcoin::Witness) -> Transaction {
        Transaction {
            version: bitcoin::transaction::Version(2),
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![bitcoin::TxIn {
                witness,
                ..Default::default()
            }],
            output: vec![],
        }
    }

    /// Ordinals-style taproot script-path witness: leaf script
    /// `OP_FALSE OP_IF "ord" <body pushes> OP_ENDIF` plus a shape-valid
    /// 33-byte control block.
    fn inscription_witness(body: &[u8]) -> bitcoin::Witness {
        let mut leaf = vec![0x00, 0x63, 0x03]; // OP_FALSE OP_IF PUSH3
        leaf.extend_from_slice(b"ord");
        for chunk in body.chunks(75) {
            leaf.push(chunk.len() as u8);
            leaf.extend_from_slice(chunk);
        }
        leaf.push(0x68); // OP_ENDIF
        let mut control = vec![0xc0];
        control.extend_from_slice(&[0x02; 32]);
        let mut w = bitcoin::Witness::new();
        w.push([0u8; 64]); // dummy schnorr signature argument
        w.push(&leaf);
        w.push(&control);
        w
    }

    #[test]
    fn test_inscription_envelope_detection() {
        // Inscription envelope in a tapscript leaf: detected on input 0.
        let tx = tx_with_witness(inscription_witness(b"hello inscription"));
        assert_eq!(tx_first_inscription_input(&tx), Some(0));

        // Same witness plus a BIP 341 annex: still detected.
        let mut w = inscription_witness(b"with annex");
        w.push([0x50, 0xaa]);
        assert_eq!(tx_first_inscription_input(&tx_with_witness(w)), Some(0));

        // P2WPKH-shaped witness (sig + 33-byte pubkey): the pubkey is not a
        // control block (wrong leading byte), so no false positive.
        let mut w = bitcoin::Witness::new();
        w.push([0u8; 72]);
        w.push([0x02; 33]);
        assert_eq!(tx_first_inscription_input(&tx_with_witness(w)), None);

        // Taproot key-path spend (single signature element): clean.
        let mut w = bitcoin::Witness::new();
        w.push([0u8; 64]);
        assert_eq!(tx_first_inscription_input(&tx_with_witness(w)), None);

        // Taproot script-path WITHOUT an envelope (plain OP_TRUE leaf): clean.
        let mut w = bitcoin::Witness::new();
        w.push([0x51]); // OP_TRUE leaf
        let mut control = vec![0xc0];
        control.extend_from_slice(&[0x02; 32]);
        w.push(&control);
        assert_eq!(tx_first_inscription_input(&tx_with_witness(w)), None);
    }

    #[test]
    fn test_token_protocol_detection() {
        let mk_op_return = |spk: Vec<u8>| Transaction {
            version: bitcoin::transaction::Version(2),
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![bitcoin::TxIn::default()],
            output: vec![TxOut {
                value: bitcoin::Amount::ZERO,
                script_pubkey: ScriptBuf::from_bytes(spk),
            }],
        };

        // Runes runestone: OP_RETURN OP_13 <payload>.
        let runes = mk_op_return(vec![0x6a, 0x5d, 0x02, 0xaa, 0xbb]);
        assert_eq!(tx_token_protocol(&runes), Some("runes"));

        // Omni Layer: OP_RETURN <push "omni" + payload>.
        let mut spk = vec![0x6a, 0x08];
        spk.extend_from_slice(b"omni\x00\x00\x00\x32");
        assert_eq!(tx_token_protocol(&mk_op_return(spk)), Some("omni"));

        // Counterparty: OP_RETURN <push "CNTRPRTY" + payload>.
        let mut spk = vec![0x6a, 0x0a];
        spk.extend_from_slice(b"CNTRPRTY\x01\x02");
        assert_eq!(tx_token_protocol(&mk_op_return(spk)), Some("counterparty"));

        // Ordinary OP_RETURN data: not a token.
        let mut spk = vec![0x6a, 0x05];
        spk.extend_from_slice(b"hello");
        assert_eq!(tx_token_protocol(&mk_op_return(spk)), None);

        // BRC-20 inscription payload: token.
        let brc = tx_with_witness(inscription_witness(br#"{"p":"brc-20","op":"mint"}"#));
        assert_eq!(tx_token_protocol(&brc), Some("brc-20"));

        // Plain (non-token) inscription: a parasite, but not a token.
        let ord = tx_with_witness(inscription_witness(b"just a picture"));
        assert_eq!(tx_token_protocol(&ord), None);
    }

    /// OP_PLENTY-style taproot script-path witness wrapping a pre-built leaf
    /// script (produced by the reference python encoder from the scam gist
    /// this detector defends against) plus a shape-valid 33-byte control
    /// block.
    fn op_plenty_witness(leaf: &[u8]) -> bitcoin::Witness {
        let mut control = vec![0xc0];
        control.extend_from_slice(&[0x02; 32]);
        let mut w = bitcoin::Witness::new();
        w.push([0u8; 64]); // dummy schnorr signature argument
        w.push(leaf);
        w.push(&control);
        w
    }

    #[test]
    fn test_op_plenty_encoding_detection() {
        // All hex fixtures below are `encode(...)` output from the gist's
        // own reference implementation (v2 self-framed form: seven OP_5 +
        // 8 length-nibble opcodes + payload opcodes + footer), round-tripped
        // through its `decode()` to confirm correctness before hardcoding.

        // encode(bytes(range(16))): 16-byte payload clears the run threshold
        // (8 length-nibble opcodes + 32 payload-nibble opcodes = 40).
        let sixteen_bytes = hex::decode(
            "555555555555559a589a589a589c589a589a599a5a9a5b9a5c9a5d9a5e9a5f9a\
             609a6158a4588f9a9058919a9258936d6d75",
        )
        .unwrap();
        assert_eq!(
            tx_first_covert_opcode_input(&tx_with_witness(op_plenty_witness(&sixteen_bytes))),
            Some(0)
        );

        // encode(b"visit hxxp://scam.example/claim to get free coins"): a
        // realistically-sized message.
        let realistic_payload = hex::decode(
            "555555555555559a589a589a58a05aa15ea0615f875e775f9e5a9a5ea25fa25f\
             a25f9a5ba45a935a935f875e875e9b5e919c925e9f5fa25e9b5e91a158a0905e\
             9f5a935e875e90a059a0615e919c58a15ca0519c58a05fa05da15c9c58a05ea1\
             5aa05da05d9c58a05ba051a0615e92a15b6d6d6d",
        )
        .unwrap();
        assert_eq!(
            tx_first_covert_opcode_input(&tx_with_witness(op_plenty_witness(&realistic_payload))),
            Some(0)
        );

        // encode(b"Hi"): the docstring's own worked example. Its whole
        // encoded body (length header + 2-byte payload + footer) is only 15
        // opcodes, under OP_PLENTY_MIN_RUN — too small a message to be worth
        // flagging, and a useful near-miss negative for the threshold.
        let hi = hex::decode("555555555555559a589a589a589a5c9e60a0616d6d75").unwrap();
        assert_eq!(
            tx_first_covert_opcode_input(&tx_with_witness(op_plenty_witness(&hi))),
            None
        );

        // A long alphabet-only run (30 opcodes, past the threshold) that
        // does NOT end in a valid footer: not flagged. Confirms detection
        // keys on the footer shape, not run length alone.
        let mut no_footer = vec![0x9a; 30];
        no_footer.extend_from_slice(&[0xac, 0xac, 0xac]); // OP_CHECKSIG x3, not a footer
        assert_eq!(
            tx_first_covert_opcode_input(&tx_with_witness(op_plenty_witness(&no_footer))),
            None
        );

        // The same 40-opcode alphabet run as the 16-byte fixture, but with a
        // single-byte data push spliced into the middle: each half falls
        // under the run threshold on its own. Documents a known limitation
        // (an attacker interleaving junk pushes can duck this heuristic) and
        // confirms the detector degrades safely rather than panicking.
        let (first_half, second_half) = sixteen_bytes.split_at(7 + 20);
        let mut split_run = first_half.to_vec();
        split_run.push(0x01); // PUSHBYTES_1
        split_run.push(0xaa);
        split_run.extend_from_slice(second_half);
        assert_eq!(
            tx_first_covert_opcode_input(&tx_with_witness(op_plenty_witness(&split_run))),
            None
        );

        // Plain OP_TRUE leaf: clean.
        assert_eq!(
            tx_first_covert_opcode_input(&tx_with_witness(op_plenty_witness(&[0x51]))),
            None
        );

        // Taproot key-path spend (single signature element): clean.
        let mut w = bitcoin::Witness::new();
        w.push([0u8; 64]);
        assert_eq!(tx_first_covert_opcode_input(&tx_with_witness(w)), None);
    }

    #[test]
    fn test_bip110_rule6_op_success() {
        let (tx, prev, leaf) = bip110_tapscript_fixture();
        // OP_SUCCESS (0xc0) alone: succeeds when not enforcing, rejected when enforcing.
        let script = ScriptBuf::from_bytes(vec![0xc0]);
        let mut s1 = vec![];
        assert!(execute_tapscript(
            &script,
            &mut s1,
            &tx,
            0,
            std::slice::from_ref(&prev),
            leaf,
            None,
            false,
            &mut SighashCache::new(&tx)
        )
        .is_ok());
        let mut s2 = vec![];
        let err = execute_tapscript(
            &script,
            &mut s2,
            &tx,
            0,
            std::slice::from_ref(&prev),
            leaf,
            None,
            true,
            &mut SighashCache::new(&tx),
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("OP_SUCCESS"), "got: {err}");
    }

    #[test]
    fn test_bip110_rule7_op_if() {
        let (tx, prev, leaf) = bip110_tapscript_fixture();
        // OP_1 OP_IF OP_ENDIF: executes an OP_IF — rejected only when enforcing.
        let script = ScriptBuf::from_bytes(vec![0x51, 0x63, 0x68]);
        let mut s1 = vec![];
        // Not enforcing: the IF executes normally (script ends with empty stack →
        // evaluation handled by caller; here we only check it doesn't error out).
        let _ = execute_tapscript(
            &script,
            &mut s1,
            &tx,
            0,
            std::slice::from_ref(&prev),
            leaf,
            None,
            false,
            &mut SighashCache::new(&tx),
        );
        let mut s2 = vec![];
        let err = execute_tapscript(
            &script,
            &mut s2,
            &tx,
            0,
            std::slice::from_ref(&prev),
            leaf,
            None,
            true,
            &mut SighashCache::new(&tx),
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("OP_IF/OP_NOTIF"), "got: {err}");
    }

    fn spend_witness_program(
        spk: Vec<u8>,
        witness_items: &[Vec<u8>],
        enforce_bip110: bool,
    ) -> CoreResult<()> {
        let prevout = TxOut {
            value: bitcoin::Amount::from_sat(1000),
            script_pubkey: ScriptBuf::from_bytes(spk),
        };
        let tx = Transaction {
            version: bitcoin::transaction::Version(2),
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![bitcoin::TxIn {
                previous_output: bitcoin::OutPoint::null(),
                script_sig: ScriptBuf::new(),
                sequence: bitcoin::Sequence::MAX,
                witness: bitcoin::Witness::from_slice(witness_items),
            }],
            output: vec![],
        };
        let mut flags = ScriptFlags::all();
        flags.verify_bip110 = enforce_bip110;
        verify_script(&tx, 0, std::slice::from_ref(&prevout), flags)
    }

    #[test]
    fn test_bip110_rule3_undefined_witness_version() {
        // Witness v2 program (OP_2 <2-byte program>): anyone-can-spend normally,
        // but spending it is invalid under BIP-110 rule 3.
        let spk = vec![0x52, 0x02, 0xaa, 0xbb];
        assert!(spend_witness_program(spk.clone(), &[vec![0x01]], false).is_ok());
        let err = spend_witness_program(spk, &[vec![0x01]], true)
            .unwrap_err()
            .to_string();
        assert!(err.contains("undefined witness version"), "got: {err}");
    }

    #[test]
    fn test_bip110_rule3_p2a_exempt() {
        // P2A (OP_1 <0x4e73>) stays a defined anyone-can-spend program even under
        // BIP-110, so spending it is valid with or without enforcement.
        let spk = vec![0x51, 0x02, 0x4e, 0x73];
        assert!(spend_witness_program(spk.clone(), &[], false).is_ok());
        assert!(spend_witness_program(spk, &[], true).is_ok());
    }

    #[test]
    fn test_bip110_rule5_control_block() {
        // Taproot script-path spend with an oversized (>257 byte) control block.
        // The output key is parsed before the rule-5 check, so use a valid x-only
        // key (the secp256k1 generator's x-coordinate).
        let gx: [u8; 32] = [
            0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87,
            0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b,
            0x16, 0xf8, 0x17, 0x98,
        ];
        let mut spk = vec![0x51, 0x20];
        spk.extend_from_slice(&gx);
        // witness = [tapleaf_script, control_block(258 bytes)]
        let witness = vec![vec![0x51], vec![0xc0u8; 258]];
        let err = spend_witness_program(spk, &witness, true)
            .unwrap_err()
            .to_string();
        assert!(err.contains("control block"), "got: {err}");
    }

    #[test]
    fn test_bip110_rule4_annex() {
        // Taproot v1 (OP_1 <32-byte program>) spent with an annex (last witness
        // item starting with 0x50). Rule 4 rejects it before key parsing, so the
        // 32-byte program need not be a valid key for this assertion.
        let mut spk = vec![0x51, 0x20];
        spk.extend(std::iter::repeat_n(0x02, 32));
        let witness = vec![vec![0x09; 64], vec![0x50, 0x00]]; // [sig-ish, annex]
        let err = spend_witness_program(spk, &witness, true)
            .unwrap_err()
            .to_string();
        assert!(err.contains("annex"), "got: {err}");
    }

    #[test]
    fn test_bip110_rule2_tapscript_push() {
        let (tx, prev, leaf) = bip110_tapscript_fixture();
        // A >256-byte push inside a tapscript is rejected when enforcing.
        let mut script = ScriptBuf::new();
        script.push_slice(bitcoin::script::PushBytesBuf::try_from(vec![0u8; 300]).unwrap());
        let mut s = vec![];
        let err = execute_tapscript(
            &script,
            &mut s,
            &tx,
            0,
            std::slice::from_ref(&prev),
            leaf,
            None,
            true,
            &mut SighashCache::new(&tx),
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("exceeds"), "got: {err}");
    }

    #[test]
    fn test_script_flags_taproot() {
        // Below taproot height
        let flags = ScriptFlags::for_height(
            709_631, 1333238400, 1333238400, 481_824, 388_381, 419_328, 363_725, 709_632,
        );
        assert!(!flags.verify_taproot);
        assert!(flags.verify_witness);

        // At taproot height
        let flags = ScriptFlags::for_height(
            709_632, 1333238400, 1333238400, 481_824, 388_381, 419_328, 363_725, 709_632,
        );
        assert!(flags.verify_taproot);

        // Above taproot height
        let flags = ScriptFlags::for_height(
            800_000, 1333238400, 1333238400, 481_824, 388_381, 419_328, 363_725, 709_632,
        );
        assert!(flags.verify_taproot);
    }

    #[test]
    fn test_script_flags_csv_height() {
        // CSV (BIP 68/112/113) is gated on csv_height, independent of bip65_height.
        // bip65_height = 388_381, csv_height = 419_328.
        let below = ScriptFlags::for_height(
            419_327, 1333238400, 1333238400, 481_824, 388_381, 419_328, 363_725, 709_632,
        );
        assert!(!below.verify_checksequenceverify);
        // CLTV (bip65) is already active well below csv_height.
        assert!(below.verify_checklocktimeverify);

        let at = ScriptFlags::for_height(
            419_328, 1333238400, 1333238400, 481_824, 388_381, 419_328, 363_725, 709_632,
        );
        assert!(at.verify_checksequenceverify);

        let above = ScriptFlags::for_height(
            500_000, 1333238400, 1333238400, 481_824, 388_381, 419_328, 363_725, 709_632,
        );
        assert!(above.verify_checksequenceverify);
    }

    #[test]
    fn test_witness_v1_program_parse() {
        // Build a witness v1 program (OP_1 <32 bytes>)
        let mut bytes = vec![0x51, 0x20]; // OP_1, push 32 bytes
        bytes.extend_from_slice(&[0xab; 32]);
        let script = Script::from_bytes(&bytes);
        let (version, program) = parse_witness_program(script).unwrap();
        assert_eq!(version, 1);
        assert_eq!(program.len(), 32);
    }

    #[test]
    fn test_remove_codeseparators() {
        // Bare separators are dropped; surrounding opcodes are preserved.
        assert_eq!(remove_codeseparators(&[0xab]), Vec::<u8>::new());
        assert_eq!(
            remove_codeseparators(&[0x51, 0xab, 0x52, 0xab, 0xab, 0x53]),
            vec![0x51, 0x52, 0x53]
        );
        // A 0xab byte *inside* a data push must NOT be removed (opcode-boundary
        // walk, mirroring Core's GetOp-based SerializeScriptCode).
        let mut push = vec![0x03, 0xab, 0xab, 0xab]; // OP_PUSH3 <ab ab ab>
        push.push(0xab); // trailing bare OP_CODESEPARATOR
        assert_eq!(remove_codeseparators(&push), vec![0x03, 0xab, 0xab, 0xab]);
        // OP_PUSHDATA1 payload is copied opaquely.
        let mut p1 = vec![0x4c, 0x02, 0xab, 0xab]; // PUSHDATA1 len=2 <ab ab>
        p1.extend_from_slice(&[0xab, 0x51]); // bare sep, then OP_1
        assert_eq!(
            remove_codeseparators(&p1),
            vec![0x4c, 0x02, 0xab, 0xab, 0x51]
        );
        // Truncated push: copy the remainder verbatim, do not panic.
        assert_eq!(remove_codeseparators(&[0x05, 0xab]), vec![0x05, 0xab]);
    }
}
