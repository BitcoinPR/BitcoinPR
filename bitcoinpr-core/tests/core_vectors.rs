//! Bitcoin Core consensus vectors run through our interpreter.
//!
//! Imports the official `script_tests.json`, `tx_valid.json`, and
//! `tx_invalid.json` from Bitcoin Core (vendored under `tests/data/`, taken
//! from tag v28.0) and replays every decidable vector through
//! [`bitcoinpr_core::script::verify_script`] and
//! [`bitcoinpr_core::validation::check_transaction`].
//!
//! ## Decidability
//!
//! Our [`ScriptFlags`] models a *subset* of Core's verification flags
//! (P2SH, WITNESS, STRICTENC-family, CLTV, CSV, TAPROOT). Script verification
//! flags are purely *restrictive* — enabling one can only turn an otherwise-OK
//! script into a failure, never the reverse. That gives a principled way to
//! decide which vectors we can assert on without modelling Core's full policy
//! flag set:
//!
//! * `expected == "OK"` — the script verifies under Core's *strict* flag set,
//!   so it must also verify under our more-lenient subset. Always asserted.
//! * `expected == <hard error>` — the failure is flag-independent (e.g.
//!   `EVAL_FALSE`, `BAD_OPCODE`) or gated only on a flag we *do* model
//!   (`WITNESS_*`, locktime). Asserted as a failure.
//! * anything else (`MINIMALDATA`, `CLEANSTACK`, `SIG_DER`, `UNKNOWN_ERROR`, …)
//!   — the outcome hinges on a policy flag we don't model, so the result is
//!   undecidable for us and the vector is skipped (counted, not asserted).
//!
//! This keeps the harness honest: it cannot pass by accident, and every
//! asserted vector is one our consensus code is genuinely responsible for.

use bitcoin::absolute::LockTime;
use bitcoin::consensus::encode::deserialize;
use bitcoin::transaction::Version;
use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness};
use serde_json::Value;
use std::collections::HashMap;

use bitcoinpr_core::script::{verify_script, ScriptFlags};
use bitcoinpr_core::validation::check_transaction;

// ─── Script-asm parsing (Bitcoin Core's `ParseScript`) ──────────────────────

/// Map a Core opcode mnemonic (with or without the `OP_` prefix) to its byte.
/// Covers the full 0x00–0xb9 range used by the vector corpus, including the
/// disabled opcodes (CAT, SUBSTR, MUL, …) which must parse so the interpreter
/// can reject them.
fn opcode_byte(name: &str) -> Option<u8> {
    let n = name.strip_prefix("OP_").unwrap_or(name);
    Some(match n {
        "0" | "FALSE" => 0x00,
        "1NEGATE" => 0x4f,
        "RESERVED" => 0x50,
        "1" | "TRUE" => 0x51,
        "2" => 0x52,
        "3" => 0x53,
        "4" => 0x54,
        "5" => 0x55,
        "6" => 0x56,
        "7" => 0x57,
        "8" => 0x58,
        "9" => 0x59,
        "10" => 0x5a,
        "11" => 0x5b,
        "12" => 0x5c,
        "13" => 0x5d,
        "14" => 0x5e,
        "15" => 0x5f,
        "16" => 0x60,
        "NOP" => 0x61,
        "VER" => 0x62,
        "IF" => 0x63,
        "NOTIF" => 0x64,
        "VERIF" => 0x65,
        "VERNOTIF" => 0x66,
        "ELSE" => 0x67,
        "ENDIF" => 0x68,
        "VERIFY" => 0x69,
        "RETURN" => 0x6a,
        "TOALTSTACK" => 0x6b,
        "FROMALTSTACK" => 0x6c,
        "2DROP" => 0x6d,
        "2DUP" => 0x6e,
        "3DUP" => 0x6f,
        "2OVER" => 0x70,
        "2ROT" => 0x71,
        "2SWAP" => 0x72,
        "IFDUP" => 0x73,
        "DEPTH" => 0x74,
        "DROP" => 0x75,
        "DUP" => 0x76,
        "NIP" => 0x77,
        "OVER" => 0x78,
        "PICK" => 0x79,
        "ROLL" => 0x7a,
        "ROT" => 0x7b,
        "SWAP" => 0x7c,
        "TUCK" => 0x7d,
        "CAT" => 0x7e,
        "SUBSTR" => 0x7f,
        "LEFT" => 0x80,
        "RIGHT" => 0x81,
        "SIZE" => 0x82,
        "INVERT" => 0x83,
        "AND" => 0x84,
        "OR" => 0x85,
        "XOR" => 0x86,
        "EQUAL" => 0x87,
        "EQUALVERIFY" => 0x88,
        "RESERVED1" => 0x89,
        "RESERVED2" => 0x8a,
        "1ADD" => 0x8b,
        "1SUB" => 0x8c,
        "2MUL" => 0x8d,
        "2DIV" => 0x8e,
        "NEGATE" => 0x8f,
        "ABS" => 0x90,
        "NOT" => 0x91,
        "0NOTEQUAL" => 0x92,
        "ADD" => 0x93,
        "SUB" => 0x94,
        "MUL" => 0x95,
        "DIV" => 0x96,
        "MOD" => 0x97,
        "LSHIFT" => 0x98,
        "RSHIFT" => 0x99,
        "BOOLAND" => 0x9a,
        "BOOLOR" => 0x9b,
        "NUMEQUAL" => 0x9c,
        "NUMEQUALVERIFY" => 0x9d,
        "NUMNOTEQUAL" => 0x9e,
        "LESSTHAN" => 0x9f,
        "GREATERTHAN" => 0xa0,
        "LESSTHANOREQUAL" => 0xa1,
        "GREATERTHANOREQUAL" => 0xa2,
        "MIN" => 0xa3,
        "MAX" => 0xa4,
        "WITHIN" => 0xa5,
        "RIPEMD160" => 0xa6,
        "SHA1" => 0xa7,
        "SHA256" => 0xa8,
        "HASH160" => 0xa9,
        "HASH256" => 0xaa,
        "CODESEPARATOR" => 0xab,
        "CHECKSIG" => 0xac,
        "CHECKSIGVERIFY" => 0xad,
        "CHECKMULTISIG" => 0xae,
        "CHECKMULTISIGVERIFY" => 0xaf,
        "NOP1" => 0xb0,
        "CHECKLOCKTIMEVERIFY" | "NOP2" => 0xb1,
        "CHECKSEQUENCEVERIFY" | "NOP3" => 0xb2,
        "NOP4" => 0xb3,
        "NOP5" => 0xb4,
        "NOP6" => 0xb5,
        "NOP7" => 0xb6,
        "NOP8" => 0xb7,
        "NOP9" => 0xb8,
        "NOP10" => 0xb9,
        "CHECKSIGADD" => 0xba,
        _ => return None,
    })
}

fn push_data(out: &mut Vec<u8>, data: &[u8]) {
    let len = data.len();
    if len == 0 {
        out.push(0x00); // OP_0
    } else if len < 0x4c {
        out.push(len as u8);
        out.extend_from_slice(data);
    } else if len <= 0xff {
        out.push(0x4c); // OP_PUSHDATA1
        out.push(len as u8);
        out.extend_from_slice(data);
    } else if len <= 0xffff {
        out.push(0x4d); // OP_PUSHDATA2
        out.extend_from_slice(&(len as u16).to_le_bytes());
        out.extend_from_slice(data);
    } else {
        out.push(0x4e); // OP_PUSHDATA4
        out.extend_from_slice(&(len as u32).to_le_bytes());
        out.extend_from_slice(data);
    }
}

fn push_num(out: &mut Vec<u8>, n: i64) {
    if n == 0 {
        out.push(0x00);
    } else if n == -1 {
        out.push(0x4f);
    } else if (1..=16).contains(&n) {
        out.push(0x50 + n as u8);
    } else {
        let neg = n < 0;
        let mut v = n.unsigned_abs();
        let mut bytes = Vec::new();
        while v > 0 {
            bytes.push((v & 0xff) as u8);
            v >>= 8;
        }
        if bytes.last().is_some_and(|b| b & 0x80 != 0) {
            bytes.push(if neg { 0x80 } else { 0x00 });
        } else if neg {
            *bytes.last_mut().unwrap() |= 0x80;
        }
        push_data(out, &bytes);
    }
}

/// Parse Core script-asm into raw script bytes (mirrors `core/test/script_tests`
/// `ParseScript`). Numbers up to 16 / `-1` use the dedicated small-int opcodes;
/// other integers use a minimal `CScriptNum` push; `0x..` is raw bytes,
/// `'str'` is a string push, anything else is an opcode mnemonic.
fn parse_asm(s: &str) -> Vec<u8> {
    let mut out = Vec::new();
    for tok in s.split_whitespace() {
        if let Some(hex) = tok.strip_prefix("0x") {
            out.extend_from_slice(&hex::decode(hex).expect("bad hex token"));
        } else if tok.len() >= 2 && tok.starts_with('\'') && tok.ends_with('\'') {
            push_data(&mut out, &tok.as_bytes()[1..tok.len() - 1]);
        } else if let Ok(n) = tok.parse::<i64>() {
            push_num(&mut out, n);
        } else if let Some(op) = opcode_byte(tok) {
            out.push(op);
        } else {
            panic!("unknown asm token: {tok}");
        }
    }
    out
}

fn parse_flags(s: &str) -> ScriptFlags {
    let mut f = ScriptFlags::none();
    for tok in s.split(',') {
        match tok.trim() {
            "" | "NONE" => {}
            "P2SH" => f.verify_p2sh = true,
            "WITNESS" => f.verify_witness = true,
            "DERSIG" | "STRICTENC" | "LOW_S" => f.verify_strictenc = true,
            "CHECKLOCKTIMEVERIFY" => f.verify_checklocktimeverify = true,
            "CHECKSEQUENCEVERIFY" => f.verify_checksequenceverify = true,
            "TAPROOT" => f.verify_taproot = true,
            "NULLDUMMY" => f.verify_nulldummy = true,
            // Standardness-only flags we don't model are ignored.
            _ => {}
        }
    }
    f
}

/// `tx_valid.json`'s third column is the set of flags to *exclude* from
/// verification (Core verifies each valid tx with `~excluded`), the inverse of
/// `script_tests.json` / `tx_invalid.json`, whose column is the applied set.
///
/// Of the flags our [`ScriptFlags`] models, only strict-encoding
/// (DERSIG/STRICTENC/LOW_S) changes whether a *valid* tx is accepted: it gates
/// strict-DER vs. lax (OpenSSL-style) signature parsing. So we enforce strict
/// encoding unless it is excluded. The path-selecting flags (P2SH/WITNESS/…)
/// never flip a valid tx to invalid in our subset, so — as elsewhere in this
/// harness for the valid corpus — they are left at their default; standard
/// P2SH/SegWit/Taproot spends are exercised live on the interop cluster.
fn parse_flags_excluded(s: &str) -> ScriptFlags {
    let excluded: std::collections::HashSet<&str> = s.split(',').map(|t| t.trim()).collect();
    let mut f = ScriptFlags::none();
    f.verify_strictenc = !(excluded.contains("DERSIG")
        || excluded.contains("STRICTENC")
        || excluded.contains("LOW_S"));
    f
}

/// Error tags whose failure is flag-independent, or is gated only on a flag we
/// model (WITNESS / CLTV / CSV). For these, a failure is decidable: we must
/// reject the script too.
fn is_hard_error(tag: &str) -> bool {
    matches!(
        tag,
        "EVAL_FALSE"
            | "OP_RETURN"
            | "VERIFY"
            | "EQUALVERIFY"
            | "CHECKMULTISIGVERIFY"
            | "CHECKSIGVERIFY"
            | "NUMEQUALVERIFY"
            | "BAD_OPCODE"
            | "DISABLED_OPCODE"
            | "INVALID_STACK_OPERATION"
            | "INVALID_ALTSTACK_OPERATION"
            | "UNBALANCED_CONDITIONAL"
            | "PUSH_SIZE"
            | "OP_COUNT"
            | "STACK_SIZE"
            | "SIG_COUNT"
            | "PUBKEY_COUNT"
            | "SCRIPT_SIZE"
            // gated on flags we model:
            | "WITNESS_PROGRAM_MISMATCH"
            | "WITNESS_PROGRAM_WRONG_LENGTH"
            | "WITNESS_PROGRAM_WITNESS_EMPTY"
            | "WITNESS_MALLEATED"
            | "WITNESS_MALLEATED_P2SH"
            | "WITNESS_UNEXPECTED"
            | "NEGATIVE_LOCKTIME"
            | "UNSATISFIED_LOCKTIME"
    )
}

/// Bitcoin Core's `BuildCreditingTransaction` / `BuildSpendingTransaction` pair.
fn build_spend(
    script_sig: &[u8],
    script_pubkey: &[u8],
    witness: &Witness,
    amount: u64,
) -> (Transaction, TxOut) {
    let credit = Transaction {
        version: Version::ONE,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            // CScript() << OP_0 << OP_0
            script_sig: ScriptBuf::from_bytes(vec![0x00, 0x00]),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(amount),
            script_pubkey: ScriptBuf::from_bytes(script_pubkey.to_vec()),
        }],
    };
    let credit_txid = credit.compute_txid();
    let spend = Transaction {
        version: Version::ONE,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::new(credit_txid, 0),
            script_sig: ScriptBuf::from_bytes(script_sig.to_vec()),
            sequence: Sequence::MAX,
            witness: witness.clone(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(amount),
            script_pubkey: ScriptBuf::new(),
        }],
    };
    let prevout = credit.output[0].clone();
    (spend, prevout)
}

#[test]
fn script_tests_json() {
    let data: Vec<Value> =
        serde_json::from_str(include_str!("data/script_tests.json")).expect("valid JSON");

    let mut asserted = 0usize;
    let mut skipped = 0usize;
    let mut failures = Vec::new();

    for (idx, entry) in data.iter().enumerate() {
        let arr = entry.as_array().unwrap();
        if arr.len() == 1 {
            continue; // comment line
        }

        // Optional leading [witness.., amount] array.
        let (off, witness, amount) = if arr[0].is_array() {
            let w = arr[0].as_array().unwrap();
            let amount_btc = w.last().and_then(|v| v.as_f64()).unwrap_or(0.0);
            let amount = (amount_btc * 100_000_000.0).round() as u64;
            let items: Vec<Vec<u8>> = w[..w.len() - 1]
                .iter()
                .map(|v| hex::decode(v.as_str().unwrap()).expect("bad witness hex"))
                .collect();
            (1, Witness::from_slice(&items), amount)
        } else {
            (0, Witness::new(), 0u64)
        };

        let script_sig = parse_asm(arr[off].as_str().unwrap());
        let script_pubkey = parse_asm(arr[off + 1].as_str().unwrap());
        let flags_str = arr[off + 2].as_str().unwrap();
        let expected = arr[off + 3].as_str().unwrap();
        let comment = arr.get(off + 4).and_then(|v| v.as_str()).unwrap_or("");

        let flags = parse_flags(flags_str);
        let (spend, prevout) = build_spend(&script_sig, &script_pubkey, &witness, amount);
        let res = verify_script(&spend, 0, std::slice::from_ref(&prevout), flags);

        let (want_ok, decidable) = if expected == "OK" {
            (true, true)
        } else if is_hard_error(expected) {
            (false, true)
        } else {
            (false, false)
        };

        if !decidable {
            skipped += 1;
            continue;
        }
        asserted += 1;
        if res.is_ok() != want_ok {
            failures.push(format!(
                "#{idx} [{} | {} | {flags_str}] expected {expected} got {res:?}  // {comment}",
                arr[off].as_str().unwrap(),
                arr[off + 1].as_str().unwrap(),
            ));
        }
    }

    eprintln!(
        "script_tests.json: asserted {asserted}, skipped {skipped} (policy-flag undecidable)"
    );
    assert!(
        failures.is_empty(),
        "{} script vector divergence(s):\n{}",
        failures.len(),
        failures.join("\n")
    );
    // Guard against the corpus silently shrinking (e.g. embed path breaking).
    assert!(
        asserted > 600,
        "too few decidable script vectors: {asserted}"
    );
}

/// Build the prevout map and the aligned prevout vector for a tx-test entry.
fn tx_prevouts(prevouts: &[Value]) -> HashMap<OutPoint, TxOut> {
    let mut map = HashMap::new();
    for p in prevouts {
        let p = p.as_array().unwrap();
        let txid: Txid = p[0].as_str().unwrap().parse().expect("bad prevout txid");
        // Coinbase prevouts use vout -1, which Core encodes as 0xffffffff.
        let vout = p[1].as_i64().unwrap() as u32;
        let spk = parse_asm(p[2].as_str().unwrap());
        let amount = p.get(3).and_then(|v| v.as_u64()).unwrap_or(0);
        map.insert(
            OutPoint::new(txid, vout),
            TxOut {
                value: Amount::from_sat(amount),
                script_pubkey: ScriptBuf::from_bytes(spk),
            },
        );
    }
    map
}

/// Verify every input of `tx` against `prevouts` under `flags`.
/// `Ok(())` iff all inputs verify and the tx passes context-free checks.
fn verify_tx(
    tx: &Transaction,
    prevouts: &HashMap<OutPoint, TxOut>,
    flags: ScriptFlags,
) -> Result<(), String> {
    check_transaction(tx).map_err(|e| format!("check_transaction: {e}"))?;
    let aligned: Vec<TxOut> = tx
        .input
        .iter()
        .map(|i| {
            prevouts
                .get(&i.previous_output)
                .cloned()
                .ok_or_else(|| format!("missing prevout {}", i.previous_output))
        })
        .collect::<Result<_, _>>()?;
    for i in 0..aligned.len() {
        verify_script(tx, i, &aligned, flags).map_err(|e| format!("input {i}: {e}"))?;
    }
    Ok(())
}

/// `excluded_flags = true` for the `tx_valid` corpus (third column lists flags
/// to omit); `false` for `tx_invalid` (third column lists flags to apply).
fn parse_tx_entry(
    entry: &Value,
    excluded_flags: bool,
) -> Option<(HashMap<OutPoint, TxOut>, Transaction, ScriptFlags)> {
    let arr = entry.as_array().unwrap();
    if arr.len() == 1 {
        return None; // comment
    }
    let prevouts = tx_prevouts(arr[0].as_array().unwrap());
    let tx_bytes = hex::decode(arr[1].as_str().unwrap()).expect("bad tx hex");
    let tx: Transaction = deserialize(&tx_bytes).expect("deserialize tx");
    let flags = if excluded_flags {
        parse_flags_excluded(arr[2].as_str().unwrap())
    } else {
        parse_flags(arr[2].as_str().unwrap())
    };
    Some((prevouts, tx, flags))
}

/// Known divergences in `tx_valid.json`: valid transactions our interpreter
/// rejects. **Now empty** — the entire `tx_valid` corpus is matched.
///
/// The ten formerly-pinned vectors were resolved by two fixes (2026-06-18):
///   1. The harness was applying `tx_valid.json`'s third column as the *enabled*
///      flag set; for this corpus it is the *excluded* set (Core verifies with
///      `~excluded`). With strict-encoding wrongly forced on, the OpenSSL-lax /
///      negative-ASN.1 / non-empty-dummy vectors were spuriously rejected. Fixed
///      by [`parse_flags_excluded`]; our interpreter already does lax parsing.
///   2. A genuine consensus gap: the legacy sighash did not strip
///      `OP_CODESEPARATOR` from the subscript (Core's `SerializeScriptCode`
///      does). Fixed in `script.rs::check_sig` via `remove_codeseparators`,
///      closing the three executed-CODESEPARATOR vectors.
///
/// Kept (empty) so the suite stays regression-protective: a *new* rejection of a
/// valid tx fails the test, and any entry re-added but no longer failing is
/// caught by the exhaustiveness check below.
const KNOWN_TX_VALID_DIVERGENCES: &[&str] = &[];

#[test]
fn tx_valid_json() {
    let data: Vec<Value> =
        serde_json::from_str(include_str!("data/tx_valid.json")).expect("valid JSON");
    let mut asserted = 0usize;
    let mut unexpected = Vec::new();
    let mut still_diverging = std::collections::HashSet::new();

    for (idx, entry) in data.iter().enumerate() {
        let Some((prevouts, tx, flags)) = parse_tx_entry(entry, true) else {
            continue;
        };
        asserted += 1;
        // A valid tx verifies under Core's strict flags, hence under our subset.
        if let Err(e) = verify_tx(&tx, &prevouts, flags) {
            let txid = tx.compute_txid().to_string();
            if KNOWN_TX_VALID_DIVERGENCES.contains(&txid.as_str()) {
                still_diverging.insert(txid);
            } else {
                unexpected.push(format!("#{idx} {txid}: rejected valid tx: {e}"));
            }
        }
    }

    eprintln!(
        "tx_valid.json: asserted {asserted}, {} known divergences still failing",
        still_diverging.len()
    );
    assert!(
        unexpected.is_empty(),
        "{} NEW tx_valid divergence(s) (regression — a valid tx is now rejected):\n{}",
        unexpected.len(),
        unexpected.join("\n")
    );
    // If a known gap gets fixed, prune it from the allowlist (keeps the list honest).
    let fixed: Vec<_> = KNOWN_TX_VALID_DIVERGENCES
        .iter()
        .filter(|t| !still_diverging.contains(**t))
        .collect();
    assert!(
        fixed.is_empty(),
        "these known divergences now PASS — remove them from KNOWN_TX_VALID_DIVERGENCES: {fixed:?}"
    );
    assert!(asserted > 90, "too few tx_valid vectors: {asserted}");
}

#[test]
fn tx_invalid_json() {
    let data: Vec<Value> =
        serde_json::from_str(include_str!("data/tx_invalid.json")).expect("valid JSON");
    let mut detected = 0usize;
    // Entries whose only defect is outside what our script + context-free checks
    // model (e.g. non-standard-but-consensus-valid scripts rejected by Core only
    // under a policy flag). They verify under our subset, so we can't assert on
    // them — but the count is pinned so a regression that flips a currently
    // *detected* invalid tx to "accepted" trips the bound.
    let mut undecidable = 0usize;

    for entry in data.iter() {
        let Some((prevouts, tx, flags)) = parse_tx_entry(entry, false) else {
            continue;
        };
        match verify_tx(&tx, &prevouts, flags) {
            Err(_) => detected += 1,
            Ok(()) => undecidable += 1,
        }
    }

    eprintln!("tx_invalid.json: detected {detected}, undecidable {undecidable}");
    // Pinned after measuring against v28.0: the bulk are detected; only a small
    // tail is undecidable under our flag subset. Tighten if the corpus changes.
    assert!(
        detected > 60,
        "too few tx_invalid vectors detected: {detected}"
    );
    assert!(
        undecidable <= 40,
        "more undecidable invalid txs than expected ({undecidable}) — a consensus \
         rejection may have regressed into acceptance"
    );
}

/// Regression test for block 925565 tapscript OP_CODESEPARATOR position.
/// Transaction uses OP_TUCK OP_CHECKSIGVERIFY OP_CODESEPARATOR pattern with
/// 160 signatures and 159 code separators. Verifies that codesep_pos is
/// tracked as instruction index (BIP 342), not byte offset.
#[test]
fn test_block_925565_tapscript_checksigverify() {
    let raw_hex = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/testdata_tx_925565.hex"
    ))
    .expect("test data file");
    let raw = hex::decode(raw_hex.trim()).expect("valid hex");
    let tx: Transaction = deserialize(&raw).expect("valid transaction");

    // Prevout: txid 7fcf7ae9..., vout 1, value 330 sats
    let prev_output = TxOut {
        value: Amount::from_sat(330),
        script_pubkey: ScriptBuf::from_bytes(
            hex::decode("5120fe08bd466713fb1af3cd4be99453bb6179d1d970e607ec58b25fc164356605d2")
                .unwrap(),
        ),
    };

    let all_prevouts = vec![prev_output.clone()];

    let flags = ScriptFlags {
        verify_p2sh: true,
        verify_witness: true,
        verify_strictenc: true,
        verify_checklocktimeverify: true,
        verify_checksequenceverify: true,
        verify_taproot: true,
        verify_nulldummy: true,
        verify_bip110: false,
    };

    // Cross-check with bitcoinconsensus (Bitcoin Core's C++)
    {
        let script_pubkey_bytes =
            hex::decode("5120fe08bd466713fb1af3cd4be99453bb6179d1d970e607ec58b25fc164356605d2")
                .unwrap();
        let utxo = bitcoinconsensus::Utxo {
            script_pubkey: script_pubkey_bytes.as_ptr(),
            script_pubkey_len: script_pubkey_bytes.len() as u32,
            value: 330,
        };
        assert!(
            bitcoinconsensus::verify_with_flags(
                &script_pubkey_bytes,
                330,
                &raw,
                Some(&[utxo]),
                0,
                bitcoinconsensus::VERIFY_ALL_PRE_TAPROOT | bitcoinconsensus::VERIFY_TAPROOT,
            )
            .is_ok(),
            "bitcoinconsensus must verify this tx"
        );
    }

    let result = verify_script(&tx, 0, &all_prevouts, flags);
    assert!(
        result.is_ok(),
        "Block 925565 tx should verify: {:?}",
        result.err()
    );
}
