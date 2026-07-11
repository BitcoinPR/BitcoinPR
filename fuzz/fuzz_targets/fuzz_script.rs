#![no_main]
//! Fuzz the script interpreter via `verify_script`. Splits the input into a
//! scriptSig and a scriptPubKey, builds Core's crediting/spending tx pair, and
//! runs verification under all flags. The interpreter must terminate without
//! panicking on any byte sequence (push parsing, opcode dispatch, limits).
use libfuzzer_sys::fuzz_target;

use bitcoin::absolute::LockTime;
use bitcoin::transaction::Version;
use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};
use bitcoinpr_core::script::{verify_script, ScriptFlags};

fuzz_target!(|data: &[u8]| {
    // First byte picks a split point so we cover both scriptSig and scriptPubKey.
    if data.is_empty() {
        return;
    }
    let split = (data[0] as usize) % data.len().max(1);
    let rest = &data[1..];
    let (sig_bytes, spk_bytes) = rest.split_at(split.min(rest.len()));

    let credit = Transaction {
        version: Version::ONE,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::from_bytes(vec![0x00, 0x00]),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(0),
            script_pubkey: ScriptBuf::from_bytes(spk_bytes.to_vec()),
        }],
    };
    let credit_txid = credit.compute_txid();
    let spend = Transaction {
        version: Version::ONE,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::new(credit_txid, 0),
            script_sig: ScriptBuf::from_bytes(sig_bytes.to_vec()),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(0),
            script_pubkey: ScriptBuf::new(),
        }],
    };
    let prevout = credit.output[0].clone();
    let _ = verify_script(&spend, 0, std::slice::from_ref(&prevout), ScriptFlags::all());
});
