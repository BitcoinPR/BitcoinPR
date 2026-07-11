//! BIP 350 (bech32m) index-path fixture: prove the scripthash index can derive
//! a stable Electrum-style scripthash from a taproot (witness v1) address.
//!
//! This is test-only: it exercises the existing public
//! `ScripthashIndex::compute_scripthash` helper (SHA256 of the scriptPubKey,
//! reversed) against a deterministically constructed bech32m taproot address.

use bitcoin::hashes::{sha256, Hash};
use bitcoin::{Address, Network, WitnessProgram, WitnessVersion};
use bitcoinpr_index::ScripthashIndex;
use std::str::FromStr;

/// A regtest taproot address decodes through the index path and yields a stable,
/// non-empty scripthash that matches an independent SHA256(scriptPubKey) reverse.
#[test]
fn taproot_bech32m_scripthash_is_stable() {
    // Deterministic 32-byte program → witness v1 taproot scriptPubKey.
    let program_bytes = [0x07u8; 32];
    let wp = WitnessProgram::new(WitnessVersion::V1, &program_bytes).unwrap();
    let addr = Address::from_witness_program(wp, Network::Regtest);

    // Regtest taproot addresses use the bech32m `bcrt1p` prefix.
    let addr_str = addr.to_string();
    assert!(
        addr_str.starts_with("bcrt1p"),
        "regtest taproot must be bech32m bcrt1p: {addr_str}"
    );

    // Round-trip the string through the parser (the index decode path).
    let parsed = Address::from_str(&addr_str)
        .unwrap()
        .require_network(Network::Regtest)
        .unwrap();
    let spk = parsed.script_pubkey();

    let scripthash = ScripthashIndex::compute_scripthash(spk.as_bytes());

    // Stable and non-empty.
    assert_ne!(scripthash, [0u8; 32], "scripthash must be non-empty");

    // Matches an independent reference computation: reverse(sha256(spk)).
    let mut expected = *sha256::Hash::hash(spk.as_bytes()).as_byte_array();
    expected.reverse();
    assert_eq!(scripthash, expected);

    // Deterministic across calls.
    assert_eq!(
        scripthash,
        ScripthashIndex::compute_scripthash(spk.as_bytes())
    );
}
