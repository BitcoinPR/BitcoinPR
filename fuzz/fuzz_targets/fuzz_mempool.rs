#![no_main]
//! Fuzz the persisted-mempool parser. The length-prefixed framing is fully
//! attacker-controlled on disk; truncated counts/lengths must yield a short
//! list, never a panic or unbounded allocation.
use libfuzzer_sys::fuzz_target;

use bitcoinpr_core::mempool::Mempool;

fuzz_target!(|data: &[u8]| {
    let _ = Mempool::parse_persisted_txs(data);
});
