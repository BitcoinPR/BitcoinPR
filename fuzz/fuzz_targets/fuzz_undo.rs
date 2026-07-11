#![no_main]
//! Fuzz the block undo-record decoder. Undo data is read back from RocksDB at
//! reorg time; a corrupt/truncated record must surface an error, not panic or
//! over-read.
use libfuzzer_sys::fuzz_target;

use bitcoinpr_storage::utxo_set::UtxoSet;

fuzz_target!(|data: &[u8]| {
    let _ = UtxoSet::deserialize_undo(data);
});
