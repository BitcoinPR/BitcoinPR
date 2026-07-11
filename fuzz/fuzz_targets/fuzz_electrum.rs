#![no_main]
//! Fuzz the Electrum JSON-RPC line parser. Each newline-delimited client line
//! is fed straight to the deserializer; arbitrary bytes must parse-or-reject
//! without panicking.
use libfuzzer_sys::fuzz_target;

use bitcoinpr_index::electrum::fuzz_parse_request_line;

fuzz_target!(|data: &[u8]| {
    // Electrum frames are UTF-8 JSON lines; lossy-decode so non-UTF-8 still
    // exercises the parser rather than being filtered out.
    let line = String::from_utf8_lossy(data);
    let _ = fuzz_parse_request_line(&line);
});
