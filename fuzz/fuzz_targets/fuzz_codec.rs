#![no_main]
//! Fuzz `MessageCodec::read_message` — the P2P wire decoder. Malformed headers,
//! bogus lengths, and truncated/oversized payloads must error cleanly, never
//! panic or over-allocate.
use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;

use bitcoinpr_p2p::codec::MessageCodec;

static RT: OnceLock<tokio::runtime::Runtime> = OnceLock::new();

const MAINNET_MAGIC: [u8; 4] = [0xf9, 0xbe, 0xb4, 0xd9];

fuzz_target!(|data: &[u8]| {
    // Prepend the network magic so most inputs pass the magic gate and exercise
    // the command/length/checksum/payload paths beyond it.
    let mut buf = Vec::with_capacity(4 + data.len());
    buf.extend_from_slice(&MAINNET_MAGIC);
    buf.extend_from_slice(data);

    let codec = MessageCodec::new(u32::from_le_bytes(MAINNET_MAGIC));
    let rt = RT.get_or_init(|| {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("build runtime")
    });
    rt.block_on(async {
        let mut slice = &buf[..];
        let _ = codec.read_message(&mut slice).await;
    });
});
