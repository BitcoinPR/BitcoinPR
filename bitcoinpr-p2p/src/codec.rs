use bitcoin::consensus::{Decodable, Encodable};
use bitcoin::p2p::message::RawNetworkMessage;
use std::io::Cursor;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tracing::trace;

use crate::error::{P2pError, P2pResult};

/// Blanket maximum message payload size (32 MB, matches Bitcoin Core's
/// MAX_PROTOCOL_MESSAGE_LENGTH backstop). Per-command caps below are the
/// effective limits; this remains as a final backstop.
const MAX_MESSAGE_SIZE: usize = 32 * 1024 * 1024;

/// Cap for `block` payloads. Core's MAX_BLOCK_SERIALIZED_SIZE is 4_000_000
/// bytes; we add 8 KB headroom for the message framing and any encoding slack.
const MAX_BLOCK_PAYLOAD: usize = 4_000_000 + 8 * 1024;

/// Cap for `tx` payloads. Core's standardness policy caps transactions at
/// 400_000 weight (~100k vbytes, ~400 KB serialized with witnesses); we allow
/// 1 MB to be safe for nonstandard relay while still bounding allocation.
const MAX_TX_PAYLOAD: usize = 1_000_000;

/// Cap for `headers` payloads. Core sends at most MAX_HEADERS_RESULTS = 2000
/// headers x 81 bytes each + compact-size prefix ≈ 162_009 bytes.
const MAX_HEADERS_PAYLOAD: usize = 170_000;

/// Cap for `inv`/`getdata`/`notfound` payloads. Core caps these at
/// MAX_INV_SZ = 50_000 entries x 36 bytes + compact-size prefix ≈ 1_800_009.
const MAX_INV_PAYLOAD: usize = 1_900_000;

/// Cap for `addr`/`addrv2` payloads. Core caps at MAX_ADDR_TO_SEND = 1_000
/// entries x ~30-40 bytes each.
const MAX_ADDR_PAYLOAD: usize = 100_000;

/// Cap for `getheaders`/`getblocks` payloads. The block locator holds at most
/// MAX_LOCATOR_SZ = 101 hashes (32 bytes each) plus version + stop hash.
const MAX_LOCATOR_PAYLOAD: usize = 8_000;

/// Default cap for all other (and unknown) commands. The largest legitimate
/// message in this class is `filterload` at Core's MAX_BLOOM_FILTER_SIZE
/// (36_000 bytes), comfortably under 64 KB.
const MAX_DEFAULT_PAYLOAD: usize = 64 * 1024;

/// Chunk size for incremental payload reads. Payloads larger than one chunk
/// are read piecewise so an attacker advertising a multi-MB length but
/// trickling bytes cannot pin the full allocation up front.
const READ_CHUNK_SIZE: usize = 256 * 1024;

/// Maximum allowed payload size for a given wire command (the NUL-padded
/// 12-byte ASCII field from the message header). Unknown commands get the
/// default cap — they are decoded then ignored downstream, so there is no
/// reason to allocate large buffers for them.
pub(crate) fn max_payload_for_command(command: &[u8]) -> usize {
    let end = command
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(command.len());
    match &command[..end] {
        b"block" => MAX_BLOCK_PAYLOAD,
        b"tx" => MAX_TX_PAYLOAD,
        b"headers" => MAX_HEADERS_PAYLOAD,
        b"inv" | b"getdata" | b"notfound" => MAX_INV_PAYLOAD,
        b"addr" | b"addrv2" => MAX_ADDR_PAYLOAD,
        b"getheaders" | b"getblocks" => MAX_LOCATOR_PAYLOAD,
        _ => MAX_DEFAULT_PAYLOAD,
    }
}

/// Reads and writes Bitcoin P2P messages over an async TCP stream.
pub struct MessageCodec {
    /// Expected network magic, as the little-endian u32 of the on-wire bytes
    /// (constructed via `u32::from_le_bytes(network.magic().to_bytes())`).
    magic: u32,
}

impl MessageCodec {
    pub fn new(magic: u32) -> Self {
        MessageCodec { magic }
    }

    /// Read a single message from the stream, returning the decoded message
    /// and the raw payload bytes.
    pub async fn read_message<R: AsyncRead + Unpin>(
        &self,
        reader: &mut R,
    ) -> P2pResult<(RawNetworkMessage, Vec<u8>)> {
        // Read the full header (4 magic + 12 command + 4 length + 4 checksum = 24 bytes)
        let mut header_buf = [0u8; 24];
        reader
            .read_exact(&mut header_buf)
            .await
            .map_err(|e| P2pError::Connection(format!("failed to read message header: {e}")))?;

        // Reject messages whose network magic doesn't match ours (wrong-network
        // peers or garbage traffic) before allocating for the payload. The magic
        // occupies the first 4 header bytes in wire order.
        if header_buf[0..4] != self.magic.to_le_bytes() {
            return Err(P2pError::Protocol(format!(
                "bad network magic: got {:02x?}, expected {:02x?}",
                &header_buf[0..4],
                self.magic.to_le_bytes()
            )));
        }

        // Parse payload length from header bytes [16..20]
        let payload_len =
            u32::from_le_bytes(header_buf[16..20].try_into().expect("fixed-size slice")) as usize;

        // Blanket backstop (Core's MAX_PROTOCOL_MESSAGE_LENGTH analogue).
        if payload_len > MAX_MESSAGE_SIZE {
            return Err(P2pError::Protocol(format!(
                "message payload too large: {payload_len} bytes"
            )));
        }

        // Per-command cap, enforced BEFORE any payload allocation so a hostile
        // peer with the right magic cannot direct multi-MB allocations with a
        // 24-byte header. The command field is header bytes [4..16].
        let command = &header_buf[4..16];
        let cap = max_payload_for_command(command);
        if payload_len > cap {
            let end = command.iter().position(|&b| b == 0).unwrap_or(12);
            return Err(P2pError::Protocol(format!(
                "payload too large for command '{}': {} bytes (cap {})",
                String::from_utf8_lossy(&command[..end]),
                payload_len,
                cap
            )));
        }

        // Read the payload. For payloads larger than one chunk, read
        // incrementally and grow the buffer as bytes actually arrive, so an
        // attacker advertising a large length but trickling data cannot pin
        // the full allocation up front.
        let mut payload: Vec<u8> = Vec::with_capacity(payload_len.min(READ_CHUNK_SIZE));
        while payload.len() < payload_len {
            let old_len = payload.len();
            let n = (payload_len - old_len).min(READ_CHUNK_SIZE);
            payload.resize(old_len + n, 0);
            reader
                .read_exact(&mut payload[old_len..])
                .await
                .map_err(|e| {
                    P2pError::Connection(format!("failed to read message payload: {e}"))
                })?;
        }

        // Concatenate header + payload and decode (consensus_decode validates
        // the header checksum against the payload).
        let mut full_msg = Vec::with_capacity(24 + payload_len);
        full_msg.extend_from_slice(&header_buf);
        full_msg.extend_from_slice(&payload);

        let mut cursor = Cursor::new(&full_msg);
        let msg = RawNetworkMessage::consensus_decode(&mut cursor)
            .map_err(|e| P2pError::Serialization(format!("decode message: {e}")))?;

        trace!("Read message: {:?}", msg.cmd());
        Ok((msg, payload))
    }

    /// Write a single message to the stream.
    pub async fn write_message<W: AsyncWrite + Unpin>(
        &self,
        writer: &mut W,
        msg: &RawNetworkMessage,
    ) -> P2pResult<()> {
        let mut buf = Vec::new();
        msg.consensus_encode(&mut buf)
            .map_err(|e| P2pError::Serialization(format!("encode message: {e}")))?;

        writer
            .write_all(&buf)
            .await
            .map_err(|e| P2pError::Connection(format!("failed to write message: {e}")))?;
        writer
            .flush()
            .await
            .map_err(|e| P2pError::Connection(format!("failed to flush: {e}")))?;

        trace!("Wrote message: {:?}", msg.cmd());
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use bitcoin::p2p::message::NetworkMessage;
    use bitcoin::Network;

    fn test_magic() -> u32 {
        u32::from_le_bytes(Network::Regtest.magic().to_bytes())
    }

    /// Build a 24-byte wire header with the given command and advertised
    /// payload length (checksum left zeroed — irrelevant for cap tests, which
    /// must reject before the payload is ever read).
    fn wire_header(command: &[u8], payload_len: u32) -> [u8; 24] {
        assert!(command.len() <= 12);
        let mut h = [0u8; 24];
        h[0..4].copy_from_slice(&test_magic().to_le_bytes());
        h[4..4 + command.len()].copy_from_slice(command);
        h[16..20].copy_from_slice(&payload_len.to_le_bytes());
        h
    }

    async fn read_from_bytes(buf: &[u8]) -> P2pResult<(RawNetworkMessage, Vec<u8>)> {
        let codec = MessageCodec::new(test_magic());
        let mut reader = buf;
        codec.read_message(&mut reader).await
    }

    #[tokio::test]
    async fn ping_oversized_rejected_before_allocation() {
        // A `ping` advertising 1 MB must be rejected by the default 64 KB cap
        // with a Protocol error (disconnect), before any payload read.
        let h = wire_header(b"ping", 1_000_000);
        let err = read_from_bytes(&h).await.unwrap_err();
        assert!(
            matches!(err, P2pError::Protocol(_)),
            "expected Protocol error, got: {err:?}"
        );
        assert!(err.to_string().contains("ping"));
    }

    #[tokio::test]
    async fn block_over_backstop_rejected() {
        // 33 MB exceeds the blanket MAX_MESSAGE_SIZE backstop.
        let h = wire_header(b"block", 33 * 1024 * 1024);
        let err = read_from_bytes(&h).await.unwrap_err();
        assert!(
            matches!(err, P2pError::Protocol(_)),
            "expected Protocol error, got: {err:?}"
        );
    }

    #[tokio::test]
    async fn block_over_block_cap_rejected() {
        // 5 MB is under the backstop but over the 4 MB block cap.
        let h = wire_header(b"block", 5_000_000);
        let err = read_from_bytes(&h).await.unwrap_err();
        assert!(
            matches!(err, P2pError::Protocol(_)),
            "expected Protocol error, got: {err:?}"
        );
        assert!(err.to_string().contains("block"));
    }

    #[tokio::test]
    async fn block_under_cap_passes_size_check() {
        // 3.9 MB is under the block cap, so the size checks pass and the codec
        // proceeds to read the payload. With a truncated stream this surfaces
        // as a Connection error from read_exact — proving the cap allowed it.
        let h = wire_header(b"block", 3_900_000);
        let err = read_from_bytes(&h).await.unwrap_err();
        assert!(
            matches!(err, P2pError::Connection(_)),
            "expected Connection error (truncated payload), got: {err:?}"
        );
    }

    #[tokio::test]
    async fn unknown_command_oversized_rejected() {
        // Unknown commands get the default 64 KB cap; 1 MB must be rejected.
        let h = wire_header(b"boguscmd", 1_000_000);
        let err = read_from_bytes(&h).await.unwrap_err();
        assert!(
            matches!(err, P2pError::Protocol(_)),
            "expected Protocol error, got: {err:?}"
        );
        assert!(err.to_string().contains("boguscmd"));
    }

    #[tokio::test]
    async fn unknown_command_small_passes_size_check() {
        // A small unknown command passes the header size checks; with a
        // truncated stream the failure is a Connection error from the
        // payload read, not a Protocol rejection.
        let h = wire_header(b"boguscmd", 100);
        let err = read_from_bytes(&h).await.unwrap_err();
        assert!(
            matches!(err, P2pError::Connection(_)),
            "expected Connection error (truncated payload), got: {err:?}"
        );
    }

    #[tokio::test]
    async fn ping_roundtrip() {
        let codec = MessageCodec::new(test_magic());
        let msg =
            RawNetworkMessage::new(Network::Regtest.magic(), NetworkMessage::Ping(0xdeadbeef));

        let mut wire = Vec::new();
        codec.write_message(&mut wire, &msg).await.unwrap();

        let mut reader = wire.as_slice();
        let (decoded, _payload) = codec.read_message(&mut reader).await.unwrap();
        assert_eq!(decoded, msg);
    }

    #[test]
    fn cap_table_matches_expected_bounds() {
        assert_eq!(
            max_payload_for_command(b"block\0\0\0\0\0\0\0"),
            MAX_BLOCK_PAYLOAD
        );
        assert_eq!(
            max_payload_for_command(b"tx\0\0\0\0\0\0\0\0\0\0"),
            MAX_TX_PAYLOAD
        );
        assert_eq!(
            max_payload_for_command(b"headers\0\0\0\0\0"),
            MAX_HEADERS_PAYLOAD
        );
        assert_eq!(
            max_payload_for_command(b"inv\0\0\0\0\0\0\0\0\0"),
            MAX_INV_PAYLOAD
        );
        assert_eq!(
            max_payload_for_command(b"getdata\0\0\0\0\0"),
            MAX_INV_PAYLOAD
        );
        assert_eq!(
            max_payload_for_command(b"notfound\0\0\0\0"),
            MAX_INV_PAYLOAD
        );
        assert_eq!(
            max_payload_for_command(b"addr\0\0\0\0\0\0\0\0"),
            MAX_ADDR_PAYLOAD
        );
        assert_eq!(
            max_payload_for_command(b"addrv2\0\0\0\0\0\0"),
            MAX_ADDR_PAYLOAD
        );
        assert_eq!(
            max_payload_for_command(b"getheaders\0\0"),
            MAX_LOCATOR_PAYLOAD
        );
        assert_eq!(
            max_payload_for_command(b"getblocks\0\0\0"),
            MAX_LOCATOR_PAYLOAD
        );
        assert_eq!(
            max_payload_for_command(b"version\0\0\0\0\0"),
            MAX_DEFAULT_PAYLOAD
        );
        assert_eq!(
            max_payload_for_command(b"filterload\0\0"),
            MAX_DEFAULT_PAYLOAD
        );
        // Every per-command cap stays under the blanket backstop.
        for cap in [
            MAX_BLOCK_PAYLOAD,
            MAX_TX_PAYLOAD,
            MAX_HEADERS_PAYLOAD,
            MAX_INV_PAYLOAD,
            MAX_ADDR_PAYLOAD,
            MAX_LOCATOR_PAYLOAD,
            MAX_DEFAULT_PAYLOAD,
        ] {
            assert!(cap <= MAX_MESSAGE_SIZE);
        }
    }
}
