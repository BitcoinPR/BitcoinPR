//! BIP 324 v2 transport wiring.
//!
//! Drives the v2 handshake on a live socket and bridges between the application
//! layer (`RawNetworkMessage`) and the encrypted record layer in
//! [`crate::v2_transport`]. After the handshake, [`SendTransport`] /
//! [`RecvTransport`] are the single point through which every message is framed,
//! transparently using either v1 plaintext or v2 encrypted packets.
//!
//! Handshake (we send zero garbage and no decoys, which keeps the
//! garbage-authenticating AAD empty on our side):
//! ```text
//!   send:  ellswift_pubkey(64) || garbage_terminator(16) || version_packet
//!   recv:  ellswift_pubkey(64) || <peer garbage> || garbage_terminator(16)
//!                              || <decoys...> || version_packet
//! ```
//! The responder additionally distinguishes a v1 peer by matching the first 16
//! bytes against the v1 `version` message header prefix.

use std::pin::Pin;
use std::task::{Context, Poll};

use bitcoin::consensus::{Decodable, Encodable};
use bitcoin::hashes::{sha256d, Hash};
use bitcoin::p2p::message::RawNetworkMessage;
use std::io::Cursor;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

use crate::codec::{max_payload_for_command, MessageCodec};
use crate::error::{P2pError, P2pResult};
use crate::v2_transport::{
    ShortMsgId, V2MessageType, V2Packet, V2Receiver, V2Sender, V2Transport, AEAD_TAG_LEN,
    HEADER_LEN, LENGTH_FIELD_LEN,
};

/// Maximum garbage bytes a peer may send before the terminator (BIP 324).
const MAX_GARBAGE_LEN: usize = 4095;
/// Terminator length.
const GARBAGE_TERM_LEN: usize = 16;
/// Hard cap on a single v2 packet's contents, independent of the per-command
/// caps applied after the command is known.
const MAX_V2_CONTENTS: usize = 4_000_000 + 8 * 1024;

/// The 16-byte prefix a v1 peer's first bytes start with: network magic followed
/// by the `version` command field. The responder uses this to tell v1 from v2.
pub fn v1_version_prefix(magic: [u8; 4]) -> [u8; 16] {
    let mut p = [0u8; 16];
    p[0..4].copy_from_slice(&magic);
    p[4..11].copy_from_slice(b"version");
    p
}

/// A reader that yields a buffered prefix before delegating to the inner reader.
/// Used on inbound connections so the bytes consumed for v1/v2 detection are
/// still available to whichever handshake path runs.
pub struct PrefixedReader<R> {
    prefix: Vec<u8>,
    pos: usize,
    inner: R,
}

impl<R> PrefixedReader<R> {
    pub fn new(prefix: Vec<u8>, inner: R) -> Self {
        PrefixedReader {
            prefix,
            pos: 0,
            inner,
        }
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for PrefixedReader<R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if self.pos < self.prefix.len() {
            let remaining = self.prefix.len() - self.pos;
            let n = remaining.min(buf.remaining());
            let start = self.pos;
            buf.put_slice(&self.prefix[start..start + n]);
            self.pos += n;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

// ── Application ↔ v2-contents bridging ──────────────────────────────────────

/// Serialize a message and split it into (command, payload) for v2 framing.
fn split_v1_message(msg: &RawNetworkMessage) -> P2pResult<(String, Vec<u8>)> {
    let mut buf = Vec::new();
    msg.consensus_encode(&mut buf)
        .map_err(|e| P2pError::Serialization(format!("encode message: {e}")))?;
    if buf.len() < 24 {
        return Err(P2pError::Serialization("short v1 frame".into()));
    }
    let end = buf[4..16].iter().position(|&b| b == 0).unwrap_or(12);
    let command = String::from_utf8_lossy(&buf[4..4 + end]).to_string();
    let payload = buf[24..].to_vec();
    Ok((command, payload))
}

/// Build v2 packet contents (message-type framing) from a message.
fn encode_v2_contents(msg: &RawNetworkMessage) -> P2pResult<Vec<u8>> {
    let (command, payload) = split_v1_message(msg)?;
    let msg_type = match ShortMsgId::from_command(&command) {
        Some(id) => V2MessageType::Short(id as u8),
        None => V2MessageType::Full(command),
    };
    Ok(V2Packet {
        ignore: false,
        msg_type,
        payload,
    }
    .encode_contents())
}

/// Reassemble a `RawNetworkMessage` from a decrypted v2 packet's contents.
/// Reuses the v1 decoder (and its per-command size caps) by rebuilding the
/// 24-byte framed message with a correct checksum.
fn decode_v2_contents(magic: [u8; 4], contents: &[u8]) -> P2pResult<(RawNetworkMessage, Vec<u8>)> {
    let packet = V2Packet::decode_contents(contents, false)
        .ok_or_else(|| P2pError::Protocol("malformed v2 packet contents".into()))?;
    let command = match packet.msg_type {
        V2MessageType::Short(id) => ShortMsgId::from_u8(id)
            .ok_or_else(|| P2pError::Protocol(format!("unknown v2 short msg id {id}")))?
            .to_command()
            .to_string(),
        V2MessageType::Full(cmd) => cmd,
    };
    if command.len() > 12 {
        return Err(P2pError::Protocol("v2 command too long".into()));
    }
    let mut cmd_field = [0u8; 12];
    cmd_field[..command.len()].copy_from_slice(command.as_bytes());

    let payload = packet.payload;
    let cap = max_payload_for_command(&cmd_field);
    if payload.len() > cap {
        return Err(P2pError::Protocol(format!(
            "v2 payload too large for '{command}': {} (cap {cap})",
            payload.len()
        )));
    }

    let checksum = sha256d::Hash::hash(&payload);
    let mut frame = Vec::with_capacity(24 + payload.len());
    frame.extend_from_slice(&magic);
    frame.extend_from_slice(&cmd_field);
    frame.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    frame.extend_from_slice(&checksum[0..4]);
    frame.extend_from_slice(&payload);

    let mut cursor = Cursor::new(&frame);
    let msg = RawNetworkMessage::consensus_decode(&mut cursor)
        .map_err(|e| P2pError::Serialization(format!("decode v2 message '{command}': {e}")))?;
    Ok((msg, payload))
}

// ── Send / Recv transport (used by handshake exchange and the I/O loops) ─────

/// The write side of an established connection.
pub enum SendTransport {
    V1(MessageCodec),
    V2(V2Sender),
}

impl SendTransport {
    pub async fn send<W: AsyncWrite + Unpin>(
        &mut self,
        writer: &mut W,
        msg: &RawNetworkMessage,
    ) -> P2pResult<()> {
        match self {
            SendTransport::V1(codec) => codec.write_message(writer, msg).await,
            SendTransport::V2(sender) => {
                let contents = encode_v2_contents(msg)?;
                let packet = sender.encrypt_packet(&contents);
                writer
                    .write_all(&packet)
                    .await
                    .map_err(|e| P2pError::Connection(format!("v2 write: {e}")))?;
                writer
                    .flush()
                    .await
                    .map_err(|e| P2pError::Connection(format!("v2 flush: {e}")))?;
                Ok(())
            }
        }
    }
}

/// The read side of an established connection.
pub enum RecvTransport {
    V1(MessageCodec),
    V2 { recv: V2Receiver, magic: [u8; 4] },
}

impl RecvTransport {
    pub async fn recv<R: AsyncRead + Unpin>(
        &mut self,
        reader: &mut R,
    ) -> P2pResult<(RawNetworkMessage, Vec<u8>)> {
        match self {
            RecvTransport::V1(codec) => codec.read_message(reader).await,
            RecvTransport::V2 { recv, magic } => loop {
                let contents = read_v2_packet(reader, recv).await?;
                // Empty contents = a keep-alive/version-style packet with no
                // message; skip it and read the next.
                if contents.is_empty() {
                    continue;
                }
                return decode_v2_contents(*magic, &contents);
            },
        }
    }
}

/// Read one v2 packet body and return its decrypted contents, skipping decoys.
async fn read_v2_packet<R: AsyncRead + Unpin>(
    reader: &mut R,
    recv: &mut V2Receiver,
) -> P2pResult<Vec<u8>> {
    loop {
        let mut enc_len = [0u8; LENGTH_FIELD_LEN];
        reader
            .read_exact(&mut enc_len)
            .await
            .map_err(|e| P2pError::Connection(format!("v2 read len: {e}")))?;
        let contents_len = recv.decrypt_len(&enc_len);
        if contents_len > MAX_V2_CONTENTS {
            return Err(P2pError::Protocol(format!(
                "v2 packet contents too large: {contents_len}"
            )));
        }
        let total = contents_len + HEADER_LEN + AEAD_TAG_LEN;
        let mut body = vec![0u8; total];
        reader
            .read_exact(&mut body)
            .await
            .map_err(|e| P2pError::Connection(format!("v2 read body: {e}")))?;
        let (ignore, contents) = recv
            .decrypt_packet(&body)
            .ok_or_else(|| P2pError::Protocol("v2 packet auth failed".into()))?;
        if ignore {
            continue; // decoy packet
        }
        return Ok(contents);
    }
}

// ── Handshake ───────────────────────────────────────────────────────────────

/// Run the v2 handshake as initiator (outbound). On success returns the split
/// send/recv ciphers ready for the version exchange.
pub async fn initiate_v2<R, W>(
    reader: &mut R,
    writer: &mut W,
    magic: [u8; 4],
) -> P2pResult<(V2Sender, V2Receiver)>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut transport = V2Transport::new_initiator(magic);
    // Send our key (zero garbage).
    writer
        .write_all(transport.our_pubkey())
        .await
        .map_err(|e| P2pError::Connection(format!("v2 send key: {e}")))?;
    writer
        .flush()
        .await
        .map_err(|e| P2pError::Connection(format!("v2 flush: {e}")))?;

    let mut peer_key = [0u8; 64];
    reader
        .read_exact(&mut peer_key)
        .await
        .map_err(|e| P2pError::Connection(format!("v2 read peer key: {e}")))?;
    let keys = transport
        .take_keys(&peer_key)
        .ok_or_else(|| P2pError::Protocol("v2 ECDH/key derivation failed".into()))?;
    finish_v2(keys, reader, writer).await
}

/// Run the v2 handshake as responder (inbound). `reader` must still hold the 64
/// initiator key bytes (e.g. via [`PrefixedReader`] carrying the 16 detection
/// bytes). On success returns the split send/recv ciphers.
pub async fn respond_v2<R, W>(
    reader: &mut R,
    writer: &mut W,
    magic: [u8; 4],
) -> P2pResult<(V2Sender, V2Receiver)>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut transport = V2Transport::new_responder(magic);
    let mut peer_key = [0u8; 64];
    reader
        .read_exact(&mut peer_key)
        .await
        .map_err(|e| P2pError::Connection(format!("v2 read peer key: {e}")))?;
    // Send our key (zero garbage) only after deriving, so we keep ordering simple.
    let keys = transport
        .take_keys(&peer_key)
        .ok_or_else(|| P2pError::Protocol("v2 ECDH/key derivation failed".into()))?;
    writer
        .write_all(transport.our_pubkey())
        .await
        .map_err(|e| P2pError::Connection(format!("v2 send key: {e}")))?;
    writer
        .flush()
        .await
        .map_err(|e| P2pError::Connection(format!("v2 flush: {e}")))?;
    finish_v2(keys, reader, writer).await
}

/// Shared tail of both handshake roles: send terminator + version packet, then
/// read the peer's garbage terminator + version packet, then split the ciphers.
async fn finish_v2<R, W>(
    mut keys: crate::v2_transport::V2SessionKeys,
    reader: &mut R,
    writer: &mut W,
) -> P2pResult<(V2Sender, V2Receiver)>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    // Our garbage is empty, so the version packet's AAD is empty.
    writer
        .write_all(&keys.send_garbage_terminator)
        .await
        .map_err(|e| P2pError::Connection(format!("v2 send term: {e}")))?;
    let version_pkt = keys.encrypt_packet(&[], &[], false);
    writer
        .write_all(&version_pkt)
        .await
        .map_err(|e| P2pError::Connection(format!("v2 send version: {e}")))?;
    writer
        .flush()
        .await
        .map_err(|e| P2pError::Connection(format!("v2 flush: {e}")))?;

    // Scan for the peer's garbage terminator, capturing the garbage (AAD for
    // the peer's first packet).
    let peer_garbage = read_until_terminator(reader, &keys.recv_garbage_terminator).await?;

    // Read packets until the first non-decoy (the version packet). The first
    // packet received carries the garbage AAD.
    let mut aad: &[u8] = &peer_garbage;
    loop {
        let mut enc_len = [0u8; LENGTH_FIELD_LEN];
        reader
            .read_exact(&mut enc_len)
            .await
            .map_err(|e| P2pError::Connection(format!("v2 hs read len: {e}")))?;
        let contents_len = keys.decrypt_packet_len(&enc_len);
        if contents_len > MAX_V2_CONTENTS {
            return Err(P2pError::Protocol("v2 hs packet too large".into()));
        }
        let total = contents_len + HEADER_LEN + AEAD_TAG_LEN;
        let mut body = vec![0u8; total];
        reader
            .read_exact(&mut body)
            .await
            .map_err(|e| P2pError::Connection(format!("v2 hs read body: {e}")))?;
        let (ignore, _contents) = keys
            .decrypt_packet(&body, aad)
            .ok_or_else(|| P2pError::Protocol("v2 hs auth failed".into()))?;
        aad = &[];
        if !ignore {
            break; // version packet — handshake complete
        }
    }

    Ok(keys.into_halves())
}

/// Read bytes until the 16-byte garbage terminator is seen, returning the
/// garbage bytes that preceded it (at most [`MAX_GARBAGE_LEN`]).
async fn read_until_terminator<R: AsyncRead + Unpin>(
    reader: &mut R,
    terminator: &[u8; GARBAGE_TERM_LEN],
) -> P2pResult<Vec<u8>> {
    let mut window: Vec<u8> = Vec::with_capacity(MAX_GARBAGE_LEN + GARBAGE_TERM_LEN);
    loop {
        let mut byte = [0u8; 1];
        reader
            .read_exact(&mut byte)
            .await
            .map_err(|e| P2pError::Connection(format!("v2 garbage read: {e}")))?;
        window.push(byte[0]);
        if window.len() >= GARBAGE_TERM_LEN
            && &window[window.len() - GARBAGE_TERM_LEN..] == terminator
        {
            window.truncate(window.len() - GARBAGE_TERM_LEN);
            return Ok(window);
        }
        if window.len() > MAX_GARBAGE_LEN + GARBAGE_TERM_LEN {
            return Err(P2pError::Protocol("v2 garbage terminator not found".into()));
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use bitcoin::p2p::message::NetworkMessage;
    use bitcoin::Network;
    use tokio::io::split;

    fn raw(network: Network, payload: NetworkMessage) -> RawNetworkMessage {
        RawNetworkMessage::new(network.magic(), payload)
    }

    /// Full v2 handshake over an in-memory duplex, then exchange messages in both
    /// directions through the established send/recv transports — exercising the
    /// ellswift exchange, garbage terminator, version packet, cipher split, and
    /// the message↔packet bridge end to end.
    #[tokio::test]
    async fn v2_handshake_and_message_roundtrip() {
        let network = Network::Regtest;
        let magic = network.magic().to_bytes();

        let (a, b) = tokio::io::duplex(1 << 16);
        let (mut ar, mut aw) = split(a);
        let (mut br, mut bw) = split(b);

        let init = tokio::spawn(async move {
            let keys = initiate_v2(&mut ar, &mut aw, magic).await.unwrap();
            (ar, aw, keys)
        });
        let resp = tokio::spawn(async move {
            let keys = respond_v2(&mut br, &mut bw, magic).await.unwrap();
            (br, bw, keys)
        });
        let (mut ar, mut aw, (a_send, a_recv)) = init.await.unwrap();
        let (mut br, mut bw, (b_send, b_recv)) = resp.await.unwrap();

        let mut a_send = SendTransport::V2(a_send);
        let mut a_recv = RecvTransport::V2 {
            recv: a_recv,
            magic,
        };
        let mut b_send = SendTransport::V2(b_send);
        let mut b_recv = RecvTransport::V2 {
            recv: b_recv,
            magic,
        };

        // Initiator -> responder: a short-id message (ping) round-trips.
        let ping = raw(network, NetworkMessage::Ping(0x0123_4567_89ab_cdef));
        a_send.send(&mut aw, &ping).await.unwrap();
        let (got, _) = b_recv.recv(&mut br).await.unwrap();
        assert!(matches!(
            got.payload(),
            NetworkMessage::Ping(0x0123_4567_89ab_cdef)
        ));

        // Responder -> initiator: a full-command message (verack, no short id).
        let verack = raw(network, NetworkMessage::Verack);
        b_send.send(&mut bw, &verack).await.unwrap();
        let (got, _) = a_recv.recv(&mut ar).await.unwrap();
        assert!(matches!(got.payload(), NetworkMessage::Verack));

        // A larger payload (headers-less getheaders carries a locator) to cross
        // a multi-byte length and confirm framing.
        let pong = raw(network, NetworkMessage::Pong(42));
        a_send.send(&mut aw, &pong).await.unwrap();
        let (got, _) = b_recv.recv(&mut br).await.unwrap();
        assert!(matches!(got.payload(), NetworkMessage::Pong(42)));
    }
}
