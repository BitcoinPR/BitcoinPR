//! I2P transport via the SAM v3 bridge.
//!
//! Speaks the SAM (Simple Anonymous Messaging) v3.3 protocol to a local I2P
//! router (i2pd / Java I2P) so the node can reach and be reached by other nodes
//! over I2P, with no clearnet exposure. Mirrors the Tor design: a long-lived
//! control connection holds the STREAM session open, outbound dials open a
//! fresh SAM socket per connection (`STREAM CONNECT`), and an accept loop
//! (`STREAM ACCEPT`) yields inbound peers. The session's private destination is
//! persisted so the node keeps a stable `.b32.i2p` address across restarts.
//!
//! The data stream SAM hands back after a successful CONNECT/ACCEPT is an
//! ordinary `TcpStream`, so it feeds the existing v1/v2 transport unchanged.

use std::net::SocketAddr;
use std::path::PathBuf;

use bitcoin::hashes::{sha256, Hash};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::tcp::OwnedReadHalf;
use tokio::net::TcpStream;
use tracing::{debug, info};

use crate::error::{P2pError, P2pResult};
use crate::netaddr::NetAddr;

/// Settings for the SAM session.
pub struct I2pConfig {
    /// SAM bridge address (`-i2psam`, default 127.0.0.1:7656).
    pub sam_addr: SocketAddr,
    /// Where the persisted I2P private destination lives
    /// (`<net_dir>/i2p_private_key`).
    pub key_path: PathBuf,
}

/// A live SAM STREAM session. Holds the control connection open (keepalive task)
/// so the session — and our destination — persists for the node's lifetime.
pub struct I2pSession {
    session_id: String,
    sam_addr: SocketAddr,
    /// Our own `.b32.i2p` address, ready to advertise via `addrv2`.
    pub my_addr: NetAddr,
    keepalive: tokio::task::JoinHandle<()>,
}

impl Drop for I2pSession {
    fn drop(&mut self) {
        self.keepalive.abort();
    }
}

/// SAM protocol version we negotiate.
const SAM_MIN: &str = "3.1";
const SAM_MAX: &str = "3.3";

/// Open a SAM control connection, perform the HELLO handshake, and create (or
/// restore) a STREAM session. The returned session can dial and accept peers.
pub async fn create_session(cfg: &I2pConfig) -> P2pResult<I2pSession> {
    let session_id = format!("bitcoinpr-{:08x}", rand::random::<u32>());
    let (mut reader, mut writer) = sam_hello(cfg.sam_addr).await?;

    // Reuse a persisted destination for a stable .b32.i2p, else ask for a new
    // transient one (SAM returns the freshly-generated private key).
    let dest_arg = match std::fs::read_to_string(&cfg.key_path) {
        Ok(k) if !k.trim().is_empty() => k.trim().to_string(),
        _ => "TRANSIENT".to_string(),
    };
    send_line(
        &mut writer,
        &format!("SESSION CREATE STYLE=STREAM ID={session_id} DESTINATION={dest_arg}"),
    )
    .await?;
    let reply = read_line(&mut reader).await?;
    expect_ok(&reply, "SESSION STATUS")?;
    // The reply's DESTINATION is our private key; persist it for next time.
    if let Some(priv_key) = kv(&reply, "DESTINATION=") {
        if dest_arg == "TRANSIENT" {
            if let Err(e) = write_key(&cfg.key_path, &priv_key) {
                debug!("Failed to persist I2P key ({e}); .b32.i2p will change on restart");
            }
        }
    }

    // Resolve our own public destination to compute the .b32.i2p address.
    send_line(&mut writer, "NAMING LOOKUP NAME=ME").await?;
    let naming = read_line(&mut reader).await?;
    expect_ok(&naming, "NAMING REPLY")?;
    let my_dest = kv(&naming, "VALUE=")
        .ok_or_else(|| P2pError::Connection("SAM NAMING REPLY missing VALUE".into()))?;
    let my_addr = dest_to_netaddr(&my_dest)?;
    info!(i2p = %my_addr, "I2P SAM session established");

    // Hold the control connection (and thus the session) open for our lifetime.
    let keepalive = tokio::spawn(async move {
        let _writer = writer;
        let mut buf = [0u8; 256];
        loop {
            match reader.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            }
        }
        debug!("I2P SAM control connection closed");
    });

    Ok(I2pSession {
        session_id,
        sam_addr: cfg.sam_addr,
        my_addr,
        keepalive,
    })
}

impl I2pSession {
    /// Dial an I2P peer via `STREAM CONNECT`. On success the SAM socket becomes
    /// the raw data stream to the peer.
    pub async fn connect_peer(&self, peer: &NetAddr) -> P2pResult<TcpStream> {
        let host = peer
            .i2p_host()
            .ok_or_else(|| P2pError::Connection("not an I2P address".into()))?;
        let (mut reader, mut writer) = sam_hello(self.sam_addr).await?;
        send_line(
            &mut writer,
            &format!(
                "STREAM CONNECT ID={} DESTINATION={host} SILENT=false",
                self.session_id
            ),
        )
        .await?;
        let reply = read_line(&mut reader).await?;
        expect_ok(&reply, "STREAM STATUS")?;
        Ok(reunite(reader, writer))
    }

    /// Wait for an inbound I2P peer via `STREAM ACCEPT`. Returns the data stream
    /// and the peer's `.b32.i2p` address. Each call handles one connection, so
    /// callers loop to keep accepting.
    pub async fn accept(&self) -> P2pResult<(TcpStream, NetAddr)> {
        let (mut reader, mut writer) = sam_hello(self.sam_addr).await?;
        send_line(
            &mut writer,
            &format!("STREAM ACCEPT ID={} SILENT=false", self.session_id),
        )
        .await?;
        // First reply: STREAM STATUS RESULT=OK. Then, on connect, SAM sends a
        // line with the peer's full destination before the data begins.
        let status = read_line(&mut reader).await?;
        expect_ok(&status, "STREAM STATUS")?;
        let peer_line = read_line(&mut reader).await?;
        // The destination is the first whitespace-delimited token.
        let peer_dest = peer_line
            .split_whitespace()
            .next()
            .ok_or_else(|| P2pError::Connection("SAM accept: empty peer line".into()))?;
        let peer_addr = dest_to_netaddr(peer_dest)?;
        Ok((reunite(reader, writer), peer_addr))
    }
}

// ── SAM helpers ──────────────────────────────────────────────────────────────

/// Connect to the SAM bridge and complete the HELLO version handshake.
async fn sam_hello(
    sam_addr: SocketAddr,
) -> P2pResult<(BufReader<OwnedReadHalf>, tokio::net::tcp::OwnedWriteHalf)> {
    let stream = TcpStream::connect(sam_addr)
        .await
        .map_err(|e| P2pError::Connection(format!("connect to SAM bridge {sam_addr}: {e}")))?;
    stream.set_nodelay(true).ok();
    let (read_half, mut writer) = stream.into_split();
    let mut reader = BufReader::new(read_half);
    send_line(
        &mut writer,
        &format!("HELLO VERSION MIN={SAM_MIN} MAX={SAM_MAX}"),
    )
    .await?;
    let reply = read_line(&mut reader).await?;
    expect_ok(&reply, "HELLO REPLY")?;
    Ok((reader, writer))
}

/// Reunite the split halves back into a single `TcpStream` for the data phase.
fn reunite(reader: BufReader<OwnedReadHalf>, writer: tokio::net::tcp::OwnedWriteHalf) -> TcpStream {
    // The BufReader may hold buffered bytes; SAM sends no data before the
    // stream begins (SILENT=false replies are line-delimited and fully read),
    // so the buffer is empty here and reuniting is lossless.
    let read_half = reader.into_inner();
    read_half
        .reunite(writer)
        .expect("halves are from the same stream")
}

async fn send_line(writer: &mut (impl AsyncWriteExt + Unpin), line: &str) -> P2pResult<()> {
    writer
        .write_all(format!("{line}\n").as_bytes())
        .await
        .map_err(|e| P2pError::Connection(format!("SAM write: {e}")))?;
    writer
        .flush()
        .await
        .map_err(|e| P2pError::Connection(format!("SAM flush: {e}")))
}

async fn read_line(reader: &mut BufReader<OwnedReadHalf>) -> P2pResult<String> {
    let mut line = String::new();
    let n = reader
        .read_line(&mut line)
        .await
        .map_err(|e| P2pError::Connection(format!("SAM read: {e}")))?;
    if n == 0 {
        return Err(P2pError::Connection("SAM connection closed".into()));
    }
    Ok(line.trim_end_matches(['\r', '\n']).to_string())
}

/// Check a SAM reply begins with `prefix` and carries `RESULT=OK`.
fn expect_ok(line: &str, prefix: &str) -> P2pResult<()> {
    if !line.starts_with(prefix) {
        return Err(P2pError::Connection(format!(
            "SAM: expected {prefix}, got: {line}"
        )));
    }
    match kv(line, "RESULT=").as_deref() {
        Some("OK") => Ok(()),
        other => Err(P2pError::Connection(format!(
            "SAM {prefix} failed: RESULT={}",
            other.unwrap_or("<missing>")
        ))),
    }
}

/// Value of a `KEY=VALUE` token (unquoted or double-quoted).
fn kv(haystack: &str, key: &str) -> Option<String> {
    let start = haystack.find(key)? + key.len();
    let rest = &haystack[start..];
    if let Some(inner) = rest.strip_prefix('"') {
        let end = inner.find('"').unwrap_or(inner.len());
        Some(inner[..end].to_string())
    } else {
        Some(rest.split_whitespace().next().unwrap_or("").to_string())
    }
}

/// Convert an I2P destination (base64) into a `NetAddr::I2p` — the 32-byte
/// address is `SHA-256(destination)`, matching the `.b32.i2p` label.
fn dest_to_netaddr(dest_b64: &str) -> P2pResult<NetAddr> {
    let bytes = i2p_base64_decode(dest_b64)
        .ok_or_else(|| P2pError::Connection("invalid I2P destination base64".into()))?;
    let hash = sha256::Hash::hash(&bytes).to_byte_array();
    Ok(NetAddr::I2p { hash, port: 0 })
}

/// I2P's base64 variant (RFC 4648 with `-` and `~` for `+` and `/`).
fn i2p_base64_decode(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let mut buffer: u32 = 0;
    let mut bits = 0u32;
    for c in s.bytes() {
        let val = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'-' => 62,
            b'~' => 63,
            b'=' => break,
            _ => return None,
        } as u32;
        buffer = (buffer << 6) | val;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buffer >> bits) as u8);
        }
    }
    Some(out)
}

fn write_key(path: &std::path::Path, key: &str) -> std::io::Result<()> {
    std::fs::write(path, key)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn i2p_base64_matches_standard_with_alt_chars() {
        // "foobar" → standard base64 "Zm9vYmFy" (no +// so alphabet-equal here).
        assert_eq!(i2p_base64_decode("Zm9vYmFy").unwrap(), b"foobar");
        // Bytes that exercise the 62/63 slots: standard '+'/'/' map to '-'/'~'.
        // 0xFB 0xFF 0xBF → standard "+/+/"? verify round trip via known vector:
        // base64("\xff\xef\xbf") = "/++/"→ i2p "~--~".
        assert_eq!(i2p_base64_decode("~--~").unwrap(), vec![0xff, 0xef, 0xbf]);
    }

    #[test]
    fn dest_hash_is_sha256_of_destination() {
        // A tiny fake "destination"; the address hash must be its SHA-256.
        let dest = "Zm9vYmFy"; // "foobar"
        let na = dest_to_netaddr(dest).unwrap();
        let expected = sha256::Hash::hash(b"foobar").to_byte_array();
        match na {
            NetAddr::I2p { hash, port } => {
                assert_eq!(hash, expected);
                assert_eq!(port, 0);
            }
            _ => panic!("expected I2p"),
        }
    }

    #[test]
    fn kv_and_expect_ok() {
        let line = "STREAM STATUS RESULT=OK MESSAGE=\"all good\"";
        assert!(expect_ok(line, "STREAM STATUS").is_ok());
        assert_eq!(kv(line, "MESSAGE=").as_deref(), Some("all good"));
        let bad = "STREAM STATUS RESULT=CANT_REACH_PEER";
        assert!(expect_ok(bad, "STREAM STATUS").is_err());
    }
}
