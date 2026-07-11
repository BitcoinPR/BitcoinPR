//! Tor control-port client — establishes a v3 `.onion` hidden service.
//!
//! Talks the Tor control protocol to `ADD_ONION` an ephemeral ed25519-v3 hidden
//! service that forwards inbound connections to our local P2P listener, so the
//! node is reachable over Tor without the operator hand-editing `torrc`. The
//! private key is persisted so the `.onion` is stable across restarts.
//!
//! The ephemeral service lives only as long as the control connection, so the
//! returned [`HiddenService`] holds that connection open for the node's
//! lifetime (dropping it tears the service down).
//!
//! Auth methods, in preference order: HASHEDPASSWORD (`-torpassword`),
//! SAFECOOKIE (HMAC challenge over the cookie file), COOKIE, then NULL.

use std::net::SocketAddr;
use std::path::PathBuf;

use bitcoin::hashes::{sha256, Hash, HashEngine, Hmac, HmacEngine};
use rand::RngCore;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::tcp::OwnedReadHalf;
use tokio::net::TcpStream;
use tracing::{debug, info, warn};

use crate::error::{P2pError, P2pResult};
use crate::netaddr::NetAddr;

/// Settings for establishing the hidden service.
pub struct TorConfig {
    /// Tor control port (`-torcontrol`, default 127.0.0.1:9051).
    pub control_addr: SocketAddr,
    /// Control-port password (`-torpassword`); enables HASHEDPASSWORD auth.
    pub password: Option<String>,
    /// The port the `.onion` advertises (peers dial `<onion>:virtual_port`).
    pub virtual_port: u16,
    /// Our local P2P listener port that Tor forwards inbound streams to.
    pub target_port: u16,
    /// Where the persisted ED25519-V3 private key lives (`<net_dir>/onion_v3_key`).
    pub key_path: PathBuf,
}

/// A live hidden service. Holds the control connection open (via the keepalive
/// task) so the ephemeral onion service is not torn down.
pub struct HiddenService {
    /// Our `.onion` address, ready to advertise via `addrv2`.
    pub onion: NetAddr,
    keepalive: tokio::task::JoinHandle<()>,
}

impl Drop for HiddenService {
    fn drop(&mut self) {
        self.keepalive.abort();
    }
}

/// Connect to the Tor control port, authenticate, and create (or restore) a v3
/// hidden service forwarding to our local listener.
pub async fn create_hidden_service(cfg: &TorConfig) -> P2pResult<HiddenService> {
    let stream = TcpStream::connect(cfg.control_addr).await.map_err(|e| {
        P2pError::Connection(format!("connect to Tor control {}: {e}", cfg.control_addr))
    })?;
    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);

    authenticate(&mut reader, &mut write_half, cfg).await?;
    let onion = add_onion(&mut reader, &mut write_half, cfg).await?;
    info!(onion = %onion, "Tor hidden service established");

    // Keep the control connection open for the service's lifetime; reading
    // drains any async control events and detects the connection closing.
    let keepalive = tokio::spawn(async move {
        let _write_half = write_half; // held open until the task ends
        let mut buf = [0u8; 256];
        loop {
            match reader.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            }
        }
        debug!("Tor control connection closed");
    });

    Ok(HiddenService { onion, keepalive })
}

async fn authenticate(
    reader: &mut BufReader<OwnedReadHalf>,
    writer: &mut (impl AsyncWriteExt + Unpin),
    cfg: &TorConfig,
) -> P2pResult<()> {
    send_line(writer, "PROTOCOLINFO 1").await?;
    let reply = read_reply(reader).await?;
    let (methods, cookie_file) = parse_protocolinfo(&reply);

    if cfg.password.is_some() && methods.iter().any(|m| m == "HASHEDPASSWORD") {
        let pw = cfg.password.as_deref().unwrap_or_default();
        send_line(writer, &format!("AUTHENTICATE \"{}\"", escape_pw(pw))).await?;
    } else if methods.iter().any(|m| m == "SAFECOOKIE") {
        safecookie_auth(reader, writer, cookie_file.as_deref()).await?;
    } else if methods.iter().any(|m| m == "COOKIE") {
        let cookie = read_cookie(cookie_file.as_deref())?;
        send_line(writer, &format!("AUTHENTICATE {}", hex::encode(cookie))).await?;
    } else if methods.iter().any(|m| m == "NULL") {
        send_line(writer, "AUTHENTICATE").await?;
    } else {
        return Err(P2pError::Connection(format!(
            "no supported Tor auth method (offered: {methods:?})"
        )));
    }
    read_reply(reader).await?; // 250 OK or error
    Ok(())
}

async fn safecookie_auth(
    reader: &mut BufReader<OwnedReadHalf>,
    writer: &mut (impl AsyncWriteExt + Unpin),
    cookie_file: Option<&str>,
) -> P2pResult<()> {
    let cookie = read_cookie(cookie_file)?;
    let mut client_nonce = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut client_nonce);

    send_line(
        writer,
        &format!("AUTHCHALLENGE SAFECOOKIE {}", hex::encode(client_nonce)),
    )
    .await?;
    let reply = read_reply(reader).await?;
    let line = reply
        .iter()
        .find(|l| l.contains("SERVERHASH="))
        .ok_or_else(|| P2pError::Connection("Tor AUTHCHALLENGE missing SERVERHASH".into()))?;
    let server_hash = hex::decode(kv(line, "SERVERHASH=").unwrap_or_default())
        .map_err(|_| P2pError::Connection("bad Tor SERVERHASH".into()))?;
    let server_nonce = hex::decode(kv(line, "SERVERNONCE=").unwrap_or_default())
        .map_err(|_| P2pError::Connection("bad Tor SERVERNONCE".into()))?;

    // msg = cookie || client_nonce || server_nonce
    let mut msg = Vec::with_capacity(cookie.len() + 64);
    msg.extend_from_slice(&cookie);
    msg.extend_from_slice(&client_nonce);
    msg.extend_from_slice(&server_nonce);

    let expected = hmac_sha256(
        b"Tor safe cookie authentication server-to-controller hash",
        &msg,
    );
    if server_hash != expected {
        return Err(P2pError::Connection(
            "Tor SERVERHASH mismatch (control auth failed)".into(),
        ));
    }
    let client_hash = hmac_sha256(
        b"Tor safe cookie authentication controller-to-server hash",
        &msg,
    );
    send_line(
        writer,
        &format!("AUTHENTICATE {}", hex::encode(client_hash)),
    )
    .await?;
    Ok(())
}

async fn add_onion(
    reader: &mut BufReader<OwnedReadHalf>,
    writer: &mut (impl AsyncWriteExt + Unpin),
    cfg: &TorConfig,
) -> P2pResult<NetAddr> {
    // Reuse a persisted key for a stable .onion, else create a fresh one.
    let key_arg = match std::fs::read_to_string(&cfg.key_path) {
        Ok(k) if !k.trim().is_empty() => k.trim().to_string(),
        _ => "NEW:ED25519-V3".to_string(),
    };
    let cmd = format!(
        "ADD_ONION {key_arg} Port={},127.0.0.1:{}",
        cfg.virtual_port, cfg.target_port
    );
    send_line(writer, &cmd).await?;
    let reply = read_reply(reader).await?;

    let service_id = reply
        .iter()
        .find_map(|l| kv(l, "ServiceID="))
        .ok_or_else(|| P2pError::Connection("Tor ADD_ONION missing ServiceID".into()))?;
    // Persist a freshly-generated key so the address is stable next time.
    if let Some(pk) = reply.iter().find_map(|l| kv(l, "PrivateKey=")) {
        if let Err(e) = write_key(&cfg.key_path, &pk) {
            warn!("Failed to persist Tor onion key ({e}); .onion will change on restart");
        }
    }

    NetAddr::parse(&format!("{service_id}.onion"), cfg.virtual_port)
        .ok_or_else(|| P2pError::Connection(format!("Tor returned invalid ServiceID {service_id}")))
}

// ── control-protocol helpers ─────────────────────────────────────────────────

async fn send_line(writer: &mut (impl AsyncWriteExt + Unpin), line: &str) -> P2pResult<()> {
    writer
        .write_all(format!("{line}\r\n").as_bytes())
        .await
        .map_err(|e| P2pError::Connection(format!("Tor control write: {e}")))?;
    writer
        .flush()
        .await
        .map_err(|e| P2pError::Connection(format!("Tor control flush: {e}")))
}

/// Read one (possibly multi-line) control reply. Lines look like `250-Key=Val`
/// (continuation) or `250 OK` (final). Returns the text after the code/sep of
/// every line; errors if the final code is not 2xx.
async fn read_reply(reader: &mut BufReader<OwnedReadHalf>) -> P2pResult<Vec<String>> {
    let mut lines = Vec::new();
    loop {
        let mut line = String::new();
        let n = reader
            .read_line(&mut line)
            .await
            .map_err(|e| P2pError::Connection(format!("Tor control read: {e}")))?;
        if n == 0 {
            return Err(P2pError::Connection("Tor control connection closed".into()));
        }
        let line = line.trim_end_matches(['\r', '\n']).to_string();
        if line.len() < 4 {
            return Err(P2pError::Connection(format!(
                "short Tor control reply: {line}"
            )));
        }
        let code = &line[..3];
        let sep = line.as_bytes()[3];
        lines.push(line[4..].to_string());
        if sep == b' ' {
            if !code.starts_with('2') {
                return Err(P2pError::Connection(format!(
                    "Tor control error {code}: {line}"
                )));
            }
            break;
        }
    }
    Ok(lines)
}

/// Extract `AUTH METHODS=...` (comma list) and `COOKIEFILE="..."` from a
/// PROTOCOLINFO reply.
fn parse_protocolinfo(reply: &[String]) -> (Vec<String>, Option<String>) {
    let mut methods = Vec::new();
    let mut cookie_file = None;
    for line in reply {
        if let Some(rest) = line.strip_prefix("AUTH ") {
            if let Some(m) = kv(rest, "METHODS=") {
                methods = m.split(',').map(|s| s.trim().to_string()).collect();
            }
            if let Some(cf) = kv(rest, "COOKIEFILE=") {
                cookie_file = Some(cf.trim_matches('"').to_string());
            }
        }
    }
    (methods, cookie_file)
}

/// Value of a `Key=Value` token, honouring an optional double-quoted value.
fn kv(haystack: &str, key: &str) -> Option<String> {
    let start = haystack.find(key)? + key.len();
    let rest = &haystack[start..];
    if let Some(inner) = rest.strip_prefix('"') {
        // Quoted: up to the next unescaped quote.
        let end = inner.find('"').unwrap_or(inner.len());
        Some(inner[..end].to_string())
    } else {
        Some(rest.split_whitespace().next().unwrap_or("").to_string())
    }
}

fn read_cookie(path: Option<&str>) -> P2pResult<Vec<u8>> {
    let path = path.ok_or_else(|| P2pError::Connection("Tor cookie file not provided".into()))?;
    std::fs::read(path).map_err(|e| P2pError::Connection(format!("read Tor cookie {path}: {e}")))
}

fn hmac_sha256(key: &[u8], msg: &[u8]) -> Vec<u8> {
    let mut eng = HmacEngine::<sha256::Hash>::new(key);
    eng.input(msg);
    Hmac::<sha256::Hash>::from_engine(eng)
        .to_byte_array()
        .to_vec()
}

fn escape_pw(pw: &str) -> String {
    pw.replace('\\', "\\\\").replace('"', "\\\"")
}

/// Persist the onion private key with owner-only permissions.
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
    fn hmac_sha256_rfc4231_case2() {
        // RFC 4231 test case 2: key="Jefe", data="what do ya want for nothing?"
        let mac = hmac_sha256(b"Jefe", b"what do ya want for nothing?");
        assert_eq!(
            hex::encode(mac),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    #[test]
    fn parse_protocolinfo_methods_and_cookie() {
        let reply = vec![
            "PROTOCOLINFO 1".to_string(),
            "AUTH METHODS=COOKIE,SAFECOOKIE COOKIEFILE=\"/run/tor/control.authcookie\"".to_string(),
            "VERSION Tor=\"0.4.8.10\"".to_string(),
            "OK".to_string(),
        ];
        let (methods, cookie) = parse_protocolinfo(&reply);
        assert_eq!(methods, vec!["COOKIE", "SAFECOOKIE"]);
        assert_eq!(cookie.as_deref(), Some("/run/tor/control.authcookie"));
    }

    #[test]
    fn kv_extracts_add_onion_fields() {
        assert_eq!(
            kv("ServiceID=abcdefgh234567", "ServiceID=").as_deref(),
            Some("abcdefgh234567")
        );
        assert_eq!(
            kv("PrivateKey=ED25519-V3:deadBEEF==", "PrivateKey=").as_deref(),
            Some("ED25519-V3:deadBEEF==")
        );
    }
}
