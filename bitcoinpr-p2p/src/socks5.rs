//! Minimal async SOCKS5 client (RFC 1928 + RFC 1929 user/pass auth).
//!
//! Hand-rolled — like the rest of this crate's networking — to dial peers
//! through a proxy (Tor) without a new dependency. Supports CONNECT to both IP
//! and **domain-name** targets; the latter is what lets a `.onion` host be
//! resolved by Tor rather than locally. The returned stream is a plain
//! `TcpStream`, so it flows unchanged into the existing v1/v2 transport.
//!
//! Optional username/password credentials double as Tor stream isolation: a
//! distinct pair per connection makes Tor build a separate circuit.

use std::net::SocketAddr;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::error::{P2pError, P2pResult};
use crate::netaddr::NetAddr;

/// Proxy settings for outbound dials. Empty by default (direct connections).
#[derive(Clone, Debug, Default)]
pub struct ProxyConfig {
    /// SOCKS5 proxy for IPv4/IPv6 targets (`-proxy`). `None` = connect directly.
    pub ip_proxy: Option<SocketAddr>,
    /// SOCKS5 proxy for `.onion` targets (`-onion`); falls back to `ip_proxy`.
    pub onion_proxy: Option<SocketAddr>,
    /// Randomize SOCKS5 credentials per connection so Tor isolates each dial
    /// onto its own circuit (Core's `-proxyrandomize`, on by default).
    pub randomize_credentials: bool,
}

impl ProxyConfig {
    /// The SOCKS5 proxy to reach `addr`, if one applies. I2P is not proxied
    /// here — it uses the SAM bridge — so it always returns `None`.
    pub fn proxy_for(&self, addr: &NetAddr) -> Option<SocketAddr> {
        match addr {
            NetAddr::Ip(_) => self.ip_proxy,
            NetAddr::OnionV3 { .. } => self.onion_proxy.or(self.ip_proxy),
            NetAddr::I2p { .. } => None,
        }
    }

    /// Whether any SOCKS5 proxy is configured.
    pub fn any(&self) -> bool {
        self.ip_proxy.is_some() || self.onion_proxy.is_some()
    }
}

/// Where a SOCKS5 CONNECT should terminate.
#[derive(Debug, Clone)]
pub enum Socks5Target {
    /// A resolved IP endpoint (proxied IPv4/IPv6 peer).
    Ip(SocketAddr),
    /// A hostname the proxy resolves itself (e.g. a `.onion` address).
    Domain { host: String, port: u16 },
}

impl Socks5Target {
    fn port(&self) -> u16 {
        match self {
            Socks5Target::Ip(sa) => sa.port(),
            Socks5Target::Domain { port, .. } => *port,
        }
    }
}

/// Optional SOCKS5 username/password (RFC 1929). Used for Tor stream isolation.
#[derive(Debug, Clone)]
pub struct Socks5Auth {
    pub username: String,
    pub password: String,
}

const VER: u8 = 0x05;
const CMD_CONNECT: u8 = 0x01;
const METHOD_NONE: u8 = 0x00;
const METHOD_USERPASS: u8 = 0x02;
const METHOD_UNACCEPTABLE: u8 = 0xff;
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;

/// Open a TCP connection to `proxy` and CONNECT it through to `target`.
pub async fn connect(
    proxy: SocketAddr,
    target: &Socks5Target,
    auth: Option<&Socks5Auth>,
) -> P2pResult<TcpStream> {
    let mut stream = TcpStream::connect(proxy)
        .await
        .map_err(|e| P2pError::Connection(format!("connect to SOCKS5 proxy {proxy}: {e}")))?;
    stream.set_nodelay(true).ok();
    handshake(&mut stream, target, auth).await?;
    Ok(stream)
}

/// Drive the SOCKS5 negotiation on an already-open stream (split out so it can
/// be exercised over an in-memory duplex in tests).
pub async fn handshake<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    target: &Socks5Target,
    auth: Option<&Socks5Auth>,
) -> P2pResult<()> {
    // ── Method negotiation ───────────────────────────────────────────────
    let greeting: &[u8] = if auth.is_some() {
        &[VER, 2, METHOD_NONE, METHOD_USERPASS]
    } else {
        &[VER, 1, METHOD_NONE]
    };
    stream
        .write_all(greeting)
        .await
        .map_err(|e| P2pError::Connection(format!("socks5 greeting: {e}")))?;
    stream
        .flush()
        .await
        .map_err(|e| P2pError::Connection(format!("socks5 flush: {e}")))?;

    let mut selected = [0u8; 2];
    stream
        .read_exact(&mut selected)
        .await
        .map_err(|e| P2pError::Connection(format!("socks5 method reply: {e}")))?;
    if selected[0] != VER {
        return Err(P2pError::Protocol(format!(
            "socks5 bad version {:#x}",
            selected[0]
        )));
    }
    match selected[1] {
        METHOD_NONE => {}
        METHOD_USERPASS => {
            let auth = auth.ok_or_else(|| {
                P2pError::Protocol("socks5 proxy demanded auth we didn't offer".into())
            })?;
            userpass_auth(stream, auth).await?;
        }
        METHOD_UNACCEPTABLE => {
            return Err(P2pError::Connection(
                "socks5 proxy rejected all auth methods".into(),
            ));
        }
        other => {
            return Err(P2pError::Protocol(format!(
                "socks5 unexpected method {other:#x}"
            )));
        }
    }

    // ── CONNECT request ──────────────────────────────────────────────────
    let mut req = vec![VER, CMD_CONNECT, 0x00];
    match target {
        Socks5Target::Ip(SocketAddr::V4(a)) => {
            req.push(ATYP_IPV4);
            req.extend_from_slice(&a.ip().octets());
        }
        Socks5Target::Ip(SocketAddr::V6(a)) => {
            req.push(ATYP_IPV6);
            req.extend_from_slice(&a.ip().octets());
        }
        Socks5Target::Domain { host, .. } => {
            let bytes = host.as_bytes();
            if bytes.len() > 255 {
                return Err(P2pError::Protocol("socks5 domain name too long".into()));
            }
            req.push(ATYP_DOMAIN);
            req.push(bytes.len() as u8);
            req.extend_from_slice(bytes);
        }
    }
    req.extend_from_slice(&target.port().to_be_bytes());
    stream
        .write_all(&req)
        .await
        .map_err(|e| P2pError::Connection(format!("socks5 connect request: {e}")))?;
    stream
        .flush()
        .await
        .map_err(|e| P2pError::Connection(format!("socks5 flush: {e}")))?;

    // ── CONNECT reply ────────────────────────────────────────────────────
    let mut head = [0u8; 4];
    stream
        .read_exact(&mut head)
        .await
        .map_err(|e| P2pError::Connection(format!("socks5 connect reply: {e}")))?;
    if head[0] != VER {
        return Err(P2pError::Protocol(format!(
            "socks5 bad reply version {:#x}",
            head[0]
        )));
    }
    if head[1] != 0x00 {
        return Err(P2pError::Connection(format!(
            "socks5 connect failed: {}",
            reply_error(head[1])
        )));
    }
    // Drain the bound-address field (its length depends on ATYP).
    let bnd_len = match head[3] {
        ATYP_IPV4 => 4,
        ATYP_IPV6 => 16,
        ATYP_DOMAIN => {
            let mut len = [0u8; 1];
            stream
                .read_exact(&mut len)
                .await
                .map_err(|e| P2pError::Connection(format!("socks5 bnd len: {e}")))?;
            len[0] as usize
        }
        other => {
            return Err(P2pError::Protocol(format!(
                "socks5 bad reply atyp {other:#x}"
            )));
        }
    };
    let mut discard = vec![0u8; bnd_len + 2]; // address + port
    stream
        .read_exact(&mut discard)
        .await
        .map_err(|e| P2pError::Connection(format!("socks5 bnd addr: {e}")))?;
    Ok(())
}

async fn userpass_auth<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    auth: &Socks5Auth,
) -> P2pResult<()> {
    let u = auth.username.as_bytes();
    let p = auth.password.as_bytes();
    if u.len() > 255 || p.len() > 255 {
        return Err(P2pError::Protocol("socks5 credential too long".into()));
    }
    let mut msg = vec![0x01]; // RFC 1929 sub-negotiation version
    msg.push(u.len() as u8);
    msg.extend_from_slice(u);
    msg.push(p.len() as u8);
    msg.extend_from_slice(p);
    stream
        .write_all(&msg)
        .await
        .map_err(|e| P2pError::Connection(format!("socks5 auth: {e}")))?;
    stream
        .flush()
        .await
        .map_err(|e| P2pError::Connection(format!("socks5 flush: {e}")))?;
    let mut reply = [0u8; 2];
    stream
        .read_exact(&mut reply)
        .await
        .map_err(|e| P2pError::Connection(format!("socks5 auth reply: {e}")))?;
    if reply[1] != 0x00 {
        return Err(P2pError::Connection("socks5 auth rejected".into()));
    }
    Ok(())
}

fn reply_error(code: u8) -> &'static str {
    match code {
        0x01 => "general SOCKS server failure",
        0x02 => "connection not allowed by ruleset",
        0x03 => "network unreachable",
        0x04 => "host unreachable",
        0x05 => "connection refused",
        0x06 => "TTL expired",
        0x07 => "command not supported",
        0x08 => "address type not supported",
        _ => "unknown error",
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// Minimal fake SOCKS5 server that validates the client's framing for a
    /// no-auth CONNECT to a domain, then reports success with an IPv4 bound
    /// address. Returns the CONNECT request bytes it observed.
    async fn fake_server_domain<S: AsyncRead + AsyncWrite + Unpin>(server: &mut S) -> Vec<u8> {
        // Greeting.
        let mut greeting = [0u8; 3];
        server.read_exact(&mut greeting).await.unwrap();
        assert_eq!(greeting, [VER, 1, METHOD_NONE]);
        server.write_all(&[VER, METHOD_NONE]).await.unwrap();
        // Request header + atyp.
        let mut head = [0u8; 4];
        server.read_exact(&mut head).await.unwrap();
        assert_eq!(&head[..3], &[VER, CMD_CONNECT, 0x00]);
        assert_eq!(head[3], ATYP_DOMAIN);
        let mut len = [0u8; 1];
        server.read_exact(&mut len).await.unwrap();
        let mut rest = vec![0u8; len[0] as usize + 2];
        server.read_exact(&mut rest).await.unwrap();
        // Success reply with a 0.0.0.0:0 bound address.
        server
            .write_all(&[VER, 0x00, 0x00, ATYP_IPV4, 0, 0, 0, 0, 0, 0])
            .await
            .unwrap();
        rest
    }

    #[tokio::test]
    async fn connect_domain_roundtrip() {
        let (mut client, mut server) = tokio::io::duplex(1024);
        let target = Socks5Target::Domain {
            host: "example56onion.onion".to_string(),
            port: 8333,
        };
        let srv = tokio::spawn(async move { fake_server_domain(&mut server).await });
        handshake(&mut client, &target, None).await.unwrap();
        let observed = srv.await.unwrap();
        // host bytes then big-endian port.
        assert_eq!(&observed[..observed.len() - 2], b"example56onion.onion");
        assert_eq!(&observed[observed.len() - 2..], &8333u16.to_be_bytes());
    }

    #[tokio::test]
    async fn connect_reports_proxy_failure() {
        let (mut client, mut server) = tokio::io::duplex(1024);
        let target = Socks5Target::Ip("1.2.3.4:8333".parse().unwrap());
        tokio::spawn(async move {
            let mut greeting = [0u8; 3];
            server.read_exact(&mut greeting).await.unwrap();
            server.write_all(&[VER, METHOD_NONE]).await.unwrap();
            let mut req = [0u8; 10]; // ver..atyp + 4 ipv4 + 2 port
            server.read_exact(&mut req).await.unwrap();
            // Host-unreachable failure.
            server
                .write_all(&[VER, 0x04, 0x00, ATYP_IPV4, 0, 0, 0, 0, 0, 0])
                .await
                .unwrap();
        });
        let err = handshake(&mut client, &target, None).await.unwrap_err();
        assert!(err.to_string().contains("host unreachable"), "{err}");
    }

    #[tokio::test]
    async fn userpass_auth_negotiation() {
        let (mut client, mut server) = tokio::io::duplex(1024);
        let target = Socks5Target::Ip("1.2.3.4:8333".parse().unwrap());
        let auth = Socks5Auth {
            username: "iso".into(),
            password: "lation".into(),
        };
        tokio::spawn(async move {
            let mut greeting = [0u8; 4];
            server.read_exact(&mut greeting).await.unwrap();
            assert_eq!(greeting, [VER, 2, METHOD_NONE, METHOD_USERPASS]);
            server.write_all(&[VER, METHOD_USERPASS]).await.unwrap();
            // user/pass sub-negotiation.
            let mut ver = [0u8; 1];
            server.read_exact(&mut ver).await.unwrap();
            assert_eq!(ver[0], 0x01);
            let mut ul = [0u8; 1];
            server.read_exact(&mut ul).await.unwrap();
            let mut user = vec![0u8; ul[0] as usize];
            server.read_exact(&mut user).await.unwrap();
            assert_eq!(&user, b"iso");
            let mut pl = [0u8; 1];
            server.read_exact(&mut pl).await.unwrap();
            let mut pass = vec![0u8; pl[0] as usize];
            server.read_exact(&mut pass).await.unwrap();
            assert_eq!(&pass, b"lation");
            server.write_all(&[0x01, 0x00]).await.unwrap(); // auth OK
            let mut req = [0u8; 10];
            server.read_exact(&mut req).await.unwrap();
            server
                .write_all(&[VER, 0x00, 0x00, ATYP_IPV4, 0, 0, 0, 0, 0, 0])
                .await
                .unwrap();
        });
        handshake(&mut client, &target, Some(&auth)).await.unwrap();
    }
}
