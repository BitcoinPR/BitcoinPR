//! Network-aware peer address type.
//!
//! The rest of the crate historically spoke only `std::net::SocketAddr`, which
//! can represent IPv4/IPv6 but *cannot* hold a Tor `.onion` or I2P `.b32.i2p`
//! address. [`NetAddr`] supersedes `SocketAddr` as the address currency so the
//! address book, dialer, and gossip can carry onion/I2P peers alongside IP ones.
//!
//! Wire encoding rides on `bitcoin::p2p::address::AddrV2` (BIP155); this module
//! only adds the pieces the `bitcoin` crate doesn't: the `.onion` v3 checksum
//! (SHA3-256), and RFC 4648 base32 for the `.onion` / `.b32.i2p` host strings.

use std::fmt;
use std::net::{IpAddr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::str::FromStr;

use bitcoin::p2p::address::AddrV2;
use serde::{Deserialize, Serialize};

/// A peer address across every network BitcoinPR can reach.
///
/// `Copy` so it drops into the many call sites that copy a `SocketAddr`
/// (`*addr`, `HashSet::insert`, …) without churn. IP addresses behave exactly as
/// before; onion/I2P are new variants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum NetAddr {
    /// IPv4 or IPv6 (unchanged behaviour from the old `SocketAddr` world).
    Ip(SocketAddr),
    /// Tor v3 hidden service: 32-byte ed25519 public key + port.
    OnionV3 { pubkey: [u8; 32], port: u16 },
    /// I2P destination: 32-byte SHA-256 of the destination (the `.b32.i2p`
    /// label) + port (conventionally 0).
    I2p { hash: [u8; 32], port: u16 },
}

/// The reachable-network class of an address, used by `-onlynet`, the RPC
/// `getnetworkinfo` `networks` array, and diversity bucketing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AddrNetwork {
    Ipv4,
    Ipv6,
    Onion,
    I2p,
}

impl AddrNetwork {
    /// Lower-case network name as used by Bitcoin Core RPC / `-onlynet`.
    pub fn as_str(self) -> &'static str {
        match self {
            AddrNetwork::Ipv4 => "ipv4",
            AddrNetwork::Ipv6 => "ipv6",
            AddrNetwork::Onion => "onion",
            AddrNetwork::I2p => "i2p",
        }
    }
}

impl FromStr for AddrNetwork {
    type Err = ();
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "ipv4" => Ok(AddrNetwork::Ipv4),
            "ipv6" => Ok(AddrNetwork::Ipv6),
            "onion" | "tor" => Ok(AddrNetwork::Onion),
            "i2p" => Ok(AddrNetwork::I2p),
            _ => Err(()),
        }
    }
}

impl NetAddr {
    /// The network class of this address.
    pub fn network(&self) -> AddrNetwork {
        match self {
            NetAddr::Ip(SocketAddr::V4(_)) => AddrNetwork::Ipv4,
            NetAddr::Ip(SocketAddr::V6(_)) => AddrNetwork::Ipv6,
            NetAddr::OnionV3 { .. } => AddrNetwork::Onion,
            NetAddr::I2p { .. } => AddrNetwork::I2p,
        }
    }

    /// TCP/logical port.
    pub fn port(&self) -> u16 {
        match self {
            NetAddr::Ip(sa) => sa.port(),
            NetAddr::OnionV3 { port, .. } | NetAddr::I2p { port, .. } => *port,
        }
    }

    /// `true` for IPv4/IPv6 addresses.
    pub fn is_ip(&self) -> bool {
        matches!(self, NetAddr::Ip(_))
    }

    /// The underlying `SocketAddr` for IP addresses; `None` for onion/I2P.
    pub fn to_socket_addr(&self) -> Option<SocketAddr> {
        match self {
            NetAddr::Ip(sa) => Some(*sa),
            _ => None,
        }
    }

    /// The underlying `IpAddr` for IP addresses; `None` for onion/I2P. Used by
    /// ban/self/subnet gates that only apply to IP peers.
    pub fn ip(&self) -> Option<IpAddr> {
        self.to_socket_addr().map(|sa| sa.ip())
    }

    /// The `.onion` hostname (`<56 base32>.onion`) for an onion address.
    pub fn onion_host(&self) -> Option<String> {
        match self {
            NetAddr::OnionV3 { pubkey, .. } => Some(encode_onion_v3(pubkey)),
            _ => None,
        }
    }

    /// The `.b32.i2p` hostname for an I2P address.
    pub fn i2p_host(&self) -> Option<String> {
        match self {
            NetAddr::I2p { hash, .. } => Some(format!("{}.b32.i2p", base32_encode(hash))),
            _ => None,
        }
    }

    /// BIP155 wire representation: `(addr, port)`.
    pub fn to_addr_v2(&self) -> (AddrV2, u16) {
        match self {
            NetAddr::Ip(SocketAddr::V4(sa)) => (AddrV2::Ipv4(*sa.ip()), sa.port()),
            NetAddr::Ip(SocketAddr::V6(sa)) => (AddrV2::Ipv6(*sa.ip()), sa.port()),
            NetAddr::OnionV3 { pubkey, port } => (AddrV2::TorV3(*pubkey), *port),
            NetAddr::I2p { hash, port } => (AddrV2::I2p(*hash), *port),
        }
    }

    /// Build from a BIP155 `AddrV2` + port. Returns `None` for address kinds we
    /// don't route (deprecated TorV2, CJDNS, and unknown families).
    pub fn from_addr_v2(addr: &AddrV2, port: u16) -> Option<NetAddr> {
        match addr {
            AddrV2::Ipv4(ip) => Some(NetAddr::Ip(SocketAddr::V4(SocketAddrV4::new(*ip, port)))),
            AddrV2::Ipv6(ip) => Some(NetAddr::Ip(SocketAddr::V6(SocketAddrV6::new(
                *ip, port, 0, 0,
            )))),
            AddrV2::TorV3(pubkey) => Some(NetAddr::OnionV3 {
                pubkey: *pubkey,
                port,
            }),
            AddrV2::I2p(hash) => Some(NetAddr::I2p { hash: *hash, port }),
            AddrV2::TorV2(_) | AddrV2::Cjdns(_) | AddrV2::Unknown(..) => None,
        }
    }

    /// Parse a literal address: `ip:port`, `<b32>.onion[:port]`, or
    /// `<b32>.b32.i2p`. Plain DNS hostnames return `None` (the caller resolves
    /// those separately). `default_port` fills in a missing onion/i2p port.
    pub fn parse(s: &str, default_port: u16) -> Option<NetAddr> {
        let s = s.trim();
        let lower = s.to_ascii_lowercase();
        // `.onion` / `.b32.i2p` may carry an explicit `:port` suffix (I2P
        // conventionally `:0`, e.g. in Bitcoin Core's fixed-seed lists).
        let (host, port) = match lower.rsplit_once(':') {
            Some((h, p)) if h.ends_with(".onion") || h.ends_with(".b32.i2p") => {
                (h.to_string(), p.parse().ok()?)
            }
            _ => (lower.clone(), default_port),
        };
        if let Some(rest) = host.strip_suffix(".b32.i2p") {
            let hash = base32_decode(rest)?;
            let hash: [u8; 32] = hash.try_into().ok()?;
            return Some(NetAddr::I2p { hash, port });
        }
        if let Some(label) = host.strip_suffix(".onion") {
            let pubkey = decode_onion_v3(label)?;
            return Some(NetAddr::OnionV3 { pubkey, port });
        }
        // Fall back to an IP literal (`SocketAddr` requires a port).
        s.parse::<SocketAddr>().ok().map(NetAddr::Ip)
    }
}

impl From<SocketAddr> for NetAddr {
    fn from(sa: SocketAddr) -> Self {
        NetAddr::Ip(sa)
    }
}

impl fmt::Display for NetAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NetAddr::Ip(sa) => write!(f, "{sa}"),
            NetAddr::OnionV3 { pubkey, port } => {
                write!(f, "{}.onion:{port}", encode_onion_v3_label(pubkey))
            }
            NetAddr::I2p { hash, .. } => write!(f, "{}.b32.i2p", base32_encode(hash)),
        }
    }
}

// ── Tor v3 onion encoding ────────────────────────────────────────────────────
//
// A v3 onion hostname is `base32(PUBKEY || CHECKSUM || VERSION)` where
// VERSION = 0x03 and CHECKSUM = SHA3_256(".onion checksum" || PUBKEY || VERSION)[..2].

const ONION_VERSION: u8 = 0x03;

/// The 56-character base32 label (no `.onion` suffix).
fn encode_onion_v3_label(pubkey: &[u8; 32]) -> String {
    let mut buf = Vec::with_capacity(35);
    buf.extend_from_slice(pubkey);
    buf.extend_from_slice(&onion_checksum(pubkey));
    buf.push(ONION_VERSION);
    base32_encode(&buf)
}

/// The full `<56 base32>.onion` hostname.
fn encode_onion_v3(pubkey: &[u8; 32]) -> String {
    format!("{}.onion", encode_onion_v3_label(pubkey))
}

/// Decode a 56-character v3 onion label into its 32-byte pubkey, validating the
/// version byte and checksum. Returns `None` on any mismatch.
fn decode_onion_v3(label: &str) -> Option<[u8; 32]> {
    let raw = base32_decode(label)?;
    if raw.len() != 35 || raw[34] != ONION_VERSION {
        return None;
    }
    let mut pubkey = [0u8; 32];
    pubkey.copy_from_slice(&raw[..32]);
    if raw[32..34] != onion_checksum(&pubkey) {
        return None;
    }
    Some(pubkey)
}

fn onion_checksum(pubkey: &[u8; 32]) -> [u8; 2] {
    let mut buf = Vec::with_capacity(15 + 32 + 1);
    buf.extend_from_slice(b".onion checksum");
    buf.extend_from_slice(pubkey);
    buf.push(ONION_VERSION);
    let digest = sha3::sha3_256(&buf);
    [digest[0], digest[1]]
}

// ── RFC 4648 base32 (lower-case, no padding) ─────────────────────────────────

const B32_ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";

fn base32_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(5) * 8);
    let mut buffer: u32 = 0;
    let mut bits = 0u32;
    for &byte in data {
        buffer = (buffer << 8) | byte as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            let idx = ((buffer >> bits) & 0x1f) as usize;
            out.push(B32_ALPHABET[idx] as char);
        }
    }
    if bits > 0 {
        let idx = ((buffer << (5 - bits)) & 0x1f) as usize;
        out.push(B32_ALPHABET[idx] as char);
    }
    out
}

fn base32_decode(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(s.len() * 5 / 8);
    let mut buffer: u32 = 0;
    let mut bits = 0u32;
    for c in s.bytes() {
        let val = match c {
            b'a'..=b'z' => c - b'a',
            b'A'..=b'Z' => c - b'A',
            b'2'..=b'7' => c - b'2' + 26,
            _ => return None,
        } as u32;
        buffer = (buffer << 5) | val;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((buffer >> bits) as u8);
        }
    }
    Some(out)
}

// ── SHA3-256 (Keccak-f[1600]) ────────────────────────────────────────────────
//
// Hand-rolled to avoid a new dependency (the `bitcoin` crate's `hashes` provides
// SHA-2 family only). Used solely for the onion v3 checksum.

mod sha3 {
    const RC: [u64; 24] = [
        0x0000000000000001,
        0x0000000000008082,
        0x800000000000808a,
        0x8000000080008000,
        0x000000000000808b,
        0x0000000080000001,
        0x8000000080008081,
        0x8000000000008009,
        0x000000000000008a,
        0x0000000000000088,
        0x0000000080008009,
        0x000000008000000a,
        0x000000008000808b,
        0x800000000000008b,
        0x8000000000008089,
        0x8000000000008003,
        0x8000000000008002,
        0x8000000000000080,
        0x000000000000800a,
        0x800000008000000a,
        0x8000000080008081,
        0x8000000000008080,
        0x0000000080000001,
        0x8000000080008008,
    ];
    const ROTC: [u32; 24] = [
        1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44,
    ];
    const PILN: [usize; 24] = [
        10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1,
    ];

    fn keccak_f(st: &mut [u64; 25]) {
        for round in RC.iter() {
            // Theta
            let mut bc = [0u64; 5];
            for i in 0..5 {
                bc[i] = st[i] ^ st[i + 5] ^ st[i + 10] ^ st[i + 15] ^ st[i + 20];
            }
            for i in 0..5 {
                let t = bc[(i + 4) % 5] ^ bc[(i + 1) % 5].rotate_left(1);
                for j in (0..25).step_by(5) {
                    st[j + i] ^= t;
                }
            }
            // Rho + Pi
            let mut t = st[1];
            for i in 0..24 {
                let j = PILN[i];
                let prev = st[j];
                st[j] = t.rotate_left(ROTC[i]);
                t = prev;
            }
            // Chi
            for j in (0..25).step_by(5) {
                let row = [st[j], st[j + 1], st[j + 2], st[j + 3], st[j + 4]];
                for i in 0..5 {
                    st[j + i] ^= (!row[(i + 1) % 5]) & row[(i + 2) % 5];
                }
            }
            // Iota
            st[0] ^= *round;
        }
    }

    const RATE: usize = 136; // 1088-bit rate for SHA3-256

    fn absorb_block(st: &mut [u64; 25], block: &[u8; RATE]) {
        for i in 0..RATE / 8 {
            let mut lane = [0u8; 8];
            lane.copy_from_slice(&block[i * 8..i * 8 + 8]);
            st[i] ^= u64::from_le_bytes(lane);
        }
        keccak_f(st);
    }

    /// SHA3-256 per FIPS 202.
    pub fn sha3_256(data: &[u8]) -> [u8; 32] {
        let mut st = [0u64; 25];
        let mut chunks = data.chunks_exact(RATE);
        for chunk in chunks.by_ref() {
            let mut block = [0u8; RATE];
            block.copy_from_slice(chunk);
            absorb_block(&mut st, &block);
        }
        let rem = chunks.remainder();
        let mut block = [0u8; RATE];
        block[..rem.len()].copy_from_slice(rem);
        block[rem.len()] = 0x06; // SHA3 domain separation + first pad bit
        block[RATE - 1] |= 0x80; // final pad bit
        absorb_block(&mut st, &block);

        let mut out = [0u8; 32];
        for i in 0..4 {
            out[i * 8..i * 8 + 8].copy_from_slice(&st[i].to_le_bytes());
        }
        out
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn sha3_256_known_answers() {
        assert_eq!(
            hex::encode(sha3::sha3_256(b"")),
            "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
        );
        assert_eq!(
            hex::encode(sha3::sha3_256(b"abc")),
            "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"
        );
        // Crosses the 136-byte rate boundary (200 bytes of 0xa3).
        let long = [0xa3u8; 200];
        assert_eq!(
            hex::encode(sha3::sha3_256(&long)),
            "79f38adec5c20307a98ef76e8324afbfd46cfd81b22e3973c65fa1bd9de31787"
        );
    }

    #[test]
    fn base32_roundtrip() {
        for data in [&b""[..], b"f", b"fo", b"foo", b"foob", b"fooba", b"foobar"] {
            assert_eq!(base32_decode(&base32_encode(data)).unwrap(), data);
        }
    }

    #[test]
    fn onion_v3_real_address_roundtrip() {
        // DuckDuckGo's v3 onion — validates base32 + SHA3 checksum + version
        // against a real, Tor-accepted address.
        let host = "duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad";
        let pubkey = decode_onion_v3(host).expect("valid onion");
        assert_eq!(encode_onion_v3_label(&pubkey), host);
        // A one-bit corruption must fail the checksum.
        let mut bad = pubkey;
        bad[0] ^= 1;
        assert_eq!(base32_decode("!!!"), None);
        assert_ne!(encode_onion_v3_label(&bad), host);
    }

    #[test]
    fn netaddr_addr_v2_roundtrip() {
        let cases = [
            NetAddr::Ip("1.2.3.4:8333".parse().unwrap()),
            NetAddr::Ip("[2001:db8::1]:8333".parse().unwrap()),
            NetAddr::OnionV3 {
                pubkey: [7u8; 32],
                port: 8333,
            },
            NetAddr::I2p {
                hash: [9u8; 32],
                port: 0,
            },
        ];
        for na in cases {
            let (a, p) = na.to_addr_v2();
            assert_eq!(NetAddr::from_addr_v2(&a, p), Some(na));
        }
    }

    #[test]
    fn netaddr_parse_forms() {
        assert!(matches!(
            NetAddr::parse("1.2.3.4:8333", 8333),
            Some(NetAddr::Ip(_))
        ));
        let onion = "duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion";
        assert!(matches!(
            NetAddr::parse(onion, 8333),
            Some(NetAddr::OnionV3 { port: 8333, .. })
        ));
        assert!(matches!(
            NetAddr::parse(&format!("{onion}:9999"), 8333),
            Some(NetAddr::OnionV3 { port: 9999, .. })
        ));
        // I2P, with and without the conventional `:0` port suffix (Bitcoin
        // Core's fixed-seed lists use `<b32>.b32.i2p:0`).
        let i2p_host = format!("{}.b32.i2p", base32_encode(&[9u8; 32]));
        assert!(matches!(
            NetAddr::parse(&i2p_host, 8333),
            Some(NetAddr::I2p { port: 8333, .. })
        ));
        assert!(matches!(
            NetAddr::parse(&format!("{i2p_host}:0"), 8333),
            Some(NetAddr::I2p { port: 0, .. })
        ));
        // Plain hostnames are not literals — caller must resolve.
        assert_eq!(NetAddr::parse("seed.example.com", 8333), None);
    }

    #[test]
    fn netaddr_json_roundtrip() {
        let na = NetAddr::OnionV3 {
            pubkey: [3u8; 32],
            port: 8333,
        };
        let json = serde_json::to_string(&na).unwrap();
        assert_eq!(serde_json::from_str::<NetAddr>(&json).unwrap(), na);
    }
}
