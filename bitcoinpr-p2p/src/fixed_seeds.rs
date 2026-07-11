//! Built-in fixed seed peers — the bootstrap of last resort.
//!
//! Mirrors Bitcoin Core's `chainparamsseeds`: a node whose address book is
//! empty and that cannot (or must not) use clearnet DNS seeds still needs a
//! first peer to learn addresses from. The canonical case is a Tor-only node
//! (`-onlynet=onion` skips DNS seeding entirely), which without this list can
//! never bootstrap from a cold start.
//!
//! The embedded list is generated from Bitcoin Core's
//! `contrib/seeds/nodes_main.txt` (see the header of `data/nodes_main.txt`
//! for the source commit) and contains IPv4, IPv6, onion v3, and I2P
//! addresses. CJDNS entries (fc00::/8) are skipped — BitcoinPR does not route
//! CJDNS. Only mainnet ships a list; other networks return an empty vec and
//! rely on DNS seeds / manual `connect=`.
//!
//! Fixed seeds are deliberately low-priority: callers only consult them when
//! the address book is starved, and entries enter the book like any other
//! address, so gossip-learned peers with real reliability history win.

use std::net::IpAddr;

use bitcoin::Network;

use crate::netaddr::NetAddr;

/// Mainnet seed list, one address literal per line (`#` comments allowed).
const NODES_MAIN: &str = include_str!("../data/nodes_main.txt");

/// Default mainnet P2P port, used for entries without an explicit port.
const MAINNET_PORT: u16 = 8333;

/// The built-in fixed seeds for `network`. Empty for every network except
/// mainnet. Unparseable and CJDNS entries are silently skipped.
pub fn fixed_seeds(network: Network) -> Vec<NetAddr> {
    let raw = match network {
        Network::Bitcoin => NODES_MAIN,
        _ => return Vec::new(),
    };
    raw.lines()
        // Strip `# ...` comments — Core annotates IP entries with `# ASnnn`.
        .map(|line| line.split('#').next().unwrap_or("").trim())
        .filter(|line| !line.is_empty())
        .filter_map(|line| NetAddr::parse(line, MAINNET_PORT))
        .filter(|addr| !is_cjdns(addr))
        .collect()
}

/// CJDNS overlays squat on fc00::/8; those parse as plain IPv6 but are not
/// reachable over the real internet.
fn is_cjdns(addr: &NetAddr) -> bool {
    matches!(addr.ip(), Some(IpAddr::V6(v6)) if v6.octets()[0] == 0xfc)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::netaddr::AddrNetwork;

    #[test]
    fn mainnet_seeds_parse_and_cover_all_networks() {
        let seeds = fixed_seeds(Network::Bitcoin);
        // Core ships 512 per network class; require a healthy floor of each
        // so a regenerated file that drops a class fails loudly.
        let count = |net: AddrNetwork| seeds.iter().filter(|a| a.network() == net).count();
        assert!(count(AddrNetwork::Ipv4) >= 100, "too few IPv4 seeds");
        assert!(count(AddrNetwork::Ipv6) >= 100, "too few IPv6 seeds");
        assert!(count(AddrNetwork::Onion) >= 100, "too few onion seeds");
        assert!(count(AddrNetwork::I2p) >= 100, "too few I2P seeds");
        // No CJDNS leakage.
        assert!(seeds.iter().all(|a| !is_cjdns(a)));
        // IP entries must carry the real port from the list.
        assert!(seeds
            .iter()
            .filter_map(|a| a.to_socket_addr())
            .all(|sa| sa.port() != 0));
    }

    #[test]
    fn non_mainnet_has_no_fixed_seeds() {
        assert!(fixed_seeds(Network::Testnet).is_empty());
        assert!(fixed_seeds(Network::Signet).is_empty());
        assert!(fixed_seeds(Network::Regtest).is_empty());
    }
}
