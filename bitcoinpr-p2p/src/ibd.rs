//! Shared helpers for initial block download (IBD) optimization.

use bitcoin::p2p::ServiceFlags;
use std::time::Duration;

use crate::peer::PeerInfo;

/// Margin between block tip and header tip below which we consider the node
/// "caught up" (matches web/mining/electrum consumers).
pub const IBD_CATCH_UP_MARGIN: u32 = 4;

/// Height gap above which NETWORK_LIMITED peers may serve historical blocks.
pub const NETWORK_LIMITED_GAP: u32 = 10_000;

/// Returns true when the block tip is far behind the downloaded header tip.
pub fn is_catching_up(block_height: u32, header_tip: u32) -> bool {
    header_tip.saturating_sub(block_height) > IBD_CATCH_UP_MARGIN
}

/// Whether a peer may receive block download assignments.
pub fn peer_eligible_for_download(peer: &PeerInfo, block_height: u32, header_tip: u32) -> bool {
    if peer.start_height <= 0 {
        return false;
    }
    if peer.services.has(ServiceFlags::NETWORK) {
        return true;
    }
    if peer.services.has(ServiceFlags::NETWORK_LIMITED)
        && is_catching_up(block_height, header_tip)
        && header_tip.saturating_sub(block_height) > NETWORK_LIMITED_GAP
    {
        return true;
    }
    false
}

/// Collect peer IDs eligible for block download at the current sync position.
pub fn eligible_download_peer_ids(
    peers: &[PeerInfo],
    block_height: u32,
    header_tip: u32,
) -> Vec<u64> {
    peers
        .iter()
        .filter(|p| peer_eligible_for_download(p, block_height, header_tip))
        .map(|p| p.id)
        .collect()
}

/// Count peers eligible for block download.
pub fn count_eligible_download_peers(
    peers: &[PeerInfo],
    block_height: u32,
    header_tip: u32,
) -> usize {
    peers
        .iter()
        .filter(|p| peer_eligible_for_download(p, block_height, header_tip))
        .count()
}

/// Adaptive per-peer stale-clear base timeout scaled by expected block size at height.
///
/// - < 200 KB blocks (pre-1MB era): 30s
/// - 1 MB+ blocks (~SegWit activation): 120s
/// - 4 MB SegWit blocks: 300s
pub fn stale_base_timeout(block_height: u32) -> Duration {
    if block_height >= 700_000 {
        Duration::from_secs(300)
    } else if block_height >= 400_000 {
        Duration::from_secs(120)
    } else {
        Duration::from_secs(30)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::netaddr::NetAddr;
    use bitcoin::p2p::ServiceFlags;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    fn make_peer(services: ServiceFlags, start_height: i32) -> PeerInfo {
        PeerInfo {
            id: 1,
            addr: NetAddr::Ip(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 8333)),
            version: 70016,
            services,
            user_agent: "test".into(),
            start_height,
            synced_height: 0,
            relay: true,
            inbound: false,
            discovered_addr: None,
            v2: false,
        }
    }

    #[test]
    fn catching_up_when_gap_large() {
        assert!(is_catching_up(520_000, 953_000));
        assert!(!is_catching_up(953_000, 953_002));
    }

    #[test]
    fn network_limited_only_when_far_behind() {
        let limited = make_peer(ServiceFlags::NETWORK_LIMITED, 900_000);
        assert!(peer_eligible_for_download(&limited, 520_000, 953_000));
        assert!(!peer_eligible_for_download(&limited, 950_000, 953_000));
    }

    #[test]
    fn stale_timeout_scales_with_height() {
        assert_eq!(stale_base_timeout(300_000), Duration::from_secs(30));
        assert_eq!(stale_base_timeout(500_000), Duration::from_secs(120));
        assert_eq!(stale_base_timeout(800_000), Duration::from_secs(300));
    }
}
