use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{Duration, SystemTime};
use tracing::warn;

use crate::netaddr::NetAddr;

/// Maximum number of stored addresses.
const MAX_ADDRESSES: usize = 4096;
/// How long an address is considered fresh before needing re-announcement.
const ADDR_FRESH_DURATION: Duration = Duration::from_secs(3 * 60 * 60); // 3 hours
/// peers.dat format version. Bump on incompatible changes; a mismatch on
/// load is treated like a corrupt file (warn + start fresh). v2 widened the
/// stored address from `SocketAddr` to [`NetAddr`] (onion/I2P support).
const PEERS_FORMAT_VERSION: u32 = 2;
/// Maximum number of anchor addresses persisted (Core keeps 2 block-relay anchors).
pub const MAX_ANCHORS: usize = 2;

/// A stored peer address with metadata.
///
/// `last_seen` is wall-clock time (not `Instant`) so the address book can be
/// persisted across restarts with meaningful ages.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddrEntry {
    pub addr: NetAddr,
    pub services: u64,
    pub last_seen: SystemTime,
    /// How many times we've successfully connected to this address.
    pub success_count: u32,
    /// How many times a connection attempt failed.
    pub failure_count: u32,
}

/// On-disk format of `peers.dat` (JSON).
#[derive(Serialize, Deserialize)]
struct PersistedPeers {
    /// Format version (`PEERS_FORMAT_VERSION`).
    version: u32,
    /// Known addresses with reliability metadata.
    addrs: Vec<AddrEntry>,
    /// Outbound peers we were connected to at save time; re-dialed first on
    /// the next startup (Core's anchors.dat concept).
    anchors: Vec<NetAddr>,
}

/// Simple address manager that stores known peer addresses
/// and provides them for connection and relay.
pub struct AddrManager {
    addrs: HashMap<NetAddr, AddrEntry>,
}

impl Default for AddrManager {
    fn default() -> Self {
        Self::new()
    }
}

impl AddrManager {
    pub fn new() -> Self {
        AddrManager {
            addrs: HashMap::new(),
        }
    }

    /// Add or update a peer address.
    /// Insert or refresh an address. Returns `true` if it was **not** already
    /// known (i.e. newly learned), so callers can implement Core's "relay only
    /// new addresses" rule — relaying every received addr lets a meshed network
    /// amplify one address into an unbounded gossip storm.
    pub fn add(&mut self, addr: NetAddr, services: u64) -> bool {
        let is_new = !self.addrs.contains_key(&addr);
        if self.addrs.len() >= MAX_ADDRESSES && is_new {
            // Evict the oldest entry
            if let Some(oldest) = self
                .addrs
                .iter()
                .min_by_key(|(_, e)| e.last_seen)
                .map(|(a, _)| *a)
            {
                self.addrs.remove(&oldest);
            }
        }

        let entry = self.addrs.entry(addr).or_insert(AddrEntry {
            addr,
            services,
            last_seen: SystemTime::now(),
            success_count: 0,
            failure_count: 0,
        });
        entry.last_seen = SystemTime::now();
        entry.services = services;
        is_new
    }

    /// Record a successful connection.
    pub fn mark_good(&mut self, addr: &NetAddr) {
        if let Some(entry) = self.addrs.get_mut(addr) {
            entry.success_count += 1;
            entry.last_seen = SystemTime::now();
        }
    }

    /// Record a failed connection attempt.
    pub fn mark_failed(&mut self, addr: &NetAddr) {
        if let Some(entry) = self.addrs.get_mut(addr) {
            entry.failure_count += 1;
        }
    }

    /// Get addresses suitable for relay to other peers.
    /// Returns up to `max` fresh addresses.
    pub fn get_for_relay(&self, max: usize) -> Vec<&AddrEntry> {
        let now = SystemTime::now();
        let mut entries: Vec<&AddrEntry> = self
            .addrs
            .values()
            // duration_since errs when last_seen is in the future (clock skew);
            // treat that as fresh rather than dropping the address.
            .filter(|e| {
                now.duration_since(e.last_seen)
                    .map_or(true, |age| age < ADDR_FRESH_DURATION)
            })
            .collect();

        // Sort by last_seen descending (freshest first)
        entries.sort_by(|a, b| b.last_seen.cmp(&a.last_seen));
        entries.truncate(max);
        entries
    }

    /// Get addresses sorted by reliability for connection attempts.
    /// Excludes addresses with 3+ more failures than successes.
    /// Untried addresses (zero attempts) are shuffled to the front so the
    /// node explores fresh peers instead of retrying the same failures.
    pub fn get_for_connect(&self, max: usize) -> Vec<NetAddr> {
        let mut untried: Vec<NetAddr> = Vec::new();
        let mut tried: Vec<(NetAddr, i64)> = Vec::new();

        for (addr, e) in &self.addrs {
            let net_score = e.success_count as i64 - e.failure_count as i64;
            // Skip addresses that have failed 3+ more times than succeeded
            if net_score < -2 {
                continue;
            }
            if e.success_count == 0 && e.failure_count == 0 {
                untried.push(*addr);
            } else {
                tried.push((*addr, net_score));
            }
        }

        // Shuffle untried so we explore different addresses each cycle
        use rand::seq::SliceRandom;
        untried.shuffle(&mut rand::thread_rng());

        // Sort tried by score descending (most reliable first)
        tried.sort_by(|a, b| b.1.cmp(&a.1));

        // Untried first (fresh exploration), then tried (reliable fallback)
        let mut result: Vec<NetAddr> = untried;
        result.extend(tried.into_iter().map(|(a, _)| a));
        result.truncate(max);
        result
    }

    /// Number of stored addresses.
    pub fn len(&self) -> usize {
        self.addrs.len()
    }

    /// Whether the address book is empty.
    pub fn is_empty(&self) -> bool {
        self.addrs.is_empty()
    }

    /// Serialize the address book (plus anchor addresses) into the
    /// `peers.dat` JSON format. `anchors` is capped at `MAX_ANCHORS`.
    pub fn save_to_bytes(&self, anchors: &[NetAddr]) -> Vec<u8> {
        let state = PersistedPeers {
            version: PEERS_FORMAT_VERSION,
            addrs: self.addrs.values().cloned().collect(),
            anchors: anchors.iter().copied().take(MAX_ANCHORS).collect(),
        };
        match serde_json::to_vec(&state) {
            Ok(bytes) => bytes,
            Err(e) => {
                // Practically unreachable (only a pre-epoch SystemTime fails);
                // an empty file is treated as corrupt on the next load.
                warn!("Failed to serialize address book: {}", e);
                Vec::new()
            }
        }
    }

    /// Load the address book from `peers.dat` bytes, returning the persisted
    /// anchor addresses. A corrupt file or format-version mismatch never
    /// fails startup — it logs a warning and leaves the manager fresh.
    pub fn load_from_bytes(&mut self, data: &[u8]) -> Vec<NetAddr> {
        let state: PersistedPeers = match serde_json::from_slice(data) {
            Ok(s) => s,
            Err(e) => {
                warn!(
                    "Failed to parse peers.dat — starting with an empty address book: {}",
                    e
                );
                return Vec::new();
            }
        };
        if state.version != PEERS_FORMAT_VERSION {
            warn!(
                found = state.version,
                expected = PEERS_FORMAT_VERSION,
                "peers.dat format version mismatch — starting with an empty address book"
            );
            return Vec::new();
        }
        for entry in state.addrs.into_iter().take(MAX_ADDRESSES) {
            self.addrs.insert(entry.addr, entry);
        }
        state.anchors.into_iter().take(MAX_ANCHORS).collect()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn test_addr_manager_add_and_get() {
        let mut mgr = AddrManager::new();

        let addr1 = NetAddr::Ip("1.2.3.4:8333".parse().unwrap());
        let addr2 = NetAddr::Ip("5.6.7.8:8333".parse().unwrap());

        // `add` reports novelty: true on first insert, false on refresh — the
        // signal used to relay only newly-learned addresses (storm prevention).
        assert!(mgr.add(addr1, 1), "first insert is new");
        assert!(mgr.add(addr2, 1), "first insert is new");
        assert!(!mgr.add(addr1, 1), "re-adding a known address is not new");
        assert_eq!(mgr.len(), 2);

        // Make both addresses "tried" so the reliability sort applies (untried
        // addresses are shuffled to the front for fresh exploration).
        mgr.mark_good(&addr1);
        mgr.mark_failed(&addr2);
        let conns = mgr.get_for_connect(10);
        assert_eq!(conns.len(), 2);
        // addr1 should be first (higher reliability score)
        assert_eq!(conns[0], addr1);
    }

    #[test]
    fn test_addr_manager_relay() {
        let mut mgr = AddrManager::new();
        let addr = NetAddr::Ip("10.0.0.1:8333".parse().unwrap());
        mgr.add(addr, 1);

        let relay = mgr.get_for_relay(10);
        assert_eq!(relay.len(), 1);
        assert_eq!(relay[0].addr, addr);
    }

    #[test]
    fn test_stores_and_persists_onion_and_i2p() {
        // Onion/I2P addresses must be storable, relayable, and survive a
        // peers.dat round-trip alongside IP addresses (the v2 format).
        let mut mgr = AddrManager::new();
        let ip = NetAddr::Ip("1.2.3.4:8333".parse().unwrap());
        let onion = NetAddr::OnionV3 {
            pubkey: [5u8; 32],
            port: 8333,
        };
        let i2p = NetAddr::I2p {
            hash: [6u8; 32],
            port: 0,
        };
        assert!(mgr.add(ip, 1));
        assert!(mgr.add(onion, 1));
        assert!(mgr.add(i2p, 1));
        assert!(!mgr.add(onion, 1), "re-adding onion is not novel");
        assert_eq!(mgr.get_for_relay(10).len(), 3);

        let bytes = mgr.save_to_bytes(&[onion]);
        let mut loaded = AddrManager::new();
        let anchors = loaded.load_from_bytes(&bytes);
        assert_eq!(loaded.len(), 3);
        assert_eq!(anchors, vec![onion]);
        assert!(loaded.addrs.contains_key(&i2p));
    }

    #[test]
    fn test_persistence_roundtrip_preserves_reliability() {
        let mut mgr = AddrManager::new();
        let a1 = NetAddr::Ip("1.2.3.4:8333".parse().unwrap());
        let a2 = NetAddr::Ip("5.6.7.8:8333".parse().unwrap());
        mgr.add(a1, 1);
        mgr.add(a2, 9);
        mgr.mark_good(&a1);
        mgr.mark_good(&a1);
        mgr.mark_failed(&a2);

        let bytes = mgr.save_to_bytes(&[a1]);

        let mut loaded = AddrManager::new();
        let anchors = loaded.load_from_bytes(&bytes);
        assert_eq!(loaded.len(), 2);
        assert_eq!(anchors, vec![a1]);

        let e1 = &loaded.addrs[&a1];
        assert_eq!(e1.success_count, 2);
        assert_eq!(e1.failure_count, 0);
        assert_eq!(e1.services, 1);
        let e2 = &loaded.addrs[&a2];
        assert_eq!(e2.failure_count, 1);
        assert_eq!(e2.services, 9);

        // Reloaded entries are still fresh enough to relay.
        assert_eq!(loaded.get_for_relay(10).len(), 2);
    }

    #[test]
    fn test_persistence_corrupt_bytes_start_fresh() {
        let mut mgr = AddrManager::new();
        let anchors = mgr.load_from_bytes(b"\x00\xffgarbage not json");
        assert!(anchors.is_empty());
        assert_eq!(mgr.len(), 0);
    }

    #[test]
    fn test_persistence_version_mismatch_starts_fresh() {
        let mut mgr = AddrManager::new();
        mgr.add(NetAddr::Ip("1.2.3.4:8333".parse().unwrap()), 1);
        let bytes = mgr.save_to_bytes(&[]);
        // Rewrite the version field to a future version.
        let altered = String::from_utf8(bytes)
            .unwrap()
            .replace("\"version\":2", "\"version\":999");

        let mut loaded = AddrManager::new();
        let anchors = loaded.load_from_bytes(altered.as_bytes());
        assert!(anchors.is_empty());
        assert_eq!(loaded.len(), 0);
    }

    #[test]
    fn test_persisted_anchors_capped_at_two() {
        let mgr = AddrManager::new();
        let anchors: Vec<NetAddr> = (1..=5)
            .map(|i| NetAddr::Ip(format!("10.0.0.{i}:8333").parse().unwrap()))
            .collect();
        let bytes = mgr.save_to_bytes(&anchors);

        let mut loaded = AddrManager::new();
        let loaded_anchors = loaded.load_from_bytes(&bytes);
        assert_eq!(loaded_anchors.len(), MAX_ANCHORS);
        assert_eq!(loaded_anchors, anchors[..MAX_ANCHORS]);
    }
}
