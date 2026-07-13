use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, SystemTime};
use tracing::{info, warn};

use crate::peer::PeerId;

/// Default ban duration: 24 hours.
const DEFAULT_BAN_DURATION: Duration = Duration::from_secs(24 * 60 * 60);

/// Threshold at which a peer gets banned.
const BAN_THRESHOLD: u32 = 100;

/// banlist.json format version. Bump on incompatible changes; a mismatch on
/// load is treated like a corrupt file (warn + start fresh).
const BANLIST_FORMAT_VERSION: u32 = 1;

/// Misbehavior reasons and their penalty scores.
#[derive(Debug, Clone, Copy)]
pub enum Misbehavior {
    /// Sent an invalid block header.
    InvalidHeader,
    /// Kept sending headers that don't connect to anything we know
    /// (applied once per `MAX_UNCONNECTING_HEADERS` consecutive messages,
    /// mirroring Core's unconnecting-headers throttle).
    UnconnectingHeaders,
    /// Sent a block that failed validation.
    InvalidBlock,
    /// Sent an invalid transaction.
    InvalidTransaction,
    /// Sent too many messages (flooding).
    MessageFlooding,
    /// Sent an unknown or unexpected message.
    UnexpectedMessage,
    /// Failed to respond to ping in time.
    PingTimeout,
    /// Sent duplicate data.
    DuplicateData,
}

impl Misbehavior {
    /// Return the penalty score for this misbehavior.
    pub fn score(self) -> u32 {
        match self {
            Misbehavior::InvalidHeader => 20,
            Misbehavior::UnconnectingHeaders => 20,
            Misbehavior::InvalidBlock => 100,
            Misbehavior::InvalidTransaction => 10,
            Misbehavior::MessageFlooding => 50,
            Misbehavior::UnexpectedMessage => 1,
            Misbehavior::PingTimeout => 5,
            Misbehavior::DuplicateData => 5,
        }
    }
}

/// A banned IP address with expiration time.
///
/// `until` is wall-clock time (not `Instant`) so active bans can be persisted
/// across restarts.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct BanEntry {
    reason: String,
    until: SystemTime,
}

/// On-disk format of `banlist.json`.
///
/// Only bans are persisted — misbehavior scores reset on restart, but an
/// active ban must survive or every misbehaving IP gets a free unban on
/// every reboot.
#[derive(Serialize, Deserialize)]
struct PersistedBanlist {
    /// Format version (`BANLIST_FORMAT_VERSION`).
    version: u32,
    /// Banned IPs with reason and expiry.
    bans: Vec<(IpAddr, BanEntry)>,
}

/// Tracks peer misbehavior scores and IP bans.
pub struct PeerScoring {
    /// Misbehavior scores per peer.
    scores: HashMap<PeerId, u32>,
    /// Peer ID to IP address mapping.
    peer_ips: HashMap<PeerId, IpAddr>,
    /// Banned IP addresses.
    banned: HashMap<IpAddr, BanEntry>,
}

impl Default for PeerScoring {
    fn default() -> Self {
        Self::new()
    }
}

impl PeerScoring {
    pub fn new() -> Self {
        PeerScoring {
            scores: HashMap::new(),
            peer_ips: HashMap::new(),
            banned: HashMap::new(),
        }
    }

    /// Register a peer's IP address.
    pub fn register_peer(&mut self, peer_id: PeerId, ip: IpAddr) {
        self.peer_ips.insert(peer_id, ip);
        self.scores.entry(peer_id).or_insert(0);
    }

    /// Remove a peer from tracking.
    pub fn unregister_peer(&mut self, peer_id: PeerId) {
        self.scores.remove(&peer_id);
        self.peer_ips.remove(&peer_id);
    }

    /// Record misbehavior for a peer. Returns true if the peer should be banned.
    pub fn record_misbehavior(&mut self, peer_id: PeerId, reason: Misbehavior) -> bool {
        let penalty = reason.score();
        let score = self.scores.entry(peer_id).or_insert(0);
        *score = score.saturating_add(penalty);
        let total = *score;

        warn!(
            peer_id,
            penalty,
            total_score = total,
            reason = ?reason,
            "Peer misbehavior recorded"
        );

        if total >= BAN_THRESHOLD {
            // Ban the peer's IP
            if let Some(ip) = self.peer_ips.get(&peer_id).copied() {
                self.ban_ip(
                    ip,
                    format!("{reason:?} (score: {total})"),
                    DEFAULT_BAN_DURATION,
                );
            }
            true
        } else {
            false
        }
    }

    /// Get the current score for a peer.
    pub fn get_score(&self, peer_id: PeerId) -> u32 {
        self.scores.get(&peer_id).copied().unwrap_or(0)
    }

    /// Ban an IP address for a given duration.
    pub fn ban_ip(&mut self, ip: IpAddr, reason: String, duration: Duration) {
        info!(%ip, %reason, secs = duration.as_secs(), "Banning IP");
        self.banned.insert(
            ip,
            BanEntry {
                reason,
                until: SystemTime::now() + duration,
            },
        );
    }

    /// Check if an IP address is currently banned.
    pub fn is_banned(&self, ip: &IpAddr) -> bool {
        if let Some(entry) = self.banned.get(ip) {
            SystemTime::now() < entry.until
        } else {
            false
        }
    }

    /// Remove expired bans.
    pub fn cleanup_expired_bans(&mut self) {
        let now = SystemTime::now();
        self.banned.retain(|ip, entry| {
            if now >= entry.until {
                info!(%ip, "Ban expired");
                false
            } else {
                true
            }
        });
    }

    /// Get all currently banned IPs.
    pub fn banned_ips(&self) -> Vec<(IpAddr, String)> {
        self.banned
            .iter()
            .filter(|(_, entry)| SystemTime::now() < entry.until)
            .map(|(ip, entry)| (*ip, entry.reason.clone()))
            .collect()
    }

    /// Serialize the ban list into the `banlist.json` format. Misbehavior
    /// scores are intentionally not persisted (they reset each session).
    pub fn save_to_bytes(&self) -> Vec<u8> {
        let state = PersistedBanlist {
            version: BANLIST_FORMAT_VERSION,
            bans: self
                .banned
                .iter()
                .map(|(ip, entry)| (*ip, entry.clone()))
                .collect(),
        };
        match serde_json::to_vec(&state) {
            Ok(bytes) => bytes,
            Err(e) => {
                warn!("Failed to serialize ban list: {}", e);
                Vec::new()
            }
        }
    }

    /// Load active bans from `banlist.json` bytes, dropping any that have
    /// already expired. A corrupt file or format-version mismatch never
    /// fails startup — it logs a warning and starts fresh.
    pub fn load_from_bytes(&mut self, data: &[u8]) {
        let state: PersistedBanlist = match serde_json::from_slice(data) {
            Ok(s) => s,
            Err(e) => {
                warn!(
                    "Failed to parse banlist.json — starting with an empty ban list: {}",
                    e
                );
                return;
            }
        };
        if state.version != BANLIST_FORMAT_VERSION {
            warn!(
                found = state.version,
                expected = BANLIST_FORMAT_VERSION,
                "banlist.json format version mismatch — starting with an empty ban list"
            );
            return;
        }
        let now = SystemTime::now();
        let mut loaded = 0usize;
        for (ip, entry) in state.bans {
            if entry.until > now {
                self.banned.insert(ip, entry);
                loaded += 1;
            }
        }
        if loaded > 0 {
            info!(count = loaded, "Loaded active bans from banlist.json");
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn test_misbehavior_scoring() {
        let mut scoring = PeerScoring::new();
        let peer_id = 1;
        let ip: IpAddr = "192.168.1.1".parse().unwrap();

        scoring.register_peer(peer_id, ip);

        // Small offense shouldn't ban
        let banned = scoring.record_misbehavior(peer_id, Misbehavior::UnexpectedMessage);
        assert!(!banned);
        assert_eq!(scoring.get_score(peer_id), 1);

        // Invalid block is an instant ban (score 100)
        let banned = scoring.record_misbehavior(peer_id, Misbehavior::InvalidBlock);
        assert!(banned);
        assert!(scoring.is_banned(&ip));
    }

    #[test]
    fn test_ban_check() {
        let mut scoring = PeerScoring::new();
        let ip: IpAddr = "10.0.0.1".parse().unwrap();

        assert!(!scoring.is_banned(&ip));

        scoring.ban_ip(ip, "test".to_string(), Duration::from_secs(3600));
        assert!(scoring.is_banned(&ip));

        // Different IP should not be banned
        let other_ip: IpAddr = "10.0.0.2".parse().unwrap();
        assert!(!scoring.is_banned(&other_ip));
    }

    #[test]
    fn test_cumulative_score() {
        let mut scoring = PeerScoring::new();
        let peer_id = 42;
        let ip: IpAddr = "172.16.0.1".parse().unwrap();

        scoring.register_peer(peer_id, ip);

        // 5 invalid headers = 5 * 20 = 100 -> ban
        for i in 0..4 {
            let banned = scoring.record_misbehavior(peer_id, Misbehavior::InvalidHeader);
            assert!(
                !banned,
                "should not be banned after {} invalid headers",
                i + 1
            );
        }
        let banned = scoring.record_misbehavior(peer_id, Misbehavior::InvalidHeader);
        assert!(banned, "should be banned after 5 invalid headers");
        assert!(scoring.is_banned(&ip));
    }

    #[test]
    fn test_banlist_roundtrip_active_ban_survives() {
        let mut scoring = PeerScoring::new();
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        scoring.ban_ip(ip, "test".to_string(), Duration::from_secs(3600));

        let bytes = scoring.save_to_bytes();
        let mut loaded = PeerScoring::new();
        loaded.load_from_bytes(&bytes);
        assert!(loaded.is_banned(&ip));
        assert_eq!(loaded.banned_ips().len(), 1);
    }

    #[test]
    fn test_banlist_expired_ban_dropped_on_load() {
        let mut scoring = PeerScoring::new();
        let ip: IpAddr = "10.0.0.2".parse().unwrap();
        // Zero-duration ban: already expired by the time we load it back.
        scoring.ban_ip(ip, "expired".to_string(), Duration::from_secs(0));

        let bytes = scoring.save_to_bytes();
        let mut loaded = PeerScoring::new();
        loaded.load_from_bytes(&bytes);
        assert!(!loaded.is_banned(&ip));
        assert!(loaded.banned_ips().is_empty());
    }

    #[test]
    fn test_banlist_corrupt_bytes_start_fresh() {
        let mut scoring = PeerScoring::new();
        scoring.load_from_bytes(b"\x00\xffgarbage not json");
        assert!(scoring.banned_ips().is_empty());
    }
}
