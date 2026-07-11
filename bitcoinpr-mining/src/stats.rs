use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use serde::Serialize;
use tokio::sync::RwLock;

use crate::shares::{ShareEntry, ShareTracker, WorkerStats};

/// Point-in-time snapshot of mining statistics for the web dashboard.
#[derive(Debug, Clone, Serialize)]
pub struct MiningStatsSnapshot {
    pub hashrate: f64,
    pub hashrate_unit: String,
    pub shares_accepted: u64,
    pub shares_rejected: u64,
    pub blocks_found: u64,
    pub best_share_difficulty: f64,
    pub connected_workers: u32,
    pub uptime_secs: u64,
    pub solo_mining: bool,
    pub gateway_status: String,
    /// Datum pool connection status (None in solo mode).
    pub datum_status: Option<crate::datum::DatumStatus>,
}

/// Per-worker information exposed to the API layer.
#[derive(Debug, Clone, Serialize)]
pub struct WorkerInfo {
    pub name: String,
    pub hashrate: f64,
    pub shares_accepted: u64,
    pub shares_rejected: u64,
    pub last_share_time: u64,
}

/// High-level query interface consumed by the web server.
pub struct MiningDashboard {
    share_tracker: ShareTracker,
    worker_count: Arc<AtomicU32>,
    gateway_running: Arc<RwLock<bool>>,
    /// Datum pool client; `None` in solo mode.
    datum_client: Option<Arc<crate::datum::DatumClient>>,
}

impl MiningDashboard {
    pub fn new(
        share_tracker: ShareTracker,
        datum_client: Option<Arc<crate::datum::DatumClient>>,
    ) -> Self {
        MiningDashboard {
            share_tracker,
            worker_count: Arc::new(AtomicU32::new(0)),
            gateway_running: Arc::new(RwLock::new(false)),
            datum_client,
        }
    }

    /// Return the shared worker counter so the stratum server can update it.
    pub fn worker_count(&self) -> Arc<AtomicU32> {
        self.worker_count.clone()
    }

    /// Build an atomic snapshot of all mining metrics.
    pub async fn snapshot(&self) -> MiningStatsSnapshot {
        let raw_hashrate = self.share_tracker.hashrate();
        let (hashrate, hashrate_unit) = format_hashrate(raw_hashrate);
        let workers = self.worker_count.load(Ordering::Relaxed);
        let running = *self.gateway_running.read().await;

        let datum_status = match &self.datum_client {
            Some(c) => Some(c.status().await),
            None => None,
        };

        MiningStatsSnapshot {
            hashrate,
            hashrate_unit,
            shares_accepted: self.share_tracker.accepted(),
            shares_rejected: self.share_tracker.rejected(),
            blocks_found: self.share_tracker.blocks_found(),
            best_share_difficulty: self.share_tracker.best_difficulty(),
            connected_workers: workers,
            uptime_secs: self.share_tracker.uptime_secs(),
            solo_mining: self.datum_client.is_none(),
            gateway_status: if running {
                "running".to_string()
            } else {
                "stopped".to_string()
            },
            datum_status,
        }
    }

    /// Per-worker statistics.
    pub async fn workers(&self) -> Vec<WorkerInfo> {
        self.share_tracker
            .worker_stats()
            .into_iter()
            .map(|ws: WorkerStats| WorkerInfo {
                name: ws.name,
                hashrate: ws.hashrate,
                shares_accepted: ws.shares_accepted,
                shares_rejected: ws.shares_rejected,
                last_share_time: ws.last_share_time,
            })
            .collect()
    }

    /// Return the most recent shares (newest last).
    pub async fn recent_shares(&self, limit: usize) -> Vec<ShareEntry> {
        self.share_tracker.recent_shares(limit)
    }

    /// Update the gateway running flag.
    pub async fn set_gateway_running(&self, running: bool) {
        *self.gateway_running.write().await = running;
    }
}

/// Scale a raw H/s value into a human-friendly magnitude + unit string.
fn format_hashrate(hashrate_hs: f64) -> (f64, String) {
    if hashrate_hs > 1e15 {
        (hashrate_hs / 1e15, "PH/s".to_string())
    } else if hashrate_hs > 1e12 {
        (hashrate_hs / 1e12, "TH/s".to_string())
    } else if hashrate_hs > 1e9 {
        (hashrate_hs / 1e9, "GH/s".to_string())
    } else if hashrate_hs > 1e6 {
        (hashrate_hs / 1e6, "MH/s".to_string())
    } else if hashrate_hs > 1e3 {
        (hashrate_hs / 1e3, "KH/s".to_string())
    } else {
        (hashrate_hs, "H/s".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_hashrate_units() {
        assert_eq!(format_hashrate(500.0).1, "H/s");
        assert_eq!(format_hashrate(5_000.0).1, "KH/s");
        assert_eq!(format_hashrate(5_000_000.0).1, "MH/s");
        assert_eq!(format_hashrate(5_000_000_000.0).1, "GH/s");
        assert_eq!(format_hashrate(5_000_000_000_000.0).1, "TH/s");
        assert_eq!(format_hashrate(5_000_000_000_000_000.0).1, "PH/s");
    }

    #[test]
    fn test_format_hashrate_scaling() {
        let (val, _) = format_hashrate(2_500_000.0);
        assert!((val - 2.5).abs() < 1e-9);
    }

    #[tokio::test]
    async fn test_dashboard_snapshot() {
        let tracker = ShareTracker::new();
        tracker.record_share("w1".into(), 1.0, true);
        let dash = MiningDashboard::new(tracker, None);
        let snap = dash.snapshot().await;
        assert_eq!(snap.shares_accepted, 1);
        assert_eq!(snap.shares_rejected, 0);
        assert_eq!(snap.gateway_status, "stopped");
    }

    #[tokio::test]
    async fn test_dashboard_worker_count() {
        let dash = MiningDashboard::new(ShareTracker::new(), None);
        dash.worker_count().store(5, Ordering::Relaxed);
        let snap = dash.snapshot().await;
        assert_eq!(snap.connected_workers, 5);
    }

    #[tokio::test]
    async fn test_dashboard_gateway_status() {
        let dash = MiningDashboard::new(ShareTracker::new(), None);
        dash.set_gateway_running(true).await;
        let snap = dash.snapshot().await;
        assert_eq!(snap.gateway_status, "running");
    }
}
