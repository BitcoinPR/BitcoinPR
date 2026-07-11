use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::Serialize;

/// A single recorded mining share.
#[derive(Debug, Clone, Serialize)]
pub struct ShareEntry {
    pub worker: String,
    pub timestamp: u64,
    pub difficulty: f64,
    pub accepted: bool,
}

/// Per-worker aggregated statistics derived from the rolling window.
#[derive(Debug, Clone, Serialize)]
pub struct WorkerStats {
    pub name: String,
    pub hashrate: f64,
    pub shares_accepted: u64,
    pub shares_rejected: u64,
    pub last_share_time: u64,
}

/// Thread-safe share tracker using a rolling window for hashrate estimation.
///
/// Clone is cheap — it increments an `Arc` refcount.
#[derive(Clone)]
pub struct ShareTracker {
    inner: Arc<Mutex<ShareTrackerInner>>,
}

struct ShareTrackerInner {
    shares: VecDeque<ShareEntry>,
    accepted: u64,
    rejected: u64,
    blocks_found: u64,
    best_difficulty: f64,
    start_time: Instant,
    window: Duration,
}

impl ShareTrackerInner {
    fn prune_old(&mut self) {
        let now_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let cutoff = now_secs.saturating_sub(self.window.as_secs());
        while let Some(front) = self.shares.front() {
            if front.timestamp < cutoff {
                self.shares.pop_front();
            } else {
                break;
            }
        }
    }
}

impl ShareTracker {
    /// Create a new tracker with the default 10-minute rolling window.
    pub fn new() -> Self {
        ShareTracker {
            inner: Arc::new(Mutex::new(ShareTrackerInner {
                shares: VecDeque::new(),
                accepted: 0,
                rejected: 0,
                blocks_found: 0,
                best_difficulty: 0.0,
                start_time: Instant::now(),
                window: Duration::from_secs(600),
            })),
        }
    }

    /// Record a mining share, pruning entries older than the rolling window.
    pub fn record_share(&self, worker: String, difficulty: f64, accepted: bool) {
        let mut inner = self.inner.lock().expect("stats lock poisoned");

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        inner.shares.push_back(ShareEntry {
            worker,
            timestamp,
            difficulty,
            accepted,
        });

        if accepted {
            inner.accepted += 1;
            if difficulty > inner.best_difficulty {
                inner.best_difficulty = difficulty;
            }
        } else {
            inner.rejected += 1;
        }

        inner.prune_old();
    }

    /// Increment the blocks-found counter.
    pub fn record_block_found(&self) {
        let mut inner = self.inner.lock().expect("stats lock poisoned");
        inner.blocks_found += 1;
    }

    /// Estimated hashrate (H/s) from accepted shares in the rolling window.
    ///
    /// Formula: `sum(difficulty) * 2^32 / window_seconds`.
    pub fn hashrate(&self) -> f64 {
        let mut inner = self.inner.lock().expect("stats lock poisoned");
        inner.prune_old();

        let window_secs = inner.window.as_secs_f64();
        if window_secs == 0.0 {
            return 0.0;
        }

        let difficulty_sum: f64 = inner
            .shares
            .iter()
            .filter(|s| s.accepted)
            .map(|s| s.difficulty)
            .sum();

        difficulty_sum * 4_294_967_296.0 / window_secs
    }

    pub fn accepted(&self) -> u64 {
        self.inner.lock().expect("stats lock poisoned").accepted
    }

    pub fn rejected(&self) -> u64 {
        self.inner.lock().expect("stats lock poisoned").rejected
    }

    pub fn blocks_found(&self) -> u64 {
        self.inner.lock().expect("stats lock poisoned").blocks_found
    }

    pub fn best_difficulty(&self) -> f64 {
        self.inner
            .lock()
            .expect("stats lock poisoned")
            .best_difficulty
    }

    /// Seconds since the tracker was created.
    pub fn uptime_secs(&self) -> u64 {
        self.inner
            .lock()
            .expect("stats lock poisoned")
            .start_time
            .elapsed()
            .as_secs()
    }

    /// Return the most recent `limit` shares (newest last).
    pub fn recent_shares(&self, limit: usize) -> Vec<ShareEntry> {
        let mut inner = self.inner.lock().expect("stats lock poisoned");
        inner.prune_old();

        let len = inner.shares.len();
        let skip = len.saturating_sub(limit);
        inner.shares.iter().skip(skip).cloned().collect()
    }

    /// Aggregate per-worker statistics from shares in the rolling window.
    pub fn worker_stats(&self) -> Vec<WorkerStats> {
        let mut inner = self.inner.lock().expect("stats lock poisoned");
        inner.prune_old();

        let window_secs = inner.window.as_secs_f64();

        struct Accumulator {
            accepted: u64,
            rejected: u64,
            difficulty_sum: f64,
            last_share_time: u64,
        }

        let mut workers: HashMap<String, Accumulator> = HashMap::new();

        for share in &inner.shares {
            let acc = workers.entry(share.worker.clone()).or_insert(Accumulator {
                accepted: 0,
                rejected: 0,
                difficulty_sum: 0.0,
                last_share_time: 0,
            });

            if share.accepted {
                acc.accepted += 1;
                acc.difficulty_sum += share.difficulty;
            } else {
                acc.rejected += 1;
            }

            if share.timestamp > acc.last_share_time {
                acc.last_share_time = share.timestamp;
            }
        }

        workers
            .into_iter()
            .map(|(name, acc)| {
                let hashrate = if window_secs > 0.0 {
                    acc.difficulty_sum * 4_294_967_296.0 / window_secs
                } else {
                    0.0
                };
                WorkerStats {
                    name,
                    hashrate,
                    shares_accepted: acc.accepted,
                    shares_rejected: acc.rejected,
                    last_share_time: acc.last_share_time,
                }
            })
            .collect()
    }
}

impl Default for ShareTracker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn test_record_and_query() {
        let tracker = ShareTracker::new();
        tracker.record_share("worker1".into(), 1.0, true);
        tracker.record_share("worker1".into(), 2.0, true);
        tracker.record_share("worker2".into(), 1.0, false);

        assert_eq!(tracker.accepted(), 2);
        assert_eq!(tracker.rejected(), 1);
        assert!((tracker.best_difficulty() - 2.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_recent_shares() {
        let tracker = ShareTracker::new();
        for i in 0..20 {
            tracker.record_share(format!("w{i}"), 1.0, true);
        }
        let recent = tracker.recent_shares(5);
        assert_eq!(recent.len(), 5);
    }

    #[test]
    fn test_worker_stats() {
        let tracker = ShareTracker::new();
        tracker.record_share("alice".into(), 1.0, true);
        tracker.record_share("alice".into(), 2.0, true);
        tracker.record_share("bob".into(), 1.0, false);

        let stats = tracker.worker_stats();
        assert_eq!(stats.len(), 2);
    }

    #[test]
    fn test_blocks_found() {
        let tracker = ShareTracker::new();
        assert_eq!(tracker.blocks_found(), 0);
        tracker.record_block_found();
        tracker.record_block_found();
        assert_eq!(tracker.blocks_found(), 2);
    }

    #[test]
    fn test_clone_shares_state() {
        let tracker = ShareTracker::new();
        tracker.record_share("w".into(), 5.0, true);

        let clone = tracker.clone();
        assert_eq!(clone.accepted(), 1);
        assert!((clone.best_difficulty() - 5.0).abs() < f64::EPSILON);
    }
}
