//! Network-adjusted time (Bitcoin Core's `nTimeOffset`).
//!
//! Each peer reports its clock in the `version` message. We track the offset of
//! each peer's clock from ours and apply the *median* offset to a
//! network-adjusted clock, used for the +2h future-block check so a single
//! node with a slightly-wrong clock doesn't reject (or over-accept) otherwise
//! valid headers. The adjustment is deliberately conservative — clamped to
//! ±70 minutes, applied only once we have at least 5 samples — and a larger
//! divergence is treated as *our* clock being wrong (no adjustment, operator
//! warned) rather than trusting the network to move us far.

use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

/// Maximum samples retained (matches Core's median filter window).
const MAX_SAMPLES: usize = 200;
/// Minimum samples before any adjustment is applied.
const MIN_SAMPLES: usize = 5;
/// Largest offset we will ever apply, in seconds (±70 minutes, as in Core).
pub const MAX_TIME_OFFSET_SECS: i64 = 70 * 60;

static OFFSET_SECS: AtomicI64 = AtomicI64::new(0);
static SAMPLES: Mutex<Vec<i64>> = Mutex::new(Vec::new());
static CLOCK_WARNED: AtomicBool = AtomicBool::new(false);

/// The local clock in Unix seconds. Fail-closed to 0 on a pre-1970 clock.
pub fn local_time_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// The currently applied median peer offset (seconds); 0 until enough samples.
pub fn time_offset_secs() -> i64 {
    OFFSET_SECS.load(Ordering::Relaxed)
}

/// Network-adjusted Unix time: the local clock plus the median peer offset.
pub fn adjusted_time_secs() -> i64 {
    local_time_secs() + OFFSET_SECS.load(Ordering::Relaxed)
}

/// Feed a peer's reported clock offset (their `version` timestamp minus our
/// local time, in seconds) into the median filter and recompute the applied
/// offset. Safe to call from any peer task.
pub fn add_time_sample(offset_secs: i64) {
    let mut samples = SAMPLES.lock().expect("time samples mutex poisoned");
    if samples.len() >= MAX_SAMPLES {
        return;
    }
    samples.push(offset_secs);

    // Only recompute on an odd, sufficiently large sample count so the median
    // is an actual observed value (no averaging of two middle samples).
    if samples.len() >= MIN_SAMPLES && samples.len() % 2 == 1 {
        let mut sorted = samples.clone();
        sorted.sort_unstable();
        let median = sorted[sorted.len() / 2];
        if median.abs() <= MAX_TIME_OFFSET_SECS {
            OFFSET_SECS.store(median, Ordering::Relaxed);
        } else {
            // The network says our clock is off by more than 70 minutes. Don't
            // chase it — far more likely our own clock is wrong. Warn once.
            OFFSET_SECS.store(0, Ordering::Relaxed);
            if !CLOCK_WARNED.swap(true, Ordering::Relaxed) {
                tracing::warn!(
                    median_offset_secs = median,
                    "Peers report our clock is off by more than 70 minutes; not adjusting. \
                     Please check that this computer's date and time are correct, or the node \
                     may reject valid blocks."
                );
            }
        }
    }
}

/// Reset all time-offset state. Test-only.
#[doc(hidden)]
pub fn reset_for_test() {
    SAMPLES.lock().expect("time samples mutex poisoned").clear();
    OFFSET_SECS.store(0, Ordering::Relaxed);
    CLOCK_WARNED.store(false, Ordering::Relaxed);
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::sync::Mutex as StdMutex;

    // These tests share the process-global filter, so serialize them.
    static TEST_LOCK: StdMutex<()> = StdMutex::new(());

    #[test]
    fn no_adjustment_until_five_samples() {
        let _g = TEST_LOCK.lock().unwrap();
        reset_for_test();
        for _ in 0..4 {
            add_time_sample(100);
        }
        assert_eq!(
            time_offset_secs(),
            0,
            "fewer than 5 samples must not adjust"
        );
        add_time_sample(100); // 5th
        assert_eq!(time_offset_secs(), 100, "median of five 100s is 100");
    }

    #[test]
    fn median_is_robust_to_outliers() {
        let _g = TEST_LOCK.lock().unwrap();
        reset_for_test();
        // Five samples: 3 near zero, 2 wild. Median picks the central one.
        for s in [10, -5, 5, 3000, -9000] {
            add_time_sample(s);
        }
        // sorted: [-9000, -5, 5, 10, 3000] -> median 5
        assert_eq!(time_offset_secs(), 5);
    }

    #[test]
    fn large_divergence_is_clamped_to_zero() {
        let _g = TEST_LOCK.lock().unwrap();
        reset_for_test();
        // All peers ~2 hours ahead — beyond the 70-minute cap: stay at 0.
        for _ in 0..5 {
            add_time_sample(2 * 60 * 60);
        }
        assert_eq!(
            time_offset_secs(),
            0,
            "offset beyond ±70min must not be applied"
        );
    }

    #[test]
    fn adjusted_time_tracks_offset() {
        let _g = TEST_LOCK.lock().unwrap();
        reset_for_test();
        for _ in 0..5 {
            add_time_sample(600); // +10 min, within cap
        }
        let delta = adjusted_time_secs() - local_time_secs();
        assert_eq!(delta, 600);
    }
}
