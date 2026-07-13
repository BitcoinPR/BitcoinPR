//! Per-connection share-difficulty ramping ("vardiff") for the Stratum V1
//! gateway.
//!
//! Share difficulty is only a submit-rate filter: block detection always
//! checks the header hash against the job's real nBits target
//! (`handle_v1_submit`), so retargeting can never lose a block. The goal is
//! purely statistical — keep every worker near one share per
//! [`VARDIFF_TARGET_INTERVAL_SECS`] so the 10-minute rolling `ShareTracker`
//! window always holds enough shares for a stable hashrate estimate and a
//! populated worker list, whatever the miner's size.
//!
//! A connection starts at [`VARDIFF_START`] (or the miner's
//! `mining.suggest_difficulty`, clamped) and retargets in two places:
//!
//! * [`Vardiff::on_share`] — every [`EVAL_SHARES`] accepted shares, from the
//!   observed average interval (the ramp-up path: a fast miner reaches its
//!   steady-state difficulty in a handful of shares).
//! * [`Vardiff::on_tick`] — from the session's periodic timer, using elapsed
//!   time as a lower bound on the true interval (the ramp-down path: a miner
//!   too small for the current difficulty may never submit a share, so there
//!   is nothing for `on_share` to observe).
//!
//! Both paths share the same dead band and per-step clamp so the difficulty
//! cannot oscillate. Difficulty is capped at the network difficulty (a share
//! rarer than a block is pointless) and floored at [`VARDIFF_MIN`].
//!
//! Vardiff is NOT constructed when `--miningdifficulty` pins the share
//! difficulty, or when the network difficulty is at or below the floor
//! (regtest), where the static network difficulty is used as before.

use std::time::Instant;

/// Difficulty a fresh connection starts at unless the miner suggested one.
/// Low enough that even small ASICs (~150 GH/s → one share per ~15 s) produce
/// shares immediately, so ramp-up always has data to work with.
pub const VARDIFF_START: f64 = 512.0;

/// Hard floor. Supports test miners down to a few hundred kH/s; also the
/// activation threshold — a chain whose difficulty is at or below this
/// (regtest) doesn't need vardiff at all.
pub const VARDIFF_MIN: f64 = 0.001;

/// Ideal seconds between shares (TODO spec: 10–20 s).
pub const VARDIFF_TARGET_INTERVAL_SECS: f64 = 15.0;

/// Period of the session-loop tick that drives [`Vardiff::on_tick`].
pub const VARDIFF_TICK_SECS: u64 = 30;

/// Seconds a window may run shareless before `on_tick` steps the difficulty
/// down. 4× the target interval, so a healthy worker never trips it.
const IDLE_LOWER_SECS: f64 = 60.0;

/// Accepted shares per `on_share` evaluation window.
const EVAL_SHARES: u32 = 4;

/// Maximum single-retarget factor, up or down.
const MAX_STEP: f64 = 4.0;

/// Dead band around the target interval: estimates within
/// [target/2, target*2] leave the difficulty untouched.
const BAND: f64 = 2.0;

pub struct Vardiff {
    difficulty: f64,
    max: f64,
    shares_in_window: u32,
    window_start: Instant,
}

impl Vardiff {
    /// `max` is the network difficulty; `initial` is clamped into
    /// [[`VARDIFF_MIN`], `max`].
    pub fn new(initial: f64, max: f64, now: Instant) -> Self {
        let max = max.max(VARDIFF_MIN);
        Vardiff {
            difficulty: initial.clamp(VARDIFF_MIN, max),
            max,
            shares_in_window: 0,
            window_start: now,
        }
    }

    /// The share difficulty currently in force for this connection.
    pub fn difficulty(&self) -> f64 {
        self.difficulty
    }

    /// Record an accepted share. Returns the new difficulty when a retarget
    /// fired (the caller must push `mining.set_difficulty` + a fresh job).
    pub fn on_share(&mut self, now: Instant) -> Option<f64> {
        self.shares_in_window += 1;
        if self.shares_in_window < EVAL_SHARES {
            return None;
        }
        let elapsed = now.duration_since(self.window_start).as_secs_f64();
        let est_interval = (elapsed / f64::from(self.shares_in_window)).max(1e-6);
        self.shares_in_window = 0;
        self.window_start = now;
        self.retarget(est_interval)
    }

    /// Periodic check for a difficulty set too high to ever see shares.
    /// Uses elapsed wall time as a lower bound on the true share interval.
    pub fn on_tick(&mut self, now: Instant) -> Option<f64> {
        let elapsed = now.duration_since(self.window_start).as_secs_f64();
        if elapsed < IDLE_LOWER_SECS {
            return None;
        }
        // With N shares in `elapsed` seconds the interval is at least
        // elapsed/(N+1); shares still flowing fast enough are left to
        // `on_share`'s more precise estimate.
        let est_interval = elapsed / f64::from(self.shares_in_window + 1);
        if est_interval <= VARDIFF_TARGET_INTERVAL_SECS * BAND {
            return None;
        }
        self.shares_in_window = 0;
        self.window_start = now;
        self.retarget(est_interval)
    }

    /// Honor a `mining.suggest_difficulty` from the miner (clamped). Returns
    /// the difficulty to announce when it materially changed.
    pub fn suggest(&mut self, suggested: f64, now: Instant) -> Option<f64> {
        if !suggested.is_finite() || suggested <= 0.0 {
            return None;
        }
        let new = suggested.clamp(VARDIFF_MIN, self.max);
        if !Self::materially_different(self.difficulty, new) {
            return None;
        }
        self.difficulty = new;
        self.shares_in_window = 0;
        self.window_start = now;
        Some(new)
    }

    /// Track the network difficulty across templates so the cap follows
    /// retargets. Returns a new difficulty if the cap forced one down.
    pub fn update_max(&mut self, network_difficulty: f64) -> Option<f64> {
        self.max = network_difficulty.max(VARDIFF_MIN);
        if self.difficulty > self.max {
            self.difficulty = self.max;
            return Some(self.difficulty);
        }
        None
    }

    fn retarget(&mut self, est_interval: f64) -> Option<f64> {
        let target = VARDIFF_TARGET_INTERVAL_SECS;
        if (target / BAND..=target * BAND).contains(&est_interval) {
            return None;
        }
        let ratio = (target / est_interval).clamp(1.0 / MAX_STEP, MAX_STEP);
        let new = (self.difficulty * ratio).clamp(VARDIFF_MIN, self.max);
        if !Self::materially_different(self.difficulty, new) {
            return None;
        }
        self.difficulty = new;
        Some(new)
    }

    /// Suppress sub-1% "retargets" (e.g. already pinned at a clamp bound) so
    /// the miner isn't spammed with no-op `set_difficulty` notifications.
    fn materially_different(old: f64, new: f64) -> bool {
        (new - old).abs() / old > 0.01
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::time::Duration;

    const NET_DIFF: f64 = 126_000_000_000_000.0; // ~mainnet mid-2026

    fn secs(s: f64) -> Duration {
        Duration::from_secs_f64(s)
    }

    /// Feed `n` accepted shares at a fixed interval; return the last retarget.
    fn feed_shares(v: &mut Vardiff, t0: Instant, n: u32, interval: f64) -> Option<f64> {
        let mut out = None;
        for i in 1..=n {
            if let Some(d) = v.on_share(t0 + secs(interval * f64::from(i))) {
                out = Some(d);
            }
        }
        out
    }

    #[test]
    fn starts_at_initial_clamped() {
        let t0 = Instant::now();
        assert_eq!(
            Vardiff::new(VARDIFF_START, NET_DIFF, t0).difficulty(),
            512.0
        );
        // Initial above the network cap clamps down; below the floor clamps up.
        assert_eq!(Vardiff::new(1e20, NET_DIFF, t0).difficulty(), NET_DIFF);
        assert_eq!(Vardiff::new(0.0, NET_DIFF, t0).difficulty(), VARDIFF_MIN);
    }

    #[test]
    fn ramps_up_on_fast_shares() {
        let t0 = Instant::now();
        let mut v = Vardiff::new(512.0, NET_DIFF, t0);
        // One share per second: 4th share evaluates, 15/1 clamps to ×4.
        let new = feed_shares(&mut v, t0, EVAL_SHARES, 1.0);
        assert_eq!(new, Some(2048.0));
        assert_eq!(v.difficulty(), 2048.0);
    }

    #[test]
    fn holds_inside_dead_band() {
        let t0 = Instant::now();
        let mut v = Vardiff::new(512.0, NET_DIFF, t0);
        // 12 s interval is inside [7.5, 30]: evaluation fires, no retarget.
        assert_eq!(feed_shares(&mut v, t0, EVAL_SHARES, 12.0), None);
        assert_eq!(v.difficulty(), 512.0);
    }

    #[test]
    fn eases_down_on_slow_shares() {
        let t0 = Instant::now();
        let mut v = Vardiff::new(512.0, NET_DIFF, t0);
        // 60 s interval: ratio 15/60 = ÷4.
        assert_eq!(feed_shares(&mut v, t0, EVAL_SHARES, 60.0), Some(128.0));
    }

    #[test]
    fn tick_lowers_when_shareless() {
        let t0 = Instant::now();
        let mut v = Vardiff::new(512.0, NET_DIFF, t0);
        // Quiet ticks inside the idle grace period do nothing.
        assert_eq!(v.on_tick(t0 + secs(30.0)), None);
        // 60 s with zero shares: interval ≥ 60 s → ÷4.
        assert_eq!(v.on_tick(t0 + secs(60.0)), Some(128.0));
        // Window reset: the next tick 30 s later is quiet again.
        assert_eq!(v.on_tick(t0 + secs(90.0)), None);
        assert_eq!(v.on_tick(t0 + secs(120.0)), Some(32.0));
    }

    #[test]
    fn tick_leaves_flowing_shares_alone() {
        let t0 = Instant::now();
        let mut v = Vardiff::new(512.0, NET_DIFF, t0);
        // 3 shares in 61 s ≈ 15 s interval — healthy, no ramp-down.
        for i in 1..=3 {
            assert_eq!(v.on_share(t0 + secs(15.0 * f64::from(i))), None);
        }
        assert_eq!(v.on_tick(t0 + secs(61.0)), None);
        assert_eq!(v.difficulty(), 512.0);
    }

    #[test]
    fn clamps_at_floor_and_network_cap() {
        let t0 = Instant::now();
        let mut v = Vardiff::new(VARDIFF_MIN, NET_DIFF, t0);
        // Already at the floor: a shareless tick must not emit a no-op.
        assert_eq!(v.on_tick(t0 + secs(120.0)), None);
        assert_eq!(v.difficulty(), VARDIFF_MIN);

        let mut v = Vardiff::new(100.0, 150.0, t0);
        // Flooding shares want ×4 = 400 but the network cap is 150.
        assert_eq!(feed_shares(&mut v, t0, EVAL_SHARES, 0.5), Some(150.0));
        // A second flood is already pinned at the cap: no further notify.
        assert_eq!(feed_shares(&mut v, t0 + secs(2.0), EVAL_SHARES, 0.5), None);
    }

    #[test]
    fn suggest_clamps_and_applies() {
        let t0 = Instant::now();
        let mut v = Vardiff::new(512.0, NET_DIFF, t0);
        assert_eq!(v.suggest(1000.0, t0), Some(1000.0));
        assert_eq!(v.difficulty(), 1000.0);
        // Bogus values are ignored.
        assert_eq!(v.suggest(-5.0, t0), None);
        assert_eq!(v.suggest(f64::NAN, t0), None);
        // Suggestion above the cap clamps to it.
        assert_eq!(v.suggest(1e20, t0), Some(NET_DIFF));
        // Re-suggesting the current value is a no-op.
        assert_eq!(v.suggest(1e20, t0), None);
    }

    #[test]
    fn update_max_forces_difficulty_down() {
        let t0 = Instant::now();
        let mut v = Vardiff::new(512.0, NET_DIFF, t0);
        assert_eq!(v.update_max(NET_DIFF * 2.0), None);
        assert_eq!(v.update_max(100.0), Some(100.0));
        assert_eq!(v.difficulty(), 100.0);
    }

    #[test]
    fn window_resets_after_retarget() {
        let t0 = Instant::now();
        let mut v = Vardiff::new(512.0, NET_DIFF, t0);
        // First window ramps to 2048 at t0+4s.
        feed_shares(&mut v, t0, EVAL_SHARES, 1.0).unwrap();
        // Three more fast shares don't evaluate yet (window restarted).
        assert_eq!(
            feed_shares(&mut v, t0 + secs(4.0), EVAL_SHARES - 1, 1.0),
            None
        );
        // The 4th does, and ramps again from the fresh window.
        assert_eq!(v.on_share(t0 + secs(8.0)), Some(8192.0));
    }
}
