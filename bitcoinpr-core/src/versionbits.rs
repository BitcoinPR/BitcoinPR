//! BIP 9 / BIP 8 — Soft-fork deployment state machine (Versionbits).
//!
//! Tracks the state of soft-fork deployments using block version bits.
//! Each deployment transitions through states:
//!   DEFINED → STARTED → LOCKED_IN → ACTIVE
//!   DEFINED → STARTED → FAILED (if timeout reached without lock-in)
//!
//! BIP 90: Since the historical forks (BIP 34/65/66, CSV BIP 68/112/113, and
//! SegWit) have long since activated, they are validated as *buried deployments*
//! via hardcoded per-network heights in [`crate::consensus::ConsensusParams`]
//! (see `ConsensusParams::deployment_active`). This versionbits state machine is
//! therefore used ONLY for `getblocktemplate` signaling and dashboard/status
//! display — it is NEVER consulted on the consensus-critical validation path.

use bitcoin::block::Header;
use tracing::debug;

/// The state of a soft-fork deployment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeploymentState {
    /// Deployment is defined but not yet started.
    Defined,
    /// Deployment signaling period has started.
    Started,
    /// Deployment has been locked in and will activate after one more retarget period.
    LockedIn,
    /// Deployment is active.
    Active,
    /// Deployment failed to activate before the timeout.
    Failed,
}

/// Parameters for a single soft-fork deployment.
#[derive(Debug, Clone)]
pub struct Deployment {
    /// Human-readable name.
    pub name: &'static str,
    /// Which bit in nVersion to check (0-28).
    pub bit: u8,
    /// Median-time-past at which signaling begins.
    pub start_time: u64,
    /// Median-time-past at which the deployment times out (BIP 9).
    pub timeout: u64,
    /// Minimum activation height (BIP 8 extension, 0 = no minimum).
    pub min_activation_height: u32,
    /// Required signaling threshold out of 2016 blocks (BIP 9 default: 1916 = 95%).
    pub threshold: u32,
}

/// Track the state of all known soft-fork deployments.
pub struct VersionBitsTracker {
    deployments: Vec<Deployment>,
    /// Current state for each deployment.
    states: Vec<DeploymentState>,
}

/// Number of blocks in a retarget period (signaling window).
const RETARGET_PERIOD: u32 = 2016;

impl VersionBitsTracker {
    /// Create a new tracker with the given deployments.
    pub fn new(deployments: Vec<Deployment>) -> Self {
        let states = vec![DeploymentState::Defined; deployments.len()];
        VersionBitsTracker {
            deployments,
            states,
        }
    }

    /// Create a tracker for mainnet with known historical deployments.
    pub fn mainnet() -> Self {
        Self::new(vec![
            Deployment {
                name: "csv",
                bit: 0,
                start_time: 1462060800, // May 1, 2016
                timeout: 1493596800,    // May 1, 2017
                min_activation_height: 0,
                threshold: 1916, // 95%
            },
            Deployment {
                name: "segwit",
                bit: 1,
                start_time: 1479168000, // Nov 15, 2016
                timeout: 1510704000,    // Nov 15, 2017
                min_activation_height: 0,
                threshold: 1916,
            },
            Deployment {
                name: "taproot",
                bit: 2,
                start_time: 1619222400, // April 24, 2021
                timeout: 1628640000,    // Aug 11, 2021
                min_activation_height: 709632,
                threshold: 1815, // 90%
            },
            // NOTE: BIP-110 (Reduced Data Temporary Softfork) is deliberately NOT
            // listed here. Its signaling is a modified BIP-9 (55% threshold, a
            // mandatory-signaling window, no FAILED state, and — unlike this
            // tracker's fixed `min_activation_height` — an activation height that
            // is computed dynamically from on-chain signaling). This generic BIP-9
            // tracker can't represent those semantics, so BIP-110 has a single
            // source of truth in `crate::bip110` (`Bip110Deployment` /
            // `Bip110Checker`), which drives consensus, mempool, mining signaling,
            // and RPC status alike. Do not re-add a `bip110` entry here — it would
            // be a second, divergent definition that no live path consults.
        ])
    }

    /// Create a tracker for regtest (all deployments active from genesis).
    pub fn regtest() -> Self {
        let mut tracker = Self::new(vec![]);
        tracker.states.clear();
        tracker
    }

    /// Get the state of a deployment by name.
    pub fn state(&self, name: &str) -> Option<DeploymentState> {
        self.deployments
            .iter()
            .position(|d| d.name == name)
            .map(|i| self.states[i])
    }

    /// Get all deployment states as (name, state) pairs.
    pub fn all_states(&self) -> Vec<(&str, DeploymentState)> {
        self.deployments
            .iter()
            .zip(self.states.iter())
            .map(|(d, s)| (d.name, *s))
            .collect()
    }

    /// Update deployment states based on a new block at the given height and MTP.
    /// Should be called at each retarget boundary (height % 2016 == 0).
    pub fn update_states(&mut self, height: u32, median_time: u64, signal_counts: &[u32]) {
        if height % RETARGET_PERIOD != 0 {
            return;
        }

        for (i, deployment) in self.deployments.iter().enumerate() {
            let signal_count = signal_counts.get(i).copied().unwrap_or(0);
            let new_state = Self::next_state(
                self.states[i],
                deployment,
                height,
                median_time,
                signal_count,
            );
            if new_state != self.states[i] {
                debug!(
                    name = deployment.name,
                    old = ?self.states[i],
                    new = ?new_state,
                    height,
                    "Deployment state transition"
                );
                self.states[i] = new_state;
            }
        }
    }

    /// Count signaling blocks in a retarget period.
    /// Returns the number of blocks that have the deployment's bit set.
    pub fn count_signals(headers: &[Header], bit: u8) -> u32 {
        let version_mask = 1u32 << bit;
        let version_top = 0x20000000u32;
        headers
            .iter()
            .filter(|h| {
                let v = h.version.to_consensus() as u32;
                (v & version_top) == version_top && (v & version_mask) != 0
            })
            .count() as u32
    }

    /// Compute the next state for a deployment.
    fn next_state(
        current: DeploymentState,
        deployment: &Deployment,
        height: u32,
        median_time: u64,
        signal_count: u32,
    ) -> DeploymentState {
        match current {
            DeploymentState::Defined => {
                if median_time >= deployment.start_time {
                    DeploymentState::Started
                } else {
                    DeploymentState::Defined
                }
            }
            DeploymentState::Started => {
                if signal_count >= deployment.threshold {
                    DeploymentState::LockedIn
                } else if median_time >= deployment.timeout {
                    DeploymentState::Failed
                } else {
                    DeploymentState::Started
                }
            }
            DeploymentState::LockedIn => {
                // BIP 8: check min_activation_height
                if height >= deployment.min_activation_height {
                    DeploymentState::Active
                } else {
                    DeploymentState::LockedIn
                }
            }
            // Terminal states
            DeploymentState::Active => DeploymentState::Active,
            DeploymentState::Failed => DeploymentState::Failed,
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn test_deployment_state_machine() {
        let deployments = vec![Deployment {
            name: "test_deploy",
            bit: 0,
            start_time: 1000,
            timeout: 2000,
            min_activation_height: 0,
            threshold: 1916,
        }];
        let mut tracker = VersionBitsTracker::new(deployments);

        // Initially DEFINED
        assert_eq!(tracker.state("test_deploy"), Some(DeploymentState::Defined));

        // Before start_time, stays DEFINED
        tracker.update_states(2016, 500, &[0]);
        assert_eq!(tracker.state("test_deploy"), Some(DeploymentState::Defined));

        // After start_time, transitions to STARTED
        tracker.update_states(4032, 1500, &[0]);
        assert_eq!(tracker.state("test_deploy"), Some(DeploymentState::Started));

        // Without enough signals, stays STARTED
        tracker.update_states(6048, 1600, &[1000]);
        assert_eq!(tracker.state("test_deploy"), Some(DeploymentState::Started));

        // With enough signals, transitions to LOCKED_IN
        tracker.update_states(8064, 1700, &[1916]);
        assert_eq!(
            tracker.state("test_deploy"),
            Some(DeploymentState::LockedIn)
        );

        // Next period, transitions to ACTIVE
        tracker.update_states(10080, 1800, &[0]);
        assert_eq!(tracker.state("test_deploy"), Some(DeploymentState::Active));
    }

    #[test]
    fn test_deployment_timeout() {
        let deployments = vec![Deployment {
            name: "test_timeout",
            bit: 1,
            start_time: 1000,
            timeout: 2000,
            min_activation_height: 0,
            threshold: 1916,
        }];
        let mut tracker = VersionBitsTracker::new(deployments);

        // Move to STARTED
        tracker.update_states(2016, 1500, &[0]);
        assert_eq!(
            tracker.state("test_timeout"),
            Some(DeploymentState::Started)
        );

        // Timeout without lock-in → FAILED
        tracker.update_states(4032, 2500, &[0]);
        assert_eq!(tracker.state("test_timeout"), Some(DeploymentState::Failed));

        // FAILED is terminal
        tracker.update_states(6048, 3000, &[2016]);
        assert_eq!(tracker.state("test_timeout"), Some(DeploymentState::Failed));
    }

    #[test]
    fn test_min_activation_height() {
        let deployments = vec![Deployment {
            name: "test_min_height",
            bit: 2,
            start_time: 0,
            timeout: u64::MAX,
            min_activation_height: 10000,
            threshold: 1916,
        }];
        let mut tracker = VersionBitsTracker::new(deployments);

        // Immediately STARTED (start_time = 0)
        tracker.update_states(2016, 100, &[0]);
        assert_eq!(
            tracker.state("test_min_height"),
            Some(DeploymentState::Started)
        );

        // Lock in
        tracker.update_states(4032, 200, &[2016]);
        assert_eq!(
            tracker.state("test_min_height"),
            Some(DeploymentState::LockedIn)
        );

        // Below min_activation_height, stays LOCKED_IN
        tracker.update_states(6048, 300, &[0]);
        assert_eq!(
            tracker.state("test_min_height"),
            Some(DeploymentState::LockedIn)
        );

        // At or above min_activation_height, becomes ACTIVE
        tracker.update_states(10080, 400, &[0]);
        assert_eq!(
            tracker.state("test_min_height"),
            Some(DeploymentState::Active)
        );
    }

    #[test]
    fn test_mainnet_deployments() {
        let tracker = VersionBitsTracker::mainnet();
        let states = tracker.all_states();
        // BIP-110 is intentionally absent — its dynamic-activation semantics live
        // solely in `crate::bip110`, not in this generic BIP-9 tracker.
        assert_eq!(states.len(), 3);
        assert_eq!(states[0].0, "csv");
        assert_eq!(states[1].0, "segwit");
        assert_eq!(states[2].0, "taproot");
        // All start as DEFINED
        for (_, state) in &states {
            assert_eq!(*state, DeploymentState::Defined);
        }
    }
}
