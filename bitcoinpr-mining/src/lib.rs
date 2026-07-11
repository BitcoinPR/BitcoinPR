#![warn(clippy::unwrap_used)]

pub mod config;
pub mod datum;
pub mod protocol;
pub mod shares;
pub mod stats;
pub mod template_provider;

pub use config::{DatumConfig, MiningConfig, MiningMode};
pub use datum::{CoinbaseOutput, DatumClient, DatumShare, DatumStatus, PayoutInfo};
pub use protocol::{CoinbaseOutputSpec, DatumMessage};
pub use shares::ShareTracker;
pub use stats::{MiningDashboard, MiningStatsSnapshot, WorkerInfo};
pub use template_provider::TemplateProvider;
