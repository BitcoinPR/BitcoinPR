#![warn(clippy::unwrap_used)]

pub mod bip110;
pub mod block_filter;
pub mod chain;
pub mod compact_block;
pub mod consensus;
pub mod error;
pub mod events;
pub mod mempool;
pub mod merkle;
pub mod script;
pub mod time;
pub mod validation;
pub mod versionbits;

pub use bip110::{
    activation_at as bip110_activation_at, Bip110Activation, Bip110Checker, Bip110Deployment,
    ThresholdState,
};
pub use chain::ChainState;
pub use consensus::ConsensusParams;
pub use error::{CoreError, CoreResult};
pub use events::{EventBus, NodeNotification};
pub use mempool::{
    FeeEstimator, Mempool, MempoolChainContext, MempoolEntry, DEFAULT_MAX_MEMPOOL_BYTES,
};
pub use script::{count_sigops, ScriptFlags, SigCache};
pub use validation::{
    add_chain_work, calculate_next_work_required, calculate_work, compact_target_to_difficulty,
    compute_merkle_root, get_median_time_past, is_final_tx, sequence_lock_points,
    validate_block_header, validate_block_weight, validate_coinbase, validate_sequence_locks,
    validate_witness_commitment, verify_merkle_root, verify_merkle_root_with_txids,
};
