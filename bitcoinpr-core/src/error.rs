use bitcoin::BlockHash;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CoreError {
    #[error("block not found: {0}")]
    BlockNotFound(BlockHash),

    #[error("invalid proof of work")]
    InvalidProofOfWork,

    #[error("invalid block hash: expected {expected}, got {got}")]
    InvalidBlockHash { expected: BlockHash, got: BlockHash },

    #[error("invalid merkle root")]
    InvalidMerkleRoot,

    #[error("invalid timestamp: {0}")]
    InvalidTimestamp(String),

    #[error("invalid difficulty target: {0}")]
    InvalidDifficultyTarget(String),

    #[error("invalid block: {0}")]
    InvalidBlock(String),

    #[error("invalid transaction: {0}")]
    InvalidTransaction(String),

    #[error("invalid script: {0}")]
    InvalidScript(String),

    #[error("missing input UTXO: {0}")]
    MissingUtxo(String),

    #[error("double spend detected: {0}")]
    DoubleSpend(String),

    #[error("invalid coinbase: {0}")]
    InvalidCoinbase(String),

    #[error("block weight exceeds limit: {weight} > {limit}")]
    BlockWeightExceeded { weight: u64, limit: u32 },

    #[error("invalid block subsidy: expected {expected}, got {got}")]
    InvalidSubsidy { expected: u64, got: u64 },

    /// Undo data for a block is absent. Distinct from [`CoreError::Storage`]
    /// so callers can tell "corruption — fail closed" apart from a transient
    /// I/O failure without string matching; once block pruning lands, a
    /// pruned-undo variant of this condition becomes an *expected* state that
    /// must refuse with re-sync guidance instead of rebuilding from recovery.
    #[error("undo data missing for block {hash} at height {height} — cannot disconnect; UTXO set would be corrupted (recover via forward re-sync)")]
    UndoMissing { hash: BlockHash, height: u32 },

    /// Typed storage-layer failure (M6, 2026-07-02 review): carries the
    /// full `StorageError` (with its `source()` chain) instead of a flattened
    /// string, so callers can distinguish transient I/O from corruption.
    #[error("storage error: {0}")]
    Storage(#[from] bitcoinpr_storage::StorageError),

    /// Chain context needed for a consensus check could not be loaded (e.g.
    /// MTP prev-header or retarget ancestors missing from the header index).
    /// Deliberately fail-closed and distinct from [`CoreError::Storage`]: the
    /// data is absent, not failing to read — the block can be retried once
    /// headers arrive.
    #[error("chain context unavailable: {0}")]
    ChainContext(String),
}

pub type CoreResult<T> = Result<T, CoreError>;
