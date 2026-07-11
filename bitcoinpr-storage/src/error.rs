use thiserror::Error;

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("database error: {0}")]
    Database(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("serialization error: {0}")]
    Serialization(String),

    #[error("key not found: {0}")]
    NotFound(String),

    #[error("rocksdb error: {0}")]
    RocksDb(#[from] rocksdb::Error),

    #[error("missing column family: {0} (database created by an incompatible version?)")]
    MissingColumnFamily(String),
}

pub type StorageResult<T> = Result<T, StorageError>;
