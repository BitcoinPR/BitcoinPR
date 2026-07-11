use thiserror::Error;

#[derive(Debug, Error)]
pub enum P2pError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("connection error: {0}")]
    Connection(String),

    #[error("protocol error: {0}")]
    Protocol(String),

    #[error("handshake failed: {0}")]
    HandshakeFailed(String),

    #[error("timeout: {0}")]
    Timeout(String),

    #[error("peer banned: {0}")]
    PeerBanned(String),

    #[error("serialization error: {0}")]
    Serialization(String),

    #[error("dns resolution failed: {0}")]
    DnsResolution(String),
}

pub type P2pResult<T> = Result<T, P2pError>;
