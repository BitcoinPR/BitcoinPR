use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct BlockchainInfo {
    pub chain: String,
    pub blocks: u32,
    pub headers: u32,
    pub bestblockhash: String,
    pub difficulty: f64,
    #[serde(rename = "verificationprogress")]
    pub verification_progress: f64,
    pub initialblockdownload: bool,
    pub pruned: bool,
    /// Lowest-height complete block stored; present only when `pruned`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pruneheight: Option<u32>,
    pub warnings: String,
}

#[derive(Debug, Serialize)]
pub struct BlockInfo {
    pub hash: String,
    pub confirmations: i64,
    pub height: u32,
    pub version: i32,
    #[serde(rename = "versionHex")]
    pub version_hex: String,
    pub merkleroot: String,
    pub time: u32,
    pub nonce: u32,
    pub bits: String,
    pub difficulty: f64,
    #[serde(rename = "nTx")]
    pub n_tx: usize,
    pub previousblockhash: Option<String>,
    pub size: usize,
    pub weight: u64,
}

#[derive(Debug, Serialize)]
pub struct MempoolInfo {
    pub loaded: bool,
    pub size: usize,
    pub bytes: usize,
    pub usage: usize,
    pub total_fee: f64,
}

#[derive(Debug, Serialize)]
pub struct NetworkInfo {
    pub version: u32,
    pub subversion: String,
    #[serde(rename = "protocolversion")]
    pub protocol_version: u32,
    pub connections: usize,
    pub connections_in: usize,
    pub connections_out: usize,
    /// Network-adjusted time offset from the local clock, in seconds (Core's
    /// `nTimeOffset` median over peer `version` timestamps).
    pub timeoffset: i64,
    pub networks: Vec<serde_json::Value>,
    /// Addresses this node advertises as its own (IP / `.onion` / `.b32.i2p`).
    #[serde(rename = "localaddresses")]
    pub local_addresses: Vec<serde_json::Value>,
    pub warnings: String,
}

#[derive(Debug, Serialize)]
pub struct PeerInfoEntry {
    pub id: u64,
    pub addr: String,
    /// Reachable-network class of `addr`: `ipv4`, `ipv6`, `onion`, or `i2p`
    /// (Bitcoin Core's `getpeerinfo` `network` field).
    pub network: String,
    pub version: u32,
    pub subver: String,
    pub startingheight: i32,
    pub synced_headers: i32,
    pub synced_blocks: i32,
    /// Whether the peer initiated the connection to us (true) or we connected
    /// out to them (false). Bitcoin Core/Knots populate this; monitoring tools
    /// and the explorer use it to distinguish inbound from outbound peers.
    pub inbound: bool,
}
