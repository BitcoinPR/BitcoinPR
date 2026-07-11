use serde::{Deserialize, Serialize};
use serde_json::Value;

/// SV2 Template Distribution Protocol message types.
///
/// These are the wire formats per the Stratum V2 specification (sections 7.1–7.7).
/// Transport uses newline-delimited JSON over TCP; binary Noise-encrypted
/// framing can be added as a future enhancement.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "method", content = "params")]
pub enum Sv2Message {
    /// 7.1: Client indicates coinbase output constraints.
    CoinbaseOutputConstraints {
        coinbase_output_max_additional_size: u32,
        coinbase_output_max_additional_sigops: u16,
    },
    /// 7.2: Server provides a new block template.
    NewTemplate {
        template_id: u64,
        future_template: bool,
        version: u32,
        coinbase_tx_version: u32,
        coinbase_prefix: String,
        coinbase_tx_input_sequence: u32,
        coinbase_tx_value_remaining: u64,
        coinbase_tx_outputs_count: u32,
        coinbase_tx_outputs: String,
        coinbase_tx_locktime: u32,
        merkle_path: Vec<String>,
    },
    /// 7.3: Server notifies of new previous block hash.
    SetNewPrevHash {
        template_id: u64,
        prev_hash: String,
        header_timestamp: u32,
        n_bits: u32,
        target: String,
    },
    /// 7.4: Client requests transaction data for a template.
    RequestTransactionData { template_id: u64 },
    /// 7.5: Server responds with transaction data.
    RequestTransactionDataSuccess {
        template_id: u64,
        excess_data: String,
        transaction_list: Vec<String>,
    },
    /// 7.6: Server responds with an error for transaction data request.
    RequestTransactionDataError {
        template_id: u64,
        error_code: String,
    },
    /// 7.7: Client submits a mining solution.
    SubmitSolution {
        template_id: u64,
        version: u32,
        header_timestamp: u32,
        header_nonce: u32,
        coinbase_tx: String,
    },
}

/// Connection setup message.
///
/// In the full SV2 specification, the connection is established through a Noise_NX
/// handshake (Noise Protocol Framework with pattern NX, using secp256k1 and
/// ChaChaPoly). This requires the `noise-protocol` crate and a Certificate
/// Authority. The current implementation uses a plaintext JSON-RPC setup with
/// ECDH key agreement: the server generates an ephemeral secp256k1 keypair and
/// sends the public key in `SetupConnectionSuccess`. A full Noise_NX upgrade
/// would replace this struct-based exchange with a 3-message handshake:
///   -> e                   (initiator ephemeral key)
///   <- e, ee, s, es        (responder ephemeral + static keys, encrypted)
///   -> s, se               (initiator static key, encrypted)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetupConnection {
    pub protocol: u8,
    pub min_version: u16,
    pub max_version: u16,
    pub flags: u32,
    pub endpoint_host: String,
    pub endpoint_port: u16,
    pub vendor: String,
    pub hardware_version: String,
    pub firmware: String,
    pub device_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetupConnectionSuccess {
    pub used_version: u16,
    pub flags: u32,
}

// ---------------------------------------------------------------------------
// Stratum V1 (JSON-RPC) types
// ---------------------------------------------------------------------------

/// Generic JSON-RPC request (Stratum V1 wire format).
#[derive(Debug, Clone, Deserialize)]
pub struct JsonRpcRequest {
    pub id: Option<Value>,
    pub method: String,
    #[serde(default)]
    pub params: Value,
}

/// Generic JSON-RPC response.
#[derive(Debug, Clone, Serialize)]
pub struct JsonRpcResponse {
    pub id: Option<Value>,
    pub result: Value,
    pub error: Option<Value>,
}

/// Server-initiated JSON-RPC notification (no id).
#[derive(Debug, Clone, Serialize)]
pub struct JsonRpcNotification {
    pub id: Option<Value>,
    pub method: String,
    pub params: Value,
}

// ---------------------------------------------------------------------------
// Datum protocol types (JSON over TLS, newline-delimited)
// ---------------------------------------------------------------------------

/// A coinbase output the pool requires the miner to include.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoinbaseOutputSpec {
    /// Fraction of the coinbase value (e.g. 0.02 for a 2% pool fee).
    pub value_fraction: f64,
    pub script_pubkey_hex: String,
    /// "pool_fee", "payout_commitment", etc.
    pub label: String,
}

/// Datum protocol messages. JSON, newline-delimited, sent over TLS.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "method", content = "params")]
pub enum DatumMessage {
    // Client -> Server
    Handshake {
        protocol_version: u16,
        worker_name: String,
        payout_address: String,
        auth_token: Option<String>,
        user_agent: String,
    },
    SubmitShare {
        session_id: String,
        template_height: u32,
        header_hash: String,
        nonce: u32,
        ntime: u32,
        coinbase_tx: String,
        difficulty: f64,
    },
    TemplateUpdate {
        height: u32,
        prev_hash: String,
        coinbase_value: u64,
        tx_count: u32,
    },
    // Server -> Client
    ServerHello {
        protocol_version: u16,
        session_id: String,
        pool_name: String,
        pool_difficulty: f64,
        coinbase_outputs: Vec<CoinbaseOutputSpec>,
        payout_scheme: String,
    },
    CoinbaseOutputUpdate {
        coinbase_outputs: Vec<CoinbaseOutputSpec>,
    },
    ShareResult {
        accepted: bool,
        reason: Option<String>,
        pool_hashrate: Option<f64>,
    },
    PayoutNotification {
        txid: String,
        amount: u64,
        block_height: u32,
    },
    Error {
        code: u32,
        message: String,
    },
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod datum_tests {
    use super::*;

    #[test]
    fn handshake_json_round_trip() {
        let msg = DatumMessage::Handshake {
            protocol_version: 1,
            worker_name: "worker1".to_string(),
            payout_address: "bc1qexample".to_string(),
            auth_token: Some("token".to_string()),
            user_agent: "BitcoinPR/0.1".to_string(),
        };
        let json = serde_json::to_string(&msg).unwrap();
        let back: DatumMessage = serde_json::from_str(&json).unwrap();
        match back {
            DatumMessage::Handshake {
                protocol_version,
                worker_name,
                payout_address,
                auth_token,
                user_agent,
            } => {
                assert_eq!(protocol_version, 1);
                assert_eq!(worker_name, "worker1");
                assert_eq!(payout_address, "bc1qexample");
                assert_eq!(auth_token.as_deref(), Some("token"));
                assert_eq!(user_agent, "BitcoinPR/0.1");
            }
            _ => panic!("expected Handshake variant"),
        }
    }

    #[test]
    fn server_hello_json_round_trip() {
        let msg = DatumMessage::ServerHello {
            protocol_version: 1,
            session_id: "sess-123".to_string(),
            pool_name: "ocean".to_string(),
            pool_difficulty: 1024.0,
            coinbase_outputs: vec![CoinbaseOutputSpec {
                value_fraction: 0.02,
                script_pubkey_hex: "0014abcd".to_string(),
                label: "pool_fee".to_string(),
            }],
            payout_scheme: "TIDES".to_string(),
        };
        let json = serde_json::to_string(&msg).unwrap();
        let back: DatumMessage = serde_json::from_str(&json).unwrap();
        match back {
            DatumMessage::ServerHello {
                protocol_version,
                session_id,
                pool_name,
                pool_difficulty,
                coinbase_outputs,
                payout_scheme,
            } => {
                assert_eq!(protocol_version, 1);
                assert_eq!(session_id, "sess-123");
                assert_eq!(pool_name, "ocean");
                assert_eq!(pool_difficulty, 1024.0);
                assert_eq!(coinbase_outputs.len(), 1);
                assert_eq!(coinbase_outputs[0].label, "pool_fee");
                assert_eq!(payout_scheme, "TIDES");
            }
            _ => panic!("expected ServerHello variant"),
        }
    }
}
