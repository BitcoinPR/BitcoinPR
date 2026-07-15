use jsonrpsee::core::RpcResult;
use jsonrpsee::proc_macros::rpc;
use serde_json::Value;

/// Bitcoin Core-compatible JSON-RPC API trait.
#[rpc(server)]
pub trait BitcoinRpc {
    // --- Blockchain ---

    #[method(name = "getblockchaininfo")]
    fn get_blockchain_info(&self) -> RpcResult<Value>;

    #[method(name = "getblock")]
    fn get_block(&self, blockhash: String, verbosity: Option<u8>) -> RpcResult<Value>;

    #[method(name = "getblockhash")]
    fn get_block_hash(&self, height: u32) -> RpcResult<Value>;

    #[method(name = "getblockcount")]
    fn get_block_count(&self) -> RpcResult<u32>;

    #[method(name = "getdifficulty")]
    fn get_difficulty(&self) -> RpcResult<f64>;

    #[method(name = "getbestblockhash")]
    fn get_best_block_hash(&self) -> RpcResult<String>;

    #[method(name = "pruneblockchain")]
    fn prune_blockchain(&self, height: u32) -> RpcResult<u32>;

    #[method(name = "getchainsplitinfo")]
    fn get_chain_split_info(&self) -> RpcResult<Value>;

    #[method(name = "abandonbip110")]
    fn abandon_bip110(&self, force: Option<bool>) -> RpcResult<Value>;

    #[method(name = "invalidateblock")]
    fn invalidate_block(&self, blockhash: String) -> RpcResult<Value>;

    #[method(name = "reconsiderblock")]
    fn reconsider_block(&self, blockhash: String) -> RpcResult<Value>;

    // --- Raw transactions ---

    #[method(name = "getrawtransaction")]
    fn get_raw_transaction(&self, txid: String, verbose: Option<bool>) -> RpcResult<Value>;

    #[method(name = "sendrawtransaction")]
    fn send_raw_transaction(&self, hexstring: String) -> RpcResult<String>;

    #[method(name = "decoderawtransaction")]
    fn decode_raw_transaction(&self, hexstring: String) -> RpcResult<Value>;

    // --- UTXO ---

    #[method(name = "gettxout")]
    fn get_tx_out(&self, txid: String, n: u32, include_mempool: Option<bool>) -> RpcResult<Value>;

    // --- Mempool ---

    #[method(name = "getmempoolinfo")]
    fn get_mempool_info(&self) -> RpcResult<Value>;

    #[method(name = "getrawmempool")]
    fn get_raw_mempool(&self) -> RpcResult<Vec<String>>;

    // --- Network ---

    #[method(name = "getnetworkinfo")]
    fn get_network_info(&self) -> RpcResult<Value>;

    #[method(name = "getpeerinfo")]
    fn get_peer_info(&self) -> RpcResult<Value>;

    #[method(name = "getconnectioncount")]
    fn get_connection_count(&self) -> RpcResult<usize>;

    // --- Util ---

    #[method(name = "validateaddress")]
    fn validate_address(&self, address: String) -> RpcResult<Value>;

    #[method(name = "estimatesmartfee")]
    fn estimate_smart_fee(&self, conf_target: u32) -> RpcResult<Value>;

    // --- Mining ---

    #[method(name = "getblocktemplate")]
    fn get_block_template(&self, request: Option<Value>) -> RpcResult<Value>;

    #[method(name = "submitblock")]
    fn submit_block(&self, hexdata: String) -> RpcResult<Value>;

    #[method(name = "getmininginfo")]
    fn get_mining_info(&self) -> RpcResult<Value>;

    #[method(name = "generatetoaddress")]
    fn generate_to_address(&self, nblocks: u32, address: String) -> RpcResult<Vec<String>>;

    // --- Control ---

    #[method(name = "stop")]
    fn stop(&self) -> RpcResult<String>;

    #[method(name = "help")]
    fn help(&self, command: Option<String>) -> RpcResult<String>;

    #[method(name = "getindexinfo")]
    fn get_index_info(&self) -> RpcResult<Value>;

    #[method(name = "uptime")]
    fn uptime(&self) -> RpcResult<u64>;
}
