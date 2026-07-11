use crate::events::NodeNotification;
use crate::scripthash::ScripthashIndex;
use bitcoin::consensus::encode;
use bitcoin::hashes::{sha256, sha256d, Hash};
use bitcoin::Transaction;
use bitcoinpr_core::{ConsensusParams, Mempool, ScriptFlags, SigCache};
use bitcoinpr_p2p::PeerCommand;
use bitcoinpr_storage::{BlockStore, HeaderIndex, TxIndex, UtxoSet};
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tokio::sync::{broadcast, mpsc, RwLock};
use tokio::time::{interval, Duration};
use tracing::{debug, info, warn};

const SERVER_VERSION: &str = concat!("BitcoinPR/", env!("CARGO_PKG_VERSION"));
const PROTOCOL_VERSION: &str = "1.4";

/// How far the validated block tip may trail the downloaded header tip before
/// the node is treated as still catching up (and per-block client notifications
/// are suppressed). See [`is_catching_up`].
const IBD_NOTIFY_MARGIN: u32 = 4;

/// Whether the node is still catching up to the chain tip, judged live from the
/// gap between the downloaded header tip and `block_height`.
///
/// This intentionally does NOT consult the `is_ibd` latch: that flag is set once
/// at startup and only ever cleared, so it can drop to `false` before the chain
/// is actually synced and then never re-arm — which would flood subscribed
/// Electrum wallets with a header/status update for every block for the rest of
/// IBD (and, with a stuck-`true` latch, would conversely suppress the keepalive
/// heartbeat forever). The header-tip-vs-block-tip gap is self-correcting and
/// mirrors how the RPC layer reports IBD for `getblockchaininfo`.
fn is_catching_up(state: &ElectrumState, block_height: u32) -> bool {
    let header_tip = state
        .header_index
        .get_header_tip_height()
        .ok()
        .flatten()
        .unwrap_or(0);
    header_tip.saturating_sub(block_height) > IBD_NOTIFY_MARGIN
}

/// Shared node state passed to each Electrum client handler.
#[derive(Clone)]
pub struct ElectrumState {
    pub index: Arc<ScripthashIndex>,
    pub header_index: Arc<HeaderIndex>,
    pub block_store: Arc<BlockStore>,
    pub tx_index: Option<Arc<TxIndex>>,
    pub mempool: Arc<RwLock<Mempool>>,
    pub utxo_set: Option<Arc<UtxoSet>>,
    pub sig_cache: Arc<SigCache>,
    pub best_height: Arc<RwLock<u32>>,
    pub params: ConsensusParams,
    pub command_tx: Option<mpsc::Sender<PeerCommand>>,
    pub is_ibd: Arc<AtomicBool>,
    /// MOTD banner returned by the `server.banner` Electrum method.
    pub banner: String,
}

/// Transport configuration for the Electrum server.
#[derive(Clone, Debug)]
pub struct ElectrumConfig {
    /// Plain-text TCP listen port.
    pub tcp_port: u16,
    /// SSL/TLS listen port.
    pub ssl_port: u16,
    /// Path to a PEM-encoded TLS certificate chain. When `None`, a self-signed
    /// certificate is generated at startup.
    pub tls_cert_path: Option<PathBuf>,
    /// Path to the PEM-encoded private key matching `tls_cert_path`.
    pub tls_key_path: Option<PathBuf>,
    /// Directory in which a generated self-signed TLS keypair is persisted
    /// (`electrum-tls.crt` / `electrum-tls.key`) so TOFU clients that pin the
    /// certificate survive restarts. `None` falls back to regenerating an
    /// in-memory certificate every startup. Ignored when explicit
    /// `tls_cert_path`/`tls_key_path` are configured.
    pub tls_datadir: Option<PathBuf>,
}

impl Default for ElectrumConfig {
    fn default() -> Self {
        ElectrumConfig {
            tcp_port: 50001,
            ssl_port: 50002,
            tls_cert_path: None,
            tls_key_path: None,
            tls_datadir: None,
        }
    }
}

/// A lightweight Electrum-protocol TCP server backed by the scripthash index.
/// Listens on two ports: plain TCP (default 50001) and SSL/TLS (default 50002).
pub struct ElectrumServer {
    state: ElectrumState,
    event_sender: broadcast::Sender<NodeNotification>,
    config: ElectrumConfig,
}

#[derive(Deserialize)]
struct JsonRpcRequest {
    id: Value,
    method: String,
    #[serde(default)]
    params: Vec<Value>,
}

/// Parse a single Electrum JSON-RPC request line, returning the method name on
/// success. Exposed `#[doc(hidden)]` so the fuzz harness can exercise the line
/// parser against arbitrary input without spinning up an `ElectrumServer`.
#[doc(hidden)]
pub fn fuzz_parse_request_line(line: &str) -> Option<String> {
    serde_json::from_str::<JsonRpcRequest>(line)
        .ok()
        .map(|r| r.method)
}

impl ElectrumServer {
    pub fn new(
        state: ElectrumState,
        event_sender: broadcast::Sender<NodeNotification>,
        config: ElectrumConfig,
    ) -> Self {
        ElectrumServer {
            state,
            event_sender,
            config,
        }
    }

    pub async fn run(&self) -> anyhow::Result<()> {
        // Start plain TCP listener
        let tcp_listener = TcpListener::bind(("0.0.0.0", self.config.tcp_port)).await?;
        info!(port = self.config.tcp_port, "Electrum TCP server listening");

        // Load the TLS certificate from disk when configured, otherwise generate
        // a self-signed one. Start the dedicated SSL listener on success.
        let tls_acceptor = match build_tls_acceptor(
            self.config.tls_cert_path.as_deref(),
            self.config.tls_key_path.as_deref(),
            self.config.tls_datadir.as_deref(),
        ) {
            Ok(acceptor) => {
                let source = if self.config.tls_cert_path.is_some() {
                    "configured certificate"
                } else {
                    "self-signed certificate"
                };
                info!(
                    port = self.config.ssl_port,
                    source, "Electrum SSL server listening"
                );
                Some(acceptor)
            }
            Err(e) => {
                warn!(error = %e, "Failed to load TLS certificate, SSL disabled");
                None
            }
        };

        let ssl_listener = if tls_acceptor.is_some() {
            match TcpListener::bind(("0.0.0.0", self.config.ssl_port)).await {
                Ok(l) => Some(l),
                Err(e) => {
                    warn!(port = self.config.ssl_port, error = %e, "Failed to bind SSL port");
                    None
                }
            }
        } else {
            None
        };

        loop {
            tokio::select! {
                // Accept on TCP port — auto-detect TLS vs plain
                result = tcp_listener.accept() => {
                    let (stream, addr) = result?;
                    let acceptor = tls_acceptor.clone();
                    let state = self.state.clone();
                    let event_sender = self.event_sender.clone();
                    let event_rx = self.event_sender.subscribe();
                    tokio::spawn(async move {
                        info!(%addr, "Electrum client connecting (tcp port)");
                        if let Err(e) = handle_connection(stream, addr, acceptor, state, event_sender, event_rx).await {
                            info!(%addr, error = %e, "Electrum client disconnected (tcp port)");
                        }
                    });
                }

                // Accept on dedicated SSL port — always TLS
                result = async {
                    match (&ssl_listener, &tls_acceptor) {
                        (Some(listener), Some(_)) => listener.accept().await,
                        _ => std::future::pending().await,
                    }
                } => {
                    let (stream, addr) = result?;
                    let acceptor = tls_acceptor
                        .as_ref()
                        .expect("SSL accept arm only runs when a TLS acceptor exists")
                        .clone();
                    let state = self.state.clone();
                    let event_sender = self.event_sender.clone();
                    let event_rx = self.event_sender.subscribe();
                    tokio::spawn(async move {
                        match acceptor.accept(stream).await {
                            Ok(tls_stream) => {
                                info!(%addr, "Electrum SSL client connected");
                                if let Err(e) = handle_client(tls_stream, state, event_sender, event_rx).await {
                                    info!(%addr, error = %e, "Electrum SSL client disconnected");
                                }
                            }
                            Err(e) => {
                                warn!(%addr, error = %e, "TLS handshake failed");
                            }
                        }
                    });
                }
            }
        }
    }
}

/// Accept a connection on the TCP port, auto-detecting TLS vs plain text.
///
/// Peeks at the first byte: `0x16` indicates a TLS ClientHello, anything
/// else (typically `{` for JSON-RPC) is plain text.
async fn handle_connection(
    stream: tokio::net::TcpStream,
    addr: std::net::SocketAddr,
    tls_acceptor: Option<tokio_rustls::TlsAcceptor>,
    state: ElectrumState,
    event_sender: broadcast::Sender<NodeNotification>,
    event_rx: broadcast::Receiver<NodeNotification>,
) -> anyhow::Result<()> {
    let mut peek_buf = [0u8; 1];
    stream.peek(&mut peek_buf).await?;

    if peek_buf[0] == 0x16 {
        // TLS ClientHello detected
        if let Some(acceptor) = tls_acceptor {
            debug!(%addr, first_byte = format!("0x{:02x}", peek_buf[0]), "Detected TLS ClientHello, upgrading");
            let tls_stream = acceptor.accept(stream).await?;
            handle_client(tls_stream, state, event_sender, event_rx).await
        } else {
            warn!(%addr, "Client sent TLS but no TLS acceptor configured");
            anyhow::bail!("Client sent TLS but no TLS acceptor available");
        }
    } else {
        // Plain text JSON-RPC
        debug!(%addr, first_byte = format!("0x{:02x}", peek_buf[0]), "Plain TCP Electrum connection");
        handle_client(stream, state, event_sender, event_rx).await
    }
}

/// Build a TLS acceptor, loading the certificate/key from disk when both paths
/// are provided. With no configured paths, a self-signed pair is persisted in
/// (and reloaded from) `datadir` so the certificate stays stable across
/// restarts; without a datadir it is regenerated in memory each startup.
fn build_tls_acceptor(
    cert_path: Option<&Path>,
    key_path: Option<&Path>,
    datadir: Option<&Path>,
) -> anyhow::Result<tokio_rustls::TlsAcceptor> {
    match (cert_path, key_path) {
        (Some(cert), Some(key)) => load_tls_from_files(cert, key),
        (Some(_), None) | (None, Some(_)) => Err(anyhow::anyhow!(
            "both --electrumcert and --electrumkey must be set to use a custom TLS certificate"
        )),
        (None, None) => match datadir {
            Some(dir) => load_or_create_persistent_tls(dir),
            None => generate_self_signed_tls(),
        },
    }
}

/// Default filenames for the persisted self-signed Electrum TLS keypair.
const TLS_CERT_FILE: &str = "electrum-tls.crt";
const TLS_KEY_FILE: &str = "electrum-tls.key";

/// Load the persisted self-signed keypair from `dir`, generating and writing
/// it first if missing or unreadable. Keeping the same certificate across
/// restarts matters because Electrum clients pin it on first use (TOFU).
fn load_or_create_persistent_tls(dir: &Path) -> anyhow::Result<tokio_rustls::TlsAcceptor> {
    let cert_path = dir.join(TLS_CERT_FILE);
    let key_path = dir.join(TLS_KEY_FILE);

    if cert_path.exists() && key_path.exists() {
        match load_tls_from_files(&cert_path, &key_path) {
            Ok(acceptor) => {
                info!(cert = %cert_path.display(), "Loaded persisted Electrum TLS certificate");
                return Ok(acceptor);
            }
            Err(e) => {
                warn!(error = %e, cert = %cert_path.display(),
                    "Persisted Electrum TLS keypair unreadable, regenerating");
            }
        }
    }

    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])?;
    let cert_pem = cert.cert.pem();
    let key_pem = cert.key_pair.serialize_pem();

    std::fs::create_dir_all(dir)
        .map_err(|e| anyhow::anyhow!("creating TLS dir {}: {}", dir.display(), e))?;
    std::fs::write(&cert_path, cert_pem)
        .map_err(|e| anyhow::anyhow!("writing TLS cert {}: {}", cert_path.display(), e))?;

    // The private key must not be world-readable: create it with mode 0600.
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&key_path)
            .map_err(|e| anyhow::anyhow!("writing TLS key {}: {}", key_path.display(), e))?;
        f.write_all(key_pem.as_bytes())?;
    }
    #[cfg(not(unix))]
    std::fs::write(&key_path, &key_pem)
        .map_err(|e| anyhow::anyhow!("writing TLS key {}: {}", key_path.display(), e))?;

    info!(cert = %cert_path.display(), "Generated and persisted self-signed Electrum TLS keypair");
    load_tls_from_files(&cert_path, &key_path)
}

/// Load a PEM-encoded certificate chain and private key from disk.
fn load_tls_from_files(
    cert_path: &Path,
    key_path: &Path,
) -> anyhow::Result<tokio_rustls::TlsAcceptor> {
    use rustls::ServerConfig;
    use rustls_pki_types::pem::PemObject;

    let cert_pem = std::fs::read(cert_path)
        .map_err(|e| anyhow::anyhow!("reading TLS cert {}: {}", cert_path.display(), e))?;
    let key_pem = std::fs::read(key_path)
        .map_err(|e| anyhow::anyhow!("reading TLS key {}: {}", key_path.display(), e))?;

    let certs: Vec<rustls::pki_types::CertificateDer<'static>> =
        rustls_pki_types::CertificateDer::pem_slice_iter(&cert_pem)
            .collect::<Result<Vec<_>, _>>()?;
    if certs.is_empty() {
        return Err(anyhow::anyhow!(
            "no certificates found in {}",
            cert_path.display()
        ));
    }

    let key = rustls_pki_types::PrivateKeyDer::from_pem_slice(&key_pem)
        .map_err(|e| anyhow::anyhow!("no private key found in {}: {}", key_path.display(), e))?;

    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;

    Ok(tokio_rustls::TlsAcceptor::from(Arc::new(config)))
}

/// Generate a self-signed TLS certificate and return a TLS acceptor.
fn generate_self_signed_tls() -> anyhow::Result<tokio_rustls::TlsAcceptor> {
    use rustls::ServerConfig;
    use rustls_pki_types::pem::PemObject;

    // Generate self-signed certificate using rcgen
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])?;
    let cert_pem = cert.cert.pem();
    let key_pem = cert.key_pair.serialize_pem();

    // Parse certificate
    let certs: Vec<rustls::pki_types::CertificateDer<'static>> =
        rustls_pki_types::CertificateDer::pem_slice_iter(cert_pem.as_bytes())
            .collect::<Result<Vec<_>, _>>()?;

    // Parse private key
    let key = rustls_pki_types::PrivateKeyDer::from_pem_slice(key_pem.as_bytes())
        .map_err(|e| anyhow::anyhow!("No private key found in PEM: {e}"))?;

    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;

    Ok(tokio_rustls::TlsAcceptor::from(Arc::new(config)))
}

/// Per-client connection handler: reads JSON-RPC requests and pushes event
/// notifications for active subscriptions.
///
/// Generic over the stream type so it works with both plain TCP and TLS.
async fn handle_client<S>(
    stream: S,
    state: ElectrumState,
    event_sender: broadcast::Sender<NodeNotification>,
    mut event_rx: broadcast::Receiver<NodeNotification>,
) -> anyhow::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (reader, mut writer) = tokio::io::split(stream);
    let reader = BufReader::new(reader);
    let mut lines = reader.lines();

    let mut subscribed_scripthashes: HashSet<[u8; 32]> = HashSet::new();
    let mut headers_subscribed = false;
    // Periodic heartbeat: re-send the current best header to clients that have
    // subscribed to blockchain.headers.subscribe but haven't received a NewBlock
    // notification recently.  Electrum 3.x treats a server as "failed" and
    // disconnects with SERVER_RETRY_INTERVAL=10s when it hears nothing from the
    // server after the initial subscribe burst.  Sending the current header every
    // 45 seconds keeps the connection marked as live without spamming the client.
    let mut heartbeat = interval(Duration::from_secs(45));
    heartbeat.tick().await; // consume the immediate first tick

    loop {
        tokio::select! {
            line_result = lines.next_line() => {
                match line_result {
                    Ok(Some(line)) => {
                        let response = process_request(
                            &line,
                            &state,
                            &event_sender,
                            &mut subscribed_scripthashes,
                            &mut headers_subscribed,
                        ).await;
                        writer.write_all(response.as_bytes()).await?;
                        writer.write_all(b"\n").await?;
                        writer.flush().await?;
                    }
                    Ok(None) => break,
                    Err(e) => {
                        debug!(error = %e, "Read error from Electrum client");
                        break;
                    }
                }
            }

            event = event_rx.recv() => {
                match event {
                    Ok(NodeNotification::NewBlock { hash, height }) => {
                        // Suppress rapid-fire notifications while catching up to
                        // avoid flooding clients and causing connection
                        // instability. Judged live from the header/block gap, not
                        // the `is_ibd` latch (which can clear early and never
                        // re-arm).
                        if is_catching_up(&state, height) {
                            continue;
                        }
                        if headers_subscribed {
                            // Electrum protocol requires the raw 80-byte header hex
                            let header_hex = if let Ok(block_hash) = hash.parse::<bitcoin::BlockHash>() {
                                if let Ok(Some(stored)) = state.header_index.get_header(&block_hash) {
                                    hex::encode(encode::serialize(&stored.header))
                                } else {
                                    hash.clone()
                                }
                            } else {
                                hash.clone()
                            };
                            let notification = json!({
                                "jsonrpc": "2.0",
                                "method": "blockchain.headers.subscribe",
                                "params": [{"height": height, "hex": header_hex}]
                            });
                            writer.write_all(notification.to_string().as_bytes()).await?;
                            writer.write_all(b"\n").await?;
                        }

                        for sh in &subscribed_scripthashes {
                            if let Some(status) = compute_scripthash_status(&state, sh).await {
                                let notification = json!({
                                    "jsonrpc": "2.0",
                                    "method": "blockchain.scripthash.subscribe",
                                    "params": [hex::encode(sh), status]
                                });
                                writer.write_all(notification.to_string().as_bytes()).await?;
                                writer.write_all(b"\n").await?;
                            }
                        }

                        writer.flush().await?;
                    }
                    Ok(NodeNotification::NewTx { txid }) => {
                        // Suppress while catching up to mirror NewBlock behaviour
                        // and avoid flooding clients; mempool txs during IBD are
                        // unusual anyway. Gauged from the current block tip.
                        if is_catching_up(&state, *state.best_height.read().await) {
                            continue;
                        }
                        if subscribed_scripthashes.is_empty() {
                            continue;
                        }

                        // Resolve the tx and collect every scripthash it touches
                        // (outputs paid to + resolved-prevout inputs spent from).
                        let parsed: Option<bitcoin::Txid> = txid.parse().ok();
                        let tx = match parsed {
                            Some(id) => {
                                let mempool = state.mempool.read().await;
                                mempool.get(&id).map(|e| e.tx.clone())
                            }
                            None => None,
                        };

                        if let Some(tx) = tx {
                            let snapshot = mempool_snapshot(&state).await;
                            let mut affected: HashSet<[u8; 32]> = HashSet::new();
                            for output in &tx.output {
                                affected.insert(ScripthashIndex::compute_scripthash(
                                    output.script_pubkey.as_bytes(),
                                ));
                            }
                            for input in &tx.input {
                                if input.previous_output.is_null() {
                                    continue;
                                }
                                if let Some((script, _value)) =
                                    resolve_prevout(&input.previous_output, &snapshot, &state)
                                {
                                    affected.insert(ScripthashIndex::compute_scripthash(&script));
                                }
                            }

                            for sh in affected.iter() {
                                if !subscribed_scripthashes.contains(sh) {
                                    continue;
                                }
                                if let Some(status) = compute_scripthash_status(&state, sh).await {
                                    let notification = json!({
                                        "jsonrpc": "2.0",
                                        "method": "blockchain.scripthash.subscribe",
                                        "params": [hex::encode(sh), status]
                                    });
                                    writer.write_all(notification.to_string().as_bytes()).await?;
                                    writer.write_all(b"\n").await?;
                                }
                            }
                            writer.flush().await?;
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        warn!(missed = n, "Electrum client lagged behind event bus, re-checking subscriptions");
                        // Re-notify all subscribed scripthashes since we missed events
                        for sh in &subscribed_scripthashes {
                            if let Some(status) = compute_scripthash_status(&state, sh).await {
                                let notification = json!({
                                    "jsonrpc": "2.0",
                                    "method": "blockchain.scripthash.subscribe",
                                    "params": [hex::encode(sh), status]
                                });
                                writer.write_all(notification.to_string().as_bytes()).await?;
                                writer.write_all(b"\n").await?;
                            }
                        }
                        writer.flush().await?;
                    }
                    Err(broadcast::error::RecvError::Closed) => break,
                    _ => {}
                }
            }

            _ = heartbeat.tick() => {
                // Heartbeat: re-push the current header to any client that has
                // subscribed so the connection is seen as live.  Without this,
                // Electrum 3.x marks the server as failed ~10 s after the
                // initial subscribe burst when no blocks arrive (regtest).
                let best_h = *state.best_height.read().await;
                if headers_subscribed && !is_catching_up(&state, best_h) {
                    let header_hex = state.header_index
                        .get_hash_at_height(best_h)
                        .ok()
                        .flatten()
                        .and_then(|bh| state.header_index.get_header(&bh).ok().flatten())
                        .map(|s| hex::encode(encode::serialize(&s.header)));

                    if let Some(hex) = header_hex {
                        let notification = json!({
                            "jsonrpc": "2.0",
                            "method": "blockchain.headers.subscribe",
                            "params": [{"height": best_h, "hex": hex}]
                        });
                        writer.write_all(notification.to_string().as_bytes()).await?;
                        writer.write_all(b"\n").await?;
                        writer.flush().await?;
                        debug!(height = best_h, "Sent heartbeat header notification");
                    }
                }
            }
        }
    }

    Ok(())
}

/// Parse a single JSON-RPC line, dispatch to the appropriate handler, and
/// return the serialised JSON response.
async fn process_request(
    line: &str,
    state: &ElectrumState,
    event_sender: &broadcast::Sender<NodeNotification>,
    subscribed_scripthashes: &mut HashSet<[u8; 32]>,
    headers_subscribed: &mut bool,
) -> String {
    let request: JsonRpcRequest = match serde_json::from_str(line) {
        Ok(r) => r,
        Err(e) => {
            debug!(raw = %line, error = %e, "Electrum JSON parse error");
            return json!({
                "jsonrpc": "2.0",
                "id": null,
                "error": {"code": -32700, "message": format!("Parse error: {}", e)}
            })
            .to_string();
        }
    };

    debug!(method = %request.method, id = %request.id, params = %serde_json::to_string(&request.params).unwrap_or_default(), "Electrum request");

    let result = match request.method.as_str() {
        "server.version" => handle_server_version(&request.params),
        "server.banner" => Ok(json!(state.banner)),
        "server.features" => {
            let genesis_hash = state.params.genesis_block.block_hash().to_string();
            debug!(genesis_hash = %genesis_hash, "Electrum server.features");
            Ok(json!({
                "server_version": SERVER_VERSION,
                "protocol_min": "1.4",
                "protocol_max": PROTOCOL_VERSION,
                "genesis_hash": genesis_hash,
                "hash_function": "sha256",
            }))
        }
        "server.ping" => Ok(Value::Null),
        "blockchain.scripthash.subscribe" => {
            handle_scripthash_subscribe(&request.params, state, subscribed_scripthashes).await
        }
        "blockchain.scripthash.get_balance" => {
            handle_scripthash_get_balance(&request.params, state).await
        }
        "blockchain.scripthash.listunspent" => {
            handle_scripthash_listunspent(&request.params, state).await
        }
        "blockchain.scripthash.get_history" => {
            handle_scripthash_get_history(&request.params, state).await
        }
        "blockchain.scripthash.get_mempool" => {
            handle_scripthash_get_mempool(&request.params, state).await
        }
        "blockchain.headers.subscribe" => {
            *headers_subscribed = true;
            handle_headers_subscribe(state).await
        }
        "blockchain.transaction.get" => handle_transaction_get(&request.params, state).await,
        "blockchain.transaction.broadcast" => {
            handle_transaction_broadcast(&request.params, state, event_sender).await
        }
        "blockchain.transaction.get_merkle" => {
            handle_transaction_get_merkle(&request.params, state).await
        }
        "blockchain.block.header" => handle_block_header(&request.params, state).await,
        "blockchain.block.headers" => handle_block_headers(&request.params, state).await,
        "blockchain.estimatefee" => Ok(json!(-1)),
        "blockchain.relayfee" => Ok(json!(0.00001)),
        "mempool.get_fee_histogram" => Ok(json!([])),
        "server.donation_address" => Ok(json!("")),
        "server.peers.subscribe" => Ok(json!([])),
        "server.add_peer" => Ok(json!(false)),
        _ => Err(json!({
            "code": -32601,
            "message": format!("Method not found: {}", request.method)
        })),
    };

    match result {
        Ok(ref value) => {
            debug!(method = %request.method, result = %value, "Electrum response OK");
            json!({
                "jsonrpc": "2.0",
                "id": request.id,
                "result": value,
            })
            .to_string()
        }
        Err(ref error) => {
            debug!(method = %request.method, error = %error, "Electrum response ERROR");
            json!({
                "jsonrpc": "2.0",
                "id": request.id,
                "error": error,
            })
            .to_string()
        }
    }
}

fn handle_server_version(params: &[Value]) -> Result<Value, Value> {
    let client_name = params.first().and_then(|v| v.as_str()).unwrap_or("unknown");

    // Protocol version can be a string "1.4" or an array ["1.4", "1.4.2"]
    let client_protocol = match params.get(1) {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Array(arr)) => {
            let parts: Vec<&str> = arr.iter().filter_map(|v| v.as_str()).collect();
            parts.join("-")
        }
        _ => "?".to_string(),
    };

    debug!(
        client = %client_name,
        client_protocol = %client_protocol,
        server = SERVER_VERSION,
        protocol = PROTOCOL_VERSION,
        "Electrum version negotiation"
    );

    Ok(json!([SERVER_VERSION, PROTOCOL_VERSION]))
}

async fn handle_scripthash_subscribe(
    params: &[Value],
    state: &ElectrumState,
    subscribed: &mut HashSet<[u8; 32]>,
) -> Result<Value, Value> {
    let sh_hex = params
        .first()
        .and_then(|v| v.as_str())
        .ok_or_else(|| json!({"code": -32602, "message": "Missing scripthash parameter"}))?;

    let sh_bytes = parse_scripthash(sh_hex)?;
    subscribed.insert(sh_bytes);

    let status = compute_scripthash_status(state, &sh_bytes).await;
    debug!(
        scripthash = %sh_hex,
        has_history = status.is_some(),
        total_subscriptions = subscribed.len(),
        "scripthash.subscribe"
    );
    match status {
        Some(s) => Ok(Value::String(s)),
        None => Ok(Value::Null),
    }
}

async fn handle_scripthash_get_balance(
    params: &[Value],
    state: &ElectrumState,
) -> Result<Value, Value> {
    let sh_hex = params
        .first()
        .and_then(|v| v.as_str())
        .ok_or_else(|| json!({"code": -32602, "message": "Missing scripthash parameter"}))?;

    let sh_bytes = parse_scripthash(sh_hex)?;

    let balance = state
        .index
        .get_balance(&sh_bytes)
        .map_err(|e| json!({"code": -1, "message": format!("Database error: {}", e)}))?;

    // Unconfirmed balance: sum of mempool outputs paying to this scripthash
    // minus the value of resolved mempool inputs spending from it. Expressed
    // as a signed delta per the Electrum convention.
    let snapshot = mempool_snapshot(state).await;
    let mut unconfirmed: i64 = balance.unconfirmed as i64;
    if !snapshot.is_empty() {
        let matches = scan_mempool_for_scripthash(&snapshot, &sh_bytes, state);
        for m in &matches {
            unconfirmed += m.received as i64;
            unconfirmed -= m.spent as i64;
        }
    }

    debug!(
        scripthash = %sh_hex,
        confirmed = balance.confirmed,
        unconfirmed = unconfirmed,
        "scripthash.get_balance"
    );

    Ok(json!({
        "confirmed": balance.confirmed,
        "unconfirmed": unconfirmed,
    }))
}

/// Handle blockchain.scripthash.listunspent.
///
/// When a `tx_index` is available, each history entry is resolved to the full
/// transaction so the per-output `value` field can be populated correctly.
/// Spent outputs are identified by tracking all inputs in the address's tx
/// history — this covers intra-history spends exactly.  (Cross-history spends,
/// where a spending tx has no other outputs to this address, are not in the
/// history; those are uncommon for coinbase-only addresses.)
///
/// Without a `tx_index` we fall back to the old behaviour of returning
/// `value: 0`, which is at least structurally valid for clients that only
/// need UTXOs for fee estimation and don't care about the exact amount.
async fn handle_scripthash_listunspent(
    params: &[Value],
    state: &ElectrumState,
) -> Result<Value, Value> {
    let sh_hex = params
        .first()
        .and_then(|v| v.as_str())
        .ok_or_else(|| json!({"code": -32602, "message": "Missing scripthash parameter"}))?;

    let sh_bytes = parse_scripthash(sh_hex)?;

    let history = state
        .index
        .get_tx_history(&sh_bytes)
        .map_err(|e| json!({"code": -1, "message": format!("Database error: {}", e)}))?;

    if let Some(ref tx_index) = state.tx_index {
        // Map (txid, vout) → (value_sats, height) for each output to this address.
        let mut outputs: HashMap<(String, u32), (u64, u32)> = HashMap::new();
        // Track every outpoint spent by any tx in this address's history.
        let mut spent: HashSet<(String, u32)> = HashSet::new();

        for entry in &history {
            let txid: bitcoin::Txid = entry
                .txid
                .parse()
                .map_err(|_| json!({"code": -1, "message": "Invalid txid stored in index"}))?;

            let idx_entry = match tx_index
                .get(&txid)
                .map_err(|e| json!({"code": -1, "message": format!("TxIndex error: {}", e)}))?
            {
                Some(e) => e,
                None => continue,
            };

            let pos = match state
                .header_index
                .get_block_pos(&idx_entry.block_hash)
                .map_err(|e| json!({"code": -1, "message": format!("BlockPos error: {}", e)}))?
            {
                Some(p) => p,
                None => continue,
            };

            let raw = state
                .block_store
                .read_block(&pos)
                .map_err(|e| json!({"code": -1, "message": format!("Block read error: {}", e)}))?;

            let block = encode::deserialize::<bitcoin::Block>(&raw).map_err(
                |e| json!({"code": -1, "message": format!("Block decode error: {}", e)}),
            )?;

            let tx = match block.txdata.get(idx_entry.tx_pos as usize) {
                Some(t) => t,
                None => continue,
            };

            // Collect outputs to this scripthash.
            for (vout, output) in tx.output.iter().enumerate() {
                let out_sh = ScripthashIndex::compute_scripthash(output.script_pubkey.as_bytes());
                if out_sh == sh_bytes {
                    outputs
                        .entry((entry.txid.clone(), vout as u32))
                        .or_insert((output.value.to_sat(), entry.height));
                }
            }

            // Track all inputs as potential spends of this address's outputs.
            for input in &tx.input {
                if !input.previous_output.is_null() {
                    spent.insert((
                        input.previous_output.txid.to_string(),
                        input.previous_output.vout,
                    ));
                }
            }
        }

        // Return only unspent outputs, sorted by height ascending.
        let mut unspent: Vec<Value> = outputs
            .into_iter()
            .filter(|(key, _)| !spent.contains(key))
            .map(|((txid, vout), (value, height))| {
                json!({
                    "tx_hash": txid,
                    "tx_pos": vout,
                    "height": height,
                    "value": value,
                })
            })
            .collect();
        unspent.sort_by_key(|v| v["height"].as_u64().unwrap_or(0));

        return Ok(Value::Array(unspent));
    }

    // Fallback: no tx index — return history entries with value=0.
    // Value will be wrong but the structure is valid.
    let unspent: Vec<Value> = history
        .iter()
        .map(|entry| {
            json!({
                "tx_hash": entry.txid,
                "tx_pos": entry.tx_index,
                "height": entry.height,
                "value": 0,
            })
        })
        .collect();

    Ok(Value::Array(unspent))
}

async fn handle_scripthash_get_history(
    params: &[Value],
    state: &ElectrumState,
) -> Result<Value, Value> {
    let sh_hex = params
        .first()
        .and_then(|v| v.as_str())
        .ok_or_else(|| json!({"code": -32602, "message": "Missing scripthash parameter"}))?;

    let sh_bytes = parse_scripthash(sh_hex)?;

    let history = state
        .index
        .get_tx_history(&sh_bytes)
        .map_err(|e| json!({"code": -1, "message": format!("Database error: {}", e)}))?;

    // Confirmed entries first, in the existing order.
    let mut entries: Vec<Value> = history
        .iter()
        .map(|entry| {
            json!({
                "tx_hash": entry.txid,
                "height": entry.height,
            })
        })
        .collect();

    // Append unconfirmed (mempool) entries touching this scripthash.
    entries.extend(mempool_history_entries(state, &sh_bytes).await);

    Ok(Value::Array(entries))
}

/// Handle blockchain.scripthash.get_mempool — returns ONLY the unconfirmed
/// (mempool) entries touching the scripthash, with no confirmed history.
async fn handle_scripthash_get_mempool(
    params: &[Value],
    state: &ElectrumState,
) -> Result<Value, Value> {
    let sh_hex = params
        .first()
        .and_then(|v| v.as_str())
        .ok_or_else(|| json!({"code": -32602, "message": "Missing scripthash parameter"}))?;

    let sh_bytes = parse_scripthash(sh_hex)?;

    let entries = mempool_history_entries(state, &sh_bytes).await;
    Ok(Value::Array(entries))
}

/// Build Electrum history JSON entries for the mempool transactions touching a
/// scripthash. Shared by get_history and get_mempool.
///
/// Per the Electrum protocol, unconfirmed entries MUST carry a `fee` field (in
/// satoshis) in addition to `tx_hash` and `height` — omitting it makes some
/// wallets (e.g. Electrum 4.x) reject the response and drop into a reconnect
/// loop the moment a subscribed address has a mempool transaction.
async fn mempool_history_entries(state: &ElectrumState, scripthash: &[u8; 32]) -> Vec<Value> {
    let snapshot = mempool_snapshot(state).await;
    if snapshot.is_empty() {
        return Vec::new();
    }
    let matches = scan_mempool_for_scripthash(&snapshot, scripthash, state);
    if matches.is_empty() {
        return Vec::new();
    }
    // Look up each matching tx's fee from the mempool (sats).
    let mempool = state.mempool.read().await;
    matches
        .into_iter()
        .map(|m| {
            let fee = m
                .txid
                .parse::<bitcoin::Txid>()
                .ok()
                .and_then(|txid| mempool.get(&txid).map(|e| e.fee))
                .unwrap_or(0);
            json!({
                "tx_hash": m.txid,
                "height": m.height,
                "fee": fee,
            })
        })
        .collect()
}

async fn handle_headers_subscribe(state: &ElectrumState) -> Result<Value, Value> {
    let height = *state.best_height.read().await;
    if let Ok(Some(hash)) = state.header_index.get_hash_at_height(height) {
        if let Ok(Some(stored)) = state.header_index.get_header(&hash) {
            let raw = encode::serialize(&stored.header);
            return Ok(json!({"height": height, "hex": hex::encode(raw)}));
        }
    }
    Ok(json!({"height": height, "hex": ""}))
}

/// Handle blockchain.transaction.get — returns raw tx hex (or verbose JSON).
async fn handle_transaction_get(params: &[Value], state: &ElectrumState) -> Result<Value, Value> {
    let txid_hex = params
        .first()
        .and_then(|v| v.as_str())
        .ok_or_else(|| json!({"code": -32602, "message": "Missing txid parameter"}))?;

    let txid: bitcoin::Txid = txid_hex
        .parse()
        .map_err(|_| json!({"code": -32602, "message": "Invalid txid"}))?;

    // Check mempool first
    {
        let mempool = state.mempool.read().await;
        if let Some(entry) = mempool.get(&txid) {
            let raw = encode::serialize(&entry.tx);
            return Ok(json!(hex::encode(raw)));
        }
    }

    // Check tx index
    if let Some(ref tx_index) = state.tx_index {
        if let Ok(Some(idx_entry)) = tx_index.get(&txid) {
            // Load the block and extract the transaction
            if let Ok(Some(pos)) = state.header_index.get_block_pos(&idx_entry.block_hash) {
                if let Ok(raw_block) = state.block_store.read_block(&pos) {
                    if let Ok(block) = encode::deserialize::<bitcoin::Block>(&raw_block) {
                        if let Some(tx) = block.txdata.get(idx_entry.tx_pos as usize) {
                            let raw = encode::serialize(tx);
                            return Ok(json!(hex::encode(raw)));
                        }
                    }
                }
            }
        }
    }

    Err(json!({"code": -1, "message": "Transaction not found"}))
}

/// Handle blockchain.transaction.get_merkle — return merkle proof for a confirmed tx.
///
/// Returns `{"merkle": [...], "block_height": N, "pos": M}` where `merkle` is the
/// list of sibling hashes needed to prove inclusion, and `pos` is the tx index.
async fn handle_transaction_get_merkle(
    params: &[Value],
    state: &ElectrumState,
) -> Result<Value, Value> {
    let txid_hex = params
        .first()
        .and_then(|v| v.as_str())
        .ok_or_else(|| json!({"code": -32602, "message": "Missing txid parameter"}))?;

    let txid: bitcoin::Txid = txid_hex
        .parse()
        .map_err(|_| json!({"code": -32602, "message": "Invalid txid"}))?;

    // Look up the block containing this transaction
    let tx_index = state
        .tx_index
        .as_ref()
        .ok_or_else(|| json!({"code": -1, "message": "Transaction index not available"}))?;

    let idx_entry = tx_index
        .get(&txid)
        .map_err(|e| json!({"code": -1, "message": format!("Index error: {}", e)}))?
        .ok_or_else(|| json!({"code": -1, "message": "Transaction not found in index"}))?;

    // Get the block height
    let stored = state
        .header_index
        .get_header(&idx_entry.block_hash)
        .map_err(|e| json!({"code": -1, "message": format!("Header error: {}", e)}))?
        .ok_or_else(|| json!({"code": -1, "message": "Block header not found"}))?;

    // Load the block to get all txids
    let pos = state
        .header_index
        .get_block_pos(&idx_entry.block_hash)
        .map_err(|e| json!({"code": -1, "message": format!("Block pos error: {}", e)}))?
        .ok_or_else(|| json!({"code": -1, "message": "Block data not found"}))?;

    let raw_block = state
        .block_store
        .read_block(&pos)
        .map_err(|e| json!({"code": -1, "message": format!("Block read error: {}", e)}))?;

    let block = encode::deserialize::<bitcoin::Block>(&raw_block)
        .map_err(|e| json!({"code": -1, "message": format!("Block decode error: {}", e)}))?;

    // Collect all txids and compute the merkle branch
    let txids: Vec<[u8; 32]> = block
        .txdata
        .iter()
        .map(|tx| *tx.compute_txid().as_byte_array())
        .collect();

    let tx_pos = idx_entry.tx_pos as usize;
    let merkle = compute_merkle_branch(&txids, tx_pos);

    Ok(json!({
        "merkle": merkle,
        "block_height": stored.height,
        "pos": tx_pos,
    }))
}

/// Compute a merkle branch (list of sibling hashes) for the element at `index`.
///
/// Returns hex strings in reversed (display) byte order, as the Electrum
/// protocol expects. Tree construction lives in `bitcoinpr_core::merkle` (M4).
fn compute_merkle_branch(hashes: &[[u8; 32]], index: usize) -> Vec<String> {
    let (_root, branch) = bitcoinpr_core::merkle::branch(hashes, index);
    branch
        .into_iter()
        .map(|mut hash| {
            hash.reverse();
            hex::encode(hash)
        })
        .collect()
}

/// Handle blockchain.transaction.broadcast — validate, add to mempool, and relay to peers.
async fn handle_transaction_broadcast(
    params: &[Value],
    state: &ElectrumState,
    event_sender: &broadcast::Sender<NodeNotification>,
) -> Result<Value, Value> {
    let raw_hex = params
        .first()
        .and_then(|v| v.as_str())
        .ok_or_else(|| json!({"code": -32602, "message": "Missing raw transaction hex"}))?;

    let raw_bytes = hex::decode(raw_hex)
        .map_err(|e| json!({"code": -32602, "message": format!("Invalid hex: {}", e)}))?;

    let tx: bitcoin::Transaction = encode::deserialize(&raw_bytes)
        .map_err(|e| json!({"code": -32602, "message": format!("Invalid transaction: {}", e)}))?;

    let txid = tx.compute_txid();

    // Add to mempool if we have a UTXO set
    if let Some(ref utxo_set) = state.utxo_set {
        // Finality/sequence-lock context: the tx must be valid in the next
        // block (tip height + 1, tip MTP). Missing tip hash degrades to an
        // MTP of 0, which fails time-locked txs closed.
        let tip_height = *state.best_height.read().await;
        let tip_hash = state
            .header_index
            .get_hash_at_height(tip_height)
            .ok()
            .flatten();
        let chain_ctx = match tip_hash {
            Some(hash) => {
                // BIP-110 deployment state for the next block (fresh, uncached
                // evaluation — Electrum broadcasts are infrequent), so the mempool
                // applies the same RDTS policy as block validation.
                let checker = state
                    .params
                    .bip110_deployment
                    .as_ref()
                    .map(|dep| bitcoinpr_core::Bip110Checker::new(dep.clone()));
                let bip110 = bitcoinpr_core::bip110_activation_at(
                    &state.params,
                    checker.as_ref(),
                    &state.header_index,
                    &hash,
                    tip_height + 1,
                );
                bitcoinpr_core::MempoolChainContext::at_tip(&state.header_index, tip_height, &hash)
                    .with_bip110(bip110)
            }
            None => bitcoinpr_core::MempoolChainContext {
                tip_height,
                tip_mtp: 0,
                header_index: &state.header_index,
                bip110: bitcoinpr_core::Bip110Activation::INACTIVE,
            },
        };
        let mut mempool = state.mempool.write().await;
        if !mempool.contains(&txid) {
            let flags = ScriptFlags::all();
            mempool
                .add_transaction(
                    tx.clone(),
                    utxo_set,
                    flags,
                    &state.params,
                    Some(state.sig_cache.as_ref()),
                    &chain_ctx,
                )
                .map_err(
                    |e| json!({"code": -26, "message": format!("Transaction rejected: {}", e)}),
                )?;
            info!(%txid, "Electrum broadcast: added to mempool");
            // Notify the event bus so mining can re-template and include this tx.
            let _ = event_sender.send(NodeNotification::NewTx {
                txid: txid.to_string(),
            });
        }
    } else {
        warn!(%txid, "Electrum broadcast: UTXO set not available, relaying without mempool validation");
    }

    // Broadcast to P2P peers
    if let Some(ref cmd_tx) = state.command_tx {
        let _ = cmd_tx.send(PeerCommand::BroadcastTx(tx)).await;
        debug!(%txid, "Electrum broadcast: relayed to P2P peers");
    } else {
        warn!(%txid, "Electrum broadcast: no P2P command channel, transaction not relayed");
    }

    Ok(json!(txid.to_string()))
}

/// Handle blockchain.block.header — returns the raw 80-byte header as hex.
async fn handle_block_header(params: &[Value], state: &ElectrumState) -> Result<Value, Value> {
    let height = params
        .first()
        .and_then(|v| v.as_u64())
        .ok_or_else(|| json!({"code": -32602, "message": "Missing height parameter"}))?
        as u32;

    let hash = state
        .header_index
        .get_hash_at_height(height)
        .map_err(|e| json!({"code": -1, "message": format!("DB error: {}", e)}))?
        .ok_or_else(|| json!({"code": -1, "message": format!("No block at height {}", height)}))?;

    let stored = state
        .header_index
        .get_header(&hash)
        .map_err(|e| json!({"code": -1, "message": format!("DB error: {}", e)}))?
        .ok_or_else(|| json!({"code": -1, "message": "Header not found"}))?;

    let raw = encode::serialize(&stored.header);
    Ok(json!(hex::encode(raw)))
}

/// Handle blockchain.block.headers — returns a batch of consecutive headers.
///
/// When `cp_height` > 0, the response must include a merkle proof (`root` and
/// `branch`) so the client can verify the headers against a known checkpoint.
async fn handle_block_headers(params: &[Value], state: &ElectrumState) -> Result<Value, Value> {
    let start_height = params
        .first()
        .and_then(|v| v.as_u64())
        .ok_or_else(|| json!({"code": -32602, "message": "Missing start_height"}))?
        as u32;

    let count = params
        .get(1)
        .and_then(|v| v.as_u64())
        .unwrap_or(1)
        .min(2016) as u32;

    let cp_height = params.get(2).and_then(|v| v.as_u64()).unwrap_or(0) as u32;

    // Collect the raw serialized headers
    let mut raw_headers: Vec<Vec<u8>> = Vec::new();
    let mut hex_headers = String::new();

    for h in start_height..start_height + count {
        let hash = match state.header_index.get_hash_at_height(h) {
            Ok(Some(h)) => h,
            _ => break,
        };
        let stored = match state.header_index.get_header(&hash) {
            Ok(Some(s)) => s,
            _ => break,
        };
        let raw = encode::serialize(&stored.header);
        hex_headers.push_str(&hex::encode(&raw));
        raw_headers.push(raw);
    }

    let actual_count = raw_headers.len() as u32;

    if cp_height == 0 {
        return Ok(json!({
            "count": actual_count,
            "hex": hex_headers,
            "max": 2016,
        }));
    }

    // Client requested a checkpoint proof. Build a merkle tree of all headers
    // from height 0..=cp_height to prove our returned headers are in the chain.
    // The leaf for a header at height H is SHA256(SHA256(raw_header)).
    // The proof covers the "last returned header" (start_height + count - 1).
    if actual_count == 0 || cp_height < start_height + actual_count - 1 {
        return Ok(json!({
            "count": actual_count,
            "hex": hex_headers,
            "max": 2016,
        }));
    }

    let target_height = start_height + actual_count - 1;

    // Collect all header hashes from 0..=cp_height for the merkle tree
    let tree_size = (cp_height + 1) as usize;
    let mut leaves: Vec<[u8; 32]> = Vec::with_capacity(tree_size);

    for h in 0..=cp_height {
        if h >= start_height && h <= target_height {
            // Use the header we already fetched
            let idx = (h - start_height) as usize;
            let hash = double_sha256(&raw_headers[idx]);
            leaves.push(hash);
        } else if let Ok(Some(bh)) = state.header_index.get_hash_at_height(h) {
            if let Ok(Some(stored)) = state.header_index.get_header(&bh) {
                let raw = encode::serialize(&stored.header);
                let hash = double_sha256(&raw);
                leaves.push(hash);
            } else {
                leaves.push([0u8; 32]);
            }
        } else {
            leaves.push([0u8; 32]);
        }
    }

    let (root, branch) = bitcoinpr_core::merkle::branch(&leaves, target_height as usize);

    Ok(json!({
        "count": actual_count,
        "hex": hex_headers,
        "max": 2016,
        "root": hex::encode(root),
        "branch": branch.iter().map(hex::encode).collect::<Vec<_>>(),
    }))
}

/// Double SHA-256 hash.
fn double_sha256(data: &[u8]) -> [u8; 32] {
    let hash = sha256d::Hash::hash(data);
    *hash.as_byte_array()
}

fn parse_scripthash(hex_str: &str) -> Result<[u8; 32], Value> {
    let bytes = hex::decode(hex_str)
        .map_err(|e| json!({"code": -32602, "message": format!("Invalid hex: {}", e)}))?;

    if bytes.len() != 32 {
        return Err(json!({"code": -32602, "message": "Scripthash must be 32 bytes"}));
    }

    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

/// A mempool transaction that touches a given scripthash.
///
/// `height` follows the Electrum convention for unconfirmed transactions:
/// `0` when all inputs spend confirmed outputs, and `-1` when at least one
/// input spends another (still unconfirmed) mempool transaction.
struct MempoolMatch {
    txid: String,
    /// Electrum height: 0 (confirmed parents) or -1 (unconfirmed parents).
    height: i64,
    /// Total value of outputs in this tx that pay to the scripthash (sats).
    received: u64,
    /// Total value of resolved prevouts spent by this tx that belong to the
    /// scripthash (sats). Unresolvable prevouts are skipped (best-effort).
    spent: u64,
}

/// Resolve the scriptPubKey (and value) of a previous output by consulting,
/// in order: other mempool transactions' outputs, the UTXO set, then the tx
/// index (reading the containing block). Returns `None` when no source can
/// resolve the outpoint, in which case callers skip the input (best-effort).
fn resolve_prevout(
    outpoint: &bitcoin::OutPoint,
    mempool_txs: &HashMap<bitcoin::Txid, Transaction>,
    state: &ElectrumState,
) -> Option<(Vec<u8>, u64)> {
    // 1. Another mempool tx's output (unconfirmed parent).
    if let Some(parent) = mempool_txs.get(&outpoint.txid) {
        if let Some(out) = parent.output.get(outpoint.vout as usize) {
            return Some((out.script_pubkey.as_bytes().to_vec(), out.value.to_sat()));
        }
    }

    // 2. The UTXO set (confirmed, still-unspent output).
    if let Some(ref utxo_set) = state.utxo_set {
        if let Ok(Some(entry)) = utxo_set.get(outpoint) {
            return Some((entry.script_pubkey, entry.amount));
        }
    }

    // 3. The tx index: load the block and read the referenced output.
    if let Some(ref tx_index) = state.tx_index {
        if let Ok(Some(idx_entry)) = tx_index.get(&outpoint.txid) {
            if let Ok(Some(pos)) = state.header_index.get_block_pos(&idx_entry.block_hash) {
                if let Ok(raw) = state.block_store.read_block(&pos) {
                    if let Ok(block) = encode::deserialize::<bitcoin::Block>(&raw) {
                        if let Some(tx) = block.txdata.get(idx_entry.tx_pos as usize) {
                            if let Some(out) = tx.output.get(outpoint.vout as usize) {
                                return Some((
                                    out.script_pubkey.as_bytes().to_vec(),
                                    out.value.to_sat(),
                                ));
                            }
                        }
                    }
                }
            }
        }
    }

    None
}

/// Scan a mempool snapshot for transactions that touch `scripthash`, either by
/// paying to it (an output whose computed scripthash matches) or spending from
/// it (an input whose resolved prevout scriptPubKey hashes to the scripthash).
///
/// The returned matches carry the Electrum unconfirmed `height` (0 or -1), the
/// received value (outputs to the scripthash) and the spent value (resolved
/// prevouts belonging to the scripthash). Matches are sorted by txid for a
/// deterministic ordering. This is the single shared scan used by status,
/// history, get_mempool and balance.
fn scan_mempool_for_scripthash(
    mempool_txs: &HashMap<bitcoin::Txid, Transaction>,
    scripthash: &[u8; 32],
    state: &ElectrumState,
) -> Vec<MempoolMatch> {
    let mut matches: Vec<MempoolMatch> = Vec::new();

    for (txid, tx) in mempool_txs.iter() {
        let mut received: u64 = 0;
        let mut spent: u64 = 0;
        let mut has_unconfirmed_parent = false;
        let mut touches = false;

        // Outputs paying to this scripthash.
        for output in &tx.output {
            let out_sh = ScripthashIndex::compute_scripthash(output.script_pubkey.as_bytes());
            if &out_sh == scripthash {
                received = received.saturating_add(output.value.to_sat());
                touches = true;
            }
        }

        // Inputs: resolve prevouts to detect spends from this scripthash and to
        // determine whether any parent is itself unconfirmed.
        for input in &tx.input {
            if input.previous_output.is_null() {
                continue;
            }
            // Track unconfirmed parents regardless of scripthash membership.
            if mempool_txs.contains_key(&input.previous_output.txid) {
                has_unconfirmed_parent = true;
            }
            if let Some((script, value)) =
                resolve_prevout(&input.previous_output, mempool_txs, state)
            {
                let in_sh = ScripthashIndex::compute_scripthash(&script);
                if &in_sh == scripthash {
                    spent = spent.saturating_add(value);
                    touches = true;
                }
            }
        }

        if touches {
            matches.push(MempoolMatch {
                txid: txid.to_string(),
                height: if has_unconfirmed_parent { -1 } else { 0 },
                received,
                spent,
            });
        }
    }

    matches.sort_by(|a, b| a.txid.cmp(&b.txid));
    matches
}

/// Take a snapshot of the current mempool transactions keyed by txid.
///
/// Snapshotting (rather than holding the read guard) keeps the `RwLock` guard
/// from being held across `await` points in the async handlers.
async fn mempool_snapshot(state: &ElectrumState) -> HashMap<bitcoin::Txid, Transaction> {
    let mempool = state.mempool.read().await;
    mempool.entries().map(|e| (e.txid, e.tx.clone())).collect()
}

/// Compute the Electrum protocol "status" for a scripthash, including
/// unconfirmed (mempool) transactions.
///
/// The status is the SHA256 hash of the concatenated `"txid:height:"` strings
/// for each confirmed history entry, followed by the mempool entries that touch
/// the scripthash (height 0, or -1 for unconfirmed parents). Returns `None`
/// when the scripthash has no confirmed and no unconfirmed history.
///
/// When the mempool is empty the output is byte-identical to the previous
/// confirmed-only implementation: confirmed entries are appended first, in the
/// same order, and nothing else is added.
async fn compute_scripthash_status(state: &ElectrumState, scripthash: &[u8; 32]) -> Option<String> {
    let history = state.index.get_tx_history(scripthash).ok()?;

    let mut status_str = String::new();
    for entry in &history {
        status_str.push_str(&entry.txid);
        status_str.push(':');
        status_str.push_str(&entry.height.to_string());
        status_str.push(':');
    }

    // Append mempool entries after the confirmed ones.
    let snapshot = mempool_snapshot(state).await;
    if !snapshot.is_empty() {
        let matches = scan_mempool_for_scripthash(&snapshot, scripthash, state);
        for m in &matches {
            status_str.push_str(&m.txid);
            status_str.push(':');
            status_str.push_str(&m.height.to_string());
            status_str.push(':');
        }
    }

    if status_str.is_empty() {
        return None;
    }

    let hash = sha256::Hash::hash(status_str.as_bytes());
    Some(hex::encode(hash.as_byte_array()))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tls_tests {
    use super::*;

    #[test]
    fn persistent_tls_generate_write_reload_roundtrip() {
        let dir = tempfile::tempdir().unwrap();

        // First call: nothing on disk yet — generates and persists the keypair.
        load_or_create_persistent_tls(dir.path()).expect("generate+persist");

        let cert_path = dir.path().join(TLS_CERT_FILE);
        let key_path = dir.path().join(TLS_KEY_FILE);
        assert!(cert_path.exists(), "cert file written");
        assert!(key_path.exists(), "key file written");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&key_path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "key file must be mode 0600");
        }

        let cert_before = std::fs::read(&cert_path).unwrap();

        // Second call: loads the persisted pair without regenerating it.
        load_or_create_persistent_tls(dir.path()).expect("reload persisted");
        let cert_after = std::fs::read(&cert_path).unwrap();
        assert_eq!(
            cert_before, cert_after,
            "cert must be stable across restarts"
        );
    }

    #[test]
    fn persistent_tls_regenerates_corrupt_pair() {
        let dir = tempfile::tempdir().unwrap();
        let cert_path = dir.path().join(TLS_CERT_FILE);
        let key_path = dir.path().join(TLS_KEY_FILE);
        std::fs::write(&cert_path, b"not a pem").unwrap();
        std::fs::write(&key_path, b"not a pem").unwrap();

        load_or_create_persistent_tls(dir.path()).expect("regenerate over corrupt files");
        let cert = std::fs::read_to_string(&cert_path).unwrap();
        assert!(cert.contains("BEGIN CERTIFICATE"), "corrupt cert replaced");
    }
}
