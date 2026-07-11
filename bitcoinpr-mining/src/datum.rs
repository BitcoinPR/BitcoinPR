//! Datum protocol client.
//!
//! Implements a JSON-over-TLS (newline-delimited) client for a Datum Prime
//! pool. The [`DatumClient`] connects when the mining mode is
//! [`MiningMode::Datum`](crate::config::MiningMode::Datum), performs a
//! handshake, forwards qualifying shares submitted via [`DatumClient::submit_share`],
//! and surfaces connection state for the dashboard via [`DatumClient::status`].
//!
//! The client is resilient: a missing or unreachable Datum server results in a
//! degraded mode where the client keeps retrying with exponential backoff
//! rather than panicking. When the operator switches back to solo mining the
//! client idles cheaply.

use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::sync::{broadcast, mpsc, watch, Mutex, RwLock};
use tokio_rustls::TlsConnector;
use tracing::{debug, info, warn};

use bitcoinpr_core::NodeNotification;

use crate::config::{MiningConfig, MiningMode};
use crate::protocol::{CoinbaseOutputSpec, DatumMessage};
use crate::shares::ShareTracker;

/// Internal share-submission queue capacity. Shares beyond this are dropped
/// (with a warning) rather than blocking the caller.
const SHARE_QUEUE_CAPACITY: usize = 1024;

/// Lower bound for the reconnect backoff.
const BACKOFF_MIN: Duration = Duration::from_secs(1);
/// Upper bound for the reconnect backoff.
const BACKOFF_MAX: Duration = Duration::from_secs(60);

/// A coinbase output the pool requires the miner to include.
///
/// Note: `value` is a *placeholder* of `0` for pool-supplied outputs. The
/// absolute satoshi value depends on the block's coinbase value, which the
/// Datum client does not know at conversion time. The
/// [`TemplateProvider`](crate::template_provider::TemplateProvider) applies the
/// pool's `value_fraction` (see [`pool_coinbase_output_specs`](DatumClient::pool_coinbase_output_specs))
/// against the real coinbase value when building the block.
#[derive(Debug, Clone)]
pub struct CoinbaseOutput {
    pub value: u64,
    pub script_pubkey: Vec<u8>,
}

/// A share to forward to the Datum pool. Built by the TemplateProvider when a
/// share meets the pool difficulty threshold.
#[derive(Debug, Clone)]
pub struct DatumShare {
    pub template_height: u32,
    pub header_hash: String,
    pub nonce: u32,
    pub ntime: u32,
    pub coinbase_tx: String,
    pub difficulty: f64,
}

#[derive(Debug, Clone)]
pub struct PayoutInfo {
    pub txid: String,
    pub amount: u64,
    pub block_height: u32,
}

/// Snapshot of Datum connection state for the dashboard.
#[derive(Debug, Clone, serde::Serialize)]
pub struct DatumStatus {
    pub connected: bool,
    pub pool_name: Option<String>,
    pub pool_difficulty: Option<f64>,
    pub payout_scheme: Option<String>,
    pub shares_submitted: u64,
    pub shares_accepted: u64,
    pub last_payout: Option<DatumPayoutView>,
    pub uptime_secs: u64,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct DatumPayoutView {
    pub txid: String,
    pub amount: u64,
    pub block_height: u32,
}

/// Mutable Datum connection state, shared between `run` and `status`/accessors.
#[derive(Debug)]
struct DatumState {
    connected: bool,
    pool_name: Option<String>,
    pool_difficulty: Option<f64>,
    payout_scheme: Option<String>,
    session_id: Option<String>,
    shares_submitted: u64,
    shares_accepted: u64,
    last_payout: Option<PayoutInfo>,
    start_time: Instant,
}

impl DatumState {
    fn new() -> Self {
        DatumState {
            connected: false,
            pool_name: None,
            pool_difficulty: None,
            payout_scheme: None,
            session_id: None,
            shares_submitted: 0,
            shares_accepted: 0,
            last_payout: None,
            start_time: Instant::now(),
        }
    }

    /// Reset the per-session fields on disconnect (keeps cumulative counters).
    fn clear_session(&mut self) {
        self.connected = false;
        self.session_id = None;
    }
}

/// Decode pool coinbase output specs into [`CoinbaseOutput`]s.
///
/// Entries whose `script_pubkey_hex` is not valid hex are skipped (with a
/// warning). The returned `value` is always `0`: the fractional value is
/// applied later by the TemplateProvider against the real coinbase value.
fn specs_to_outputs(specs: &[CoinbaseOutputSpec]) -> Vec<CoinbaseOutput> {
    specs
        .iter()
        .filter_map(|spec| match hex::decode(&spec.script_pubkey_hex) {
            Ok(script_pubkey) => Some(CoinbaseOutput {
                value: 0,
                script_pubkey,
            }),
            Err(e) => {
                warn!(
                    label = %spec.label,
                    script_pubkey_hex = %spec.script_pubkey_hex,
                    error = %e,
                    "skipping pool coinbase output with invalid script hex"
                );
                None
            }
        })
        .collect()
}

/// JSON-over-TLS Datum protocol client.
///
/// Construct with [`DatumClient::new`], then spawn [`DatumClient::run`] on the
/// tokio runtime. Other components hold an `Arc<DatumClient>` and call
/// [`submit_share`](DatumClient::submit_share),
/// [`pool_coinbase_outputs`](DatumClient::pool_coinbase_outputs), and
/// [`status`](DatumClient::status).
pub struct DatumClient {
    config: Arc<RwLock<MiningConfig>>,
    config_version: watch::Receiver<u64>,
    #[allow(dead_code)]
    share_tracker: ShareTracker,
    event_sender: broadcast::Sender<NodeNotification>,
    state: Arc<RwLock<DatumState>>,
    /// Raw pool-required coinbase output specs from the most recent
    /// `ServerHello` / `CoinbaseOutputUpdate`. Empty when not connected.
    pool_outputs: Arc<RwLock<Vec<CoinbaseOutputSpec>>>,
    /// Producer half of the internal share submission queue.
    share_tx: mpsc::Sender<DatumShare>,
    /// Consumer half, taken by `run` on first invocation.
    share_rx: Arc<Mutex<Option<mpsc::Receiver<DatumShare>>>>,
}

impl DatumClient {
    pub fn new(
        config: Arc<RwLock<MiningConfig>>,
        config_version: watch::Receiver<u64>,
        share_tracker: ShareTracker,
        event_sender: broadcast::Sender<NodeNotification>,
    ) -> Self {
        let (share_tx, share_rx) = mpsc::channel(SHARE_QUEUE_CAPACITY);
        DatumClient {
            config,
            config_version,
            share_tracker,
            event_sender,
            state: Arc::new(RwLock::new(DatumState::new())),
            pool_outputs: Arc::new(RwLock::new(Vec::new())),
            share_tx,
            share_rx: Arc::new(Mutex::new(Some(share_rx))),
        }
    }

    /// Current pool-required coinbase outputs (with placeholder `value = 0`).
    ///
    /// Empty if not connected or in solo mode. See [`CoinbaseOutput`] for why
    /// `value` is a placeholder; use
    /// [`pool_coinbase_output_specs`](Self::pool_coinbase_output_specs) to get
    /// the fractional specs the TemplateProvider needs to compute real values.
    pub async fn pool_coinbase_outputs(&self) -> Vec<CoinbaseOutput> {
        let specs = self.pool_outputs.read().await;
        specs_to_outputs(&specs)
    }

    /// Raw pool-required coinbase output specs (with `value_fraction`).
    ///
    /// Empty if not connected or in solo mode.
    pub async fn pool_coinbase_output_specs(&self) -> Vec<CoinbaseOutputSpec> {
        self.pool_outputs.read().await.clone()
    }

    /// Forward a qualifying share to the pool (non-blocking; queues internally).
    ///
    /// If the internal queue is full the share is dropped with a warning rather
    /// than blocking the caller.
    pub async fn submit_share(&self, share: DatumShare) {
        match self.share_tx.try_send(share) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(_)) => {
                warn!("datum share queue full; dropping share");
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                debug!("datum share queue closed; dropping share");
            }
        }
    }

    /// Connection state for the dashboard.
    pub async fn status(&self) -> DatumStatus {
        let state = self.state.read().await;
        DatumStatus {
            connected: state.connected,
            pool_name: state.pool_name.clone(),
            pool_difficulty: state.pool_difficulty,
            payout_scheme: state.payout_scheme.clone(),
            shares_submitted: state.shares_submitted,
            shares_accepted: state.shares_accepted,
            last_payout: state.last_payout.as_ref().map(|p| DatumPayoutView {
                txid: p.txid.clone(),
                amount: p.amount,
                block_height: p.block_height,
            }),
            uptime_secs: state.start_time.elapsed().as_secs(),
        }
    }

    /// Connects, handles messages, auto-reconnects with exponential backoff.
    ///
    /// Returns only on unrecoverable error or shutdown (a closed
    /// `config_version` watch channel is treated as shutdown → `Ok(())`).
    /// Spawn on the tokio runtime.
    pub async fn run(&self) -> anyhow::Result<()> {
        // Take the consumer half of the share queue. If `run` is somehow called
        // twice, the second call has no receiver and we bail out cleanly.
        let mut share_rx = match self.share_rx.lock().await.take() {
            Some(rx) => rx,
            None => {
                warn!("DatumClient::run called more than once; ignoring");
                return Ok(());
            }
        };

        let connector = Self::build_tls_connector();
        let mut backoff = BACKOFF_MIN;

        loop {
            // 1. Idle while not in Datum mode.
            if !self.wait_for_datum_mode().await {
                // config_version channel closed → shutdown.
                return Ok(());
            }

            // Snapshot the datum config for this connection attempt.
            let (server_url, worker_name, payout_address, auth_token) = {
                let cfg = self.config.read().await;
                (
                    cfg.datum.server_url.clone(),
                    cfg.datum.worker_name.clone(),
                    cfg.datum.payout_address.clone(),
                    cfg.datum.auth_token.clone(),
                )
            };

            let Some((host, port)) = parse_server_url(&server_url) else {
                warn!(server_url = %server_url, "invalid datum.server_url; retrying");
                if !self.backoff_sleep(&mut backoff).await {
                    return Ok(());
                }
                continue;
            };

            info!(host = %host, port, "connecting to Datum pool");

            match self
                .connect_and_serve(
                    &connector,
                    &host,
                    port,
                    &worker_name,
                    &payout_address,
                    auth_token.as_deref(),
                    &mut share_rx,
                    &mut backoff,
                )
                .await
            {
                Ok(()) => {
                    // Clean disconnect (server closed or config changed).
                    debug!("datum session ended; will re-evaluate mode");
                }
                Err(e) => {
                    warn!(error = %e, "datum session error");
                }
            }

            // Tear down session state and notify.
            let reason = "connection closed".to_string();
            {
                let mut state = self.state.write().await;
                state.clear_session();
            }
            self.pool_outputs.write().await.clear();
            let _ = self
                .event_sender
                .send(NodeNotification::DatumDisconnected { reason });

            // Re-check mode before sleeping: if the operator switched to solo,
            // loop back to the cheap idle path immediately.
            if self.config.read().await.mode != MiningMode::Datum {
                continue;
            }

            if !self.backoff_sleep(&mut backoff).await {
                return Ok(());
            }
        }
    }

    /// Build a rustls-based TLS connector trusting the Mozilla root set.
    fn build_tls_connector() -> TlsConnector {
        let root_store = rustls::RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
        };
        let config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        TlsConnector::from(Arc::new(config))
    }

    /// Block until the mining mode is `Datum`. Returns `false` if the
    /// `config_version` watch channel closed (shutdown), `true` once Datum mode
    /// is active.
    async fn wait_for_datum_mode(&self) -> bool {
        loop {
            if self.config.read().await.mode == MiningMode::Datum {
                return true;
            }
            // Ensure we report disconnected while idling in solo mode.
            {
                let mut state = self.state.write().await;
                if state.connected {
                    state.clear_session();
                }
            }

            let mut cv = self.config_version.clone();
            tokio::select! {
                _ = tokio::time::sleep(Duration::from_secs(2)) => {}
                changed = cv.changed() => {
                    if changed.is_err() {
                        // Sender dropped → shutdown.
                        return false;
                    }
                }
            }
        }
    }

    /// Sleep for the current backoff then double it (capped). Returns `false`
    /// if the `config_version` channel closes during the sleep (shutdown).
    async fn backoff_sleep(&self, backoff: &mut Duration) -> bool {
        debug!(secs = backoff.as_secs(), "datum reconnect backoff");
        let mut cv = self.config_version.clone();
        tokio::select! {
            _ = tokio::time::sleep(*backoff) => {}
            changed = cv.changed() => {
                if changed.is_err() {
                    return false;
                }
            }
        }
        *backoff = (*backoff * 2).min(BACKOFF_MAX);
        true
    }

    /// Establish the TLS connection, handshake, and run the steady-state loop.
    ///
    /// Returns `Ok(())` on a clean disconnect (server closed the stream or the
    /// datum config changed and we should reconnect). Returns `Err` on any I/O
    /// or TLS failure.
    #[allow(clippy::too_many_arguments)]
    async fn connect_and_serve(
        &self,
        connector: &TlsConnector,
        host: &str,
        port: u16,
        worker_name: &str,
        payout_address: &str,
        auth_token: Option<&str>,
        share_rx: &mut mpsc::Receiver<DatumShare>,
        backoff: &mut Duration,
    ) -> anyhow::Result<()> {
        let tcp = TcpStream::connect((host, port)).await?;
        let server_name = rustls::pki_types::ServerName::try_from(host.to_string())
            .map_err(|e| anyhow::anyhow!("invalid DNS name {host:?}: {e}"))?;
        let tls = connector.connect(server_name, tcp).await?;
        debug!(host = %host, port, "TLS connection established");

        let (read_half, mut write_half) = tokio::io::split(tls);
        let mut reader = BufReader::new(read_half);

        // 3. Send handshake.
        let handshake = DatumMessage::Handshake {
            protocol_version: 1,
            worker_name: worker_name.to_string(),
            payout_address: payout_address.to_string(),
            auth_token: auth_token.map(|s| s.to_string()),
            user_agent: format!("/BitcoinPR-datum:{}/", env!("CARGO_PKG_VERSION")),
        };
        write_message(&mut write_half, &handshake).await?;
        debug!("datum handshake sent");

        // Watch the datum sub-config so we can reconnect on changes.
        let mut cv = self.config_version.clone();
        let initial_datum = {
            let cfg = self.config.read().await;
            datum_fingerprint(&cfg)
        };

        let mut line = String::new();
        loop {
            line.clear();
            tokio::select! {
                // (a) Read a line from the server.
                read = reader.read_line(&mut line) => {
                    let n = read?;
                    if n == 0 {
                        debug!("datum server closed connection");
                        return Ok(());
                    }
                    let trimmed = line.trim();
                    if trimmed.is_empty() {
                        continue;
                    }
                    match serde_json::from_str::<DatumMessage>(trimmed) {
                        Ok(msg) => {
                            self.handle_message(msg, backoff).await;
                        }
                        Err(e) => {
                            warn!(error = %e, raw = %trimmed, "failed to parse datum message");
                        }
                    }
                }

                // (b) Forward a queued share to the pool.
                maybe_share = share_rx.recv() => {
                    match maybe_share {
                        Some(share) => {
                            self.forward_share(&mut write_half, share).await?;
                        }
                        None => {
                            // Producer dropped — should not happen while the
                            // client is alive; treat as shutdown.
                            debug!("datum share queue producer dropped");
                            return Ok(());
                        }
                    }
                }

                // (c) Config changed — reconnect if the datum settings changed
                //     or the operator left Datum mode.
                changed = cv.changed() => {
                    if changed.is_err() {
                        // Shutdown — propagate by returning Ok; the outer loop
                        // re-checks mode and the watch close is detected there.
                        return Ok(());
                    }
                    let cfg = self.config.read().await;
                    if cfg.mode != MiningMode::Datum {
                        debug!("mode left Datum; closing session");
                        return Ok(());
                    }
                    if datum_fingerprint(&cfg) != initial_datum {
                        info!("datum config changed; reconnecting");
                        return Ok(());
                    }
                }
            }
        }
    }

    /// Send a `SubmitShare` for a queued share and bump the submitted counter.
    async fn forward_share<W>(&self, write_half: &mut W, share: DatumShare) -> anyhow::Result<()>
    where
        W: AsyncWriteExt + Unpin,
    {
        let session_id = {
            let state = self.state.read().await;
            state.session_id.clone()
        };
        let Some(session_id) = session_id else {
            debug!("dropping share submitted before handshake completed");
            return Ok(());
        };

        let msg = DatumMessage::SubmitShare {
            session_id,
            template_height: share.template_height,
            header_hash: share.header_hash.clone(),
            nonce: share.nonce,
            ntime: share.ntime,
            coinbase_tx: share.coinbase_tx.clone(),
            difficulty: share.difficulty,
        };
        write_message(write_half, &msg).await?;
        {
            let mut state = self.state.write().await;
            state.shares_submitted += 1;
        }
        debug!(
            height = share.template_height,
            difficulty = share.difficulty,
            "submitted share to datum pool"
        );
        Ok(())
    }

    /// Handle a single server-originated message.
    async fn handle_message(&self, msg: DatumMessage, backoff: &mut Duration) {
        match msg {
            DatumMessage::ServerHello {
                protocol_version,
                session_id,
                pool_name,
                pool_difficulty,
                coinbase_outputs,
                payout_scheme,
            } => {
                info!(
                    protocol_version,
                    pool_name = %pool_name,
                    pool_difficulty,
                    payout_scheme = %payout_scheme,
                    "datum ServerHello; connected"
                );
                {
                    let mut state = self.state.write().await;
                    state.connected = true;
                    state.pool_name = Some(pool_name.clone());
                    state.pool_difficulty = Some(pool_difficulty);
                    state.payout_scheme = Some(payout_scheme);
                    state.session_id = Some(session_id);
                }
                *self.pool_outputs.write().await = coinbase_outputs;
                // Reset backoff after a successful handshake.
                *backoff = BACKOFF_MIN;
                let _ = self
                    .event_sender
                    .send(NodeNotification::DatumConnected { pool_name });
            }

            DatumMessage::CoinbaseOutputUpdate { coinbase_outputs } => {
                debug!(
                    count = coinbase_outputs.len(),
                    "datum coinbase outputs updated"
                );
                *self.pool_outputs.write().await = coinbase_outputs;
            }

            DatumMessage::ShareResult {
                accepted,
                reason,
                pool_hashrate,
            } => {
                let difficulty = {
                    let mut state = self.state.write().await;
                    if accepted {
                        state.shares_accepted += 1;
                    }
                    state.pool_difficulty.unwrap_or(0.0)
                };
                debug!(accepted, ?reason, ?pool_hashrate, "datum share result");
                let _ = self
                    .event_sender
                    .send(NodeNotification::DatumShareSubmitted {
                        accepted,
                        difficulty,
                    });
            }

            DatumMessage::PayoutNotification {
                txid,
                amount,
                block_height,
            } => {
                info!(txid = %txid, amount, block_height, "datum payout");
                {
                    let mut state = self.state.write().await;
                    state.last_payout = Some(PayoutInfo {
                        txid: txid.clone(),
                        amount,
                        block_height,
                    });
                }
                let _ = self
                    .event_sender
                    .send(NodeNotification::DatumPayout { txid, amount });
            }

            DatumMessage::Error { code, message } => {
                warn!(code, message = %message, "datum server error");
            }

            // Client -> Server variants should never arrive from the server.
            other => {
                debug!(?other, "ignoring unexpected datum message from server");
            }
        }
    }
}

/// Parse a `host:port` server URL. Returns `None` if malformed.
fn parse_server_url(url: &str) -> Option<(String, u16)> {
    let (host, port) = url.rsplit_once(':')?;
    if host.is_empty() {
        return None;
    }
    let port: u16 = port.parse().ok()?;
    Some((host.to_string(), port))
}

/// A cheap fingerprint of the datum sub-config used to detect changes that
/// require a reconnect.
fn datum_fingerprint(cfg: &MiningConfig) -> (String, String, String, Option<String>) {
    (
        cfg.datum.server_url.clone(),
        cfg.datum.worker_name.clone(),
        cfg.datum.payout_address.clone(),
        cfg.datum.auth_token.clone(),
    )
}

/// Serialize a [`DatumMessage`] to newline-delimited JSON and write it.
async fn write_message<W>(write_half: &mut W, msg: &DatumMessage) -> anyhow::Result<()>
where
    W: AsyncWriteExt + Unpin,
{
    let mut bytes = serde_json::to_vec(msg)?;
    bytes.push(b'\n');
    write_half.write_all(&bytes).await?;
    write_half.flush().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_client() -> DatumClient {
        let config = Arc::new(RwLock::new(MiningConfig::default()));
        let (_tx, rx) = watch::channel(0u64);
        let tracker = ShareTracker::new();
        let (event_tx, _event_rx) = broadcast::channel(64);
        DatumClient::new(config, rx, tracker, event_tx)
    }

    #[tokio::test]
    async fn solo_mode_is_disconnected_and_empty() {
        let client = make_client();
        let status = client.status().await;
        assert!(!status.connected);
        assert!(client.pool_coinbase_outputs().await.is_empty());
        assert!(client.pool_coinbase_output_specs().await.is_empty());
    }

    #[tokio::test]
    async fn submit_share_does_not_panic() {
        let client = make_client();
        client
            .submit_share(DatumShare {
                template_height: 100,
                header_hash: "deadbeef".to_string(),
                nonce: 42,
                ntime: 1_700_000_000,
                coinbase_tx: "00".to_string(),
                difficulty: 1024.0,
            })
            .await;
        // Queue accepted it; submitted counter is only bumped once forwarded.
        let status = client.status().await;
        assert_eq!(status.shares_submitted, 0);
    }

    #[test]
    fn specs_to_outputs_decodes_valid_hex() {
        // p2wpkh: OP_0 <20-byte pubkey hash> => "0014" + 20 bytes
        let script_hex = format!("0014{}", "ab".repeat(20));
        let specs = vec![
            CoinbaseOutputSpec {
                value_fraction: 0.02,
                script_pubkey_hex: script_hex.clone(),
                label: "pool_fee".to_string(),
            },
            CoinbaseOutputSpec {
                value_fraction: 0.0,
                script_pubkey_hex: "nothex!!".to_string(),
                label: "bad".to_string(),
            },
        ];
        let outputs = specs_to_outputs(&specs);
        // The invalid-hex entry is skipped.
        assert_eq!(outputs.len(), 1);
        assert_eq!(outputs[0].value, 0);
        assert_eq!(outputs[0].script_pubkey.len(), 22);
        assert_eq!(outputs[0].script_pubkey[0], 0x00);
        assert_eq!(outputs[0].script_pubkey[1], 0x14);
    }

    #[test]
    fn parse_server_url_works() {
        assert_eq!(
            parse_server_url("datum.ocean.xyz:3334"),
            Some(("datum.ocean.xyz".to_string(), 3334))
        );
        assert_eq!(parse_server_url("noport"), None);
        assert_eq!(parse_server_url(":3334"), None);
        assert_eq!(parse_server_url("host:notaport"), None);
    }
}
