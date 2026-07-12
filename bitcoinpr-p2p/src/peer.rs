use bitcoin::p2p::message::{NetworkMessage, RawNetworkMessage};
use bitcoin::p2p::message_network::VersionMessage;
use bitcoin::p2p::ServiceFlags;
use bitcoin::Network;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
// Note: BufReader was tested and caused mutex contention with
// tokio::io::split(), leading to peer disconnects. Raw reads are fine
// since codec.read_message does read_exact (no wasted syscalls).
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::time::timeout;
use tracing::{debug, info};

use crate::codec::MessageCodec;
use crate::error::{P2pError, P2pResult};
use crate::i2p::I2pSession;
use crate::messages;
use crate::netaddr::NetAddr;
use crate::socks5::{self, ProxyConfig, Socks5Auth, Socks5Target};
use crate::transport::{
    initiate_v2, respond_v2, v1_version_prefix, PrefixedReader, RecvTransport, SendTransport,
};

static NEXT_PEER_ID: AtomicU64 = AtomicU64::new(1);

/// Nonces of our own outbound `version` messages whose handshakes are still
/// in flight (Bitcoin Core's self-connection detection). If an *inbound*
/// `version` arrives carrying one of these nonces, the "peer" is our own dial
/// looping back to us (e.g. our advertised address gossiped back into the
/// addr book) and the handshake is aborted on both ends.
static OUTBOUND_VERSION_NONCES: std::sync::Mutex<Vec<u64>> = std::sync::Mutex::new(Vec::new());

/// Registers an outbound version nonce for the guard's lifetime. The inbound
/// side always reads (and checks) our version before replying, so holding the
/// registration across `version_exchange` fully covers the loopback window.
struct NonceGuard(u64);

impl NonceGuard {
    fn register(nonce: u64) -> Self {
        OUTBOUND_VERSION_NONCES
            .lock()
            .expect("nonce set lock poisoned")
            .push(nonce);
        NonceGuard(nonce)
    }

    fn is_ours(nonce: u64) -> bool {
        OUTBOUND_VERSION_NONCES
            .lock()
            .expect("nonce set lock poisoned")
            .contains(&nonce)
    }
}

impl Drop for NonceGuard {
    fn drop(&mut self) {
        OUTBOUND_VERSION_NONCES
            .lock()
            .expect("nonce set lock poisoned")
            .retain(|n| *n != self.0);
    }
}

pub type PeerId = u64;

/// Placeholder used in the legacy `version` address fields when the peer has no
/// IP (onion/I2P). Bitcoin Core likewise sends a null address for these.
fn null_socket_addr() -> SocketAddr {
    SocketAddr::from(([0u8, 0, 0, 0], 0))
}

/// Open a TCP stream to `addr`. I2P addresses dial through the SAM session; the
/// rest route through the SOCKS5 proxy when one applies. IP peers connect
/// directly when no proxy is set; onion peers require a proxy (Tor).
async fn open_stream(
    addr: NetAddr,
    proxy: &ProxyConfig,
    i2p: Option<&I2pSession>,
) -> P2pResult<TcpStream> {
    // I2P is reached via the SAM bridge, never SOCKS5.
    if matches!(addr, NetAddr::I2p { .. }) {
        return match i2p {
            Some(session) => session.connect_peer(&addr).await,
            None => Err(P2pError::Connection(
                "I2P peer but no SAM session (set --i2psam)".into(),
            )),
        };
    }
    if let Some(proxy_addr) = proxy.proxy_for(&addr) {
        let target = match addr {
            NetAddr::Ip(sa) => Socks5Target::Ip(sa),
            NetAddr::OnionV3 { port, .. } => Socks5Target::Domain {
                // `.onion_host()` is always `Some` for an onion address.
                host: addr
                    .onion_host()
                    .ok_or_else(|| P2pError::Connection("onion host encode failed".into()))?,
                port,
            },
            NetAddr::I2p { .. } => unreachable!("handled above"),
        };
        // Per-connection random credentials isolate each dial onto its own Tor
        // circuit (Core's -proxyrandomize).
        let auth = proxy.randomize_credentials.then(|| Socks5Auth {
            username: format!("{:016x}", rand::random::<u64>()),
            password: format!("{:016x}", rand::random::<u64>()),
        });
        return socks5::connect(proxy_addr, &target, auth.as_ref()).await;
    }
    // No proxy: only IP peers are directly reachable.
    match addr {
        NetAddr::Ip(sa) => TcpStream::connect(sa)
            .await
            .map_err(|e| P2pError::Connection(format!("connect to {addr}: {e}"))),
        _ => Err(P2pError::Connection(format!(
            "no proxy configured to reach {addr}"
        ))),
    }
}

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const READ_TIMEOUT: Duration = Duration::from_secs(300); // 5 minutes

/// Information about a connected peer after handshake.
#[derive(Debug, Clone)]
pub struct PeerInfo {
    pub id: PeerId,
    pub addr: NetAddr,
    pub version: u32,
    pub services: ServiceFlags,
    pub user_agent: String,
    pub start_height: i32,
    /// Best block height we believe this peer currently has, refreshed from
    /// its headers / block-inv announcements (start_height is only its height
    /// at connect time). Backs getpeerinfo's synced_headers/synced_blocks and
    /// the web Peers page.
    pub synced_height: i32,
    pub relay: bool,
    /// Whether this is an inbound connection (they connected to us).
    pub inbound: bool,
    /// For outbound connections: the address the remote peer sees us as
    /// (from their version message `receiver` field). Used to discover our WAN IP.
    pub discovered_addr: Option<NetAddr>,
    /// Whether this connection negotiated the BIP 324 v2 encrypted transport.
    pub v2: bool,
}

/// Messages sent from the peer read loop to the manager.
pub enum PeerEvent {
    /// Received a message from this peer, with optional raw payload bytes
    /// (preserved for block messages to avoid re-serialization).
    Message(PeerId, NetworkMessage, Option<Vec<u8>>),
    /// Peer disconnected or errored.
    Disconnected(PeerId, String),
    /// An inbound peer has completed handshake and is ready.
    InboundConnected(Peer),
    /// An outbound dial (spawned off the manager's event loop, H3 2026-07-02
    /// review) has completed its handshake and is ready.
    OutboundConnected(Peer, NetAddr),
    /// An outbound dial failed; carries the target address so the manager can
    /// clear its in-flight bookkeeping.
    OutboundFailed(NetAddr, String),
}

/// A connected peer with read/write tasks.
pub struct Peer {
    pub info: PeerInfo,
    /// Send outgoing messages to this peer's write loop.
    pub msg_tx: mpsc::Sender<RawNetworkMessage>,
}

impl Peer {
    /// Connect to a peer, perform the handshake, and return a Peer plus spawned
    /// read/write loop tasks. When `v2` is set, the BIP 324 v2 transport is
    /// attempted first and the connection is retried as v1 if it fails (so v1-
    /// only peers still connect).
    #[allow(clippy::too_many_arguments)]
    pub async fn connect(
        addr: NetAddr,
        network: Network,
        start_height: i32,
        event_tx: mpsc::Sender<PeerEvent>,
        advertise_addr: Option<SocketAddr>,
        services: ServiceFlags,
        v2: bool,
        proxy: &ProxyConfig,
        i2p: Option<&I2pSession>,
    ) -> P2pResult<Self> {
        let id = NEXT_PEER_ID.fetch_add(1, Ordering::SeqCst);

        if v2 {
            match Self::connect_inner(
                id,
                addr,
                network,
                start_height,
                event_tx.clone(),
                advertise_addr,
                services,
                true,
                proxy,
                i2p,
            )
            .await
            {
                Ok(peer) => return Ok(peer),
                Err(e) => {
                    debug!(peer_id = id, %addr, "v2 connect failed ({e}); retrying as v1");
                }
            }
        }
        Self::connect_inner(
            id,
            addr,
            network,
            start_height,
            event_tx,
            advertise_addr,
            services,
            false,
            proxy,
            i2p,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn connect_inner(
        id: PeerId,
        addr: NetAddr,
        network: Network,
        start_height: i32,
        event_tx: mpsc::Sender<PeerEvent>,
        advertise_addr: Option<SocketAddr>,
        services: ServiceFlags,
        use_v2: bool,
        proxy: &ProxyConfig,
        i2p: Option<&I2pSession>,
    ) -> P2pResult<Self> {
        debug!(peer_id = id, %addr, use_v2, "Connecting to peer");

        let stream = timeout(HANDSHAKE_TIMEOUT, open_stream(addr, proxy, i2p))
            .await
            .map_err(|_| P2pError::Timeout("connection timeout".into()))??;
        stream.set_nodelay(true).ok();

        let local_addr = advertise_addr.unwrap_or_else(|| {
            stream
                .local_addr()
                .unwrap_or_else(|_| "0.0.0.0:0".parse().expect("static address is valid"))
        });

        let (mut reader, mut writer) = stream.into_split();
        let magic_bytes = network.magic().to_bytes();
        let magic = u32::from_le_bytes(magic_bytes);

        let (mut send_tr, mut recv_tr) = if use_v2 {
            let (sender, receiver) = timeout(
                HANDSHAKE_TIMEOUT,
                initiate_v2(&mut reader, &mut writer, magic_bytes),
            )
            .await
            .map_err(|_| P2pError::Timeout("v2 handshake timeout".into()))??;
            (
                SendTransport::V2(sender),
                RecvTransport::V2 {
                    recv: receiver,
                    magic: magic_bytes,
                },
            )
        } else {
            (
                SendTransport::V1(MessageCodec::new(magic)),
                RecvTransport::V1(MessageCodec::new(magic)),
            )
        };

        let their_version = version_exchange(
            &mut reader,
            &mut writer,
            &mut send_tr,
            &mut recv_tr,
            network,
            local_addr,
            addr.to_socket_addr().unwrap_or_else(null_socket_addr),
            start_height,
            services,
            false,
        )
        .await?;

        info!(
            peer_id = id, %addr, version = their_version.version,
            user_agent = %their_version.user_agent, height = their_version.start_height,
            v2 = use_v2, "Peer handshake complete"
        );

        let info = PeerInfo {
            id,
            addr,
            version: their_version.version,
            services: their_version.services,
            user_agent: their_version.user_agent.clone(),
            start_height: their_version.start_height,
            synced_height: their_version.start_height,
            relay: their_version.relay,
            inbound: false,
            discovered_addr: their_version.receiver.socket_addr().ok().map(NetAddr::Ip),
            v2: use_v2,
        };

        let msg_tx = spawn_io(id, network, send_tr, recv_tr, reader, writer, event_tx);
        Ok(Peer { info, msg_tx })
    }

    /// Accept an inbound connection. The first 16 bytes are inspected to tell a
    /// v1 `version` handshake from a v2 (BIP 324) one; when `v2` is disabled the
    /// connection is always treated as v1.
    #[allow(clippy::too_many_arguments)]
    pub async fn accept_inbound(
        stream: TcpStream,
        addr: NetAddr,
        network: Network,
        start_height: i32,
        event_tx: mpsc::Sender<PeerEvent>,
        advertise_addr: Option<SocketAddr>,
        services: ServiceFlags,
        v2: bool,
    ) -> P2pResult<Self> {
        let id = NEXT_PEER_ID.fetch_add(1, Ordering::SeqCst);
        debug!(peer_id = id, %addr, "Accepting inbound connection");
        stream.set_nodelay(true).ok();

        let local_addr = advertise_addr.unwrap_or_else(|| {
            stream
                .local_addr()
                .unwrap_or_else(|_| "0.0.0.0:0".parse().expect("static address is valid"))
        });

        let (mut raw_reader, mut writer) = stream.into_split();
        let magic_bytes = network.magic().to_bytes();
        let magic = u32::from_le_bytes(magic_bytes);

        // Peek the first 16 bytes for v1/v2 detection, then make them available
        // again to whichever handshake runs via PrefixedReader.
        let mut head = [0u8; 16];
        timeout(HANDSHAKE_TIMEOUT, raw_reader.read_exact(&mut head))
            .await
            .map_err(|_| P2pError::Timeout("inbound detect timeout".into()))?
            .map_err(|e| P2pError::Connection(format!("inbound detect read: {e}")))?;
        let is_v1 = head == v1_version_prefix(magic_bytes);
        let mut reader = PrefixedReader::new(head.to_vec(), raw_reader);

        let (mut send_tr, mut recv_tr) = if v2 && !is_v1 {
            // Committed to v2: the detection bytes are part of the ellswift key,
            // so we cannot fall back to v1 from here.
            let (sender, receiver) = timeout(
                HANDSHAKE_TIMEOUT,
                respond_v2(&mut reader, &mut writer, magic_bytes),
            )
            .await
            .map_err(|_| P2pError::Timeout("v2 handshake timeout".into()))??;
            (
                SendTransport::V2(sender),
                RecvTransport::V2 {
                    recv: receiver,
                    magic: magic_bytes,
                },
            )
        } else {
            (
                SendTransport::V1(MessageCodec::new(magic)),
                RecvTransport::V1(MessageCodec::new(magic)),
            )
        };

        let their_version = version_exchange(
            &mut reader,
            &mut writer,
            &mut send_tr,
            &mut recv_tr,
            network,
            local_addr,
            addr.to_socket_addr().unwrap_or_else(null_socket_addr),
            start_height,
            services,
            true,
        )
        .await?;

        debug!(
            peer_id = id, %addr, version = their_version.version,
            user_agent = %their_version.user_agent, height = their_version.start_height,
            v2 = !matches!(recv_tr, RecvTransport::V1(_)), "Inbound peer handshake complete"
        );

        let info = PeerInfo {
            id,
            addr,
            version: their_version.version,
            services: their_version.services,
            user_agent: their_version.user_agent.clone(),
            start_height: their_version.start_height,
            synced_height: their_version.start_height,
            relay: their_version.relay,
            inbound: true,
            // An inbound peer's `version.receiver` is the address it used to
            // reach us — a valid source of our own external address, and the
            // only one available to an inbound-only node (it has no outbound
            // peers to learn it from). Enables addr self-advertisement (O5).
            discovered_addr: their_version.receiver.socket_addr().ok().map(NetAddr::Ip),
            v2: !matches!(recv_tr, RecvTransport::V1(_)),
        };

        let msg_tx = spawn_io(id, network, send_tr, recv_tr, reader, writer, event_tx);
        Ok(Peer { info, msg_tx })
    }
}

/// Run the bitcoin version/verack exchange over an established transport.
/// `inbound` selects who sends the version message first.
#[allow(clippy::too_many_arguments)]
async fn version_exchange<R, W>(
    reader: &mut R,
    writer: &mut W,
    send_tr: &mut SendTransport,
    recv_tr: &mut RecvTransport,
    network: Network,
    local_addr: SocketAddr,
    addr: SocketAddr,
    start_height: i32,
    services: ServiceFlags,
    inbound: bool,
) -> P2pResult<VersionMessage>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let nonce = rand::random::<u64>();
    let version_msg =
        messages::build_version_message(network, local_addr, addr, start_height, nonce, services);

    // Keep our outbound nonce registered for the whole exchange so the
    // inbound side of a self-connection can recognize it (dropped on every
    // exit path via the guard).
    let _nonce_guard = (!inbound).then(|| NonceGuard::register(nonce));

    if !inbound {
        send_tr.send(writer, &version_msg).await?;
    }

    let (their_version_msg, _) = timeout(HANDSHAKE_TIMEOUT, recv_tr.recv(reader))
        .await
        .map_err(|_| P2pError::Timeout("version timeout".into()))??;
    let their_version = match their_version_msg.payload() {
        NetworkMessage::Version(v) => v.clone(),
        other => {
            return Err(P2pError::HandshakeFailed(format!(
                "expected version, got {:?}",
                other.cmd()
            )));
        }
    };

    // Self-connection detection (Core's nonce check): an inbound version
    // carrying a nonce we generated for one of our own outbound dials means
    // we connected to ourselves — our advertised address circulated back
    // through addr gossip. Abort; the outbound side sees the closed stream.
    if inbound && their_version.nonce != 0 && NonceGuard::is_ours(their_version.nonce) {
        return Err(P2pError::HandshakeFailed(
            "connected to self (version nonce match)".into(),
        ));
    }

    // Feed this peer's clock offset into the network-adjusted-time filter
    // (Core's nTimeOffset): their reported time minus our local clock.
    bitcoinpr_core::time::add_time_sample(
        their_version.timestamp - bitcoinpr_core::time::local_time_secs(),
    );

    if inbound {
        send_tr.send(writer, &version_msg).await?;
    }

    // BIP 155: offer addrv2 to peers that speak protocol >= 70016, before
    // verack (Core's ordering). Lets us learn/relay onion & I2P addresses.
    if their_version.version >= messages::PROTOCOL_VERSION {
        send_tr
            .send(writer, &messages::build_sendaddrv2(network))
            .await?;
    }

    send_tr
        .send(writer, &messages::build_verack(network))
        .await?;

    // Read verack, tolerating wtxidrelay/sendaddrv2 sent before it.
    let (verack_msg, _) = timeout(HANDSHAKE_TIMEOUT, recv_tr.recv(reader))
        .await
        .map_err(|_| P2pError::Timeout("verack timeout".into()))??;
    if !matches!(verack_msg.payload(), NetworkMessage::Verack) {
        let (next, _) = timeout(HANDSHAKE_TIMEOUT, recv_tr.recv(reader))
            .await
            .map_err(|_| P2pError::Timeout("verack timeout".into()))??;
        if !matches!(next.payload(), NetworkMessage::Verack) {
            debug!("No verack received, continuing anyway");
        }
    }

    Ok(their_version)
}

/// Spawn the read and write loop tasks and return the outbound message sender.
fn spawn_io<R, W>(
    id: PeerId,
    network: Network,
    mut send_tr: SendTransport,
    mut recv_tr: RecvTransport,
    mut reader: R,
    mut writer: W,
    event_tx: mpsc::Sender<PeerEvent>,
) -> mpsc::Sender<RawNetworkMessage>
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    // Send sendheaders to request header announcements.
    let sendheaders = messages::build_sendheaders(network);
    let (msg_tx, mut msg_rx) = mpsc::channel::<RawNetworkMessage>(1024);

    // Write loop.
    let write_event_tx = event_tx.clone();
    tokio::spawn(async move {
        // Queue sendheaders first.
        if let Err(e) = send_tr.send(&mut writer, &sendheaders).await {
            let _ = write_event_tx
                .send(PeerEvent::Disconnected(id, format!("write error: {e}")))
                .await;
            return;
        }
        while let Some(msg) = msg_rx.recv().await {
            if let Err(e) = send_tr.send(&mut writer, &msg).await {
                // Routine peer hang-up (broken pipe mid-write); the
                // Disconnected event below drives all cleanup.
                debug!(peer_id = id, "Write error: {e}");
                let _ = write_event_tx
                    .send(PeerEvent::Disconnected(id, format!("write error: {e}")))
                    .await;
                break;
            }
        }
        debug!(peer_id = id, "Write loop ended");
    });

    // Read loop.
    let read_event_tx = event_tx;
    tokio::spawn(async move {
        loop {
            match timeout(READ_TIMEOUT, recv_tr.recv(&mut reader)).await {
                Ok(Ok((raw_msg, raw_payload))) => {
                    let msg = raw_msg.payload().clone();
                    let raw_bytes = if matches!(msg, NetworkMessage::Block(_)) {
                        Some(raw_payload)
                    } else {
                        None
                    };
                    if read_event_tx
                        .send(PeerEvent::Message(id, msg, raw_bytes))
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
                Ok(Err(e)) => {
                    let _ = read_event_tx
                        .send(PeerEvent::Disconnected(id, e.to_string()))
                        .await;
                    break;
                }
                Err(_) => {
                    let _ = read_event_tx
                        .send(PeerEvent::Disconnected(id, "read timeout".into()))
                        .await;
                    break;
                }
            }
        }
        debug!(peer_id = id, "Read loop ended");
    });

    msg_tx
}

impl Peer {
    /// Send a message to this peer (non-blocking).
    pub fn send(&self, msg: RawNetworkMessage) -> P2pResult<()> {
        self.msg_tx.try_send(msg).map_err(|e| match e {
            mpsc::error::TrySendError::Full(_) => {
                P2pError::Connection("peer write channel full".into())
            }
            mpsc::error::TrySendError::Closed(_) => {
                P2pError::Connection("peer write channel closed".into())
            }
        })
    }
}
