use bitcoin::bip152::ShortId;
use bitcoin::block::Header;
use bitcoin::consensus::Decodable;
use bitcoin::hashes::Hash;
use bitcoin::p2p::message::NetworkMessage;
use bitcoin::p2p::message_blockdata::Inventory;
use bitcoin::p2p::message_compact_blocks::GetBlockTxn;
use bitcoin::{Block, BlockHash, Network, Transaction, Txid};
use bitcoinpr_core::mempool::Mempool;
use bitcoinpr_core::ConsensusParams;
use bitcoinpr_storage::{BlockStore, HeaderIndex};
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::{mpsc, RwLock};
use tracing::{debug, error, info, warn};

use crate::addr_manager::AddrManager;
use crate::dns;
use crate::fixed_seeds;
use crate::messages;
use crate::netaddr::NetAddr;
use crate::peer::{Peer, PeerEvent, PeerId, PeerInfo};
use crate::scoring::{Misbehavior, PeerScoring};

const MAX_OUTBOUND: usize = 24;
/// Outbound target when `-onlynet` excludes every IP network (Tor/I2P-only).
/// Onion-service circuits deliver a fraction of clearnet throughput
/// (~12-55 KB/s each measured), so IBD bandwidth is roughly linear in the
/// number of circuits — a larger pool is the cheapest lever.
const ONION_MAX_OUTBOUND: usize = 44;
const MAX_INBOUND: usize = 101; // total peers capped at 125 (Core default)
/// Maximum number of outbound connections per /16 subnet.
const MAX_OUTBOUND_PER_SUBNET: usize = 2;
/// How often the peer state (address book + ban list) is persisted to disk.
const PEER_STATE_SAVE_INTERVAL: std::time::Duration = std::time::Duration::from_secs(5 * 60);

/// Events emitted by the P2P manager to the node coordinator.
#[derive(Debug)]
pub enum NodeEvent {
    /// Received headers from a peer.
    Headers(PeerId, Vec<Header>),
    /// Received a full block from a peer, with optional raw serialized bytes.
    Block(PeerId, Block, Option<Vec<u8>>),
    /// Received a transaction from a peer.
    Transaction(PeerId, Transaction),
    /// A new peer connected.
    PeerConnected(PeerInfo),
    /// A peer disconnected.
    PeerDisconnected(PeerId),
    /// Peer sent notfound for requested inventory items (blocks unavailable).
    NotFound(PeerId, Vec<Inventory>),
    /// Peer announced block hashes via inv (signals the peer has these blocks).
    BlockInv(PeerId, Vec<BlockHash>),
}

/// Commands sent from the node coordinator to the P2P manager.
#[derive(Debug)]
pub enum PeerCommand {
    /// Request headers starting from these locator hashes.
    GetHeaders {
        peer_id: PeerId,
        locator_hashes: Vec<BlockHash>,
        stop_hash: BlockHash,
    },
    /// Request full blocks.
    GetBlocks {
        peer_id: PeerId,
        hashes: Vec<BlockHash>,
    },
    /// Send a ping to a peer (keepalive).
    SendPing { peer_id: PeerId, nonce: u64 },
    /// Send a pong to a peer.
    SendPong { peer_id: PeerId, nonce: u64 },
    /// Broadcast a transaction to all peers.
    BroadcastTx(Transaction),
    /// Broadcast a solved block to all peers and update the advertised height.
    BroadcastBlock(Block, u32),
    /// Report misbehavior for a peer (may result in ban + disconnect).
    Misbehaving {
        peer_id: PeerId,
        reason: Misbehavior,
    },
    /// Disconnect a peer (without banning). Used to rotate out non-delivering peers.
    DisconnectPeer { peer_id: PeerId },
    /// Aggressively refresh the peer pool during deep IBD (disconnect useless
    /// inbound peers and dial fresh outbound archive nodes).
    RefreshPeerConnections {
        disconnect_zero_height_inbound: bool,
        target_outbound: usize,
    },
    /// Shutdown the P2P manager.
    Shutdown,
}

/// Per-peer state tracking.
#[allow(dead_code)]
#[derive(Default)]
struct PeerState {
    /// Minimum fee rate (sat/kB) this peer wants to hear about (BIP 133).
    fee_filter: u64,
    /// Whether this peer wants compact blocks (BIP 152).
    wants_compact_blocks: bool,
    /// Compact block protocol version (1 or 2).
    compact_version: u64,
    /// Whether this peer sent us `sendheaders` (BIP 130), meaning it wants
    /// new-block announcements as `headers` messages rather than `inv`.
    wants_send_headers: bool,
    /// Whether this peer sent us `sendaddrv2` (BIP 155), meaning it wants
    /// address gossip in the richer `addrv2` format (required for onion/I2P).
    wants_addrv2: bool,
    /// BIP 37 bloom filter loaded by this peer via `filterload`. `None` until
    /// the peer loads one (and only ever set when `peer_bloom_filters` is on).
    bloom_filter: Option<crate::bloom::BloomFilter>,
}

/// Tracks a compact block awaiting missing transactions from a `getblocktxn` response.
struct PendingCompactBlock {
    /// The block header.
    header: Header,
    /// Ordered transaction slots: Some = already known, None = awaiting from peer.
    txs: Vec<Option<Transaction>>,
    /// Peer that sent the compact block.
    #[allow(dead_code)]
    peer_id: PeerId,
}

const MAX_SEEN_TXIDS: usize = 50_000;

/// Bounded set tracking recently seen transaction IDs to avoid duplicate requests.
struct SeenTxids {
    set: HashSet<Txid>,
    order: VecDeque<Txid>,
}

impl SeenTxids {
    fn new() -> Self {
        SeenTxids {
            set: HashSet::with_capacity(MAX_SEEN_TXIDS),
            order: VecDeque::with_capacity(MAX_SEEN_TXIDS),
        }
    }

    fn contains(&self, txid: &Txid) -> bool {
        self.set.contains(txid)
    }

    fn insert(&mut self, txid: Txid) -> bool {
        if !self.set.insert(txid) {
            return false;
        }
        self.order.push_back(txid);
        while self.order.len() > MAX_SEEN_TXIDS {
            if let Some(old) = self.order.pop_front() {
                self.set.remove(&old);
            }
        }
        true
    }
}

/// Manages all peer connections and routes messages.
pub struct PeerManager {
    network: Network,
    params: ConsensusParams,
    peers: HashMap<PeerId, Peer>,
    peer_state: HashMap<PeerId, PeerState>,
    /// Channel for receiving events from peer read loops.
    peer_event_tx: mpsc::Sender<PeerEvent>,
    peer_event_rx: mpsc::Receiver<PeerEvent>,
    /// Channel for sending events to the node coordinator.
    node_event_tx: mpsc::Sender<NodeEvent>,
    /// Dedicated high-capacity channel for full blocks (avoids starving on
    /// headers/inv/tx traffic on the main node event channel).
    block_event_tx: mpsc::Sender<NodeEvent>,
    /// Channel for receiving commands from the node coordinator.
    command_rx: mpsc::Receiver<PeerCommand>,
    /// Manual connect addresses.
    connect_addrs: Vec<NetAddr>,
    /// Port to listen for inbound connections.
    listen_port: u16,
    /// Number of inbound peers.
    inbound_count: usize,
    /// Set of peer IDs that connected inbound (used to correctly decrement inbound_count).
    inbound_peers: std::collections::HashSet<PeerId>,
    /// Peer misbehavior scoring and banning.
    scoring: PeerScoring,
    /// Known peer address manager.
    addr_manager: AddrManager,
    /// Peer ID to address mapping (for subnet tracking / anchors).
    peer_addrs: HashMap<PeerId, NetAddr>,
    /// Shared mempool for serving GetData requests.
    mempool: Arc<RwLock<Mempool>>,
    /// Recently seen transaction IDs to avoid duplicate requests.
    seen_txids: SeenTxids,
    /// Pending compact block reconstructions awaiting missing transactions.
    pending_compact: HashMap<BlockHash, PendingCompactBlock>,
    /// Our discovered external (WAN) IP address, learned from outbound peers'
    /// version messages. We take the most-reported address.
    discovered_external_ip: Option<IpAddr>,
    /// Votes for our external IP from different outbound peers.
    external_ip_votes: HashMap<IpAddr, u32>,
    /// Shared advertise address for spawned tasks (inbound listener, retry connects).
    /// Updated when we discover our WAN IP so new connections advertise the correct address.
    shared_advertise_addr: Arc<std::sync::RwLock<Option<SocketAddr>>>,
    /// Shared best block height, updated by the validation loop.
    /// Used in version messages so new peers see our current height.
    shared_best_height: Arc<std::sync::RwLock<i32>>,
    /// Timestamp of the last self-addr broadcast (for 24h re-advertisement).
    last_addr_broadcast: Option<std::time::Instant>,
    /// Timestamp of the last DNS seed re-resolution. The addr manager holds
    /// thousands of addresses, so re-resolving on every 30s maintenance tick
    /// is pure noise — only refresh every 5 minutes or when short of candidates.
    last_dns_resolve: Option<std::time::Instant>,
    /// Timestamp of the last built-in fixed-seed injection. Injection is the
    /// bootstrap of last resort (empty/starved address book, e.g. a cold-start
    /// Tor-only node); rate-limited so a fully unreachable network doesn't
    /// re-add the same addresses on every maintenance tick.
    last_fixed_seed_inject: Option<std::time::Instant>,
    /// Header index for serving getheaders requests from inbound peers.
    header_index: Option<Arc<HeaderIndex>>,
    /// Block store for serving getdata(block) requests from inbound peers.
    block_store: Option<Arc<BlockStore>>,
    /// BIP 37 / BIP 111: whether we serve bloom-filtered connections. When false
    /// (the default) we ignore filter messages and never advertise NODE_BLOOM.
    peer_bloom_filters: bool,
    /// BIP 159: this node prunes block data — advertise NODE_NETWORK_LIMITED
    /// instead of NODE_NETWORK.
    network_limited: bool,
    /// When true, skip IPv6 addresses for outbound dials and addr learning.
    disable_ipv6: bool,
    /// BIP 324: attempt the v2 encrypted transport on outbound dials and accept
    /// it on inbound connections (falling back to v1 transparently).
    v2_transport: bool,
    /// SOCKS5 proxy configuration for outbound dials (Tor `-proxy`/`-onion`).
    proxy: crate::socks5::ProxyConfig,
    /// `-onlynet`: when non-empty, restrict outbound dials to these networks.
    /// Empty = all networks allowed.
    onlynet: HashSet<crate::netaddr::AddrNetwork>,
    /// Outbound connection target: `MAX_OUTBOUND` normally, raised to
    /// `ONION_MAX_OUTBOUND` when `-onlynet` excludes all IP networks
    /// (per-circuit throughput over Tor/I2P is far lower than clearnet).
    outbound_target: usize,
    /// Shared list of addresses we advertise as our own (IP / onion / I2P),
    /// surfaced by the RPC `getnetworkinfo` `localaddresses`. `None` disables.
    local_addresses: Option<Arc<std::sync::RwLock<Vec<NetAddr>>>>,
    /// I2P SAM session for dialing/accepting I2P peers. `None` disables I2P.
    i2p_session: Option<Arc<crate::i2p::I2pSession>>,
    /// Whether to run the I2P inbound `STREAM ACCEPT` loop.
    i2p_accept: bool,
    /// Test-only: treat RFC1918 / private IPv4 addresses as routable so the
    /// external-address discovery and `addr` self-advertisement path (O5/O7) can
    /// be exercised end-to-end on a private interop cluster. Never enabled in
    /// production; loopback / unspecified / link-local / documentation addresses
    /// are still rejected.
    gossip_private_addrs: bool,
    /// Directory where peers.dat / banlist.json are persisted.
    /// `None` disables persistence (e.g. in tests).
    peer_state_dir: Option<PathBuf>,
    /// Anchor addresses loaded from peers.dat: the outbound peers we were
    /// connected to at the last shutdown, re-dialed first on startup
    /// (Core's anchors.dat concept) so a restarted node reconnects to its
    /// recent peers instead of bootstrapping trust from DNS seeds alone.
    anchors: Vec<NetAddr>,
    /// Outbound dials currently in flight (spawned, handshake not yet
    /// resolved). Prevents duplicate dials to the same address and counts
    /// toward the outbound target so maintenance ticks don't over-dial.
    inflight_dials: HashSet<NetAddr>,
    /// When the peer state was last persisted (periodic-save bookkeeping).
    last_peer_state_save: std::time::Instant,
}

/// Normalize IPv4-mapped IPv6 addresses (`::ffff:a.b.c.d`) to plain IPv4 so
/// identity comparisons work across the two representations — inbound
/// connections on a dual-stack listener report the mapped form while addr
/// gossip carries plain IPv4.
fn canonical_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(v6)),
        v4 => v4,
    }
}

impl PeerManager {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        network: Network,
        params: ConsensusParams,
        node_event_tx: mpsc::Sender<NodeEvent>,
        block_event_tx: mpsc::Sender<NodeEvent>,
        command_rx: mpsc::Receiver<PeerCommand>,
        connect_addrs: Vec<NetAddr>,
        mempool: Arc<RwLock<Mempool>>,
        shared_best_height: Arc<std::sync::RwLock<i32>>,
    ) -> Self {
        Self::with_port(
            network,
            params.default_port,
            params,
            node_event_tx,
            block_event_tx,
            command_rx,
            connect_addrs,
            mempool,
            shared_best_height,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn with_port(
        network: Network,
        listen_port: u16,
        params: ConsensusParams,
        node_event_tx: mpsc::Sender<NodeEvent>,
        block_event_tx: mpsc::Sender<NodeEvent>,
        command_rx: mpsc::Receiver<PeerCommand>,
        connect_addrs: Vec<NetAddr>,
        mempool: Arc<RwLock<Mempool>>,
        shared_best_height: Arc<std::sync::RwLock<i32>>,
    ) -> Self {
        let (peer_event_tx, peer_event_rx) = mpsc::channel(1024);
        PeerManager {
            network,
            params,
            peers: HashMap::new(),
            peer_state: HashMap::new(),
            peer_event_tx,
            peer_event_rx,
            node_event_tx,
            block_event_tx,
            command_rx,
            connect_addrs,
            listen_port,
            inbound_count: 0,
            inbound_peers: std::collections::HashSet::new(),
            scoring: PeerScoring::new(),
            addr_manager: AddrManager::new(),
            peer_addrs: HashMap::new(),
            mempool,
            seen_txids: SeenTxids::new(),
            pending_compact: HashMap::new(),
            discovered_external_ip: None,
            external_ip_votes: HashMap::new(),
            shared_advertise_addr: Arc::new(std::sync::RwLock::new(None)),
            shared_best_height,
            last_addr_broadcast: None,
            last_dns_resolve: None,
            last_fixed_seed_inject: None,
            header_index: None,
            block_store: None,
            peer_bloom_filters: false,
            network_limited: false,
            inflight_dials: HashSet::new(),
            disable_ipv6: false,
            v2_transport: false,
            proxy: crate::socks5::ProxyConfig::default(),
            onlynet: HashSet::new(),
            outbound_target: MAX_OUTBOUND,
            local_addresses: None,
            i2p_session: None,
            i2p_accept: false,
            gossip_private_addrs: false,
            peer_state_dir: None,
            anchors: Vec::new(),
            last_peer_state_save: std::time::Instant::now(),
        }
    }

    /// Load persisted peer state (peers.dat + banlist.json) from `dir` and
    /// remember the directory for periodic / shutdown saves. Must be called
    /// before `run()` so the connect loop sees the loaded state. Corrupt or
    /// missing files never block startup — warn and start fresh.
    pub fn load_peer_state(&mut self, dir: &Path) {
        self.peer_state_dir = Some(dir.to_path_buf());

        // Active bans always load, even under --connect: a ban must survive
        // a restart or every misbehaving IP gets a free unban on reboot.
        let ban_path = dir.join("banlist.json");
        match std::fs::read(&ban_path) {
            Ok(data) => self.scoring.load_from_bytes(&data),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => warn!("Failed to read {}: {}", ban_path.display(), e),
        }

        // The address book and anchors are skipped when a manual --connect
        // list is set: pinned topologies (e.g. the interop cluster) must keep
        // dialing exactly their configured peers.
        if !self.connect_addrs.is_empty() {
            return;
        }
        let peers_path = dir.join("peers.dat");
        match std::fs::read(&peers_path) {
            Ok(data) => {
                self.anchors = self.addr_manager.load_from_bytes(&data);
                info!(
                    addrs = self.addr_manager.len(),
                    anchors = self.anchors.len(),
                    "Loaded persisted peer address book"
                );
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => warn!("Failed to read {}: {}", peers_path.display(), e),
        }
    }

    /// Up to `MAX_ANCHORS` currently-connected outbound peer addresses.
    /// `peer_addrs` only ever contains outbound peers (inbound connections
    /// are tracked in `inbound_peers` and never inserted here), so every
    /// candidate is a valid anchor.
    fn current_anchors(&self) -> Vec<NetAddr> {
        self.peer_addrs
            .values()
            .copied()
            .take(crate::addr_manager::MAX_ANCHORS)
            .collect()
    }

    /// Persist the address book (peers.dat) and active bans (banlist.json)
    /// to the configured datadir. Failures are logged and never abort the
    /// node. No-op when persistence is not configured.
    fn save_peer_state(&mut self) {
        let Some(dir) = self.peer_state_dir.clone() else {
            return;
        };
        let anchors = self.current_anchors();
        let peers_bytes = self.addr_manager.save_to_bytes(&anchors);
        let bans_bytes = self.scoring.save_to_bytes();
        if let Err(e) = Self::write_atomic(&dir.join("peers.dat"), &peers_bytes) {
            warn!("Failed to save peers.dat: {}", e);
        }
        if let Err(e) = Self::write_atomic(&dir.join("banlist.json"), &bans_bytes) {
            warn!("Failed to save banlist.json: {}", e);
        }
        self.last_peer_state_save = std::time::Instant::now();
        debug!(
            addrs = self.addr_manager.len(),
            anchors = anchors.len(),
            "Peer state saved"
        );
    }

    /// Write `data` to `<path>.tmp` then rename into place, so a crash
    /// mid-save never corrupts the previous on-disk state.
    fn write_atomic(path: &Path, data: &[u8]) -> std::io::Result<()> {
        let mut tmp = path.as_os_str().to_owned();
        tmp.push(".tmp");
        let tmp = PathBuf::from(tmp);
        std::fs::write(&tmp, data)?;
        std::fs::rename(&tmp, path)
    }

    /// Skip IPv6 addresses for outbound peer connections and addr-manager adds.
    pub fn set_disable_ipv6(&mut self, disable: bool) {
        self.disable_ipv6 = disable;
        if disable {
            info!("IPv6 peer connections disabled — outbound dials use IPv4 only");
        }
    }

    /// Enable the BIP 324 v2 encrypted transport (outbound initiation + inbound
    /// acceptance, with transparent v1 fallback).
    pub fn set_v2_transport(&mut self, enable: bool) {
        self.v2_transport = enable;
        if enable {
            info!("BIP 324 v2 transport enabled");
        }
    }

    /// Set the SOCKS5 proxy configuration (Tor `-proxy`/`-onion`). When a proxy
    /// is set, outbound dials to the relevant networks are routed through it.
    pub fn set_proxy(&mut self, proxy: crate::socks5::ProxyConfig) {
        if let Some(p) = proxy.ip_proxy {
            info!(proxy = %p, "SOCKS5 proxy enabled for IP connections");
        }
        if let Some(p) = proxy.onion_proxy {
            info!(proxy = %p, "SOCKS5 proxy enabled for onion connections");
        }
        self.proxy = proxy;
    }

    /// Restrict outbound connections to the given networks (`-onlynet`). Empty
    /// leaves all networks enabled.
    pub fn set_onlynet(&mut self, nets: Vec<crate::netaddr::AddrNetwork>) {
        use crate::netaddr::AddrNetwork;
        self.onlynet = nets.into_iter().collect();
        let ip_allowed = self.onlynet.is_empty()
            || self.onlynet.contains(&AddrNetwork::Ipv4)
            || self.onlynet.contains(&AddrNetwork::Ipv6);
        self.outbound_target = if ip_allowed {
            MAX_OUTBOUND
        } else {
            ONION_MAX_OUTBOUND
        };
        if !self.onlynet.is_empty() {
            let names: Vec<&str> = self.onlynet.iter().map(|n| n.as_str()).collect();
            info!(
                networks = ?names,
                outbound_target = self.outbound_target,
                "Outbound connections restricted to -onlynet"
            );
        }
    }

    /// Attach the shared advertised-address list (`getnetworkinfo`
    /// `localaddresses`). Callers may also push a `.onion`/I2P self-address.
    pub fn set_local_addresses(&mut self, handle: Arc<std::sync::RwLock<Vec<NetAddr>>>) {
        self.local_addresses = Some(handle);
    }

    /// Attach an I2P SAM session so the node can dial (and, when `accept` is
    /// set, receive) I2P peers.
    pub fn set_i2p_session(&mut self, session: Arc<crate::i2p::I2pSession>, accept: bool) {
        self.i2p_session = Some(session);
        self.i2p_accept = accept;
    }

    /// Publish one of our own addresses into the shared advertised-address list
    /// (deduplicated). No-op when the list isn't attached.
    fn publish_local_addr(&self, addr: NetAddr) {
        if let Some(list) = &self.local_addresses {
            if let Ok(mut v) = list.write() {
                if !v.contains(&addr) {
                    v.push(addr);
                }
            }
        }
    }

    /// Our own advertised addresses (IP / onion / I2P). Falls back to the
    /// discovered external IP when no shared list is attached.
    fn self_advertised_addrs(&self) -> Vec<NetAddr> {
        if let Some(list) = &self.local_addresses {
            if let Ok(v) = list.read() {
                if !v.is_empty() {
                    return v.clone();
                }
            }
        }
        self.discovered_external_ip
            .map(|ip| NetAddr::Ip(SocketAddr::new(ip, self.listen_port)))
            .into_iter()
            .collect()
    }

    /// Whether `addr` is one of our own advertised addresses — used to avoid
    /// self-dialing our own onion/I2P address gossiped back to us.
    fn is_self_addr(&self, addr: &NetAddr) -> bool {
        if let Some(list) = &self.local_addresses {
            if let Ok(v) = list.read() {
                return v.contains(addr);
            }
        }
        false
    }

    /// Whether clearnet DNS seeding is permitted. Skipped when `-onlynet`
    /// excludes both IPv4 and IPv6 (e.g. a Tor-only node), so a private node
    /// never leaks a clearnet DNS lookup.
    fn dns_seeding_allowed(&self) -> bool {
        use crate::netaddr::AddrNetwork;
        self.onlynet.is_empty()
            || self.onlynet.contains(&AddrNetwork::Ipv4)
            || self.onlynet.contains(&AddrNetwork::Ipv6)
    }

    /// Test-only: allow RFC1918 / private IPv4 addresses to be adopted as our
    /// external address and gossiped, so O5/O7 can be wire-validated on a
    /// private interop cluster. Must never be set in production.
    pub fn set_gossip_private_addrs(&mut self, enable: bool) {
        self.gossip_private_addrs = enable;
        if enable {
            warn!("gossip-private-addrs enabled — private/RFC1918 addresses are treated as routable (TEST ONLY)");
        }
    }

    /// Inject built-in fixed seeds into the address book — the bootstrap of
    /// last resort. Called when the book cannot supply enough dial candidates
    /// after DNS seeding was skipped (`-onlynet` without IP networks) or came
    /// back empty. A random subset is added so restarts don't hammer the same
    /// few seed nodes; entries are filtered by `-onlynet`/`-disableipv6` so a
    /// Tor-only node never pollutes its book with unreachable IP seeds.
    /// Rate-limited to once per 10 minutes; returns whether any were added.
    fn maybe_inject_fixed_seeds(&mut self) -> bool {
        const REINJECT_INTERVAL: std::time::Duration = std::time::Duration::from_secs(600);
        /// Plenty to fill MAX_OUTBOUND even with a poor success rate, without
        /// drowning reliability-sorted gossip entries in seed noise.
        const MAX_INJECT: usize = 128;
        if self
            .last_fixed_seed_inject
            .is_some_and(|t| t.elapsed() < REINJECT_INTERVAL)
        {
            return false;
        }
        let mut seeds: Vec<NetAddr> = fixed_seeds::fixed_seeds(self.params.network)
            .into_iter()
            .filter(|a| self.outbound_addr_allowed(*a))
            .collect();
        if seeds.is_empty() {
            return false;
        }
        self.last_fixed_seed_inject = Some(std::time::Instant::now());
        use rand::seq::SliceRandom;
        seeds.shuffle(&mut rand::thread_rng());
        seeds.truncate(MAX_INJECT);
        for addr in &seeds {
            self.addr_manager.add(*addr, 0);
        }
        info!(
            count = seeds.len(),
            "Address book starved — seeding from built-in fixed seeds"
        );
        true
    }

    fn outbound_addr_allowed(&self, addr: NetAddr) -> bool {
        // `-onlynet`: when set, only dial the listed networks.
        if !self.onlynet.is_empty() && !self.onlynet.contains(&addr.network()) {
            return false;
        }
        // `disable_ipv6` only gates IPv6; onion/I2P pass through here (they are
        // gated by `-onlynet`/proxy availability instead).
        match addr.ip() {
            Some(ip) => !self.disable_ipv6 || matches!(ip, IpAddr::V4(_)),
            None => true,
        }
    }

    /// Attach the header index and block store so this manager can respond to
    /// `getheaders` and `getdata(block)` requests from inbound peers.
    pub fn set_chain_storage(
        &mut self,
        header_index: Arc<HeaderIndex>,
        block_store: Arc<BlockStore>,
    ) {
        self.header_index = Some(header_index);
        self.block_store = Some(block_store);
    }

    /// Enable/disable serving BIP 37 bloom-filtered connections (BIP 111).
    /// When enabled we advertise NODE_BLOOM and honor filter messages.
    pub fn set_peer_bloom_filters(&mut self, enabled: bool) {
        self.peer_bloom_filters = enabled;
    }

    /// Mark this node as pruned: advertise NODE_NETWORK_LIMITED (BIP 159)
    /// instead of NODE_NETWORK.
    pub fn set_network_limited(&mut self, enabled: bool) {
        self.network_limited = enabled;
    }

    /// Service flags we advertise in version / addr messages.
    /// BIP 111: NODE_BLOOM only when serving bloom filters.
    /// BIP 159: NODE_NETWORK_LIMITED (instead of NODE_NETWORK) when pruning.
    fn advertised_services(&self) -> bitcoin::p2p::ServiceFlags {
        messages::node_service_flags(self.peer_bloom_filters, self.network_limited)
    }

    /// Check if an IP address is globally routable (not private, loopback, etc.)
    ///
    /// With the test-only `gossip_private_addrs` override set, RFC1918 private
    /// IPv4 addresses are also treated as routable so the external-address
    /// discovery / `addr` self-advertisement path can run on a private interop
    /// cluster; loopback / unspecified / link-local / documentation addresses
    /// remain non-routable in every mode.
    fn is_routable(&self, ip: &IpAddr) -> bool {
        match ip {
            IpAddr::V4(v4) => {
                !v4.is_loopback()
                    && !v4.is_unspecified()
                    && (self.gossip_private_addrs || !v4.is_private())
                    && !v4.is_link_local()
                    && !v4.is_broadcast()
                    && !v4.is_documentation()
            }
            IpAddr::V6(v6) => !v6.is_loopback() && !v6.is_unspecified(),
        }
    }

    /// Extract the /16 subnet prefix from an IP address.
    fn subnet_key(ip: &IpAddr) -> u16 {
        match ip {
            IpAddr::V4(v4) => {
                let octets = v4.octets();
                ((octets[0] as u16) << 8) | (octets[1] as u16)
            }
            IpAddr::V6(v6) => {
                let segments = v6.segments();
                segments[0] // Use the first /16 of the IPv6 address
            }
        }
    }

    /// Count how many outbound peers we have in a given /16 subnet.
    fn outbound_peers_in_subnet(&self, ip: &IpAddr) -> usize {
        let target_subnet = Self::subnet_key(ip);
        self.peer_addrs
            .values()
            .filter_map(|peer_addr| peer_addr.ip())
            .filter(|peer_ip| Self::subnet_key(peer_ip) == target_subnet)
            .count()
    }

    /// Whether we already have *any* connection (inbound or outbound) to this IP.
    /// Compares by IP, not socket address: an inbound peer's `info.addr` carries
    /// its ephemeral source port, so a port-exact check would miss it and let the
    /// maintenance loop redial a peer we are already connected to — a redundant
    /// connect/drop cycle (the churn O7 is about) once peer addresses are known.
    fn already_connected_ip(&self, ip: &IpAddr) -> bool {
        let ip = canonical_ip(*ip);
        self.peers
            .values()
            .filter_map(|p| p.info.addr.ip())
            .any(|peer_ip| canonical_ip(peer_ip) == ip)
    }

    /// Whether we already have a connection to this exact onion/I2P address.
    /// Onion/I2P peers have no IP, so they are deduped by full address equality.
    fn already_connected_addr(&self, addr: &NetAddr) -> bool {
        self.peers.values().any(|p| p.info.addr == *addr)
    }

    /// Network-agnostic "already connected?" — by IP for IP peers (so an inbound
    /// peer's ephemeral source port doesn't hide a duplicate), by exact address
    /// for onion/I2P.
    fn already_connected(&self, addr: &NetAddr) -> bool {
        match addr.ip() {
            Some(ip) => self.already_connected_ip(&ip),
            None => self.already_connected_addr(addr),
        }
    }

    /// Whether `ip` is our own discovered external address. Dialing it would
    /// be a self-connection: our advertised address circulates back through
    /// addr gossip and lands in the dial candidate list. (The version-nonce
    /// check in the handshake is the backstop for the window before the
    /// external address is discovered.)
    fn is_self_ip(&self, ip: &IpAddr) -> bool {
        self.discovered_external_ip
            .map(|own| canonical_ip(own) == canonical_ip(*ip))
            .unwrap_or(false)
    }

    /// Run the peer manager event loop.
    pub async fn run(&mut self) {
        // Anchor connections: re-dial the outbound peers we were connected to
        // at the last shutdown, before DNS seeding and regardless of other
        // addr-manager candidates. This closes the restart-time eclipse
        // window and makes a restarted node dial out immediately instead of
        // sitting passively until peers re-dial it. One attempt each —
        // failures are simply dropped. Empty when a --connect list is set
        // (anchors are never loaded in that case).
        let anchors = std::mem::take(&mut self.anchors);
        for addr in anchors {
            info!(%addr, "Dialing anchor peer from previous session");
            self.connect_to_peer(addr);
        }

        // Resolve peer addresses
        let mut addrs = self.connect_addrs.clone();
        if addrs.is_empty() {
            if self.dns_seeding_allowed() {
                info!("Resolving DNS seeds...");
                addrs = dns::resolve_seeds(&self.params)
                    .await
                    .into_iter()
                    .map(NetAddr::Ip)
                    .collect();
            } else {
                info!("Skipping clearnet DNS seeds (-onlynet excludes IP networks)");
            }
            // Fold in reliability-sorted candidates from the persisted
            // address book so a restarted node reconnects to known-good
            // peers even when DNS seeding returns nothing (essential in a
            // Tor-only setup, which bootstraps from the addr book / -addnode).
            for candidate in self.addr_manager.get_for_connect(self.outbound_target) {
                if !addrs.contains(&candidate) {
                    addrs.push(candidate);
                }
            }
            // Bootstrap of last resort: with DNS skipped (Tor-only) and a
            // cold/wiped address book there may be nothing left to dial.
            if addrs.len() < self.outbound_target && self.maybe_inject_fixed_seeds() {
                for candidate in self.addr_manager.get_for_connect(self.outbound_target) {
                    if !addrs.contains(&candidate) {
                        addrs.push(candidate);
                    }
                }
            }
        }

        if addrs.is_empty() && self.peers.is_empty() {
            warn!("No outbound peer addresses available");
            // Don't return — still need to listen for inbound connections
        }

        // Start inbound listener
        let listen_addr: SocketAddr = format!("0.0.0.0:{}", self.listen_port)
            .parse()
            .expect("0.0.0.0:<u16 port> is always a valid socket address");
        let listener = match TcpListener::bind(listen_addr).await {
            Ok(l) => {
                info!(%listen_addr, "Listening for inbound connections");
                Some(l)
            }
            Err(e) => {
                warn!(%listen_addr, "Failed to bind P2P listener: {}", e);
                None
            }
        };

        // Spawn inbound accept loop.  Keep the JoinHandle so we can abort it
        // on shutdown — otherwise the listener keeps accepting (and handshaking)
        // connections long after the manager's main loop has exited.
        let listener_handle = if let Some(listener) = listener {
            let inbound_event_tx = self.peer_event_tx.clone();
            let inbound_network = self.network;
            let inbound_adv = self.shared_advertise_addr.clone();
            let inbound_height = self.shared_best_height.clone();
            // BIP 111: services advertised on inbound handshakes (captured at spawn).
            let inbound_services = self.advertised_services();
            let inbound_v2 = self.v2_transport;
            Some(tokio::spawn(async move {
                loop {
                    match listener.accept().await {
                        Ok((stream, addr)) => {
                            let event_tx = inbound_event_tx.clone();
                            let adv = *inbound_adv.read().expect("lock poisoned");
                            let height = *inbound_height.read().expect("lock poisoned");
                            tokio::spawn(async move {
                                match Peer::accept_inbound(
                                    stream,
                                    NetAddr::Ip(addr),
                                    inbound_network,
                                    height,
                                    event_tx.clone(),
                                    adv,
                                    inbound_services,
                                    inbound_v2,
                                )
                                .await
                                {
                                    Ok(peer) => {
                                        let _ =
                                            event_tx.send(PeerEvent::InboundConnected(peer)).await;
                                    }
                                    Err(e) => {
                                        debug!(%addr, "Inbound handshake failed: {}", e);
                                    }
                                }
                            });
                        }
                        Err(e) => {
                            error!("Accept error: {}", e);
                        }
                    }
                }
            }))
        } else {
            None
        };

        // I2P inbound: loop on SAM `STREAM ACCEPT`, handing each accepted stream
        // to the same handshake path as TCP inbound (tagged with the peer's
        // .b32.i2p address).
        if self.i2p_accept {
            if let Some(session) = self.i2p_session.clone() {
                let i2p_event_tx = self.peer_event_tx.clone();
                let i2p_network = self.network;
                let i2p_height = self.shared_best_height.clone();
                let i2p_services = self.advertised_services();
                let i2p_v2 = self.v2_transport;
                tokio::spawn(async move {
                    loop {
                        match session.accept().await {
                            Ok((stream, peer_addr)) => {
                                let event_tx = i2p_event_tx.clone();
                                let height = *i2p_height.read().expect("lock poisoned");
                                tokio::spawn(async move {
                                    match Peer::accept_inbound(
                                        stream,
                                        peer_addr,
                                        i2p_network,
                                        height,
                                        event_tx.clone(),
                                        None,
                                        i2p_services,
                                        i2p_v2,
                                    )
                                    .await
                                    {
                                        Ok(peer) => {
                                            let _ = event_tx
                                                .send(PeerEvent::InboundConnected(peer))
                                                .await;
                                        }
                                        Err(e) => {
                                            debug!(%peer_addr, "I2P inbound handshake failed: {e}")
                                        }
                                    }
                                });
                            }
                            Err(e) => {
                                // A transient SAM error shouldn't spin the loop.
                                debug!("I2P accept error: {e}");
                                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                            }
                        }
                    }
                });
                info!("I2P inbound accept loop started");
            }
        }

        // Seed address manager with resolved addresses
        for addr in &addrs {
            self.addr_manager.add(*addr, 0);
        }

        // Connect to initial peers (skipping any already connected as anchors)
        let max_connect = addrs.len().min(self.outbound_target);
        for addr in addrs.iter().take(max_connect) {
            let already = self.peers.values().any(|p| p.info.addr == *addr);
            if !already && self.outbound_addr_allowed(*addr) {
                self.connect_to_peer(*addr);
            }
        }

        let _addr_idx = max_connect; // retained for clarity; replaced by addr_manager.get_for_connect()
        let mut peer_maintenance = tokio::time::interval(std::time::Duration::from_secs(30));
        peer_maintenance.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        // Main event loop
        loop {
            tokio::select! {
                Some(event) = self.peer_event_rx.recv() => {
                    match event {
                        PeerEvent::Message(peer_id, msg, raw_bytes) => {
                            self.handle_message(peer_id, msg, raw_bytes).await;
                        }
                        PeerEvent::InboundConnected(peer) => {
                            if self.inbound_count >= MAX_INBOUND {
                                debug!("Max inbound reached, dropping connection");
                                continue;
                            }
                            if let Some(ip) = peer.info.addr.ip() {
                                if self.scoring.is_banned(&ip) {
                                    debug!(addr = %peer.info.addr, "Rejected banned inbound peer");
                                    continue;
                                }
                            }
                            let info = peer.info.clone();
                            let id = info.id;
                            if let Some(ip) = info.addr.ip() {
                                self.scoring.register_peer(id, ip);
                            }
                            // Track per-peer state (fee filter, sendheaders, bloom
                            // filter, ...) for inbound peers too, so BIP 37 filter
                            // messages have somewhere to live.
                            self.peer_state.insert(id, PeerState::default());
                            self.peers.insert(id, peer);
                            self.inbound_count += 1;
                            self.inbound_peers.insert(id);
                            // Learn our external address from how this inbound peer
                            // addressed us (their version.receiver) and self-advertise.
                            // This is the only address source for an inbound-only node.
                            if let Some(discovered) =
                                info.discovered_addr.and_then(|d| d.to_socket_addr())
                            {
                                self.note_external_addr(id, discovered);
                            }
                            debug!(peer_id = id, addr = %info.addr, "Inbound peer connected");
                            let _ = self.node_event_tx.try_send(NodeEvent::PeerConnected(info));
                        }
                        PeerEvent::OutboundConnected(peer, addr) => {
                            let peer_id = peer.info.id;
                            info!(peer_id, %addr, "Outbound peer connected");
                            self.register_outbound_peer(peer, addr);
                        }
                        PeerEvent::OutboundFailed(addr, reason) => {
                            self.inflight_dials.remove(&addr);
                            debug!(%addr, "Failed to connect: {}", reason);
                        }
                        PeerEvent::Disconnected(peer_id, reason) => {
                            debug!(peer_id, %reason, "Peer disconnected");
                            self.disconnect_peer(peer_id);
                            let _ = self.node_event_tx.try_send(NodeEvent::PeerDisconnected(peer_id));

                            // Try to maintain outbound connection count using
                            // addr_manager's reliability-sorted list.
                            let outbound = self.peers.len().saturating_sub(self.inbound_count)
                                + self.inflight_dials.len();
                            if outbound < self.outbound_target {
                                let candidates = self.addr_manager.get_for_connect(10);
                                for candidate in candidates {
                                    let already = self.peers.values().any(|p| p.info.addr == candidate);
                                    if !already {
                                        self.connect_to_peer(candidate);
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }
                Some(cmd) = self.command_rx.recv() => {
                    match cmd {
                        PeerCommand::GetHeaders { peer_id, locator_hashes, stop_hash } => {
                            if let Some(peer) = self.peers.get(&peer_id) {
                                let msg = messages::build_getheaders(self.network, locator_hashes, stop_hash);
                                if peer.send(msg).is_err() {
                                    warn!(peer_id, "Peer write channel full/closed, disconnecting");
                                    self.disconnect_peer(peer_id);
                                    let _ = self.node_event_tx.try_send(NodeEvent::PeerDisconnected(peer_id));
                                }
                            }
                        }
                        PeerCommand::GetBlocks { peer_id, hashes } => {
                            // Bitcoin Core limits to 16 blocks per getdata
                            // (MAX_BLOCKS_IN_TRANSIT_PER_PEER). Sending more
                            // causes many peers to disconnect or deprioritize us.
                            if let Some(peer) = self.peers.get(&peer_id) {
                                let mut send_failed = false;
                                for chunk in hashes.chunks(16) {
                                    let msg = messages::build_getdata_blocks(self.network, chunk.to_vec());
                                    if peer.send(msg).is_err() {
                                        warn!(peer_id, "Peer write channel full on getdata, disconnecting");
                                        send_failed = true;
                                        break;
                                    }
                                }
                                if send_failed {
                                    // Peer connection is broken — trigger disconnect
                                    // so blocks get re-queued immediately.
                                    self.disconnect_peer(peer_id);
                                    let _ = self.node_event_tx.try_send(NodeEvent::PeerDisconnected(peer_id));
                                }
                            }
                        }
                        PeerCommand::SendPing { peer_id, nonce } => {
                            if let Some(peer) = self.peers.get(&peer_id) {
                                let msg = messages::build_ping(self.network, nonce);
                                let _ = peer.send(msg);
                            }
                        }
                        PeerCommand::SendPong { peer_id, nonce } => {
                            if let Some(peer) = self.peers.get(&peer_id) {
                                let msg = messages::build_pong(self.network, nonce);
                                let _ = peer.send(msg);
                            }
                        }
                        PeerCommand::BroadcastTx(tx) => {
                            let txid = tx.compute_txid();
                            self.seen_txids.insert(txid);
                            let msg = messages::build_inv_tx(self.network, txid);
                            for peer in self.peers.values() {
                                let _ = peer.send(msg.clone());
                            }
                        }
                        PeerCommand::BroadcastBlock(block, height) => {
                            // Update the advertised height so inbound version messages
                            // reflect the current chain tip.  Local mining (Stratum or
                            // generatetoaddress) never goes through NodeEvent::Block, so
                            // shared_best_height would otherwise stay at the startup value
                            // and every connecting peer would see height=0.
                            *self.shared_best_height.write().expect("lock poisoned") = height as i32;

                            // Announce the newly-mined block to peers using the correct
                            // Bitcoin P2P protocol — never push the full block unsolicited.
                            // Peers that sent sendheaders (BIP 130) expect a `headers`
                            // announcement; others get an `inv(MSG_BLOCK)`.
                            //
                            // NOTE: MSG_WITNESS_BLOCK (0x40000002) is only valid inside a
                            // *getdata* request where it signals the requester wants witness
                            // data.  Using it in an *inv* announcement is non-standard and
                            // causes Bitcoin Core to log "Unknown inv type" and ignore the
                            // message entirely.  Block announcements always use MSG_BLOCK (2).
                            let block_hash = block.block_hash();
                            let header = block.header;
                            let inv_msg = messages::build_raw_network_message(
                                self.network,
                                NetworkMessage::Inv(vec![
                                    bitcoin::p2p::message_blockdata::Inventory::Block(block_hash),
                                ]),
                            );
                            let headers_msg = messages::build_raw_network_message(
                                self.network,
                                NetworkMessage::Headers(vec![header]),
                            );
                            for (id, peer) in &self.peers {
                                let wants_hdrs = self.peer_state
                                    .get(id)
                                    .map(|s| s.wants_send_headers)
                                    .unwrap_or(false);
                                if wants_hdrs {
                                    let _ = peer.send(headers_msg.clone());
                                } else {
                                    let _ = peer.send(inv_msg.clone());
                                }
                            }
                        }
                        PeerCommand::Misbehaving { peer_id, reason } => {
                            let should_ban = self.scoring.record_misbehavior(peer_id, reason);
                            if should_ban {
                                info!(peer_id, "Disconnecting and banning misbehaving peer");
                                self.disconnect_peer(peer_id);
                                let _ = self.node_event_tx.try_send(
                                    NodeEvent::PeerDisconnected(peer_id)
                                );
                            }
                        }
                        PeerCommand::DisconnectPeer { peer_id } => {
                            info!(peer_id, "Disconnecting non-delivering peer");
                            self.disconnect_peer(peer_id);
                            let _ = self.node_event_tx.try_send(
                                NodeEvent::PeerDisconnected(peer_id)
                            );
                        }
                        PeerCommand::RefreshPeerConnections {
                            disconnect_zero_height_inbound,
                            target_outbound,
                        } => {
                            // Never let a caller's target lower the manager's own
                            // (e.g. the raised onion-only target).
                            let target_outbound = target_outbound.max(self.outbound_target);
                            if disconnect_zero_height_inbound {
                                let zero_height: Vec<PeerId> = self
                                    .peers
                                    .iter()
                                    .filter(|(id, p)| {
                                        self.inbound_peers.contains(id)
                                            && p.info.start_height == 0
                                    })
                                    .map(|(id, _)| *id)
                                    .collect();
                                for pid in zero_height {
                                    info!(
                                        peer_id = pid,
                                        "Disconnecting height=0 inbound peer to free connection slot"
                                    );
                                    self.disconnect_peer(pid);
                                    let _ = self.node_event_tx.try_send(
                                        NodeEvent::PeerDisconnected(pid),
                                    );
                                }
                            }
                            let outbound = self.peers.len().saturating_sub(self.inbound_count)
                                + self.inflight_dials.len();
                            if outbound < target_outbound {
                                let fresh = if self.dns_seeding_allowed() {
                                    dns::resolve_seeds(&self.params).await
                                } else {
                                    Vec::new()
                                };
                                if !fresh.is_empty() {
                                    for a in &fresh {
                                        self.addr_manager.add(NetAddr::Ip(*a), 0);
                                    }
                                }
                                let mut candidates =
                                    self.addr_manager.get_for_connect(target_outbound * 2);
                                let needed = target_outbound.saturating_sub(outbound);
                                if candidates.len() < needed && self.maybe_inject_fixed_seeds() {
                                    candidates =
                                        self.addr_manager.get_for_connect(target_outbound * 2);
                                }
                                let mut connected = 0usize;
                                for candidate in candidates {
                                    if connected >= needed {
                                        break;
                                    }
                                    let already = self
                                        .peers
                                        .values()
                                        .any(|p| p.info.addr == candidate);
                                    if !already {
                                        self.connect_to_peer(candidate);
                                        connected += 1;
                                    }
                                }
                                if connected > 0 {
                                    info!(
                                        connected,
                                        outbound,
                                        target = target_outbound,
                                        "Aggressive peer refresh: dialed new outbound peers"
                                    );
                                }
                            }
                        }
                        PeerCommand::Shutdown => {
                            info!("P2P manager shutting down");
                            // Stop accepting new inbound connections immediately.
                            if let Some(ref h) = listener_handle {
                                h.abort();
                            }
                            // Final save on the graceful-shutdown path: the
                            // anchors recorded here are the outbound peers we
                            // re-dial first on the next startup.
                            self.save_peer_state();
                            break;
                        }
                    }
                }
                _ = peer_maintenance.tick() => {
                    // Periodic check: ensure we have enough outbound peers.
                    // Re-resolve DNS seeds and connect if we're below target.
                    let outbound = self.peers.len().saturating_sub(self.inbound_count)
                        + self.inflight_dials.len();
                    if outbound < self.outbound_target {
                        let needed = self.outbound_target - outbound;
                        // Use addr_manager's reliability-sorted list (filters
                        // out high-failure addresses). Only re-resolve DNS
                        // seeds when the addr manager can't supply enough
                        // candidates or the last resolve is >5 minutes old —
                        // re-resolving on every 30s tick is pure log noise.
                        let mut candidates = self.addr_manager.get_for_connect(self.outbound_target * 2);
                        let dns_due = self.last_dns_resolve.is_none_or(|t| {
                            t.elapsed() >= std::time::Duration::from_secs(300)
                        });
                        if (candidates.len() < needed || dns_due) && self.dns_seeding_allowed() {
                            let fresh = dns::resolve_seeds(&self.params).await;
                            self.last_dns_resolve = Some(std::time::Instant::now());
                            if !fresh.is_empty() {
                                for a in &fresh {
                                    self.addr_manager.add(NetAddr::Ip(*a), 0);
                                }
                                candidates = self.addr_manager.get_for_connect(self.outbound_target * 2);
                            }
                        }
                        // Still starved after (or without) DNS — fall back to
                        // the built-in fixed seeds (rate-limited internally).
                        if candidates.len() < needed && self.maybe_inject_fixed_seeds() {
                            candidates = self.addr_manager.get_for_connect(self.outbound_target * 2);
                        }
                        let mut dialed = 0;
                        for candidate in candidates {
                            if dialed >= needed { break; }
                            // Dedup by IP (see already_connected_ip): inbound peers
                            // carry an ephemeral source port, so an addr-exact check
                            // would redial peers we already have, churning the pool.
                            if !self.already_connected(&candidate) {
                                self.connect_to_peer(candidate);
                                dialed += 1;
                            }
                        }
                        if dialed > 0 {
                            // `dialing` = dials initiated this tick (not yet
                            // handshaked); `outbound_slots` = settled outbound
                            // peers + dials already in flight before this tick.
                            info!(dialing = dialed, outbound_slots = outbound, target = self.outbound_target, "Peer maintenance: dialing new peers");
                        }
                    }

                    // Re-advertise our address every 24 hours so peers keep us
                    // in their address books and relay our address to new nodes.
                    if let Some(ext_ip) = self.discovered_external_ip {
                        let should_broadcast = match self.last_addr_broadcast {
                            None => true,
                            Some(last) => last.elapsed() >= std::time::Duration::from_secs(86400),
                        };
                        if should_broadcast {
                            let ext_addr = SocketAddr::new(ext_ip, self.listen_port);
                            let addr_msg = messages::build_self_addr(self.network, ext_addr, self.advertised_services());
                            for peer in self.peers.values() {
                                let _ = peer.send(addr_msg.clone());
                            }
                            self.last_addr_broadcast = Some(std::time::Instant::now());
                            info!("Re-advertised address to {} peers", self.peers.len());
                        }
                    }

                    // Persist peer state (address book + active bans + anchors)
                    // periodically so a crash doesn't lose everything learned
                    // since startup.
                    if self.peer_state_dir.is_some()
                        && self.last_peer_state_save.elapsed() >= PEER_STATE_SAVE_INTERVAL
                    {
                        self.save_peer_state();
                    }
                }
            }
        }
    }

    /// Record how a peer addressed us (their `version.receiver`) as a vote for
    /// our external address, and self-advertise via `addr` gossip once we're
    /// confident. Works for both inbound and outbound peers — crucially the
    /// inbound path, since an inbound-only node (e.g. the seed) has no outbound
    /// peers to learn its address from otherwise (O5). The peer must already be
    /// in `self.peers`.
    fn note_external_addr(&mut self, peer_id: PeerId, discovered: SocketAddr) {
        let ip = discovered.ip();
        if !self.is_routable(&ip) {
            return;
        }
        *self.external_ip_votes.entry(ip).or_insert(0) += 1;
        let vote_count = self.external_ip_votes[&ip];
        let total_votes: u32 = self.external_ip_votes.values().sum();
        let services = self.advertised_services();

        // Adopt the address on the first vote, or once 2 peers agree.
        if (self.discovered_external_ip.is_none() || vote_count >= 2)
            && self.discovered_external_ip != Some(ip)
        {
            info!(external_ip = %ip, votes = vote_count, "Discovered external IP from peers");
            self.discovered_external_ip = Some(ip);
            let ext_addr = SocketAddr::new(ip, self.listen_port);
            *self.shared_advertise_addr.write().expect("lock poisoned") = Some(ext_addr);
            self.publish_local_addr(NetAddr::Ip(ext_addr));
        }

        let Some(ext_ip) = self.discovered_external_ip else {
            return;
        };
        let ext_addr = SocketAddr::new(ext_ip, self.listen_port);
        // Advertise our address to this peer so it enters their address book
        // and gets relayed onward.
        if let Some(peer) = self.peers.get(&peer_id) {
            let _ = peer.send(messages::build_self_addr(self.network, ext_addr, services));
        }
        // On the confirming (2nd) vote, gossip to everyone.
        if total_votes == 2 {
            for peer in self.peers.values() {
                let _ = peer.send(messages::build_self_addr(self.network, ext_addr, services));
            }
            self.last_addr_broadcast = Some(std::time::Instant::now());
        }
    }

    /// Begin an outbound dial. The cheap pre-checks run here on the event
    /// loop, but the TCP connect + handshake (up to HANDSHAKE_TIMEOUT each)
    /// are spawned as a background task that reports back via
    /// `PeerEvent::OutboundConnected` / `OutboundFailed` — the `select!` loop
    /// never awaits a dial (H3, 2026-07-02 review: serial awaited dials could
    /// stall all peer processing ~80 s on a dead anchor list).
    fn connect_to_peer(&mut self, addr: NetAddr) {
        if !self.outbound_addr_allowed(addr) {
            debug!(%addr, "Skipping peer: IPv6 disabled");
            return;
        }
        let start_height = *self.shared_best_height.read().expect("lock poisoned");

        // IP-specific gates (ban list, self-dial, subnet diversity) apply only
        // to IP peers; onion/I2P have no IP and are deduped by exact address.
        if let Some(ip) = addr.ip() {
            if self.scoring.is_banned(&ip) {
                debug!(%addr, "Skipping banned peer");
                return;
            }
            // Never dial our own advertised address.
            if self.is_self_ip(&ip) {
                debug!(%addr, "Skipping peer: own external address (self-dial)");
                return;
            }
            // Don't open a second connection to a peer we already have (in
            // either direction) — that connection is redundant and gets
            // dropped, and the maintenance loop would just redial it next tick
            // (the O7 churn).
            if self.already_connected_ip(&ip) {
                debug!(%addr, "Skipping peer: already connected to this IP");
                return;
            }
            // Check subnet diversity: avoid too many peers from the same /16
            if self.outbound_peers_in_subnet(&ip) >= MAX_OUTBOUND_PER_SUBNET {
                debug!(%addr, "Skipping peer: too many connections from same /16 subnet");
                return;
            }
        } else if self.is_self_addr(&addr) {
            debug!(%addr, "Skipping peer: own advertised address (self-dial)");
            return;
        } else if self.already_connected_addr(&addr) {
            debug!(%addr, "Skipping peer: already connected to this address");
            return;
        }

        // One dial per address at a time.
        if !self.inflight_dials.insert(addr) {
            debug!(%addr, "Skipping peer: dial already in flight");
            return;
        }

        let advertise = self
            .discovered_external_ip
            .map(|ip| SocketAddr::new(ip, self.listen_port));
        let services = self.advertised_services();
        let network = self.network;
        let v2 = self.v2_transport;
        let proxy = self.proxy.clone();
        let i2p = self.i2p_session.clone();
        let event_tx = self.peer_event_tx.clone();
        tokio::spawn(async move {
            match Peer::connect(
                addr,
                network,
                start_height,
                event_tx.clone(),
                advertise,
                services,
                v2,
                &proxy,
                i2p.as_deref(),
            )
            .await
            {
                Ok(peer) => {
                    let _ = event_tx
                        .send(PeerEvent::OutboundConnected(peer, addr))
                        .await;
                }
                Err(e) => {
                    let _ = event_tx
                        .send(PeerEvent::OutboundFailed(addr, e.to_string()))
                        .await;
                }
            }
        });
    }

    /// Finish registering an outbound peer whose spawned dial completed.
    fn register_outbound_peer(&mut self, peer: Peer, addr: NetAddr) {
        self.inflight_dials.remove(&addr);

        // A racing inbound connection (or a second dial that resolved first)
        // may have connected this address while the handshake ran — drop the
        // duplicate; dropping the Peer closes its channels and tasks.
        if self.already_connected(&addr) {
            debug!(%addr, "Dropping completed dial: already connected");
            return;
        }

        let info = peer.info.clone();
        let id = info.id;

        if let Some(ip) = addr.ip() {
            self.scoring.register_peer(id, ip);
        }
        self.peer_addrs.insert(id, addr);
        self.addr_manager.mark_good(&addr);
        self.peer_state.insert(id, PeerState::default());
        self.peers.insert(id, peer);

        // Learn our external IP from how this peer addressed us, and
        // self-advertise once known (shared with the inbound path).
        if let Some(discovered) = info.discovered_addr.and_then(|d| d.to_socket_addr()) {
            self.note_external_addr(id, discovered);
        }

        let _ = self.node_event_tx.try_send(NodeEvent::PeerConnected(info));

        // Send getaddr to solicit their address book and trigger
        // them to remember our address for relay to other peers.
        let getaddr_msg =
            messages::build_raw_network_message(self.network, NetworkMessage::GetAddr);
        if let Some(peer) = self.peers.get(&id) {
            let _ = peer.send(getaddr_msg);
        }
    }

    /// Disconnect and clean up a peer.
    fn disconnect_peer(&mut self, peer_id: PeerId) {
        self.peers.remove(&peer_id);
        self.peer_state.remove(&peer_id);
        if let Some(addr) = self.peer_addrs.remove(&peer_id) {
            self.addr_manager.mark_failed(&addr);
        }
        self.scoring.unregister_peer(peer_id);
        if self.inbound_peers.remove(&peer_id) {
            self.inbound_count = self.inbound_count.saturating_sub(1);
        }
    }

    async fn handle_message(
        &mut self,
        peer_id: PeerId,
        msg: NetworkMessage,
        raw_bytes: Option<Vec<u8>>,
    ) {
        match msg {
            NetworkMessage::Headers(headers) => {
                debug!(peer_id, count = headers.len(), "Received headers");
                let _ = self
                    .node_event_tx
                    .try_send(NodeEvent::Headers(peer_id, headers));
            }
            NetworkMessage::Block(block) => {
                debug!(peer_id, hash = %block.block_hash(), "Received block");
                if let Err(e) = self
                    .block_event_tx
                    .try_send(NodeEvent::Block(peer_id, block, raw_bytes))
                {
                    warn!(
                        peer_id,
                        "Block event channel full, block dropped — will be re-requested: {}", e
                    );
                }
            }
            NetworkMessage::Tx(tx) => {
                let txid = tx.compute_txid();
                self.seen_txids.insert(txid);
                debug!(peer_id, %txid, "Received transaction");
                let _ = self
                    .node_event_tx
                    .try_send(NodeEvent::Transaction(peer_id, tx));
            }
            NetworkMessage::Ping(nonce) => {
                // Send pong back
                if let Some(peer) = self.peers.get(&peer_id) {
                    let pong = messages::build_pong(self.network, nonce);
                    let _ = peer.send(pong);
                }
            }
            NetworkMessage::Inv(inv) => {
                // All announced block hashes (used to refresh the peer's known
                // height, even for blocks we already have).
                let block_hashes: Vec<BlockHash> = inv
                    .iter()
                    .filter_map(|i| match i {
                        Inventory::Block(h) | Inventory::WitnessBlock(h) => Some(*h),
                        _ => None,
                    })
                    .collect();

                if !block_hashes.is_empty() {
                    // Only getdata blocks we don't already have stored. Now that
                    // nodes re-announce blocks they received from a peer (so blocks
                    // mined by a non-seed node propagate cluster-wide), invs for
                    // blocks we already connected would otherwise trigger a redundant
                    // getdata → duplicate Block → orphan-buffer churn. Filtering here
                    // (as Bitcoin Core does) keeps the announce fan-out from echoing
                    // into a request storm.
                    let wanted: Vec<BlockHash> = match &self.header_index {
                        Some(hi) => block_hashes
                            .iter()
                            .filter(|h| !matches!(hi.get_block_pos(h), Ok(Some(_))))
                            .copied()
                            .collect(),
                        None => block_hashes.clone(),
                    };
                    if !wanted.is_empty() {
                        if let Some(peer) = self.peers.get(&peer_id) {
                            let msg = messages::build_getdata_blocks(self.network, wanted);
                            let _ = peer.send(msg);
                        }
                    }
                    // Surface the announcement so the node coordinator can update
                    // this peer's known height (block inv signals the peer has
                    // these blocks, even when no `headers` announcement follows).
                    let _ = self
                        .node_event_tx
                        .try_send(NodeEvent::BlockInv(peer_id, block_hashes));
                }

                // Request any announced transactions we haven't seen
                let unseen_txids: Vec<Txid> = inv
                    .iter()
                    .filter_map(|i| match i {
                        Inventory::Transaction(txid) | Inventory::WitnessTransaction(txid) => {
                            Some(*txid)
                        }
                        _ => None,
                    })
                    .filter(|txid| !self.seen_txids.contains(txid))
                    .collect();

                if !unseen_txids.is_empty() {
                    debug!(
                        peer_id,
                        count = unseen_txids.len(),
                        "Requesting announced transactions"
                    );
                    for txid in &unseen_txids {
                        self.seen_txids.insert(*txid);
                    }
                    if let Some(peer) = self.peers.get(&peer_id) {
                        let msg = messages::build_getdata_txs(self.network, unseen_txids);
                        let _ = peer.send(msg);
                    }
                }
            }
            NetworkMessage::Addr(addrs) => {
                debug!(peer_id, count = addrs.len(), "Received addr");
                // Store addresses, collecting only the ones that are new to us.
                // Bitcoin Core relays only *newly-learned* addresses; relaying
                // every received addr makes a meshed network amplify a single
                // address into an unbounded gossip storm (each relay triggers
                // two more, with no termination), which addr self-advertisement
                // (O5) readily seeds. Forwarding only novel addresses bounds the
                // fan-out: each address propagates at most once per node.
                let mut fresh: Vec<_> = Vec::new();
                for entry in &addrs {
                    let (_, addr_info) = entry;
                    let socket_addr = SocketAddr::new(addr_info.address.into(), addr_info.port);
                    if self
                        .addr_manager
                        .add(NetAddr::Ip(socket_addr), addr_info.services.to_u64())
                    {
                        fresh.push(entry.clone());
                    }
                }
                // Relay only the newly-learned addresses (max 2 peers, max 1000).
                if !fresh.is_empty() && fresh.len() <= 1000 {
                    let relay_msg = NetworkMessage::Addr(fresh);
                    let relay_raw = messages::build_raw_network_message(self.network, relay_msg);
                    let mut relay_count = 0;
                    for (id, peer) in &self.peers {
                        if *id != peer_id && relay_count < 2 {
                            let _ = peer.send(relay_raw.clone());
                            relay_count += 1;
                        }
                    }
                }
            }
            NetworkMessage::SendHeaders => {
                // Peer wants new-block announcements as `headers` messages (BIP 130).
                if let Some(state) = self.peer_state.get_mut(&peer_id) {
                    state.wants_send_headers = true;
                }
            }
            NetworkMessage::Verack => {}
            NetworkMessage::FeeFilter(fee_rate) => {
                debug!(peer_id, fee_rate, "Received feefilter");
                if let Some(state) = self.peer_state.get_mut(&peer_id) {
                    state.fee_filter = fee_rate.max(0) as u64;
                }
            }
            NetworkMessage::SendCmpct(sendcmpct) => {
                debug!(
                    peer_id,
                    send = sendcmpct.send_compact,
                    version = sendcmpct.version,
                    "Received sendcmpct"
                );
                if let Some(state) = self.peer_state.get_mut(&peer_id) {
                    state.wants_compact_blocks = sendcmpct.send_compact;
                    state.compact_version = sendcmpct.version;
                }
            }
            NetworkMessage::CmpctBlock(cmpctblock) => {
                let compact = &cmpctblock.compact_block;
                let block_hash = compact.header.block_hash();
                let total_tx_count = compact.short_ids.len() + compact.prefilled_txs.len();
                debug!(peer_id, %block_hash, total_tx_count, "Received compact block");

                // Attempt reconstruction from mempool
                let siphash_keys = ShortId::calculate_siphash_keys(&compact.header, compact.nonce);
                let mempool = self.mempool.read().await;

                // Build a lookup table: short_id -> Transaction from mempool
                let mut mempool_by_short_id: HashMap<ShortId, Transaction> = HashMap::new();
                for entry in mempool.entries() {
                    let short_id = ShortId::with_siphash_keys(
                        &entry.tx.compute_wtxid().to_raw_hash(),
                        siphash_keys,
                    );
                    mempool_by_short_id.insert(short_id, entry.tx.clone());
                }
                drop(mempool);

                // Reconstruct transaction list
                let mut txs: Vec<Option<Transaction>> = Vec::with_capacity(total_tx_count);
                let mut prefill_iter = compact.prefilled_txs.iter();
                let mut short_id_iter = compact.short_ids.iter();
                let mut missing_indices: Vec<u64> = Vec::new();
                let mut next_prefill_idx: usize = 0;

                // Prefilled tx indices are differentially encoded
                if let Some(first) = prefill_iter.next() {
                    next_prefill_idx = first.idx as usize;
                }

                for i in 0..total_tx_count {
                    if i == next_prefill_idx {
                        // This slot is prefilled (coinbase or explicitly provided)
                        // Find the prefilled tx for this index
                        // Re-walk prefills to find matching absolute index
                        let found = compact.prefilled_txs.iter().find(|_| {
                            // simplified: we already consumed prefill_iter above
                            false
                        });
                        // Actually, let's rebuild properly
                        let _ = found;
                        txs.push(None); // placeholder
                    } else if let Some(short_id) = short_id_iter.next() {
                        if let Some(tx) = mempool_by_short_id.get(short_id) {
                            txs.push(Some(tx.clone()));
                        } else {
                            missing_indices.push(i as u64);
                            txs.push(None);
                        }
                    } else {
                        txs.push(None);
                        missing_indices.push(i as u64);
                    }
                }

                // Simpler reconstruction: rebuild tx slots from prefilled + short_ids
                txs.clear();
                let mut prefill_abs_idx: Vec<(usize, Transaction)> = Vec::new();
                {
                    let mut idx = 0usize;
                    for ptx in &compact.prefilled_txs {
                        idx += ptx.idx as usize;
                        prefill_abs_idx.push((idx, ptx.tx.clone()));
                        idx += 1;
                    }
                }
                missing_indices.clear();
                let mut short_id_pos = 0;
                let mut prefill_pos = 0;
                for i in 0..total_tx_count {
                    if prefill_pos < prefill_abs_idx.len() && prefill_abs_idx[prefill_pos].0 == i {
                        txs.push(Some(prefill_abs_idx[prefill_pos].1.clone()));
                        prefill_pos += 1;
                    } else if short_id_pos < compact.short_ids.len() {
                        let short_id = &compact.short_ids[short_id_pos];
                        short_id_pos += 1;
                        if let Some(tx) = mempool_by_short_id.get(short_id) {
                            txs.push(Some(tx.clone()));
                        } else {
                            missing_indices.push(i as u64);
                            txs.push(None);
                        }
                    } else {
                        missing_indices.push(i as u64);
                        txs.push(None);
                    }
                }

                if missing_indices.is_empty() {
                    // Full reconstruction succeeded — emit as a normal block
                    let block = Block {
                        header: compact.header,
                        txdata: txs
                            .into_iter()
                            .map(|t| t.expect("missing_indices is empty, so every slot is Some"))
                            .collect(),
                    };
                    debug!(peer_id, %block_hash, "Compact block fully reconstructed from mempool");
                    let _ = self
                        .block_event_tx
                        .try_send(NodeEvent::Block(peer_id, block, None));
                } else {
                    // Request missing transactions via getblocktxn
                    debug!(
                        peer_id, %block_hash, missing = missing_indices.len(),
                        "Compact block missing txs, requesting via getblocktxn"
                    );
                    self.pending_compact.insert(
                        block_hash,
                        PendingCompactBlock {
                            header: compact.header,
                            txs,
                            peer_id,
                        },
                    );
                    if let Some(peer) = self.peers.get(&peer_id) {
                        let request = bitcoin::bip152::BlockTransactionsRequest {
                            block_hash,
                            indexes: missing_indices,
                        };
                        let msg = messages::build_raw_network_message(
                            self.network,
                            NetworkMessage::GetBlockTxn(GetBlockTxn {
                                txs_request: request,
                            }),
                        );
                        let _ = peer.send(msg);
                    }
                }
            }
            NetworkMessage::GetBlockTxn(_) => {
                // Peer wants specific transactions from a block we announced
                // We don't serve compact blocks yet, so ignore
                debug!(
                    peer_id,
                    "Received getblocktxn (not yet serving compact blocks)"
                );
            }
            NetworkMessage::BlockTxn(blocktxn) => {
                // Response to our getblocktxn — complete the compact block reconstruction
                let block_hash = blocktxn.transactions.block_hash;
                if let Some(mut pending) = self.pending_compact.remove(&block_hash) {
                    let mut fill_iter = blocktxn.transactions.transactions.into_iter();
                    for slot in pending.txs.iter_mut() {
                        if slot.is_none() {
                            if let Some(tx) = fill_iter.next() {
                                *slot = Some(tx);
                            }
                        }
                    }
                    if pending.txs.iter().all(|t| t.is_some()) {
                        let block = Block {
                            header: pending.header,
                            txdata: pending
                                .txs
                                .into_iter()
                                .map(|t| t.expect("all slots checked is_some above"))
                                .collect(),
                        };
                        debug!(peer_id, %block_hash, "Compact block completed via blocktxn");
                        let _ = self
                            .block_event_tx
                            .try_send(NodeEvent::Block(peer_id, block, None));
                    } else {
                        // Still incomplete — fall back to full block request
                        warn!(peer_id, %block_hash, "Compact block still incomplete after blocktxn, requesting full block");
                        if let Some(peer) = self.peers.get(&peer_id) {
                            let msg =
                                messages::build_getdata_blocks(self.network, vec![block_hash]);
                            let _ = peer.send(msg);
                        }
                    }
                } else {
                    debug!(peer_id, %block_hash, "Received blocktxn for unknown compact block");
                }
            }
            NetworkMessage::AddrV2(addrs) => {
                debug!(peer_id, count = addrs.len(), "Received addrv2");
                // Parse each entry into a NetAddr (skipping address families we
                // don't route), store it, and collect the newly-learned ones.
                // Same storm-prevention rule as legacy `addr`: relay only novel
                // addresses, to at most 2 peers.
                let mut fresh: Vec<bitcoin::p2p::address::AddrV2Message> = Vec::new();
                for msg in &addrs {
                    if let Some(na) = NetAddr::from_addr_v2(&msg.addr, msg.port) {
                        if self.addr_manager.add(na, msg.services.to_u64()) {
                            fresh.push(msg.clone());
                        }
                    }
                }
                if !fresh.is_empty() && fresh.len() <= 1000 {
                    let relay_raw = messages::build_raw_network_message(
                        self.network,
                        NetworkMessage::AddrV2(fresh),
                    );
                    let mut relay_count = 0;
                    for (id, peer) in &self.peers {
                        // Only relay addrv2 to peers that asked for it (BIP 155).
                        let wants = self
                            .peer_state
                            .get(id)
                            .map(|s| s.wants_addrv2)
                            .unwrap_or(false);
                        if *id != peer_id && wants && relay_count < 2 {
                            let _ = peer.send(relay_raw.clone());
                            relay_count += 1;
                        }
                    }
                }
            }
            NetworkMessage::SendAddrV2 => {
                // Peer understands addrv2 (BIP 155): relay onion/I2P/CJDNS
                // addresses to it in that format from now on.
                if let Some(state) = self.peer_state.get_mut(&peer_id) {
                    state.wants_addrv2 = true;
                }
            }
            NetworkMessage::WtxidRelay => {}
            NetworkMessage::Pong(_) => {}
            // BIP 37: load a connection bloom filter for this peer.
            NetworkMessage::FilterLoad(fl) => {
                if self.peer_bloom_filters {
                    let filter = crate::bloom::BloomFilter::from_filter_load(&fl);
                    if let Some(state) = self.peer_state.get_mut(&peer_id) {
                        state.bloom_filter = Some(filter);
                        debug!(peer_id, "Loaded BIP 37 bloom filter");
                    }
                } else {
                    debug!(peer_id, "Ignoring filterload (peer bloom filters disabled)");
                }
            }
            // BIP 37: add a data element to this peer's bloom filter.
            NetworkMessage::FilterAdd(fa) => {
                if self.peer_bloom_filters {
                    if let Some(filter) = self
                        .peer_state
                        .get_mut(&peer_id)
                        .and_then(|s| s.bloom_filter.as_mut())
                    {
                        filter.insert(&fa.data);
                    }
                } else {
                    debug!(peer_id, "Ignoring filteradd (peer bloom filters disabled)");
                }
            }
            // BIP 37: clear this peer's bloom filter.
            NetworkMessage::FilterClear => {
                if let Some(state) = self.peer_state.get_mut(&peer_id) {
                    state.bloom_filter = None;
                }
            }
            // BIP 35: serve our mempool contents as an inv of txids. Only honored
            // when NODE_BLOOM is advertised (peer bloom filters enabled); otherwise
            // it stays a no-op so we don't dump the mempool to arbitrary peers.
            NetworkMessage::MemPool => {
                if self.peer_bloom_filters {
                    let txs: Vec<(Txid, Transaction)> = {
                        let mempool = self.mempool.read().await;
                        mempool.entries().map(|e| (e.txid, e.tx.clone())).collect()
                    };
                    let mut inv: Vec<Inventory> = Vec::with_capacity(txs.len());
                    match self
                        .peer_state
                        .get(&peer_id)
                        .and_then(|s| s.bloom_filter.as_ref())
                    {
                        // If the peer loaded a filter, only announce matching txs.
                        Some(filter) => {
                            for (txid, tx) in &txs {
                                if filter.matches_tx(tx) {
                                    inv.push(Inventory::WitnessTransaction(*txid));
                                }
                            }
                        }
                        None => {
                            for (txid, _) in &txs {
                                inv.push(Inventory::WitnessTransaction(*txid));
                            }
                        }
                    }
                    if let Some(peer) = self.peers.get(&peer_id) {
                        // BIP 35 / inv messages are capped at 50000 items.
                        for chunk in inv.chunks(50_000) {
                            let msg = messages::build_raw_network_message(
                                self.network,
                                NetworkMessage::Inv(chunk.to_vec()),
                            );
                            let _ = peer.send(msg);
                        }
                    }
                    debug!(peer_id, count = inv.len(), "Served mempool (BIP 35)");
                } else {
                    debug!(
                        peer_id,
                        "Received mempool request but peer bloom filters disabled"
                    );
                }
            }
            NetworkMessage::GetData(inv) => {
                // BIP 37: filtered-block requests are collected here and served
                // after the mempool read lock is released (they need &mut state).
                let mut filtered_blocks: Vec<BlockHash> = Vec::new();
                // Blocks served to this peer: a peer that getdata's a block from
                // us is taking that block, but (unlike an announcing peer) will
                // never announce it back to us — we sent it, so it knows we have
                // it. Report the served hashes through the same BlockInv event
                // the inv path uses so per-peer synced_height stays live for
                // download-only peers (the Core/Knots "peers page stuck at an
                // old height" symptom).
                let mut served_blocks: Vec<BlockHash> = Vec::new();
                {
                    let mempool = self.mempool.read().await;
                    for item in &inv {
                        match item {
                            Inventory::Transaction(txid) | Inventory::WitnessTransaction(txid) => {
                                if let Some(entry) = mempool.get(txid) {
                                    if let Some(peer) = self.peers.get(&peer_id) {
                                        let msg = messages::build_raw_network_message(
                                            self.network,
                                            NetworkMessage::Tx(entry.tx.clone()),
                                        );
                                        let _ = peer.send(msg);
                                    }
                                }
                            }
                            Inventory::Block(hash) | Inventory::WitnessBlock(hash) => {
                                // Serve the block from disk if we have it
                                if let (Some(ref hi), Some(ref bs)) =
                                    (&self.header_index, &self.block_store)
                                {
                                    match hi.get_block_pos(hash) {
                                        Ok(Some(pos)) => match bs.read_block(&pos) {
                                            Ok(raw) => {
                                                match Block::consensus_decode(&mut raw.as_slice()) {
                                                    Ok(block) => {
                                                        debug!(
                                                            peer_id,
                                                            hash = %hash,
                                                            "Serving block via getdata"
                                                        );
                                                        let msg =
                                                            messages::build_raw_network_message(
                                                                self.network,
                                                                NetworkMessage::Block(block),
                                                            );
                                                        if let Some(peer) = self.peers.get(&peer_id)
                                                        {
                                                            if peer.send(msg).is_ok() {
                                                                served_blocks.push(*hash);
                                                            }
                                                        }
                                                    }
                                                    Err(e) => {
                                                        warn!(peer_id, hash = %hash, "Failed to decode block for getdata: {}", e);
                                                    }
                                                }
                                            }
                                            Err(e) => {
                                                // We have the block position but the read
                                                // failed (e.g. a not-yet-flushed async write
                                                // that even the read_block flush-retry could
                                                // not recover). Tell the peer explicitly with
                                                // notfound so it re-requests promptly elsewhere
                                                // instead of stalling on silence — the silent
                                                // drop here previously stranded peers one block
                                                // behind after a reorg.
                                                warn!(peer_id, hash = %hash, "Failed to read block for getdata, sending notfound: {}", e);
                                                let notfound = messages::build_raw_network_message(
                                                    self.network,
                                                    NetworkMessage::NotFound(vec![*item]),
                                                );
                                                if let Some(peer) = self.peers.get(&peer_id) {
                                                    let _ = peer.send(notfound);
                                                }
                                            }
                                        },
                                        Ok(None) => {
                                            debug!(peer_id, hash = %hash, "Block not found for getdata, sending notfound");
                                            let notfound = messages::build_raw_network_message(
                                                self.network,
                                                NetworkMessage::NotFound(vec![*item]),
                                            );
                                            if let Some(peer) = self.peers.get(&peer_id) {
                                                let _ = peer.send(notfound);
                                            }
                                        }
                                        Err(e) => {
                                            warn!(peer_id, hash = %hash, "Storage error for getdata: {}", e);
                                        }
                                    }
                                }
                            }
                            // BIP 37: filtered-block request. MSG_FILTERED_BLOCK == 3,
                            // MSG_FILTERED_WITNESS_BLOCK == 0x40000003. rust-bitcoin 0.32
                            // exposes these as `Inventory::Unknown { inv_type, hash }`.
                            Inventory::Unknown { inv_type, hash }
                                if (*inv_type == 3 || *inv_type == 0x4000_0003)
                                    && self.peer_bloom_filters =>
                            {
                                filtered_blocks.push(BlockHash::from_byte_array(*hash));
                            }
                            _ => {}
                        }
                    }
                }
                // Serve any filtered-block requests now that the mempool lock is
                // dropped (serving needs mutable access to the peer's filter).
                for hash in filtered_blocks {
                    self.serve_filtered_block(peer_id, hash).await;
                }
                if !served_blocks.is_empty() {
                    let _ = self
                        .node_event_tx
                        .try_send(NodeEvent::BlockInv(peer_id, served_blocks));
                }
            }
            NetworkMessage::GetHeaders(getheaders_msg) => {
                debug!(
                    peer_id,
                    locator_count = getheaders_msg.locator_hashes.len(),
                    "Received getheaders"
                );
                if let Some(ref header_index) = self.header_index {
                    // Walk locator to find the highest block we share with the peer.
                    // IMPORTANT: only match against the canonical chain — i.e. the
                    // locator hash must be what get_hash_at_height() returns for its
                    // height.  If we match an orphaned (non-canonical) header we would
                    // return headers whose prev_blockhash doesn't connect from the
                    // peer's locator, causing "headers out of order" on the peer side
                    // and an immediate disconnect / rapid reconnect storm.
                    let mut start_height = 0u32;
                    for locator_hash in &getheaders_msg.locator_hashes {
                        if let Ok(Some(stored)) = header_index.get_header(locator_hash) {
                            // Confirm this hash is the canonical block at its height.
                            let canonical = header_index
                                .get_hash_at_height(stored.height)
                                .ok()
                                .flatten();
                            if canonical.as_ref() == Some(locator_hash) {
                                start_height = stored.height + 1;
                                break;
                            }
                            // Hash is stored but not canonical (orphan) — keep searching.
                        }
                    }

                    // Collect up to 2000 headers starting at start_height
                    let mut headers: Vec<Header> = Vec::with_capacity(2000);
                    let stop_hash = getheaders_msg.stop_hash;
                    let has_stop = stop_hash != BlockHash::all_zeros();
                    let mut h = start_height;
                    while headers.len() < 2000 {
                        let hash = match header_index.get_hash_at_height(h) {
                            Ok(Some(hash)) => hash,
                            _ => break,
                        };
                        if let Ok(Some(stored)) = header_index.get_header(&hash) {
                            headers.push(stored.header);
                        } else {
                            break;
                        }
                        if has_stop && hash == stop_hash {
                            break;
                        }
                        h += 1;
                    }

                    debug!(
                        peer_id,
                        count = headers.len(),
                        start_height,
                        "Sending headers response to getheaders"
                    );
                    let resp = messages::build_raw_network_message(
                        self.network,
                        NetworkMessage::Headers(headers),
                    );
                    if let Some(peer) = self.peers.get(&peer_id) {
                        let _ = peer.send(resp);
                    }
                } else {
                    debug!(peer_id, "Received getheaders but header_index not attached");
                }
            }
            NetworkMessage::GetBlocks(getblocks_msg) => {
                // Older-style block inventory request — respond with up to 500 block hashes via inv.
                debug!(
                    peer_id,
                    locator_count = getblocks_msg.locator_hashes.len(),
                    "Received getblocks"
                );
                if let Some(ref header_index) = self.header_index {
                    let mut start_height = 0u32;
                    for locator_hash in &getblocks_msg.locator_hashes {
                        if let Ok(Some(stored)) = header_index.get_header(locator_hash) {
                            start_height = stored.height + 1;
                            break;
                        }
                    }

                    let mut inv: Vec<Inventory> = Vec::with_capacity(500);
                    let stop_hash = getblocks_msg.stop_hash;
                    let has_stop = stop_hash != BlockHash::all_zeros();
                    let mut h = start_height;
                    while inv.len() < 500 {
                        let hash = match header_index.get_hash_at_height(h) {
                            Ok(Some(hash)) => hash,
                            _ => break,
                        };
                        inv.push(Inventory::Block(hash));
                        if has_stop && hash == stop_hash {
                            break;
                        }
                        h += 1;
                    }

                    if !inv.is_empty() {
                        debug!(
                            peer_id,
                            count = inv.len(),
                            "Sending inv response to getblocks"
                        );
                        let resp = messages::build_raw_network_message(
                            self.network,
                            NetworkMessage::Inv(inv),
                        );
                        if let Some(peer) = self.peers.get(&peer_id) {
                            let _ = peer.send(resp);
                        }
                    }
                } else {
                    debug!(peer_id, "Received getblocks but header_index not attached");
                }
            }
            NetworkMessage::GetAddr => {
                // Respond with known addresses from our address manager.
                let entries = self.addr_manager.get_for_relay(1000);
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs() as u32)
                    .unwrap_or(0);
                let wants_addrv2 = self
                    .peer_state
                    .get(&peer_id)
                    .map(|s| s.wants_addrv2)
                    .unwrap_or(false);
                if wants_addrv2 {
                    // BIP 155: send every address family (including onion/I2P).
                    use bitcoin::p2p::address::AddrV2Message;
                    let mut list: Vec<AddrV2Message> = entries
                        .iter()
                        .map(|entry| {
                            let (addr, port) = entry.addr.to_addr_v2();
                            AddrV2Message {
                                time: now,
                                services: bitcoin::p2p::ServiceFlags::from(entry.services),
                                addr,
                                port,
                            }
                        })
                        .collect();
                    // Self-advertise every address we're reachable at — IP plus
                    // our .onion / .b32.i2p — so peers learn and relay us (O5).
                    for self_addr in self.self_advertised_addrs() {
                        let (addr, port) = self_addr.to_addr_v2();
                        list.push(AddrV2Message {
                            time: now,
                            services: self.advertised_services(),
                            addr,
                            port,
                        });
                    }
                    if !list.is_empty() {
                        let count = list.len();
                        let msg = messages::build_raw_network_message(
                            self.network,
                            NetworkMessage::AddrV2(list),
                        );
                        if let Some(peer) = self.peers.get(&peer_id) {
                            let _ = peer.send(msg);
                        }
                        debug!(peer_id, count, "Responded to getaddr (addrv2)");
                    }
                } else {
                    // Legacy `addr` carries only IP addresses; onion/I2P entries
                    // are skipped for peers that didn't send `sendaddrv2`.
                    let mut addr_list: Vec<(u32, bitcoin::p2p::Address)> = entries
                        .iter()
                        .filter_map(|entry| {
                            let sa = entry.addr.to_socket_addr()?;
                            Some((
                                now,
                                bitcoin::p2p::Address::new(
                                    &sa,
                                    bitcoin::p2p::ServiceFlags::from(entry.services),
                                ),
                            ))
                        })
                        .collect();
                    // Include our own address so peers learn and relay us (O5).
                    if let Some(ext_ip) = self.discovered_external_ip {
                        let ext_addr = SocketAddr::new(ext_ip, self.listen_port);
                        addr_list.push((
                            now,
                            bitcoin::p2p::Address::new(&ext_addr, self.advertised_services()),
                        ));
                    }
                    if !addr_list.is_empty() {
                        let count = addr_list.len();
                        let msg = messages::build_raw_network_message(
                            self.network,
                            NetworkMessage::Addr(addr_list),
                        );
                        if let Some(peer) = self.peers.get(&peer_id) {
                            let _ = peer.send(msg);
                        }
                        debug!(peer_id, count, "Responded to getaddr");
                    }
                }
            }
            NetworkMessage::NotFound(inv) => {
                debug!(peer_id, count = inv.len(), "Received notfound");
                let _ = self
                    .node_event_tx
                    .try_send(NodeEvent::NotFound(peer_id, inv));
            }
            other => {
                debug!(peer_id, cmd = ?other.cmd(), "Unhandled message");
            }
        }
    }

    /// BIP 37: serve a `merkleblock` plus the matching transactions for a
    /// filtered-block request. Only does anything when peer bloom filters are
    /// enabled and the peer has actually loaded a filter.
    async fn serve_filtered_block(&mut self, peer_id: PeerId, hash: BlockHash) {
        if !self.peer_bloom_filters {
            return;
        }
        // Clone the storage Arcs so we don't hold a borrow of `self` while we
        // later take a mutable borrow of the peer's filter state.
        let (hi, bs) = match (&self.header_index, &self.block_store) {
            (Some(hi), Some(bs)) => (hi.clone(), bs.clone()),
            _ => return,
        };
        let pos = match hi.get_block_pos(&hash) {
            Ok(Some(pos)) => pos,
            _ => return,
        };
        let raw = match bs.read_block(&pos) {
            Ok(raw) => raw,
            Err(e) => {
                warn!(peer_id, hash = %hash, "Failed to read block for filtered getdata: {}", e);
                return;
            }
        };
        let block = match Block::consensus_decode(&mut raw.as_slice()) {
            Ok(block) => block,
            Err(e) => {
                warn!(peer_id, hash = %hash, "Failed to decode block for filtered getdata: {}", e);
                return;
            }
        };

        // Run the peer's filter over each tx, updating it per BIP 37 flags.
        let filter = match self
            .peer_state
            .get_mut(&peer_id)
            .and_then(|s| s.bloom_filter.as_mut())
        {
            Some(filter) => filter,
            None => return, // peer requested a filtered block without a filter
        };
        let mut matched: Vec<Txid> = Vec::new();
        let mut matched_txs: Vec<Transaction> = Vec::new();
        for tx in &block.txdata {
            if filter.is_relevant_and_update(tx) {
                matched.push(tx.compute_txid());
                matched_txs.push(tx.clone());
            }
        }

        let merkle =
            bitcoin::MerkleBlock::from_block_with_predicate(&block, |txid| matched.contains(txid));

        if let Some(peer) = self.peers.get(&peer_id) {
            debug!(peer_id, hash = %hash, matched = matched_txs.len(), "Serving filtered block (BIP 37)");
            let mb_msg = messages::build_raw_network_message(
                self.network,
                NetworkMessage::MerkleBlock(merkle),
            );
            let _ = peer.send(mb_msg);
            for tx in matched_txs {
                let tx_msg =
                    messages::build_raw_network_message(self.network, NetworkMessage::Tx(tx));
                let _ = peer.send(tx_msg);
            }
        }
    }

    /// Get a list of connected peer IDs.
    pub fn connected_peer_ids(&self) -> Vec<PeerId> {
        self.peers.keys().copied().collect()
    }

    /// Get info about all connected peers.
    pub fn peer_infos(&self) -> Vec<PeerInfo> {
        self.peers.values().map(|p| p.info.clone()).collect()
    }

    /// Get the ID of the first connected peer (for header sync).
    pub fn first_peer_id(&self) -> Option<PeerId> {
        self.peers.keys().next().copied()
    }

    /// Select the best peer for block downloads.
    /// Prefers peers with the highest reported start height and protocol version.
    pub fn preferred_download_peer(&self) -> Option<PeerId> {
        self.peers
            .values()
            .max_by_key(|p| (p.info.start_height, p.info.version))
            .map(|p| p.info.id)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn test_manager(connect_addrs: Vec<NetAddr>) -> PeerManager {
        let (node_tx, _node_rx) = mpsc::channel(8);
        let (block_tx, _block_rx) = mpsc::channel(8);
        let (_cmd_tx, cmd_rx) = mpsc::channel(8);
        let mempool = Arc::new(RwLock::new(Mempool::new(1 << 20)));
        let height = Arc::new(std::sync::RwLock::new(0));
        PeerManager::with_port(
            Network::Regtest,
            18444,
            ConsensusParams::regtest(),
            node_tx,
            block_tx,
            cmd_rx,
            connect_addrs,
            mempool,
            height,
        )
    }

    fn fake_peer(id: PeerId, addr: SocketAddr, inbound: bool) -> Peer {
        let (msg_tx, _rx) = mpsc::channel(8);
        Peer {
            info: PeerInfo {
                id,
                addr: NetAddr::Ip(addr),
                version: 70016,
                services: bitcoin::p2p::ServiceFlags::NETWORK,
                user_agent: "t".into(),
                start_height: 0,
                synced_height: 0,
                relay: true,
                inbound,
                discovered_addr: None,
                v2: false,
            },
            msg_tx,
        }
    }

    #[test]
    fn inbound_only_node_learns_and_advertises_external_addr() {
        // An inbound-only node (no outbound peers) must still discover its own
        // address from how an inbound peer addressed us, then self-advertise (O5).
        let mut mgr = test_manager(vec![]);
        assert!(mgr.discovered_external_ip.is_none());

        // Inbound peer; its info.addr is the ephemeral source, but it told us in
        // its version that it reached us at a routable address.
        let inbound_src: SocketAddr = "10.1.2.3:51000".parse().unwrap();
        mgr.peers.insert(1, fake_peer(1, inbound_src, true));
        mgr.inbound_peers.insert(1);

        // A genuinely routable public address (not private / loopback / TEST-NET).
        let how_they_see_us: SocketAddr = "8.8.8.8:8333".parse().unwrap();
        mgr.note_external_addr(1, how_they_see_us);

        assert_eq!(
            mgr.discovered_external_ip,
            Some("8.8.8.8".parse().unwrap()),
            "inbound-only node should adopt its externally-visible IP"
        );
        assert_eq!(
            *mgr.shared_advertise_addr.read().unwrap(),
            Some(SocketAddr::new("8.8.8.8".parse().unwrap(), mgr.listen_port)),
            "advertise address should be published for new connections"
        );
    }

    #[test]
    fn external_addr_ignores_private_ip() {
        // Private/RFC1918 addresses must never be adopted or gossiped.
        let mut mgr = test_manager(vec![]);
        mgr.peers
            .insert(1, fake_peer(1, "10.0.0.5:40000".parse().unwrap(), true));
        mgr.note_external_addr(1, "192.168.1.2:8333".parse().unwrap());
        assert!(mgr.discovered_external_ip.is_none());
    }

    #[test]
    fn external_addr_adopts_private_ip_with_test_override() {
        // With the test-only override, an RFC1918 address (as used by the interop
        // cluster) IS adopted and published — this is what lets O5/O7 be
        // wire-validated end-to-end without routable public IPs.
        let mut mgr = test_manager(vec![]);
        mgr.set_gossip_private_addrs(true);
        mgr.peers
            .insert(1, fake_peer(1, "172.30.0.9:40000".parse().unwrap(), true));
        let how_they_see_us: SocketAddr = "172.30.0.5:8333".parse().unwrap();
        mgr.note_external_addr(1, how_they_see_us);
        assert_eq!(
            mgr.discovered_external_ip,
            Some("172.30.0.5".parse().unwrap()),
            "override should let a private cluster address be adopted"
        );
        assert_eq!(
            *mgr.shared_advertise_addr.read().unwrap(),
            Some(SocketAddr::new(
                "172.30.0.5".parse().unwrap(),
                mgr.listen_port
            )),
        );
        // Loopback is still rejected even with the override.
        let mut mgr2 = test_manager(vec![]);
        mgr2.set_gossip_private_addrs(true);
        mgr2.peers
            .insert(1, fake_peer(1, "172.30.0.9:40000".parse().unwrap(), true));
        mgr2.note_external_addr(1, "127.0.0.1:8333".parse().unwrap());
        assert!(mgr2.discovered_external_ip.is_none());
    }

    #[test]
    fn already_connected_dedups_inbound_by_ip_not_port() {
        let mut mgr = test_manager(vec![]);
        // An inbound peer's info.addr carries the ephemeral *source* port.
        let inbound_src: SocketAddr = "5.5.5.5:54321".parse().unwrap();
        mgr.peers.insert(1, fake_peer(1, inbound_src, true));

        // The maintenance loop would consider the peer's *listen* address.
        let listen: SocketAddr = "5.5.5.5:8333".parse().unwrap();
        assert!(
            mgr.already_connected_ip(&listen.ip()),
            "must recognize we already have this IP despite the different port"
        );
        // A genuinely new IP is dialable.
        let other: IpAddr = "6.6.6.6".parse().unwrap();
        assert!(!mgr.already_connected_ip(&other));
    }

    #[test]
    fn test_onlynet_restricts_outbound_and_dns() {
        use crate::netaddr::AddrNetwork;
        let mut mgr = test_manager(vec![]);
        // Default: all networks allowed, DNS seeding permitted.
        assert!(mgr.dns_seeding_allowed());
        assert!(mgr.outbound_addr_allowed(NetAddr::Ip("1.2.3.4:8333".parse().unwrap())));

        // Tor-only: IP dials rejected, onion allowed, clearnet DNS skipped.
        mgr.set_onlynet(vec![AddrNetwork::Onion]);
        assert!(!mgr.dns_seeding_allowed());
        assert!(!mgr.outbound_addr_allowed(NetAddr::Ip("1.2.3.4:8333".parse().unwrap())));
        assert!(mgr.outbound_addr_allowed(NetAddr::OnionV3 {
            pubkey: [1u8; 32],
            port: 8333
        }));

        // Allowing ipv4 re-enables DNS seeding.
        mgr.set_onlynet(vec![AddrNetwork::Ipv4, AddrNetwork::Onion]);
        assert!(mgr.dns_seeding_allowed());
    }

    #[test]
    fn test_onlynet_without_ip_raises_outbound_target() {
        use crate::netaddr::AddrNetwork;
        let mut mgr = test_manager(vec![]);
        assert_eq!(mgr.outbound_target, MAX_OUTBOUND);

        // Tor/I2P-only: per-circuit throughput is low, target rises.
        mgr.set_onlynet(vec![AddrNetwork::Onion]);
        assert_eq!(mgr.outbound_target, ONION_MAX_OUTBOUND);
        mgr.set_onlynet(vec![AddrNetwork::Onion, AddrNetwork::I2p]);
        assert_eq!(mgr.outbound_target, ONION_MAX_OUTBOUND);

        // Any IP network allowed → normal target.
        mgr.set_onlynet(vec![AddrNetwork::Ipv4, AddrNetwork::Onion]);
        assert_eq!(mgr.outbound_target, MAX_OUTBOUND);
        mgr.set_onlynet(vec![]);
        assert_eq!(mgr.outbound_target, MAX_OUTBOUND);
    }

    #[test]
    fn test_fixed_seed_injection_respects_onlynet_and_rate_limit() {
        use crate::netaddr::AddrNetwork;
        let (node_tx, _node_rx) = mpsc::channel(8);
        let (block_tx, _block_rx) = mpsc::channel(8);
        let (_cmd_tx, cmd_rx) = mpsc::channel(8);
        let mempool = Arc::new(RwLock::new(Mempool::new(1 << 20)));
        let height = Arc::new(std::sync::RwLock::new(0));
        let mut mgr = PeerManager::with_port(
            Network::Bitcoin,
            8333,
            ConsensusParams::mainnet(),
            node_tx,
            block_tx,
            cmd_rx,
            vec![],
            mempool,
            height,
        );
        mgr.set_onlynet(vec![AddrNetwork::Onion]);

        assert!(mgr.maybe_inject_fixed_seeds(), "cold book must inject");
        let candidates = mgr.addr_manager.get_for_connect(usize::MAX);
        assert!(!candidates.is_empty(), "injection must yield candidates");
        assert!(
            candidates.iter().all(|a| a.network() == AddrNetwork::Onion),
            "-onlynet=onion book must contain only onion seeds"
        );
        // Rate limit: an immediate second call is a no-op.
        assert!(!mgr.maybe_inject_fixed_seeds());

        // Regtest ships no fixed seeds at all.
        let mut regtest = test_manager(vec![]);
        assert!(!regtest.maybe_inject_fixed_seeds());
    }

    #[test]
    fn test_current_anchors_outbound_only_capped_at_two() {
        let mut mgr = test_manager(vec![]);
        // peer_addrs only ever tracks outbound peers; inbound peers live in
        // inbound_peers and are never inserted, so they can't become anchors.
        mgr.peer_addrs
            .insert(1, NetAddr::Ip("1.1.1.1:8333".parse().unwrap()));
        mgr.peer_addrs
            .insert(2, NetAddr::Ip("2.2.2.2:8333".parse().unwrap()));
        mgr.peer_addrs
            .insert(3, NetAddr::Ip("3.3.3.3:8333".parse().unwrap()));
        mgr.inbound_peers.insert(4);

        let anchors = mgr.current_anchors();
        assert_eq!(anchors.len(), 2, "anchors capped at 2");
        assert!(anchors
            .iter()
            .all(|a| mgr.peer_addrs.values().any(|p| p == a)));
    }

    #[test]
    fn test_peer_state_save_load_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let mut mgr = test_manager(vec![]);
        mgr.load_peer_state(dir.path()); // no files yet — sets the save dir

        let anchor = NetAddr::Ip("9.9.9.9:8333".parse().unwrap());
        mgr.addr_manager.add(anchor, 1);
        mgr.peer_addrs.insert(7, anchor);
        let banned: IpAddr = "8.8.8.8".parse().unwrap();
        mgr.scoring.ban_ip(
            banned,
            "test".to_string(),
            std::time::Duration::from_secs(3600),
        );
        mgr.save_peer_state();

        let mut fresh = test_manager(vec![]);
        fresh.load_peer_state(dir.path());
        assert_eq!(fresh.addr_manager.len(), 1);
        assert_eq!(fresh.anchors, vec![anchor]);
        assert!(fresh.scoring.is_banned(&banned));
    }

    #[test]
    fn test_connect_list_skips_addr_book_but_loads_bans() {
        let dir = tempfile::tempdir().unwrap();
        let mut mgr = test_manager(vec![]);
        mgr.load_peer_state(dir.path());
        let addr = NetAddr::Ip("9.9.9.9:8333".parse().unwrap());
        mgr.addr_manager.add(addr, 1);
        mgr.peer_addrs.insert(7, addr);
        let banned: IpAddr = "8.8.8.8".parse().unwrap();
        mgr.scoring.ban_ip(
            banned,
            "test".to_string(),
            std::time::Duration::from_secs(3600),
        );
        mgr.save_peer_state();

        // A node with --connect must keep its pinned topology: no persisted
        // addresses or anchors are loaded, but active bans still apply.
        let mut pinned = test_manager(vec![NetAddr::Ip("5.5.5.5:8333".parse().unwrap())]);
        pinned.load_peer_state(dir.path());
        assert_eq!(pinned.addr_manager.len(), 0);
        assert!(pinned.anchors.is_empty());
        assert!(pinned.scoring.is_banned(&banned));
    }
}
