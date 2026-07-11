use bitcoin::p2p::message::{NetworkMessage, RawNetworkMessage};
use bitcoin::p2p::message_blockdata::{GetHeadersMessage, Inventory};
use bitcoin::p2p::message_network::VersionMessage;
use bitcoin::p2p::{Address, ServiceFlags};
use bitcoin::{BlockHash, Network};
use std::net::SocketAddr;
use std::time::{SystemTime, UNIX_EPOCH};

/// Protocol version we advertise.
pub const PROTOCOL_VERSION: u32 = 70016;

/// User agent string. BIP 14: `/Name:Version/` subversion format. The version is
/// the workspace crate version (`Cargo.toml` is the single source of truth).
pub const USER_AGENT: &str = concat!("/bitcoinpr:", env!("CARGO_PKG_VERSION"), "/");

/// Compute advertised service flags.
/// BIP 111: advertise NODE_BLOOM only when we serve BIP 37 bloom filters.
/// BIP 159: a pruned node advertises NODE_NETWORK_LIMITED *instead of*
/// NODE_NETWORK — it can serve the most recent 288 blocks but not deep
/// history, so claiming full NODE_NETWORK would be a lie to peers doing IBD.
pub fn node_service_flags(peer_bloom: bool, network_limited: bool) -> ServiceFlags {
    let mut f = if network_limited {
        ServiceFlags::NETWORK_LIMITED | ServiceFlags::WITNESS
    } else {
        ServiceFlags::NETWORK | ServiceFlags::WITNESS
    };
    if peer_bloom {
        // BIP 111
        f |= ServiceFlags::BLOOM;
    }
    f
}

/// Build a version message to send during handshake.
pub fn build_version_message(
    network: Network,
    local_addr: SocketAddr,
    remote_addr: SocketAddr,
    start_height: i32,
    nonce: u64,
    services: ServiceFlags,
) -> RawNetworkMessage {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time before UNIX epoch")
        .as_secs() as i64;

    let version = VersionMessage {
        version: PROTOCOL_VERSION,
        services,
        timestamp,
        receiver: Address::new(&remote_addr, ServiceFlags::NETWORK),
        sender: Address::new(&local_addr, ServiceFlags::NETWORK),
        nonce,
        user_agent: USER_AGENT.to_string(),
        start_height,
        relay: true,
    };

    RawNetworkMessage::new(network.magic(), NetworkMessage::Version(version))
}

/// Build a verack message.
pub fn build_verack(network: Network) -> RawNetworkMessage {
    RawNetworkMessage::new(network.magic(), NetworkMessage::Verack)
}

/// Build a getheaders message.
pub fn build_getheaders(
    network: Network,
    locator_hashes: Vec<BlockHash>,
    stop_hash: BlockHash,
) -> RawNetworkMessage {
    let msg = GetHeadersMessage::new(locator_hashes, stop_hash);
    RawNetworkMessage::new(network.magic(), NetworkMessage::GetHeaders(msg))
}

/// Build a ping message.
pub fn build_ping(network: Network, nonce: u64) -> RawNetworkMessage {
    RawNetworkMessage::new(network.magic(), NetworkMessage::Ping(nonce))
}

/// Build a pong message.
pub fn build_pong(network: Network, nonce: u64) -> RawNetworkMessage {
    RawNetworkMessage::new(network.magic(), NetworkMessage::Pong(nonce))
}

/// Build a sendheaders message.
pub fn build_sendheaders(network: Network) -> RawNetworkMessage {
    RawNetworkMessage::new(network.magic(), NetworkMessage::SendHeaders)
}

/// Build a sendaddrv2 message (BIP 155) — signals we understand `addrv2`
/// and want onion/I2P/CJDNS addresses gossiped in that richer format.
pub fn build_sendaddrv2(network: Network) -> RawNetworkMessage {
    RawNetworkMessage::new(network.magic(), NetworkMessage::SendAddrV2)
}

/// Build a getdata message for blocks.
pub fn build_getdata_blocks(network: Network, hashes: Vec<BlockHash>) -> RawNetworkMessage {
    let inv: Vec<Inventory> = hashes.into_iter().map(Inventory::WitnessBlock).collect();
    RawNetworkMessage::new(network.magic(), NetworkMessage::GetData(inv))
}

/// Build a getdata message for transactions.
pub fn build_getdata_txs(network: Network, txids: Vec<bitcoin::Txid>) -> RawNetworkMessage {
    let inv: Vec<Inventory> = txids
        .into_iter()
        .map(Inventory::WitnessTransaction)
        .collect();
    RawNetworkMessage::new(network.magic(), NetworkMessage::GetData(inv))
}

/// Build an inv message for a transaction.
pub fn build_inv_tx(network: Network, txid: bitcoin::Txid) -> RawNetworkMessage {
    let inv = vec![Inventory::WitnessTransaction(txid)];
    RawNetworkMessage::new(network.magic(), NetworkMessage::Inv(inv))
}

/// Build a sendcmpct message (BIP 152).
pub fn build_sendcmpct(network: Network, announce: bool, version: u64) -> RawNetworkMessage {
    use bitcoin::p2p::message_compact_blocks::SendCmpct;
    let msg = SendCmpct {
        send_compact: announce,
        version,
    };
    RawNetworkMessage::new(network.magic(), NetworkMessage::SendCmpct(msg))
}

/// Build an addr message advertising our own listening address.
pub fn build_self_addr(
    network: Network,
    local_addr: SocketAddr,
    services: ServiceFlags,
) -> RawNetworkMessage {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time before UNIX epoch")
        .as_secs() as u32;
    let addr = (timestamp, Address::new(&local_addr, services));
    RawNetworkMessage::new(network.magic(), NetworkMessage::Addr(vec![addr]))
}

/// Wrap any NetworkMessage into a RawNetworkMessage for the given network.
pub fn build_raw_network_message(network: Network, msg: NetworkMessage) -> RawNetworkMessage {
    RawNetworkMessage::new(network.magic(), msg)
}
