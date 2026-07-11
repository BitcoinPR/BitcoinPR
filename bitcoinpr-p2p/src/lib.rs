#![warn(clippy::unwrap_used)]

pub mod addr_manager;
pub mod bloom;
pub mod codec;
pub mod dns;
pub mod error;
pub mod fixed_seeds;
pub mod i2p;
pub mod ibd;
pub mod manager;
pub mod messages;
pub mod netaddr;
pub mod peer;
pub mod scoring;
pub mod socks5;
pub mod sync;
pub mod tor;
pub mod transport;
pub mod v2_transport;

pub use addr_manager::AddrManager;
pub use error::{P2pError, P2pResult};
pub use i2p::{create_session, I2pConfig, I2pSession};
pub use ibd::{
    count_eligible_download_peers, eligible_download_peer_ids, is_catching_up,
    peer_eligible_for_download, stale_base_timeout, IBD_CATCH_UP_MARGIN, NETWORK_LIMITED_GAP,
};
pub use manager::{NodeEvent, PeerCommand, PeerManager};
pub use netaddr::{AddrNetwork, NetAddr};
pub use peer::{PeerId, PeerInfo};
pub use scoring::{Misbehavior, PeerScoring};
pub use socks5::ProxyConfig;
pub use sync::{BlockSync, HeaderSync, HeaderSyncError};
pub use tor::{create_hidden_service, HiddenService, TorConfig};
