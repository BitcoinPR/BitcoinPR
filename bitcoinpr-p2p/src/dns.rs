use bitcoinpr_core::ConsensusParams;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::lookup_host;
use tracing::{debug, info, warn};

/// Per-seed DNS resolution timeout. `lookup_host` uses the blocking OS
/// resolver on a worker thread; an unreachable DNS server would otherwise
/// hold each lookup for the resolver's own timeout (commonly ~5 s per seed).
const SEED_LOOKUP_TIMEOUT: Duration = Duration::from_secs(3);

/// Resolve DNS seeds to get initial peer addresses.
///
/// All seeds are resolved concurrently, each capped at
/// [`SEED_LOOKUP_TIMEOUT`], so the worst case is one timeout — not the sum
/// over all seeds (H3, 2026-07-02 review: this used to be awaited serially
/// inside the P2P event loop, freezing all peer processing for the duration).
pub async fn resolve_seeds(params: &ConsensusParams) -> Vec<SocketAddr> {
    let port = params.default_port;

    let handles: Vec<_> = params
        .dns_seeds
        .iter()
        .map(|seed| {
            let seed = seed.to_string();
            let host = format!("{seed}:{port}");
            tokio::spawn(async move {
                match tokio::time::timeout(SEED_LOOKUP_TIMEOUT, lookup_host(host.as_str())).await {
                    Ok(Ok(resolved)) => {
                        let resolved: Vec<SocketAddr> = resolved.collect();
                        debug!("Resolved {} -> {} addresses", seed, resolved.len());
                        resolved
                    }
                    Ok(Err(e)) => {
                        warn!("Failed to resolve DNS seed {}: {}", seed, e);
                        Vec::new()
                    }
                    Err(_) => {
                        warn!(
                            "DNS seed {} timed out after {:?}",
                            seed, SEED_LOOKUP_TIMEOUT
                        );
                        Vec::new()
                    }
                }
            })
        })
        .collect();

    let mut addrs: Vec<SocketAddr> = Vec::new();
    for handle in handles {
        if let Ok(resolved) = handle.await {
            addrs.extend(resolved);
        }
    }

    info!(
        "DNS resolution complete: {} peer addresses found",
        addrs.len()
    );
    addrs
}
