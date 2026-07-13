//! CLI argument parsing, config-file loading, and small pure helpers for
//! network/datadir/port resolution. Extracted verbatim from main.rs (D1 of
//! the main.rs decomposition).

use clap::Parser;
use serde::Deserialize;
use std::collections::HashMap;
use std::path::PathBuf;
use tracing::info;

#[derive(Parser, Debug)]
#[command(name = "bitcoinprd", version, about = "Bitcoin full node in Rust")]
pub(crate) struct Cli {
    /// Network to connect to: mainnet, testnet, or regtest
    #[arg(long, default_value = "mainnet")]
    pub(crate) network: String,

    /// Data directory for blockchain storage
    #[arg(long, default_value = "~/.bitcoinpr")]
    pub(crate) datadir: String,

    /// Directory to hold the raw block files (blk*.dat) — point this at a
    /// larger/slower disk (e.g. an HDD) to keep bulk block data off the fast
    /// drive that holds the indexes and UTXO set. Mirrors Bitcoin Core's
    /// -blocksdir. The blocks live at <blocksdir>/<network>/blocks; everything
    /// else (headers, utxo, txindex, scripthash index) stays under --datadir.
    #[arg(long)]
    pub(crate) blocksdir: Option<String>,

    /// Move existing blk*.dat files from the datadir into --blocksdir on
    /// startup, then continue running against the new location. One-shot
    /// migration: the indexes are untouched (block positions don't record the
    /// directory), so this is safe across filesystems. Requires --blocksdir.
    #[arg(long)]
    pub(crate) migrateblocks: bool,

    /// RPC server bind address
    #[arg(long, default_value = "127.0.0.1")]
    pub(crate) rpcbind: String,

    /// RPC server port
    #[arg(long)]
    pub(crate) rpcport: Option<u16>,

    /// RPC username
    #[arg(long, default_value = "bitcoinpr")]
    pub(crate) rpcuser: String,

    /// RPC password
    #[arg(long, default_value = "bitcoinpr")]
    pub(crate) rpcpassword: String,

    /// P2P listen port
    #[arg(long)]
    pub(crate) port: Option<u16>,

    /// Connect only to this peer (can be specified multiple times)
    #[arg(long)]
    pub(crate) connect: Vec<String>,

    /// Log level: trace, debug, info, warn, error
    #[arg(long, default_value = "info")]
    pub(crate) loglevel: String,

    /// Maintain a full transaction index (enables getrawtransaction for all txs)
    #[arg(long)]
    pub(crate) txindex: bool,

    /// Output structured JSON logs instead of human-readable format
    #[arg(long)]
    pub(crate) jsonlog: bool,

    /// Enable address indexing (scripthash index for explorer and Electrum)
    #[arg(long)]
    pub(crate) index: bool,

    /// Rebuild the scripthash index from scratch on startup
    #[arg(long)]
    pub(crate) reindex: bool,

    /// Rebuild UTXO set + tx index + scripthash index from stored block files.
    /// Preserves headers and blk*.dat files. Use when block data on disk is
    /// intact but derived state (UTXO/txindex) is corrupted or unrecoverable.
    /// Replays every block from genesis through the stored block files.
    #[arg(long)]
    pub(crate) reindex_chainstate: bool,

    /// Web explorer port (default 3000)
    #[arg(long, default_value = "3000")]
    pub(crate) webport: u16,

    /// Admin token required (as `Authorization: Bearer <token>`) for mutating
    /// web-explorer endpoints such as POST /api/mining/config. When unset,
    /// those endpoints are disabled and the explorer is strictly read-only.
    #[arg(long)]
    pub(crate) webadmintoken: Option<String>,

    /// Bind address for the plain-HTTP health endpoint, as ip:port
    /// (e.g. 127.0.0.1:18543). Defaults to the RPC bind IP on rpcport+100.
    /// Use this to keep the health endpoint on loopback when RPC is bound
    /// to a non-loopback address.
    #[arg(long)]
    pub(crate) healthbind: Option<String>,

    /// UTXO database cache size in MB (default 450)
    #[arg(long, default_value = "450")]
    pub(crate) dbcache: u32,

    /// Enable Datum mining gateway
    #[arg(long)]
    pub(crate) mining: bool,

    /// Mining gateway port (default 3333)
    #[arg(long, default_value = "3333")]
    pub(crate) miningport: u16,

    /// Address for coinbase outputs (e.g. tb1q... for testnet)
    #[arg(long)]
    pub(crate) miningaddress: Option<String>,

    /// Pin the Stratum share difficulty (Bitcoin-style difficulty number),
    /// disabling per-worker vardiff. Without it, each connection's share
    /// difficulty ramps automatically toward ~1 share per 15 s.
    /// Never changes block nBits — mined blocks stay consensus-valid.
    /// Example: --miningdifficulty 70000 ≈ 1 share per 10 min at 500 GH/s.
    #[arg(long)]
    pub(crate) miningdifficulty: Option<f64>,

    /// Coinbase scriptSig tag (appended after BIP34 height). Default: /BitcoinPR/
    #[arg(long)]
    pub(crate) coinbasetag: Option<String>,

    /// Pool attribution name embedded for block-explorer identification.
    #[arg(long)]
    pub(crate) poolname: Option<String>,

    /// Serve BIP 37 bloom-filtered connections (advertises NODE_BLOOM, BIP 111).
    #[arg(long)]
    pub(crate) peerbloomfilters: bool,

    /// Electrum server plain-text TCP port (requires --index)
    #[arg(long, default_value = "50001")]
    pub(crate) electrumport: u16,

    /// Electrum server SSL/TLS port (defaults to --electrumport + 1)
    #[arg(long)]
    pub(crate) electrumsslport: Option<u16>,

    /// Path to a PEM TLS certificate chain for the Electrum SSL port.
    /// When unset, a self-signed certificate is generated at startup.
    #[arg(long)]
    pub(crate) electrumcert: Option<String>,

    /// Path to the PEM private key matching --electrumcert.
    #[arg(long)]
    pub(crate) electrumkey: Option<String>,

    /// MOTD banner returned by the Electrum `server.banner` method.
    #[arg(long)]
    pub(crate) electrumbanner: Option<String>,

    /// Disable outbound IPv6 peer connections (use when the host has no IPv6 route).
    #[arg(long)]
    pub(crate) disableipv6: bool,

    /// Disable the BIP 324 v2 encrypted transport (on by default). v1-only peers
    /// still connect regardless via automatic fallback.
    #[arg(long)]
    pub(crate) no_v2transport: bool,

    /// Route outbound connections through this SOCKS5 proxy (`host:port`), e.g.
    /// a Tor daemon at 127.0.0.1:9050. Applies to every network unless --onion
    /// overrides the onion route. `.onion` hostnames are resolved by the proxy.
    #[arg(long)]
    pub(crate) proxy: Option<String>,

    /// SOCKS5 proxy (`host:port`) used specifically for `.onion` connections,
    /// overriding --proxy for Tor. Defaults to --proxy when unset.
    #[arg(long)]
    pub(crate) onion: Option<String>,

    /// Restrict outbound connections to the given network(s): ipv4, ipv6, onion,
    /// i2p. Repeatable; when set, only the listed networks are dialed (e.g.
    /// `--onlynet=onion` for a Tor-only node). Unset = all networks.
    #[arg(long)]
    pub(crate) onlynet: Vec<String>,

    /// Randomize SOCKS5 credentials per connection so Tor isolates each dial
    /// onto its own circuit (Core -proxyrandomize). Default 1.
    #[arg(long, value_parser = cli_bool, num_args = 0..=1, default_missing_value = "1")]
    pub(crate) proxyrandomize: Option<bool>,

    /// Create a v3 `.onion` hidden service via the Tor control port so the node
    /// is reachable over Tor (Core -listenonion). Default 1: attempted when a
    /// Tor control port is reachable, otherwise silently skipped.
    #[arg(long, value_parser = cli_bool, num_args = 0..=1, default_missing_value = "1")]
    pub(crate) listenonion: Option<bool>,

    /// Tor control port used for -listenonion (Core -torcontrol).
    /// Default 127.0.0.1:9051.
    #[arg(long)]
    pub(crate) torcontrol: Option<String>,

    /// Password for the Tor control port (Core -torpassword). When unset,
    /// cookie-file (SAFECOOKIE) authentication is used if available.
    #[arg(long)]
    pub(crate) torpassword: Option<String>,

    /// I2P SAM bridge address (`host:port`) enabling the I2P transport
    /// (Core -i2psam), e.g. an i2pd router at 127.0.0.1:7656. Unset disables I2P.
    #[arg(long)]
    pub(crate) i2psam: Option<String>,

    /// Accept inbound I2P connections via the SAM session (Core
    /// -i2pacceptincoming). Default 1 when --i2psam is set.
    #[arg(long, value_parser = cli_bool, num_args = 0..=1, default_missing_value = "1")]
    pub(crate) i2pacceptincoming: Option<bool>,

    /// TEST ONLY: treat private/RFC1918 addresses as routable so the `addr`
    /// self-advertisement / gossip path can be exercised end-to-end on a
    /// private (e.g. interop-cluster) network. Never enable in production.
    #[arg(long)]
    pub(crate) gossip_private_addrs: bool,

    /// BIP-110 (Reduced Data Temporary Softfork) activation height override.
    /// Sets the height at/after which the seven RDTS rules are enforced (and the
    /// grandfathering cutoff for spent UTXOs). Mainnet defaults to 965664; other
    /// networks have no default. Primarily for testing RDTS enforcement on regtest.
    #[arg(long)]
    pub(crate) bip110height: Option<u32>,

    /// Prune (delete) old block files, keeping total block-file size under
    /// this many MiB (0 = disabled; minimum 550). Undo records of pruned
    /// blocks are removed too. The most recent 288 blocks are always kept
    /// (BIP 159 reorg window) and the node advertises NODE_NETWORK_LIMITED
    /// instead of NODE_NETWORK. Incompatible with --txindex and --index.
    #[arg(long, default_value = "0")]
    pub(crate) prune: u64,

    /// Relay and mine transactions with OP_RETURN data-carrier outputs
    /// (Core/Knots -datacarrier). Set to 0 to reject them from the mempool.
    /// Policy only — blocks containing them still validate. Default: 1.
    #[arg(long, value_parser = cli_bool, num_args = 0..=1, default_missing_value = "1")]
    pub(crate) datacarrier: Option<bool>,

    /// Relay and mine bare (non-P2SH) multisig outputs (Core/Knots
    /// -permitbaremultisig). Default 0, matching Knots: bare multisig is the
    /// data-embedding vector used by Stamps/SRC-20 and its outputs bloat the
    /// UTXO set forever. Set to 1 for Bitcoin Core-compatible relay.
    #[arg(long, value_parser = cli_bool, num_args = 0..=1, default_missing_value = "1")]
    pub(crate) permitbaremultisig: Option<bool>,

    /// Reject parasitic-protocol transactions — inscription envelopes
    /// (OP_FALSE OP_IF ... OP_ENDIF) in tapscript witnesses (Knots
    /// -rejectparasites). Default 1 (Knots default); disable with
    /// --rejectparasites=0. Policy only.
    #[arg(long, value_parser = cli_bool, num_args = 0..=1, default_missing_value = "1")]
    pub(crate) rejectparasites: Option<bool>,

    /// Reject token-protocol transactions — Runes runestones,
    /// Omni/Counterparty OP_RETURN payloads, BRC-20 inscriptions (Knots
    /// -rejecttokens). Default 1 (stricter than Knots); disable with
    /// --rejecttokens=0. Policy only.
    #[arg(long, value_parser = cli_bool, num_args = 0..=1, default_missing_value = "1")]
    pub(crate) rejecttokens: Option<bool>,

    /// Maximum size in bytes of OP_RETURN output scripts to relay and mine,
    /// including the OP_RETURN opcode byte (Core/Knots -datacarriersize).
    /// Core defaults to 83; Knots uses 42. Ignored when --datacarrier=0.
    /// Default: 83.
    #[arg(long)]
    pub(crate) datacarriersize: Option<usize>,
}

/// clap value parser for Bitcoin Core-style boolean option values
/// (`--datacarrier=0`, `--rejecttokens`, `--permitbaremultisig false`).
fn cli_bool(v: &str) -> Result<bool, String> {
    parse_conf_bool(v)
        .ok_or_else(|| format!("expected 1/0, true/false, yes/no, or on/off, got '{v}'"))
}

/// Configuration from bitcoinpr.conf file.
/// Uses Bitcoin Core-style key=value format (not TOML sections).
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub(crate) struct Config {
    pub(crate) network: Option<String>,
    pub(crate) datadir: Option<String>,
    pub(crate) blocksdir: Option<String>,
    pub(crate) rpcbind: Option<String>,
    pub(crate) rpcport: Option<u16>,
    pub(crate) rpcuser: Option<String>,
    pub(crate) rpcpassword: Option<String>,
    pub(crate) port: Option<u16>,
    pub(crate) loglevel: Option<String>,
    #[serde(default)]
    pub(crate) connect: Vec<String>,
    pub(crate) index: Option<bool>,
    pub(crate) webport: Option<u16>,
    pub(crate) webadmintoken: Option<String>,
    pub(crate) healthbind: Option<String>,
    pub(crate) mining: Option<bool>,
    pub(crate) miningport: Option<u16>,
    pub(crate) miningaddress: Option<String>,
    pub(crate) miningdifficulty: Option<f64>,
    pub(crate) coinbasetag: Option<String>,
    pub(crate) poolname: Option<String>,
    pub(crate) dbcache: Option<u32>,
    pub(crate) peerbloomfilters: Option<bool>,
    pub(crate) txindex: Option<bool>,
    pub(crate) jsonlog: Option<bool>,
    pub(crate) electrumport: Option<u16>,
    pub(crate) electrumsslport: Option<u16>,
    pub(crate) electrumcert: Option<String>,
    pub(crate) electrumkey: Option<String>,
    pub(crate) electrumbanner: Option<String>,
    pub(crate) disableipv6: Option<bool>,
    pub(crate) v2transport: Option<bool>,
    pub(crate) proxy: Option<String>,
    pub(crate) onion: Option<String>,
    pub(crate) onlynet: Vec<String>,
    pub(crate) proxyrandomize: Option<bool>,
    pub(crate) listenonion: Option<bool>,
    pub(crate) torcontrol: Option<String>,
    pub(crate) torpassword: Option<String>,
    pub(crate) i2psam: Option<String>,
    pub(crate) i2pacceptincoming: Option<bool>,
    pub(crate) gossip_private_addrs: Option<bool>,
    pub(crate) bip110height: Option<u32>,
    pub(crate) prune: Option<u64>,
    pub(crate) datacarrier: Option<bool>,
    pub(crate) permitbaremultisig: Option<bool>,
    pub(crate) rejectparasites: Option<bool>,
    pub(crate) rejecttokens: Option<bool>,
    pub(crate) datacarriersize: Option<usize>,
}

/// Parse a Bitcoin Core-style boolean config value. Accepts `1`/`0`,
/// `true`/`false`, `yes`/`no`, and `on`/`off` (case-insensitive). Returns
/// `None` for unrecognized values so callers fall back to defaults.
pub(crate) fn parse_conf_bool(v: &str) -> Option<bool> {
    match v.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Some(true),
        "0" | "false" | "no" | "off" => Some(false),
        _ => None,
    }
}

/// Parse an optional numeric config value. A present-but-unparseable value is
/// a hard error: config mistakes on a full node must be fatal, not silently
/// replaced with a default (M9, 2026-07-02 review).
fn conf_num<T: std::str::FromStr>(
    map: &HashMap<String, String>,
    key: &str,
) -> anyhow::Result<Option<T>>
where
    T::Err: std::fmt::Display,
{
    match map.get(key) {
        None => Ok(None),
        Some(v) => v
            .trim()
            .parse::<T>()
            .map(Some)
            .map_err(|e| anyhow::anyhow!("invalid value '{v}' for config key '{key}': {e}")),
    }
}

/// Parse an optional boolean config value; unrecognized values are fatal
/// (same rationale as [`conf_num`]).
fn conf_bool(map: &HashMap<String, String>, key: &str) -> anyhow::Result<Option<bool>> {
    match map.get(key) {
        None => Ok(None),
        Some(v) => parse_conf_bool(v).map(Some).ok_or_else(|| {
            anyhow::anyhow!(
                "invalid boolean '{v}' for config key '{key}' \
                 (expected 1/0, true/false, yes/no, on/off)"
            )
        }),
    }
}

/// Load configuration from a Bitcoin Core-style key=value config file.
/// A missing file yields defaults; a file with malformed values is fatal.
pub(crate) fn load_config(path: &PathBuf) -> anyhow::Result<Config> {
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return Ok(Config::default()),
    };

    info!(path = %path.display(), "Loading config file");

    let mut map = HashMap::new();
    let mut connects = Vec::new();
    let mut onlynets = Vec::new();

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((key, value)) = line.split_once('=') {
            let key = key.trim();
            let value = value.trim();
            if key == "connect" || key == "addnode" {
                connects.push(value.to_string());
            } else if key == "onlynet" {
                onlynets.push(value.to_string());
            } else {
                map.insert(key.to_string(), value.to_string());
            }
        }
    }

    Ok(Config {
        network: map.get("network").cloned(),
        datadir: map.get("datadir").cloned(),
        blocksdir: map.get("blocksdir").cloned(),
        rpcbind: map.get("rpcbind").cloned(),
        rpcport: conf_num(&map, "rpcport")?,
        rpcuser: map.get("rpcuser").cloned(),
        rpcpassword: map.get("rpcpassword").cloned(),
        port: conf_num(&map, "port")?,
        loglevel: map.get("loglevel").cloned(),
        connect: connects,
        index: conf_bool(&map, "index")?,
        webport: conf_num(&map, "webport")?,
        webadmintoken: map.get("webadmintoken").cloned(),
        healthbind: map.get("healthbind").cloned(),
        mining: conf_bool(&map, "mining")?,
        miningport: conf_num(&map, "miningport")?,
        miningaddress: map.get("miningaddress").cloned(),
        miningdifficulty: conf_num(&map, "miningdifficulty")?,
        coinbasetag: map.get("coinbasetag").cloned(),
        poolname: map.get("poolname").cloned(),
        dbcache: conf_num(&map, "dbcache")?,
        peerbloomfilters: conf_bool(&map, "peerbloomfilters")?,
        txindex: conf_bool(&map, "txindex")?,
        jsonlog: conf_bool(&map, "jsonlog")?,
        electrumport: conf_num(&map, "electrumport")?,
        electrumsslport: conf_num(&map, "electrumsslport")?,
        electrumcert: map.get("electrumcert").cloned(),
        electrumkey: map.get("electrumkey").cloned(),
        electrumbanner: map.get("electrumbanner").cloned(),
        disableipv6: conf_bool(&map, "disableipv6")?,
        v2transport: conf_bool(&map, "v2transport")?,
        proxy: map.get("proxy").cloned(),
        onion: map.get("onion").cloned(),
        onlynet: onlynets,
        proxyrandomize: conf_bool(&map, "proxyrandomize")?,
        listenonion: conf_bool(&map, "listenonion")?,
        torcontrol: map.get("torcontrol").cloned(),
        torpassword: map.get("torpassword").cloned(),
        i2psam: map.get("i2psam").cloned(),
        i2pacceptincoming: conf_bool(&map, "i2pacceptincoming")?,
        gossip_private_addrs: conf_bool(&map, "gossipprivateaddrs")?,
        bip110height: conf_num(&map, "bip110height")?,
        prune: conf_num(&map, "prune")?,
        datacarrier: conf_bool(&map, "datacarrier")?,
        permitbaremultisig: conf_bool(&map, "permitbaremultisig")?,
        rejectparasites: conf_bool(&map, "rejectparasites")?,
        rejecttokens: conf_bool(&map, "rejecttokens")?,
        datacarriersize: conf_num(&map, "datacarriersize")?,
    })
}

/// Parse a `--network`/`network=` value. Unknown names are fatal: silently
/// defaulting a typo like `regtset` to mainnet would dial mainnet DNS seeds
/// and write into the mainnet datadir (M9, 2026-07-02 review).
pub(crate) fn parse_network(s: &str) -> anyhow::Result<bitcoin::Network> {
    match s.to_lowercase().as_str() {
        "mainnet" | "main" => Ok(bitcoin::Network::Bitcoin),
        "testnet" | "test" => Ok(bitcoin::Network::Testnet),
        "testnet4" | "test4" => Ok(bitcoin::Network::Testnet4),
        "regtest" => Ok(bitcoin::Network::Regtest),
        "signet" => Ok(bitcoin::Network::Signet),
        other => anyhow::bail!(
            "unknown network '{other}'; expected mainnet|testnet|testnet4|regtest|signet"
        ),
    }
}

/// Convert a Bitcoin-style difficulty float to a compact nBits u32.
///
/// difficulty = difficulty_1_target / target
/// difficulty_1_target ≈ 2^224  (the actual value is 0x00000000FFFF * 2^208)
///
/// We use log2 arithmetic to avoid precision loss on very large targets, then
/// pack the result into the 4-byte compact format used in block headers.
pub(crate) fn difficulty_to_nbits(difficulty: f64) -> u32 {
    if difficulty <= 0.0 || difficulty.is_nan() {
        return 0x207fffff; // regtest minimum (maximum target)
    }

    // log2(target) = log2(difficulty_1_target) - log2(difficulty)
    // difficulty_1_target = 0xFFFF * 2^208  =>  log2 ≈ 15.9999 + 208 ≈ 223.9999
    let log2_target = 224.0_f64 - difficulty.log2();

    if log2_target >= 256.0 {
        return 0x207fffff; // difficulty < 1: clamp to min
    }
    if log2_target <= 0.0 {
        return 0x03000001; // absurdly high difficulty: maximum target
    }

    // Number of bytes needed to represent the target (at least 3)
    let nbytes = ((log2_target / 8.0).ceil() as i32).max(3) as u32;

    // Mantissa = target / 256^(nbytes-3)
    // = 2^log2_target / 2^(8*(nbytes-3))
    let mantissa_log2 = log2_target - 8.0 * (nbytes - 3) as f64;
    let mantissa = (2.0_f64.powf(mantissa_log2).round() as u32).min(0xffffff);

    // If the high bit of the 3-byte mantissa is set the decoder would treat it
    // as negative — shift up by one byte in that case.
    if mantissa & 0x800000 != 0 {
        ((nbytes + 1) << 24) | (mantissa >> 8)
    } else {
        (nbytes << 24) | (mantissa & 0x7fffff)
    }
}

pub(crate) fn expand_datadir(datadir: &str) -> PathBuf {
    if datadir.starts_with('~') {
        if let Some(home) = std::env::var_os("HOME") {
            return PathBuf::from(home).join(&datadir[2..]);
        }
    }
    PathBuf::from(datadir)
}

/// Append the network-specific subdirectory to a base path. Mainnet uses the
/// base directly; other networks nest under their chain name. Used for both the
/// datadir and --blocksdir so block storage mirrors the datadir layout.
pub(crate) fn net_subdir(base: &std::path::Path, network: bitcoin::Network) -> PathBuf {
    match network {
        bitcoin::Network::Bitcoin => base.to_path_buf(),
        bitcoin::Network::Testnet => base.join("testnet3"),
        bitcoin::Network::Testnet4 => base.join("testnet4"),
        bitcoin::Network::Regtest => base.join("regtest"),
        bitcoin::Network::Signet => base.join("signet"),
    }
}

pub(crate) fn default_rpc_port(network: bitcoin::Network) -> u16 {
    match network {
        bitcoin::Network::Bitcoin => 8332,
        bitcoin::Network::Testnet => 18332,
        bitcoin::Network::Testnet4 => 48332,
        bitcoin::Network::Regtest => 18443,
        bitcoin::Network::Signet => 38332,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    /// M9 (2026-07-02 review): a typoed network name must be fatal, not a
    /// silent fallback to mainnet (which would dial mainnet seeds and write
    /// into the mainnet datadir).
    #[test]
    fn parse_network_rejects_unknown_names() {
        assert!(parse_network("regtset").is_err());
        assert!(parse_network("").is_err());
        let err = parse_network("bogus").unwrap_err().to_string();
        assert!(err.contains("unknown network 'bogus'"), "got: {err}");
        assert_eq!(parse_network("REGTEST").unwrap(), bitcoin::Network::Regtest);
        assert_eq!(parse_network("main").unwrap(), bitcoin::Network::Bitcoin);
    }

    fn write_temp_conf(label: &str, contents: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("bitcoinpr_conf_{label}_{nanos}.conf"));
        std::fs::write(&path, contents).unwrap();
        path
    }

    /// M9: present-but-malformed numeric and boolean conf values must be
    /// fatal instead of silently parsing to a default.
    #[test]
    fn load_config_rejects_malformed_values() {
        let path = write_temp_conf("badnum", "rpcport=not-a-port\n");
        let err = load_config(&path).unwrap_err().to_string();
        assert!(err.contains("rpcport"), "got: {err}");
        std::fs::remove_file(&path).unwrap();

        let path = write_temp_conf("badbool", "txindex=maybe\n");
        let err = load_config(&path).unwrap_err().to_string();
        assert!(err.contains("txindex"), "got: {err}");
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn load_config_parses_relay_policy_options() {
        let path = write_temp_conf(
            "policy",
            "datacarrier=0\npermitbaremultisig=0\nrejectparasites=1\nrejecttokens=0\ndatacarriersize=42\n",
        );
        let cfg = load_config(&path).unwrap();
        assert_eq!(cfg.datacarrier, Some(false));
        assert_eq!(cfg.permitbaremultisig, Some(false));
        assert_eq!(cfg.rejectparasites, Some(true));
        assert_eq!(cfg.rejecttokens, Some(false));
        assert_eq!(cfg.datacarriersize, Some(42));
        std::fs::remove_file(&path).unwrap();

        // Unset keys stay None so per-network defaults apply.
        let path = write_temp_conf("policy_unset", "rpcport=18443\n");
        let cfg = load_config(&path).unwrap();
        assert_eq!(cfg.datacarrier, None);
        assert_eq!(cfg.permitbaremultisig, None);
        assert_eq!(cfg.datacarriersize, None);
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn load_config_accepts_valid_values_and_missing_file() {
        let path = write_temp_conf("good", "rpcport=18443\ntxindex=1\nnetwork=regtest\n");
        let cfg = load_config(&path).unwrap();
        assert_eq!(cfg.rpcport, Some(18443));
        assert_eq!(cfg.txindex, Some(true));
        assert_eq!(cfg.network.as_deref(), Some("regtest"));
        std::fs::remove_file(&path).unwrap();

        // Missing file falls back to defaults, not an error.
        let missing = std::env::temp_dir().join("bitcoinpr_conf_definitely_missing.conf");
        assert!(load_config(&missing).unwrap().rpcport.is_none());
    }
}
