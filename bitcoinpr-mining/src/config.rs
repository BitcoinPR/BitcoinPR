use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Maximum allowed length (in bytes) of the coinbase scriptSig tag.
pub const MAX_COINBASE_TAG_LEN: usize = 80;

/// Mining coordination mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum MiningMode {
    /// Local solo mining, no pool coordination.
    #[default]
    Solo,
    /// Datum protocol — template sovereignty with pool payout splits.
    Datum,
}

/// Datum server connection settings (used only when `mode == MiningMode::Datum`).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DatumConfig {
    /// e.g. "datum.ocean.xyz:3334"
    pub server_url: String,
    /// Miner's payout address for pool rewards.
    pub payout_address: String,
    /// Identifier sent to the pool.
    pub worker_name: String,
    #[serde(default)]
    pub auth_token: Option<String>,
}

/// Runtime mining configuration. Wrapped in `Arc<RwLock<..>>` and shared across
/// the TemplateProvider, DatumClient, and web layer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MiningConfig {
    /// Coinbase destination address (None => OP_TRUE anyone-can-spend).
    #[serde(default)]
    pub mining_address: Option<String>,
    /// Coinbase scriptSig tag bytes (e.g. b"/BitcoinPR/"), appended after the
    /// BIP34 height push and before the extranonces.
    #[serde(default, with = "tag_serde")]
    pub coinbase_tag: Vec<u8>,
    /// Pool attribution name for block-explorer identification.
    #[serde(default)]
    pub pool_name: String,
    /// Stratum port (read-only after startup — changing requires listener rebind).
    #[serde(default)]
    pub stratum_port: u16,
    /// Mining mode.
    #[serde(default)]
    pub mode: MiningMode,
    /// Datum server configuration.
    #[serde(default)]
    pub datum: DatumConfig,
}

impl Default for MiningConfig {
    fn default() -> Self {
        MiningConfig {
            mining_address: None,
            coinbase_tag: b"/BitcoinPR/".to_vec(),
            pool_name: "BitcoinPR".to_string(),
            stratum_port: 3333,
            mode: MiningMode::Solo,
            datum: DatumConfig::default(),
        }
    }
}

impl MiningConfig {
    /// Path to the on-disk config file inside `datadir`.
    pub fn config_path(datadir: &Path) -> PathBuf {
        datadir.join("mining.toml")
    }

    /// Load and parse `mining.toml` if present. On any error (missing file,
    /// parse error) returns `Self::default()`. A `tracing::warn!` is emitted
    /// only for parse errors, not for a missing file.
    pub fn load(datadir: &Path) -> Self {
        let path = Self::config_path(datadir);
        let contents = match std::fs::read_to_string(&path) {
            Ok(c) => c,
            Err(_) => return Self::default(),
        };
        match toml::from_str(&contents) {
            Ok(cfg) => cfg,
            Err(e) => {
                tracing::warn!("failed to parse mining config at {:?}: {}", path, e);
                Self::default()
            }
        }
    }

    /// Serialize to TOML and write to `config_path`, creating the datadir if
    /// missing.
    pub fn save(&self, datadir: &Path) -> anyhow::Result<()> {
        std::fs::create_dir_all(datadir)?;
        let path = Self::config_path(datadir);
        let contents = toml::to_string_pretty(self)?;
        std::fs::write(&path, contents)?;
        Ok(())
    }

    /// Validate configuration consistency.
    pub fn validate(&self) -> Result<(), String> {
        if let Some(addr) = &self.mining_address {
            addr.parse::<bitcoin::Address<bitcoin::address::NetworkUnchecked>>()
                .map_err(|e| format!("invalid mining_address: {e}"))?;
        }

        if self.coinbase_tag.len() > MAX_COINBASE_TAG_LEN {
            return Err(format!(
                "coinbase_tag is {} bytes, exceeds maximum of {}",
                self.coinbase_tag.len(),
                MAX_COINBASE_TAG_LEN
            ));
        }

        if self.mode == MiningMode::Datum {
            if self.datum.server_url.is_empty() {
                return Err("datum.server_url must not be empty in Datum mode".to_string());
            }
            let (host, port) = self
                .datum
                .server_url
                .rsplit_once(':')
                .ok_or_else(|| "datum.server_url must be in host:port form".to_string())?;
            if host.is_empty() {
                return Err("datum.server_url host must not be empty".to_string());
            }
            port.parse::<u16>()
                .map_err(|e| format!("datum.server_url has invalid port: {e}"))?;

            self.datum
                .payout_address
                .parse::<bitcoin::Address<bitcoin::address::NetworkUnchecked>>()
                .map_err(|e| format!("invalid datum.payout_address: {e}"))?;
        }

        Ok(())
    }

    /// Lossy UTF-8 of the tag (for display/JSON).
    pub fn coinbase_tag_str(&self) -> String {
        String::from_utf8_lossy(&self.coinbase_tag).to_string()
    }
}

/// Serde helper for `coinbase_tag`: stores the tag as a UTF-8 string when valid
/// (so `mining.toml` shows `coinbase_tag = "/BitcoinPR/"`), otherwise falls back
/// to a `hex:`-prefixed hex encoding. On deserialize, a `hex:` prefix selects
/// hex decoding; otherwise the string is treated as UTF-8 bytes.
mod tag_serde {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(tag: &[u8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match std::str::from_utf8(tag) {
            Ok(s) => serializer.serialize_str(s),
            Err(_) => serializer.serialize_str(&format!("hex:{}", hex::encode(tag))),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        if let Some(rest) = s.strip_prefix("hex:") {
            hex::decode(rest).map_err(serde::de::Error::custom)
        } else {
            Ok(s.into_bytes())
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn unique_temp_dir(label: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("bitcoinpr_cfg_{label}_{nanos}"));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn default_values() {
        let cfg = MiningConfig::default();
        assert_eq!(cfg.mining_address, None);
        assert_eq!(cfg.coinbase_tag, b"/BitcoinPR/".to_vec());
        assert_eq!(cfg.pool_name, "BitcoinPR");
        assert_eq!(cfg.stratum_port, 3333);
        assert_eq!(cfg.mode, MiningMode::Solo);
        assert_eq!(cfg.datum.server_url, "");
    }

    #[test]
    fn save_load_round_trip() {
        let dir = unique_temp_dir("roundtrip");

        let cfg = MiningConfig {
            mining_address: Some("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4".to_string()),
            coinbase_tag: b"/custom-tag/".to_vec(),
            pool_name: "myPool".to_string(),
            stratum_port: 4444,
            mode: MiningMode::Datum,
            datum: DatumConfig {
                server_url: "datum.ocean.xyz:3334".to_string(),
                payout_address: "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4".to_string(),
                worker_name: "worker1".to_string(),
                auth_token: Some("secret".to_string()),
            },
        };

        cfg.save(&dir).unwrap();
        let loaded = MiningConfig::load(&dir);

        assert_eq!(loaded.mining_address, cfg.mining_address);
        assert_eq!(loaded.coinbase_tag, cfg.coinbase_tag);
        assert_eq!(loaded.pool_name, cfg.pool_name);
        assert_eq!(loaded.stratum_port, cfg.stratum_port);
        assert_eq!(loaded.mode, cfg.mode);
        assert_eq!(loaded.datum.server_url, cfg.datum.server_url);
        assert_eq!(loaded.datum.payout_address, cfg.datum.payout_address);
        assert_eq!(loaded.datum.worker_name, cfg.datum.worker_name);
        assert_eq!(loaded.datum.auth_token, cfg.datum.auth_token);

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn validate_rejects_oversized_tag() {
        let cfg = MiningConfig {
            coinbase_tag: vec![b'x'; MAX_COINBASE_TAG_LEN + 1],
            ..Default::default()
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn validate_rejects_datum_empty_server_url() {
        let mut cfg = MiningConfig {
            mode: MiningMode::Datum,
            ..Default::default()
        };
        cfg.datum.server_url = String::new();
        cfg.datum.payout_address = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4".to_string();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn tag_serde_round_trips_utf8_and_binary() {
        #[derive(Serialize, Deserialize, Debug, PartialEq)]
        struct Wrap {
            #[serde(with = "tag_serde")]
            tag: Vec<u8>,
        }

        let utf8 = Wrap {
            tag: b"/BitcoinPR/".to_vec(),
        };
        let s = toml::to_string(&utf8).unwrap();
        assert!(s.contains("/BitcoinPR/"));
        let back: Wrap = toml::from_str(&s).unwrap();
        assert_eq!(back, utf8);

        let binary = Wrap {
            tag: vec![0xff, 0x00, 0x01],
        };
        let s = toml::to_string(&binary).unwrap();
        assert!(s.contains("hex:"));
        let back: Wrap = toml::from_str(&s).unwrap();
        assert_eq!(back, binary);
    }
}
