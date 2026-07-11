use bitcoin::{Block, BlockHash, Network, ScriptBuf};

/// Consensus parameters for a specific Bitcoin network.
#[derive(Debug, Clone)]
pub struct ConsensusParams {
    pub network: Network,
    pub magic: [u8; 4],
    pub default_port: u16,
    pub genesis_block: Block,
    pub dns_seeds: Vec<&'static str>,
    /// Maximum proof-of-work target (lowest difficulty).
    pub pow_limit: [u8; 32],
    /// Target timespan for difficulty adjustment (2 weeks = 1_209_600 seconds).
    pub pow_target_timespan: u64,
    /// Target spacing between blocks (10 minutes = 600 seconds).
    pub pow_target_spacing: u64,
    /// Number of blocks between subsidy halvings.
    pub subsidy_halving_interval: u32,
    /// BIP 16 activation Unix timestamp (P2SH).
    /// April 1, 2012 00:00:00 UTC = 1333238400.  Set to 0 to always enable.
    pub bip16_time: u32,
    /// BIP 34 activation height (block height in coinbase).
    pub bip34_height: u32,
    /// BIP 65 activation height (OP_CHECKLOCKTIMEVERIFY).
    pub bip65_height: u32,
    /// BIP 90 (buried): BIP 68/112/113 CSV activation height.
    pub csv_height: u32,
    /// BIP 66 activation height (strict DER signatures).
    pub bip66_height: u32,
    /// SegWit activation height.
    pub segwit_height: u32,
    /// Taproot activation height (BIP 341).
    pub taproot_height: u32,
    /// If set, skip script verification for blocks at or below this hash.
    pub assume_valid: Option<BlockHash>,
    /// Minimum cumulative chain work for a header chain to be treated as the
    /// real network chain (Bitcoin Core's `nMinimumChainWork`), big-endian.
    /// Block download is deferred until the best header chain exceeds this
    /// work, and header sync is never marked complete below it. All-zero
    /// disables the check (regtest/signet).
    pub min_chain_work: [u8; 32],
    /// Whether difficulty adjustment is allowed to reduce to minimum (regtest/testnet).
    pub pow_no_retargeting: bool,
    /// Allow minimum difficulty blocks (testnet rule).
    pub pow_allow_min_difficulty_blocks: bool,
    /// Coinbase maturity (number of confirmations before coinbase outputs are spendable).
    pub coinbase_maturity: u32,
    /// Maximum block weight in weight units.
    pub max_block_weight: u32,
    /// Maximum size of OP_RETURN output scripts we relay (including the OP_RETURN byte).
    /// Bitcoin Core default is 83 bytes.
    pub max_datacarrier_size: usize,
    /// Relay/mine transactions with OP_RETURN data-carrier outputs (Core/Knots
    /// `-datacarrier`). Policy only — blocks containing them still validate.
    pub datacarrier: bool,
    /// Relay/mine bare (non-P2SH) `m-of-n OP_CHECKMULTISIG` outputs (Core/Knots
    /// `-permitbaremultisig`). Defaults to false like Knots: bare multisig is
    /// the data-embedding vector used by Stamps/SRC-20, whose fake-pubkey
    /// outputs are unspendable and bloat the UTXO set forever. Policy only.
    pub permit_bare_multisig: bool,
    /// Reject parasitic-protocol transactions (Knots `-rejectparasites`):
    /// inscription envelopes (`OP_FALSE OP_IF … OP_ENDIF`) in tapscript
    /// witnesses. Defaults to true, matching Knots. Policy only.
    pub reject_parasites: bool,
    /// Reject token-protocol transactions (Knots `-rejecttokens`): Runes
    /// runestones (`OP_RETURN OP_13`), Omni/Counterparty OP_RETURN prefixes,
    /// and BRC-20 inscription payloads. Defaults to true (stricter than
    /// Knots' default of false, by operator preference); disable with
    /// `rejecttokens=0`. Policy only.
    pub reject_tokens: bool,
    /// BIP-110 (Reduced Data Temporary Softfork) **fixed-mode** activation height
    /// override. When `Some(h)`, signaling is bypassed and the deployment is
    /// ACTIVE from height `h` with no expiry — the rules apply to outputs created
    /// at height `>= h` and to inputs spending UTXOs created at height `>= h`
    /// (earlier UTXOs grandfathered). This is the `--bip110height` override, used
    /// to pin activation deterministically for testing (regtest). It takes
    /// precedence over `bip110_deployment`.
    pub bip110_activation_height: Option<u32>,
    /// BIP-110 signaling deployment (mainnet). When set and no fixed override is
    /// present, the activation height is computed dynamically from on-chain bit-4
    /// signaling via [`crate::bip110::Bip110Checker`]; the deployment also expires
    /// `active_duration` blocks after activation. `None` on networks without a
    /// defined RDTS deployment.
    pub bip110_deployment: Option<crate::bip110::Bip110Deployment>,
    /// Signet challenge script (BIP 325). None for non-signet networks.
    pub signet_challenge: Option<ScriptBuf>,
}

impl ConsensusParams {
    pub fn for_network(network: Network) -> Self {
        match network {
            Network::Bitcoin => Self::mainnet(),
            Network::Testnet => Self::testnet(),
            Network::Testnet4 => Self::testnet4(),
            Network::Regtest => Self::regtest(),
            Network::Signet => Self::signet(),
        }
    }

    pub fn mainnet() -> Self {
        ConsensusParams {
            network: Network::Bitcoin,
            magic: [0xf9, 0xbe, 0xb4, 0xd9],
            default_port: 8333,
            genesis_block: bitcoin::constants::genesis_block(Network::Bitcoin),
            dns_seeds: vec![
                "seed.bitcoin.sipa.be",
                "dnsseed.bluematt.me",
                "dnsseed.bitcoin.dashjr.org",
                "seed.bitcoinstats.com",
                "seed.bitcoin.jonasschnelli.ch",
                "seed.btc.petertodd.net",
                "seed.bitcoin.sprovoost.nl",
                "dnsseed.emzy.de",
                "seed.bitcoin.wiz.biz",
            ],
            pow_limit: pow_limit_mainnet(),
            pow_target_timespan: 14 * 24 * 60 * 60, // 2 weeks
            pow_target_spacing: 10 * 60,            // 10 minutes
            subsidy_halving_interval: 210_000,
            bip16_time: 1333238400, // April 1, 2012 — BIP 16 P2SH activation
            bip34_height: 227_931,
            bip65_height: 388_381,
            csv_height: 419_328,
            bip66_height: 363_725,
            segwit_height: 481_824,
            taproot_height: 709_632,
            // Block 840000 (4th halving) — skip script verification up to this point for faster IBD
            assume_valid: Some(
                "0000000000000000000320283a032748cef8227873ff4872689bf23f1cda83a5"
                    .parse()
                    .expect("hardcoded assume-valid hash is valid"),
            ),
            // Bitcoin Core master nMinimumChainWork (chainparams.cpp)
            min_chain_work: chain_work_from_hex(
                "0000000000000000000000000000000000000001128750f82f4c366153a3a030",
            ),
            pow_no_retargeting: false,
            pow_allow_min_difficulty_blocks: false,
            coinbase_maturity: 100,
            max_block_weight: 4_000_000,
            max_datacarrier_size: 83,
            datacarrier: true,
            permit_bare_multisig: false,
            reject_parasites: true,
            reject_tokens: true,
            // BIP-110 RDTS: activation height is computed dynamically from bit-4
            // signaling (no fixed override on mainnet).
            bip110_activation_height: None,
            bip110_deployment: Some(crate::bip110::Bip110Deployment::mainnet()),
            signet_challenge: None,
        }
    }

    pub fn testnet() -> Self {
        ConsensusParams {
            network: Network::Testnet,
            magic: [0x0b, 0x11, 0x09, 0x07],
            default_port: 18333,
            genesis_block: bitcoin::constants::genesis_block(Network::Testnet),
            dns_seeds: vec![
                "testnet-seed.bitcoin.jonasschnelli.ch",
                "seed.tbtc.petertodd.net",
                "seed.testnet.bitcoin.sprovoost.nl",
                "testnet-seed.bluematt.me",
            ],
            pow_limit: pow_limit_testnet(),
            pow_target_timespan: 14 * 24 * 60 * 60,
            pow_target_spacing: 10 * 60,
            subsidy_halving_interval: 210_000,
            bip16_time: 1333238400, // April 1, 2012 — BIP 16 P2SH activation
            bip34_height: 21111,
            bip65_height: 581885,
            csv_height: 770_112,
            bip66_height: 330776,
            segwit_height: 834624,
            taproot_height: 2_011_000, // Testnet3 taproot activation (BIP9, ~Oct 2021)
            assume_valid: None,
            // Bitcoin Core master nMinimumChainWork for testnet3
            min_chain_work: chain_work_from_hex(
                "0000000000000000000000000000000000000000000017dde1c649f3708d14b6",
            ),
            pow_no_retargeting: false,
            pow_allow_min_difficulty_blocks: true,
            coinbase_maturity: 100,
            max_block_weight: 4_000_000,
            max_datacarrier_size: 83,
            datacarrier: true,
            permit_bare_multisig: false,
            reject_parasites: true,
            reject_tokens: true,
            // BIP-110 RDTS: unconfigured on this network (override with --bip110height).
            bip110_activation_height: None,
            bip110_deployment: None,
            signet_challenge: None,
        }
    }

    pub fn testnet4() -> Self {
        ConsensusParams {
            network: Network::Testnet4,
            magic: [0x1c, 0x16, 0x3f, 0x28],
            default_port: 48333,
            genesis_block: bitcoin::constants::genesis_block(Network::Testnet4),
            dns_seeds: vec![
                "seed.testnet4.bitcoin.sprovoost.nl",
                "seed.testnet4.wiz.biz",
            ],
            pow_limit: pow_limit_testnet(),
            pow_target_timespan: 14 * 24 * 60 * 60,
            pow_target_spacing: 10 * 60,
            subsidy_halving_interval: 210_000,
            bip16_time: 1333238400, // April 1, 2012
            bip34_height: 1,
            bip65_height: 1,
            csv_height: 1,
            bip66_height: 1,
            segwit_height: 1,
            taproot_height: 1,
            assume_valid: None,
            // Bitcoin Core master nMinimumChainWork for testnet4
            min_chain_work: chain_work_from_hex(
                "0000000000000000000000000000000000000000000009a0fe15d0177d086304",
            ),
            pow_no_retargeting: false,
            pow_allow_min_difficulty_blocks: true,
            coinbase_maturity: 100,
            max_block_weight: 4_000_000,
            max_datacarrier_size: 83,
            datacarrier: true,
            permit_bare_multisig: false,
            reject_parasites: true,
            reject_tokens: true,
            // BIP-110 RDTS: unconfigured on this network (override with --bip110height).
            bip110_activation_height: None,
            bip110_deployment: None,
            signet_challenge: None,
        }
    }

    pub fn regtest() -> Self {
        ConsensusParams {
            network: Network::Regtest,
            magic: [0xfa, 0xbf, 0xb5, 0xda],
            default_port: 18444,
            genesis_block: bitcoin::constants::genesis_block(Network::Regtest),
            dns_seeds: vec![],
            pow_limit: pow_limit_regtest(),
            pow_target_timespan: 14 * 24 * 60 * 60,
            pow_target_spacing: 10 * 60,
            subsidy_halving_interval: 150,
            bip16_time: 0,   // Always active on regtest
            bip34_height: 1, // Active from block 1 (matches modern Bitcoin Core regtest)
            bip65_height: 1,
            csv_height: 1,
            bip66_height: 1,
            segwit_height: 0,
            taproot_height: 0, // Active from genesis on regtest
            assume_valid: None,
            min_chain_work: [0u8; 32], // no minimum on regtest
            pow_no_retargeting: true,
            pow_allow_min_difficulty_blocks: true,
            coinbase_maturity: 100,
            max_block_weight: 4_000_000,
            max_datacarrier_size: 83,
            datacarrier: true,
            permit_bare_multisig: false,
            reject_parasites: true,
            reject_tokens: true,
            // BIP-110 RDTS: unconfigured on this network (override with --bip110height).
            bip110_activation_height: None,
            bip110_deployment: None,
            signet_challenge: None,
        }
    }

    /// Create Signet parameters (BIP 325).
    pub fn signet() -> Self {
        // Default signet challenge script (from Bitcoin Core)
        let challenge = hex::decode(
            "512103ad5e0edad18cb1f0fc0d28a3d4f1f3e445640337489abb10404f2d1e086be430210359ef5021964fe22d6f8e05b2463c9540ce96883fe3b278760f048f5189f2e6c452ae"
        )
        .expect("hardcoded signet challenge hex is valid");

        ConsensusParams {
            network: Network::Signet,
            magic: [0x0a, 0x03, 0xcf, 0x40],
            default_port: 38333,
            genesis_block: bitcoin::constants::genesis_block(Network::Signet),
            dns_seeds: vec![
                "seed.signet.bitcoin.sprovoost.nl",
                "seed.signet.achow101.com",
            ],
            pow_limit: pow_limit_signet(),
            pow_target_timespan: 14 * 24 * 60 * 60,
            pow_target_spacing: 10 * 60,
            subsidy_halving_interval: 210_000,
            bip16_time: 0, // Always active on signet
            bip34_height: 1,
            bip65_height: 1,
            csv_height: 1,
            bip66_height: 1,
            segwit_height: 1,
            taproot_height: 1,
            assume_valid: None,
            // No minimum on signet: the challenge script may be a custom
            // (non-default) network whose chain work we can't know ahead.
            min_chain_work: [0u8; 32],
            pow_no_retargeting: false,
            pow_allow_min_difficulty_blocks: true,
            coinbase_maturity: 100,
            max_block_weight: 4_000_000,
            max_datacarrier_size: 83,
            datacarrier: true,
            permit_bare_multisig: false,
            reject_parasites: true,
            reject_tokens: true,
            // BIP-110 RDTS: unconfigured on this network (override with --bip110height).
            bip110_activation_height: None,
            bip110_deployment: None,
            signet_challenge: Some(ScriptBuf::from_bytes(challenge)),
        }
    }

    /// BIP 90 buried-deployment activation check. Validation uses hardcoded
    /// per-network heights rather than the BIP 9/8 versionbits state machine
    /// (which is retained only for `getblocktemplate` signaling and the
    /// dashboard — it is NOT consulted on the consensus-critical path).
    pub fn deployment_active(&self, name: &str, height: u32) -> bool {
        match name {
            "bip34" => height >= self.bip34_height,
            "bip66" => height >= self.bip66_height,
            "bip65" | "cltv" => height >= self.bip65_height,
            "csv" => height >= self.csv_height,
            "segwit" => height >= self.segwit_height,
            "taproot" => height >= self.taproot_height,
            _ => false,
        }
    }

    /// Number of blocks per difficulty adjustment period.
    pub fn difficulty_adjustment_interval(&self) -> u32 {
        (self.pow_target_timespan / self.pow_target_spacing) as u32
    }

    /// Calculate the block subsidy at a given height.
    pub fn block_subsidy(&self, height: u32) -> u64 {
        let halvings = height / self.subsidy_halving_interval;
        if halvings >= 64 {
            return 0;
        }
        // Initial subsidy is 50 BTC = 5_000_000_000 satoshis
        50_0000_0000u64 >> halvings
    }
}

/// Parse a hardcoded 64-char hex string into a big-endian 32-byte chain work.
fn chain_work_from_hex(hex_str: &str) -> [u8; 32] {
    let bytes = hex::decode(hex_str).expect("hardcoded chain work hex is valid");
    let mut work = [0u8; 32];
    work.copy_from_slice(&bytes);
    work
}

/// Mainnet PoW limit (== Bitcoin Core `powLimit`): the difficulty-1 target
/// 00000000ffff0000000000000000000000000000000000000000000000000000.
/// (Previously this was 0x00000000ffff…ffff = 2^224-1, which is far too easy —
/// it made the header target check lenient and would have mis-capped difficulty
/// retargets near the limit on testnet. Compact form is 0x1d00ffff.)
fn pow_limit_mainnet() -> [u8; 32] {
    let mut limit = [0u8; 32];
    // Big-endian: 0xFFFF at bytes 4–5, everything else zero.
    limit[4] = 0xff;
    limit[5] = 0xff;
    limit
}

/// Testnet PoW limit: same as mainnet — the difficulty-1 target.
fn pow_limit_testnet() -> [u8; 32] {
    pow_limit_mainnet()
}

/// Signet PoW limit: 00000377ae000000000000000000000000000000000000000000000000000000
/// Signet uses signed blocks (BIP 325), not real PoW. This matches Bitcoin Core's signet limit.
fn pow_limit_signet() -> [u8; 32] {
    let mut limit = [0u8; 32];
    limit[0] = 0x00;
    limit[1] = 0x00;
    limit[2] = 0x03;
    limit[3] = 0x77;
    limit[4] = 0xae;
    // rest is zeros
    limit
}

/// Regtest PoW limit: 7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
fn pow_limit_regtest() -> [u8; 32] {
    let mut limit = [0xff; 32];
    limit[0] = 0x7f;
    limit
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn test_mainnet_params() {
        let params = ConsensusParams::mainnet();
        assert_eq!(params.default_port, 8333);
        assert_eq!(params.magic, [0xf9, 0xbe, 0xb4, 0xd9]);
        assert_eq!(params.difficulty_adjustment_interval(), 2016);
        assert_eq!(params.subsidy_halving_interval, 210_000);
    }

    #[test]
    fn test_block_subsidy() {
        let params = ConsensusParams::mainnet();
        assert_eq!(params.block_subsidy(0), 50_0000_0000);
        assert_eq!(params.block_subsidy(209_999), 50_0000_0000);
        assert_eq!(params.block_subsidy(210_000), 25_0000_0000);
        assert_eq!(params.block_subsidy(420_000), 12_5000_0000);
        assert_eq!(params.block_subsidy(630_000), 6_2500_0000);
        assert_eq!(params.block_subsidy(840_000), 3_1250_0000);
        // After 64 halvings, subsidy is 0
        assert_eq!(params.block_subsidy(210_000 * 64), 0);
    }

    #[test]
    fn test_regtest_params() {
        let params = ConsensusParams::regtest();
        assert_eq!(params.default_port, 18444);
        assert!(params.pow_no_retargeting);
        assert!(params.pow_allow_min_difficulty_blocks);
        assert_eq!(params.subsidy_halving_interval, 150);
    }

    #[test]
    fn test_deployment_active() {
        let params = ConsensusParams::mainnet();

        // CSV (BIP 68/112/113) activates at mainnet height 419_328.
        assert!(!params.deployment_active("csv", 419_327));
        assert!(params.deployment_active("csv", 419_328));
        assert!(params.deployment_active("csv", 500_000));

        // SegWit activates at 481_824.
        assert!(!params.deployment_active("segwit", 481_823));
        assert!(params.deployment_active("segwit", 481_824));

        // Taproot activates at 709_632.
        assert!(!params.deployment_active("taproot", 709_631));
        assert!(params.deployment_active("taproot", 709_632));

        // Unknown deployment names are never active.
        assert!(!params.deployment_active("nonexistent", u32::MAX));
    }

    #[test]
    fn test_bip110_deployment_config() {
        // Mainnet drives activation from signaling (a deployment, no fixed height).
        let mainnet = ConsensusParams::mainnet();
        assert_eq!(mainnet.bip110_activation_height, None);
        let dep = mainnet
            .bip110_deployment
            .expect("mainnet has an RDTS deployment");
        assert_eq!(dep.bit, 4);
        assert_eq!(dep.threshold, 1109);
        assert_eq!(dep.lock_in_floor_height, 963_648);
        assert_eq!(dep.active_duration, 52_416);

        // Other networks have neither a fixed override nor a deployment by default.
        for params in [
            ConsensusParams::regtest(),
            ConsensusParams::testnet(),
            ConsensusParams::signet(),
        ] {
            assert_eq!(params.bip110_activation_height, None);
            assert!(params.bip110_deployment.is_none());
        }
    }

    #[test]
    fn test_relay_policy_defaults() {
        // Knots-style relay-policy knobs: datacarrier on (Core & Knots
        // default), bare multisig off (Knots default), parasite rejection on
        // (Knots default), token rejection on (stricter than Knots, operator
        // preference).
        for params in [
            ConsensusParams::mainnet(),
            ConsensusParams::testnet(),
            ConsensusParams::testnet4(),
            ConsensusParams::regtest(),
            ConsensusParams::signet(),
        ] {
            assert!(params.datacarrier);
            assert!(!params.permit_bare_multisig);
            assert!(params.reject_parasites);
            assert!(params.reject_tokens);
        }
    }

    #[test]
    fn test_genesis_blocks() {
        let mainnet = ConsensusParams::mainnet();
        let _testnet = ConsensusParams::testnet();
        let regtest = ConsensusParams::regtest();

        // Mainnet genesis hash
        let mainnet_hash = mainnet.genesis_block.block_hash().to_string();
        assert_eq!(
            mainnet_hash,
            "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
        );

        // Genesis blocks should be different per network
        assert_ne!(
            mainnet.genesis_block.block_hash(),
            regtest.genesis_block.block_hash()
        );
    }
}
