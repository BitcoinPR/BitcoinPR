//! BIP 37 connection bloom filter.
//!
//! rust-bitcoin provides the wire types (`FilterLoad`, `FilterAdd`, `BloomFlags`)
//! but no actual bloom-filter matching engine, so we implement BIP 37 here.
//! This is only used to serve filtered connections to peers when the operator
//! explicitly enables `--peerbloomfilters` (see BIP 111 / NODE_BLOOM).

use bitcoin::hashes::Hash;
use bitcoin::p2p::message_bloom::{BloomFlags, FilterLoad};
use bitcoin::{OutPoint, Script, Transaction};

/// Maximum bloom filter size in bytes (BIP 37).
pub const MAX_BLOOM_FILTER_SIZE: usize = 36_000;
/// Maximum number of hash functions (BIP 37).
pub const MAX_HASH_FUNCS: u32 = 50;

/// A BIP 37 connection bloom filter loaded from a peer's `filterload` message.
pub struct BloomFilter {
    data: Vec<u8>,
    hash_funcs: u32,
    tweak: u32,
    flags: BloomFlags,
}

/// MurmurHash3 (x86_32) as specified for BIP 37.
///
/// This is the standard MurmurHash3 32-bit variant; see the reference
/// implementation in Bitcoin Core's `hash.cpp` / the smhasher project.
fn murmur3_32(seed: u32, data: &[u8]) -> u32 {
    const C1: u32 = 0xcc9e_2d51;
    const C2: u32 = 0x1b87_3593;

    let mut h1 = seed;
    let nblocks = data.len() / 4;

    // body
    for i in 0..nblocks {
        let off = i * 4;
        let mut k1 = u32::from_le_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]]);
        k1 = k1.wrapping_mul(C1);
        k1 = k1.rotate_left(15);
        k1 = k1.wrapping_mul(C2);

        h1 ^= k1;
        h1 = h1.rotate_left(13);
        h1 = h1.wrapping_mul(5).wrapping_add(0xe654_6b64);
    }

    // tail
    let tail = &data[nblocks * 4..];
    let mut k1: u32 = 0;
    if tail.len() >= 3 {
        k1 ^= (tail[2] as u32) << 16;
    }
    if tail.len() >= 2 {
        k1 ^= (tail[1] as u32) << 8;
    }
    if !tail.is_empty() {
        k1 ^= tail[0] as u32;
        k1 = k1.wrapping_mul(C1);
        k1 = k1.rotate_left(15);
        k1 = k1.wrapping_mul(C2);
        h1 ^= k1;
    }

    // finalization
    h1 ^= data.len() as u32;
    h1 ^= h1 >> 16;
    h1 = h1.wrapping_mul(0x85eb_ca6b);
    h1 ^= h1 >> 13;
    h1 = h1.wrapping_mul(0xc2b2_ae35);
    h1 ^= h1 >> 16;

    h1
}

impl BloomFilter {
    /// Build a filter from a peer's `filterload`, clamping to BIP 37 limits.
    pub fn from_filter_load(fl: &FilterLoad) -> Self {
        let mut data = fl.filter.clone();
        if data.len() > MAX_BLOOM_FILTER_SIZE {
            data.truncate(MAX_BLOOM_FILTER_SIZE);
        }
        let hash_funcs = fl.hash_funcs.min(MAX_HASH_FUNCS);
        BloomFilter {
            data,
            hash_funcs,
            tweak: fl.tweak,
            flags: fl.flags,
        }
    }

    /// True if the filter holds no data (zero length or all-zero bytes).
    pub fn is_empty(&self) -> bool {
        self.data.is_empty() || self.data.iter().all(|&b| b == 0)
    }

    /// True if every bit is set (an all-0xff filter matches everything).
    pub fn is_full(&self) -> bool {
        !self.data.is_empty() && self.data.iter().all(|&b| b == 0xff)
    }

    /// BIP 37 hash: MurmurHash3 with a per-function seed, modulo the bit count.
    fn hash(&self, n_hash: u32, data: &[u8]) -> u32 {
        let seed = n_hash.wrapping_mul(0xFBA4_C795).wrapping_add(self.tweak);
        murmur3_32(seed, data) % (self.data.len() as u32 * 8)
    }

    /// Test whether `data` is (probably) in the filter.
    pub fn contains(&self, data: &[u8]) -> bool {
        // A zero-size filter matches everything (avoids divide-by-zero, CVE-2013-5700).
        if self.data.is_empty() {
            return true;
        }
        for i in 0..self.hash_funcs {
            let idx = self.hash(i, data);
            if self.data[(idx >> 3) as usize] & (1 << (7 & idx)) == 0 {
                return false;
            }
        }
        true
    }

    /// BIP 37 `filteradd`: insert a data element into the filter.
    pub fn insert(&mut self, data: &[u8]) {
        if self.data.is_empty() {
            return;
        }
        for i in 0..self.hash_funcs {
            let idx = self.hash(i, data);
            self.data[(idx >> 3) as usize] |= 1 << (7 & idx);
        }
    }

    /// Serialize an outpoint as the 36 bytes BIP 37 matches against:
    /// txid (32 bytes, internal order) followed by the little-endian vout.
    fn outpoint_bytes(outpoint: &OutPoint) -> [u8; 36] {
        let mut buf = [0u8; 36];
        buf[..32].copy_from_slice(&outpoint.txid.to_byte_array());
        buf[32..].copy_from_slice(&outpoint.vout.to_le_bytes());
        buf
    }

    /// True if any data-push in `script` is contained in the filter.
    fn script_matches(&self, script: &Script) -> bool {
        for instr in script.instructions() {
            if let Ok(instr) = instr {
                if let Some(push) = instr.push_bytes() {
                    let bytes = push.as_bytes();
                    if !bytes.is_empty() && self.contains(bytes) {
                        return true;
                    }
                }
            } else {
                break;
            }
        }
        false
    }

    /// Read-only BIP 37 match test (does not update the filter). Used to serve
    /// `mempool` (BIP 35) without taking a mutable borrow.
    pub fn matches_tx(&self, tx: &Transaction) -> bool {
        if self.data.is_empty() {
            return true;
        }
        if self.contains(&tx.compute_txid().to_byte_array()) {
            return true;
        }
        for txout in &tx.output {
            if self.script_matches(&txout.script_pubkey) {
                return true;
            }
        }
        for txin in &tx.input {
            if self.contains(&Self::outpoint_bytes(&txin.previous_output)) {
                return true;
            }
            if self.script_matches(&txin.script_sig) {
                return true;
            }
        }
        false
    }

    /// BIP 37 matching with update: returns true if `tx` matches the filter.
    /// Matched outputs cause their outpoint to be inserted according to the
    /// filter's `BloomFlags` (UPDATE_ALL / UPDATE_P2PUBKEY_ONLY).
    pub fn is_relevant_and_update(&mut self, tx: &Transaction) -> bool {
        // A zero-size filter matches everything.
        if self.data.is_empty() {
            return true;
        }

        let mut found = false;
        let txid = tx.compute_txid();
        if self.contains(&txid.to_byte_array()) {
            found = true;
        }

        for (i, txout) in tx.output.iter().enumerate() {
            if self.script_matches(&txout.script_pubkey) {
                found = true;
                let update = match self.flags {
                    BloomFlags::All => true,
                    BloomFlags::PubkeyOnly => {
                        txout.script_pubkey.is_p2pk() || txout.script_pubkey.is_multisig()
                    }
                    BloomFlags::None => false,
                };
                if update {
                    let outpoint = OutPoint {
                        txid,
                        vout: i as u32,
                    };
                    self.insert(&Self::outpoint_bytes(&outpoint));
                }
            }
        }

        if found {
            return true;
        }

        for txin in &tx.input {
            if self.contains(&Self::outpoint_bytes(&txin.previous_output)) {
                return true;
            }
            if self.script_matches(&txin.script_sig) {
                return true;
            }
        }

        false
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use bitcoin::p2p::message_bloom::{BloomFlags, FilterLoad};

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    // Test vector from Bitcoin Core's bloom_tests (bloom_create_insert_serialize):
    // a 3-byte filter with 5 hash functions and tweak 0, after inserting three
    // elements, must serialize its data to 614e9b.
    #[test]
    fn bip37_known_vector_no_tweak() {
        let fl = FilterLoad {
            filter: vec![0u8; 3],
            hash_funcs: 5,
            tweak: 0,
            flags: BloomFlags::All,
        };
        let mut filter = BloomFilter::from_filter_load(&fl);
        filter.insert(&hex("99108ad8ed9bb6274d3980bab5a85c048f0950c8"));
        filter.insert(&hex("b5a2c786d9ef4658287ced5914b37a1b4aa32eee"));
        filter.insert(&hex("b9300670b4c5366e95b2699e8b18bc75e5f729c5"));
        assert_eq!(filter.data, hex("614e9b"));
    }

    // Same vector but with tweak 2147483649 (0x80000001) -> data ce4299.
    #[test]
    fn bip37_known_vector_with_tweak() {
        let fl = FilterLoad {
            filter: vec![0u8; 3],
            hash_funcs: 5,
            tweak: 2147483649,
            flags: BloomFlags::All,
        };
        let mut filter = BloomFilter::from_filter_load(&fl);
        filter.insert(&hex("99108ad8ed9bb6274d3980bab5a85c048f0950c8"));
        filter.insert(&hex("b5a2c786d9ef4658287ced5914b37a1b4aa32eee"));
        filter.insert(&hex("b9300670b4c5366e95b2699e8b18bc75e5f729c5"));
        assert_eq!(filter.data, hex("ce4299"));
    }

    #[test]
    fn contains_inserted_and_not_others() {
        let fl = FilterLoad {
            filter: vec![0u8; 3],
            hash_funcs: 5,
            tweak: 0,
            flags: BloomFlags::All,
        };
        let mut filter = BloomFilter::from_filter_load(&fl);
        let elem = hex("99108ad8ed9bb6274d3980bab5a85c048f0950c8");
        filter.insert(&elem);
        assert!(filter.contains(&elem));
        // One bit different in the first byte must not be contained.
        assert!(!filter.contains(&hex("19108ad8ed9bb6274d3980bab5a85c048f0950c8")));
    }

    #[test]
    fn murmur3_is_deterministic() {
        let a = murmur3_32(0, b"hello world");
        let b = murmur3_32(0, b"hello world");
        assert_eq!(a, b);
        assert_ne!(murmur3_32(0, b"hello world"), murmur3_32(1, b"hello world"));
    }

    #[test]
    fn is_relevant_matches_txid() {
        use bitcoin::consensus::deserialize;
        // A minimal valid coinbase-like transaction.
        let raw = hex(
            "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0100ffffffff0100f2052a01000000434104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac00000000",
        );
        let tx: Transaction = deserialize(&raw).unwrap();
        let txid = tx.compute_txid();

        let fl = FilterLoad {
            filter: vec![0u8; 16],
            hash_funcs: 5,
            tweak: 0,
            flags: BloomFlags::All,
        };
        let mut filter = BloomFilter::from_filter_load(&fl);
        // Before inserting the txid, an empty (all-zero) filter should not match.
        assert!(!filter.matches_tx(&tx));
        filter.insert(&txid.to_byte_array());
        assert!(filter.is_relevant_and_update(&tx));
        assert!(filter.matches_tx(&tx));
    }
}
