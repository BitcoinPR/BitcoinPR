//! Fast hasher for outpoint-keyed maps (Core #30442 analogue).
//!
//! Outpoint keys — `bitcoin::OutPoint` and the serialized 36-byte
//! `[txid ‖ vout]` form — begin with 32 bytes of SHA256d output, which is
//! already uniformly distributed. Running DoS-resistant SipHash-1-3 (the
//! `std` default) over those keys buys nothing: an attacker who wanted to
//! groom bucket collisions would have to grind block/tx hashes, which is
//! exactly the proof-of-work they cannot afford. A trivial fold of the key
//! bytes is dramatically cheaper and every UTXO `get()` pays the hasher up
//! to three times (write buffer, read cache, intra-block map).
//!
//! A per-process random seed is mixed in anyway (free at construction time)
//! so bucket order is not predictable across runs.

use std::hash::{BuildHasher, Hasher};
use std::sync::OnceLock;

/// Per-process random seed, derived from `RandomState`'s per-process keys.
fn process_seed() -> u64 {
    static SEED: OnceLock<u64> = OnceLock::new();
    *SEED.get_or_init(|| {
        std::collections::hash_map::RandomState::new()
            .build_hasher()
            .finish()
    })
}

/// Hasher that folds input bytes with rotate-xor instead of SipHash.
///
/// Sound only for keys that are (or begin with) cryptographic-hash output —
/// outpoints, txids, block hashes. Do not use for attacker-chosen strings.
#[derive(Clone, Copy)]
pub struct FastOutpointHasher {
    hash: u64,
}

impl Hasher for FastOutpointHasher {
    #[inline]
    fn finish(&self) -> u64 {
        self.hash
    }

    #[inline]
    fn write(&mut self, bytes: &[u8]) {
        // Fold 8-byte chunks (a 36-byte outpoint key is 5 chunks). The
        // rotate keeps the trailing vout bytes from cancelling against the
        // txid bytes, so outputs of one tx land in different buckets.
        for chunk in bytes.chunks(8) {
            let mut buf = [0u8; 8];
            buf[..chunk.len()].copy_from_slice(chunk);
            self.hash = self.hash.rotate_left(29) ^ u64::from_le_bytes(buf);
        }
    }

    #[inline]
    fn write_u8(&mut self, i: u8) {
        self.hash = self.hash.rotate_left(29) ^ i as u64;
    }

    #[inline]
    fn write_u32(&mut self, i: u32) {
        // OutPoint's derived Hash feeds vout through here.
        self.hash = self.hash.rotate_left(29) ^ i as u64;
    }

    #[inline]
    fn write_u64(&mut self, i: u64) {
        self.hash = self.hash.rotate_left(29) ^ i;
    }

    #[inline]
    fn write_usize(&mut self, _i: usize) {
        // Length prefixes carry no entropy for fixed-size keys — skip them.
    }
}

/// `BuildHasher` for [`FastOutpointHasher`], seeding each hasher with the
/// per-process random seed.
#[derive(Clone, Copy, Default)]
pub struct FastOutpointBuildHasher;

impl BuildHasher for FastOutpointBuildHasher {
    type Hasher = FastOutpointHasher;

    #[inline]
    fn build_hasher(&self) -> FastOutpointHasher {
        FastOutpointHasher {
            hash: process_seed(),
        }
    }
}

/// `HashMap` keyed by outpoints (or other hash-derived keys) using the fast hasher.
pub type FastHashMap<K, V> = std::collections::HashMap<K, V, FastOutpointBuildHasher>;
/// `HashSet` keyed by outpoints (or other hash-derived keys) using the fast hasher.
pub type FastHashSet<K> = std::collections::HashSet<K, FastOutpointBuildHasher>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn outputs_of_same_tx_hash_differently() {
        let b = FastOutpointBuildHasher;
        let mut key_a = [0xabu8; 36];
        let mut key_b = [0xabu8; 36];
        key_a[32..].copy_from_slice(&0u32.to_le_bytes());
        key_b[32..].copy_from_slice(&1u32.to_le_bytes());
        let h = |k: &[u8; 36]| {
            let mut hasher = b.build_hasher();
            hasher.write(k);
            hasher.finish()
        };
        assert_ne!(h(&key_a), h(&key_b));
    }

    #[test]
    fn hashmap_roundtrip() {
        let mut m: FastHashMap<[u8; 36], u32> = FastHashMap::default();
        for i in 0..1000u32 {
            let mut k = [0u8; 36];
            k[..4].copy_from_slice(&i.to_le_bytes());
            k[32..].copy_from_slice(&i.to_le_bytes());
            m.insert(k, i);
        }
        for i in 0..1000u32 {
            let mut k = [0u8; 36];
            k[..4].copy_from_slice(&i.to_le_bytes());
            k[32..].copy_from_slice(&i.to_le_bytes());
            assert_eq!(m.get(&k), Some(&i));
        }
    }
}
