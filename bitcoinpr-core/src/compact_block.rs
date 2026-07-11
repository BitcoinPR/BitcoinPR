//! BIP 152 — Compact Block Relay
//!
//! Compact blocks allow nodes to send a compact representation of a block
//! using short transaction IDs, allowing the receiving node to reconstruct
//! the full block from its mempool.

use bitcoin::hashes::{sha256d, Hash};
use bitcoin::{Block, BlockHash, Transaction, Txid};

/// SipHash key derived from the block header nonce and header hash.
#[derive(Debug, Clone, Copy)]
pub struct ShortIdKey {
    pub k0: u64,
    pub k1: u64,
}

impl ShortIdKey {
    /// Derive the SipHash key from a block header hash and a nonce.
    /// Per BIP 152: SHA256(SHA256(header || nonce))[0..8] = k0, [8..16] = k1
    pub fn from_header_nonce(header_hash: &BlockHash, nonce: u64) -> Self {
        let mut data = Vec::with_capacity(80 + 8);
        // Use the block hash bytes (32 bytes) as a stand-in for the 80-byte header
        // In a full implementation we'd serialize the full header
        data.extend_from_slice(AsRef::<[u8; 32]>::as_ref(header_hash));
        data.extend_from_slice(&nonce.to_le_bytes());

        let hash = sha256d::Hash::hash(&data);
        let hash_bytes = AsRef::<[u8]>::as_ref(&hash);

        let k0 = u64::from_le_bytes(hash_bytes[0..8].try_into().expect("fixed-size slice"));
        let k1 = u64::from_le_bytes(hash_bytes[8..16].try_into().expect("fixed-size slice"));

        ShortIdKey { k0, k1 }
    }
}

/// A 6-byte short transaction ID used in compact blocks.
pub type ShortId = [u8; 6];

/// Compute the short ID for a transaction.
/// Per BIP 152: SipHash-2-4(txid) using the compact block key, then take first 6 bytes.
pub fn short_id(key: &ShortIdKey, txid: &Txid) -> ShortId {
    let hash = siphash_2_4(key.k0, key.k1, AsRef::<[u8; 32]>::as_ref(txid));
    let bytes = hash.to_le_bytes();
    let mut result = [0u8; 6];
    result.copy_from_slice(&bytes[0..6]);
    result
}

/// SipHash-2-4 implementation (simplified for BIP 152 short IDs).
fn siphash_2_4(k0: u64, k1: u64, data: &[u8]) -> u64 {
    let mut v0: u64 = 0x736f6d6570736575 ^ k0;
    let mut v1: u64 = 0x646f72616e646f6d ^ k1;
    let mut v2: u64 = 0x6c7967656e657261 ^ k0;
    let mut v3: u64 = 0x7465646279746573 ^ k1;

    let len = data.len();
    let blocks = len / 8;

    for i in 0..blocks {
        let m = u64::from_le_bytes(
            data[i * 8..(i + 1) * 8]
                .try_into()
                .expect("fixed-size slice"),
        );
        v3 ^= m;
        sipround(&mut v0, &mut v1, &mut v2, &mut v3);
        sipround(&mut v0, &mut v1, &mut v2, &mut v3);
        v0 ^= m;
    }

    let mut last = (len as u64) << 56;
    let remaining = &data[blocks * 8..];
    for (i, &byte) in remaining.iter().enumerate() {
        last |= (byte as u64) << (i * 8);
    }

    v3 ^= last;
    sipround(&mut v0, &mut v1, &mut v2, &mut v3);
    sipround(&mut v0, &mut v1, &mut v2, &mut v3);
    v0 ^= last;

    v2 ^= 0xff;
    sipround(&mut v0, &mut v1, &mut v2, &mut v3);
    sipround(&mut v0, &mut v1, &mut v2, &mut v3);
    sipround(&mut v0, &mut v1, &mut v2, &mut v3);
    sipround(&mut v0, &mut v1, &mut v2, &mut v3);

    v0 ^ v1 ^ v2 ^ v3
}

#[inline]
fn sipround(v0: &mut u64, v1: &mut u64, v2: &mut u64, v3: &mut u64) {
    *v0 = v0.wrapping_add(*v1);
    *v1 = v1.rotate_left(13);
    *v1 ^= *v0;
    *v0 = v0.rotate_left(32);
    *v2 = v2.wrapping_add(*v3);
    *v3 = v3.rotate_left(16);
    *v3 ^= *v2;
    *v0 = v0.wrapping_add(*v3);
    *v3 = v3.rotate_left(21);
    *v3 ^= *v0;
    *v2 = v2.wrapping_add(*v1);
    *v1 = v1.rotate_left(17);
    *v1 ^= *v2;
    *v2 = v2.rotate_left(32);
}

/// A compact block as defined in BIP 152.
#[derive(Debug, Clone)]
pub struct CompactBlock {
    /// The block header.
    pub header: bitcoin::block::Header,
    /// Nonce used for short ID calculation.
    pub nonce: u64,
    /// Short transaction IDs (all non-prefilled txs).
    pub short_ids: Vec<ShortId>,
    /// Pre-filled transactions (always includes the coinbase).
    pub prefilled_txs: Vec<PrefilledTx>,
}

/// A pre-filled transaction in a compact block.
#[derive(Debug, Clone)]
pub struct PrefilledTx {
    /// Differential index (offset from previous prefilled tx index + 1).
    pub index: u16,
    /// The full transaction.
    pub tx: Transaction,
}

/// A request for specific transactions missing from a compact block.
#[derive(Debug, Clone)]
pub struct BlockTxnRequest {
    /// Block hash.
    pub block_hash: BlockHash,
    /// Indices of requested transactions.
    pub indexes: Vec<u32>,
}

/// Response with the requested transactions.
#[derive(Debug, Clone)]
pub struct BlockTxnResponse {
    /// Block hash.
    pub block_hash: BlockHash,
    /// The requested transactions.
    pub transactions: Vec<Transaction>,
}

impl CompactBlock {
    /// Create a compact block from a full block.
    pub fn from_block(block: &Block, nonce: u64) -> Self {
        let header_hash = block.block_hash();
        let key = ShortIdKey::from_header_nonce(&header_hash, nonce);

        let mut short_ids = Vec::with_capacity(block.txdata.len().saturating_sub(1));
        for tx in block.txdata.iter().skip(1) {
            short_ids.push(short_id(&key, &tx.compute_txid()));
        }

        // Always prefill the coinbase
        let prefilled_txs = vec![PrefilledTx {
            index: 0,
            tx: block.txdata[0].clone(),
        }];

        CompactBlock {
            header: block.header,
            nonce,
            short_ids,
            prefilled_txs,
        }
    }

    /// Get the SipHash key for this compact block.
    pub fn short_id_key(&self) -> ShortIdKey {
        let header_hash = self.header.block_hash();
        ShortIdKey::from_header_nonce(&header_hash, self.nonce)
    }

    /// Try to reconstruct the full block from this compact block and a mempool.
    /// Returns (block, missing_indices) where missing_indices lists positions
    /// of transactions we couldn't find in the mempool.
    pub fn reconstruct(&self, mempool_txs: &[Transaction]) -> (Vec<Option<Transaction>>, Vec<u32>) {
        let key = self.short_id_key();

        // Build a map of short_id -> transaction from the mempool
        let mut id_map: std::collections::HashMap<ShortId, &Transaction> =
            std::collections::HashMap::new();
        for tx in mempool_txs {
            let sid = short_id(&key, &tx.compute_txid());
            id_map.insert(sid, tx);
        }

        let total_txs = self.prefilled_txs.len() + self.short_ids.len();
        let mut result: Vec<Option<Transaction>> = vec![None; total_txs];
        let mut missing = Vec::new();

        // Place prefilled transactions
        let mut prefill_offset = 0u32;
        for pf in &self.prefilled_txs {
            let abs_index = prefill_offset + pf.index as u32;
            if (abs_index as usize) < result.len() {
                result[abs_index as usize] = Some(pf.tx.clone());
            }
            prefill_offset = abs_index + 1;
        }

        // Fill in from short IDs
        let mut short_id_idx = 0;
        for (i, slot) in result.iter_mut().enumerate() {
            if slot.is_some() {
                continue; // Already filled by prefilled tx
            }
            if short_id_idx < self.short_ids.len() {
                let sid = &self.short_ids[short_id_idx];
                if let Some(tx) = id_map.get(sid) {
                    *slot = Some((*tx).clone());
                } else {
                    missing.push(i as u32);
                }
                short_id_idx += 1;
            }
        }

        (result, missing)
    }

    /// Fill in missing transactions from a blocktxn response.
    pub fn fill_missing(
        txs: &mut [Option<Transaction>],
        missing_indices: &[u32],
        response: &BlockTxnResponse,
    ) -> bool {
        if response.transactions.len() != missing_indices.len() {
            return false;
        }
        for (i, &idx) in missing_indices.iter().enumerate() {
            if (idx as usize) < txs.len() {
                txs[idx as usize] = Some(response.transactions[i].clone());
            } else {
                return false;
            }
        }
        true
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use bitcoin::constants::genesis_block;
    use bitcoin::Network;

    #[test]
    fn test_short_id_key_derivation() {
        let genesis = genesis_block(Network::Bitcoin);
        let hash = genesis.block_hash();
        let key = ShortIdKey::from_header_nonce(&hash, 0);
        // Just verify it produces deterministic results
        let key2 = ShortIdKey::from_header_nonce(&hash, 0);
        assert_eq!(key.k0, key2.k0);
        assert_eq!(key.k1, key2.k1);

        // Different nonce should produce different key
        let key3 = ShortIdKey::from_header_nonce(&hash, 1);
        assert_ne!(key.k0, key3.k0);
    }

    #[test]
    fn test_compact_block_from_genesis() {
        let genesis = genesis_block(Network::Bitcoin);
        let compact = CompactBlock::from_block(&genesis, 42);

        // Genesis has 1 tx (coinbase), so short_ids should be empty
        assert_eq!(compact.short_ids.len(), 0);
        assert_eq!(compact.prefilled_txs.len(), 1);
        assert_eq!(compact.prefilled_txs[0].index, 0);
        assert_eq!(compact.nonce, 42);
    }

    #[test]
    fn test_short_id_deterministic() {
        let genesis = genesis_block(Network::Bitcoin);
        let hash = genesis.block_hash();
        let key = ShortIdKey::from_header_nonce(&hash, 12345);
        let txid = genesis.txdata[0].compute_txid();

        let id1 = short_id(&key, &txid);
        let id2 = short_id(&key, &txid);
        assert_eq!(id1, id2);
    }

    #[test]
    fn test_siphash_nonzero() {
        let result = siphash_2_4(0, 0, &[0u8; 32]);
        // SipHash should produce a non-trivial result even with zero inputs
        assert_ne!(result, 0);
    }

    #[test]
    fn test_reconstruct_with_all_prefilled() {
        let genesis = genesis_block(Network::Bitcoin);
        let compact = CompactBlock::from_block(&genesis, 0);

        let (result, missing) = compact.reconstruct(&[]);
        assert!(missing.is_empty());
        assert_eq!(result.len(), 1);
        assert!(result[0].is_some());
    }
}
