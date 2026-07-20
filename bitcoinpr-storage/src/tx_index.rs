use bitcoin::hashes::Hash;
use bitcoin::{BlockHash, Txid};
use rocksdb::{Cache, Options, DB};
use std::path::Path;
use std::sync::Arc;
use tracing::debug;

use crate::error::{StorageError, StorageResult};

/// Reserved key for storing the indexed height (not a valid txid).
const META_INDEXED_HEIGHT: &[u8] = b"__meta__indexed_height__";

/// Block cache for the tx index (data + index/filter blocks). The index is
/// ~100 GB and each large SST carries an index/filter block in the MB range;
/// with RocksDB's small default cache every random txid get re-reads and
/// re-verifies megabytes of filter/index data (observed ~4 GB/s of page-cache
/// churn during scripthash backfill). 1 GB keeps the hot set resident.
const TXINDEX_BLOCK_CACHE_BYTES: usize = 1024 * 1024 * 1024;

/// Entry in the transaction index: maps txid → (block_hash, tx_position).
///
/// Two on-disk formats coexist (write-new/read-both migration):
/// - v1 (36 bytes): `block_hash[32] || tx_pos_le[4]`
/// - v2 (44 bytes): v1 + `tx_offset_le[4] || tx_len_le[4]`, the byte range of
///   the serialized transaction *within the raw block* (block-relative, so
///   entries stay valid across block-file migration/reindex). With it, a
///   prevout lookup is one small positional read + one tx decode instead of a
///   partial block scan.
#[derive(Debug, Clone)]
pub struct TxIndexEntry {
    pub block_hash: BlockHash,
    /// Position of the transaction within the block (0 = coinbase).
    pub tx_pos: u32,
    /// v2: `(offset, len)` of the serialized tx within the raw block bytes.
    /// `None` for legacy v1 entries.
    pub tx_loc: Option<(u32, u32)>,
}

impl TxIndexEntry {
    /// Serialize into a fixed buffer; returns the buffer and the encoded
    /// length (36 for v1 entries, 44 for v2).
    fn serialize(&self) -> ([u8; 44], usize) {
        let mut buf = [0u8; 44];
        buf[0..32].copy_from_slice(AsRef::<[u8; 32]>::as_ref(&self.block_hash));
        buf[32..36].copy_from_slice(&self.tx_pos.to_le_bytes());
        match self.tx_loc {
            Some((offset, len)) => {
                buf[36..40].copy_from_slice(&offset.to_le_bytes());
                buf[40..44].copy_from_slice(&len.to_le_bytes());
                (buf, 44)
            }
            None => (buf, 36),
        }
    }

    fn deserialize(data: &[u8]) -> StorageResult<Self> {
        if data.len() < 36 {
            return Err(StorageError::Serialization(
                "tx index entry too short".into(),
            ));
        }
        let mut hash_bytes = [0u8; 32];
        hash_bytes.copy_from_slice(&data[0..32]);
        let block_hash = BlockHash::from_byte_array(hash_bytes);
        let tx_pos = u32::from_le_bytes(data[32..36].try_into().expect("length checked above"));
        let tx_loc = if data.len() >= 44 {
            Some((
                u32::from_le_bytes(data[36..40].try_into().expect("length checked above")),
                u32::from_le_bytes(data[40..44].try_into().expect("length checked above")),
            ))
        } else {
            None
        };
        Ok(TxIndexEntry {
            block_hash,
            tx_pos,
            tx_loc,
        })
    }
}

/// Compute per-transaction `(offset, len)` byte locations within the raw
/// consensus-serialized block: 80-byte header, tx-count varint, then each tx.
/// `Transaction::total_size` is the exact consensus-encoded size (witness
/// included when present), so the offsets match the raw bytes in the block
/// store without re-serializing anything.
pub fn compute_tx_locations(block: &bitcoin::Block) -> Vec<(u32, u32)> {
    let mut offset = 80usize + bitcoin::consensus::encode::VarInt::from(block.txdata.len()).size();
    let mut locs = Vec::with_capacity(block.txdata.len());
    for tx in &block.txdata {
        let len = tx.total_size();
        locs.push((offset as u32, len as u32));
        offset += len;
    }
    locs
}

/// Transaction index: maps txid to the block containing it.
pub struct TxIndex {
    db: Arc<DB>,
}

impl TxIndex {
    /// Open the transaction index database.
    pub fn open(path: &Path) -> StorageResult<Self> {
        let mut opts = Options::default();
        opts.create_if_missing(true);
        opts.set_max_open_files(5_000);
        // Bloom filter: without one, every point-get on a miss reads data
        // blocks from SSTs in every level. Keys are random txids, so gets are
        // the dominant access pattern (scripthash prevout resolution, RPC
        // lookups). ~10 bits/key skips ~99% of unnecessary SST reads.
        // Note: applies to newly written SSTs; existing ones gain filters as
        // compaction rewrites them.
        let mut table_opts = rocksdb::BlockBasedOptions::default();
        table_opts.set_bloom_filter(10.0, false);
        table_opts.set_block_size(16 * 1024);
        table_opts.set_cache_index_and_filter_blocks(true);
        table_opts.set_pin_l0_filter_and_index_blocks_in_cache(true);
        // Dedicated cache — index/filter blocks are cached (above), so they
        // must not be squeezed through RocksDB's tiny default LRU.
        let block_cache = Cache::new_lru_cache(TXINDEX_BLOCK_CACHE_BYTES);
        table_opts.set_block_cache(&block_cache);
        opts.set_block_based_table_factory(&table_opts);
        // Nearly all lookups are for txids that exist (prevout resolution of
        // confirmed spends, explorer/RPC lookups of known txids), so
        // bottom-level bloom filters rarely short-circuit anything — skipping
        // them frees most of the filter footprint for the levels where
        // filters do help.
        opts.set_optimize_filters_for_hits(true);
        let db = DB::open(&opts, path)?;
        Ok(TxIndex { db: Arc::new(db) })
    }

    /// Look up a transaction by its txid.
    pub fn get(&self, txid: &Txid) -> StorageResult<Option<TxIndexEntry>> {
        let key: &[u8; 32] = AsRef::<[u8; 32]>::as_ref(txid);
        match self.db.get(key)? {
            Some(data) => Ok(Some(TxIndexEntry::deserialize(&data)?)),
            None => Ok(None),
        }
    }

    /// Batched lookup: one RocksDB `MultiGet` for many txids. RocksDB groups
    /// the keys per SST internally, sharing index/filter block loads that
    /// per-key `get()` calls would repeat. Lookup or decode failures yield
    /// `None` in the corresponding slot (callers treat missing entries as
    /// unresolvable, matching `get`'s error-tolerant call sites).
    pub fn get_many(&self, txids: &[Txid]) -> Vec<Option<TxIndexEntry>> {
        let keys = txids.iter().map(AsRef::<[u8; 32]>::as_ref);
        self.db
            .multi_get(keys)
            .into_iter()
            .map(|res| match res {
                Ok(Some(data)) => TxIndexEntry::deserialize(&data).ok(),
                _ => None,
            })
            .collect()
    }

    /// Index all transactions in a block.
    pub fn index_block(&self, block_hash: &BlockHash, txids: &[Txid]) -> StorageResult<()> {
        let mut batch = rocksdb::WriteBatch::default();
        for (pos, txid) in txids.iter().enumerate() {
            let entry = TxIndexEntry {
                block_hash: *block_hash,
                tx_pos: pos as u32,
                tx_loc: None,
            };
            let key: &[u8; 32] = AsRef::<[u8; 32]>::as_ref(txid);
            let (buf, len) = entry.serialize();
            batch.put(key, &buf[..len]);
        }
        self.db.write(batch)?;
        debug!(block = %block_hash, txs = txids.len(), "Indexed block transactions");
        Ok(())
    }

    /// Rewrite entries with their v2 byte locations (write-new/read-both
    /// migration). Called opportunistically by the prevout resolver when a
    /// funding-block scan has discovered the locations anyway, so future
    /// lookups of the same txs skip the block scan.
    pub fn upgrade_tx_locations(&self, updates: &[(Txid, TxIndexEntry)]) -> StorageResult<()> {
        if updates.is_empty() {
            return Ok(());
        }
        let mut batch = rocksdb::WriteBatch::default();
        for (txid, entry) in updates {
            let key: &[u8; 32] = AsRef::<[u8; 32]>::as_ref(txid);
            let (buf, len) = entry.serialize();
            batch.put(key, &buf[..len]);
        }
        self.db.write(batch)?;
        Ok(())
    }

    /// Remove all transaction entries for a block (for reorg).
    pub fn deindex_block(&self, txids: &[Txid]) -> StorageResult<()> {
        let mut batch = rocksdb::WriteBatch::default();
        for txid in txids {
            let key: &[u8; 32] = AsRef::<[u8; 32]>::as_ref(txid);
            batch.delete(key);
        }
        self.db.write(batch)?;
        Ok(())
    }

    /// Check if the index contains a transaction.
    pub fn contains(&self, txid: &Txid) -> StorageResult<bool> {
        let key: &[u8; 32] = AsRef::<[u8; 32]>::as_ref(txid);
        Ok(self.db.get(key)?.is_some())
    }

    /// Get the highest block height that has been indexed.
    pub fn get_indexed_height(&self) -> StorageResult<Option<u32>> {
        match self.db.get(META_INDEXED_HEIGHT)? {
            Some(data) if data.len() >= 4 => Ok(Some(u32::from_le_bytes(
                data[..4].try_into().expect("length checked above"),
            ))),
            _ => Ok(None),
        }
    }

    /// Set the highest block height that has been indexed.
    pub fn set_indexed_height(&self, height: u32) -> StorageResult<()> {
        self.db.put(META_INDEXED_HEIGHT, height.to_le_bytes())?;
        Ok(())
    }

    /// Index all transactions in a block and update the indexed height.
    /// `tx_locs`, when provided (from [`compute_tx_locations`]), writes v2
    /// entries carrying the tx byte locations within the raw block.
    pub fn index_block_at_height(
        &self,
        block_hash: &BlockHash,
        txids: &[Txid],
        height: u32,
        tx_locs: Option<&[(u32, u32)]>,
    ) -> StorageResult<()> {
        let mut batch = rocksdb::WriteBatch::default();
        for (pos, txid) in txids.iter().enumerate() {
            let entry = TxIndexEntry {
                block_hash: *block_hash,
                tx_pos: pos as u32,
                tx_loc: tx_locs.and_then(|l| l.get(pos).copied()),
            };
            let key: &[u8; 32] = AsRef::<[u8; 32]>::as_ref(txid);
            let (buf, len) = entry.serialize();
            batch.put(key, &buf[..len]);
        }
        batch.put(META_INDEXED_HEIGHT, height.to_le_bytes());
        self.db.write(batch)?;
        debug!(block = %block_hash, txs = txids.len(), height, "Indexed block transactions");
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn test_tx_index_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let tx_index = TxIndex::open(&dir.path().join("txindex")).unwrap();

        let block_hash: BlockHash =
            "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
                .parse()
                .unwrap();
        let txid: Txid = "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"
            .parse()
            .unwrap();

        tx_index.index_block(&block_hash, &[txid]).unwrap();

        let entry = tx_index.get(&txid).unwrap().unwrap();
        assert_eq!(entry.block_hash, block_hash);
        assert_eq!(entry.tx_pos, 0);

        assert!(tx_index.contains(&txid).unwrap());

        // Deindex
        tx_index.deindex_block(&[txid]).unwrap();
        assert!(!tx_index.contains(&txid).unwrap());
    }

    #[test]
    fn test_indexed_height_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let tx_index = TxIndex::open(&dir.path().join("txindex")).unwrap();

        // Initially None
        assert_eq!(tx_index.get_indexed_height().unwrap(), None);

        tx_index.set_indexed_height(42).unwrap();
        assert_eq!(tx_index.get_indexed_height().unwrap(), Some(42));

        tx_index.set_indexed_height(100).unwrap();
        assert_eq!(tx_index.get_indexed_height().unwrap(), Some(100));
    }

    #[test]
    fn test_index_block_at_height() {
        let dir = tempfile::tempdir().unwrap();
        let tx_index = TxIndex::open(&dir.path().join("txindex")).unwrap();

        let block_hash: BlockHash =
            "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
                .parse()
                .unwrap();
        let txid: Txid = "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"
            .parse()
            .unwrap();

        tx_index
            .index_block_at_height(&block_hash, &[txid], 0, None)
            .unwrap();

        // Transaction should be indexed
        let entry = tx_index.get(&txid).unwrap().unwrap();
        assert_eq!(entry.block_hash, block_hash);
        assert_eq!(entry.tx_pos, 0);

        // Height should be updated atomically
        assert_eq!(tx_index.get_indexed_height().unwrap(), Some(0));

        // Index another block at height 5
        let block_hash2: BlockHash =
            "00000000839a8e6886ab5951d76f411475428afc90947ee320161bbf18eb6048"
                .parse()
                .unwrap();
        let txid2: Txid = "0e3e2357e806b6cdb1f70b54c3a3a17b6714ee1f0e68bebb44a74b1efd512098"
            .parse()
            .unwrap();

        tx_index
            .index_block_at_height(&block_hash2, &[txid2], 5, None)
            .unwrap();
        assert_eq!(tx_index.get_indexed_height().unwrap(), Some(5));
    }

    #[test]
    fn test_v2_entry_roundtrip_and_upgrade() {
        let dir = tempfile::tempdir().unwrap();
        let tx_index = TxIndex::open(&dir.path().join("txindex")).unwrap();

        let block_hash: BlockHash =
            "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
                .parse()
                .unwrap();
        let txid: Txid = "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"
            .parse()
            .unwrap();

        // v2 write via index_block_at_height with locations
        tx_index
            .index_block_at_height(&block_hash, &[txid], 7, Some(&[(81, 204)]))
            .unwrap();
        let entry = tx_index.get(&txid).unwrap().unwrap();
        assert_eq!(entry.tx_pos, 0);
        assert_eq!(entry.tx_loc, Some((81, 204)));

        // v1 write (index_block writes legacy entries) reads back as None loc
        let txid2: Txid = "0e3e2357e806b6cdb1f70b54c3a3a17b6714ee1f0e68bebb44a74b1efd512098"
            .parse()
            .unwrap();
        tx_index.index_block(&block_hash, &[txid2]).unwrap();
        let entry = tx_index.get(&txid2).unwrap().unwrap();
        assert_eq!(entry.tx_loc, None);
        assert_eq!(entry.tx_pos, 0);

        // Opportunistic upgrade rewrites v1 → v2
        tx_index
            .upgrade_tx_locations(&[(
                txid2,
                TxIndexEntry {
                    block_hash,
                    tx_pos: 0,
                    tx_loc: Some((285, 150)),
                },
            )])
            .unwrap();
        let entry = tx_index.get(&txid2).unwrap().unwrap();
        assert_eq!(entry.tx_loc, Some((285, 150)));

        // get_many sees both formats
        let many = tx_index.get_many(&[txid, txid2]);
        assert_eq!(many[0].as_ref().unwrap().tx_loc, Some((81, 204)));
        assert_eq!(many[1].as_ref().unwrap().tx_loc, Some((285, 150)));
    }

    #[test]
    fn test_height_persists_across_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("txindex");

        {
            let tx_index = TxIndex::open(&path).unwrap();
            tx_index.set_indexed_height(999).unwrap();
        }

        // Reopen
        let tx_index = TxIndex::open(&path).unwrap();
        assert_eq!(tx_index.get_indexed_height().unwrap(), Some(999));
    }
}
