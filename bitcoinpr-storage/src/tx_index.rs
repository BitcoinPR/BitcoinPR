use bitcoin::hashes::Hash;
use bitcoin::{BlockHash, Txid};
use rocksdb::{Options, DB};
use std::path::Path;
use std::sync::Arc;
use tracing::debug;

use crate::error::{StorageError, StorageResult};

/// Reserved key for storing the indexed height (not a valid txid).
const META_INDEXED_HEIGHT: &[u8] = b"__meta__indexed_height__";

/// Entry in the transaction index: maps txid → (block_hash, tx_position).
#[derive(Debug, Clone)]
pub struct TxIndexEntry {
    pub block_hash: BlockHash,
    /// Position of the transaction within the block (0 = coinbase).
    pub tx_pos: u32,
}

impl TxIndexEntry {
    fn serialize(&self) -> [u8; 36] {
        let mut buf = [0u8; 36];
        buf[0..32].copy_from_slice(AsRef::<[u8; 32]>::as_ref(&self.block_hash));
        buf[32..36].copy_from_slice(&self.tx_pos.to_le_bytes());
        buf
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
        Ok(TxIndexEntry { block_hash, tx_pos })
    }
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
        opts.set_block_based_table_factory(&table_opts);
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

    /// Index all transactions in a block.
    pub fn index_block(&self, block_hash: &BlockHash, txids: &[Txid]) -> StorageResult<()> {
        let mut batch = rocksdb::WriteBatch::default();
        for (pos, txid) in txids.iter().enumerate() {
            let entry = TxIndexEntry {
                block_hash: *block_hash,
                tx_pos: pos as u32,
            };
            let key: &[u8; 32] = AsRef::<[u8; 32]>::as_ref(txid);
            batch.put(key, entry.serialize());
        }
        self.db.write(batch)?;
        debug!(block = %block_hash, txs = txids.len(), "Indexed block transactions");
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
    pub fn index_block_at_height(
        &self,
        block_hash: &BlockHash,
        txids: &[Txid],
        height: u32,
    ) -> StorageResult<()> {
        let mut batch = rocksdb::WriteBatch::default();
        for (pos, txid) in txids.iter().enumerate() {
            let entry = TxIndexEntry {
                block_hash: *block_hash,
                tx_pos: pos as u32,
            };
            let key: &[u8; 32] = AsRef::<[u8; 32]>::as_ref(txid);
            batch.put(key, entry.serialize());
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
            .index_block_at_height(&block_hash, &[txid], 0)
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
            .index_block_at_height(&block_hash2, &[txid2], 5)
            .unwrap();
        assert_eq!(tx_index.get_indexed_height().unwrap(), Some(5));
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
