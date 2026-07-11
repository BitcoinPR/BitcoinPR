use bitcoin::block::Header;
use bitcoin::consensus::{Decodable, Encodable};
use bitcoin::hashes::Hash;
use bitcoin::BlockHash;
use rocksdb::{BlockBasedOptions, Cache, ColumnFamilyDescriptor, Options, WriteBatch, DB};
use std::io::Cursor;
use std::path::Path;
use std::sync::Arc;
use tracing::{debug, info, warn};

use crate::error::{StorageError, StorageResult};

const CF_HEADERS: &str = "headers";
const CF_HEIGHT_INDEX: &str = "height_index";
const CF_META: &str = "meta";
const CF_BLOCK_POS: &str = "block_pos";

const META_BEST_HASH: &[u8] = b"best_hash";
const META_BEST_HEIGHT: &[u8] = b"best_height";
const META_VALIDATED_HEIGHT: &[u8] = b"validated_height";
const META_HEADER_TIP_HASH: &[u8] = b"header_tip_hash";
const META_HEADER_TIP_HEIGHT: &[u8] = b"header_tip_height";
const META_PRUNED_HEIGHT: &[u8] = b"pruned_height";

/// Helper to get block hash as a byte slice.
fn hash_bytes(hash: &BlockHash) -> &[u8] {
    AsRef::<[u8]>::as_ref(hash)
}

/// Reconstruct a BlockHash from raw bytes.
fn hash_from_bytes(data: &[u8]) -> StorageResult<BlockHash> {
    BlockHash::from_slice(data).map_err(|e| StorageError::Serialization(e.to_string()))
}

/// Stored header entry containing the header, its height, and cumulative chain work.
#[derive(Debug, Clone)]
pub struct StoredHeader {
    pub header: Header,
    pub height: u32,
    /// Cumulative chain work as a 32-byte big-endian integer.
    pub chain_work: [u8; 32],
}

impl StoredHeader {
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(80 + 4 + 32);
        self.header
            .consensus_encode(&mut buf)
            .expect("encoding into a Vec<u8> cannot fail");
        buf.extend_from_slice(&self.height.to_le_bytes());
        buf.extend_from_slice(&self.chain_work);
        buf
    }

    pub fn deserialize(data: &[u8]) -> StorageResult<Self> {
        if data.len() < 80 + 4 + 32 {
            return Err(StorageError::Serialization(format!(
                "stored header too short: {} bytes",
                data.len()
            )));
        }
        let mut cursor = Cursor::new(&data[..80]);
        let header = Header::consensus_decode(&mut cursor)
            .map_err(|e| StorageError::Serialization(e.to_string()))?;
        let height = u32::from_le_bytes(data[80..84].try_into().expect("length checked above"));
        let mut chain_work = [0u8; 32];
        chain_work.copy_from_slice(&data[84..116]);
        Ok(StoredHeader {
            header,
            height,
            chain_work,
        })
    }
}

/// Block header index backed by RocksDB.
///
/// Stores headers keyed by BlockHash and provides a height-to-hash index.
pub struct HeaderIndex {
    db: Arc<DB>,
}

impl HeaderIndex {
    /// Resolve a column-family handle, returning an error (instead of
    /// panicking) if it is missing — e.g. a corrupted or incompatible DB.
    fn cf(&self, name: &str) -> StorageResult<&rocksdb::ColumnFamily> {
        self.db
            .cf_handle(name)
            .ok_or_else(|| StorageError::MissingColumnFamily(name.to_string()))
    }

    /// Open or create the header index database at the given path.
    pub fn open(path: &Path) -> StorageResult<Self> {
        let mut db_opts = Options::default();
        db_opts.create_if_missing(true);
        db_opts.create_missing_column_families(true);
        db_opts.set_max_open_files(2_000);

        // Constrain RocksDB memory for header index (smaller dataset than UTXO)
        let block_cache = Cache::new_lru_cache(16 * 1024 * 1024); // 16 MB
        let mut table_opts = BlockBasedOptions::default();
        table_opts.set_block_cache(&block_cache);

        let mut cf_opts = Options::default();
        cf_opts.set_write_buffer_size(2 * 1024 * 1024); // 2 MB
        cf_opts.set_max_write_buffer_number(2);
        cf_opts.set_block_based_table_factory(&table_opts);

        let cf_descriptors = vec![
            ColumnFamilyDescriptor::new(CF_HEADERS, cf_opts.clone()),
            ColumnFamilyDescriptor::new(CF_HEIGHT_INDEX, cf_opts.clone()),
            ColumnFamilyDescriptor::new(CF_META, Options::default()),
            ColumnFamilyDescriptor::new(CF_BLOCK_POS, cf_opts),
        ];

        let db = DB::open_cf_descriptors(&db_opts, path, cf_descriptors)?;
        Ok(HeaderIndex { db: Arc::new(db) })
    }

    /// Insert a header into the index.
    pub fn insert_header(&self, hash: &BlockHash, stored: &StoredHeader) -> StorageResult<()> {
        let cf_headers = self.cf(CF_HEADERS)?;
        let cf_height = self.cf(CF_HEIGHT_INDEX)?;

        let mut batch = WriteBatch::default();
        batch.put_cf(&cf_headers, hash_bytes(hash), stored.serialize());
        batch.put_cf(&cf_height, stored.height.to_be_bytes(), hash_bytes(hash));
        self.db.write(batch)?;
        Ok(())
    }

    /// Insert multiple headers atomically, writing both the hash→header
    /// store and the height→hash index.
    pub fn insert_headers_batch(&self, headers: &[(BlockHash, StoredHeader)]) -> StorageResult<()> {
        let cf_headers = self.cf(CF_HEADERS)?;
        let cf_height = self.cf(CF_HEIGHT_INDEX)?;

        let mut batch = WriteBatch::default();
        for (hash, stored) in headers {
            batch.put_cf(&cf_headers, hash_bytes(hash), stored.serialize());
            batch.put_cf(&cf_height, stored.height.to_be_bytes(), hash_bytes(hash));
        }
        self.db.write(batch)?;
        debug!("Inserted {} headers in batch", headers.len());
        Ok(())
    }

    /// Insert multiple headers by hash only, without updating the
    /// height→hash index.  Used when storing headers that may not be on
    /// the best chain (fork headers, stale batches) — the height index
    /// should only be updated once the chain is confirmed to have the
    /// most cumulative work.
    pub fn insert_headers_hash_only(
        &self,
        headers: &[(BlockHash, StoredHeader)],
    ) -> StorageResult<()> {
        let cf_headers = self.cf(CF_HEADERS)?;
        let mut batch = WriteBatch::default();
        for (hash, stored) in headers {
            batch.put_cf(&cf_headers, hash_bytes(hash), stored.serialize());
        }
        self.db.write(batch)?;
        debug!("Inserted {} headers (hash-only) in batch", headers.len());
        Ok(())
    }

    /// Update the height→hash index for multiple heights atomically.
    pub fn update_height_index_batch(
        &self,
        headers: &[(BlockHash, StoredHeader)],
    ) -> StorageResult<()> {
        let cf_height = self.cf(CF_HEIGHT_INDEX)?;
        let mut batch = WriteBatch::default();
        for (hash, stored) in headers {
            batch.put_cf(&cf_height, stored.height.to_be_bytes(), hash_bytes(hash));
        }
        self.db.write(batch)?;
        Ok(())
    }

    /// Set (or overwrite) the canonical height → hash mapping for a single
    /// height, without touching the header store.
    ///
    /// Called from `ChainState::connect_block` so the height index always
    /// reflects the *active* (connected) chain. The header-first sync path and
    /// RPC `generate` already write this via `insert_header*`, but a reorg
    /// connects the new chain's blocks through `connect_block` alone — without
    /// re-inserting their headers — which previously left `CF_HEIGHT_INDEX`
    /// pointing at the now-orphaned chain for every intermediate reorged height.
    /// That stale mapping made `get_hash_at_height` (and therefore the
    /// getheaders *serving* path and `getblockhash`) return orphan-chain hashes,
    /// stranding peers that asked us to serve them the new chain.
    pub fn set_height_hash(&self, height: u32, hash: &BlockHash) -> StorageResult<()> {
        let cf = self.cf(CF_HEIGHT_INDEX)?;
        self.db
            .put_cf(&cf, height.to_be_bytes(), hash_bytes(hash))?;
        Ok(())
    }

    /// Get a stored header by its block hash.
    pub fn get_header(&self, hash: &BlockHash) -> StorageResult<Option<StoredHeader>> {
        let cf = self.cf(CF_HEADERS)?;
        match self.db.get_cf(&cf, hash_bytes(hash))? {
            Some(data) => Ok(Some(StoredHeader::deserialize(&data)?)),
            None => Ok(None),
        }
    }

    /// Walk `prev_blockhash` links backward from `from` to the ancestor at
    /// `target_height`, returning that ancestor's stored header.
    ///
    /// Unlike `get_hash_at_height` (which consults the *active* chain's
    /// height → hash index), this resolves the ancestor on the chain that
    /// actually contains `from` — required when validating a side-chain
    /// block whose fork point is older than the height being resolved
    /// (e.g. the retarget period start during a reorg), where the height
    /// index would return the wrong (old-chain) header. Mirrors Bitcoin
    /// Core's `CBlockIndex::GetAncestor`.
    ///
    /// Returns `Ok(None)` if `from` is unknown, `target_height` is above
    /// `from`'s height, or any header along the walk is missing — callers
    /// must treat that as "chain context unavailable", not as success.
    pub fn get_ancestor(
        &self,
        from: &BlockHash,
        target_height: u32,
    ) -> StorageResult<Option<StoredHeader>> {
        let mut current = match self.get_header(from)? {
            Some(h) => h,
            None => return Ok(None),
        };
        if current.height < target_height {
            return Ok(None);
        }
        while current.height > target_height {
            match self.get_header(&current.header.prev_blockhash)? {
                // Defensive: stored heights must strictly decrease along prev
                // links; a corrupt index could otherwise loop forever.
                Some(parent) if parent.height < current.height => current = parent,
                _ => return Ok(None),
            }
        }
        Ok(Some(current))
    }

    /// Get the block hash at a given height.
    pub fn get_hash_at_height(&self, height: u32) -> StorageResult<Option<BlockHash>> {
        let cf = self.cf(CF_HEIGHT_INDEX)?;
        match self.db.get_cf(&cf, height.to_be_bytes())? {
            Some(data) => Ok(Some(hash_from_bytes(&data)?)),
            None => Ok(None),
        }
    }

    /// Remove the canonical height → hash mapping for a single height.
    /// Must be called when disconnecting a block during a reorg so that
    /// `get_hash_at_height` returns `None` for the now-orphaned height rather
    /// than the stale orphan hash.
    pub fn delete_height_entry(&self, height: u32) -> StorageResult<()> {
        let cf = self.cf(CF_HEIGHT_INDEX)?;
        self.db.delete_cf(&cf, height.to_be_bytes())?;
        Ok(())
    }

    /// Get the best tip hash.
    pub fn get_best_tip(&self) -> StorageResult<Option<BlockHash>> {
        let cf = self.cf(CF_META)?;
        match self.db.get_cf(&cf, META_BEST_HASH)? {
            Some(data) => Ok(Some(hash_from_bytes(&data)?)),
            None => Ok(None),
        }
    }

    pub fn set_best_tip(&self, hash: &BlockHash, height: u32) -> StorageResult<()> {
        let cf = self.cf(CF_META)?;
        let mut batch = WriteBatch::default();
        batch.put_cf(&cf, META_BEST_HASH, hash_bytes(hash));
        batch.put_cf(&cf, META_BEST_HEIGHT, height.to_le_bytes());
        self.db.write(batch)?;
        Ok(())
    }

    pub fn get_best_height(&self) -> StorageResult<Option<u32>> {
        let cf = self.cf(CF_META)?;
        match self.db.get_cf(&cf, META_BEST_HEIGHT)? {
            Some(data) => {
                let height = u32::from_le_bytes(
                    data.try_into()
                        .map_err(|_| StorageError::Serialization("invalid height bytes".into()))?,
                );
                Ok(Some(height))
            }
            None => Ok(None),
        }
    }

    /// Get the header chain tip hash (may be ahead of validated tip).
    pub fn get_header_tip(&self) -> StorageResult<Option<BlockHash>> {
        let cf = self.cf(CF_META)?;
        match self.db.get_cf(&cf, META_HEADER_TIP_HASH)? {
            Some(data) => Ok(Some(hash_from_bytes(&data)?)),
            None => self.get_best_tip(), // fall back to validated tip
        }
    }

    pub fn get_header_tip_height(&self) -> StorageResult<Option<u32>> {
        let cf = self.cf(CF_META)?;
        match self.db.get_cf(&cf, META_HEADER_TIP_HEIGHT)? {
            Some(data) => {
                let height = u32::from_le_bytes(
                    data.try_into()
                        .map_err(|_| StorageError::Serialization("invalid height bytes".into()))?,
                );
                Ok(Some(height))
            }
            None => self.get_best_height(), // fall back
        }
    }

    pub fn set_header_tip(&self, hash: &BlockHash, height: u32) -> StorageResult<()> {
        let cf = self.cf(CF_META)?;
        let mut batch = WriteBatch::default();
        batch.put_cf(&cf, META_HEADER_TIP_HASH, hash_bytes(hash));
        batch.put_cf(&cf, META_HEADER_TIP_HEIGHT, height.to_le_bytes());
        self.db.write(batch)?;
        Ok(())
    }

    /// Store a block's position in the flat file store, keyed by block hash.
    pub fn set_block_pos(
        &self,
        hash: &BlockHash,
        pos: &crate::block_store::BlockPos,
    ) -> StorageResult<()> {
        let cf = self.cf(CF_BLOCK_POS)?;
        self.db.put_cf(&cf, hash_bytes(hash), pos.serialize())?;
        Ok(())
    }

    /// Remove a stale block-position entry (e.g. after on-disk corruption).
    pub fn remove_block_pos(&self, hash: &BlockHash) -> StorageResult<()> {
        let cf = self.cf(CF_BLOCK_POS)?;
        self.db.delete_cf(&cf, hash_bytes(hash))?;
        Ok(())
    }

    /// Retrieve a block's position from the index.
    pub fn get_block_pos(
        &self,
        hash: &BlockHash,
    ) -> StorageResult<Option<crate::block_store::BlockPos>> {
        let cf = self.cf(CF_BLOCK_POS)?;
        match self.db.get_cf(&cf, hash_bytes(hash))? {
            Some(data) => {
                if data.len() != 16 {
                    return Err(StorageError::Serialization(
                        "invalid block pos data length".into(),
                    ));
                }
                let pos = crate::block_store::BlockPos::deserialize(
                    data.as_slice().try_into().expect("length checked above"),
                );
                Ok(Some(pos))
            }
            None => Ok(None),
        }
    }

    /// Get the underlying DB handle (for sharing with other storage components).
    pub fn db(&self) -> Arc<DB> {
        self.db.clone()
    }

    /// Force a fsync of the WAL.
    ///
    /// Called at the UTXO flush boundary (every N blocks during IBD) to make
    /// the height→hash index crash-consistent up to the validated tip. Without
    /// this, a power loss after `set_best_tip` lands on disk but before the
    /// preceding `insert_header*` WAL entries are fsync'd can leave gaps in
    /// the height index that `verify_chain_integrity` will then trip over on
    /// the next startup, triggering a forward-recovery full re-sync.
    pub fn flush_wal(&self) -> StorageResult<()> {
        self.db.flush_wal(true)?;
        Ok(())
    }

    /// Verify header chain integrity on startup.
    /// Walks the chain from genesis to tip, checking that each header's
    /// prev_blockhash links to the previous height's hash.
    /// Returns `(verified_height, best_height)`. If there is a chain break,
    /// `verified_height < best_height` — the caller should truncate and
    /// re-sync from `verified_height`.
    pub fn verify_chain_integrity(&self) -> StorageResult<(u32, u32)> {
        let best_height = match self.get_best_height()? {
            Some(h) => h,
            None => return Ok((0, 0)), // empty database
        };

        // Only verify the last CHECK_DEPTH blocks — a full scan from genesis
        // is prohibitively slow on HDDs (two RocksDB reads per height).
        // Corruption in the deep history would have been caught on a prior run.
        const CHECK_DEPTH: u32 = 1_000;
        let start_height = best_height.saturating_sub(CHECK_DEPTH);

        // Seed prev_hash from the block before our scan window
        let mut prev_hash = if start_height > 0 {
            self.get_hash_at_height(start_height.saturating_sub(1))?
        } else {
            None
        };
        let mut checked = if start_height > 0 {
            start_height - 1
        } else {
            0
        };

        info!(
            start_height,
            best_height,
            "Verifying header chain integrity ({} headers)",
            best_height - start_height + 1
        );

        for height in start_height..=best_height {
            let hash = match self.get_hash_at_height(height)? {
                Some(h) => h,
                None => {
                    warn!(
                        missing_height = height,
                        best_height,
                        scan_start = start_height,
                        "Header chain gap: height→hash index entry missing — truncating to height {} (forward recovery will follow)",
                        height.saturating_sub(1)
                    );
                    return Ok((height.saturating_sub(1), best_height));
                }
            };

            let stored = match self.get_header(&hash)? {
                Some(s) => s,
                None => {
                    warn!(
                        missing_height = height,
                        %hash,
                        best_height,
                        "Header chain gap: header data missing for known hash — truncating to height {}",
                        height.saturating_sub(1)
                    );
                    return Ok((height.saturating_sub(1), best_height));
                }
            };

            if stored.height != height {
                warn!(
                    height,
                    stored_height = stored.height,
                    best_height,
                    "Header chain gap: stored height mismatches index height — truncating to height {}",
                    height.saturating_sub(1)
                );
                return Ok((height.saturating_sub(1), best_height));
            }

            if let Some(expected_prev) = prev_hash {
                if stored.header.prev_blockhash != expected_prev {
                    warn!(
                        height,
                        expected = %expected_prev,
                        got = %stored.header.prev_blockhash,
                        "Chain break — truncating to height {}",
                        height - 1
                    );
                    return Ok((height - 1, best_height));
                }
            }

            prev_hash = Some(hash);
            checked = height;
        }

        Ok((checked, best_height))
    }

    /// Truncate the header chain: reset the best tip to `keep_height` and
    /// remove height-index entries above it.  Header data for orphan hashes
    /// is left in place (harmless) to avoid a full scan of the hash→header CF.
    pub fn truncate_to(&self, keep_height: u32) -> StorageResult<()> {
        let best_height = self.get_best_height()?.unwrap_or(0);
        if keep_height >= best_height {
            return Ok(());
        }

        let cf_height = self.cf(CF_HEIGHT_INDEX)?;
        let mut batch = WriteBatch::default();

        for h in (keep_height + 1)..=best_height {
            batch.delete_cf(&cf_height, h.to_be_bytes());
        }
        self.db.write(batch)?;

        // Update best tip to the last valid header
        if let Some(hash) = self.get_hash_at_height(keep_height)? {
            self.set_best_tip(&hash, keep_height)?;
        }

        Ok(())
    }

    /// Reset the *header-sync* tip (META_HEADER_TIP_*) to a known-canonical
    /// height/hash, purging any height-index entries above it and fixing the
    /// entry *at* `canonical_height`.
    ///
    /// This is used at startup to recover from "fork contamination": a peer on
    /// a minority fork can push headers that advance our header-tip past the
    /// validated chain, causing `is_ibd` to stay stuck `true` forever.
    ///
    /// Unlike `truncate_to`, this method:
    ///   - operates on the HEADER tip (META_HEADER_TIP_*) rather than the
    ///     validated-chain tip (META_BEST_*), so validated state is untouched.
    ///   - also corrects the height_index entry *at* `canonical_height`, which
    ///     may have been overwritten with a fork hash.
    pub fn reset_fork_header_tip(
        &self,
        canonical_height: u32,
        canonical_hash: &BlockHash,
    ) -> StorageResult<()> {
        let current_tip = self.get_header_tip_height()?.unwrap_or(0);

        let cf_height = self.cf(CF_HEIGHT_INDEX)?;
        let mut batch = WriteBatch::default();

        // Remove height-index entries that belong to the fork chain
        if current_tip > canonical_height {
            for h in (canonical_height + 1)..=current_tip {
                batch.delete_cf(&cf_height, h.to_be_bytes());
            }
        }

        // Restore the height-index entry at canonical_height to the known-good hash
        batch.put_cf(
            &cf_height,
            canonical_height.to_be_bytes(),
            hash_bytes(canonical_hash),
        );

        self.db.write(batch)?;

        // Reset the header-sync tip pointer
        self.set_header_tip(canonical_hash, canonical_height)?;

        info!(
            height = canonical_height,
            hash = %canonical_hash,
            removed = current_tip.saturating_sub(canonical_height),
            "Header-tip reset: purged fork headers, restored canonical tip"
        );

        Ok(())
    }

    /// Record the last fully-validated block height (written on clean shutdown).
    /// On next startup, headers above this height are not yet backed by UTXO state.
    pub fn set_validated_height(&self, height: u32) -> StorageResult<()> {
        let cf = self.cf(CF_META)?;
        self.db
            .put_cf(&cf, META_VALIDATED_HEIGHT, height.to_le_bytes())?;
        Ok(())
    }

    /// Read the last validated height recorded at shutdown (if any).
    pub fn get_validated_height(&self) -> StorageResult<Option<u32>> {
        let cf = self.cf(CF_META)?;
        match self.db.get_cf(&cf, META_VALIDATED_HEIGHT)? {
            Some(data) => {
                let height = u32::from_le_bytes(data.try_into().map_err(|_| {
                    StorageError::Serialization("invalid validated_height bytes".into())
                })?);
                Ok(Some(height))
            }
            None => Ok(None),
        }
    }

    /// Clear the validated height marker (e.g. before a rebuild).
    pub fn clear_validated_height(&self) -> StorageResult<()> {
        let cf = self.cf(CF_META)?;
        self.db.delete_cf(&cf, META_VALIDATED_HEIGHT)?;
        Ok(())
    }

    /// Record the pruned height: every block at or below this height has had
    /// its raw block data (and undo record) removed by the pruner. The lowest
    /// complete block on disk is therefore `pruned_height + 1`.
    pub fn set_pruned_height(&self, height: u32) -> StorageResult<()> {
        let cf = self.cf(CF_META)?;
        self.db
            .put_cf(&cf, META_PRUNED_HEIGHT, height.to_le_bytes())?;
        Ok(())
    }

    /// Read the pruned height (`None` if the node has never pruned).
    pub fn get_pruned_height(&self) -> StorageResult<Option<u32>> {
        let cf = self.cf(CF_META)?;
        match self.db.get_cf(&cf, META_PRUNED_HEIGHT)? {
            Some(data) => {
                let height = u32::from_le_bytes(data.try_into().map_err(|_| {
                    StorageError::Serialization("invalid pruned_height bytes".into())
                })?);
                Ok(Some(height))
            }
            None => Ok(None),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use bitcoin::constants::genesis_block;
    use bitcoin::Network;

    #[test]
    fn test_header_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let index = HeaderIndex::open(dir.path()).unwrap();

        let genesis = genesis_block(Network::Bitcoin);
        let hash = genesis.block_hash();
        let stored = StoredHeader {
            header: genesis.header,
            height: 0,
            chain_work: [0u8; 32],
        };

        index.insert_header(&hash, &stored).unwrap();

        let retrieved = index.get_header(&hash).unwrap().unwrap();
        assert_eq!(retrieved.height, 0);
        assert_eq!(
            retrieved.header.prev_blockhash,
            genesis.header.prev_blockhash
        );

        // Height index
        let hash_at_0 = index.get_hash_at_height(0).unwrap().unwrap();
        assert_eq!(hash_at_0, hash);

        // Missing height
        assert!(index.get_hash_at_height(1).unwrap().is_none());
    }

    #[test]
    fn test_get_ancestor_walks_prev_links() {
        use bitcoin::hashes::Hash as _;

        let dir = tempfile::tempdir().unwrap();
        let index = HeaderIndex::open(dir.path()).unwrap();

        let mk = |prev: BlockHash, nonce: u32| bitcoin::block::Header {
            version: bitcoin::block::Version::from_consensus(4),
            prev_blockhash: prev,
            merkle_root: bitcoin::TxMerkleNode::all_zeros(),
            time: 1_700_000_000 + nonce,
            bits: bitcoin::CompactTarget::from_consensus(0x207fffff),
            nonce,
        };

        // Chain h1 <- h2 <- h3 at heights 1..=3 (no height-0 anchor stored).
        let h1 = mk(BlockHash::all_zeros(), 1);
        let h2 = mk(h1.block_hash(), 2);
        let h3 = mk(h2.block_hash(), 3);
        for (header, height) in [(h1, 1u32), (h2, 2), (h3, 3)] {
            index
                .insert_header(
                    &header.block_hash(),
                    &StoredHeader {
                        header,
                        height,
                        chain_work: [0u8; 32],
                    },
                )
                .unwrap();
        }

        // Walks back to the requested height.
        let anc = index.get_ancestor(&h3.block_hash(), 1).unwrap().unwrap();
        assert_eq!(anc.header.block_hash(), h1.block_hash());
        assert_eq!(anc.height, 1);

        // Zero-step walk returns the starting header itself.
        let same = index.get_ancestor(&h3.block_hash(), 3).unwrap().unwrap();
        assert_eq!(same.header.block_hash(), h3.block_hash());

        // Target above the starting height → None.
        assert!(index.get_ancestor(&h1.block_hash(), 2).unwrap().is_none());

        // Unknown starting hash → None.
        assert!(index
            .get_ancestor(&BlockHash::all_zeros(), 0)
            .unwrap()
            .is_none());

        // Missing header mid-walk (h1's parent was never stored) → None.
        assert!(index.get_ancestor(&h3.block_hash(), 0).unwrap().is_none());
    }

    #[test]
    fn test_best_tip() {
        let dir = tempfile::tempdir().unwrap();
        let index = HeaderIndex::open(dir.path()).unwrap();

        assert!(index.get_best_tip().unwrap().is_none());
        assert!(index.get_best_height().unwrap().is_none());

        let genesis = genesis_block(Network::Bitcoin);
        let hash = genesis.block_hash();
        index.set_best_tip(&hash, 0).unwrap();

        assert_eq!(index.get_best_tip().unwrap().unwrap(), hash);
        assert_eq!(index.get_best_height().unwrap().unwrap(), 0);
    }

    #[test]
    fn test_batch_insert() {
        let dir = tempfile::tempdir().unwrap();
        let index = HeaderIndex::open(dir.path()).unwrap();

        let genesis = genesis_block(Network::Bitcoin);
        let hash = genesis.block_hash();
        let entries = vec![(
            hash,
            StoredHeader {
                header: genesis.header,
                height: 0,
                chain_work: [0u8; 32],
            },
        )];

        index.insert_headers_batch(&entries).unwrap();
        assert!(index.get_header(&hash).unwrap().is_some());
    }
}
