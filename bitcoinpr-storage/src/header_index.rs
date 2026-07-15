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
const CF_INVALID: &str = "invalid_blocks";

const META_BEST_HASH: &[u8] = b"best_hash";
const META_BEST_HEIGHT: &[u8] = b"best_height";
const META_VALIDATED_HEIGHT: &[u8] = b"validated_height";
const META_HEADER_TIP_HASH: &[u8] = b"header_tip_hash";
const META_HEADER_TIP_HEIGHT: &[u8] = b"header_tip_height";
const META_PRUNED_HEIGHT: &[u8] = b"pruned_height";
const META_BIP110_ABANDONED: &[u8] = b"bip110_abandoned";
const META_SPLIT_RIVAL_TIPS: &[u8] = b"split_rival_tips";

/// Block failed consensus validation at connect while BIP-110 was enforcing.
pub const INVALID_REASON_BIP110: u8 = 1;
/// Block failed consensus validation at connect (non-BIP-110 rules).
pub const INVALID_REASON_CONSENSUS: u8 = 2;
/// Header violated the BIP-110 mandatory-signaling window (header-only check).
pub const INVALID_REASON_SIGNALING: u8 = 3;
/// Operator marked the block invalid via the `invalidateblock` RPC.
pub const INVALID_REASON_MANUAL: u8 = 4;

/// Helper to get block hash as a byte slice.
fn hash_bytes(hash: &BlockHash) -> &[u8] {
    AsRef::<[u8]>::as_ref(hash)
}

/// Reconstruct a BlockHash from raw bytes.
fn hash_from_bytes(data: &[u8]) -> StorageResult<BlockHash> {
    BlockHash::from_slice(data).map_err(|e| StorageError::Serialization(e.to_string()))
}

/// Add two 256-bit big-endian integers (cumulative chain work).
fn add_work(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut result = [0u8; 32];
    let mut carry = 0u16;
    for i in (0..32).rev() {
        let sum = a[i] as u16 + b[i] as u16 + carry;
        result[i] = sum as u8;
        carry = sum >> 8;
    }
    result
}

/// Subtract two 256-bit big-endian integers (`a - b`), saturating at zero.
pub fn sub_work(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut result = [0u8; 32];
    let mut borrow = 0i16;
    for i in (0..32).rev() {
        let diff = a[i] as i16 - b[i] as i16 - borrow;
        if diff < 0 {
            result[i] = (diff + 256) as u8;
            borrow = 1;
        } else {
            result[i] = diff as u8;
            borrow = 0;
        }
    }
    if borrow != 0 {
        [0u8; 32] // b > a
    } else {
        result
    }
}

/// Compare two 256-bit big-endian integers (cumulative chain work).
pub fn cmp_work(a: &[u8; 32], b: &[u8; 32]) -> std::cmp::Ordering {
    // Big-endian byte order makes lexicographic comparison numeric.
    a.cmp(b)
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
    /// Hashes of blocks durably marked consensus-invalid (mirror of
    /// `CF_INVALID`, loaded at open). The set stays tiny — one entry per
    /// rejected rival-chain block — so membership checks on the hot header
    /// path are allocation-free and never touch RocksDB.
    invalid_set: std::sync::RwLock<std::collections::HashSet<BlockHash>>,
    /// Bumped on every invalid-marker mutation. Lets caches derived from the
    /// marker set (e.g. HeaderSync's branch-taint memo) detect external
    /// changes — `invalidateblock`/`reconsiderblock` RPCs, capitulation —
    /// and invalidate themselves.
    invalid_generation: std::sync::atomic::AtomicU64,
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
            ColumnFamilyDescriptor::new(CF_INVALID, Options::default()),
        ];

        let db = DB::open_cf_descriptors(&db_opts, path, cf_descriptors)?;
        let index = HeaderIndex {
            db: Arc::new(db),
            invalid_set: std::sync::RwLock::new(std::collections::HashSet::new()),
            invalid_generation: std::sync::atomic::AtomicU64::new(0),
        };
        index.load_invalid_set()?;
        Ok(index)
    }

    /// Populate the in-memory invalid-hash set from `CF_INVALID`.
    fn load_invalid_set(&self) -> StorageResult<()> {
        let cf = self.cf(CF_INVALID)?;
        let mut set = std::collections::HashSet::new();
        for entry in self.db.iterator_cf(&cf, rocksdb::IteratorMode::Start) {
            let (key, _) = entry?;
            set.insert(hash_from_bytes(&key)?);
        }
        if !set.is_empty() {
            info!(count = set.len(), "Loaded invalid-block markers");
        }
        *self.invalid_set.write().expect("invalid_set lock poisoned") = set;
        Ok(())
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

        // Seed prev_hash (and its cumulative chain work) from the block
        // before our scan window. Like the linkage check, this trusts the
        // deep history — corruption there would have been caught earlier.
        let mut prev_hash = if start_height > 0 {
            self.get_hash_at_height(start_height.saturating_sub(1))?
        } else {
            None
        };
        let mut prev_work: Option<[u8; 32]> = match prev_hash {
            Some(h) => self.get_header(&h)?.map(|s| s.chain_work),
            None => None,
        };
        // Headers whose stored cumulative chain work mismatches the
        // recomputed value — rewritten in one batch before returning.
        let mut work_repairs: Vec<(BlockHash, StoredHeader)> = Vec::new();
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
                    self.apply_work_repairs(&work_repairs)?;
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
                    self.apply_work_repairs(&work_repairs)?;
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
                self.apply_work_repairs(&work_repairs)?;
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
                    self.apply_work_repairs(&work_repairs)?;
                    return Ok((height - 1, best_height));
                }
            }

            // Verify cumulative chain work. A crash can leave a header's data
            // missing while descendants (stored with their own chain work)
            // survive; if those descendants were ever recomputed against a
            // missing parent, their stored work restarts from ~zero. Stale
            // low-work entries silently poison every later header built on
            // them: the tip's cumulative work falls below nMinimumChainWork
            // and header sync / block download wedge permanently. Recompute
            // from the previous header's (possibly repaired) work and rewrite
            // any mismatch.
            match prev_work {
                Some(pw) => {
                    let block_work = stored.header.target().to_work().to_be_bytes();
                    let expected = add_work(&pw, &block_work);
                    if stored.chain_work != expected {
                        let mut fixed = stored.clone();
                        fixed.chain_work = expected;
                        work_repairs.push((hash, fixed));
                    }
                    prev_work = Some(expected);
                }
                // No trusted baseline (seed header missing, or window starts
                // at genesis): adopt the first stored value and verify the
                // rest of the window relative to it.
                None => prev_work = Some(stored.chain_work),
            }

            prev_hash = Some(hash);
            checked = height;
        }

        // Headers-first sync stores headers *beyond* the validated tip, and
        // HeaderSync seeds its cumulative work from the HEADER tip — so
        // corrupt chain work up there re-wedges sync even when everything at
        // or below the validated tip is clean (observed on mainnet: a wedged
        // run kept accepting headers above its stuck validated tip, all built
        // on poisoned work). Extend the chain-work verification to the header
        // tip. Structural problems here just end the scan — headers above the
        // validated tip are healed by normal header re-sync, not truncation.
        let header_tip_height = self.get_header_tip_height()?.unwrap_or(best_height);
        for height in (best_height + 1)..=header_tip_height {
            let Some(hash) = self.get_hash_at_height(height)? else {
                break;
            };
            let Some(stored) = self.get_header(&hash)? else {
                break;
            };
            if stored.height != height {
                break;
            }
            if let Some(expected_prev) = prev_hash {
                if stored.header.prev_blockhash != expected_prev {
                    break;
                }
            }
            match prev_work {
                Some(pw) => {
                    let block_work = stored.header.target().to_work().to_be_bytes();
                    let expected = add_work(&pw, &block_work);
                    if stored.chain_work != expected {
                        let mut fixed = stored.clone();
                        fixed.chain_work = expected;
                        work_repairs.push((hash, fixed));
                    }
                    prev_work = Some(expected);
                }
                None => prev_work = Some(stored.chain_work),
            }
            prev_hash = Some(hash);
        }

        self.apply_work_repairs(&work_repairs)?;
        Ok((checked, best_height))
    }

    /// Rewrite headers whose stored cumulative chain work was found
    /// inconsistent by `verify_chain_integrity`. Hash→header data only —
    /// the height→hash index for these heights was already verified.
    fn apply_work_repairs(&self, repairs: &[(BlockHash, StoredHeader)]) -> StorageResult<()> {
        if repairs.is_empty() {
            return Ok(());
        }
        warn!(
            count = repairs.len(),
            first_height = repairs.first().map(|(_, s)| s.height),
            last_height = repairs.last().map(|(_, s)| s.height),
            "Repairing headers with inconsistent cumulative chain work"
        );
        self.insert_headers_hash_only(repairs)
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

    /// Durably mark a block hash as consensus-invalid (`INVALID_REASON_*`).
    ///
    /// The marker is WAL-flushed before returning: it is what keeps the node
    /// from re-adopting (and re-wedging on) a heavier invalid chain across
    /// restarts, so it must never be lost to a crash.
    pub fn mark_invalid(&self, hash: &BlockHash, height: u32, reason: u8) -> StorageResult<()> {
        let cf = self.cf(CF_INVALID)?;
        let mut value = [0u8; 5];
        value[0] = reason;
        value[1..5].copy_from_slice(&height.to_le_bytes());
        self.db.put_cf(&cf, hash_bytes(hash), value)?;
        self.flush_wal()?;
        self.invalid_set
            .write()
            .expect("invalid_set lock poisoned")
            .insert(*hash);
        self.invalid_generation
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        warn!(%hash, height, reason, "Marked block consensus-invalid");
        Ok(())
    }

    /// Current invalid-marker generation; changes whenever a marker is added
    /// or removed. Compare-and-refresh point for derived caches.
    pub fn invalid_generation(&self) -> u64 {
        self.invalid_generation
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Remove a single invalid-block marker (`reconsiderblock`). No-op if
    /// the hash was not marked.
    pub fn clear_invalid(&self, hash: &BlockHash) -> StorageResult<()> {
        let cf = self.cf(CF_INVALID)?;
        self.db.delete_cf(&cf, hash_bytes(hash))?;
        self.flush_wal()?;
        let removed = self
            .invalid_set
            .write()
            .expect("invalid_set lock poisoned")
            .remove(hash);
        if removed {
            self.invalid_generation
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            info!(%hash, "Cleared invalid-block marker");
        }
        Ok(())
    }

    /// Whether `hash` has been marked consensus-invalid. Memory-only; never
    /// touches RocksDB.
    pub fn is_invalid(&self, hash: &BlockHash) -> bool {
        self.invalid_set
            .read()
            .expect("invalid_set lock poisoned")
            .contains(hash)
    }

    /// Read a block's invalid marker: `(height, reason)`.
    pub fn get_invalid(&self, hash: &BlockHash) -> StorageResult<Option<(u32, u8)>> {
        let cf = self.cf(CF_INVALID)?;
        match self.db.get_cf(&cf, hash_bytes(hash))? {
            Some(data) => {
                if data.len() != 5 {
                    return Err(StorageError::Serialization(
                        "invalid marker data length".into(),
                    ));
                }
                let reason = data[0];
                let height =
                    u32::from_le_bytes(data[1..5].try_into().expect("length checked above"));
                Ok(Some((height, reason)))
            }
            None => Ok(None),
        }
    }

    /// All invalid markers as `(hash, height, reason)`.
    pub fn iter_invalid(&self) -> StorageResult<Vec<(BlockHash, u32, u8)>> {
        let cf = self.cf(CF_INVALID)?;
        let mut out = Vec::new();
        for entry in self.db.iterator_cf(&cf, rocksdb::IteratorMode::Start) {
            let (key, value) = entry?;
            if value.len() != 5 {
                return Err(StorageError::Serialization(
                    "invalid marker data length".into(),
                ));
            }
            let height = u32::from_le_bytes(value[1..5].try_into().expect("length checked above"));
            out.push((hash_from_bytes(&key)?, height, value[0]));
        }
        Ok(out)
    }

    /// Number of invalid-block markers.
    pub fn invalid_count(&self) -> usize {
        self.invalid_set
            .read()
            .expect("invalid_set lock poisoned")
            .len()
    }

    /// Remove every invalid-block marker (operator capitulation: the rival
    /// chain must become adoptable again). A genuinely invalid block simply
    /// fails connect and gets re-marked, so clearing everything is safe.
    pub fn clear_all_invalid(&self) -> StorageResult<()> {
        let cf = self.cf(CF_INVALID)?;
        let mut batch = WriteBatch::default();
        let mut cleared = 0usize;
        for entry in self.db.iterator_cf(&cf, rocksdb::IteratorMode::Start) {
            let (key, _) = entry?;
            batch.delete_cf(&cf, key);
            cleared += 1;
        }
        self.db.write(batch)?;
        self.flush_wal()?;
        self.invalid_set
            .write()
            .expect("invalid_set lock poisoned")
            .clear();
        self.invalid_generation
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if cleared > 0 {
            info!(cleared, "Cleared all invalid-block markers");
        }
        Ok(())
    }

    /// Walk `prev_blockhash` links from `tip` looking for marked-invalid
    /// ancestors. Returns the *earliest* (lowest-height) invalid block on the
    /// branch, or `None` if the branch is clean.
    ///
    /// Short-circuits once the walk lands on the canonical chain at or below
    /// `validated_height` (everything below a validated canonical block is
    /// clean by construction), and gives up with a warning after `max_walk`
    /// steps so a pathological header chain cannot stall the caller.
    pub fn first_invalid_ancestor(
        &self,
        tip: &BlockHash,
        validated_height: u32,
        max_walk: u32,
    ) -> StorageResult<Option<(BlockHash, u32)>> {
        if self
            .invalid_set
            .read()
            .expect("invalid_set lock poisoned")
            .is_empty()
        {
            return Ok(None);
        }
        let mut current_hash = *tip;
        let mut found = None;
        for _ in 0..max_walk {
            let stored = match self.get_header(&current_hash)? {
                Some(s) => s,
                None => return Ok(found), // branch root unknown; report what we saw
            };
            if self.is_invalid(&current_hash) {
                found = Some((current_hash, stored.height));
            }
            if stored.height <= validated_height {
                if let Some(canonical) = self.get_hash_at_height(stored.height)? {
                    if canonical == current_hash {
                        return Ok(found);
                    }
                }
            }
            if stored.height == 0 {
                return Ok(found);
            }
            current_hash = stored.header.prev_blockhash;
        }
        warn!(
            %tip,
            max_walk,
            "first_invalid_ancestor walk bound hit before reaching canonical chain"
        );
        Ok(found)
    }

    /// Re-point `CF_HEIGHT_INDEX` at the branch ending in `tip_hash`, walking
    /// prev links until the index entry already matches (the branch has merged
    /// into the canonical mapping). Returns `(tip_height, entries_fixed)`.
    ///
    /// Used after a failed reorg: the reorg's connect phase rewrites height
    /// entries to the (now known-invalid) rival chain before its blocks fail
    /// validation, and the index must be restored to our chain before the
    /// header tip is reset.
    pub fn restore_branch_height_index(&self, tip_hash: &BlockHash) -> StorageResult<(u32, u32)> {
        let tip = self.get_header(tip_hash)?.ok_or_else(|| {
            StorageError::Serialization(format!(
                "restore_branch_height_index: unknown tip {tip_hash}"
            ))
        })?;
        let cf_height = self.cf(CF_HEIGHT_INDEX)?;
        let mut batch = WriteBatch::default();
        let mut fixed = 0u32;
        let mut current_hash = *tip_hash;
        let mut current = tip.clone();
        loop {
            match self.get_hash_at_height(current.height)? {
                Some(h) if h == current_hash => break, // canonical from here down
                _ => {
                    batch.put_cf(
                        &cf_height,
                        current.height.to_be_bytes(),
                        hash_bytes(&current_hash),
                    );
                    fixed += 1;
                }
            }
            if current.height == 0 {
                break;
            }
            current_hash = current.header.prev_blockhash;
            current = match self.get_header(&current_hash)? {
                // Defensive: heights must strictly decrease along prev links.
                Some(parent) if parent.height < current.height => parent,
                _ => {
                    return Err(StorageError::Serialization(format!(
                        "restore_branch_height_index: broken prev link at {current_hash}"
                    )))
                }
            };
        }
        self.db.write(batch)?;
        info!(
            tip = %tip_hash,
            height = tip.height,
            fixed,
            "Restored height index to branch"
        );
        Ok((tip.height, fixed))
    }

    /// Persist the operator's decision to abandon BIP-110 ("abandon minority
    /// chain"). WAL-flushed before returning — the flag must survive the
    /// shutdown that immediately follows it.
    pub fn set_bip110_abandoned(&self, unix_ts: u64) -> StorageResult<()> {
        let cf = self.cf(CF_META)?;
        self.db
            .put_cf(&cf, META_BIP110_ABANDONED, unix_ts.to_le_bytes())?;
        self.flush_wal()?;
        warn!(unix_ts, "BIP-110 abandoned flag persisted");
        Ok(())
    }

    /// Read the BIP-110 abandoned flag (unix timestamp of the decision).
    pub fn get_bip110_abandoned(&self) -> StorageResult<Option<u64>> {
        let cf = self.cf(CF_META)?;
        match self.db.get_cf(&cf, META_BIP110_ABANDONED)? {
            Some(data) => {
                let ts = u64::from_le_bytes(data.try_into().map_err(|_| {
                    StorageError::Serialization("invalid bip110_abandoned bytes".into())
                })?);
                Ok(Some(ts))
            }
            None => Ok(None),
        }
    }

    /// Persist the split monitor's tracked rival tips (opaque serialized
    /// blob) so a restart mid-split resumes with the split visible instead
    /// of waiting for the next rival header batch.
    pub fn set_split_rival_tips(&self, blob: &[u8]) -> StorageResult<()> {
        let cf = self.cf(CF_META)?;
        self.db.put_cf(&cf, META_SPLIT_RIVAL_TIPS, blob)?;
        Ok(())
    }

    /// Read the persisted rival-tip blob (see `set_split_rival_tips`).
    pub fn get_split_rival_tips(&self) -> StorageResult<Option<Vec<u8>>> {
        let cf = self.cf(CF_META)?;
        Ok(self.db.get_cf(&cf, META_SPLIT_RIVAL_TIPS)?)
    }

    /// Remove the persisted rival-tip blob (capitulation, or nothing left
    /// to track).
    pub fn clear_split_rival_tips(&self) -> StorageResult<()> {
        let cf = self.cf(CF_META)?;
        self.db.delete_cf(&cf, META_SPLIT_RIVAL_TIPS)?;
        Ok(())
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

    /// Headers stored with corrupt (from-zero) cumulative chain work must be
    /// repaired by the startup integrity scan. Crash artifact: a header's
    /// data goes missing while its descendants survive with chain work that
    /// restarted from zero — every later header builds on the poisoned value
    /// and the tip falls below nMinimumChainWork, wedging sync permanently.
    #[test]
    fn verify_chain_integrity_repairs_corrupt_chain_work() {
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

        let h0 = mk(BlockHash::all_zeros(), 0);
        let h1 = mk(h0.block_hash(), 1);
        let h2 = mk(h1.block_hash(), 2);
        let h3 = mk(h2.block_hash(), 3);

        let work = |h: &bitcoin::block::Header| h.target().to_work().to_be_bytes();
        let w1 = work(&h1); // genesis convention: h0 contributes zero
        let w2 = add_work(&w1, &work(&h2));
        let w3 = add_work(&w2, &work(&h3));

        // h2 and h3 stored with from-zero cumulative work (corrupt).
        for (header, height, cw) in [
            (h0, 0u32, [0u8; 32]),
            (h1, 1, w1),
            (h2, 2, work(&h2)),
            (h3, 3, work(&h3)),
        ] {
            index
                .insert_header(
                    &header.block_hash(),
                    &StoredHeader {
                        header,
                        height,
                        chain_work: cw,
                    },
                )
                .unwrap();
        }
        // h3 is a header BEYOND the validated tip (headers-first sync) — the
        // repair must reach it, since HeaderSync seeds its cumulative work
        // from the header tip.
        index.set_best_tip(&h2.block_hash(), 2).unwrap();
        index.set_header_tip(&h3.block_hash(), 3).unwrap();

        let (verified, best) = index.verify_chain_integrity().unwrap();
        assert_eq!((verified, best), (2, 2));

        let cw_at = |h: &bitcoin::block::Header| {
            index
                .get_header(&h.block_hash())
                .unwrap()
                .unwrap()
                .chain_work
        };
        assert_eq!(cw_at(&h2), w2, "corrupt chain work must be repaired");
        assert_eq!(cw_at(&h3), w3, "repair must cascade to descendants");
        assert_eq!(cw_at(&h1), w1, "correct entries must be untouched");
    }

    /// Build a header with the standard test shape (regtest bits, unique by
    /// `nonce`).
    fn mk_header(prev: BlockHash, nonce: u32) -> bitcoin::block::Header {
        bitcoin::block::Header {
            version: bitcoin::block::Version::from_consensus(4),
            prev_blockhash: prev,
            merkle_root: bitcoin::TxMerkleNode::all_zeros(),
            time: 1_700_000_000 + nonce,
            bits: bitcoin::CompactTarget::from_consensus(0x207fffff),
            nonce,
        }
    }

    fn store(index: &HeaderIndex, header: bitcoin::block::Header, height: u32) {
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

    #[test]
    fn test_invalid_markers_survive_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let h1 = mk_header(BlockHash::all_zeros(), 1);
        let hash = h1.block_hash();

        {
            let index = HeaderIndex::open(dir.path()).unwrap();
            assert!(!index.is_invalid(&hash));
            index
                .mark_invalid(&hash, 116, INVALID_REASON_BIP110)
                .unwrap();
            assert!(index.is_invalid(&hash));
            assert_eq!(index.get_invalid(&hash).unwrap(), Some((116, 1)));
            assert_eq!(index.invalid_count(), 1);
        }

        // Reopen: the in-memory set must be reloaded from CF_INVALID.
        let index = HeaderIndex::open(dir.path()).unwrap();
        assert!(index.is_invalid(&hash));
        assert_eq!(
            index.iter_invalid().unwrap(),
            vec![(hash, 116, INVALID_REASON_BIP110)]
        );

        // Clearing empties both the CF and the set, and survives reopen.
        index.clear_all_invalid().unwrap();
        assert!(!index.is_invalid(&hash));
        assert_eq!(index.invalid_count(), 0);
        drop(index);
        let index = HeaderIndex::open(dir.path()).unwrap();
        assert!(!index.is_invalid(&hash));
        assert!(index.iter_invalid().unwrap().is_empty());
    }

    #[test]
    fn test_first_invalid_ancestor_on_fork() {
        let dir = tempfile::tempdir().unwrap();
        let index = HeaderIndex::open(dir.path()).unwrap();

        // Canonical chain c1..c3 (height-indexed), fork f2..f3 off c1
        // (hash-only, like real fork headers).
        let c1 = mk_header(BlockHash::all_zeros(), 1);
        let c2 = mk_header(c1.block_hash(), 2);
        let c3 = mk_header(c2.block_hash(), 3);
        for (h, ht) in [(c1, 1u32), (c2, 2), (c3, 3)] {
            store(&index, h, ht);
        }
        let f2 = mk_header(c1.block_hash(), 102);
        let f3 = mk_header(f2.block_hash(), 103);
        index
            .insert_headers_hash_only(&[
                (
                    f2.block_hash(),
                    StoredHeader {
                        header: f2,
                        height: 2,
                        chain_work: [0u8; 32],
                    },
                ),
                (
                    f3.block_hash(),
                    StoredHeader {
                        header: f3,
                        height: 3,
                        chain_work: [0u8; 32],
                    },
                ),
            ])
            .unwrap();

        // No markers at all → clean, no walk.
        assert!(index
            .first_invalid_ancestor(&f3.block_hash(), 3, 100)
            .unwrap()
            .is_none());

        index
            .mark_invalid(&f2.block_hash(), 2, INVALID_REASON_CONSENSUS)
            .unwrap();

        // Fork tip finds the earliest invalid ancestor.
        assert_eq!(
            index
                .first_invalid_ancestor(&f3.block_hash(), 3, 100)
                .unwrap(),
            Some((f2.block_hash(), 2))
        );
        // The marked block itself is found from itself.
        assert_eq!(
            index
                .first_invalid_ancestor(&f2.block_hash(), 3, 100)
                .unwrap(),
            Some((f2.block_hash(), 2))
        );
        // The canonical tip is clean (short-circuits on the height index).
        assert!(index
            .first_invalid_ancestor(&c3.block_hash(), 3, 100)
            .unwrap()
            .is_none());
    }

    #[test]
    fn test_restore_branch_height_index() {
        let dir = tempfile::tempdir().unwrap();
        let index = HeaderIndex::open(dir.path()).unwrap();

        let c1 = mk_header(BlockHash::all_zeros(), 1);
        let c2 = mk_header(c1.block_hash(), 2);
        let c3 = mk_header(c2.block_hash(), 3);
        for (h, ht) in [(c1, 1u32), (c2, 2), (c3, 3)] {
            store(&index, h, ht);
        }

        // Simulate a failed reorg clobbering heights 2-3 with fork hashes.
        let f2 = mk_header(c1.block_hash(), 102);
        let f3 = mk_header(f2.block_hash(), 103);
        index.set_height_hash(2, &f2.block_hash()).unwrap();
        index.set_height_hash(3, &f3.block_hash()).unwrap();

        let (tip_height, fixed) = index.restore_branch_height_index(&c3.block_hash()).unwrap();
        assert_eq!(tip_height, 3);
        assert_eq!(fixed, 2, "only the clobbered entries are rewritten");
        assert_eq!(index.get_hash_at_height(2).unwrap(), Some(c2.block_hash()));
        assert_eq!(index.get_hash_at_height(3).unwrap(), Some(c3.block_hash()));
        assert_eq!(index.get_hash_at_height(1).unwrap(), Some(c1.block_hash()));

        // Idempotent: nothing left to fix.
        let (_, fixed) = index.restore_branch_height_index(&c3.block_hash()).unwrap();
        assert_eq!(fixed, 0);
    }

    #[test]
    fn test_work_arithmetic() {
        let mut a = [0u8; 32];
        a[31] = 10;
        let mut b = [0u8; 32];
        b[31] = 3;

        let diff = sub_work(&a, &b);
        assert_eq!(diff[31], 7);
        assert_eq!(&diff[..31], &[0u8; 31][..]);

        // Saturates at zero when b > a.
        assert_eq!(sub_work(&b, &a), [0u8; 32]);

        // Borrow propagation across bytes: 0x0100 - 0x01 = 0xff.
        let mut c = [0u8; 32];
        c[30] = 1;
        let mut d = [0u8; 32];
        d[31] = 1;
        let diff = sub_work(&c, &d);
        assert_eq!(diff[31], 0xff);
        assert_eq!(diff[30], 0);

        assert_eq!(cmp_work(&a, &b), std::cmp::Ordering::Greater);
        assert_eq!(cmp_work(&b, &a), std::cmp::Ordering::Less);
        assert_eq!(cmp_work(&a, &a), std::cmp::Ordering::Equal);
    }

    #[test]
    fn test_invalid_generation_and_single_clear() {
        let dir = tempfile::tempdir().unwrap();
        let index = HeaderIndex::open(dir.path()).unwrap();
        let h1 = mk_header(BlockHash::all_zeros(), 1);
        let h2 = mk_header(h1.block_hash(), 2);

        let g0 = index.invalid_generation();
        index
            .mark_invalid(&h1.block_hash(), 1, INVALID_REASON_MANUAL)
            .unwrap();
        index
            .mark_invalid(&h2.block_hash(), 2, INVALID_REASON_MANUAL)
            .unwrap();
        assert!(index.invalid_generation() > g0, "marks bump the generation");

        // Single clear removes only its marker and bumps the generation.
        let g1 = index.invalid_generation();
        index.clear_invalid(&h1.block_hash()).unwrap();
        assert!(!index.is_invalid(&h1.block_hash()));
        assert!(index.is_invalid(&h2.block_hash()));
        assert!(index.invalid_generation() > g1);

        // Clearing an unmarked hash is a no-op (no generation bump).
        let g2 = index.invalid_generation();
        index.clear_invalid(&h1.block_hash()).unwrap();
        assert_eq!(index.invalid_generation(), g2);
    }

    #[test]
    fn test_split_rival_tips_blob_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let index = HeaderIndex::open(dir.path()).unwrap();
        assert!(index.get_split_rival_tips().unwrap().is_none());
        let blob = vec![7u8; 68];
        index.set_split_rival_tips(&blob).unwrap();
        assert_eq!(index.get_split_rival_tips().unwrap(), Some(blob));
        index.clear_split_rival_tips().unwrap();
        assert!(index.get_split_rival_tips().unwrap().is_none());
    }

    #[test]
    fn test_bip110_abandoned_flag_survives_reopen() {
        let dir = tempfile::tempdir().unwrap();
        {
            let index = HeaderIndex::open(dir.path()).unwrap();
            assert_eq!(index.get_bip110_abandoned().unwrap(), None);
            index.set_bip110_abandoned(1_752_537_600).unwrap();
            assert_eq!(index.get_bip110_abandoned().unwrap(), Some(1_752_537_600));
        }
        let index = HeaderIndex::open(dir.path()).unwrap();
        assert_eq!(index.get_bip110_abandoned().unwrap(), Some(1_752_537_600));
    }
}
