use bitcoin::hashes::Hash;
use bitcoin::OutPoint;
use dashmap::DashMap;
use rocksdb::{BlockBasedOptions, Cache, ColumnFamilyDescriptor, Options, WriteBatch, DB};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::{Arc, Mutex};
use tracing::{debug, info};

use crate::error::{StorageError, StorageResult};
use crate::fast_hash::{FastHashMap, FastOutpointBuildHasher};

const CF_UTXO: &str = "utxo";
const CF_UNDO: &str = "undo";
const CF_META: &str = "utxo_meta";

/// A single unspent transaction output entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UtxoEntry {
    /// Output value in satoshis.
    pub amount: u64,
    /// The scriptPubKey of this output.
    pub script_pubkey: Vec<u8>,
    /// Block height where this output was created.
    pub height: u32,
    /// Whether this output is from a coinbase transaction.
    pub is_coinbase: bool,
}

impl UtxoEntry {
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&self.amount.to_le_bytes());
        buf.extend_from_slice(&self.height.to_le_bytes());
        buf.push(if self.is_coinbase { 1 } else { 0 });
        buf.extend_from_slice(&(self.script_pubkey.len() as u32).to_le_bytes());
        buf.extend_from_slice(&self.script_pubkey);
        buf
    }

    pub fn deserialize(data: &[u8]) -> StorageResult<Self> {
        if data.len() < 17 {
            return Err(StorageError::Serialization("UTXO entry too short".into()));
        }
        let amount = u64::from_le_bytes(data[0..8].try_into().expect("length checked above"));
        let height = u32::from_le_bytes(data[8..12].try_into().expect("length checked above"));
        let is_coinbase = data[12] != 0;
        let script_len =
            u32::from_le_bytes(data[13..17].try_into().expect("length checked above")) as usize;
        if data.len() < 17 + script_len {
            return Err(StorageError::Serialization(
                "UTXO entry script truncated".into(),
            ));
        }
        let script_pubkey = data[17..17 + script_len].to_vec();
        Ok(UtxoEntry {
            amount,
            script_pubkey,
            height,
            is_coinbase,
        })
    }
}

/// Serializes an OutPoint as 36 bytes: [32 bytes txid][4 bytes vout LE].
fn outpoint_key(outpoint: &OutPoint) -> [u8; 36] {
    let mut key = [0u8; 36];
    key[0..32].copy_from_slice(AsRef::<[u8]>::as_ref(&outpoint.txid));
    key[32..36].copy_from_slice(&outpoint.vout.to_le_bytes());
    key
}

/// A spent UTXO entry for undo data: the outpoint and its previous value.
#[derive(Debug, Clone)]
pub struct SpentUtxo {
    pub outpoint: OutPoint,
    pub entry: UtxoEntry,
}

/// Complete undo data for a block, sufficient to reverse it without the full block.
#[derive(Debug, Clone)]
pub struct UndoData {
    /// UTXOs that were consumed (spent) by this block — re-insert on rollback.
    pub spent_utxos: Vec<SpentUtxo>,
    /// Outpoints created by this block — remove on rollback.
    pub created_outpoints: Vec<OutPoint>,
    /// Hash of the previous block — for walking the chain backward during rollback.
    pub prev_block_hash: Option<[u8; 32]>,
}

/// Batch of UTXO changes to be applied atomically.
pub struct UtxoBatch {
    pub inserts: Vec<(OutPoint, UtxoEntry)>,
    pub removals: Vec<OutPoint>,
    /// The UTXO entries that were spent (for undo data).
    pub spent_utxos: Vec<SpentUtxo>,
}

impl Default for UtxoBatch {
    fn default() -> Self {
        Self::new()
    }
}

impl UtxoBatch {
    pub fn new() -> Self {
        UtxoBatch {
            inserts: Vec::new(),
            removals: Vec::new(),
            spent_utxos: Vec::new(),
        }
    }
}

/// Default cache capacity: 2M entries (~1 GB for typical UTXOs).
/// Large cache is critical for IBD performance — the UTXO set grows to 30M+
/// entries on mainnet, and every cache miss on HDD costs 5–15ms of random I/O.
/// 2M entries gives ~6% coverage which dramatically reduces disk reads for
/// recently-created UTXOs (which are the most likely to be spent soon).
const DEFAULT_CACHE_SIZE: usize = 2_000_000;

/// Default RocksDB block cache size in bytes (1 GB).
const DEFAULT_BLOCK_CACHE_MB: usize = 1024;

/// Number of blocks between automatic disk flushes (coalesced writes).
/// This is only a crash-recovery bound: on crash, at most this many blocks
/// need to be re-validated. The primary flush trigger is the byte budget
/// (`write_buffer_budget`, derived from dbcache) checked in `apply_batch` —
/// like Bitcoin Core's dbcache, the buffer acts as a write-back cache so
/// coins created and spent within the window never touch disk.
const FLUSH_INTERVAL: u32 = 10_000;

/// Default write-buffer byte budget when no dbcache is configured (256 MB).
const DEFAULT_WRITE_BUFFER_BUDGET: usize = 256 * 1024 * 1024;

/// Approximate in-memory cost of a buffered insert, excluding the script:
/// 36-byte key + UtxoEntry fixed fields + Vec/HashMap bookkeeping overhead.
const INSERT_BASE_COST: usize = 36 + 17 + 64;

/// Approximate in-memory cost of a buffered deletion tombstone:
/// 36-byte key + HashSet bookkeeping overhead.
const DELETION_COST: usize = 36 + 48;

/// Approximate fixed overhead of a buffered undo record (hash + Vec bookkeeping).
const UNDO_BASE_COST: usize = 32 + 48;

/// Approximate in-memory cost of one buffered insert.
fn insert_cost(entry: &UtxoEntry) -> usize {
    INSERT_BASE_COST + entry.script_pubkey.len()
}

/// Buffered UTXO changes waiting to be flushed to disk.
struct WriteBuffer {
    /// Pending changes in a single map (Core #33602 idea): `Some(entry)` is
    /// an insert/update, `None` a deletion tombstone. One map means one
    /// probe + one hash per `get`/`contains`/`prefetch`/`apply_batch` key
    /// instead of two against separate insert/deletion collections.
    entries: FastHashMap<[u8; 36], Option<UtxoEntry>>,
    /// Number of `Some` values in `entries` (kept incrementally so
    /// `memory_stats` doesn't scan the map).
    insert_count: usize,
    /// Number of `None` tombstones in `entries`.
    deletion_count: usize,
    /// Buffered undo data (block_hash -> serialized undo bytes).
    undo_buffer: Vec<([u8; 32], Vec<u8>)>,
    /// Approximate memory held by the buffer (inserts + deletions + undo data).
    bytes: usize,
    /// Number of blocks since last flush.
    blocks_since_flush: u32,
    /// Latest chain height/hash to persist atomically with the next flush.
    pending_flush_height: Option<u32>,
    pending_flush_hash: Option<[u8; 32]>,
}

impl WriteBuffer {
    fn new() -> Self {
        WriteBuffer {
            entries: FastHashMap::default(),
            insert_count: 0,
            deletion_count: 0,
            undo_buffer: Vec::new(),
            bytes: 0,
            blocks_since_flush: 0,
            pending_flush_height: None,
            pending_flush_hash: None,
        }
    }

    fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Scripts up to this length are stored inline in [`CoinScript`] (no heap
/// allocation). Covers the overwhelming majority of scriptPubKeys: P2WPKH 22,
/// P2SH 23, P2PKH 25, P2WSH/P2TR 34 bytes (Core #32279/#25325 analogue).
const INLINE_SCRIPT_MAX: usize = 36;

/// Script storage for cached coins: inline up to [`INLINE_SCRIPT_MAX`] bytes,
/// heap fallback for larger scripts. Kills one heap allocation per cached
/// coin for ~99% of outputs and packs more cache entries per GB of dbcache.
#[derive(Debug, Clone)]
enum CoinScript {
    Inline {
        len: u8,
        buf: [u8; INLINE_SCRIPT_MAX],
    },
    Heap(Box<[u8]>),
}

impl CoinScript {
    fn new(script: &[u8]) -> Self {
        if script.len() <= INLINE_SCRIPT_MAX {
            let mut buf = [0u8; INLINE_SCRIPT_MAX];
            buf[..script.len()].copy_from_slice(script);
            CoinScript::Inline {
                len: script.len() as u8,
                buf,
            }
        } else {
            CoinScript::Heap(script.into())
        }
    }

    fn as_bytes(&self) -> &[u8] {
        match self {
            CoinScript::Inline { len, buf } => &buf[..*len as usize],
            CoinScript::Heap(b) => b,
        }
    }
}

/// Memory-efficient UTXO representation for the in-memory cache.
/// Small scripts are stored inline (see [`CoinScript`]); large ones fall
/// back to a Box<[u8]> (ptr + len, no capacity field).
/// Packs height and coinbase flag into a single u32.
#[derive(Debug, Clone)]
struct CompactCoin {
    amount: u64,              // 8 bytes
    height_and_coinbase: u32, // 4 bytes (height << 1 | coinbase)
    script: CoinScript,       // 40 bytes inline, no heap alloc for ≤36-byte scripts
}

impl CompactCoin {
    fn new(entry: &UtxoEntry) -> Self {
        CompactCoin {
            amount: entry.amount,
            height_and_coinbase: (entry.height << 1) | (entry.is_coinbase as u32),
            script: CoinScript::new(&entry.script_pubkey),
        }
    }

    fn to_entry(&self) -> UtxoEntry {
        UtxoEntry {
            amount: self.amount,
            script_pubkey: self.script.as_bytes().to_vec(),
            height: self.height_and_coinbase >> 1,
            is_coinbase: (self.height_and_coinbase & 1) != 0,
        }
    }
}

/// Point-in-time memory usage of the UTXO subsystem (see [`UtxoSet::memory_stats`]).
#[derive(Debug, Clone, Copy)]
pub struct UtxoMemoryStats {
    /// `(bytes, insert_count, deletion_count)` of the write buffer, or `None`
    /// if the buffer mutex was contended (flush in progress).
    pub write_buffer: Option<(usize, usize, usize)>,
    /// Entries currently resident in the DashMap read cache.
    pub cache_entries: usize,
    /// Sum of RocksDB memtable bytes across all column families.
    pub memtable_bytes: u64,
    /// Bytes used in the shared RocksDB block cache.
    pub block_cache_bytes: u64,
}

/// UTXO set backed by RocksDB with a concurrent DashMap cache and coalesced write buffer.
///
/// DashMap provides fine-grained per-shard locking with ~60 bytes per-entry overhead
/// (vs moka's ~300 bytes for LRU/frequency tracking). Combined with CompactCoin's
/// ~75 bytes, total per-entry cost is ~135 bytes — 3.7x more entries in the same RAM.
pub struct UtxoSet {
    db: Arc<DB>,
    cache: DashMap<[u8; 36], CompactCoin, FastOutpointBuildHasher>,
    cache_capacity: usize,
    write_buffer: Mutex<WriteBuffer>,
    /// Byte budget for the write buffer; exceeding it triggers a flush.
    write_buffer_budget: usize,
}

impl UtxoSet {
    /// Resolve a column-family handle, returning an error (instead of
    /// panicking) if it is missing — e.g. a corrupted or incompatible DB.
    fn cf(&self, name: &str) -> StorageResult<&rocksdb::ColumnFamily> {
        self.db
            .cf_handle(name)
            .ok_or_else(|| StorageError::MissingColumnFamily(name.to_string()))
    }

    /// Open a new UTXO set database at the given path.
    ///
    /// `dbcache_mb` controls the total memory budget (in MB) for UTXO caching:
    /// - 60% goes to the coalescing write buffer (write-back cache: coins
    ///   created and spent before a flush never touch disk)
    /// - 25% goes to the RocksDB block cache (SST block data)
    /// - 15% goes to the in-memory entry cache (deserialized UTXO entries in a
    ///   `DashMap`, random eviction when full)
    ///
    /// Pass `None` to use defaults (1 GB block cache, 2M cache entries,
    /// 256 MB write buffer).
    pub fn open(path: &Path, dbcache_mb: Option<u32>) -> StorageResult<Self> {
        let mut db_opts = Options::default();
        db_opts.create_if_missing(true);
        db_opts.create_missing_column_families(true);
        db_opts.set_max_open_files(10_000);

        // HDD optimization: read-ahead during compaction avoids thousands of
        // tiny random reads that destroy throughput on spinning disks.
        db_opts.set_compaction_readahead_size(2 * 1024 * 1024); // 2 MB

        // Compute cache sizes from dbcache budget
        let (block_cache_bytes, lru_entries, write_buffer_budget) = match dbcache_mb {
            Some(mb) => {
                let total = (mb as usize) * 1024 * 1024;
                let bc = total * 25 / 100;
                // ~135 bytes per CompactCoin + DashMap overhead
                let lru = (total * 15 / 100) / 135;
                let wb = total * 60 / 100;
                (bc, lru, wb)
            }
            None => (
                DEFAULT_BLOCK_CACHE_MB * 1024 * 1024,
                DEFAULT_CACHE_SIZE,
                DEFAULT_WRITE_BUFFER_BUDGET,
            ),
        };

        let block_cache = Cache::new_lru_cache(block_cache_bytes);
        let mut table_opts = BlockBasedOptions::default();
        table_opts.set_block_cache(&block_cache);
        // Bloom filter: ~10 bits per key reduces unnecessary disk reads by ~99%.
        // Critical for UTXO lookups during IBD where most reads miss the cache.
        table_opts.set_bloom_filter(10.0, false);
        // 16KB blocks — fewer index lookups and better sequential read
        // efficiency on HDD vs the default 4KB.
        table_opts.set_block_size(16 * 1024);
        // Cache index and filter blocks in the block cache so they don't
        // compete for OS page cache. Critical for large UTXO sets.
        table_opts.set_cache_index_and_filter_blocks(true);
        table_opts.set_pin_l0_filter_and_index_blocks_in_cache(true);

        let mut cf_opts = Options::default();
        cf_opts.set_write_buffer_size(128 * 1024 * 1024); // 128 MB
        cf_opts.set_max_write_buffer_number(4);
        cf_opts.set_level_compaction_dynamic_level_bytes(true);
        cf_opts.set_block_based_table_factory(&table_opts);
        // Larger SST files reduce total file count and index lookups per read.
        cf_opts.set_target_file_size_base(128 * 1024 * 1024); // 128 MB

        let cf_descriptors = vec![
            ColumnFamilyDescriptor::new(CF_UTXO, cf_opts),
            ColumnFamilyDescriptor::new(CF_UNDO, Options::default()),
            ColumnFamilyDescriptor::new(CF_META, Options::default()),
        ];

        // Log the effective memory budget: post-mortem OOM analysis of past
        // runs was blocked on not knowing which dbcache a crashed run used.
        info!(
            dbcache_mb = dbcache_mb.map(|m| m as usize).unwrap_or(0),
            block_cache_mb = block_cache_bytes / (1024 * 1024),
            entry_cache_capacity = lru_entries,
            write_buffer_budget_mb = write_buffer_budget / (1024 * 1024),
            "UTXO set memory budget"
        );

        let db = DB::open_cf_descriptors(&db_opts, path, cf_descriptors)?;
        let cache = DashMap::with_capacity_and_hasher(lru_entries, FastOutpointBuildHasher);
        Ok(UtxoSet {
            db: Arc::new(db),
            cache,
            cache_capacity: lru_entries,
            write_buffer: Mutex::new(WriteBuffer::new()),
            write_buffer_budget,
        })
    }

    /// Open using an existing DB handle (for sharing with HeaderIndex).
    pub fn from_db(db: Arc<DB>) -> Self {
        let cache = DashMap::with_capacity_and_hasher(DEFAULT_CACHE_SIZE, FastOutpointBuildHasher);
        UtxoSet {
            db,
            cache,
            cache_capacity: DEFAULT_CACHE_SIZE,
            write_buffer: Mutex::new(WriteBuffer::new()),
            write_buffer_budget: DEFAULT_WRITE_BUFFER_BUDGET,
        }
    }

    /// Returns true if the UTXO database on disk has no entries.
    pub fn is_db_empty(&self) -> StorageResult<bool> {
        let cf = self.cf(CF_UTXO)?;
        let mut iter = self.db.raw_iterator_cf(&cf);
        iter.seek_to_first();
        Ok(!iter.valid())
    }

    /// Get a UTXO entry by outpoint. Checks write buffer, then cache, then disk.
    pub fn get(&self, outpoint: &OutPoint) -> StorageResult<Option<UtxoEntry>> {
        let key = outpoint_key(outpoint);

        // Check write buffer first (most recent state)
        {
            let wb = self
                .write_buffer
                .lock()
                .expect("UTXO write buffer mutex poisoned");
            match wb.entries.get(&key) {
                Some(None) => return Ok(None), // Deleted in buffer
                Some(Some(entry)) => return Ok(Some(entry.clone())),
                None => {}
            }
        }

        // Check concurrent cache
        if let Some(entry) = self.cache.get(&key) {
            return Ok(Some(entry.to_entry()));
        }

        // Fall through to disk
        let cf = self.cf(CF_UTXO)?;
        match self.db.get_cf(&cf, key)? {
            Some(data) => {
                let entry = UtxoEntry::deserialize(&data)?;
                self.cache.insert(key, CompactCoin::new(&entry));
                Ok(Some(entry))
            }
            None => Ok(None),
        }
    }

    /// Check if a UTXO exists.
    pub fn contains(&self, outpoint: &OutPoint) -> StorageResult<bool> {
        let key = outpoint_key(outpoint);

        // Check write buffer
        {
            let wb = self
                .write_buffer
                .lock()
                .expect("UTXO write buffer mutex poisoned");
            match wb.entries.get(&key) {
                Some(None) => return Ok(false),
                Some(Some(_)) => return Ok(true),
                None => {}
            }
        }

        // Check cache (lock-free)
        if self.cache.contains_key(&key) {
            return Ok(true);
        }

        let cf = self.cf(CF_UTXO)?;
        Ok(self.db.get_cf(&cf, key)?.is_some())
    }

    /// Batch-fetch multiple UTXO entries from disk, populating the cache.
    /// Entries already in the write buffer or cache are skipped (not re-fetched).
    /// This is used to pre-warm the cache before sequential validation.
    pub fn prefetch(&self, outpoints: &[OutPoint]) -> StorageResult<()> {
        // Collect keys that need disk reads (not in write buffer or cache)
        let mut disk_keys: Vec<[u8; 36]> = Vec::new();
        {
            let wb = self
                .write_buffer
                .lock()
                .expect("UTXO write buffer mutex poisoned");
            for outpoint in outpoints {
                let key = outpoint_key(outpoint);
                if wb.entries.contains_key(&key) {
                    continue;
                }
                if self.cache.contains_key(&key) {
                    continue;
                }
                disk_keys.push(key);
            }
        }

        if disk_keys.is_empty() {
            return Ok(());
        }

        // Batch read from RocksDB using multi_get
        let cf = self.cf(CF_UTXO)?;
        let results = self.db.batched_multi_get_cf(
            &cf, &disk_keys, false, // sorted_input
        );

        for (i, result) in results.into_iter().enumerate() {
            match result {
                Ok(Some(data)) => {
                    if let Ok(entry) = UtxoEntry::deserialize(&data) {
                        self.cache.insert(disk_keys[i], CompactCoin::new(&entry));
                    }
                }
                Ok(None) => {} // UTXO doesn't exist
                Err(_) => {}   // Skip errors, individual get() will catch them
            }
        }

        Ok(())
    }

    /// Insert a single UTXO.
    pub fn insert(&self, outpoint: &OutPoint, entry: &UtxoEntry) -> StorageResult<()> {
        let cf = self.cf(CF_UTXO)?;
        let key = outpoint_key(outpoint);
        self.db.put_cf(&cf, key, entry.serialize())?;
        self.cache.insert(key, CompactCoin::new(entry));
        Ok(())
    }

    /// Remove a single UTXO.
    pub fn remove(&self, outpoint: &OutPoint) -> StorageResult<()> {
        let cf = self.cf(CF_UTXO)?;
        let key = outpoint_key(outpoint);
        self.db.delete_cf(&cf, key)?;
        self.cache.remove(&key);
        Ok(())
    }

    /// Apply a batch of UTXO changes. Buffers writes in memory and flushes
    /// to disk when the buffer exceeds its byte budget (or after
    /// FLUSH_INTERVAL blocks as a crash-recovery bound).
    /// Returns `true` if the buffer was flushed to disk, so the caller
    /// can persist the chain tip in sync with the UTXO state.
    /// The returned `bool` is a durability signal, not informational: `true`
    /// means the write buffer flushed to disk and the chain tip MUST be
    /// persisted now to keep on-disk state consistent. Do not discard it.
    pub fn apply_batch(&self, batch: &UtxoBatch) -> StorageResult<bool> {
        let mut wb = self
            .write_buffer
            .lock()
            .expect("UTXO write buffer mutex poisoned");

        // Buffer inserts FIRST, then deletions.
        // Order matters for intra-block spends: if tx A creates output X and
        // tx B spends X in the same block, X is in both batch.inserts and
        // batch.removals.  Processing inserts first then removals ensures the
        // removal wins and X is correctly deleted.
        for (outpoint, entry) in &batch.inserts {
            let key = outpoint_key(outpoint);
            match wb.entries.insert(key, Some(entry.clone())) {
                Some(Some(old)) => wb.bytes = wb.bytes.saturating_sub(insert_cost(&old)),
                Some(None) => {
                    // Cancelled a pending deletion tombstone
                    wb.bytes = wb.bytes.saturating_sub(DELETION_COST);
                    wb.deletion_count -= 1;
                    wb.insert_count += 1;
                }
                None => wb.insert_count += 1,
            }
            wb.bytes += insert_cost(entry);
        }

        // Buffer deletions (processed second so they override intra-block inserts)
        for outpoint in &batch.removals {
            let key = outpoint_key(outpoint);
            match wb.entries.insert(key, None) {
                Some(Some(old)) => {
                    // Cancelled a pending insert
                    wb.bytes = wb.bytes.saturating_sub(insert_cost(&old));
                    wb.insert_count -= 1;
                    wb.deletion_count += 1;
                    wb.bytes += DELETION_COST;
                }
                Some(None) => {} // already a tombstone
                None => {
                    wb.deletion_count += 1;
                    wb.bytes += DELETION_COST;
                }
            }
        }

        wb.blocks_since_flush += 1;
        let should_flush =
            wb.blocks_since_flush >= FLUSH_INTERVAL || wb.bytes > self.write_buffer_budget;

        // Remove spent outpoints from the concurrent cache so reads never see
        // a stale coin. Fresh inserts are NOT cached here: `get()` checks the
        // write buffer before the cache, so caching them would only duplicate
        // memory. Survivors are promoted to the cache at flush time instead.
        for outpoint in &batch.removals {
            self.cache.remove(&outpoint_key(outpoint));
        }

        debug!(
            "Buffered UTXO batch: {} inserts, {} removals (buffer: {} ins, {} del, {} MB, {} blocks since flush)",
            batch.inserts.len(),
            batch.removals.len(),
            wb.insert_count,
            wb.deletion_count,
            wb.bytes / (1024 * 1024),
            wb.blocks_since_flush,
        );

        drop(wb);

        self.maybe_evict_cache();

        if should_flush {
            self.flush_to_disk()?;
            return Ok(true);
        }

        Ok(false)
    }

    /// Snapshot of memory usage for observability (heartbeat logging).
    ///
    /// Write-buffer fields are `None` when the buffer mutex is contended
    /// (e.g. a flush is writing to disk) — the heartbeat must never block
    /// behind a multi-second flush.
    pub fn memory_stats(&self) -> UtxoMemoryStats {
        let write_buffer = self
            .write_buffer
            .try_lock()
            .ok()
            .map(|wb| (wb.bytes, wb.insert_count, wb.deletion_count));

        // Memtable bytes across all column families; the block cache is
        // shared, so read its usage once via the UTXO CF.
        let mut memtable_bytes = 0u64;
        for cf_name in [CF_UTXO, CF_UNDO, CF_META] {
            if let Some(cf) = self.db.cf_handle(cf_name) {
                memtable_bytes += self
                    .db
                    .property_int_value_cf(cf, "rocksdb.cur-size-all-mem-tables")
                    .ok()
                    .flatten()
                    .unwrap_or(0);
            }
        }
        let block_cache_bytes = self
            .db
            .cf_handle(CF_UTXO)
            .and_then(|cf| {
                self.db
                    .property_int_value_cf(cf, "rocksdb.block-cache-usage")
                    .ok()
                    .flatten()
            })
            .unwrap_or(0);

        UtxoMemoryStats {
            write_buffer,
            cache_entries: self.cache.len(),
            memtable_bytes,
            block_cache_bytes,
        }
    }

    /// On-disk SST bytes of the `utxo` and `undo` column families, in that
    /// order (RocksDB `rocksdb.total-sst-files-size` per CF). The two CFs
    /// share one database directory but hold very different data — the live
    /// UTXO set vs. never-pruned per-block undo records (Core's equivalent
    /// lives in blocks/rev*.dat) — so storage reporting wants them split.
    /// Cheap in-memory property reads; 0 for a missing CF or property.
    pub fn cf_disk_sizes(&self) -> (u64, u64) {
        let sst_bytes = |name: &str| {
            self.db
                .cf_handle(name)
                .and_then(|cf| {
                    self.db
                        .property_int_value_cf(cf, "rocksdb.total-sst-files-size")
                        .ok()
                        .flatten()
                })
                .unwrap_or(0)
        };
        (sst_bytes(CF_UTXO), sst_bytes(CF_UNDO))
    }

    /// Evict random entries when the cache grows beyond capacity.
    fn maybe_evict_cache(&self) {
        let len = self.cache.len();
        if len <= self.cache_capacity {
            return;
        }
        let to_evict = len - self.cache_capacity;
        // Collect keys first to release shard locks before removing
        let keys: Vec<[u8; 36]> = self.cache.iter().take(to_evict).map(|e| *e.key()).collect();
        for key in &keys {
            self.cache.remove(key);
        }
    }

    /// Flush all buffered UTXO writes and undo data to RocksDB in one batch.
    /// The flush height/hash (set via `set_pending_flush_height`) are persisted
    /// atomically in the same WriteBatch, making the UTXO set self-describing.
    pub fn flush_to_disk(&self) -> StorageResult<()> {
        let mut wb = self
            .write_buffer
            .lock()
            .expect("UTXO write buffer mutex poisoned");
        if wb.is_empty() && wb.undo_buffer.is_empty() && wb.pending_flush_height.is_none() {
            wb.blocks_since_flush = 0;
            return Ok(());
        }

        let cf = self.cf(CF_UTXO)?;
        let cf_undo = self.cf(CF_UNDO)?;
        let cf_meta = self.cf(CF_META)?;

        let ins = wb.insert_count;
        let del = wb.deletion_count;
        let undos = wb.undo_buffer.len();
        let flush_h = wb.pending_flush_height;

        // Chunked flush (Core #31645, inverted for RocksDB): a large --dbcache
        // used to produce a single multi-GB WriteBatch, doubling peak memory
        // right at the flush and stalling RocksDB. Instead, stream inserts and
        // undo records in bounded chunks, then commit ALL deletions together
        // with the flush height/hash in one final atomic batch.
        //
        // Crash safety: recovery replays blocks forward from the persisted
        // flush height, and insert/undo writes are idempotent under that
        // replay (reconnecting the same blocks regenerates identical puts).
        // Deletions are NOT — a prematurely deleted coin would fail replay
        // with a missing UTXO — so they ride in the same WriteBatch as the
        // meta update. RocksDB's WAL is ordered: if the final batch is
        // durable, every earlier chunk is too.
        const CHUNK_TARGET_BYTES: usize = 128 * 1024 * 1024;

        let write_start = std::time::Instant::now();
        let mut chunks: u32 = 0;
        let mut rocks_batch = WriteBatch::default();
        let mut batch_bytes: usize = 0;

        // 1. Inserts (chunked, idempotent).
        for (key, entry) in wb.entries.iter() {
            if let Some(entry) = entry {
                let val = entry.serialize();
                batch_bytes += 36 + val.len();
                rocks_batch.put_cf(&cf, key, val);
                if batch_bytes >= CHUNK_TARGET_BYTES {
                    self.db.write(std::mem::take(&mut rocks_batch))?;
                    chunks += 1;
                    batch_bytes = 0;
                }
            }
        }

        // 2. Undo records (chunked, idempotent — replay regenerates them).
        for (hash, data) in &wb.undo_buffer {
            batch_bytes += 32 + data.len();
            rocks_batch.put_cf(&cf_undo, hash, data);
            if batch_bytes >= CHUNK_TARGET_BYTES {
                self.db.write(std::mem::take(&mut rocks_batch))?;
                chunks += 1;
                batch_bytes = 0;
            }
        }

        // 3. Deletions + flush height/hash — one atomic final batch.
        for (key, entry) in wb.entries.iter() {
            if entry.is_none() {
                rocks_batch.delete_cf(&cf, key);
            }
        }
        if let Some(height) = wb.pending_flush_height {
            rocks_batch.put_cf(&cf_meta, b"flush_height", height.to_le_bytes());
        }
        if let Some(hash) = wb.pending_flush_hash {
            rocks_batch.put_cf(&cf_meta, b"flush_hash", hash);
        }
        self.db.write(rocks_batch)?;
        chunks += 1;
        let write_ms = write_start.elapsed().as_millis() as u64;

        // Promote flushed inserts into the read cache (up to capacity) so
        // coins that survived the buffer window stay warm. Dropping the
        // partially-consumed Drain clears any remainder from the map.
        {
            let cap = self.cache_capacity;
            for (key, entry) in wb.entries.drain() {
                if self.cache.len() >= cap {
                    break;
                }
                if let Some(entry) = entry {
                    self.cache.insert(key, CompactCoin::new(&entry));
                }
            }
        }
        wb.entries.clear();
        wb.insert_count = 0;
        wb.deletion_count = 0;
        wb.undo_buffer.clear();
        wb.bytes = 0;
        wb.blocks_since_flush = 0;
        // Don't clear pending_flush_height/hash — they represent the latest
        // known state and should be written again on the next flush.

        // INFO on every flush: flushes are rare (every 1000 blocks or on
        // buffer overflow) and their duration is the prime suspect whenever
        // block connection stalls, so make it visible without RUST_LOG=debug.
        tracing::info!(
            inserts = ins,
            deletions = del,
            undo_blocks = undos,
            flush_height = flush_h,
            chunks,
            write_ms,
            "UTXO flush completed"
        );
        Ok(())
    }

    /// Flush the in-memory cache and write buffer (useful before shutdown).
    pub fn flush_cache(&self) {
        if let Err(e) = self.flush_to_disk() {
            tracing::error!("Failed to flush UTXO write buffer: {}", e);
        }
        // Skip cache.clear() — dropping tens of millions of heap-allocated
        // CompactCoin entries one by one can stall for minutes.  The write
        // buffer is already flushed to disk, so the cache is just a read
        // optimisation.  The OS reclaims all memory when the process exits.
        debug!(
            "UTXO cache has {} entries (skipping clear, OS will reclaim)",
            self.cache.len()
        );
    }

    /// Set the chain height/hash to be persisted atomically with the next
    /// UTXO flush. Call this before `apply_batch` so the flush height is
    /// always consistent with the UTXO data on disk.
    pub fn set_pending_flush_height(&self, height: u32, hash: &[u8; 32]) {
        let mut wb = self
            .write_buffer
            .lock()
            .expect("UTXO write buffer mutex poisoned");
        wb.pending_flush_height = Some(height);
        wb.pending_flush_hash = Some(*hash);
    }

    /// Read the last flush height from the UTXO meta column family.
    /// Returns `None` if no flush height has been persisted yet (fresh DB).
    pub fn get_flush_height(&self) -> StorageResult<Option<u32>> {
        let cf_meta = self.cf(CF_META)?;
        match self.db.get_cf(&cf_meta, b"flush_height")? {
            Some(data) if data.len() == 4 => Ok(Some(u32::from_le_bytes(
                data[..].try_into().expect("length checked above"),
            ))),
            Some(_) => Err(StorageError::Serialization(
                "flush_height has unexpected length".into(),
            )),
            None => Ok(None),
        }
    }

    /// Read the last flush block hash from the UTXO meta column family.
    /// Returns `None` if no flush hash has been persisted yet (fresh DB).
    pub fn get_flush_hash(&self) -> StorageResult<Option<[u8; 32]>> {
        let cf_meta = self.cf(CF_META)?;
        match self.db.get_cf(&cf_meta, b"flush_hash")? {
            Some(data) if data.len() == 32 => {
                let mut hash = [0u8; 32];
                hash.copy_from_slice(&data);
                Ok(Some(hash))
            }
            Some(_) => Err(StorageError::Serialization(
                "flush_hash has unexpected length".into(),
            )),
            None => Ok(None),
        }
    }

    /// Buffer undo data for a block.
    ///
    /// Stores spent UTXOs (for re-insertion on rollback), created outpoints
    /// (for removal on rollback), and the previous block hash (for walking
    /// the chain backward). All three are needed for block-store-free rollback.
    ///
    /// Format (v2, backward-compatible — old data has no created/prev_hash section):
    /// ```text
    /// [spent_count: u32][spent entries...][created_count: u32][created outpoints (36B each)...][prev_hash: 32B]
    /// ```
    pub fn store_undo(
        &self,
        block_hash: &[u8; 32],
        spent: &[SpentUtxo],
        created_outpoints: &[OutPoint],
        prev_block_hash: &[u8; 32],
    ) -> StorageResult<()> {
        let mut buf = Vec::new();
        // Spent UTXOs (same as old format)
        buf.extend_from_slice(&(spent.len() as u32).to_le_bytes());
        for s in spent {
            buf.extend_from_slice(&outpoint_key(&s.outpoint));
            let entry_bytes = s.entry.serialize();
            buf.extend_from_slice(&(entry_bytes.len() as u32).to_le_bytes());
            buf.extend_from_slice(&entry_bytes);
        }
        // Created outpoints (new in v2)
        buf.extend_from_slice(&(created_outpoints.len() as u32).to_le_bytes());
        for op in created_outpoints {
            buf.extend_from_slice(&outpoint_key(op));
        }
        // Previous block hash (new in v2)
        buf.extend_from_slice(prev_block_hash);

        let mut wb = self
            .write_buffer
            .lock()
            .expect("UTXO write buffer mutex poisoned");
        wb.bytes += UNDO_BASE_COST + buf.len();
        wb.undo_buffer.push((*block_hash, buf));
        Ok(())
    }

    /// Load undo data for a block.
    ///
    /// Checks the in-memory write buffer first (undo data may not have been
    /// flushed to disk yet), then falls back to RocksDB.
    ///
    /// Backward-compatible: old-format undo data (spent UTXOs only) returns
    /// `UndoData` with empty `created_outpoints` and `None` for `prev_block_hash`.
    pub fn load_undo(&self, block_hash: &[u8; 32]) -> StorageResult<Option<UndoData>> {
        // Check in-memory write buffer first — undo data buffered by
        // store_undo() may not be flushed to RocksDB yet.
        {
            let wb = self
                .write_buffer
                .lock()
                .expect("UTXO write buffer mutex poisoned");
            for (hash, data) in &wb.undo_buffer {
                if hash == block_hash {
                    return Self::deserialize_undo(data).map(Some);
                }
            }
        }
        // Fall back to RocksDB
        let cf = self.cf(CF_UNDO)?;
        match self.db.get_cf(&cf, block_hash)? {
            Some(data) => Self::deserialize_undo(&data).map(Some),
            None => Ok(None),
        }
    }

    /// Deserialize undo data from raw bytes (shared by buffer and disk reads).
    /// Takes no `self` — it is pure parsing — and is `#[doc(hidden)] pub` so
    /// the fuzz harness can drive it against malformed/truncated input.
    #[doc(hidden)]
    pub fn deserialize_undo(data: &[u8]) -> StorageResult<UndoData> {
        if data.len() < 4 {
            return Err(StorageError::Serialization("undo data too short".into()));
        }
        let count =
            u32::from_le_bytes(data[0..4].try_into().expect("length checked above")) as usize;
        let mut offset = 4;
        // `count` is read straight off disk and could be corrupt/hostile. Each
        // spent-utxo record needs at least 40 bytes (36-byte outpoint + 4-byte
        // length), so cap the pre-allocation to what the buffer can hold to
        // avoid an out-of-memory abort on a bogus count.
        let mut spent_utxos = Vec::with_capacity(count.min(data.len() / 40 + 1));
        for _ in 0..count {
            if offset + 36 > data.len() {
                return Err(StorageError::Serialization("undo data truncated".into()));
            }
            let mut op_key = [0u8; 36];
            op_key.copy_from_slice(&data[offset..offset + 36]);
            offset += 36;

            let mut txid_bytes = [0u8; 32];
            txid_bytes.copy_from_slice(&op_key[0..32]);
            let vout = u32::from_le_bytes(op_key[32..36].try_into().expect("length checked above"));
            let txid = bitcoin::Txid::from_byte_array(txid_bytes);
            let outpoint = OutPoint::new(txid, vout);

            if offset + 4 > data.len() {
                return Err(StorageError::Serialization("undo data truncated".into()));
            }
            let entry_len = u32::from_le_bytes(
                data[offset..offset + 4]
                    .try_into()
                    .expect("length checked above"),
            ) as usize;
            offset += 4;
            if offset + entry_len > data.len() {
                return Err(StorageError::Serialization("undo entry truncated".into()));
            }
            let entry = UtxoEntry::deserialize(&data[offset..offset + entry_len])?;
            offset += entry_len;

            spent_utxos.push(SpentUtxo { outpoint, entry });
        }

        // v2 extension: created outpoints + prev_block_hash
        // If there's more data after the spent UTXOs, parse the new fields.
        let mut created_outpoints = Vec::new();
        let mut prev_block_hash = None;

        if offset + 4 <= data.len() {
            let created_count = u32::from_le_bytes(
                data[offset..offset + 4]
                    .try_into()
                    .expect("length checked above"),
            ) as usize;
            offset += 4;
            for _ in 0..created_count {
                if offset + 36 > data.len() {
                    return Err(StorageError::Serialization(
                        "undo data: created outpoints truncated".into(),
                    ));
                }
                let mut op_key = [0u8; 36];
                op_key.copy_from_slice(&data[offset..offset + 36]);
                offset += 36;

                let mut txid_bytes = [0u8; 32];
                txid_bytes.copy_from_slice(&op_key[0..32]);
                let vout =
                    u32::from_le_bytes(op_key[32..36].try_into().expect("length checked above"));
                let txid = bitcoin::Txid::from_byte_array(txid_bytes);
                created_outpoints.push(OutPoint::new(txid, vout));
            }
            if offset + 32 <= data.len() {
                let mut hash = [0u8; 32];
                hash.copy_from_slice(&data[offset..offset + 32]);
                prev_block_hash = Some(hash);
            }
        }

        Ok(UndoData {
            spent_utxos,
            created_outpoints,
            prev_block_hash,
        })
    }

    /// Roll back a single block using only undo data (no block store needed).
    ///
    /// Requires v2 undo data (with created_outpoints). Returns the previous
    /// block hash for chaining rollbacks, or an error if undo data is missing
    /// or in old format (no created_outpoints).
    pub fn rollback_block(&self, block_hash: &[u8; 32]) -> StorageResult<[u8; 32]> {
        let undo = self.load_undo(block_hash)?.ok_or_else(|| {
            StorageError::Serialization(format!("no undo data for block {:x?}", &block_hash[..4]))
        })?;

        let prev_hash = undo.prev_block_hash
            .ok_or_else(|| StorageError::Serialization(
                "undo data missing prev_block_hash (old format — cannot rollback without block store)".into()
            ))?;

        if undo.created_outpoints.is_empty() && undo.spent_utxos.is_empty() {
            // Empty block (only coinbase with OP_RETURN outputs) — nothing to undo
        } else {
            let cf = self.cf(CF_UTXO)?;
            let mut rocks_batch = WriteBatch::default();

            // Remove outputs created by this block
            for outpoint in &undo.created_outpoints {
                let key = outpoint_key(outpoint);
                rocks_batch.delete_cf(&cf, key);
                self.cache.remove(&key);
            }

            // Re-insert UTXOs that were spent by this block
            for spent in &undo.spent_utxos {
                let key = outpoint_key(&spent.outpoint);
                rocks_batch.put_cf(&cf, key, spent.entry.serialize());
                self.cache.insert(key, CompactCoin::new(&spent.entry));
            }

            self.db.write(rocks_batch)?;
        }

        // Clean up undo data for this block
        self.delete_undo(block_hash)?;

        Ok(prev_hash)
    }

    /// Roll back the UTXO set from its current flush height to `target_height`.
    ///
    /// Walks backward from the flush hash using undo data only (no block store).
    /// Requires v2 undo data for every block in the range. Flushes the write
    /// buffer first to ensure disk state is current.
    ///
    /// On success, updates the flush height/hash in CF_META.
    pub fn rollback_to(&self, target_height: u32) -> StorageResult<()> {
        // Flush any pending writes so disk is consistent before rollback
        self.flush_to_disk()?;

        let mut current_height = self.get_flush_height()?.ok_or_else(|| {
            StorageError::Serialization("cannot rollback: no flush height stored".into())
        })?;
        let mut current_hash = self.get_flush_hash()?.ok_or_else(|| {
            StorageError::Serialization("cannot rollback: no flush hash stored".into())
        })?;

        if current_height <= target_height {
            return Ok(()); // Already at or below target
        }

        tracing::info!(
            from_height = current_height,
            to_height = target_height,
            blocks = current_height - target_height,
            "Rolling back UTXO set"
        );

        while current_height > target_height {
            current_hash = self.rollback_block(&current_hash)?;
            current_height -= 1;

            if (current_height - target_height).is_multiple_of(100)
                && current_height > target_height
            {
                tracing::debug!(height = current_height, "Rollback progress");
            }
        }

        // Persist the new flush height/hash
        let cf_meta = self.cf(CF_META)?;
        let mut rocks_batch = WriteBatch::default();
        rocks_batch.put_cf(&cf_meta, b"flush_height", current_height.to_le_bytes());
        rocks_batch.put_cf(&cf_meta, b"flush_hash", current_hash);
        self.db.write(rocks_batch)?;

        // Update pending state to match
        {
            let mut wb = self
                .write_buffer
                .lock()
                .expect("UTXO write buffer mutex poisoned");
            wb.pending_flush_height = Some(current_height);
            wb.pending_flush_hash = Some(current_hash);
        }

        tracing::info!(height = current_height, "UTXO rollback complete");
        Ok(())
    }

    /// Delete undo data for a block — from the in-memory write buffer as well
    /// as RocksDB. Purging the buffer matters: an undo record buffered by
    /// `store_undo` but not yet flushed would otherwise survive the delete and
    /// be re-written to disk at the next flush, leaving a stale undo record
    /// for a disconnected block.
    pub fn delete_undo(&self, block_hash: &[u8; 32]) -> StorageResult<()> {
        {
            let mut wb = self
                .write_buffer
                .lock()
                .expect("UTXO write buffer mutex poisoned");
            wb.undo_buffer.retain(|(hash, _)| hash != block_hash);
        }
        let cf = self.cf(CF_UNDO)?;
        self.db.delete_cf(&cf, block_hash)?;
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use bitcoin::hashes::Hash;
    use bitcoin::Txid;

    fn test_outpoint(vout: u32) -> OutPoint {
        OutPoint {
            txid: Txid::all_zeros(),
            vout,
        }
    }

    #[test]
    fn test_utxo_insert_get_remove() {
        let dir = tempfile::tempdir().unwrap();
        let utxo_set = UtxoSet::open(&dir.path().join("utxo"), None).unwrap();

        let outpoint = test_outpoint(0);
        let entry = UtxoEntry {
            amount: 50_0000_0000,
            script_pubkey: vec![0x76, 0xa9, 0x14],
            height: 0,
            is_coinbase: true,
        };

        utxo_set.insert(&outpoint, &entry).unwrap();
        assert!(utxo_set.contains(&outpoint).unwrap());

        let retrieved = utxo_set.get(&outpoint).unwrap().unwrap();
        assert_eq!(retrieved.amount, 50_0000_0000);
        assert_eq!(retrieved.height, 0);
        assert!(retrieved.is_coinbase);

        utxo_set.remove(&outpoint).unwrap();
        assert!(!utxo_set.contains(&outpoint).unwrap());
        assert!(utxo_set.get(&outpoint).unwrap().is_none());
    }

    #[test]
    fn test_utxo_batch() {
        let dir = tempfile::tempdir().unwrap();
        let utxo_set = UtxoSet::open(&dir.path().join("utxo"), None).unwrap();

        let op0 = test_outpoint(0);
        let op1 = test_outpoint(1);
        let entry = UtxoEntry {
            amount: 100_000,
            script_pubkey: vec![0x00, 0x14],
            height: 100,
            is_coinbase: false,
        };
        utxo_set.insert(&op0, &entry).unwrap();
        utxo_set.insert(&op1, &entry).unwrap();

        let op2 = test_outpoint(2);
        let new_entry = UtxoEntry {
            amount: 200_000,
            script_pubkey: vec![0x00, 0x20],
            height: 101,
            is_coinbase: false,
        };

        let batch = UtxoBatch {
            inserts: vec![(op2, new_entry)],
            removals: vec![op0],
            spent_utxos: vec![],
        };
        utxo_set.apply_batch(&batch).unwrap();

        assert!(!utxo_set.contains(&op0).unwrap());
        assert!(utxo_set.contains(&op1).unwrap());
        assert!(utxo_set.contains(&op2).unwrap());
        assert_eq!(utxo_set.get(&op2).unwrap().unwrap().amount, 200_000);
    }

    #[test]
    fn write_buffer_bytes_tracking_and_cancellation() {
        let dir = tempfile::tempdir().unwrap();
        let utxo_set = UtxoSet::open(&dir.path().join("utxo"), None).unwrap();

        let op = test_outpoint(0);
        let entry = UtxoEntry {
            amount: 100_000,
            script_pubkey: vec![0x00, 0x14, 0x01],
            height: 100,
            is_coinbase: false,
        };
        let cost = insert_cost(&entry);

        // Insert -> bytes == insert cost
        let batch = UtxoBatch {
            inserts: vec![(op, entry.clone())],
            removals: vec![],
            spent_utxos: vec![],
        };
        utxo_set.apply_batch(&batch).unwrap();
        assert_eq!(utxo_set.write_buffer.lock().unwrap().bytes, cost);

        // Re-insert same key -> old cost subtracted, no double counting
        utxo_set.apply_batch(&batch).unwrap();
        assert_eq!(utxo_set.write_buffer.lock().unwrap().bytes, cost);

        // Removal cancels the pending insert -> only a tombstone remains
        let batch = UtxoBatch {
            inserts: vec![],
            removals: vec![op],
            spent_utxos: vec![],
        };
        utxo_set.apply_batch(&batch).unwrap();
        {
            let wb = utxo_set.write_buffer.lock().unwrap();
            assert_eq!(wb.insert_count, 0);
            assert_eq!(wb.deletion_count, 1);
            assert_eq!(wb.bytes, DELETION_COST);
        }

        // Insert cancels the pending deletion -> back to insert cost
        let batch = UtxoBatch {
            inserts: vec![(op, entry)],
            removals: vec![],
            spent_utxos: vec![],
        };
        utxo_set.apply_batch(&batch).unwrap();
        {
            let wb = utxo_set.write_buffer.lock().unwrap();
            assert_eq!(wb.deletion_count, 0);
            assert_eq!(wb.insert_count, 1);
            assert_eq!(wb.bytes, cost);
        }
    }

    #[test]
    fn flush_triggers_on_byte_budget_and_resets_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let mut utxo_set = UtxoSet::open(&dir.path().join("utxo"), None).unwrap();
        utxo_set.write_buffer_budget = 1; // any batch exceeds the budget

        let op = test_outpoint(7);
        let entry = UtxoEntry {
            amount: 42,
            script_pubkey: vec![0x51],
            height: 1,
            is_coinbase: false,
        };
        let batch = UtxoBatch {
            inserts: vec![(op, entry)],
            removals: vec![],
            spent_utxos: vec![],
        };
        let flushed = utxo_set.apply_batch(&batch).unwrap();
        assert!(flushed, "byte budget overflow must trigger a flush");

        let wb = utxo_set.write_buffer.lock().unwrap();
        assert!(wb.entries.is_empty());
        assert_eq!(wb.bytes, 0);
        assert_eq!(wb.blocks_since_flush, 0);
        drop(wb);

        // Data must be readable from disk after the flush
        assert_eq!(utxo_set.get(&op).unwrap().unwrap().amount, 42);
    }

    #[test]
    fn test_utxo_entry_serialization() {
        let entry = UtxoEntry {
            amount: 12345678,
            script_pubkey: vec![0x76, 0xa9, 0x14, 0x00, 0x01, 0x02],
            height: 500000,
            is_coinbase: false,
        };
        let bytes = entry.serialize();
        let restored = UtxoEntry::deserialize(&bytes).unwrap();
        assert_eq!(restored.amount, 12345678);
        assert_eq!(restored.height, 500000);
        assert!(!restored.is_coinbase);
        assert_eq!(restored.script_pubkey, entry.script_pubkey);
    }

    #[test]
    fn coin_script_inline_and_heap_roundtrip() {
        // At the inline boundary (36 bytes) the script stays inline; one byte
        // over falls back to the heap. Both must round-trip byte-identically.
        for len in [0usize, 1, 22, 25, 34, 36, 37, 100, 10_000] {
            let script: Vec<u8> = (0..len).map(|i| i as u8).collect();
            let cs = CoinScript::new(&script);
            assert_eq!(cs.as_bytes(), &script[..], "len={len}");
            assert_eq!(
                matches!(cs, CoinScript::Inline { .. }),
                len <= INLINE_SCRIPT_MAX,
                "len={len}"
            );
            // Full CompactCoin roundtrip preserves the script.
            let entry = UtxoEntry {
                amount: 7,
                script_pubkey: script.clone(),
                height: 123,
                is_coinbase: len % 2 == 0,
            };
            let restored = CompactCoin::new(&entry).to_entry();
            assert_eq!(restored.script_pubkey, script);
            assert_eq!(restored.height, 123);
            assert_eq!(restored.is_coinbase, len % 2 == 0);
        }
    }

    #[test]
    fn test_flush_height_not_set_initially() {
        let dir = tempfile::tempdir().unwrap();
        let utxo_set = UtxoSet::open(&dir.path().join("utxo"), None).unwrap();

        assert_eq!(utxo_set.get_flush_height().unwrap(), None);
        assert_eq!(utxo_set.get_flush_hash().unwrap(), None);
    }

    #[test]
    fn test_flush_height_persisted_on_flush() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("utxo");
        let utxo_set = UtxoSet::open(&path, None).unwrap();

        let hash = [0xab_u8; 32];
        utxo_set.set_pending_flush_height(42, &hash);

        // Not yet on disk — only in write buffer
        assert_eq!(utxo_set.get_flush_height().unwrap(), None);

        // Insert a dummy UTXO so flush has something to write
        let outpoint = test_outpoint(0);
        let entry = UtxoEntry {
            amount: 100,
            script_pubkey: vec![0x00],
            height: 42,
            is_coinbase: false,
        };
        utxo_set.insert(&outpoint, &entry).unwrap();
        utxo_set.flush_to_disk().unwrap();

        assert_eq!(utxo_set.get_flush_height().unwrap(), Some(42));
        assert_eq!(utxo_set.get_flush_hash().unwrap(), Some(hash));

        // Reopen and verify persistence
        drop(utxo_set);
        let utxo_set2 = UtxoSet::open(&path, None).unwrap();
        assert_eq!(utxo_set2.get_flush_height().unwrap(), Some(42));
        assert_eq!(utxo_set2.get_flush_hash().unwrap(), Some(hash));
    }

    #[test]
    fn test_flush_height_updates_on_subsequent_flushes() {
        let dir = tempfile::tempdir().unwrap();
        let utxo_set = UtxoSet::open(&dir.path().join("utxo"), None).unwrap();

        let hash1 = [0x01_u8; 32];
        utxo_set.set_pending_flush_height(100, &hash1);
        utxo_set.flush_to_disk().unwrap();
        assert_eq!(utxo_set.get_flush_height().unwrap(), Some(100));

        let hash2 = [0x02_u8; 32];
        utxo_set.set_pending_flush_height(200, &hash2);
        utxo_set.flush_to_disk().unwrap();
        assert_eq!(utxo_set.get_flush_height().unwrap(), Some(200));
        assert_eq!(utxo_set.get_flush_hash().unwrap(), Some(hash2));
    }

    #[test]
    fn test_flush_height_atomic_with_utxo_batch() {
        let dir = tempfile::tempdir().unwrap();
        let utxo_set = UtxoSet::open(&dir.path().join("utxo"), None).unwrap();

        // Simulate what ChainState does: set flush height then apply_batch
        let hash = [0xcc_u8; 32];
        utxo_set.set_pending_flush_height(500, &hash);

        let outpoint = test_outpoint(99);
        let entry = UtxoEntry {
            amount: 50_000,
            script_pubkey: vec![0x51],
            height: 500,
            is_coinbase: true,
        };
        let batch = UtxoBatch {
            inserts: vec![(outpoint, entry)],
            removals: vec![],
            spent_utxos: vec![],
        };
        utxo_set.apply_batch(&batch).unwrap();

        // Force flush
        utxo_set.flush_to_disk().unwrap();

        assert_eq!(utxo_set.get_flush_height().unwrap(), Some(500));
        assert_eq!(utxo_set.get_flush_hash().unwrap(), Some(hash));
        assert!(utxo_set.contains(&test_outpoint(99)).unwrap());
    }

    fn test_outpoint_with_txid(txid_byte: u8, vout: u32) -> OutPoint {
        let mut bytes = [0u8; 32];
        bytes[0] = txid_byte;
        OutPoint {
            txid: Txid::from_byte_array(bytes),
            vout,
        }
    }

    /// Helper: simulate connecting a block by storing undo data and inserting UTXOs.
    fn simulate_connect_block(
        utxo_set: &UtxoSet,
        block_hash: &[u8; 32],
        prev_hash: &[u8; 32],
        height: u32,
        created: &[(OutPoint, UtxoEntry)],
        spent: &[SpentUtxo],
    ) {
        // Store undo data with v2 format
        let created_outpoints: Vec<OutPoint> = created.iter().map(|(op, _)| *op).collect();
        utxo_set
            .store_undo(block_hash, spent, &created_outpoints, prev_hash)
            .unwrap();

        // Apply UTXO changes
        let batch = UtxoBatch {
            inserts: created.to_vec(),
            removals: spent.iter().map(|s| s.outpoint).collect(),
            spent_utxos: spent.to_vec(),
        };
        utxo_set.set_pending_flush_height(height, block_hash);
        utxo_set.apply_batch(&batch).unwrap();
        utxo_set.flush_to_disk().unwrap();
    }

    #[test]
    fn test_rollback_single_block() {
        let dir = tempfile::tempdir().unwrap();
        let utxo_set = UtxoSet::open(&dir.path().join("utxo"), None).unwrap();

        let genesis_hash = [0x00u8; 32];
        let block1_hash = [0x01u8; 32];

        // Genesis: create one UTXO (coinbase)
        let coinbase_op = test_outpoint_with_txid(0xaa, 0);
        let coinbase_entry = UtxoEntry {
            amount: 50_0000_0000,
            script_pubkey: vec![0x76, 0xa9],
            height: 0,
            is_coinbase: true,
        };
        utxo_set.insert(&coinbase_op, &coinbase_entry).unwrap();
        utxo_set.set_pending_flush_height(0, &genesis_hash);
        utxo_set.flush_to_disk().unwrap();

        // Block 1: spends coinbase, creates two new outputs
        let out1 = test_outpoint_with_txid(0xbb, 0);
        let entry1 = UtxoEntry {
            amount: 30_0000_0000,
            script_pubkey: vec![0x00, 0x14],
            height: 1,
            is_coinbase: false,
        };
        let out2 = test_outpoint_with_txid(0xbb, 1);
        let entry2 = UtxoEntry {
            amount: 20_0000_0000,
            script_pubkey: vec![0x00, 0x14],
            height: 1,
            is_coinbase: false,
        };

        simulate_connect_block(
            &utxo_set,
            &block1_hash,
            &genesis_hash,
            1,
            &[(out1, entry1), (out2, entry2)],
            &[SpentUtxo {
                outpoint: coinbase_op,
                entry: coinbase_entry.clone(),
            }],
        );

        // Verify state after block 1
        assert!(!utxo_set.contains(&coinbase_op).unwrap());
        assert!(utxo_set.contains(&out1).unwrap());
        assert!(utxo_set.contains(&out2).unwrap());
        assert_eq!(utxo_set.get_flush_height().unwrap(), Some(1));

        // Rollback block 1
        let prev = utxo_set.rollback_block(&block1_hash).unwrap();
        assert_eq!(prev, genesis_hash);

        // Verify state after rollback: coinbase is back, block 1 outputs are gone
        assert!(utxo_set.contains(&coinbase_op).unwrap());
        assert_eq!(
            utxo_set.get(&coinbase_op).unwrap().unwrap().amount,
            50_0000_0000
        );
        assert!(!utxo_set.contains(&out1).unwrap());
        assert!(!utxo_set.contains(&out2).unwrap());
    }

    #[test]
    fn test_rollback_to_target_height() {
        let dir = tempfile::tempdir().unwrap();
        let utxo_set = UtxoSet::open(&dir.path().join("utxo"), None).unwrap();

        let genesis_hash = [0x00u8; 32];
        let block1_hash = [0x01u8; 32];
        let block2_hash = [0x02u8; 32];
        let block3_hash = [0x03u8; 32];

        // Genesis coinbase
        let coinbase = test_outpoint_with_txid(0xaa, 0);
        let coinbase_entry = UtxoEntry {
            amount: 50_0000_0000,
            script_pubkey: vec![0x51],
            height: 0,
            is_coinbase: true,
        };
        utxo_set.insert(&coinbase, &coinbase_entry).unwrap();
        utxo_set.set_pending_flush_height(0, &genesis_hash);
        utxo_set.flush_to_disk().unwrap();

        // Block 1: spends coinbase, creates out_b1
        let out_b1 = test_outpoint_with_txid(0xb1, 0);
        let entry_b1 = UtxoEntry {
            amount: 50_0000_0000,
            script_pubkey: vec![0x51],
            height: 1,
            is_coinbase: false,
        };
        simulate_connect_block(
            &utxo_set,
            &block1_hash,
            &genesis_hash,
            1,
            &[(out_b1, entry_b1.clone())],
            &[SpentUtxo {
                outpoint: coinbase,
                entry: coinbase_entry.clone(),
            }],
        );

        // Block 2: spends out_b1, creates out_b2
        let out_b2 = test_outpoint_with_txid(0xb2, 0);
        let entry_b2 = UtxoEntry {
            amount: 49_0000_0000,
            script_pubkey: vec![0x51],
            height: 2,
            is_coinbase: false,
        };
        simulate_connect_block(
            &utxo_set,
            &block2_hash,
            &block1_hash,
            2,
            &[(out_b2, entry_b2.clone())],
            &[SpentUtxo {
                outpoint: out_b1,
                entry: entry_b1.clone(),
            }],
        );

        // Block 3: spends out_b2, creates out_b3
        let out_b3 = test_outpoint_with_txid(0xb3, 0);
        let entry_b3 = UtxoEntry {
            amount: 48_0000_0000,
            script_pubkey: vec![0x51],
            height: 3,
            is_coinbase: false,
        };
        simulate_connect_block(
            &utxo_set,
            &block3_hash,
            &block2_hash,
            3,
            &[(out_b3, entry_b3)],
            &[SpentUtxo {
                outpoint: out_b2,
                entry: entry_b2.clone(),
            }],
        );

        // At height 3: only out_b3 exists
        assert_eq!(utxo_set.get_flush_height().unwrap(), Some(3));
        assert!(!utxo_set.contains(&coinbase).unwrap());
        assert!(!utxo_set.contains(&out_b1).unwrap());
        assert!(!utxo_set.contains(&out_b2).unwrap());
        assert!(utxo_set.contains(&out_b3).unwrap());

        // Rollback to height 1
        utxo_set.rollback_to(1).unwrap();

        // At height 1: only out_b1 should exist
        assert_eq!(utxo_set.get_flush_height().unwrap(), Some(1));
        assert!(!utxo_set.contains(&coinbase).unwrap());
        assert!(utxo_set.contains(&out_b1).unwrap());
        assert_eq!(utxo_set.get(&out_b1).unwrap().unwrap().amount, 50_0000_0000);
        assert!(!utxo_set.contains(&out_b2).unwrap());
        assert!(!utxo_set.contains(&out_b3).unwrap());
    }

    #[test]
    fn test_rollback_fails_on_old_format_undo() {
        let dir = tempfile::tempdir().unwrap();
        let utxo_set = UtxoSet::open(&dir.path().join("utxo"), None).unwrap();

        // Manually store old-format undo data (no created_outpoints/prev_hash)
        let block_hash = [0x01u8; 32];
        let cf_undo = utxo_set.db.cf_handle(CF_UNDO).unwrap();
        // Old format: just [count: u32 = 0]
        utxo_set
            .db
            .put_cf(&cf_undo, block_hash, 0u32.to_le_bytes())
            .unwrap();

        // Set flush height so rollback_to has something to work with
        utxo_set.set_pending_flush_height(1, &block_hash);
        utxo_set.flush_to_disk().unwrap();

        // rollback_block should fail because no prev_block_hash
        let result = utxo_set.rollback_block(&block_hash);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("old format"));
    }

    #[test]
    fn test_undo_v2_format_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let utxo_set = UtxoSet::open(&dir.path().join("utxo"), None).unwrap();

        let block_hash = [0xdd_u8; 32];
        let prev_hash = [0xcc_u8; 32];
        let op1 = test_outpoint_with_txid(0x11, 0);
        let entry1 = UtxoEntry {
            amount: 1000,
            script_pubkey: vec![0x51],
            height: 5,
            is_coinbase: false,
        };
        let created_op = test_outpoint_with_txid(0x22, 0);

        utxo_set
            .store_undo(
                &block_hash,
                &[SpentUtxo {
                    outpoint: op1,
                    entry: entry1.clone(),
                }],
                &[created_op],
                &prev_hash,
            )
            .unwrap();
        utxo_set.flush_to_disk().unwrap();

        let undo = utxo_set.load_undo(&block_hash).unwrap().unwrap();
        assert_eq!(undo.spent_utxos.len(), 1);
        assert_eq!(undo.spent_utxos[0].outpoint, op1);
        assert_eq!(undo.spent_utxos[0].entry.amount, 1000);
        assert_eq!(undo.created_outpoints.len(), 1);
        assert_eq!(undo.created_outpoints[0], created_op);
        assert_eq!(undo.prev_block_hash, Some(prev_hash));
    }
}
