use bitcoin::consensus::encode;
use bitcoin::hashes::{sha256, Hash};
use bitcoin::{BlockHash, OutPoint, Txid};
use bitcoinpr_storage::{
    BlockStore, HeaderIndex, StorageError, StorageResult, TxIndex, TxIndexEntry,
};
use lru::LruCache;
use rocksdb::{ColumnFamilyDescriptor, IteratorMode, Options, ReadOptions, DB};
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::num::NonZeroUsize;
use std::path::Path;
use std::sync::Arc;
use std::sync::Mutex;
use tracing::{debug, warn};

const CF_SCRIPTHASH_TXIDS: &str = "scripthash_txids";
const CF_SCRIPTHASH_BALANCE: &str = "scripthash_balance";
const CF_META: &str = "meta";
const META_INDEXED_HEIGHT: &[u8] = b"indexed_height";

/// Composite key layout for the txids column family:
/// `scripthash[32] || height_be[4] || tx_index_be[4]` — 40 bytes.
/// Big-endian height/tx_index so rocksdb's lexicographic key order matches
/// chain order, and a prefix scan returns entries sorted ascending.
/// Value: `txid[32]` — 32 bytes.
const KEY_SIZE: usize = 40;
const VALUE_SIZE: usize = 32;

/// Capacity of the prevout-resolver cache: outpoint → (scriptPubKey, value).
/// Seeded with every indexed block's outputs and popped on spend, it acts as
/// a rolling recent-UTXO set — coins are overwhelmingly spent young, so most
/// cross-block spends hit it without touching the tx index or block store.
/// ~150 bytes per entry ⇒ roughly 300 MB at capacity.
const RESOLVER_CACHE_CAPACITY: usize = 2_000_000;

/// Upper bound on worker threads for batched cross-block prevout resolution
/// (tx-index point lookups and funding-block reads/partial decodes).
const RESOLVER_MAX_THREADS: usize = 8;

/// A prevout the resolver must recover from a funding block:
/// (result ordinal, tx position within the funding block, output index).
type PrevoutWant = (usize, u32, u32);

/// A prevout resolvable directly through a v2 tx-index entry:
/// (result ordinal, tx position, output index, tx byte offset, tx byte len).
type DirectWant = (usize, u32, u32, u32, u32);

/// A tx location discovered while scanning a block: (tx position, offset, len).
type ScannedLoc = (u32, u32, u32);

/// Per-block resolver work, split into direct (v2) and scan (v1) wants.
type WantGroup = (Vec<DirectWant>, Vec<PrevoutWant>);

/// A cached output: (scriptPubKey bytes, value in sats).
type CachedOutput = (Box<[u8]>, u64);

/// A resolver result: (result ordinal, (scriptPubKey bytes, value in sats)).
type ResolvedPrevout = (usize, (Vec<u8>, u64));

#[derive(Debug, Clone, Serialize)]
pub struct ScripthashTxEntry {
    pub txid: String,
    pub height: u32,
    pub tx_index: u32,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct ScripthashBalance {
    pub confirmed: u64,
    pub unconfirmed: u64,
}

/// Scripthash-based index for Electrum protocol support, backed by RocksDB.
///
/// Writes are append-only: one key-value pair per (scripthash, tx) touch.
/// Multiple outputs of the same tx to the same scripthash collapse to a single
/// entry (same composite key), matching the dedup semantics Electrum clients
/// expect from `blockchain.scripthash.get_history`.
pub struct ScripthashIndex {
    db: Arc<DB>,
    /// Optional handles used to resolve the scriptPubKey/value of a spent
    /// prevout that was created in an *earlier* block. Without these, only
    /// intra-block spends can be attributed to the spending scripthash and
    /// cross-block spends are silently skipped (the historical behaviour).
    /// See [`Self::set_prevout_resolver`] and [`Self::resolve_spent_outputs`].
    tx_index: Option<Arc<TxIndex>>,
    header_index: Option<Arc<HeaderIndex>>,
    block_store: Option<Arc<BlockStore>>,
    /// LRU of outputs not yet observed spent: outpoint → (scriptPubKey,
    /// value). Seeded from each indexed block's outputs and popped on use
    /// (an outpoint can only ever be spent once), so during backfill it acts
    /// as a rolling recent-UTXO set. Only maintained when a prevout resolver
    /// is configured, keeping no-resolver spend attribution deterministic.
    resolver_cache: Mutex<LruCache<OutPoint, CachedOutput>>,
}

impl ScripthashIndex {
    /// Open or create the scripthash index database at the given path.
    pub fn open(path: &Path) -> StorageResult<Self> {
        let mut db_opts = Options::default();
        db_opts.create_if_missing(true);
        db_opts.create_missing_column_families(true);
        db_opts.set_max_open_files(5_000);

        let cf_descriptors = vec![
            ColumnFamilyDescriptor::new(CF_SCRIPTHASH_TXIDS, Options::default()),
            ColumnFamilyDescriptor::new(CF_SCRIPTHASH_BALANCE, Options::default()),
            ColumnFamilyDescriptor::new(CF_META, Options::default()),
        ];

        let db = DB::open_cf_descriptors(&db_opts, path, cf_descriptors)?;
        Ok(ScripthashIndex {
            db: Arc::new(db),
            tx_index: None,
            header_index: None,
            block_store: None,
            resolver_cache: Mutex::new(LruCache::new(
                NonZeroUsize::new(RESOLVER_CACHE_CAPACITY)
                    .expect("RESOLVER_CACHE_CAPACITY is non-zero"),
            )),
        })
    }

    /// Resolve a column-family handle, returning an error (instead of
    /// panicking) if it is missing — e.g. a corrupted or incompatible DB.
    fn cf(&self, name: &str) -> StorageResult<&rocksdb::ColumnFamily> {
        self.db
            .cf_handle(name)
            .ok_or_else(|| StorageError::MissingColumnFamily(name.to_string()))
    }

    /// Release the resolver-cache memory. Call after the backfill completes —
    /// at tip speed the cache refills from new blocks on its own.
    pub fn clear_resolver_cache(&self) {
        let mut cache = self
            .resolver_cache
            .lock()
            .expect("resolver cache lock poisoned");
        cache.clear();
    }

    /// Provide the handles needed to index *cross-block* spends.
    ///
    /// When a transaction spends an output created in an earlier block, the
    /// spending input must be attributed to the prevout's scripthash so that
    /// `blockchain.scripthash.get_history` returns the spend (Electrum derives
    /// a wallet's UTXO set and tx confirmations purely from address history).
    /// The prevout's scriptPubKey is recovered by loading the funding tx via
    /// the transaction index. Call this once, before wrapping the index in an
    /// `Arc`; if not called, cross-block spend indexing is disabled.
    pub fn set_prevout_resolver(
        &mut self,
        tx_index: Arc<TxIndex>,
        header_index: Arc<HeaderIndex>,
        block_store: Arc<BlockStore>,
    ) {
        self.tx_index = Some(tx_index);
        self.header_index = Some(header_index);
        self.block_store = Some(block_store);
    }

    /// Resolve the `(scriptPubKey, value_sats)` of a batch of confirmed
    /// prevouts by locating each funding transaction through the tx index,
    /// grouping the requests by funding block, and reading + partially
    /// decoding each distinct block only once. Both phases are spread across
    /// worker threads (bounded by [`RESOLVER_MAX_THREADS`]).
    ///
    /// Returns one slot per input outpoint. `None` means no resolver handles
    /// are configured, the prevout was not found, or a lookup failed —
    /// callers treat this as "spend not indexable" and skip it rather than
    /// failing the whole block.
    fn resolve_spent_outputs(&self, outpoints: &[OutPoint]) -> Vec<Option<(Vec<u8>, u64)>> {
        let mut results: Vec<Option<(Vec<u8>, u64)>> = vec![None; outpoints.len()];
        let (Some(tx_index), Some(header_index), Some(block_store)) = (
            self.tx_index.as_deref(),
            self.header_index.as_deref(),
            self.block_store.as_deref(),
        ) else {
            return results;
        };

        let threads = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1)
            .clamp(1, RESOLVER_MAX_THREADS);

        // Phase 1: txid → (funding block, tx position) lookups. Deduplicate
        // first (inputs often spend several outputs of the same funding tx),
        // then issue batched `MultiGet`s in parallel chunks — RocksDB shares
        // SST index/filter block loads within a batch that per-key `get()`
        // calls would repeat.
        let mut unique_txids: Vec<Txid> = Vec::new();
        let mut txid_ordinal: HashMap<Txid, usize> = HashMap::new();
        for op in outpoints {
            if let std::collections::hash_map::Entry::Vacant(e) = txid_ordinal.entry(op.txid) {
                e.insert(unique_txids.len());
                unique_txids.push(op.txid);
            }
        }
        let mut located: Vec<Option<TxIndexEntry>> = vec![None; unique_txids.len()];
        let chunk = unique_txids.len().div_ceil(threads).max(1);
        std::thread::scope(|s| {
            for (txids, slots) in unique_txids.chunks(chunk).zip(located.chunks_mut(chunk)) {
                s.spawn(move || {
                    for (entry, slot) in tx_index.get_many(txids).into_iter().zip(slots.iter_mut())
                    {
                        *slot = entry;
                    }
                });
            }
        });

        // Phase 2: group by funding block so each block is fetched once,
        // splitting v2 entries (known tx byte range → direct read) from v1
        // entries (position only → block scan).
        let mut groups: HashMap<BlockHash, WantGroup> = HashMap::new();
        for (i, op) in outpoints.iter().enumerate() {
            if let Some(entry) = &located[txid_ordinal[&op.txid]] {
                let group = groups.entry(entry.block_hash).or_default();
                match entry.tx_loc {
                    Some((offset, len)) => group.0.push((i, entry.tx_pos, op.vout, offset, len)),
                    None => group.1.push((i, entry.tx_pos, op.vout)),
                }
            }
        }

        // Phase 3: parallel output extraction. v2 wants are one small
        // positional read + tx decode each; v1 wants read + partially scan
        // the whole block, and report the tx locations the scan discovers so
        // the v1 entries can be upgraded (write-new/read-both migration).
        type WorkerOut = (Vec<ResolvedPrevout>, Vec<(Txid, TxIndexEntry)>);
        let groups: Vec<(BlockHash, WantGroup)> = groups.into_iter().collect();
        let bucket = groups.len().div_ceil(threads).max(1);
        let worker_out: Vec<WorkerOut> = std::thread::scope(|s| {
            let handles: Vec<_> = groups
                .chunks(bucket)
                .map(|bucket_groups| {
                    s.spawn(move || {
                        let mut out = Vec::new();
                        let mut upgrades: Vec<(Txid, TxIndexEntry)> = Vec::new();
                        for (hash, (direct, scan)) in bucket_groups {
                            let Ok(Some(pos)) = header_index.get_block_pos(hash) else {
                                debug!(%hash, "Prevout resolver: no block position");
                                continue;
                            };
                            let mut scan_wants: Vec<PrevoutWant> = scan.clone();
                            for &(i, tx_pos, vout, offset, len) in direct {
                                let tx = block_store
                                    .read_block_slice(&pos, offset, len)
                                    .ok()
                                    .and_then(|raw| {
                                        encode::deserialize::<bitcoin::Transaction>(&raw).ok()
                                    });
                                match tx {
                                    Some(tx) => {
                                        if let Some(o) = tx.output.get(vout as usize) {
                                            out.push((
                                                i,
                                                (
                                                    o.script_pubkey.as_bytes().to_vec(),
                                                    o.value.to_sat(),
                                                ),
                                            ));
                                        }
                                    }
                                    None => {
                                        // Bad/stale location — fall back to a
                                        // scan, which also rewrites the entry.
                                        warn!(%hash, tx_pos, "Prevout resolver: v2 tx read failed, falling back to block scan");
                                        scan_wants.push((i, tx_pos, vout));
                                    }
                                }
                            }
                            if scan_wants.is_empty() {
                                continue;
                            }
                            let raw = match block_store.read_block(&pos) {
                                Ok(raw) => raw,
                                Err(e) => {
                                    warn!(%hash, error = %e, "Prevout resolver: block read failed");
                                    continue;
                                }
                            };
                            let mut locs: Vec<ScannedLoc> = Vec::new();
                            Self::extract_outputs_from_raw_block(
                                &raw,
                                hash,
                                &scan_wants,
                                &mut out,
                                &mut locs,
                            );
                            if !locs.is_empty() {
                                // The wanted txids are already known from the
                                // outpoints — upgrading costs no hashing.
                                let mut txid_by_pos: HashMap<u32, Txid> = HashMap::new();
                                for &(i, tx_pos, _) in &scan_wants {
                                    txid_by_pos.entry(tx_pos).or_insert(outpoints[i].txid);
                                }
                                for (tx_pos, offset, len) in locs {
                                    if let Some(txid) = txid_by_pos.get(&tx_pos) {
                                        upgrades.push((
                                            *txid,
                                            TxIndexEntry {
                                                block_hash: *hash,
                                                tx_pos,
                                                tx_loc: Some((offset, len)),
                                            },
                                        ));
                                    }
                                }
                            }
                        }
                        (out, upgrades)
                    })
                })
                .collect();
            handles
                .into_iter()
                .map(|h| h.join().expect("prevout resolver worker panicked"))
                .collect()
        });
        let mut all_upgrades: Vec<(Txid, TxIndexEntry)> = Vec::new();
        for (resolved, upgrades) in worker_out {
            for (i, value) in resolved {
                results[i] = Some(value);
            }
            all_upgrades.extend(upgrades);
        }
        // Opportunistic v1→v2 upgrade: the block scans discovered these
        // locations anyway; persisting them makes future lookups of the same
        // txs a direct read. Failure is non-fatal (entries stay v1).
        if let Err(e) = tx_index.upgrade_tx_locations(&all_upgrades) {
            debug!(error = %e, "Prevout resolver: tx-loc upgrade write failed");
        }
        results
    }

    /// Decode transactions from a raw block only as far as the highest
    /// requested tx position and pull out the wanted outputs. Avoids
    /// materializing the whole block for a handful of prevouts. Records the
    /// byte location of each wanted transaction in `locs` so the caller can
    /// upgrade v1 tx-index entries to v2.
    fn extract_outputs_from_raw_block(
        raw: &[u8],
        hash: &BlockHash,
        wants: &[PrevoutWant],
        out: &mut Vec<ResolvedPrevout>,
        locs: &mut Vec<ScannedLoc>,
    ) {
        let Some(max_pos) = wants.iter().map(|&(_, tx_pos, _)| tx_pos).max() else {
            return;
        };
        let mut by_pos: HashMap<u32, Vec<(usize, u32)>> = HashMap::new();
        for &(i, tx_pos, vout) in wants {
            by_pos.entry(tx_pos).or_default().push((i, vout));
        }

        // 80-byte header, then the tx-count varint, then the transactions.
        let mut offset = 80usize;
        let Some(slice) = raw.get(offset..) else {
            warn!(%hash, "Prevout resolver: block shorter than header");
            return;
        };
        let Ok((count, used)) = encode::deserialize_partial::<encode::VarInt>(slice) else {
            warn!(%hash, "Prevout resolver: malformed tx-count varint");
            return;
        };
        offset += used;

        let last = (u64::from(max_pos) + 1).min(count.0);
        for pos in 0..last {
            let tx_start = offset;
            let Some(slice) = raw.get(offset..) else {
                warn!(%hash, tx_pos = pos, "Prevout resolver: truncated block");
                return;
            };
            let Ok((tx, used)) = encode::deserialize_partial::<bitcoin::Transaction>(slice) else {
                warn!(%hash, tx_pos = pos, "Prevout resolver: malformed transaction");
                return;
            };
            offset += used;
            if let Some(wanted) = by_pos.get(&(pos as u32)) {
                locs.push((pos as u32, tx_start as u32, used as u32));
                for &(i, vout) in wanted {
                    if let Some(o) = tx.output.get(vout as usize) {
                        out.push((i, (o.script_pubkey.as_bytes().to_vec(), o.value.to_sat())));
                    }
                }
            }
        }
    }

    /// Compute the Electrum-convention scripthash: SHA256 of the scriptPubKey bytes, reversed.
    pub fn compute_scripthash(script_pubkey: &[u8]) -> [u8; 32] {
        let hash = sha256::Hash::hash(script_pubkey);
        let mut result = [0u8; 32];
        result.copy_from_slice(hash.as_ref());
        result.reverse();
        result
    }

    /// Build the composite key `scripthash || height_be || tx_index_be`.
    fn make_key(scripthash: &[u8; 32], height: u32, tx_index: u32) -> [u8; KEY_SIZE] {
        let mut key = [0u8; KEY_SIZE];
        key[0..32].copy_from_slice(scripthash);
        key[32..36].copy_from_slice(&height.to_be_bytes());
        key[36..40].copy_from_slice(&tx_index.to_be_bytes());
        key
    }

    /// Index all transaction outputs in a block by their scripthash.
    ///
    /// For each output, computes the scripthash of its scriptPubKey and writes
    /// one composite-key entry per (scripthash, tx) touch. Balance deltas are
    /// summed per scripthash and applied with a single read-modify-write on
    /// the 16-byte balance value (O(1) per touched scripthash per block).
    ///
    /// Spending inputs are attributed to the prevout's scripthash so the spend
    /// appears in that address's history. Intra-block spends are resolved from
    /// the block itself; cross-block spends are resolved via the prevout
    /// resolver (see [`Self::set_prevout_resolver`]) when one is configured,
    /// and otherwise skipped.
    pub fn index_block_transactions(
        &self,
        block: &bitcoin::Block,
        height: u32,
    ) -> StorageResult<()> {
        let cf_txids = self.cf(CF_SCRIPTHASH_TXIDS)?;
        let cf_balance = self.cf(CF_SCRIPTHASH_BALANCE)?;

        // One entry per (scripthash, tx_index) touch, deduped via HashSet.
        let mut touches: HashSet<([u8; 32], u32, [u8; 32])> = HashSet::new();
        // Signed per-scripthash balance change for this block: outputs add,
        // spent prevouts subtract.
        let mut balance_deltas: HashMap<[u8; 32], i64> = HashMap::new();

        // Pass 1: index every output and build the intra-block prevout map
        // so same-block spends can be attributed without any lookup.
        let mut block_outputs: HashMap<([u8; 32], u32), (Vec<u8>, u64)> = HashMap::new();
        let mut txids: Vec<[u8; 32]> = Vec::with_capacity(block.txdata.len());
        for (tx_index, tx) in block.txdata.iter().enumerate() {
            let txid = tx.compute_txid();
            let txid_bytes: [u8; 32] = *AsRef::<[u8; 32]>::as_ref(&txid);
            txids.push(txid_bytes);

            for (vout, output) in tx.output.iter().enumerate() {
                let spk_bytes = output.script_pubkey.as_bytes();
                let scripthash = Self::compute_scripthash(spk_bytes);
                let value = output.value.to_sat();

                touches.insert((scripthash, tx_index as u32, txid_bytes));
                *balance_deltas.entry(scripthash).or_default() += value as i64;

                block_outputs.insert((txid_bytes, vout as u32), (spk_bytes.to_vec(), value));
            }
        }

        // Pass 2: attribute spends. Consensus orders a tx after the tx that
        // funds it within a block, so consulting the fully-built intra-block
        // map is equivalent to resolving incrementally in a single pass.
        let mut intra_spent: HashSet<([u8; 32], u32)> = HashSet::new();
        let mut pending: Vec<(u32, [u8; 32], OutPoint)> = Vec::new();
        for (tx_index, tx) in block.txdata.iter().enumerate() {
            if tx.is_coinbase() {
                continue;
            }
            let txid_bytes = txids[tx_index];
            for input in &tx.input {
                let prev_txid: [u8; 32] = *AsRef::<[u8; 32]>::as_ref(&input.previous_output.txid);
                let key = (prev_txid, input.previous_output.vout);
                if let Some((spent_spk, value)) = block_outputs.get(&key) {
                    let scripthash = Self::compute_scripthash(spent_spk);
                    touches.insert((scripthash, tx_index as u32, txid_bytes));
                    *balance_deltas.entry(scripthash).or_default() -= *value as i64;
                    intra_spent.insert(key);
                } else {
                    pending.push((tx_index as u32, txid_bytes, input.previous_output));
                }
            }
        }

        // Cross-block spends: try the outpoint cache first, then resolve the
        // misses from disk in one grouped batch. Without a resolver
        // configured the cache is not consulted either, so spends are skipped
        // deterministically (the historical no-`--txindex` behaviour) instead
        // of depending on cache warmth.
        let have_resolver = self.tx_index.is_some();
        let (mut cache_hits, mut disk_hits, mut unresolved) = (0usize, 0usize, 0usize);
        if have_resolver && !pending.is_empty() {
            let mut misses: Vec<(u32, [u8; 32], OutPoint)> = Vec::new();
            {
                // Lock scoped to the lookups only — never held across disk
                // I/O. Hits are popped: an outpoint can never be spent again.
                let mut cache = self
                    .resolver_cache
                    .lock()
                    .expect("resolver cache lock poisoned");
                for (tx_idx, txid_bytes, outpoint) in pending {
                    if let Some((spk, value)) = cache.pop(&outpoint) {
                        let scripthash = Self::compute_scripthash(&spk);
                        touches.insert((scripthash, tx_idx, txid_bytes));
                        *balance_deltas.entry(scripthash).or_default() -= value as i64;
                        cache_hits += 1;
                    } else {
                        misses.push((tx_idx, txid_bytes, outpoint));
                    }
                }
            }
            if !misses.is_empty() {
                let outpoints: Vec<OutPoint> = misses.iter().map(|m| m.2).collect();
                let spents = self.resolve_spent_outputs(&outpoints);
                for ((tx_idx, txid_bytes, _), spent) in misses.into_iter().zip(spents) {
                    if let Some((spent_spk, value)) = spent {
                        let scripthash = Self::compute_scripthash(&spent_spk);
                        touches.insert((scripthash, tx_idx, txid_bytes));
                        *balance_deltas.entry(scripthash).or_default() -= value as i64;
                        disk_hits += 1;
                    } else {
                        // Spend cannot be attributed — skipped, as before.
                        unresolved += 1;
                    }
                }
            }
        }

        let mut batch = rocksdb::WriteBatch::default();

        // Append-only writes — no read-modify-write on growing blobs.
        for (scripthash, tx_idx, txid_bytes) in &touches {
            let key = Self::make_key(scripthash, height, *tx_idx);
            batch.put_cf(&cf_txids, key, &txid_bytes[..]);
        }

        // Balance is a fixed 16-byte value; read-modify-write is O(1).
        for (scripthash, delta) in &balance_deltas {
            let (confirmed, unconfirmed) =
                if let Some(data) = self.db.get_cf(&cf_balance, scripthash)? {
                    if data.len() >= 16 {
                        (
                            u64::from_le_bytes(data[0..8].try_into().expect("fixed-size slice")),
                            u64::from_le_bytes(data[8..16].try_into().expect("fixed-size slice")),
                        )
                    } else {
                        (0u64, 0u64)
                    }
                } else {
                    (0u64, 0u64)
                };

            // Saturate at zero: a negative running balance would only arise
            // from indexing a partial range (spend indexed without its funding
            // output), and must never wrap a u64.
            let confirmed = (confirmed as i64 + delta).max(0) as u64;

            let mut balance_bytes = [0u8; 16];
            balance_bytes[0..8].copy_from_slice(&confirmed.to_le_bytes());
            balance_bytes[8..16].copy_from_slice(&unconfirmed.to_le_bytes());
            batch.put_cf(&cf_balance, scripthash, balance_bytes);
        }

        let cf_meta = self.cf(CF_META)?;
        batch.put_cf(&cf_meta, META_INDEXED_HEIGHT, height.to_le_bytes());

        let scripthashes = balance_deltas.len();
        let touch_count = touches.len();
        self.db.write(batch)?;

        // Seed the resolver cache with this block's still-unspent outputs:
        // coins are overwhelmingly spent young, so most upcoming cross-block
        // spends resolve here without touching the tx index or block store.
        if have_resolver {
            let mut cache = self
                .resolver_cache
                .lock()
                .expect("resolver cache lock poisoned");
            for ((txid_bytes, vout), (spk, value)) in block_outputs {
                if intra_spent.contains(&(txid_bytes, vout)) {
                    continue;
                }
                // Provably unspendable — never worth caching.
                if bitcoin::Script::from_bytes(&spk).is_op_return() {
                    continue;
                }
                cache.put(
                    OutPoint {
                        txid: Txid::from_byte_array(txid_bytes),
                        vout,
                    },
                    (spk.into_boxed_slice(), value),
                );
            }
        }

        debug!(
            height,
            txs = block.txdata.len(),
            scripthashes,
            touches = touch_count,
            cache_hits,
            disk_hits,
            unresolved,
            "Indexed block scripthashes"
        );
        Ok(())
    }

    /// Read all transaction history entries for a scripthash, ordered by
    /// (height, tx_index) ascending.
    pub fn get_tx_history(&self, scripthash: &[u8; 32]) -> StorageResult<Vec<ScripthashTxEntry>> {
        let cf = self.cf(CF_SCRIPTHASH_TXIDS)?;

        // Bound the iterator to keys that share the scripthash prefix.
        let mut upper = [0u8; 32];
        upper.copy_from_slice(scripthash);
        // Increment the prefix to form an exclusive upper bound. If the
        // scripthash is all 0xFF, no upper bound is set (iterator runs to end,
        // which is safe because nothing else lives in this CF).
        let mut bounded = false;
        for i in (0..32).rev() {
            if upper[i] != 0xFF {
                upper[i] += 1;
                for b in &mut upper[i + 1..] {
                    *b = 0;
                }
                bounded = true;
                break;
            }
        }

        let mut read_opts = ReadOptions::default();
        if bounded {
            read_opts.set_iterate_upper_bound(upper.to_vec());
        }

        let iter = self.db.iterator_cf_opt(
            &cf,
            read_opts,
            IteratorMode::From(scripthash.as_ref(), rocksdb::Direction::Forward),
        );

        let mut entries = Vec::new();
        for kv in iter {
            let (key, value) = kv?;
            if key.len() != KEY_SIZE || !key.starts_with(scripthash) {
                break;
            }
            if value.len() != VALUE_SIZE {
                return Err(StorageError::Serialization(
                    "scripthash tx value has invalid length".into(),
                ));
            }

            let height = u32::from_be_bytes(key[32..36].try_into().expect("fixed-size slice"));
            let tx_index = u32::from_be_bytes(key[36..40].try_into().expect("fixed-size slice"));

            let mut txid_bytes = [0u8; 32];
            txid_bytes.copy_from_slice(&value[..32]);
            let txid = bitcoin::Txid::from_byte_array(txid_bytes);

            entries.push(ScripthashTxEntry {
                txid: txid.to_string(),
                height,
                tx_index,
            });
        }

        Ok(entries)
    }

    /// Read the cached balance for a scripthash.
    pub fn get_balance(&self, scripthash: &[u8; 32]) -> StorageResult<ScripthashBalance> {
        let cf = self.cf(CF_SCRIPTHASH_BALANCE)?;

        match self.db.get_cf(&cf, scripthash)? {
            Some(data) if data.len() >= 16 => {
                let confirmed =
                    u64::from_le_bytes(data[0..8].try_into().expect("fixed-size slice"));
                let unconfirmed =
                    u64::from_le_bytes(data[8..16].try_into().expect("fixed-size slice"));
                Ok(ScripthashBalance {
                    confirmed,
                    unconfirmed,
                })
            }
            _ => Ok(ScripthashBalance::default()),
        }
    }

    /// Get the highest block height that has been indexed.
    pub fn get_indexed_height(&self) -> StorageResult<Option<u32>> {
        let cf = self.cf(CF_META)?;
        match self.db.get_cf(&cf, META_INDEXED_HEIGHT)? {
            Some(data) if data.len() >= 4 => Ok(Some(u32::from_le_bytes(
                data[..4].try_into().expect("fixed-size slice"),
            ))),
            _ => Ok(None),
        }
    }

    /// Set the highest block height that has been indexed.
    pub fn set_indexed_height(&self, height: u32) -> StorageResult<()> {
        let cf = self.cf(CF_META)?;
        self.db
            .put_cf(&cf, META_INDEXED_HEIGHT, height.to_le_bytes())?;
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use bitcoin::absolute::LockTime;
    use bitcoin::block::{Header, Version};
    use bitcoin::transaction::Version as TxVersion;
    use bitcoin::{
        Amount, Block, BlockHash, CompactTarget, OutPoint, ScriptBuf, Sequence, Transaction, TxIn,
        TxMerkleNode, TxOut, Witness,
    };
    use tempfile::TempDir;

    fn dummy_header() -> Header {
        Header {
            version: Version::ONE,
            prev_blockhash: BlockHash::all_zeros(),
            merkle_root: TxMerkleNode::all_zeros(),
            time: 0,
            bits: CompactTarget::from_consensus(0x1d00ffff),
            nonce: 0,
        }
    }

    fn mk_tx(outputs: Vec<(u64, ScriptBuf)>, inputs: Vec<OutPoint>) -> Transaction {
        Transaction {
            version: TxVersion::TWO,
            lock_time: LockTime::ZERO,
            input: if inputs.is_empty() {
                vec![TxIn {
                    previous_output: OutPoint::null(),
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::MAX,
                    witness: Witness::new(),
                }]
            } else {
                inputs
                    .into_iter()
                    .map(|o| TxIn {
                        previous_output: o,
                        script_sig: ScriptBuf::new(),
                        sequence: Sequence::MAX,
                        witness: Witness::new(),
                    })
                    .collect()
            },
            output: outputs
                .into_iter()
                .map(|(v, s)| TxOut {
                    value: Amount::from_sat(v),
                    script_pubkey: s,
                })
                .collect(),
        }
    }

    #[test]
    fn append_only_history_is_ordered_and_deduped() {
        let tmp = TempDir::new().unwrap();
        let idx = ScripthashIndex::open(tmp.path()).unwrap();

        let spk_a = ScriptBuf::from(vec![0x51]); // OP_TRUE
        let spk_b = ScriptBuf::from(vec![0x52]); // OP_2

        // Block 1: coinbase paying spk_a twice (two outputs, same script).
        let tx1 = mk_tx(vec![(100, spk_a.clone()), (200, spk_a.clone())], vec![]);
        let block1 = Block {
            header: dummy_header(),
            txdata: vec![tx1],
        };
        idx.index_block_transactions(&block1, 1).unwrap();

        // Block 2: coinbase pays spk_b.
        let tx2 = mk_tx(vec![(300, spk_b.clone())], vec![]);
        let block2 = Block {
            header: dummy_header(),
            txdata: vec![tx2],
        };
        idx.index_block_transactions(&block2, 2).unwrap();

        let sh_a = ScripthashIndex::compute_scripthash(spk_a.as_bytes());
        let sh_b = ScripthashIndex::compute_scripthash(spk_b.as_bytes());

        let hist_a = idx.get_tx_history(&sh_a).unwrap();
        assert_eq!(hist_a.len(), 1, "two outputs in same tx dedup to one entry");
        assert_eq!(hist_a[0].height, 1);
        assert_eq!(hist_a[0].tx_index, 0);

        let hist_b = idx.get_tx_history(&sh_b).unwrap();
        assert_eq!(hist_b.len(), 1);
        assert_eq!(hist_b[0].height, 2);

        // Balance: spk_a got 100+200 = 300 sats.
        assert_eq!(idx.get_balance(&sh_a).unwrap().confirmed, 300);
        assert_eq!(idx.get_balance(&sh_b).unwrap().confirmed, 300);

        // Indexed height tracker.
        assert_eq!(idx.get_indexed_height().unwrap(), Some(2));
    }

    #[test]
    fn history_prefix_scan_does_not_bleed_across_scripthashes() {
        let tmp = TempDir::new().unwrap();
        let idx = ScripthashIndex::open(tmp.path()).unwrap();

        let spk_a = ScriptBuf::from(vec![0x51]);
        let spk_b = ScriptBuf::from(vec![0x52]);

        let tx = mk_tx(vec![(10, spk_a.clone()), (20, spk_b.clone())], vec![]);
        let block = Block {
            header: dummy_header(),
            txdata: vec![tx],
        };
        idx.index_block_transactions(&block, 5).unwrap();

        let sh_a = ScripthashIndex::compute_scripthash(spk_a.as_bytes());
        let sh_b = ScripthashIndex::compute_scripthash(spk_b.as_bytes());

        let hist_a = idx.get_tx_history(&sh_a).unwrap();
        let hist_b = idx.get_tx_history(&sh_b).unwrap();
        assert_eq!(hist_a.len(), 1);
        assert_eq!(hist_b.len(), 1);
        assert_ne!(hist_a[0].txid, "");
    }

    /// A spend of an output funded in an *earlier* block must appear in the
    /// spending address's history, and the spent value must leave its balance.
    /// This is the case Electrum relies on to stop treating spent coins as
    /// UTXOs and to confirm send transactions.
    #[test]
    fn cross_block_spend_appears_in_history_with_resolver() {
        use bitcoinpr_storage::{BlockStore, HeaderIndex, TxIndex};

        let idx_tmp = TempDir::new().unwrap();
        let blocks_tmp = TempDir::new().unwrap();
        let headers_tmp = TempDir::new().unwrap();
        let txindex_tmp = TempDir::new().unwrap();

        let block_store = Arc::new(BlockStore::open(blocks_tmp.path()).unwrap());
        let header_index = Arc::new(HeaderIndex::open(headers_tmp.path()).unwrap());
        let tx_index = Arc::new(TxIndex::open(txindex_tmp.path()).unwrap());

        let mut idx = ScripthashIndex::open(idx_tmp.path()).unwrap();
        idx.set_prevout_resolver(tx_index.clone(), header_index.clone(), block_store.clone());

        let spk_a = ScriptBuf::from(vec![0x51]); // funded address
        let spk_b = ScriptBuf::from(vec![0x52]); // recipient of the spend

        // Block 1: coinbase pays 1000 sats to spk_a.
        let tx1 = mk_tx(vec![(1000, spk_a.clone())], vec![]);
        let txid1 = tx1.compute_txid();
        let block1 = Block {
            header: dummy_header(),
            txdata: vec![tx1],
        };
        // Make block 1 resolvable: store it, record its position, index its txids.
        let pos1 = block_store
            .store_block(&bitcoin::consensus::encode::serialize(&block1))
            .unwrap();
        header_index
            .set_block_pos(&block1.block_hash(), &pos1)
            .unwrap();
        tx_index
            .index_block_at_height(
                &block1.block_hash(),
                &[txid1],
                1,
                Some(&bitcoinpr_storage::compute_tx_locations(&block1)),
            )
            .unwrap();
        idx.index_block_transactions(&block1, 1).unwrap();

        // Block 2: a tx spends spk_a's output (txid1:0) and pays spk_b.
        let tx2 = mk_tx(
            vec![(1000, spk_b.clone())],
            vec![OutPoint {
                txid: txid1,
                vout: 0,
            }],
        );
        let block2 = Block {
            header: dummy_header(),
            txdata: vec![tx2],
        };
        idx.index_block_transactions(&block2, 2).unwrap();

        let sh_a = ScripthashIndex::compute_scripthash(spk_a.as_bytes());
        let sh_b = ScripthashIndex::compute_scripthash(spk_b.as_bytes());

        // spk_a is touched twice: the funding tx (block 1) and the spend (block 2).
        let hist_a = idx.get_tx_history(&sh_a).unwrap();
        assert_eq!(hist_a.len(), 2, "spend must appear in funder's history");
        assert_eq!(hist_a[0].height, 1);
        assert_eq!(hist_a[1].height, 2);

        // Balance nets to zero — the coin received in block 1 was spent in block 2.
        assert_eq!(idx.get_balance(&sh_a).unwrap().confirmed, 0);
        assert_eq!(idx.get_balance(&sh_b).unwrap().confirmed, 1000);
    }

    /// A cross-block spend must also resolve when the outpoint cache is cold
    /// (e.g. after a restart) — via the tx index + a partial block decode,
    /// including for a funding tx that is not at position 0 in its block.
    #[test]
    fn cross_block_spend_resolves_from_disk_when_cache_cold() {
        use bitcoinpr_storage::{BlockStore, HeaderIndex, TxIndex};

        let idx_tmp = TempDir::new().unwrap();
        let blocks_tmp = TempDir::new().unwrap();
        let headers_tmp = TempDir::new().unwrap();
        let txindex_tmp = TempDir::new().unwrap();

        let block_store = Arc::new(BlockStore::open(blocks_tmp.path()).unwrap());
        let header_index = Arc::new(HeaderIndex::open(headers_tmp.path()).unwrap());
        let tx_index = Arc::new(TxIndex::open(txindex_tmp.path()).unwrap());

        let mut idx = ScripthashIndex::open(idx_tmp.path()).unwrap();
        idx.set_prevout_resolver(tx_index.clone(), header_index.clone(), block_store.clone());

        let spk_a = ScriptBuf::from(vec![0x51]); // funded address
        let spk_b = ScriptBuf::from(vec![0x52]); // recipient of the spend
        let spk_c = ScriptBuf::from(vec![0x53]); // coinbase output

        // Block 1: coinbase (tx_pos 0) plus a second tx paying spk_a twice
        // (tx_pos 1). Indexed WITHOUT byte locations (legacy v1 entries).
        let tx0 = mk_tx(vec![(5000, spk_c.clone())], vec![]);
        let tx1 = mk_tx(vec![(700, spk_a.clone()), (300, spk_a.clone())], vec![]);
        let txid0 = tx0.compute_txid();
        let txid1 = tx1.compute_txid();
        let block1 = Block {
            header: dummy_header(),
            txdata: vec![tx0, tx1],
        };
        let pos1 = block_store
            .store_block(&bitcoin::consensus::encode::serialize(&block1))
            .unwrap();
        header_index
            .set_block_pos(&block1.block_hash(), &pos1)
            .unwrap();
        tx_index
            .index_block_at_height(&block1.block_hash(), &[txid0, txid1], 1, None)
            .unwrap();
        idx.index_block_transactions(&block1, 1).unwrap();

        // Simulate a restart: the outpoint cache is gone.
        idx.clear_resolver_cache();

        // Block 2: spend spk_a's first output (txid1:0), paying spk_b.
        // Resolves via block scan (v1 entry), which must also upgrade the
        // entry to v2 with the discovered byte location.
        let tx2 = mk_tx(
            vec![(700, spk_b.clone())],
            vec![OutPoint {
                txid: txid1,
                vout: 0,
            }],
        );
        let block2 = Block {
            header: dummy_header(),
            txdata: vec![tx2],
        };
        idx.index_block_transactions(&block2, 2).unwrap();

        let upgraded = tx_index.get(&txid1).unwrap().unwrap();
        assert!(
            upgraded.tx_loc.is_some(),
            "block scan must opportunistically upgrade the v1 entry to v2"
        );
        assert_eq!(upgraded.tx_pos, 1);

        // Block 3: cold cache again; spend spk_a's second output (txid1:1).
        // Now resolves via the upgraded v2 entry (direct tx read).
        idx.clear_resolver_cache();
        let tx3 = mk_tx(
            vec![(300, spk_b.clone())],
            vec![OutPoint {
                txid: txid1,
                vout: 1,
            }],
        );
        let block3 = Block {
            header: dummy_header(),
            txdata: vec![tx3],
        };
        idx.index_block_transactions(&block3, 3).unwrap();

        let sh_a = ScripthashIndex::compute_scripthash(spk_a.as_bytes());
        let sh_b = ScripthashIndex::compute_scripthash(spk_b.as_bytes());

        let hist_a = idx.get_tx_history(&sh_a).unwrap();
        assert_eq!(
            hist_a.len(),
            3,
            "both spends must appear in funder's history"
        );
        assert_eq!(hist_a[1].height, 2);
        assert_eq!(hist_a[2].height, 3);
        assert_eq!(idx.get_balance(&sh_a).unwrap().confirmed, 0);
        assert_eq!(idx.get_balance(&sh_b).unwrap().confirmed, 1000);
    }

    /// Without a resolver configured, a cross-block spend cannot be attributed
    /// and is silently skipped (graceful degradation, no panic / no wrap).
    #[test]
    fn cross_block_spend_skipped_without_resolver() {
        let tmp = TempDir::new().unwrap();
        let idx = ScripthashIndex::open(tmp.path()).unwrap();

        let spk_a = ScriptBuf::from(vec![0x51]);
        let spk_b = ScriptBuf::from(vec![0x52]);

        let tx1 = mk_tx(vec![(1000, spk_a.clone())], vec![]);
        let txid1 = tx1.compute_txid();
        let block1 = Block {
            header: dummy_header(),
            txdata: vec![tx1],
        };
        idx.index_block_transactions(&block1, 1).unwrap();

        let tx2 = mk_tx(
            vec![(1000, spk_b.clone())],
            vec![OutPoint {
                txid: txid1,
                vout: 0,
            }],
        );
        let block2 = Block {
            header: dummy_header(),
            txdata: vec![tx2],
        };
        idx.index_block_transactions(&block2, 2).unwrap();

        let sh_a = ScripthashIndex::compute_scripthash(spk_a.as_bytes());
        // Only the funding tx is in history; the spend was not resolvable.
        assert_eq!(idx.get_tx_history(&sh_a).unwrap().len(), 1);
        // Balance stays at the received value (cannot subtract an unresolved spend).
        assert_eq!(idx.get_balance(&sh_a).unwrap().confirmed, 1000);
    }
}
