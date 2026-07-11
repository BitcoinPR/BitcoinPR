use bitcoin::consensus::encode;
use bitcoin::hashes::{sha256, Hash};
use bitcoin::OutPoint;
use bitcoinpr_storage::{BlockStore, HeaderIndex, StorageError, StorageResult, TxIndex};
use lru::LruCache;
use rocksdb::{ColumnFamilyDescriptor, IteratorMode, Options, ReadOptions, DB};
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::num::NonZeroUsize;
use std::path::Path;
use std::sync::Arc;
use std::sync::Mutex;
use tracing::debug;

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

/// Number of deserialized blocks kept in the prevout-resolver LRU cache.
/// At ~2 MB per block this is ~400 MB, well within the `--dbcache` budget.
/// Inputs overwhelmingly spend recent outputs, so a modest cache delivers
/// 90%+ hit rates and avoids redundant HDD block reads during backfill.
const BLOCK_CACHE_CAPACITY: usize = 200;

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
    /// See [`Self::set_prevout_resolver`] and [`Self::resolve_spent_output`].
    tx_index: Option<Arc<TxIndex>>,
    header_index: Option<Arc<HeaderIndex>>,
    block_store: Option<Arc<BlockStore>>,
    /// LRU cache of recently-deserialized blocks, keyed by block hash.
    /// Dramatically reduces HDD reads during scripthash backfill since
    /// inputs overwhelmingly spend outputs from nearby blocks.
    block_cache: Mutex<LruCache<bitcoin::BlockHash, bitcoin::Block>>,
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
            block_cache: Mutex::new(LruCache::new(
                NonZeroUsize::new(BLOCK_CACHE_CAPACITY).expect("BLOCK_CACHE_CAPACITY is non-zero"),
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

    /// Release the block cache memory. Call after the backfill completes —
    /// the cache is only beneficial during bulk indexing.
    pub fn clear_block_cache(&self) {
        let mut cache = self.block_cache.lock().expect("block cache lock poisoned");
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

    /// Resolve the `(scriptPubKey, value_sats)` of a confirmed prevout by
    /// loading the funding transaction through the tx index and block store.
    /// Returns `None` if no resolver handles are configured, the prevout is
    /// not found, or any lookup fails — callers treat this as "spend not
    /// indexable" and skip it rather than failing the whole block.
    fn resolve_spent_output(&self, outpoint: &OutPoint) -> Option<(Vec<u8>, u64)> {
        let tx_index = self.tx_index.as_ref()?;
        let header_index = self.header_index.as_ref()?;
        let block_store = self.block_store.as_ref()?;

        let idx_entry = tx_index.get(&outpoint.txid).ok()??;
        let block_hash = idx_entry.block_hash;

        // Check the LRU cache first to avoid redundant HDD reads.
        let mut cache = self.block_cache.lock().expect("block cache lock poisoned");
        if let Some(block) = cache.get(&block_hash) {
            let tx = block.txdata.get(idx_entry.tx_pos as usize)?;
            let out = tx.output.get(outpoint.vout as usize)?;
            return Some((out.script_pubkey.as_bytes().to_vec(), out.value.to_sat()));
        }

        // Cache miss — read from disk and insert into cache.
        let pos = header_index.get_block_pos(&block_hash).ok()??;
        let raw = block_store.read_block(&pos).ok()?;
        let block = encode::deserialize::<bitcoin::Block>(&raw).ok()?;
        let tx = block.txdata.get(idx_entry.tx_pos as usize)?;
        let out = tx.output.get(outpoint.vout as usize)?;
        let result = (out.script_pubkey.as_bytes().to_vec(), out.value.to_sat());
        cache.put(block_hash, block);
        Some(result)
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

        // Intra-block output map so inputs spending earlier tx outputs in the
        // same block can be attributed (scriptPubKey + value) without a lookup.
        let mut block_outputs: HashMap<([u8; 32], u32), (Vec<u8>, u64)> = HashMap::new();

        for (tx_index, tx) in block.txdata.iter().enumerate() {
            let txid = tx.compute_txid();
            let txid_bytes: [u8; 32] = *AsRef::<[u8; 32]>::as_ref(&txid);
            let tx_index_u32 = tx_index as u32;

            for (vout, output) in tx.output.iter().enumerate() {
                let spk_bytes = output.script_pubkey.as_bytes();
                let scripthash = Self::compute_scripthash(spk_bytes);
                let value = output.value.to_sat();

                touches.insert((scripthash, tx_index_u32, txid_bytes));
                *balance_deltas.entry(scripthash).or_default() += value as i64;

                block_outputs.insert((txid_bytes, vout as u32), (spk_bytes.to_vec(), value));
            }

            if !tx.is_coinbase() {
                for input in &tx.input {
                    let prev_txid: [u8; 32] =
                        *AsRef::<[u8; 32]>::as_ref(&input.previous_output.txid);
                    let prev_vout = input.previous_output.vout;

                    // Resolve the spent output's scriptPubKey + value: first
                    // from this block (intra-block spend), then via the prevout
                    // resolver (cross-block spend). If neither yields it, the
                    // spend cannot be attributed and is skipped.
                    let spent = block_outputs
                        .get(&(prev_txid, prev_vout))
                        .cloned()
                        .or_else(|| self.resolve_spent_output(&input.previous_output));

                    if let Some((spent_spk, value)) = spent {
                        let scripthash = Self::compute_scripthash(&spent_spk);
                        touches.insert((scripthash, tx_index_u32, txid_bytes));
                        *balance_deltas.entry(scripthash).or_default() -= value as i64;
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

        self.db.write(batch)?;

        debug!(
            height,
            txs = block.txdata.len(),
            scripthashes = balance_deltas.len(),
            touches = touches.len(),
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
            .index_block_at_height(&block1.block_hash(), &[txid1], 1)
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
