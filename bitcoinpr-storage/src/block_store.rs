use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use tracing::{debug, warn};

use crate::error::{StorageError, StorageResult};
use crate::header_index::HeaderIndex;

const MAX_BLOCK_FILE_SIZE: u64 = 128 * 1024 * 1024; // 128 MB per file

/// fsync the current block file every N async writes. Aligned roughly with
/// the UTXO flush cadence (500 blocks) so that on a crash the worst case is
/// re-downloading a small tail whose UTXO effects also weren't committed.
const FSYNC_EVERY_N_WRITES: u32 = 500;

/// Cap on cached read handles. Reads are heavily skewed toward a handful of
/// hot files (scripthash backfill walks funding blocks, peers request recent
/// blocks), so a small cache captures nearly all reopens.
const READ_HANDLE_CACHE_MAX: usize = 8;

/// Position of a block within the flat file storage.
#[derive(Debug, Clone, Copy)]
pub struct BlockPos {
    pub file_num: u32,
    pub offset: u64,
    pub size: u32,
}

impl BlockPos {
    pub fn serialize(&self) -> [u8; 16] {
        let mut buf = [0u8; 16];
        buf[0..4].copy_from_slice(&self.file_num.to_le_bytes());
        buf[4..12].copy_from_slice(&self.offset.to_le_bytes());
        buf[12..16].copy_from_slice(&self.size.to_le_bytes());
        buf
    }

    pub fn deserialize(data: &[u8; 16]) -> Self {
        BlockPos {
            file_num: u32::from_le_bytes(data[0..4].try_into().expect("fixed-size slice")),
            offset: u64::from_le_bytes(data[4..12].try_into().expect("fixed-size slice")),
            size: u32::from_le_bytes(data[12..16].try_into().expect("fixed-size slice")),
        }
    }
}

/// Flat file block storage similar to Bitcoin Core's blk*.dat files.
///
/// Stores raw serialized blocks in append-only files. Uses a RocksDB index
/// (via HeaderIndex) to map BlockHash -> file position.
///
/// Supports async writes: `store_block_async` reserves a position immediately
/// and queues the actual disk write to a background thread.
pub struct BlockStore {
    blocks_dir: PathBuf,
    /// Rotate to a new blk file once the current one reaches this size.
    /// `MAX_BLOCK_FILE_SIZE` in production; overridable for tests so file
    /// rotation and pruning are exercisable with small blocks.
    max_file_size: u64,
    /// Current file being written to.
    current_file: Mutex<CurrentFile>,
    /// Background writer channel (if started). Bounded: if the writer thread
    /// falls behind the disk, senders block instead of queueing unbounded
    /// serialized blocks in memory (natural backpressure on validation).
    write_tx: Mutex<Option<std::sync::mpsc::SyncSender<WriteCmd>>>,
    /// Cached read handles keyed by file number. Positional reads
    /// (`read_exact_at`) need no seek state, so one shared handle per file
    /// serves concurrent readers without reopening per read.
    read_handles: Mutex<HashMap<u32, Arc<File>>>,
}

enum WriteCmd {
    Block {
        path: PathBuf,
        data: Vec<u8>, // [4-byte size header][raw block]
    },
    /// Flush all pending writes and fsync the current file. The writer
    /// thread acks on the given channel once the fsync completes.
    Flush(std::sync::mpsc::Sender<()>),
}

struct CurrentFile {
    file_num: u32,
    offset: u64,
}

impl BlockStore {
    /// Open or create block storage in the given directory.
    pub fn open(blocks_dir: &Path) -> StorageResult<Self> {
        Self::open_with_max_file_size(blocks_dir, MAX_BLOCK_FILE_SIZE)
    }

    /// Open with a custom rotation size. Exposed for tests (small sizes make
    /// file rotation and pruning testable); production uses [`Self::open`].
    #[doc(hidden)]
    pub fn open_with_max_file_size(blocks_dir: &Path, max_file_size: u64) -> StorageResult<Self> {
        fs::create_dir_all(blocks_dir)?;

        // Find the latest block file and its size
        let (file_num, offset) = Self::find_latest_file(blocks_dir, max_file_size);

        Ok(BlockStore {
            blocks_dir: blocks_dir.to_path_buf(),
            max_file_size,
            current_file: Mutex::new(CurrentFile { file_num, offset }),
            write_tx: Mutex::new(None),
            read_handles: Mutex::new(HashMap::new()),
        })
    }

    /// Return true if `dir` contains at least one `blk*.dat` file. Used to warn
    /// when `--blocksdir` is set but existing block files were never migrated
    /// out of the datadir.
    pub fn has_block_files(dir: &Path) -> bool {
        fs::read_dir(dir)
            .map(|rd| {
                rd.filter_map(|e| e.ok()).any(|e| {
                    e.file_name()
                        .to_str()
                        .map(|n| n.starts_with("blk") && n.ends_with(".dat"))
                        .unwrap_or(false)
                })
            })
            .unwrap_or(false)
    }

    /// Move all `blk*.dat` files from `from` to `to`. Used by `--migrateblocks`
    /// to relocate raw block data onto alternate (slower/bigger) storage while
    /// the RocksDB indexes stay on the original drive.
    ///
    /// This is safe to point at a different filesystem (the common case: moving
    /// to a separate HDD): `rename` is tried first, and on `EXDEV` it falls back
    /// to copy-to-temp + fsync + atomic rename + remove-source, so an aborted
    /// run never leaves a half-written file at the canonical destination name.
    ///
    /// The block-position index stores only `(file_num, offset, size)` — never
    /// the directory — so callers simply re-open the `BlockStore` at `to`
    /// afterward with no index changes. Returns the number of files moved.
    pub fn migrate(from: &Path, to: &Path) -> StorageResult<u32> {
        if from == to || !from.exists() {
            return Ok(0);
        }
        fs::create_dir_all(to)?;

        let mut sources: Vec<PathBuf> = fs::read_dir(from)?
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| {
                p.file_name()
                    .and_then(|n| n.to_str())
                    .map(|n| n.starts_with("blk") && n.ends_with(".dat"))
                    .unwrap_or(false)
            })
            .collect();
        sources.sort();

        let mut moved = 0u32;
        for src in sources {
            let name = match src.file_name() {
                Some(n) => n.to_owned(),
                None => continue,
            };
            let dst = to.join(&name);

            // Resume support: if a fully-sized copy already sits at the
            // destination (e.g. from an interrupted earlier run), treat it as
            // done and just drop the source rather than erroring out.
            if dst.exists() {
                let src_len = fs::metadata(&src)?.len();
                let dst_len = fs::metadata(&dst)?.len();
                if src_len == dst_len {
                    fs::remove_file(&src)?;
                    continue;
                }
                return Err(StorageError::Serialization(format!(
                    "migrate conflict: {dst:?} already exists at destination with a \
                     different size ({dst_len} vs {src_len}); refusing to overwrite"
                )));
            }

            match fs::rename(&src, &dst) {
                Ok(()) => {}
                Err(_) => {
                    // Cross-filesystem move: copy to a temp file on the
                    // destination fs, fsync, then atomically rename into place
                    // before removing the source.
                    let tmp = to.join(format!("{}.tmp", name.to_string_lossy()));
                    let _ = fs::remove_file(&tmp); // clear any stale temp
                    let copied = fs::copy(&src, &tmp)?;
                    let src_len = fs::metadata(&src)?.len();
                    if copied != src_len {
                        let _ = fs::remove_file(&tmp);
                        return Err(StorageError::Serialization(format!(
                            "migrate copy short read for {src:?}: {copied} of {src_len} bytes"
                        )));
                    }
                    if let Ok(f) = OpenOptions::new().write(true).open(&tmp) {
                        if let Err(e) = f.sync_all() {
                            warn!("fsync of migrated file {:?} failed: {}", tmp, e);
                        }
                    }
                    fs::rename(&tmp, &dst)?;
                    fs::remove_file(&src)?;
                }
            }
            moved += 1;
            debug!("Migrated block file {:?} -> {:?}", name, to);
        }

        Ok(moved)
    }

    /// Find the file to append to: the highest-numbered blk file (or the next
    /// one if it is already full). Scans the directory for the maximum file
    /// number rather than walking up from 0 — pruning deletes the *oldest*
    /// files, so walking from 0 would stop at the pruned gap, restart
    /// numbering at 0, and corrupt live higher-numbered files.
    fn find_latest_file(dir: &Path, max_file_size: u64) -> (u32, u64) {
        let max_existing: Option<u32> = fs::read_dir(dir)
            .ok()
            .into_iter()
            .flatten()
            .filter_map(|e| e.ok())
            .filter_map(|e| {
                let name = e.file_name();
                let name = name.to_str()?;
                let num = name.strip_prefix("blk")?.strip_suffix(".dat")?;
                num.parse::<u32>().ok()
            })
            .max();

        match max_existing {
            None => (0, 0),
            Some(file_num) => {
                let path = dir.join(format!("blk{file_num:05}.dat"));
                let size = fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
                if size < max_file_size {
                    (file_num, size)
                } else {
                    (file_num + 1, 0)
                }
            }
        }
    }

    /// All existing block files as `(file_num, size_bytes)`, ascending by
    /// file number. Used by the pruner to pick deletion candidates.
    pub fn list_block_files(&self) -> StorageResult<Vec<(u32, u64)>> {
        let mut files: Vec<(u32, u64)> = fs::read_dir(&self.blocks_dir)?
            .filter_map(|e| e.ok())
            .filter_map(|e| {
                let name = e.file_name();
                let name = name.to_str()?;
                let num = name
                    .strip_prefix("blk")?
                    .strip_suffix(".dat")?
                    .parse::<u32>()
                    .ok()?;
                let size = e.metadata().ok()?.len();
                Some((num, size))
            })
            .collect();
        files.sort_unstable_by_key(|(num, _)| *num);
        Ok(files)
    }

    /// File number currently being appended to. The pruner must never delete
    /// this file (or anything after it).
    pub fn current_file_num(&self) -> u32 {
        self.current_file
            .lock()
            .expect("block store current_file mutex poisoned")
            .file_num
    }

    /// Delete a block file (pruning). Refuses to delete the current write
    /// file. Returns the bytes freed. The caller is responsible for removing
    /// the block-position index entries of every block in the file *before*
    /// calling this, so no reader can hold a position into a deleted file.
    pub fn delete_block_file(&self, file_num: u32) -> StorageResult<u64> {
        let current = self.current_file_num();
        if file_num >= current {
            return Err(StorageError::Serialization(format!(
                "refusing to prune block file {file_num}: current write file is {current}"
            )));
        }
        let path = self.block_file_path(file_num);
        let size = fs::metadata(&path)?.len();
        // Drop any cached read handle first so the open fd doesn't keep the
        // pruned file's disk space pinned after the unlink.
        self.read_handles
            .lock()
            .expect("block store read_handles mutex poisoned")
            .remove(&file_num);
        fs::remove_file(&path)?;
        debug!("Pruned block file {:?} ({} bytes)", path, size);
        Ok(size)
    }

    fn block_file_path(&self, file_num: u32) -> PathBuf {
        self.blocks_dir.join(format!("blk{file_num:05}.dat"))
    }

    /// Store a raw block and return its position.
    pub fn store_block(&self, raw_block: &[u8]) -> StorageResult<BlockPos> {
        let mut current = self
            .current_file
            .lock()
            .expect("block store current_file mutex poisoned");

        // Rotate to next file if current one is large enough
        if current.offset > 0 && current.offset + raw_block.len() as u64 > self.max_file_size {
            // fsync the file we're rotating away from so its bytes are durable
            // before any new file starts taking writes.
            let prev_path = self.block_file_path(current.file_num);
            if let Ok(f) = OpenOptions::new().write(true).open(&prev_path) {
                if let Err(e) = f.sync_data() {
                    warn!("fsync on rotation failed for {:?}: {}", prev_path, e);
                }
            }
            current.file_num += 1;
            current.offset = 0;
        }

        let path = self.block_file_path(current.file_num);
        let mut file = OpenOptions::new().create(true).append(true).open(&path)?;

        // Write: [4 bytes size][raw block data]
        let size = raw_block.len() as u32;
        file.write_all(&size.to_le_bytes())?;
        file.write_all(raw_block)?;

        let pos = BlockPos {
            file_num: current.file_num,
            offset: current.offset,
            size,
        };

        current.offset += 4 + raw_block.len() as u64;

        debug!(
            "Stored block: file={}, offset={}, size={}",
            pos.file_num, pos.offset, pos.size
        );

        Ok(pos)
    }

    /// Start the background block writer thread.
    /// Must be called once before using `store_block_async`.
    pub fn start_background_writer(&self) {
        // 256 queued blocks ≈ a few hundred MB worst case — bounded so a slow
        // disk back-pressures block connection instead of growing the heap.
        let (tx, rx) = std::sync::mpsc::sync_channel::<WriteCmd>(256);
        *self
            .write_tx
            .lock()
            .expect("block store write_tx mutex poisoned") = Some(tx);

        std::thread::Builder::new()
            .name("block-writer".into())
            .spawn(move || {
                // Persistent append handle for the current blk file: reopened
                // only on rotation (path change) or after a write error, not
                // per block. The handle doubles as the fsync target.
                let mut open_file: Option<(PathBuf, File)> = None;
                let mut writes_since_fsync: u32 = 0;
                // A command pulled off the queue during coalescing that did
                // not match the batch (rotation boundary or a Flush).
                let mut carry: Option<WriteCmd> = None;

                loop {
                    let cmd = match carry.take() {
                        Some(c) => c,
                        None => match rx.recv() {
                            Ok(c) => c,
                            Err(_) => break,
                        },
                    };
                    match cmd {
                        WriteCmd::Block { path, mut data } => {
                            // Coalesce every already-queued write for the same
                            // file into one buffer → one write_all syscall.
                            let mut coalesced: u32 = 1;
                            while let Ok(next) = rx.try_recv() {
                                match next {
                                    WriteCmd::Block {
                                        path: next_path,
                                        data: next_data,
                                    } if next_path == path => {
                                        data.extend_from_slice(&next_data);
                                        coalesced += 1;
                                    }
                                    other => {
                                        carry = Some(other);
                                        break;
                                    }
                                }
                            }

                            let needs_open = match open_file {
                                Some((ref p, _)) => *p != path,
                                None => true,
                            };
                            if needs_open {
                                match OpenOptions::new().create(true).append(true).open(&path) {
                                    Ok(f) => open_file = Some((path.clone(), f)),
                                    Err(e) => {
                                        warn!("Background block write open failed: {}", e);
                                        continue;
                                    }
                                }
                            }
                            let (_, file) = open_file.as_mut().expect("opened above");
                            if let Err(e) = file.write_all(&data) {
                                warn!("Background block write failed: {}", e);
                                // Drop the handle so the next write reopens in
                                // append mode at the true end of file.
                                open_file = None;
                                continue;
                            }
                            writes_since_fsync += coalesced;

                            // Periodic fsync — keeps the durable tail within
                            // FSYNC_EVERY_N_WRITES of the current write head.
                            if writes_since_fsync >= FSYNC_EVERY_N_WRITES {
                                if let Err(e) = file.sync_data() {
                                    warn!("periodic fsync failed for {:?}: {}", path, e);
                                }
                                writes_since_fsync = 0;
                            }
                        }
                        WriteCmd::Flush(ack) => {
                            if let Some((ref p, ref f)) = open_file {
                                if let Err(e) = f.sync_data() {
                                    warn!("Flush fsync failed for {:?}: {}", p, e);
                                }
                            }
                            writes_since_fsync = 0;
                            let _ = ack.send(());
                        }
                    }
                }
                debug!("Block writer thread exiting");
            })
            .expect("failed to spawn block writer thread");
    }

    /// Store a block asynchronously: reserve the position immediately (for
    /// index updates) and queue the actual disk write to a background thread.
    /// Falls back to synchronous write if the background writer isn't running.
    pub fn store_block_async(&self, raw_block: &[u8]) -> StorageResult<BlockPos> {
        let mut current = self
            .current_file
            .lock()
            .expect("block store current_file mutex poisoned");

        if current.offset > 0 && current.offset + raw_block.len() as u64 > self.max_file_size {
            // fsync the file we're rotating away from before any writes to the
            // new file. Route through the writer so it's ordered after any
            // queued writes that still belong to the old file.
            let prev_path = self.block_file_path(current.file_num);
            let tx_guard = self
                .write_tx
                .lock()
                .expect("block store write_tx mutex poisoned");
            if let Some(ref tx) = *tx_guard {
                let (ack_tx, ack_rx) = std::sync::mpsc::channel::<()>();
                if tx.send(WriteCmd::Flush(ack_tx)).is_ok() {
                    drop(tx_guard);
                    // Bounded wait — if the writer is hung, don't deadlock
                    // rotation. The next-write fsync will catch up.
                    let _ = ack_rx.recv_timeout(std::time::Duration::from_secs(10));
                } else {
                    drop(tx_guard);
                }
            } else {
                drop(tx_guard);
                if let Ok(f) = OpenOptions::new().write(true).open(&prev_path) {
                    if let Err(e) = f.sync_data() {
                        warn!("fsync on rotation failed for {:?}: {}", prev_path, e);
                    }
                }
            }
            current.file_num += 1;
            current.offset = 0;
        }

        let pos = BlockPos {
            file_num: current.file_num,
            offset: current.offset,
            size: raw_block.len() as u32,
        };

        let path = self.block_file_path(current.file_num);
        current.offset += 4 + raw_block.len() as u64;
        drop(current);

        // Build the write payload: [4-byte size][raw block]
        let mut data = Vec::with_capacity(4 + raw_block.len());
        data.extend_from_slice(&(raw_block.len() as u32).to_le_bytes());
        data.extend_from_slice(raw_block);

        let tx_guard = self
            .write_tx
            .lock()
            .expect("block store write_tx mutex poisoned");
        if let Some(ref tx) = *tx_guard {
            let _ = tx.send(WriteCmd::Block { path, data });
        } else {
            drop(tx_guard);
            // Fallback: synchronous write
            let mut file = OpenOptions::new().create(true).append(true).open(&path)?;
            file.write_all(&data)?;
        }

        debug!(
            "Stored block: file={}, offset={}, size={}",
            pos.file_num, pos.offset, pos.size
        );

        Ok(pos)
    }

    /// Verify that a block at a given position is readable and matches the expected hash.
    ///
    /// Checks:
    /// - File exists and offset is within bounds
    /// - Size header matches `BlockPos.size`
    /// - Data deserializes as a valid `Block`
    /// - Block hash matches `expected_hash`
    ///
    /// Returns `Ok(true)` if valid, `Ok(false)` if any check fails.
    /// Only returns `Err` for unexpected I/O errors.
    pub fn verify_block(&self, pos: &BlockPos, expected_hash: &[u8; 32]) -> StorageResult<bool> {
        let path = self.block_file_path(pos.file_num);

        // Check file exists and offset is within bounds
        let file_len = match fs::metadata(&path) {
            Ok(m) => m.len(),
            Err(_) => return Ok(false),
        };
        if pos.offset + 4 + pos.size as u64 > file_len {
            return Ok(false);
        }

        // Read and verify size header
        let mut file = match File::open(&path) {
            Ok(f) => f,
            Err(_) => return Ok(false),
        };
        if file.seek(SeekFrom::Start(pos.offset)).is_err() {
            return Ok(false);
        }
        let mut size_buf = [0u8; 4];
        if file.read_exact(&mut size_buf).is_err() {
            return Ok(false);
        }
        let size = u32::from_le_bytes(size_buf);
        if size != pos.size {
            return Ok(false);
        }

        // Read block data
        let mut data = vec![0u8; size as usize];
        if file.read_exact(&mut data).is_err() {
            return Ok(false);
        }

        // Deserialize and verify hash
        match bitcoin::consensus::encode::deserialize::<bitcoin::Block>(&data) {
            Ok(block) => {
                let hash = block.block_hash();
                let hash_bytes: &[u8; 32] = AsRef::<[u8; 32]>::as_ref(&hash);
                Ok(hash_bytes == expected_hash)
            }
            Err(_) => Ok(false),
        }
    }

    /// Scan a height range and return heights where blocks are missing or corrupt.
    ///
    /// For each height in `from..=to`, checks:
    /// 1. Hash exists in the header index at that height
    /// 2. A BlockPos is stored for that hash
    /// 3. The block at that position passes `verify_block`
    ///
    /// Returns the list of heights that failed any check.
    pub fn scan_block_store(
        &self,
        header_index: &HeaderIndex,
        from: u32,
        to: u32,
    ) -> StorageResult<Vec<u32>> {
        let mut missing = Vec::new();

        for h in from..=to {
            let hash = match header_index.get_hash_at_height(h) {
                Ok(Some(hash)) => hash,
                _ => {
                    missing.push(h);
                    continue;
                }
            };

            let hash_bytes: &[u8; 32] = AsRef::<[u8; 32]>::as_ref(&hash);

            let pos = match header_index.get_block_pos(&hash) {
                Ok(Some(pos)) => pos,
                _ => {
                    missing.push(h);
                    continue;
                }
            };

            match self.verify_block(&pos, hash_bytes) {
                Ok(true) => {} // Block is good
                Ok(false) => {
                    // Stale BlockPos (partial write, wrong offset, or hash mismatch).
                    // Drop the index entry so the block is re-downloaded and rewritten.
                    if let Err(e) = header_index.remove_block_pos(&hash) {
                        tracing::warn!(
                            height = h,
                            hash = %hash,
                            error = %e,
                            "Failed to remove corrupt block_pos entry"
                        );
                    } else {
                        tracing::debug!(
                            height = h,
                            hash = %hash,
                            "Removed corrupt block_pos entry — will re-download"
                        );
                    }
                    missing.push(h);
                }
                Err(e) => {
                    tracing::warn!(height = h, error = %e, "Block verify I/O error");
                    missing.push(h);
                }
            }
        }

        if !missing.is_empty() {
            tracing::info!(
                from,
                to,
                missing_count = missing.len(),
                "Block store scan found missing/corrupt blocks"
            );
        }

        Ok(missing)
    }

    /// Scan all blk*.dat files and rebuild the block_pos index in the header
    /// index. This recovers BlockPos mappings lost during header truncation or
    /// recovery, allowing local block replay without re-downloading from peers.
    ///
    /// Returns the number of blocks successfully re-indexed.
    pub fn reindex_block_files(&self, header_index: &HeaderIndex) -> StorageResult<u32> {
        self.reindex_block_files_cancellable(header_index, None)
    }

    /// Same as `reindex_block_files`, but checks `shutting_down` between block
    /// files and bails out cleanly when shutdown is requested.
    ///
    /// On a large datadir this scan can run for tens of minutes; without the
    /// guard the background task survives long past the main event loop's exit,
    /// keeping the RocksDB handles open and racing with the next startup.
    pub fn reindex_block_files_cancellable(
        &self,
        header_index: &HeaderIndex,
        shutting_down: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
    ) -> StorageResult<u32> {
        use tracing::info;

        let mut file_num = 0u32;
        let mut total_indexed = 0u32;
        let mut total_skipped = 0u32;
        let start = std::time::Instant::now();

        loop {
            // Check shutdown between files (coarse-grained, but each file is
            // bounded at 128 MB so the worst-case latency is a single file scan).
            if let Some(ref sd) = shutting_down {
                if sd.load(std::sync::atomic::Ordering::Relaxed) {
                    info!(
                        files_scanned = file_num,
                        total_indexed, "Block file reindex interrupted by shutdown"
                    );
                    return Ok(total_indexed);
                }
            }

            let path = self.block_file_path(file_num);
            if !path.exists() {
                break;
            }

            let file_len = fs::metadata(&path)?.len();
            let mut file = File::open(&path)?;
            let mut offset = 0u64;
            let mut file_indexed = 0u32;

            while offset + 4 < file_len {
                // Read size header
                if file.seek(SeekFrom::Start(offset)).is_err() {
                    break;
                }
                let mut size_buf = [0u8; 4];
                if file.read_exact(&mut size_buf).is_err() {
                    break;
                }
                let size = u32::from_le_bytes(size_buf);

                // Sanity check: block size should be reasonable (up to 4MB)
                if size == 0 || size > 4_000_000 || offset + 4 + size as u64 > file_len {
                    break;
                }

                // Read block data
                let mut data = vec![0u8; size as usize];
                if file.read_exact(&mut data).is_err() {
                    break;
                }

                // Deserialize to get block hash
                match bitcoin::consensus::encode::deserialize::<bitcoin::Block>(&data) {
                    Ok(block) => {
                        let hash = block.block_hash();
                        // Only index blocks on the canonical header chain whose
                        // height→hash entry matches this on-disk hash. Positions
                        // keyed to fork/orphan hashes are ignored so replay can
                        // find the canonical hash via get_hash_at_height(h).
                        let canonical = match header_index.get_header(&hash) {
                            Ok(Some(stored)) => header_index
                                .get_hash_at_height(stored.height)
                                .ok()
                                .flatten()
                                .map(|canonical_hash| canonical_hash == hash)
                                .unwrap_or(false),
                            _ => false,
                        };
                        if !canonical {
                            total_skipped += 1;
                        } else {
                            let already_indexed =
                                header_index.get_block_pos(&hash).ok().flatten().is_some();
                            if !already_indexed {
                                let pos = BlockPos {
                                    file_num,
                                    offset,
                                    size,
                                };
                                if let Err(e) = header_index.set_block_pos(&hash, &pos) {
                                    debug!("Failed to set block_pos for {}: {}", hash, e);
                                } else {
                                    file_indexed += 1;
                                    total_indexed += 1;
                                }
                            } else {
                                total_skipped += 1;
                            }
                        }
                    }
                    Err(_) => {
                        // Corrupt block entry — skip and try next offset
                        total_skipped += 1;
                    }
                }

                offset += 4 + size as u64;
            }

            if file_indexed > 0 || file_num == 0 {
                info!(
                    file_num,
                    file_indexed, total_indexed, "Block file scan progress"
                );
            }
            file_num += 1;
        }

        let elapsed = start.elapsed();
        info!(
            total_indexed,
            total_skipped,
            files_scanned = file_num,
            elapsed_secs = elapsed.as_secs(),
            "Block file reindex complete"
        );

        Ok(total_indexed)
    }

    /// Read a raw block from a given position.
    pub fn read_block(&self, pos: &BlockPos) -> StorageResult<Vec<u8>> {
        match self.read_block_at(pos) {
            Ok(data) => Ok(data),
            Err(first_err) => {
                // Read-your-writes: store_block_async() returns a BlockPos before
                // the bytes reach disk (the actual write is queued to a background
                // thread). A read right after connect/store — e.g. serving a
                // just-connected block to a peer via getdata, or reading reorg
                // blocks for propagation — can therefore race ahead of the write
                // and see a not-yet-created file (NotFound), a short read
                // ("failed to fill whole buffer" / UnexpectedEof), or a partial
                // size header (size mismatch). Drain the writer queue and retry
                // once. Without this the seed silently fails to serve a freshly
                // connected block, stranding the requesting peer on the old chain
                // (observed: reorg blocks dropped during propagation, peers stuck
                // one block behind).
                if self.flush().is_ok() {
                    if let Ok(data) = self.read_block_at(pos) {
                        return Ok(data);
                    }
                }
                Err(first_err)
            }
        }
    }

    /// Get (or open and cache) a shared read handle for a block file.
    fn read_handle(&self, file_num: u32) -> StorageResult<Arc<File>> {
        let mut cache = self
            .read_handles
            .lock()
            .expect("block store read_handles mutex poisoned");
        if let Some(f) = cache.get(&file_num) {
            return Ok(Arc::clone(f));
        }
        let file = Arc::new(File::open(self.block_file_path(file_num))?);
        if cache.len() >= READ_HANDLE_CACHE_MAX {
            // Simple bound: drop everything and refill. Reads are skewed to a
            // few hot files, so the occasional full refill is negligible.
            cache.clear();
        }
        cache.insert(file_num, Arc::clone(&file));
        Ok(file)
    }

    /// Read a byte range from within a stored block (block-relative offset,
    /// e.g. a single transaction located via a v2 tx-index entry). One small
    /// positional read instead of pulling the whole block. Same
    /// read-your-writes retry as [`read_block`](Self::read_block).
    pub fn read_block_slice(
        &self,
        pos: &BlockPos,
        offset: u32,
        len: u32,
    ) -> StorageResult<Vec<u8>> {
        let end = offset
            .checked_add(len)
            .ok_or_else(|| StorageError::Serialization("block slice range overflow".into()))?;
        if end > pos.size {
            return Err(StorageError::Serialization(format!(
                "block slice out of range: {}..{} exceeds block size {}",
                offset, end, pos.size
            )));
        }
        match self.read_block_slice_at(pos, offset, len) {
            Ok(data) => Ok(data),
            Err(first_err) => {
                if self.flush().is_ok() {
                    if let Ok(data) = self.read_block_slice_at(pos, offset, len) {
                        return Ok(data);
                    }
                }
                Err(first_err)
            }
        }
    }

    fn read_block_slice_at(&self, pos: &BlockPos, offset: u32, len: u32) -> StorageResult<Vec<u8>> {
        use std::os::unix::fs::FileExt;

        let file = self.read_handle(pos.file_num)?;
        let mut data = vec![0u8; len as usize];
        file.read_exact_at(&mut data, pos.offset + 4 + offset as u64)?;
        Ok(data)
    }

    fn read_block_at(&self, pos: &BlockPos) -> StorageResult<Vec<u8>> {
        use std::os::unix::fs::FileExt;

        let file = self.read_handle(pos.file_num)?;

        // Read size header (positional read — no seek state, so the cached
        // handle can serve concurrent readers).
        let mut size_buf = [0u8; 4];
        file.read_exact_at(&mut size_buf, pos.offset)?;
        let size = u32::from_le_bytes(size_buf);

        if size != pos.size {
            return Err(StorageError::Serialization(format!(
                "block size mismatch: expected {}, got {}",
                pos.size, size
            )));
        }

        let mut data = vec![0u8; size as usize];
        file.read_exact_at(&mut data, pos.offset + 4)?;
        Ok(data)
    }

    /// Flush any in-flight async writes to disk and fsync the current block
    /// file. Call this on shutdown so the most-recent blocks survive an
    /// unclean termination instead of being left in the page cache where a
    /// partial write turns into the next startup's "block size mismatch:
    /// expected N, got <garbage>" corruption.
    ///
    /// Blocks until the writer thread acks the flush (with a 30s ceiling).
    /// If no background writer is running, fsyncs the current file directly.
    pub fn flush(&self) -> StorageResult<()> {
        let tx_guard = self
            .write_tx
            .lock()
            .expect("block store write_tx mutex poisoned");
        if let Some(ref tx) = *tx_guard {
            let (ack_tx, ack_rx) = std::sync::mpsc::channel::<()>();
            if tx.send(WriteCmd::Flush(ack_tx)).is_err() {
                // Writer already exited — no queued work to flush.
                return Ok(());
            }
            drop(tx_guard);
            let _ = ack_rx.recv_timeout(std::time::Duration::from_secs(30));
        } else {
            drop(tx_guard);
            // Sync-write mode: fsync the current file directly.
            let current = self
                .current_file
                .lock()
                .expect("block store current_file mutex poisoned");
            let path = self.block_file_path(current.file_num);
            drop(current);
            if path.exists() {
                let f = OpenOptions::new().write(true).open(&path)?;
                f.sync_data()?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn test_block_store_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let store = BlockStore::open(&dir.path().join("blocks")).unwrap();

        let block_data = b"fake block data for testing purposes";
        let pos = store.store_block(block_data).unwrap();

        assert_eq!(pos.file_num, 0);
        assert_eq!(pos.offset, 0);
        assert_eq!(pos.size, block_data.len() as u32);

        let retrieved = store.read_block(&pos).unwrap();
        assert_eq!(retrieved, block_data);
    }

    #[test]
    fn test_multiple_blocks() {
        let dir = tempfile::tempdir().unwrap();
        let store = BlockStore::open(&dir.path().join("blocks")).unwrap();

        let block1 = b"first block data";
        let block2 = b"second block data that is longer";

        let pos1 = store.store_block(block1).unwrap();
        let pos2 = store.store_block(block2).unwrap();

        // Second block should be in same file but different offset
        assert_eq!(pos1.file_num, pos2.file_num);
        assert!(pos2.offset > pos1.offset);

        // Both should read back correctly
        assert_eq!(store.read_block(&pos1).unwrap(), block1);
        assert_eq!(store.read_block(&pos2).unwrap(), block2);
    }

    #[test]
    fn test_block_pos_serialization() {
        let pos = BlockPos {
            file_num: 42,
            offset: 12345,
            size: 999,
        };
        let bytes = pos.serialize();
        let restored = BlockPos::deserialize(&bytes);
        assert_eq!(restored.file_num, 42);
        assert_eq!(restored.offset, 12345);
        assert_eq!(restored.size, 999);
    }

    #[test]
    fn test_verify_block_valid() {
        let dir = tempfile::tempdir().unwrap();
        let store = BlockStore::open(&dir.path().join("blocks")).unwrap();

        // Create a real genesis block to test with
        let genesis = bitcoin::consensus::params::Params::new(bitcoin::Network::Regtest).clone();
        let block = bitcoin::constants::genesis_block(&genesis);
        let raw = bitcoin::consensus::encode::serialize(&block);
        let pos = store.store_block(&raw).unwrap();

        let hash = block.block_hash();
        let hash_bytes: &[u8; 32] = AsRef::<[u8; 32]>::as_ref(&hash);

        assert!(store.verify_block(&pos, hash_bytes).unwrap());
    }

    #[test]
    fn test_verify_block_wrong_hash() {
        let dir = tempfile::tempdir().unwrap();
        let store = BlockStore::open(&dir.path().join("blocks")).unwrap();

        let genesis = bitcoin::consensus::params::Params::new(bitcoin::Network::Regtest).clone();
        let block = bitcoin::constants::genesis_block(&genesis);
        let raw = bitcoin::consensus::encode::serialize(&block);
        let pos = store.store_block(&raw).unwrap();

        let wrong_hash = [0xffu8; 32];
        assert!(!store.verify_block(&pos, &wrong_hash).unwrap());
    }

    #[test]
    fn test_verify_block_missing_file() {
        let dir = tempfile::tempdir().unwrap();
        let store = BlockStore::open(&dir.path().join("blocks")).unwrap();

        let pos = BlockPos {
            file_num: 99,
            offset: 0,
            size: 100,
        };
        let hash = [0x00u8; 32];
        assert!(!store.verify_block(&pos, &hash).unwrap());
    }

    #[test]
    fn test_flush_sync_mode_fsyncs_current_file() {
        let dir = tempfile::tempdir().unwrap();
        let store = BlockStore::open(&dir.path().join("blocks")).unwrap();
        // No background writer started — flush should hit the sync path.
        let pos = store.store_block(b"some block").unwrap();
        store.flush().expect("flush should succeed in sync mode");
        // File should still be readable after flush.
        assert_eq!(store.read_block(&pos).unwrap(), b"some block");
    }

    #[test]
    fn test_flush_async_mode_drains_queue() {
        let dir = tempfile::tempdir().unwrap();
        let store = BlockStore::open(&dir.path().join("blocks")).unwrap();
        store.start_background_writer();

        // Reserve a position via async, then flush, then read — flush must
        // wait for the background write to land on disk.
        let pos = store.store_block_async(b"async block payload").unwrap();
        store.flush().expect("flush should drain the writer queue");
        assert_eq!(store.read_block(&pos).unwrap(), b"async block payload");
    }

    #[test]
    fn test_flush_with_no_writes() {
        let dir = tempfile::tempdir().unwrap();
        let store = BlockStore::open(&dir.path().join("blocks")).unwrap();
        store.start_background_writer();
        // Flushing an idle writer should not block or error.
        store.flush().expect("idle flush should succeed");
    }

    #[test]
    fn test_migrate_moves_block_files_and_preserves_positions() {
        let from_dir = tempfile::tempdir().unwrap();
        let to_dir = tempfile::tempdir().unwrap();
        let from = from_dir.path().join("blocks");
        let to = to_dir.path().join("blocks");

        // Write two blocks and a non-block file that must NOT be moved.
        let store = BlockStore::open(&from).unwrap();
        let pos1 = store.store_block(b"first block payload").unwrap();
        let pos2 = store.store_block(b"second block payload").unwrap();
        fs::write(from.join("index.txt"), b"keep me").unwrap();
        drop(store);

        assert!(BlockStore::has_block_files(&from));
        assert!(!BlockStore::has_block_files(&to));

        let moved = BlockStore::migrate(&from, &to).unwrap();
        assert_eq!(moved, 1, "single blk00000.dat file moved");

        // Block files relocated; the unrelated file stays behind.
        assert!(!BlockStore::has_block_files(&from));
        assert!(BlockStore::has_block_files(&to));
        assert!(from.join("index.txt").exists());

        // Re-open at the new location; the old BlockPos values still resolve
        // because positions never recorded the directory.
        let moved_store = BlockStore::open(&to).unwrap();
        assert_eq!(
            moved_store.read_block(&pos1).unwrap(),
            b"first block payload"
        );
        assert_eq!(
            moved_store.read_block(&pos2).unwrap(),
            b"second block payload"
        );
    }

    #[test]
    fn test_migrate_noop_when_same_or_missing() {
        let dir = tempfile::tempdir().unwrap();
        let blocks = dir.path().join("blocks");
        let store = BlockStore::open(&blocks).unwrap();
        store.store_block(b"x").unwrap();
        drop(store);

        // Same source and destination is a no-op.
        assert_eq!(BlockStore::migrate(&blocks, &blocks).unwrap(), 0);
        // Missing source is a no-op.
        let missing = dir.path().join("does-not-exist");
        assert_eq!(BlockStore::migrate(&missing, &blocks).unwrap(), 0);
    }

    #[test]
    fn test_migrate_resumes_when_dest_already_complete() {
        let from_dir = tempfile::tempdir().unwrap();
        let to_dir = tempfile::tempdir().unwrap();
        let from = from_dir.path().join("blocks");
        let to = to_dir.path().join("blocks");

        let store = BlockStore::open(&from).unwrap();
        store.store_block(b"resumable block").unwrap();
        drop(store);

        // Simulate a prior interrupted run that already copied the file to the
        // destination at full size but left the source in place.
        fs::create_dir_all(&to).unwrap();
        fs::copy(from.join("blk00000.dat"), to.join("blk00000.dat")).unwrap();

        let moved = BlockStore::migrate(&from, &to).unwrap();
        assert_eq!(moved, 0, "already-complete file is not re-moved");
        assert!(!BlockStore::has_block_files(&from), "source dropped");
        assert!(BlockStore::has_block_files(&to));
    }

    #[test]
    fn test_verify_block_bad_offset() {
        let dir = tempfile::tempdir().unwrap();
        let store = BlockStore::open(&dir.path().join("blocks")).unwrap();

        // Store a small block
        let data = b"tiny";
        let _pos = store.store_block(data).unwrap();

        // Try to read at an offset way past the file
        let bad_pos = BlockPos {
            file_num: 0,
            offset: 999999,
            size: 100,
        };
        let hash = [0x00u8; 32];
        assert!(!store.verify_block(&bad_pos, &hash).unwrap());
    }
}
