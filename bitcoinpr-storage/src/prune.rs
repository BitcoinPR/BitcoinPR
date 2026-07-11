//! Block-file pruning (Phase 3 of the 2026-07-02 review fix line).
//!
//! Deletes the oldest `blk*.dat` files — and the block-position index entries
//! and undo records of every block inside them — once total block-file size
//! exceeds a configured target, mirroring Bitcoin Core's `-prune=<MiB>`.
//!
//! Safety invariants:
//! - A minimum of [`MIN_KEEP_BLOCKS`] recent blocks is always kept (Core's
//!   288-block reorg window).
//! - Nothing above the last UTXO-flushed height (`validated_height`) is ever
//!   pruned: crash recovery re-validates blocks from that height forward and
//!   must be able to read them.
//! - Index entries (block positions, undo records) are removed and the WAL
//!   fsynced *before* the files are deleted, so no reader can hold a position
//!   into a deleted file. A crash between the two leaves orphaned file data,
//!   which is harmless and reclaimed on the next prune pass.
//!
//! Block files are filled in block-connect order (validation is sequential),
//! so file numbers are monotone in height: every block in file N is lower
//! than every block in file N+1. The pruner exploits this by computing the
//! file that contains the first block that must be kept and only deleting
//! strictly older files.

use std::collections::HashSet;
use tracing::info;

use crate::block_store::BlockStore;
use crate::error::{StorageError, StorageResult};
use crate::header_index::HeaderIndex;
use crate::utxo_set::UtxoSet;

/// Minimum number of recent blocks whose data must always be kept
/// (Bitcoin Core's reorg protection window, BIP 159 NODE_NETWORK_LIMITED).
pub const MIN_KEEP_BLOCKS: u32 = 288;

/// Minimum prune target in MiB (Core's `MIN_DISK_SPACE_FOR_BLOCK_FILES`).
pub const MIN_PRUNE_TARGET_MIB: u64 = 550;

/// Outcome of a prune pass that deleted something.
#[derive(Debug)]
pub struct PruneReport {
    pub files_deleted: u32,
    pub bytes_freed: u64,
    /// Every block at or below this height has been pruned.
    pub pruned_height: u32,
}

/// The highest height eligible for pruning: `MIN_KEEP_BLOCKS` below the tip,
/// further capped by the last UTXO-flushed height (`validated_height`) so
/// crash recovery can always re-read the blocks it may need to replay, and by
/// an optional manual ceiling (the `pruneblockchain` RPC). Returns `None`
/// when the chain is too short to prune at all.
pub fn prune_ceiling(
    tip_height: u32,
    validated_height: Option<u32>,
    manual_height: Option<u32>,
) -> Option<u32> {
    let mut ceiling = tip_height.checked_sub(MIN_KEEP_BLOCKS)?;
    ceiling = ceiling.min(validated_height.unwrap_or(0));
    if let Some(manual) = manual_height {
        ceiling = ceiling.min(manual);
    }
    if ceiling == 0 {
        None
    } else {
        Some(ceiling)
    }
}

/// One prune pass: if total block-file size exceeds `target_bytes`, delete
/// the oldest block files whose every block is at or below `ceiling_height`,
/// oldest first, until the total is back under the target (or no eligible
/// file remains). Pass `target_bytes = 0` to delete everything eligible
/// (manual `pruneblockchain`).
///
/// Returns `Ok(None)` when nothing needed pruning.
pub fn prune_block_files(
    block_store: &BlockStore,
    header_index: &HeaderIndex,
    utxo_set: &UtxoSet,
    ceiling_height: u32,
    target_bytes: u64,
) -> StorageResult<Option<PruneReport>> {
    let files = block_store.list_block_files()?;
    let mut total: u64 = files.iter().map(|(_, size)| size).sum();
    if total <= target_bytes {
        return Ok(None);
    }

    // The file containing the first block that must survive bounds what we
    // may delete. If that block's position is unknown (index gap), fail safe
    // by not pruning.
    let first_kept = ceiling_height + 1;
    let keep_file = match hash_pos_file(header_index, first_kept)? {
        Some(file_num) => file_num.min(block_store.current_file_num()),
        None => return Ok(None),
    };

    // Delete oldest-first until we are back under target.
    let mut to_delete: HashSet<u32> = HashSet::new();
    for (num, size) in &files {
        if *num >= keep_file || total <= target_bytes {
            break;
        }
        to_delete.insert(*num);
        total -= size;
    }
    if to_delete.is_empty() {
        return Ok(None);
    }

    // Remove the index entries of every block living in a doomed file. Blocks
    // are file-ordered by height, so these heights are a contiguous prefix of
    // the unpruned range; stop at the first height whose file survives.
    let start = match header_index.get_pruned_height()? {
        Some(h) => h + 1,
        None => 0,
    };
    let mut pruned_height = start.saturating_sub(1);
    for height in start..=ceiling_height {
        match header_index.get_hash_at_height(height)? {
            Some(hash) => {
                match header_index.get_block_pos(&hash)? {
                    Some(pos) if to_delete.contains(&pos.file_num) => {
                        header_index.remove_block_pos(&hash)?;
                        let hash_bytes: &[u8; 32] = AsRef::<[u8; 32]>::as_ref(&hash);
                        utxo_set.delete_undo(hash_bytes)?;
                        pruned_height = height;
                    }
                    Some(_) => break,               // reached a surviving file
                    None => pruned_height = height, // already absent
                }
            }
            None => {
                // Height-index gap below the ceiling: treat as already gone.
                pruned_height = height;
            }
        }
    }

    if pruned_height < start {
        // The doomed files contained no indexed blocks (shouldn't happen, but
        // fail safe rather than deleting files we can't account for).
        return Err(StorageError::Serialization(format!(
            "prune: no indexed blocks found in files {to_delete:?}; refusing to delete"
        )));
    }

    // Persist the bookkeeping durably before touching the files.
    header_index.set_pruned_height(pruned_height)?;
    header_index.flush_wal()?;

    let mut bytes_freed = 0u64;
    let mut files_deleted = 0u32;
    let mut nums: Vec<u32> = to_delete.into_iter().collect();
    nums.sort_unstable();
    for num in nums {
        bytes_freed += block_store.delete_block_file(num)?;
        files_deleted += 1;
    }

    info!(
        files_deleted,
        bytes_freed, pruned_height, "Pruned block files"
    );
    Ok(Some(PruneReport {
        files_deleted,
        bytes_freed,
        pruned_height,
    }))
}

/// File number of the block at `height`, or `None` if the height or its
/// position is not indexed.
fn hash_pos_file(header_index: &HeaderIndex, height: u32) -> StorageResult<Option<u32>> {
    match header_index.get_hash_at_height(height)? {
        Some(hash) => Ok(header_index.get_block_pos(&hash)?.map(|pos| pos.file_num)),
        None => Ok(None),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use bitcoin::hashes::Hash;
    use bitcoin::BlockHash;

    /// A fabricated per-height block hash for index bookkeeping.
    fn fake_hash(height: u32) -> BlockHash {
        let mut bytes = [0u8; 32];
        bytes[0..4].copy_from_slice(&height.to_le_bytes());
        bytes[31] = 0xAB;
        BlockHash::from_byte_array(bytes)
    }

    /// Build a store with `n` fake blocks of ~1 KiB each and a 4 KiB file
    /// rotation size (≈3 blocks per file), fully indexed with undo records.
    fn build_chain(dir: &std::path::Path, n: u32) -> (BlockStore, HeaderIndex, UtxoSet) {
        let block_store = BlockStore::open_with_max_file_size(&dir.join("blocks"), 4096).unwrap();
        let header_index = HeaderIndex::open(&dir.join("headers")).unwrap();
        let utxo_set = UtxoSet::open(&dir.join("utxo"), None).unwrap();

        for height in 0..n {
            let raw = vec![height as u8; 1024];
            let pos = block_store.store_block(&raw).unwrap();
            let hash = fake_hash(height);
            header_index.set_block_pos(&hash, &pos).unwrap();
            header_index.set_height_hash(height, &hash).unwrap();
            let prev = if height == 0 {
                [0u8; 32]
            } else {
                *AsRef::<[u8; 32]>::as_ref(&fake_hash(height - 1))
            };
            let hash_bytes: &[u8; 32] = AsRef::<[u8; 32]>::as_ref(&hash);
            utxo_set.store_undo(hash_bytes, &[], &[], &prev).unwrap();
        }
        (block_store, header_index, utxo_set)
    }

    #[test]
    fn ceiling_respects_keep_window_validated_height_and_manual_cap() {
        // Chain shorter than the keep window: nothing prunable.
        assert_eq!(prune_ceiling(100, Some(100), None), None);
        // Keep window bounds the ceiling.
        assert_eq!(prune_ceiling(1000, Some(1000), None), Some(1000 - 288));
        // Never above the last UTXO-flushed height.
        assert_eq!(prune_ceiling(1000, Some(500), None), Some(500));
        // Unknown validated height: fail safe, prune nothing.
        assert_eq!(prune_ceiling(1000, None, None), None);
        // Manual cap (pruneblockchain RPC) lowers it further.
        assert_eq!(prune_ceiling(1000, Some(500), Some(300)), Some(300));
    }

    #[test]
    fn prune_deletes_files_positions_and_undo_below_ceiling() {
        let dir = tempfile::tempdir().unwrap();
        let (block_store, header_index, utxo_set) = build_chain(dir.path(), 40);

        let files_before = block_store.list_block_files().unwrap();
        assert!(files_before.len() > 5, "need several files to prune");

        // Prune everything eligible below height 30.
        let report = prune_block_files(&block_store, &header_index, &utxo_set, 30, 0)
            .unwrap()
            .expect("must prune");
        assert!(report.files_deleted > 0);
        assert!(report.pruned_height <= 30);
        assert!(report.pruned_height > 0);

        // Meta recorded.
        assert_eq!(
            header_index.get_pruned_height().unwrap(),
            Some(report.pruned_height)
        );

        // Pruned blocks: position and undo gone.
        for height in 0..=report.pruned_height {
            let hash = fake_hash(height);
            assert!(
                header_index.get_block_pos(&hash).unwrap().is_none(),
                "height {height} position must be removed"
            );
            let hb: &[u8; 32] = AsRef::<[u8; 32]>::as_ref(&hash);
            assert!(
                utxo_set.load_undo(hb).unwrap().is_none(),
                "height {height} undo must be removed"
            );
        }

        // Kept blocks: still readable end-to-end.
        for height in (report.pruned_height + 1)..40 {
            let hash = fake_hash(height);
            let pos = header_index
                .get_block_pos(&hash)
                .unwrap()
                .unwrap_or_else(|| panic!("height {height} must keep its position"));
            let raw = block_store.read_block(&pos).unwrap();
            assert_eq!(raw, vec![height as u8; 1024]);
        }

        // A second pass with the same ceiling is a no-op (target 1 byte would
        // trigger deletion, but every remaining file holds kept blocks).
        // Note target_bytes=0 with remaining files: the keep_file bound stops it.
        let again = prune_block_files(&block_store, &header_index, &utxo_set, 30, 0).unwrap();
        assert!(again.is_none(), "second pass must be a no-op: {again:?}");
    }

    #[test]
    fn reopen_after_prune_does_not_restart_file_numbering() {
        let dir = tempfile::tempdir().unwrap();
        let (block_store, header_index, utxo_set) = build_chain(dir.path(), 40);
        prune_block_files(&block_store, &header_index, &utxo_set, 30, 0)
            .unwrap()
            .expect("must prune");
        let current = block_store.current_file_num();
        drop(block_store);

        // Re-open: the write position must resume at the highest surviving
        // file, not fall back into the pruned gap at blk00000.dat.
        let reopened =
            BlockStore::open_with_max_file_size(&dir.path().join("blocks"), 4096).unwrap();
        assert_eq!(reopened.current_file_num(), current);
        assert!(
            !dir.path().join("blocks").join("blk00000.dat").exists(),
            "pruned first file must stay deleted"
        );
        // And appending still works.
        reopened.store_block(&[0xEE; 512]).unwrap();
    }

    #[test]
    fn prune_respects_byte_target() {
        let dir = tempfile::tempdir().unwrap();
        let (block_store, header_index, utxo_set) = build_chain(dir.path(), 40);
        let total: u64 = block_store
            .list_block_files()
            .unwrap()
            .iter()
            .map(|(_, s)| s)
            .sum();

        // Target slightly below current usage: deletes only the oldest file.
        let target = total - 1000;
        let report = prune_block_files(&block_store, &header_index, &utxo_set, 30, target)
            .unwrap()
            .expect("must prune one file");
        assert_eq!(report.files_deleted, 1);

        // Already under target now: no-op.
        let again = prune_block_files(&block_store, &header_index, &utxo_set, 30, target).unwrap();
        assert!(again.is_none());
    }
}
