//! Startup recovery and reindex logic, extracted verbatim from main.rs
//! (D2 of the main.rs decomposition). Each function covers one startup
//! phase; bodies are unchanged code moves from main().

use bitcoinpr_core::{ChainState, ConsensusParams};
use bitcoinpr_storage::{BlockStore, HeaderIndex, UtxoSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tracing::{debug, error, info, warn};

use crate::config::{expand_datadir, net_subdir};

/// Name of the pointer file written inside `<net_dir>/` that remembers the
/// most recently used non-default blocks directory. Read on startup when
/// `--blocksdir` is not specified so the node doesn't silently fall back to
/// an empty default directory and re-download the entire chain.
const BLOCKSDIR_POINTER: &str = "blocksdir.conf";

/// Resolve where raw block files (blk*.dat) live. By default they sit in
/// <net_dir>/blocks alongside the indexes; --blocksdir relocates just the
/// block files onto alternate (slower/bigger) storage, mirroring the network
/// layout under the new base. The indexes (headers/utxo/txindex/index) always
/// stay under --datadir.
///
/// If `--blocksdir` is absent, the function checks for a `blocksdir.conf`
/// pointer file written by a previous run. An explicit `--blocksdir` always
/// wins and updates the pointer.
///
/// Startup phase: blocks-directory resolution + `--migrateblocks` handling.
pub(crate) fn resolve_blocks_dir(
    net_dir: &Path,
    blocksdir: &Option<String>,
    migrateblocks: bool,
    network: bitcoin::Network,
) -> anyhow::Result<PathBuf> {
    let default_blocks_dir = net_dir.join("blocks");
    let pointer_path = net_dir.join(BLOCKSDIR_POINTER);

    let blocks_dir = match &blocksdir {
        Some(base) => net_subdir(&expand_datadir(base), network).join("blocks"),
        None => {
            // No --blocksdir on the command line — check for a saved pointer.
            match read_blocksdir_pointer(&pointer_path) {
                Some(saved) => saved,
                None => default_blocks_dir.clone(),
            }
        }
    };

    // --migrateblocks: one-shot move of existing blk*.dat from the datadir into
    // the new --blocksdir. Block positions don't record the directory, so the
    // indexes need no changes and the node keeps running afterward.
    if migrateblocks {
        if blocks_dir == default_blocks_dir {
            error!(
                "--migrateblocks requires --blocksdir to point somewhere other \
                 than the datadir (resolved blocks dir is {}); nothing to do",
                blocks_dir.display()
            );
            std::process::exit(1);
        }
        info!(
            from = %default_blocks_dir.display(),
            to = %blocks_dir.display(),
            "--migrateblocks: relocating raw block files (indexes stay in datadir)"
        );
        let moved = BlockStore::migrate(&default_blocks_dir, &blocks_dir)?;
        info!(moved, "--migrateblocks: block file relocation complete");
        write_blocksdir_pointer(&pointer_path, &blocks_dir);
    } else if blocks_dir != default_blocks_dir && BlockStore::has_block_files(&default_blocks_dir) {
        // --blocksdir set, but legacy blocks still sit in the datadir and were
        // not migrated. Reading from the (likely empty) new dir would make the
        // node think every block is missing and re-download the whole chain.
        warn!(
            old = %default_blocks_dir.display(),
            new = %blocks_dir.display(),
            "blk*.dat files exist in the datadir but --blocksdir points elsewhere. \
             Re-run once with --migrateblocks to move them, or the node will not \
             find the existing blocks."
        );
    }

    // Persist the pointer whenever a non-default blocks dir is in use
    // (covers both explicit --blocksdir and pointer-restored paths).
    if blocks_dir != default_blocks_dir {
        write_blocksdir_pointer(&pointer_path, &blocks_dir);
    }

    Ok(blocks_dir)
}

/// Read the `blocksdir.conf` pointer file. Returns `Some(path)` if the file
/// exists, the path it contains is a directory with `blk*.dat` files, and is
/// therefore usable. Returns `None` (with a warning) if the pointer exists
/// but the target is missing/empty (e.g. external drive detached).
fn read_blocksdir_pointer(pointer_path: &Path) -> Option<PathBuf> {
    let content = std::fs::read_to_string(pointer_path).ok()?;
    let saved = PathBuf::from(content.trim());
    if !saved.is_absolute() {
        warn!(
            pointer = %pointer_path.display(),
            value = %saved.display(),
            "blocksdir.conf contains a relative path — ignoring"
        );
        return None;
    }
    if BlockStore::has_block_files(&saved) {
        info!(
            blocks_dir = %saved.display(),
            "Using saved blocks directory from {}",
            pointer_path.display()
        );
        Some(saved)
    } else if saved.is_dir() {
        // Directory exists but has no blk*.dat — might be first run to a
        // fresh target, or blocks were deleted. Still use it so we don't
        // create a second copy in the default location.
        info!(
            blocks_dir = %saved.display(),
            "Saved blocks directory exists but has no blk*.dat yet — using it anyway"
        );
        Some(saved)
    } else {
        warn!(
            blocks_dir = %saved.display(),
            "blocksdir.conf points to a missing directory — falling back to default \
             (external drive detached?)"
        );
        None
    }
}

/// Write (or overwrite) the `blocksdir.conf` pointer file with the resolved
/// blocks directory path. Best-effort: failure is logged but not fatal.
fn write_blocksdir_pointer(pointer_path: &Path, blocks_dir: &Path) {
    if let Err(e) = std::fs::write(pointer_path, blocks_dir.to_string_lossy().as_bytes()) {
        warn!(
            path = %pointer_path.display(),
            error = %e,
            "Failed to write blocksdir.conf pointer"
        );
    } else {
        debug!(
            path = %pointer_path.display(),
            blocks_dir = %blocks_dir.display(),
            "Saved blocks directory pointer"
        );
    }
}

/// Bug #4: --reindex-chainstate — wipe UTXO + tx index + scripthash index
/// but preserve the header chain and blk*.dat files, then reset the chain
/// tip to genesis so startup replays every block through the header chain.
/// This is the explicit, operator-controlled recovery for the case where
/// derived state is unrecoverable but block data on disk is intact.
///
/// Startup phase: `--reindex-chainstate` wipe.
pub(crate) fn reindex_chainstate_wipe(
    net_dir: &Path,
    params: &ConsensusParams,
    reindex_chainstate: bool,
) -> anyhow::Result<()> {
    if reindex_chainstate {
        info!(
            "--reindex-chainstate: wiping UTXO set, tx index, and scripthash \
             index (headers and block files preserved)"
        );
        for subdir in &["utxo", "txindex", "index"] {
            let p = net_dir.join(subdir);
            if p.exists() {
                std::fs::remove_dir_all(&p)?;
            }
        }
        // Reset header-chain bookkeeping so ChainState replays from genesis.
        // The header chain itself (headers CF + height_index) is preserved so
        // replay walks through the same chain without re-downloading headers.
        let tmp_hi = HeaderIndex::open(&net_dir.join("headers"))?;
        tmp_hi.clear_validated_height()?;
        let genesis_hash = params.genesis_block.block_hash();
        tmp_hi.set_best_tip(&genesis_hash, 0)?;
        drop(tmp_hi);
        info!("--reindex-chainstate: chain tip reset to genesis — block replay will rebuild UTXO");
    }

    Ok(())
}

/// --reindex or unrecoverable chain break: wipe derived state and rebuild
///
/// Startup phase: chain-integrity check, chain-break recovery, and the
/// `--reindex` / forced-reindex wipe of derived state.
pub(crate) fn check_integrity_and_reindex(
    net_dir: &Path,
    dbcache_mb: Option<u32>,
    params: &ConsensusParams,
    block_store: &Arc<BlockStore>,
    reindex: bool,
    reindex_chainstate: bool,
) -> anyhow::Result<()> {
    let needs_reindex = reindex;
    let mut force_reindex = false;

    if !needs_reindex && !reindex_chainstate {
        // Quick integrity check before opening everything
        let tmp_hi = HeaderIndex::open(&net_dir.join("headers"))?;

        // Fix 5: Check if shutdown was unclean — if validated_height < best_height,
        // headers exist that were never fully validated (UTXO state may not match).
        // Use the UTXO flush_height as the authoritative recovery point: it's
        // written atomically with each UTXO flush and represents the last height
        // where the on-disk UTXO set is known to be consistent.
        let validated = tmp_hi.get_validated_height()?;
        let tmp_utxo_check = UtxoSet::open(&net_dir.join("utxo"), dbcache_mb)?;
        let utxo_flush_height = tmp_utxo_check.get_flush_height()?;
        drop(tmp_utxo_check);

        // The safe height is the higher of validated_height and utxo_flush_height,
        // since the UTXO flush is written more frequently (every 1000 blocks)
        // while validated_height is only written on clean shutdown.
        let safe_height = match (validated, utxo_flush_height) {
            (Some(v), Some(f)) => Some(v.max(f)),
            (Some(v), None) => Some(v),
            (None, Some(f)) => Some(f),
            (None, None) => None,
        };
        let best_stored = tmp_hi.get_best_height()?.unwrap_or(0);
        if let Some(sh) = safe_height {
            if sh < best_stored {
                warn!(
                    safe_height = sh,
                    validated_height = ?validated,
                    utxo_flush_height = ?utxo_flush_height,
                    stored_height = best_stored,
                    "Unclean shutdown detected — headers ahead of validated UTXO state"
                );
                // Truncate headers to the safe height (not further)
                tmp_hi.truncate_to(sh)?;
                info!(
                    height = sh,
                    "Truncated headers to last consistent UTXO height"
                );
            }
        }

        match tmp_hi.verify_chain_integrity() {
            Ok((verified, best)) if verified < best => {
                warn!(
                    verified_height = verified,
                    stored_height = best,
                    "Chain break at height {} — attempting block disconnect recovery",
                    verified + 1
                );
                // Try to disconnect blocks from tip to the valid height
                let tmp_utxo = UtxoSet::open(&net_dir.join("utxo"), dbcache_mb)?;
                let tmp_bs = block_store.clone();
                let tip_height = tmp_hi.get_best_height().ok().flatten().unwrap_or(0);
                let tip_hash = tmp_hi
                    .get_best_tip()
                    .ok()
                    .flatten()
                    .unwrap_or(params.genesis_block.block_hash());

                let mut cs_tmp = ChainState::new(
                    params.clone(),
                    Arc::new(tmp_hi),
                    Arc::new(tmp_utxo),
                    tmp_bs,
                    tip_height,
                    tip_hash,
                );
                // Walk the disconnect loop, capturing fine-grained failure
                // info. We distinguish "no block_pos entry", "I/O error reading
                // block file" (the symptom of a corrupted block-file tail),
                // "deserialize failed" (truncated/garbled bytes), and
                // "disconnect_block rejected" (UTXO inconsistency). Bug #1's
                // recovery path uses the failure mode + the deepest height we
                // reached to decide between targeted rollback and a heavier
                // recovery — without these, an operator sees "Block data
                // missing for disconnect" and has no idea whether the file is
                // truncated, the index is wrong, or something else.
                let mut rollback_ok = true;
                let mut disconnect_failure: Option<&'static str> = None;
                while cs_tmp.best_height > verified {
                    let h = cs_tmp.best_height;
                    let hash = cs_tmp.best_hash;
                    info!(height = h, %hash, "Disconnecting block to roll back UTXO set");

                    let pos = match cs_tmp.header_index.get_block_pos(&hash) {
                        Ok(Some(p)) => p,
                        Ok(None) => {
                            warn!(
                                height = h,
                                %hash,
                                "Disconnect aborted: no block_pos index entry — \
                                 hash→location map lost track of this block"
                            );
                            disconnect_failure = Some("no_block_pos");
                            rollback_ok = false;
                            break;
                        }
                        Err(e) => {
                            warn!(
                                height = h,
                                %hash,
                                error = %e,
                                "Disconnect aborted: block_pos lookup I/O error"
                            );
                            disconnect_failure = Some("block_pos_io_error");
                            rollback_ok = false;
                            break;
                        }
                    };

                    let raw = match cs_tmp.block_store.read_block(&pos) {
                        Ok(r) => r,
                        Err(e) => {
                            // This is what the "expected N, got 4294967124"
                            // corruption from the May-30 incident produced —
                            // the size prefix at &pos.offset read back as
                            // uninitialized bytes from an unflushed page.
                            warn!(
                                height = h,
                                %hash,
                                file = pos.file_num,
                                offset = pos.offset,
                                expected_size = pos.size,
                                error = %e,
                                "Disconnect aborted: block file read failed \
                                 (likely truncated/corrupt block at tail of blk*.dat)"
                            );
                            disconnect_failure = Some("block_read_error");
                            rollback_ok = false;
                            break;
                        }
                    };

                    let block =
                        match bitcoin::consensus::encode::deserialize::<bitcoin::Block>(&raw) {
                            Ok(b) => b,
                            Err(e) => {
                                warn!(
                                    height = h,
                                    %hash,
                                    error = %e,
                                    "Disconnect aborted: block bytes did not deserialize"
                                );
                                disconnect_failure = Some("deserialize_error");
                                rollback_ok = false;
                                break;
                            }
                        };

                    if let Err(e) = cs_tmp.disconnect_block(&block, h) {
                        warn!(
                            height = h,
                            %hash,
                            error = %e,
                            "Disconnect aborted: UTXO disconnect rejected by chain state"
                        );
                        disconnect_failure = Some("disconnect_rejected");
                        rollback_ok = false;
                        break;
                    }
                }
                // After the loop, cs_tmp.best_height holds the deepest height
                // we successfully rolled back to (== `verified` on full
                // success, > verified on partial rollback). Bug #1 consumes
                // this when deciding the recovery strategy.
                let rolled_back_to = cs_tmp.best_height;
                if rollback_ok {
                    cs_tmp.utxo_set.flush_to_disk()?;
                    cs_tmp.header_index.truncate_to(verified)?;
                    info!(
                        height = cs_tmp.best_height,
                        target = verified,
                        "Rollback complete"
                    );
                } else {
                    // Bug #1+#2: Block-driven disconnect failed (typically because
                    // a tail block in blk*.dat is corrupt — pre-Bug-#5 writes were
                    // not fsynced). Instead of wiping all derived state, try the
                    // undo-only path: UtxoSet::rollback_to walks backward using
                    // CF_UNDO entries and never touches the block files. This
                    // recovers cleanly from the exact failure mode that wiped
                    // 800k blocks of validated state on May 30.
                    warn!(
                        target = verified,
                        rolled_back_to,
                        failure = disconnect_failure.unwrap_or("unknown"),
                        "Block-driven disconnect failed — attempting undo-only \
                         UTXO rollback (no block file reads)"
                    );
                    match cs_tmp.utxo_set.rollback_to(verified) {
                        Ok(()) => {
                            cs_tmp.header_index.truncate_to(verified)?;
                            info!(
                                height = verified,
                                "Undo-only rollback succeeded — chain state restored \
                                 without touching block files"
                            );
                        }
                        Err(undo_err) => {
                            // Undo data missing or corrupt above `verified`. Fall
                            // back to the last known-good UTXO snapshot — flush_height
                            // is written atomically with every UTXO flush and is the
                            // deepest height guaranteed to be on-disk consistent.
                            let snapshot = cs_tmp.utxo_set.get_flush_height().ok().flatten();
                            warn!(
                                target = verified,
                                error = %undo_err,
                                snapshot = ?snapshot,
                                "Undo-only rollback failed — falling back to UTXO \
                                 flush-height snapshot"
                            );
                            match snapshot {
                                Some(snap_h) if snap_h <= verified => {
                                    // Snapshot is already at or below the verified
                                    // height — just truncate headers to the snapshot.
                                    cs_tmp.header_index.truncate_to(snap_h)?;
                                    info!(
                                        height = snap_h,
                                        "Recovered to UTXO flush-height snapshot — \
                                         headers truncated to match"
                                    );
                                }
                                Some(snap_h) => {
                                    // Snapshot is between verified and the broken
                                    // tip. Rollback to snapshot first, then truncate.
                                    match cs_tmp.utxo_set.rollback_to(snap_h) {
                                        Ok(()) => {
                                            cs_tmp.header_index.truncate_to(snap_h)?;
                                            info!(
                                                height = snap_h,
                                                "Recovered to UTXO flush-height \
                                                 snapshot via undo-only rollback"
                                            );
                                        }
                                        Err(snap_err) => {
                                            error!(
                                                error = %snap_err,
                                                snapshot = snap_h,
                                                "Snapshot rollback also failed — \
                                                 derived state is unrecoverable"
                                            );
                                            drop(cs_tmp);
                                            return Err(anyhow::anyhow!(
                                                "Chain state is unrecoverable without \
                                                 rebuilding from stored blocks. Rerun \
                                                 with --reindex-chainstate to rebuild \
                                                 the UTXO set from blk*.dat files \
                                                 (block data is preserved)."
                                            ));
                                        }
                                    }
                                }
                                None => {
                                    error!(
                                        "No UTXO flush-height snapshot available — \
                                         derived state is unrecoverable"
                                    );
                                    drop(cs_tmp);
                                    return Err(anyhow::anyhow!(
                                        "Chain state is unrecoverable. Rerun with \
                                         --reindex-chainstate to rebuild the UTXO \
                                         set from stored blocks (block data is preserved)."
                                    ));
                                }
                            }
                        }
                    }
                }
                // Drop temporary handles so we can wipe dirs if needed
                drop(cs_tmp);
            }
            Ok((verified, _)) => {
                info!(height = verified, "Header chain integrity verified");
            }
            Err(e) => {
                warn!("Integrity check error: {} — forcing full reindex", e);
                force_reindex = true;
            }
        }
    }

    if needs_reindex || force_reindex {
        info!("Reindex: wiping UTXO set, headers, and tx index — will rebuild from block store");
        // Wipe derived-state directories; block store is preserved
        for subdir in &["utxo", "headers", "txindex", "index"] {
            let p = net_dir.join(subdir);
            if p.exists() {
                std::fs::remove_dir_all(&p)?;
            }
        }
    }

    Ok(())
}

/// Load chain state from storage
///
/// Startup phase: chain-state load + empty-UTXO-with-nonzero-tip handling.
/// Returns the (best_height, best_hash) tip main() should start from.
pub(crate) fn load_chain_tip(
    header_index: &Arc<HeaderIndex>,
    utxo_set: &Arc<UtxoSet>,
    params: &ConsensusParams,
) -> anyhow::Result<(u32, bitcoin::BlockHash)> {
    let (mut best_height, mut best_hash) = match header_index.get_best_tip()? {
        Some(hash) => {
            let height = header_index.get_best_height()?.unwrap_or(0);
            info!(height, hash = %hash, "Resuming from stored chain tip");
            (height, hash)
        }
        None => {
            // Initialize with genesis block header
            let genesis = &params.genesis_block;
            let genesis_hash = genesis.block_hash();
            let stored = bitcoinpr_storage::StoredHeader {
                header: genesis.header,
                height: 0,
                chain_work: [0u8; 32],
            };
            header_index.insert_header(&genesis_hash, &stored)?;
            header_index.set_best_tip(&genesis_hash, 0)?;
            info!(hash = %genesis_hash, "Initialized with genesis block");
            (0, genesis_hash)
        }
    };

    // If the UTXO set is empty but we have a non-zero tip, the UTXO was wiped
    // (manually or by recovery). Reset tip to genesis so we replay from blocks.
    if best_height > 0 && utxo_set.is_db_empty()? {
        warn!(
            height = best_height,
            "UTXO set is empty but chain tip is non-zero — resetting to genesis for replay"
        );
        let genesis_hash = params.genesis_block.block_hash();
        header_index.set_best_tip(&genesis_hash, 0)?;
        best_height = 0;
        best_hash = genesis_hash;
    }

    Ok((best_height, best_hash))
}

/// Phase A: UTXO flush height reconciliation.
/// The UTXO set stores the last height at which it was flushed to disk.
/// If this diverges from best_tip, auto-recover instead of requiring --reindex.
///
/// Startup Phase A. Returns the (possibly re-opened) UTXO set, the
/// reconciled tip, and whether the UTXO state was confirmed consistent.
pub(crate) fn phase_a_reconcile_utxo(
    net_dir: &Path,
    dbcache_mb: Option<u32>,
    params: &ConsensusParams,
    header_index: &Arc<HeaderIndex>,
    mut utxo_set: Arc<UtxoSet>,
    mut best_height: u32,
    mut best_hash: bitcoin::BlockHash,
) -> anyhow::Result<(Arc<UtxoSet>, u32, bitcoin::BlockHash, bool)> {
    let mut utxo_verified = false; // true if Phase A confirmed UTXO consistency
    if best_height > 0 {
        match utxo_set.get_flush_height() {
            Ok(Some(utxo_height)) => {
                if utxo_height < best_height {
                    warn!(
                        utxo_flush_height = utxo_height,
                        stored_tip = best_height,
                        "UTXO flush height behind stored tip — resetting tip to UTXO height"
                    );
                    // The UTXO set is authoritative: reset best_tip to match it
                    if let Ok(Some(utxo_hash)) = utxo_set.get_flush_hash() {
                        use bitcoin::hashes::Hash;
                        let hash = bitcoin::BlockHash::from_byte_array(utxo_hash);
                        header_index.set_best_tip(&hash, utxo_height)?;
                        best_height = utxo_height;
                        best_hash = hash;
                        info!(height = utxo_height, hash = %best_hash, "Tip reset to UTXO flush height");
                    } else {
                        // Have height but no hash — find it from header index
                        if let Ok(Some(hash)) = header_index.get_hash_at_height(utxo_height) {
                            header_index.set_best_tip(&hash, utxo_height)?;
                            best_height = utxo_height;
                            best_hash = hash;
                            info!(height = utxo_height, hash = %best_hash, "Tip reset to UTXO flush height (hash from header index)");
                        } else {
                            warn!(
                                "Cannot find hash for UTXO flush height {} — will use existing tip",
                                utxo_height
                            );
                        }
                    }
                } else if utxo_height > best_height {
                    // UTXO is ahead of tip — the UTXO set successfully processed
                    // blocks that the tip marker didn't record (unclean shutdown
                    // between UTXO flush and tip update). The UTXO set is
                    // authoritative: advance the stored tip to match it.
                    warn!(
                        utxo_flush_height = utxo_height,
                        stored_tip = best_height,
                        "UTXO flush height ahead of stored tip — advancing tip to match UTXO"
                    );
                    let mut advanced = false;
                    if let Ok(Some(utxo_hash)) = utxo_set.get_flush_hash() {
                        use bitcoin::hashes::Hash;
                        let hash = bitcoin::BlockHash::from_byte_array(utxo_hash);
                        header_index.set_best_tip(&hash, utxo_height)?;
                        best_height = utxo_height;
                        best_hash = hash;
                        info!(height = utxo_height, hash = %best_hash, "Tip advanced to UTXO flush height");
                        utxo_verified = true;
                        advanced = true;
                    } else if let Ok(Some(hash)) = header_index.get_hash_at_height(utxo_height) {
                        header_index.set_best_tip(&hash, utxo_height)?;
                        best_height = utxo_height;
                        best_hash = hash;
                        info!(height = utxo_height, hash = %best_hash, "Tip advanced to UTXO flush height (from header index)");
                        utxo_verified = true;
                        advanced = true;
                    }
                    if !advanced {
                        // Last resort: try rolling back UTXO to match the stale tip
                        warn!("Cannot find hash for UTXO flush height — attempting rollback as fallback");
                        match utxo_set.rollback_to(best_height) {
                            Ok(()) => {
                                info!(
                                    from = utxo_height,
                                    to = best_height,
                                    "UTXO rolled back to match stored tip"
                                );
                                utxo_verified = true;
                            }
                            Err(e) => {
                                warn!(
                                    error = %e,
                                    "UTXO rollback failed — falling back to wipe and rebuild"
                                );
                                for subdir in &["utxo", "txindex", "index"] {
                                    let p = net_dir.join(subdir);
                                    if p.exists() {
                                        std::fs::remove_dir_all(&p)?;
                                    }
                                }
                                let genesis_hash = params.genesis_block.block_hash();
                                header_index.set_best_tip(&genesis_hash, 0)?;
                                best_height = 0;
                                best_hash = genesis_hash;
                                drop(utxo_set);
                                utxo_set =
                                    Arc::new(UtxoSet::open(&net_dir.join("utxo"), dbcache_mb)?);
                                info!("UTXO wiped and tip reset to genesis for rebuild");
                            }
                        }
                    }
                } else {
                    info!(
                        utxo_flush_height = utxo_height,
                        "UTXO flush height matches stored tip"
                    );
                    utxo_verified = true;
                }
            }
            Ok(None) => {
                // No flush height stored yet — this is a pre-Phase-A database or
                // fresh start. Nothing to reconcile; the feature will start tracking
                // from the next flush.
                debug!("No UTXO flush height stored yet (pre-Phase-A or fresh DB)");
            }
            Err(e) => {
                warn!(
                    "Failed to read UTXO flush height: {} — skipping reconciliation",
                    e
                );
            }
        }
    }

    Ok((utxo_set, best_height, best_hash, utxo_verified))
}

/// Verify the tip block is actually stored (block store + block pos).
/// If the validated tip is ahead of what's actually in the block store
/// (e.g., header sync advanced the tip but blocks were never downloaded),
/// walk backward to find the highest block that IS stored and reset the
/// tip there. This preserves the vast majority of validated state instead
/// of wiping everything.
///
/// Skip this check if Phase A already confirmed the UTXO flush height matches
/// the tip — the UTXO state is proven consistent and the missing block at the
/// tip will be re-downloaded naturally from peers.
///
/// Startup phase: tip-block storage verification. Returns the (possibly
/// re-opened) UTXO set and the (possibly reset) tip.
#[allow(clippy::too_many_arguments)]
pub(crate) fn verify_tip_block_stored(
    net_dir: &Path,
    dbcache_mb: Option<u32>,
    params: &ConsensusParams,
    header_index: &Arc<HeaderIndex>,
    block_store: &Arc<BlockStore>,
    mut utxo_set: Arc<UtxoSet>,
    mut best_height: u32,
    mut best_hash: bitcoin::BlockHash,
    utxo_verified: bool,
) -> anyhow::Result<(Arc<UtxoSet>, u32, bitcoin::BlockHash)> {
    if best_height > 0 && !utxo_verified {
        let has_block = header_index
            .get_block_pos(&best_hash)
            .ok()
            .flatten()
            .and_then(|pos| block_store.read_block(&pos).ok())
            .and_then(|raw| bitcoin::consensus::encode::deserialize::<bitcoin::Block>(&raw).ok())
            .is_some();
        if !has_block {
            warn!(
                height = best_height,
                hash = %best_hash,
                "Tip block not in block store — searching backward for last stored block"
            );
            // Walk backward to find the highest block that IS in the store.
            // Limit search to 2000 blocks back to avoid scanning the entire chain.
            let search_floor = best_height.saturating_sub(2000);
            let mut fallback_height = best_height;
            let mut found_stored = false;
            while fallback_height > search_floor {
                fallback_height -= 1;
                if let Ok(Some(hash)) = header_index.get_hash_at_height(fallback_height) {
                    let stored = header_index
                        .get_block_pos(&hash)
                        .ok()
                        .flatten()
                        .and_then(|pos| block_store.read_block(&pos).ok())
                        .is_some();
                    if stored {
                        info!(
                            original_tip = best_height,
                            fallback_height,
                            blocks_lost = best_height - fallback_height,
                            "Found last stored block — resetting tip"
                        );
                        header_index.set_best_tip(&hash, fallback_height)?;
                        best_height = fallback_height;
                        best_hash = hash;
                        found_stored = true;
                        break;
                    }
                }
            }
            if !found_stored {
                // Catastrophic: no stored blocks found in the last 2000 — wipe and rebuild.
                warn!("No stored blocks found within search window — wiping UTXO for full rebuild");
                for subdir in &["utxo", "txindex", "index"] {
                    let p = net_dir.join(subdir);
                    if p.exists() {
                        std::fs::remove_dir_all(&p)?;
                    }
                }
                let genesis_hash = params.genesis_block.block_hash();
                header_index.set_best_tip(&genesis_hash, 0)?;
                best_height = 0;
                best_hash = genesis_hash;
                info!("Recovery: wiped UTXO set, will replay from stored blocks");
                drop(utxo_set);
                utxo_set = Arc::new(UtxoSet::open(&net_dir.join("utxo"), dbcache_mb)?);
            }
        }
    }

    Ok((utxo_set, best_height, best_hash))
}

/// Phase C: Scan for missing/corrupt blocks in the validated range.
/// If any are found, they'll be queued for targeted re-download from peers
/// instead of requiring a full reindex.
///
/// Startup Phase C. Returns the list of missing/corrupt block heights that
/// main() queues for targeted re-download.
pub(crate) fn phase_c_scan_missing_blocks(
    block_store: &Arc<BlockStore>,
    header_index: &Arc<HeaderIndex>,
    best_height: u32,
) -> Vec<u32> {
    let mut missing_blocks: Vec<u32> = Vec::new();
    if best_height > 0 {
        // Only scan a window near the tip where async writes may not have completed.
        // Scanning the full chain would be slow; deep corruption is rare.
        let scan_from = best_height.saturating_sub(1000);
        let scan_to = best_height;
        match block_store.scan_block_store(header_index, scan_from, scan_to) {
            Ok(missing) if !missing.is_empty() => {
                warn!(
                    scan_from,
                    scan_to,
                    missing_count = missing.len(),
                    first_missing = missing[0],
                    "Block store scan found missing/corrupt blocks — will re-download from peers"
                );
                missing_blocks = missing;
            }
            Ok(_) => {
                debug!(scan_from, scan_to, "Block store scan: all blocks present");
            }
            Err(e) => {
                warn!("Block store scan failed: {} — skipping", e);
            }
        }
    }

    missing_blocks
}

/// Phase D: Repair missing height→hash entries in the header index.
///
/// Blocks mined via Stratum (submit_mined_block) were not calling
/// header_index.insert_header(), leaving CF_HEIGHT_INDEX gaps.  Those gaps
/// cause:
///   • getblockhash(h) → "Block height out of range"
///   • calculate_next_bits() → falls back to 0x1d00ffff → peers reject next
///     block with "bad-diffbits"
///   • Electrum blockchain.block.header → "No block at height N" → client
///     loops
///
/// Fix: walk backward from the validated tip, collect any heights that lack a
/// CF_HEIGHT_INDEX entry (but whose block data is still in the block store),
/// then replay them forward with correct chain_work.
///
/// Startup Phase D: height→hash index repair walk.
pub(crate) fn phase_d_repair_height_index(
    header_index: &Arc<HeaderIndex>,
    block_store: &Arc<BlockStore>,
    best_height: u32,
    best_hash: bitcoin::BlockHash,
) {
    if best_height > 0 {
        // Walk backward from best_hash.  We look for any height whose
        // CF_HEIGHT_INDEX entry is missing.  The tip itself (best_height) may be
        // valid while heights just below it are gaps, so we always check one
        // step below the tip first, then keep walking until we find two
        // consecutive valid entries (solid anchor below the gap).
        let mut walk_hash = best_hash;
        let mut walk_height = best_height;
        let mut missing_headers: Vec<(u32, bitcoin::BlockHash, bitcoin::block::Header)> =
            Vec::new();
        let mut consecutive_valid: u32 = 0;
        let scan_limit = best_height.min(2016); // don't walk back more than one retarget period
        'repair_walk: loop {
            let has_entry = header_index
                .get_hash_at_height(walk_height)
                .ok()
                .flatten()
                .is_some();

            if has_entry {
                consecutive_valid += 1;
                if consecutive_valid >= 2 {
                    break; // two consecutive valid entries = solid anchor, done
                }
            } else {
                consecutive_valid = 0; // gap found — reset the counter
            }

            // Load this block to get its header and prev_blockhash
            match header_index.get_block_pos(&walk_hash) {
                Ok(Some(pos)) => {
                    match block_store.read_block(&pos) {
                        Ok(raw) => {
                            match bitcoin::consensus::encode::deserialize::<bitcoin::Block>(&raw) {
                                Ok(block) => {
                                    if !has_entry {
                                        // Collect for repair
                                        missing_headers.push((
                                            walk_height,
                                            walk_hash,
                                            block.header,
                                        ));
                                    }
                                    let prev = block.header.prev_blockhash;
                                    if walk_height == 0
                                        || walk_height <= best_height.saturating_sub(scan_limit)
                                    {
                                        break;
                                    }
                                    walk_hash = prev;
                                    walk_height -= 1;
                                }
                                Err(e) => {
                                    warn!(height = walk_height, error = %e, "Header repair: failed to deserialize block");
                                    break 'repair_walk;
                                }
                            }
                        }
                        Err(e) => {
                            warn!(height = walk_height, error = %e, "Header repair: failed to read block");
                            break 'repair_walk;
                        }
                    }
                }
                _ => {
                    if !has_entry {
                        warn!(
                            height = walk_height,
                            "Header repair: block not in store, stopping repair"
                        );
                    }
                    break 'repair_walk;
                }
            }
        }
        if !missing_headers.is_empty() {
            let count = missing_headers.len();
            // Walk forward (from oldest missing to newest) to insert headers with correct chain_work
            missing_headers.reverse();
            for (h, hash, header) in missing_headers {
                let prev_hash = header.prev_blockhash;
                let block_work = bitcoinpr_core::calculate_work(&header.target());
                let prev_work = header_index
                    .get_header(&prev_hash)
                    .ok()
                    .flatten()
                    .map(|s| s.chain_work)
                    .unwrap_or([0u8; 32]);
                let chain_work = bitcoinpr_core::add_chain_work(&prev_work, &block_work);
                let stored = bitcoinpr_storage::StoredHeader {
                    header,
                    height: h,
                    chain_work,
                };
                if let Err(e) = header_index.insert_header(&hash, &stored) {
                    warn!(height = h, error = %e, "Header repair: insert_header failed");
                }
            }
            // Restore the header tip to the real best
            let _ = header_index.set_header_tip(&best_hash, best_height);
            info!(
                repaired = count,
                tip = best_height,
                "Header index repaired — inserted missing height→hash entries"
            );
        }
    }
}
