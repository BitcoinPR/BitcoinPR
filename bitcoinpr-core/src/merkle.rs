//! Single home for Bitcoin merkle-tree construction (M4, 2026-07-02 review).
//!
//! Before consolidation this pair-hash-with-odd-duplication algorithm was
//! implemented seven times across `bitcoinpr-core`, `bitcoinpr-index`,
//! `bitcoinpr-mining`, and `bitcoinpr-rpc` — with the CVE-2012-2459 mutation
//! detection existing in exactly one of them. Consensus-adjacent logic this
//! widely duplicated invites divergence; every call site now goes through
//! these three functions.

use bitcoin::hashes::{sha256d, Hash as _};

/// Double-SHA256 of the concatenation of two 32-byte nodes — Bitcoin's
/// merkle pairing rule.
fn hash_pair(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut buf = [0u8; 64];
    buf[..32].copy_from_slice(a);
    buf[32..].copy_from_slice(b);
    *sha256d::Hash::hash(&buf).as_ref()
}

/// Merkle root over raw 32-byte leaves using Bitcoin's convention (the last
/// node of an odd level is paired with itself). Returns 32 zero bytes for an
/// empty input — the BIP 141 witness-root convention.
///
/// Consensus block-tx roots should use [`root_detecting_mutation`] instead,
/// which also reports CVE-2012-2459 mutated trees.
pub fn root(leaves: &[[u8; 32]]) -> [u8; 32] {
    if leaves.is_empty() {
        return [0u8; 32];
    }
    let mut level: Vec<[u8; 32]> = leaves.to_vec();
    while level.len() > 1 {
        if !level.len().is_multiple_of(2) {
            let last = *level.last().expect("loop guard: level is non-empty");
            level.push(last);
        }
        let mut next: Vec<[u8; 32]> = Vec::with_capacity(level.len() / 2);
        for pair in level.chunks(2) {
            next.push(hash_pair(&pair[0], &pair[1]));
        }
        level = next;
    }
    level[0]
}

/// Compute a merkle root from raw leaf hashes, also reporting whether the tree
/// is "mutated" (CVE-2012-2459). Faithful port of Bitcoin Core's
/// `MerkleComputation`: the algorithm's own self-duplication of an odd
/// trailing node (`hash(h, h)`) is NOT flagged; only two *real* equal sibling
/// subtrees set the flag — which can only arise from duplicated transactions,
/// since txids are otherwise unique. Returns `(None, false)` for empty input.
pub fn root_detecting_mutation(leaves: &[[u8; 32]]) -> (Option<[u8; 32]>, bool) {
    if leaves.is_empty() {
        return (None, false);
    }

    let mut mutated = false;
    let mut count: u32 = 0;
    let mut inner = [[0u8; 32]; 32];

    // Accumulate leaves, collapsing complete subtrees as we go.
    while (count as usize) < leaves.len() {
        let mut h = leaves[count as usize];
        count += 1;
        let mut level = 0usize;
        while count & (1u32 << level) == 0 {
            if inner[level] == h {
                mutated = true;
            }
            h = hash_pair(&inner[level], &h);
            level += 1;
        }
        inner[level] = h;
    }

    // Collapse the remaining partial subtrees, self-duplicating odd nodes.
    let mut level = 0usize;
    while count & (1u32 << level) == 0 {
        level += 1;
    }
    let mut h = inner[level];
    while count != (1u32 << level) {
        h = hash_pair(&h, &h); // padding duplication — never a mutation
        count += 1u32 << level;
        level += 1;
        while count & (1u32 << level) == 0 {
            if inner[level] == h {
                mutated = true;
            }
            h = hash_pair(&inner[level], &h);
            level += 1;
        }
    }

    (Some(h), mutated)
}

/// Build the merkle tree over `leaves` and return `(root, branch)` where
/// `branch` is the list of sibling hashes for the leaf at `index`, bottom-up
/// (an SPV / Electrum / Stratum proof path). Empty input yields
/// `([0u8; 32], [])`; a single leaf is its own root with an empty branch.
pub fn branch(leaves: &[[u8; 32]], index: usize) -> ([u8; 32], Vec<[u8; 32]>) {
    if leaves.is_empty() {
        return ([0u8; 32], Vec::new());
    }

    let mut branch = Vec::new();
    let mut level: Vec<[u8; 32]> = leaves.to_vec();
    let mut idx = index;

    while level.len() > 1 {
        if !level.len().is_multiple_of(2) {
            let last = *level.last().expect("loop guard: level is non-empty");
            level.push(last);
        }

        let sibling = if idx.is_multiple_of(2) {
            idx + 1
        } else {
            idx - 1
        };
        branch.push(level[sibling]);

        let mut next: Vec<[u8; 32]> = Vec::with_capacity(level.len() / 2);
        for pair in level.chunks(2) {
            next.push(hash_pair(&pair[0], &pair[1]));
        }
        level = next;
        idx /= 2;
    }

    (level[0], branch)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn leaf(n: u8) -> [u8; 32] {
        [n; 32]
    }

    #[test]
    fn empty_and_single_leaf() {
        assert_eq!(root(&[]), [0u8; 32]);
        assert_eq!(root_detecting_mutation(&[]), (None, false));
        assert_eq!(branch(&[], 0), ([0u8; 32], vec![]));

        let l = leaf(7);
        assert_eq!(root(&[l]), l);
        assert_eq!(root_detecting_mutation(&[l]), (Some(l), false));
        assert_eq!(branch(&[l], 0), (l, vec![]));
    }

    /// The two root implementations must agree on non-mutated trees of every
    /// small size (odd-duplication edge cases live in sizes 2..=9).
    #[test]
    fn root_agrees_with_mutation_detecting_root() {
        for n in 1..=9u8 {
            let leaves: Vec<[u8; 32]> = (0..n).map(leaf).collect();
            let (r, mutated) = root_detecting_mutation(&leaves);
            assert!(!mutated, "distinct leaves must not flag mutation (n={n})");
            assert_eq!(r.unwrap(), root(&leaves), "roots diverge at n={n}");
        }
    }

    /// Folding a leaf up its branch must reproduce the root, for every leaf
    /// index and tree size.
    #[test]
    fn branch_folds_back_to_root() {
        for n in 1..=9usize {
            let leaves: Vec<[u8; 32]> = (0..n as u8).map(leaf).collect();
            let expected_root = root(&leaves);
            for index in 0..n {
                let (r, path) = branch(&leaves, index);
                assert_eq!(r, expected_root);
                let mut h = leaves[index];
                let mut idx = index;
                for sibling in &path {
                    h = if idx % 2 == 0 {
                        hash_pair(&h, sibling)
                    } else {
                        hash_pair(sibling, &h)
                    };
                    idx /= 2;
                }
                assert_eq!(h, expected_root, "n={n} index={index}");
            }
        }
    }

    /// CVE-2012-2459: duplicating the final transaction pair produces the
    /// same root but must set the mutation flag.
    #[test]
    fn duplicate_leaves_flag_mutation() {
        let leaves: Vec<[u8; 32]> = (0..3u8).map(leaf).collect();
        let (r1, m1) = root_detecting_mutation(&leaves);
        assert!(!m1);
        // Duplicate the trailing leaf explicitly — same root, mutated.
        let dup = vec![leaves[0], leaves[1], leaves[2], leaves[2]];
        let (r2, m2) = root_detecting_mutation(&dup);
        assert_eq!(r1, r2, "mutated tree has the same root (the attack)");
        assert!(m2, "explicit duplicate must be flagged");
    }
}

/// Property tests (Phase 6, 2026-07-02 review): random trees pin the three
/// entry points against each other and against rust-bitcoin's own root.
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        /// root() and root_detecting_mutation() must agree on arbitrary
        /// (almost surely distinct) random leaves, with no mutation flagged.
        #[test]
        fn roots_agree(leaves in proptest::collection::vec(proptest::array::uniform32(any::<u8>()), 1..64)) {
            let (r, _mutated) = root_detecting_mutation(&leaves);
            prop_assert_eq!(r.unwrap(), root(&leaves));
        }

        /// Every leaf's branch folds back to the root.
        #[test]
        fn branches_fold_to_root(
            leaves in proptest::collection::vec(proptest::array::uniform32(any::<u8>()), 1..64),
            index_seed in any::<usize>(),
        ) {
            let index = index_seed % leaves.len();
            let expected = root(&leaves);
            let (r, path) = branch(&leaves, index);
            prop_assert_eq!(r, expected);
            let mut h = leaves[index];
            let mut idx = index;
            for sibling in &path {
                h = if idx % 2 == 0 { hash_pair(&h, sibling) } else { hash_pair(sibling, &h) };
                idx /= 2;
            }
            prop_assert_eq!(h, expected);
        }

        /// Cross-check against rust-bitcoin's merkle root over the same leaves.
        #[test]
        fn root_matches_rust_bitcoin(leaves in proptest::collection::vec(proptest::array::uniform32(any::<u8>()), 1..64)) {
            use bitcoin::hashes::sha256d;
            let hashes = leaves.iter().map(|l| sha256d::Hash::from_byte_array(*l));
            let expected: Option<sha256d::Hash> = bitcoin::merkle_tree::calculate_root(hashes);
            prop_assert_eq!(root(&leaves), expected.unwrap().to_byte_array());
        }
    }
}
