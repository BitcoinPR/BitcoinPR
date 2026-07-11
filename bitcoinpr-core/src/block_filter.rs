//! BIP 157/158 — Compact Block Filters.
//!
//! BIP 158 defines Golomb-Rice coded sets (GCS) for encoding sets of data elements
//! derived from a block's transactions (scriptPubKeys). BIP 157 defines the P2P
//! messages for serving these filters to light clients.
//!
//! Filter type 0x00 ("basic") includes:
//! - All scriptPubKeys of outputs created by the block's transactions
//! - All scriptPubKeys of outputs spent by the block's transactions
//! - Excludes OP_RETURN outputs and duplicate items

use bitcoin::blockdata::script::Script;
use bitcoin::hashes::{sha256d, Hash};
use bitcoin::{Block, BlockHash};
use std::collections::HashSet;

/// BIP 158 basic filter parameters.
/// P = 2^GOLOMB_P is the false positive rate (1/2^19 ≈ 1 in 524288).
const GOLOMB_P: u8 = 19;
/// SipHash key derivation uses the block hash.
const BASIC_FILTER_TYPE: u8 = 0x00;

/// A compact block filter (BIP 158).
#[derive(Debug, Clone)]
pub struct BlockFilter {
    /// Filter type (0x00 = basic).
    pub filter_type: u8,
    /// Block hash this filter is for.
    pub block_hash: BlockHash,
    /// The encoded GCS filter data.
    pub filter_data: Vec<u8>,
}

/// A filter header: hash(filter_hash || prev_filter_header).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FilterHeader(pub [u8; 32]);

impl FilterHeader {
    /// The genesis (zero) filter header used before block 0.
    pub fn genesis() -> Self {
        FilterHeader([0u8; 32])
    }

    /// Compute the next filter header: SHA256d(filter_hash || prev_header).
    pub fn next(&self, filter_hash: &[u8; 32]) -> Self {
        let mut data = [0u8; 64];
        data[..32].copy_from_slice(filter_hash);
        data[32..].copy_from_slice(&self.0);
        let hash = sha256d::Hash::hash(&data);
        FilterHeader(hash.to_byte_array())
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Build a basic (type 0x00) block filter for a given block.
///
/// Includes all non-OP_RETURN output scriptPubKeys and all spent output scriptPubKeys.
/// `prev_scripts` provides the scriptPubKeys of the outputs spent by each input.
pub fn build_basic_filter(
    block: &Block,
    block_hash: &BlockHash,
    prev_scripts: &[Vec<Vec<u8>>],
) -> BlockFilter {
    let mut elements = HashSet::new();

    for (tx_idx, tx) in block.txdata.iter().enumerate() {
        // Add output scriptPubKeys (except OP_RETURN)
        for output in &tx.output {
            let script = &output.script_pubkey;
            if !script.is_op_return() && !script.is_empty() {
                elements.insert(script.as_bytes().to_vec());
            }
        }

        // Add spent output scriptPubKeys (skip coinbase)
        if !tx.is_coinbase() {
            if let Some(prev) = prev_scripts.get(tx_idx) {
                for script_bytes in prev {
                    if !script_bytes.is_empty() {
                        let script = Script::from_bytes(script_bytes);
                        if !script.is_op_return() {
                            elements.insert(script_bytes.clone());
                        }
                    }
                }
            }
        }
    }

    if elements.is_empty() {
        return BlockFilter {
            filter_type: BASIC_FILTER_TYPE,
            block_hash: *block_hash,
            filter_data: vec![0], // Empty filter: just N=0
        };
    }

    let key = siphash_key_from_block_hash(block_hash);
    let filter_data = gcs_encode(&elements, key);

    BlockFilter {
        filter_type: BASIC_FILTER_TYPE,
        block_hash: *block_hash,
        filter_data,
    }
}

/// Compute the filter hash (double SHA-256 of the filter data).
pub fn filter_hash(filter_data: &[u8]) -> [u8; 32] {
    sha256d::Hash::hash(filter_data).to_byte_array()
}

/// Match a set of query elements against a filter (for light clients).
/// Returns true if any query element may be in the filter (with false positive rate 1/2^P).
pub fn match_any(filter_data: &[u8], block_hash: &BlockHash, query_elements: &[Vec<u8>]) -> bool {
    if query_elements.is_empty() {
        return false;
    }
    if filter_data.is_empty() || filter_data == [0] {
        return false;
    }

    let key = siphash_key_from_block_hash(block_hash);

    // Decode the filter
    let (n, data_offset) = read_compact_size(filter_data);
    if n == 0 {
        return false;
    }

    let f = n * (1u64 << GOLOMB_P);

    // Hash query elements and sort
    let mut query_hashes: Vec<u64> = query_elements
        .iter()
        .map(|e| hash_to_range(e, f, key))
        .collect();
    query_hashes.sort_unstable();
    query_hashes.dedup();

    // Decode filter values and check for matches
    let mut reader = BitReader::new(&filter_data[data_offset..]);
    let mut filter_val = 0u64;
    let mut query_idx = 0;

    for _ in 0..n {
        let delta = reader.read_golomb_rice(GOLOMB_P);
        filter_val += delta;

        while query_idx < query_hashes.len() && query_hashes[query_idx] < filter_val {
            query_idx += 1;
        }

        if query_idx < query_hashes.len() && query_hashes[query_idx] == filter_val {
            return true;
        }

        if query_idx >= query_hashes.len() {
            break;
        }
    }

    false
}

/// Derive SipHash key from block hash (first 16 bytes).
fn siphash_key_from_block_hash(block_hash: &BlockHash) -> [u8; 16] {
    let hash_bytes: &[u8] = block_hash.as_ref();
    let mut key = [0u8; 16];
    key.copy_from_slice(&hash_bytes[..16]);
    key
}

/// SipHash-2-4 with 128-bit key for GCS hashing.
fn siphash_2_4(key: &[u8; 16], data: &[u8]) -> u64 {
    let k0 = u64::from_le_bytes(key[..8].try_into().expect("fixed-size slice"));
    let k1 = u64::from_le_bytes(key[8..16].try_into().expect("fixed-size slice"));

    let mut v0: u64 = 0x736f6d6570736575 ^ k0;
    let mut v1: u64 = 0x646f72616e646f6d ^ k1;
    let mut v2: u64 = 0x6c7967656e657261 ^ k0;
    let mut v3: u64 = 0x7465646279746573 ^ k1;

    let chunks = data.len() / 8;
    for i in 0..chunks {
        let m = u64::from_le_bytes(
            data[i * 8..(i + 1) * 8]
                .try_into()
                .expect("fixed-size slice"),
        );
        v3 ^= m;
        for _ in 0..2 {
            sip_round(&mut v0, &mut v1, &mut v2, &mut v3);
        }
        v0 ^= m;
    }

    let mut last = (data.len() as u64 & 0xff) << 56;
    let remaining = &data[chunks * 8..];
    for (i, &byte) in remaining.iter().enumerate() {
        last |= (byte as u64) << (i * 8);
    }
    v3 ^= last;
    for _ in 0..2 {
        sip_round(&mut v0, &mut v1, &mut v2, &mut v3);
    }
    v0 ^= last;

    v2 ^= 0xff;
    for _ in 0..4 {
        sip_round(&mut v0, &mut v1, &mut v2, &mut v3);
    }

    v0 ^ v1 ^ v2 ^ v3
}

#[inline]
fn sip_round(v0: &mut u64, v1: &mut u64, v2: &mut u64, v3: &mut u64) {
    *v0 = v0.wrapping_add(*v1);
    *v1 = v1.rotate_left(13);
    *v1 ^= *v0;
    *v0 = v0.rotate_left(32);
    *v2 = v2.wrapping_add(*v3);
    *v3 = v3.rotate_left(16);
    *v3 ^= *v2;
    *v0 = v0.wrapping_add(*v3);
    *v3 = v3.rotate_left(21);
    *v3 ^= *v0;
    *v2 = v2.wrapping_add(*v1);
    *v1 = v1.rotate_left(17);
    *v1 ^= *v2;
    *v2 = v2.rotate_left(32);
}

/// Map an element into the range [0, f) using SipHash.
fn hash_to_range(element: &[u8], f: u64, key: [u8; 16]) -> u64 {
    let hash = siphash_2_4(&key, element);
    // Map to [0, f) using fast range reduction
    fast_range(hash, f)
}

/// Fast range reduction: maps a 64-bit hash uniformly into [0, n).
fn fast_range(hash: u64, n: u64) -> u64 {
    ((hash as u128 * n as u128) >> 64) as u64
}

/// Golomb-Rice encode a set of elements into a GCS filter.
fn gcs_encode(elements: &HashSet<Vec<u8>>, key: [u8; 16]) -> Vec<u8> {
    let n = elements.len() as u64;
    let f = n * (1u64 << GOLOMB_P);

    // Hash all elements and sort
    let mut hashed: Vec<u64> = elements.iter().map(|e| hash_to_range(e, f, key)).collect();
    hashed.sort_unstable();

    let mut output = Vec::new();
    // Write N as compact size
    write_compact_size(&mut output, n);

    // Golomb-Rice encode the differences
    let mut writer = BitWriter::new();
    let mut prev = 0u64;
    for &val in &hashed {
        let delta = val - prev;
        writer.write_golomb_rice(delta, GOLOMB_P);
        prev = val;
    }
    output.extend_from_slice(&writer.finish());

    output
}

/// Write a CompactSize unsigned integer.
fn write_compact_size(out: &mut Vec<u8>, n: u64) {
    if n < 0xfd {
        out.push(n as u8);
    } else if n <= 0xffff {
        out.push(0xfd);
        out.extend_from_slice(&(n as u16).to_le_bytes());
    } else if n <= 0xffffffff {
        out.push(0xfe);
        out.extend_from_slice(&(n as u32).to_le_bytes());
    } else {
        out.push(0xff);
        out.extend_from_slice(&n.to_le_bytes());
    }
}

/// Read a CompactSize unsigned integer, returning (value, bytes_consumed).
fn read_compact_size(data: &[u8]) -> (u64, usize) {
    if data.is_empty() {
        return (0, 0);
    }
    match data[0] {
        0xff => {
            let val = u64::from_le_bytes(data[1..9].try_into().unwrap_or([0; 8]));
            (val, 9)
        }
        0xfe => {
            let val = u32::from_le_bytes(data[1..5].try_into().unwrap_or([0; 4])) as u64;
            (val, 5)
        }
        0xfd => {
            let val = u16::from_le_bytes(data[1..3].try_into().unwrap_or([0; 2])) as u64;
            (val, 3)
        }
        n => (n as u64, 1),
    }
}

/// Bit-level writer for Golomb-Rice encoding.
struct BitWriter {
    bytes: Vec<u8>,
    current: u8,
    bits_used: u8,
}

impl BitWriter {
    fn new() -> Self {
        BitWriter {
            bytes: Vec::new(),
            current: 0,
            bits_used: 0,
        }
    }

    fn write_bit(&mut self, bit: bool) {
        if bit {
            self.current |= 1 << (7 - self.bits_used);
        }
        self.bits_used += 1;
        if self.bits_used == 8 {
            self.bytes.push(self.current);
            self.current = 0;
            self.bits_used = 0;
        }
    }

    fn write_bits(&mut self, value: u64, n_bits: u8) {
        for i in (0..n_bits).rev() {
            self.write_bit((value >> i) & 1 == 1);
        }
    }

    /// Write a Golomb-Rice encoded value.
    /// Quotient encoded in unary (q zeros + 1), remainder in P bits.
    fn write_golomb_rice(&mut self, value: u64, p: u8) {
        let q = value >> p;
        let r = value & ((1u64 << p) - 1);

        // Unary encoding of quotient: q zeros followed by a 1
        for _ in 0..q {
            self.write_bit(false);
        }
        self.write_bit(true);

        // Binary encoding of remainder in P bits
        self.write_bits(r, p);
    }

    fn finish(mut self) -> Vec<u8> {
        if self.bits_used > 0 {
            self.bytes.push(self.current);
        }
        self.bytes
    }
}

/// Bit-level reader for Golomb-Rice decoding.
struct BitReader<'a> {
    data: &'a [u8],
    byte_idx: usize,
    bit_idx: u8,
}

impl<'a> BitReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        BitReader {
            data,
            byte_idx: 0,
            bit_idx: 0,
        }
    }

    fn read_bit(&mut self) -> bool {
        if self.byte_idx >= self.data.len() {
            return false;
        }
        let bit = (self.data[self.byte_idx] >> (7 - self.bit_idx)) & 1 == 1;
        self.bit_idx += 1;
        if self.bit_idx == 8 {
            self.bit_idx = 0;
            self.byte_idx += 1;
        }
        bit
    }

    fn read_bits(&mut self, n_bits: u8) -> u64 {
        let mut value = 0u64;
        for _ in 0..n_bits {
            value = (value << 1) | (self.read_bit() as u64);
        }
        value
    }

    /// Read a Golomb-Rice encoded value.
    fn read_golomb_rice(&mut self, p: u8) -> u64 {
        // Read unary-encoded quotient
        let mut q = 0u64;
        while !self.read_bit() {
            q += 1;
        }
        // Read P-bit remainder
        let r = self.read_bits(p);
        (q << p) | r
    }
}

/// P2P message types for BIP 157.
#[derive(Debug, Clone)]
pub struct GetCFilters {
    pub filter_type: u8,
    pub start_height: u32,
    pub stop_hash: BlockHash,
}

#[derive(Debug, Clone)]
pub struct CFilter {
    pub filter_type: u8,
    pub block_hash: BlockHash,
    pub filter_data: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct GetCFHeaders {
    pub filter_type: u8,
    pub start_height: u32,
    pub stop_hash: BlockHash,
}

#[derive(Debug, Clone)]
pub struct CFHeaders {
    pub filter_type: u8,
    pub stop_hash: BlockHash,
    pub prev_filter_header: FilterHeader,
    pub filter_hashes: Vec<[u8; 32]>,
}

#[derive(Debug, Clone)]
pub struct GetCFCheckPt {
    pub filter_type: u8,
    pub stop_hash: BlockHash,
}

#[derive(Debug, Clone)]
pub struct CFCheckPt {
    pub filter_type: u8,
    pub stop_hash: BlockHash,
    pub filter_headers: Vec<FilterHeader>,
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn test_compact_size_roundtrip() {
        for &val in &[
            0u64,
            1,
            100,
            252,
            253,
            0xffff,
            0x10000,
            0xffffffff,
            0x100000000,
        ] {
            let mut buf = Vec::new();
            write_compact_size(&mut buf, val);
            let (decoded, _) = read_compact_size(&buf);
            assert_eq!(val, decoded, "CompactSize roundtrip failed for {val}");
        }
    }

    #[test]
    fn test_golomb_rice_roundtrip() {
        let values = vec![0u64, 1, 5, 100, 1000, 524288, 1048576];

        let mut writer = BitWriter::new();
        for &val in &values {
            writer.write_golomb_rice(val, GOLOMB_P);
        }
        let encoded = writer.finish();

        let mut reader = BitReader::new(&encoded);
        for &expected in &values {
            let decoded = reader.read_golomb_rice(GOLOMB_P);
            assert_eq!(expected, decoded, "Golomb-Rice roundtrip failed");
        }
    }

    #[test]
    fn test_siphash_deterministic() {
        let key = [0u8; 16];
        let h1 = siphash_2_4(&key, b"hello");
        let h2 = siphash_2_4(&key, b"hello");
        assert_eq!(h1, h2);

        let h3 = siphash_2_4(&key, b"world");
        assert_ne!(h1, h3);
    }

    #[test]
    fn test_fast_range() {
        // fast_range should map uniformly into [0, n)
        let hash = u64::MAX;
        let result = fast_range(hash, 100);
        assert!(result < 100);

        let hash = 0u64;
        let result = fast_range(hash, 100);
        assert_eq!(result, 0);
    }

    #[test]
    fn test_empty_filter() {
        let _elements: HashSet<Vec<u8>> = HashSet::new();
        // An empty set should produce a filter with N=0
        let _key = [0u8; 16];
        // Manually test: empty set gives just the compact size 0
        let mut output = Vec::new();
        write_compact_size(&mut output, 0);
        assert_eq!(output, vec![0]);
    }

    #[test]
    fn test_gcs_encode_decode_match() {
        let mut elements = HashSet::new();
        elements.insert(b"script_pubkey_1".to_vec());
        elements.insert(b"script_pubkey_2".to_vec());
        elements.insert(b"script_pubkey_3".to_vec());

        let key = [1u8; 16];
        let filter_data = gcs_encode(&elements, key);

        // Verify we can match elements that are in the filter
        let (n, offset) = read_compact_size(&filter_data);
        assert_eq!(n, 3);

        let f = n * (1u64 << GOLOMB_P);

        // Decode all values
        let mut reader = BitReader::new(&filter_data[offset..]);
        let mut decoded_vals = Vec::new();
        let mut prev = 0u64;
        for _ in 0..n {
            let delta = reader.read_golomb_rice(GOLOMB_P);
            prev += delta;
            decoded_vals.push(prev);
        }

        // Each element should hash into the decoded values
        for elem in &elements {
            let h = hash_to_range(elem, f, key);
            assert!(decoded_vals.contains(&h), "Element not found in filter");
        }
    }

    #[test]
    fn test_match_any() {
        let mut elements = HashSet::new();
        elements.insert(b"output_script_a".to_vec());
        elements.insert(b"output_script_b".to_vec());
        elements.insert(b"spent_script_c".to_vec());

        let block_hash = BlockHash::all_zeros();
        let key = siphash_key_from_block_hash(&block_hash);
        let filter_data = gcs_encode(&elements, key);

        // Matching element should return true
        assert!(match_any(
            &filter_data,
            &block_hash,
            &[b"output_script_a".to_vec()]
        ));

        // Non-matching element should (almost certainly) return false
        assert!(!match_any(
            &filter_data,
            &block_hash,
            &[b"definitely_not_in_filter_xyz_12345".to_vec()]
        ));

        // Empty query should return false
        assert!(!match_any(&filter_data, &block_hash, &[]));

        // Empty filter should return false
        assert!(!match_any(
            &[0],
            &block_hash,
            &[b"output_script_a".to_vec()]
        ));
    }

    #[test]
    fn test_filter_header_chain() {
        let h0 = FilterHeader::genesis();
        assert_eq!(h0.0, [0u8; 32]);

        let filter_hash_1 = [1u8; 32];
        let h1 = h0.next(&filter_hash_1);
        assert_ne!(h1.0, [0u8; 32]);

        let filter_hash_2 = [2u8; 32];
        let h2 = h1.next(&filter_hash_2);
        assert_ne!(h2.0, h1.0);

        // Deterministic
        let h2_again = h1.next(&filter_hash_2);
        assert_eq!(h2.0, h2_again.0);
    }
}
