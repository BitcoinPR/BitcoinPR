//! BIP 324 — Version 2 Encrypted P2P Transport Protocol.
//!
//! Implements opportunistic encryption for Bitcoin P2P connections:
//! 1. ElligatorSwift key exchange (64-byte public key encoding)
//! 2. ECDH shared secret derivation
//! 3. FSChaCha20-Poly1305 AEAD for packet encryption with forward-secret
//!    rekeying every 224 packets (per BIP 324)
//! 4. Short message type IDs for bandwidth efficiency
//!
//! The protocol upgrades the V1 plaintext Bitcoin P2P protocol to an encrypted
//! channel while maintaining backward compatibility through version negotiation.
//!
//! Record layer (BIP 324 "Packet encryption"):
//! - Each packet is `enc_length (3 bytes) || AEAD(header (1 byte) || contents)`.
//! - Lengths are encrypted with FSChaCha20 (an unauthenticated rekeying stream
//!   cipher); the payload uses FSChaCha20Poly1305 (a rekeying wrapper around
//!   RFC 8439 ChaCha20-Poly1305).
//! - Both ciphers rekey every `REKEY_INTERVAL` (224) messages for forward
//!   secrecy; decoy ("ignore") packets advance the counters like any other.

use bitcoin::hashes::{sha256, Hash, HashEngine, Hmac, HmacEngine};
use bitcoin::secp256k1::ellswift::{ElligatorSwift, ElligatorSwiftParty};
use bitcoin::secp256k1::{Secp256k1, SecretKey};
use std::fmt;

/// BIP 324 network magic bytes sent by the initiator to signal V2 support.
pub const V2_TRANSPORT_MAGIC: [u8; 16] = [0; 16]; // 16 zero bytes

/// Maximum encrypted payload size (4 MiB) accepted at the application layer.
pub const MAX_PAYLOAD_SIZE: usize = 4 * 1024 * 1024;

/// Maximum contents length encodable in the 3-byte packet length field.
pub const MAX_CONTENTS_LEN: usize = (1 << 24) - 1;

/// ChaCha20-Poly1305 tag length (used during packet framing).
pub const AEAD_TAG_LEN: usize = 16;

/// Encrypted packet length field size.
pub const LENGTH_FIELD_LEN: usize = 3;

/// Plaintext header size (1 byte; bit 7 = ignore bit).
pub const HEADER_LEN: usize = 1;

/// The "ignore" (decoy) bit in the packet header byte (bit 7 per BIP 324).
pub const IGNORE_BIT: u8 = 0x80;

/// Number of packets/chunks after which the FSChaCha ciphers rekey (BIP 324).
pub const REKEY_INTERVAL: u64 = 224;

/// Short message type IDs for BIP 324 — the 1-byte encoding for common P2P
/// messages. These IDs (1..=28) and their ordering are normative: they must
/// match the table in BIP 324 exactly, since both peers encode/decode against
/// it on the wire. Messages without an ID here (version, verack, getaddr,
/// sendheaders, sendaddrv2, wtxidrelay, …) are carried with the full 12-byte
/// command via [`V2MessageType::Full`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ShortMsgId {
    Addr = 1,
    Block = 2,
    Blocktxn = 3,
    CmpctBlock = 4,
    FeeFilter = 5,
    FilterAdd = 6,
    FilterClear = 7,
    FilterLoad = 8,
    GetBlocks = 9,
    GetBlockTxn = 10,
    GetData = 11,
    GetHeaders = 12,
    Headers = 13,
    Inv = 14,
    Mempool = 15,
    MerkleBlock = 16,
    NotFound = 17,
    Ping = 18,
    Pong = 19,
    SendCmpct = 20,
    Tx = 21,
    GetCFilters = 22,
    CFilter = 23,
    GetCFHeaders = 24,
    CFHeaders = 25,
    GetCFCheckPt = 26,
    CFCheckPt = 27,
    Addrv2 = 28,
}

impl ShortMsgId {
    /// Convert a V1 command string to a short message ID.
    pub fn from_command(cmd: &str) -> Option<Self> {
        match cmd {
            "addr" => Some(ShortMsgId::Addr),
            "block" => Some(ShortMsgId::Block),
            "blocktxn" => Some(ShortMsgId::Blocktxn),
            "cmpctblock" => Some(ShortMsgId::CmpctBlock),
            "feefilter" => Some(ShortMsgId::FeeFilter),
            "filteradd" => Some(ShortMsgId::FilterAdd),
            "filterclear" => Some(ShortMsgId::FilterClear),
            "filterload" => Some(ShortMsgId::FilterLoad),
            "getblocks" => Some(ShortMsgId::GetBlocks),
            "getblocktxn" => Some(ShortMsgId::GetBlockTxn),
            "getdata" => Some(ShortMsgId::GetData),
            "getheaders" => Some(ShortMsgId::GetHeaders),
            "headers" => Some(ShortMsgId::Headers),
            "inv" => Some(ShortMsgId::Inv),
            "mempool" => Some(ShortMsgId::Mempool),
            "merkleblock" => Some(ShortMsgId::MerkleBlock),
            "notfound" => Some(ShortMsgId::NotFound),
            "ping" => Some(ShortMsgId::Ping),
            "pong" => Some(ShortMsgId::Pong),
            "sendcmpct" => Some(ShortMsgId::SendCmpct),
            "tx" => Some(ShortMsgId::Tx),
            "getcfilters" => Some(ShortMsgId::GetCFilters),
            "cfilter" => Some(ShortMsgId::CFilter),
            "getcfheaders" => Some(ShortMsgId::GetCFHeaders),
            "cfheaders" => Some(ShortMsgId::CFHeaders),
            "getcfcheckpt" => Some(ShortMsgId::GetCFCheckPt),
            "cfcheckpt" => Some(ShortMsgId::CFCheckPt),
            "addrv2" => Some(ShortMsgId::Addrv2),
            _ => None,
        }
    }

    /// Build a short message ID from its on-the-wire numeric value.
    pub fn from_u8(id: u8) -> Option<Self> {
        Self::from_command(Self::command_for_id(id)?)
    }

    fn command_for_id(id: u8) -> Option<&'static str> {
        Some(match id {
            1 => "addr",
            2 => "block",
            3 => "blocktxn",
            4 => "cmpctblock",
            5 => "feefilter",
            6 => "filteradd",
            7 => "filterclear",
            8 => "filterload",
            9 => "getblocks",
            10 => "getblocktxn",
            11 => "getdata",
            12 => "getheaders",
            13 => "headers",
            14 => "inv",
            15 => "mempool",
            16 => "merkleblock",
            17 => "notfound",
            18 => "ping",
            19 => "pong",
            20 => "sendcmpct",
            21 => "tx",
            22 => "getcfilters",
            23 => "cfilter",
            24 => "getcfheaders",
            25 => "cfheaders",
            26 => "getcfcheckpt",
            27 => "cfcheckpt",
            28 => "addrv2",
            _ => return None,
        })
    }

    /// Convert a short message ID back to a V1 command string.
    pub fn to_command(self) -> &'static str {
        Self::command_for_id(self as u8).expect("every variant has a command")
    }
}

/// V2 transport session state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum V2State {
    /// Waiting to send/receive ElligatorSwift public keys.
    AwaitingKeys,
    /// Key exchange complete, waiting for version/verack.
    AwaitingVersion,
    /// Fully established encrypted session.
    Established,
    /// Peer doesn't support V2; fall back to V1.
    FallbackV1,
}

/// Represents one side's key material for the BIP 324 handshake.
pub struct V2KeyMaterial {
    /// Our ephemeral secret key.
    pub secret_key: SecretKey,
    /// Our 64-byte ElligatorSwift-encoded public key.
    pub elligatorsw_pubkey: [u8; 64],
}

impl V2KeyMaterial {
    /// Generate fresh key material for a V2 handshake.
    /// Uses real ElligatorSwift encoding from libsecp256k1 (BIP 324 compatible).
    pub fn generate() -> Self {
        let secp = Secp256k1::new();
        let (secret_key, _public_key) = secp.generate_keypair(&mut rand::thread_rng());

        // Real ElligatorSwift encoding: produces a 64-byte uniform encoding
        // that is indistinguishable from random bytes (BIP 324 §4.1).
        let es = ElligatorSwift::from_seckey(&secp, secret_key, None);
        let elligatorsw_pubkey = es.to_array();

        V2KeyMaterial {
            secret_key,
            elligatorsw_pubkey,
        }
    }
}

impl fmt::Debug for V2KeyMaterial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("V2KeyMaterial")
            .field(
                "elligatorsw_pubkey",
                &hex::encode(&self.elligatorsw_pubkey[..8]),
            )
            .finish()
    }
}

// --- RFC 8439 primitives (ChaCha20 block function and ChaCha20-Poly1305 AEAD) ---

#[inline(always)]
fn quarter_round(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    state[a] = state[a].wrapping_add(state[b]);
    state[d] = (state[d] ^ state[a]).rotate_left(16);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_left(12);
    state[a] = state[a].wrapping_add(state[b]);
    state[d] = (state[d] ^ state[a]).rotate_left(8);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_left(7);
}

/// The ChaCha20 block function (RFC 8439 §2.3): 32-byte key, 12-byte nonce,
/// 32-bit block counter -> 64 bytes of keystream.
fn chacha20_block(key: &[u8; 32], nonce: &[u8; 12], counter: u32) -> [u8; 64] {
    let mut state = [0u32; 16];
    state[0] = 0x6170_7865;
    state[1] = 0x3320_646e;
    state[2] = 0x7962_2d32;
    state[3] = 0x6b20_6574;
    for i in 0..8 {
        state[4 + i] =
            u32::from_le_bytes([key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]]);
    }
    state[12] = counter;
    for i in 0..3 {
        state[13 + i] = u32::from_le_bytes([
            nonce[4 * i],
            nonce[4 * i + 1],
            nonce[4 * i + 2],
            nonce[4 * i + 3],
        ]);
    }

    let mut working = state;
    for _ in 0..10 {
        // Column rounds
        quarter_round(&mut working, 0, 4, 8, 12);
        quarter_round(&mut working, 1, 5, 9, 13);
        quarter_round(&mut working, 2, 6, 10, 14);
        quarter_round(&mut working, 3, 7, 11, 15);
        // Diagonal rounds
        quarter_round(&mut working, 0, 5, 10, 15);
        quarter_round(&mut working, 1, 6, 11, 12);
        quarter_round(&mut working, 2, 7, 8, 13);
        quarter_round(&mut working, 3, 4, 9, 14);
    }

    let mut out = [0u8; 64];
    for i in 0..16 {
        let word = working[i].wrapping_add(state[i]);
        out[4 * i..4 * i + 4].copy_from_slice(&word.to_le_bytes());
    }
    out
}

/// XOR `data` in place with the ChaCha20 keystream starting at `counter`.
fn chacha20_xor(key: &[u8; 32], nonce: &[u8; 12], mut counter: u32, data: &mut [u8]) {
    for chunk in data.chunks_mut(64) {
        let ks = chacha20_block(key, nonce, counter);
        counter = counter.wrapping_add(1);
        for (b, k) in chunk.iter_mut().zip(ks.iter()) {
            *b ^= k;
        }
    }
}

/// Poly1305 one-time authenticator (RFC 8439 §2.5). 32-byte key, returns 16-byte tag.
/// 26-bit limb implementation (poly1305-donna style).
fn poly1305_mac(key: &[u8; 32], msg: &[u8]) -> [u8; 16] {
    let le32 = |b: &[u8]| -> u32 { u32::from_le_bytes([b[0], b[1], b[2], b[3]]) };

    // Clamp r.
    let r0 = le32(&key[0..4]) & 0x03ff_ffff;
    let r1 = (le32(&key[3..7]) >> 2) & 0x03ff_ff03;
    let r2 = (le32(&key[6..10]) >> 4) & 0x03ff_c0ff;
    let r3 = (le32(&key[9..13]) >> 6) & 0x03f0_3fff;
    let r4 = (le32(&key[12..16]) >> 8) & 0x000f_ffff;

    let s1 = r1 * 5;
    let s2 = r2 * 5;
    let s3 = r3 * 5;
    let s4 = r4 * 5;

    let (mut h0, mut h1, mut h2, mut h3, mut h4) = (0u32, 0u32, 0u32, 0u32, 0u32);

    let mut iter = msg.chunks(16);
    for block in iter.by_ref() {
        let mut buf = [0u8; 17];
        buf[..block.len()].copy_from_slice(block);
        let hibit: u32 = if block.len() == 16 {
            1 << 24
        } else {
            // Pad partial final block with a 0x01 byte then zeros; no high bit.
            buf[block.len()] = 1;
            0
        };

        h0 = h0.wrapping_add(le32(&buf[0..4]) & 0x03ff_ffff);
        h1 = h1.wrapping_add((le32(&buf[3..7]) >> 2) & 0x03ff_ffff);
        h2 = h2.wrapping_add((le32(&buf[6..10]) >> 4) & 0x03ff_ffff);
        h3 = h3.wrapping_add((le32(&buf[9..13]) >> 6) & 0x03ff_ffff);
        h4 = h4.wrapping_add((le32(&buf[12..16]) >> 8) | hibit);

        // h *= r (mod 2^130 - 5)
        let m = |a: u32, b: u32| -> u64 { (a as u64) * (b as u64) };
        let d0 = m(h0, r0) + m(h1, s4) + m(h2, s3) + m(h3, s2) + m(h4, s1);
        let mut d1 = m(h0, r1) + m(h1, r0) + m(h2, s4) + m(h3, s3) + m(h4, s2);
        let mut d2 = m(h0, r2) + m(h1, r1) + m(h2, r0) + m(h3, s4) + m(h4, s3);
        let mut d3 = m(h0, r3) + m(h1, r2) + m(h2, r1) + m(h3, r0) + m(h4, s4);
        let mut d4 = m(h0, r4) + m(h1, r3) + m(h2, r2) + m(h3, r1) + m(h4, r0);

        // Partial carry propagation.
        let mut c: u64;
        c = d0 >> 26;
        h0 = (d0 & 0x03ff_ffff) as u32;
        d1 += c;
        c = d1 >> 26;
        h1 = (d1 & 0x03ff_ffff) as u32;
        d2 += c;
        c = d2 >> 26;
        h2 = (d2 & 0x03ff_ffff) as u32;
        d3 += c;
        c = d3 >> 26;
        h3 = (d3 & 0x03ff_ffff) as u32;
        d4 += c;
        c = d4 >> 26;
        h4 = (d4 & 0x03ff_ffff) as u32;
        h0 = h0.wrapping_add((c as u32) * 5);
        let c2 = h0 >> 26;
        h0 &= 0x03ff_ffff;
        h1 = h1.wrapping_add(c2);
    }

    // Full carry h.
    let mut c: u32;
    c = h1 >> 26;
    h1 &= 0x03ff_ffff;
    h2 = h2.wrapping_add(c);
    c = h2 >> 26;
    h2 &= 0x03ff_ffff;
    h3 = h3.wrapping_add(c);
    c = h3 >> 26;
    h3 &= 0x03ff_ffff;
    h4 = h4.wrapping_add(c);
    c = h4 >> 26;
    h4 &= 0x03ff_ffff;
    h0 = h0.wrapping_add(c * 5);
    c = h0 >> 26;
    h0 &= 0x03ff_ffff;
    h1 = h1.wrapping_add(c);

    // Compute g = h + 5 - 2^130 to check h >= p.
    let mut g0 = h0.wrapping_add(5);
    c = g0 >> 26;
    g0 &= 0x03ff_ffff;
    let mut g1 = h1.wrapping_add(c);
    c = g1 >> 26;
    g1 &= 0x03ff_ffff;
    let mut g2 = h2.wrapping_add(c);
    c = g2 >> 26;
    g2 &= 0x03ff_ffff;
    let mut g3 = h3.wrapping_add(c);
    c = g3 >> 26;
    g3 &= 0x03ff_ffff;
    let g4 = h4.wrapping_add(c).wrapping_sub(1 << 26);

    // Select h if h < p, g otherwise (constant time).
    let mask = (g4 >> 31).wrapping_sub(1);
    let nmask = !mask;
    h0 = (h0 & nmask) | (g0 & mask);
    h1 = (h1 & nmask) | (g1 & mask);
    h2 = (h2 & nmask) | (g2 & mask);
    h3 = (h3 & nmask) | (g3 & mask);
    h4 = (h4 & nmask) | (g4 & mask);

    // h %= 2^128 (repack into four 32-bit words).
    let w0 = h0 | (h1 << 26);
    let w1 = (h1 >> 6) | (h2 << 20);
    let w2 = (h2 >> 12) | (h3 << 14);
    let w3 = (h3 >> 18) | (h4 << 8);

    // tag = (h + s) % 2^128
    let mut f: u64;
    let mut tag = [0u8; 16];
    f = (w0 as u64) + (le32(&key[16..20]) as u64);
    tag[0..4].copy_from_slice(&(f as u32).to_le_bytes());
    f = (w1 as u64) + (le32(&key[20..24]) as u64) + (f >> 32);
    tag[4..8].copy_from_slice(&(f as u32).to_le_bytes());
    f = (w2 as u64) + (le32(&key[24..28]) as u64) + (f >> 32);
    tag[8..12].copy_from_slice(&(f as u32).to_le_bytes());
    f = (w3 as u64) + (le32(&key[28..32]) as u64) + (f >> 32);
    tag[12..16].copy_from_slice(&(f as u32).to_le_bytes());
    tag
}

/// Compute the Poly1305 tag over `aad` and `ciphertext` per RFC 8439 §2.8.
fn chacha20_poly1305_tag(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    ciphertext: &[u8],
) -> [u8; 16] {
    let block0 = chacha20_block(key, nonce, 0);
    let mut otk = [0u8; 32];
    otk.copy_from_slice(&block0[..32]);

    let mut mac_data = Vec::with_capacity(aad.len() + ciphertext.len() + 32);
    mac_data.extend_from_slice(aad);
    mac_data.resize(mac_data.len().div_ceil(16) * 16, 0);
    mac_data.extend_from_slice(ciphertext);
    mac_data.resize(mac_data.len().div_ceil(16) * 16, 0);
    mac_data.extend_from_slice(&(aad.len() as u64).to_le_bytes());
    mac_data.extend_from_slice(&(ciphertext.len() as u64).to_le_bytes());
    poly1305_mac(&otk, &mac_data)
}

/// `aead_chacha20_poly1305_encrypt` per RFC 8439 §2.8.
/// Returns `ciphertext || tag` (16 bytes longer than the plaintext).
fn aead_chacha20_poly1305_encrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    plaintext: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(plaintext.len() + AEAD_TAG_LEN);
    out.extend_from_slice(plaintext);
    chacha20_xor(key, nonce, 1, &mut out);
    let tag = chacha20_poly1305_tag(key, nonce, aad, &out);
    out.extend_from_slice(&tag);
    out
}

/// `aead_chacha20_poly1305_decrypt` per RFC 8439 §2.8.
/// Returns the plaintext, or `None` on authentication failure.
fn aead_chacha20_poly1305_decrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    ciphertext: &[u8],
) -> Option<Vec<u8>> {
    if ciphertext.len() < AEAD_TAG_LEN {
        return None;
    }
    let (ct, tag) = ciphertext.split_at(ciphertext.len() - AEAD_TAG_LEN);
    let expected = chacha20_poly1305_tag(key, nonce, aad, ct);
    // Constant-time tag comparison.
    let mut diff = 0u8;
    for (a, b) in expected.iter().zip(tag.iter()) {
        diff |= a ^ b;
    }
    if diff != 0 {
        return None;
    }
    let mut pt = ct.to_vec();
    chacha20_xor(key, nonce, 1, &mut pt);
    Some(pt)
}

// --- BIP 324 rekeying wrappers: FSChaCha20 and FSChaCha20Poly1305 ---

/// FSChaCha20 (BIP 324): a rekeying stream cipher around the ChaCha20 block
/// function, used for the 3-byte packet length fields.
///
/// Each call to [`FsChaCha20::crypt`] processes one *chunk*. The nonce for a
/// batch of `REKEY_INTERVAL` chunks is 4 zero bytes followed by the 64-bit
/// little-endian number of rekeyings performed (`chunk_counter / 224`).
/// After every 224th chunk, the next 32 keystream bytes become the new key and
/// the block counter resets to 0.
#[derive(Clone)]
pub struct FsChaCha20 {
    key: [u8; 32],
    block_counter: u32,
    chunk_counter: u64,
    keystream: Vec<u8>,
}

impl FsChaCha20 {
    /// Create a new cipher with the given initial key.
    pub fn new(initial_key: [u8; 32]) -> Self {
        FsChaCha20 {
            key: initial_key,
            block_counter: 0,
            chunk_counter: 0,
            keystream: Vec::new(),
        }
    }

    fn get_keystream_bytes(&mut self, nbytes: usize) -> Vec<u8> {
        while self.keystream.len() < nbytes {
            let mut nonce = [0u8; 12];
            nonce[4..].copy_from_slice(&(self.chunk_counter / REKEY_INTERVAL).to_le_bytes());
            self.keystream.extend_from_slice(&chacha20_block(
                &self.key,
                &nonce,
                self.block_counter,
            ));
            self.block_counter = self.block_counter.wrapping_add(1);
        }
        self.keystream.drain(..nbytes).collect()
    }

    /// Encrypt or decrypt one chunk (the operation is its own inverse).
    pub fn crypt(&mut self, chunk: &[u8]) -> Vec<u8> {
        let ks = self.get_keystream_bytes(chunk.len());
        let ret: Vec<u8> = ks.iter().zip(chunk.iter()).map(|(k, c)| k ^ c).collect();
        if (self.chunk_counter + 1) % REKEY_INTERVAL == 0 {
            let new_key = self.get_keystream_bytes(32);
            self.key.copy_from_slice(&new_key);
            self.block_counter = 0;
        }
        self.chunk_counter += 1;
        ret
    }

    #[cfg(test)]
    pub(crate) fn current_key(&self) -> [u8; 32] {
        self.key
    }
}

impl fmt::Debug for FsChaCha20 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FsChaCha20")
            .field("chunk_counter", &self.chunk_counter)
            .finish()
    }
}

/// FSChaCha20Poly1305 (BIP 324): a rekeying wrapper AEAD around
/// RFC 8439 ChaCha20-Poly1305, used for packet payload encryption.
///
/// The nonce for a message is the 32-bit little-endian number of messages with
/// the current key (`packet_counter % 224`) followed by the 64-bit
/// little-endian number of rekeyings performed (`packet_counter / 224`).
/// After every 224th message the cipher rekeys: the new key is the first 32
/// bytes of the AEAD encryption of 32 zero bytes with nonce
/// `0xFFFFFFFF || LE64(rekeyings)`.
///
/// The packet counter advances on *every* message, including decoy packets and
/// failed decryptions.
#[derive(Clone)]
pub struct FsChaCha20Poly1305 {
    key: [u8; 32],
    packet_counter: u64,
}

impl FsChaCha20Poly1305 {
    /// Create a new AEAD with the given initial key.
    pub fn new(initial_key: [u8; 32]) -> Self {
        FsChaCha20Poly1305 {
            key: initial_key,
            packet_counter: 0,
        }
    }

    fn nonce(&self) -> [u8; 12] {
        let mut nonce = [0u8; 12];
        nonce[..4].copy_from_slice(&((self.packet_counter % REKEY_INTERVAL) as u32).to_le_bytes());
        nonce[4..].copy_from_slice(&(self.packet_counter / REKEY_INTERVAL).to_le_bytes());
        nonce
    }

    /// Rekey if this message completes a 224-message epoch, then advance the counter.
    fn advance(&mut self, nonce: &[u8; 12]) {
        if (self.packet_counter + 1) % REKEY_INTERVAL == 0 {
            let mut rekey_nonce = [0xFFu8; 12];
            rekey_nonce[4..].copy_from_slice(&nonce[4..]);
            let out = aead_chacha20_poly1305_encrypt(&self.key, &rekey_nonce, b"", &[0u8; 32]);
            self.key.copy_from_slice(&out[..32]);
        }
        self.packet_counter += 1;
    }

    /// Encrypt one message; returns `ciphertext || tag`.
    pub fn encrypt(&mut self, aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
        let nonce = self.nonce();
        let ret = aead_chacha20_poly1305_encrypt(&self.key, &nonce, aad, plaintext);
        self.advance(&nonce);
        ret
    }

    /// Decrypt one message; returns the plaintext or `None` on auth failure.
    /// The counter advances even on failure (a failed packet terminates the
    /// connection in practice).
    pub fn decrypt(&mut self, aad: &[u8], ciphertext: &[u8]) -> Option<Vec<u8>> {
        let nonce = self.nonce();
        let ret = aead_chacha20_poly1305_decrypt(&self.key, &nonce, aad, ciphertext);
        self.advance(&nonce);
        ret
    }

    #[cfg(test)]
    pub(crate) fn packet_counter(&self) -> u64 {
        self.packet_counter
    }

    #[cfg(test)]
    pub(crate) fn current_key(&self) -> [u8; 32] {
        self.key
    }
}

impl fmt::Debug for FsChaCha20Poly1305 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FsChaCha20Poly1305")
            .field("packet_counter", &self.packet_counter)
            .finish()
    }
}

/// Raw key material derived from the ECDH secret via HKDF (BIP 324 §"Keys").
struct DerivedKeys {
    initiator_l: [u8; 32],
    initiator_p: [u8; 32],
    responder_l: [u8; 32],
    responder_p: [u8; 32],
    /// First 16 bytes: initiator terminator; last 16: responder terminator.
    garbage_terminators: [u8; 32],
    session_id: [u8; 32],
}

fn derive_keys(shared_secret: &[u8; 32], network_magic: &[u8; 4]) -> DerivedKeys {
    // HKDF-Extract: PRK = HMAC-SHA256(salt = "bitcoin_v2_shared_secret" + magic, IKM)
    let mut salt = Vec::with_capacity(28);
    salt.extend_from_slice(b"bitcoin_v2_shared_secret");
    salt.extend_from_slice(network_magic);
    let prk = hkdf_extract(&salt, shared_secret);

    DerivedKeys {
        initiator_l: hkdf_expand(&prk, b"initiator_L"),
        initiator_p: hkdf_expand(&prk, b"initiator_P"),
        responder_l: hkdf_expand(&prk, b"responder_L"),
        responder_p: hkdf_expand(&prk, b"responder_P"),
        garbage_terminators: hkdf_expand(&prk, b"garbage_terminators"),
        session_id: hkdf_expand(&prk, b"session_id"),
    }
}

/// Shared session state derived from the ECDH handshake: directional
/// FSChaCha20 (length) and FSChaCha20Poly1305 (payload) ciphers, the session
/// ID and the garbage terminators (BIP 324).
#[derive(Clone)]
pub struct V2SessionKeys {
    /// Session ID (for optional authentication).
    pub session_id: [u8; 32],
    /// Garbage terminator we send after our public key.
    pub send_garbage_terminator: [u8; 16],
    /// Garbage terminator we expect from the peer.
    pub recv_garbage_terminator: [u8; 16],
    /// Length cipher for packets we send.
    pub send_l: FsChaCha20,
    /// Payload AEAD for packets we send.
    pub send_p: FsChaCha20Poly1305,
    /// Length cipher for packets we receive.
    pub recv_l: FsChaCha20,
    /// Payload AEAD for packets we receive.
    pub recv_p: FsChaCha20Poly1305,
}

impl fmt::Debug for V2SessionKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("V2SessionKeys")
            .field("session_id", &hex::encode(&self.session_id[..8]))
            .field("send_p", &self.send_p)
            .field("recv_p", &self.recv_p)
            .finish()
    }
}

impl V2SessionKeys {
    /// Derive session keys from the ECDH shared secret (BIP 324 §"Keys").
    ///
    /// `network_magic` is the 4-byte P2P network magic (e.g. `f9beb4d9` for
    /// mainnet), mixed into the HKDF salt so v2 sessions are network-bound.
    pub fn derive(shared_secret: &[u8; 32], network_magic: &[u8; 4], is_initiator: bool) -> Self {
        let keys = derive_keys(shared_secret, network_magic);
        let mut initiator_term = [0u8; 16];
        let mut responder_term = [0u8; 16];
        initiator_term.copy_from_slice(&keys.garbage_terminators[..16]);
        responder_term.copy_from_slice(&keys.garbage_terminators[16..]);

        if is_initiator {
            V2SessionKeys {
                session_id: keys.session_id,
                send_garbage_terminator: initiator_term,
                recv_garbage_terminator: responder_term,
                send_l: FsChaCha20::new(keys.initiator_l),
                send_p: FsChaCha20Poly1305::new(keys.initiator_p),
                recv_l: FsChaCha20::new(keys.responder_l),
                recv_p: FsChaCha20Poly1305::new(keys.responder_p),
            }
        } else {
            V2SessionKeys {
                session_id: keys.session_id,
                send_garbage_terminator: responder_term,
                recv_garbage_terminator: initiator_term,
                send_l: FsChaCha20::new(keys.responder_l),
                send_p: FsChaCha20Poly1305::new(keys.responder_p),
                recv_l: FsChaCha20::new(keys.initiator_l),
                recv_p: FsChaCha20Poly1305::new(keys.initiator_p),
            }
        }
    }

    /// Encrypt one packet (`v2_enc_packet` in BIP 324):
    /// returns `enc_length (3 bytes) || AEAD(header || contents)`.
    ///
    /// `ignore` sets the decoy bit; decoy packets advance the cipher counters
    /// exactly like normal packets.
    pub fn encrypt_packet(&mut self, contents: &[u8], aad: &[u8], ignore: bool) -> Vec<u8> {
        assert!(
            contents.len() <= MAX_CONTENTS_LEN,
            "contents too large for v2 packet"
        );
        let header = if ignore { IGNORE_BIT } else { 0x00 };
        let mut plaintext = Vec::with_capacity(HEADER_LEN + contents.len());
        plaintext.push(header);
        plaintext.extend_from_slice(contents);
        let aead_ciphertext = self.send_p.encrypt(aad, &plaintext);

        let len_bytes = (contents.len() as u32).to_le_bytes();
        let enc_len = self.send_l.crypt(&len_bytes[..LENGTH_FIELD_LEN]);

        let mut out = Vec::with_capacity(LENGTH_FIELD_LEN + aead_ciphertext.len());
        out.extend_from_slice(&enc_len);
        out.extend_from_slice(&aead_ciphertext);
        out
    }

    /// Decrypt the 3-byte encrypted length field of an incoming packet,
    /// returning the contents length. The remaining packet bytes to read are
    /// `contents_len + HEADER_LEN + AEAD_TAG_LEN`.
    pub fn decrypt_packet_len(&mut self, enc_len: &[u8; LENGTH_FIELD_LEN]) -> usize {
        let dec = self.recv_l.crypt(enc_len);
        (dec[0] as usize) | ((dec[1] as usize) << 8) | ((dec[2] as usize) << 16)
    }

    /// Decrypt and authenticate an incoming packet's AEAD ciphertext
    /// (`header || contents` ciphertext plus 16-byte tag).
    /// Returns `(ignore_bit, contents)` or `None` on authentication failure.
    pub fn decrypt_packet(
        &mut self,
        aead_ciphertext: &[u8],
        aad: &[u8],
    ) -> Option<(bool, Vec<u8>)> {
        let plaintext = self.recv_p.decrypt(aad, aead_ciphertext)?;
        if plaintext.is_empty() {
            return None;
        }
        let ignore = plaintext[0] & IGNORE_BIT != 0;
        Some((ignore, plaintext[HEADER_LEN..].to_vec()))
    }

    /// Split the bidirectional session into independent send and receive halves
    /// so the peer's write task and read task can each own their cipher state
    /// (the FSChaCha streams are per-direction, so no sharing is needed).
    pub fn into_halves(self) -> (V2Sender, V2Receiver) {
        (
            V2Sender {
                l: self.send_l,
                p: self.send_p,
            },
            V2Receiver {
                l: self.recv_l,
                p: self.recv_p,
            },
        )
    }
}

/// The send half of an established V2 session (length cipher + payload AEAD).
/// Owned by the peer write task.
pub struct V2Sender {
    l: FsChaCha20,
    p: FsChaCha20Poly1305,
}

impl V2Sender {
    /// Encrypt one packet: `enc_length(3) || AEAD(header || contents)`. Uses
    /// empty AAD — the garbage-authenticating AAD only applies to the first
    /// post-handshake packet, which is consumed during the handshake itself.
    pub fn encrypt_packet(&mut self, contents: &[u8]) -> Vec<u8> {
        let mut plaintext = Vec::with_capacity(HEADER_LEN + contents.len());
        plaintext.push(0x00); // header byte, ignore bit clear
        plaintext.extend_from_slice(contents);
        let aead_ciphertext = self.p.encrypt(&[], &plaintext);
        let len_bytes = (contents.len() as u32).to_le_bytes();
        let enc_len = self.l.crypt(&len_bytes[..LENGTH_FIELD_LEN]);
        let mut out = Vec::with_capacity(LENGTH_FIELD_LEN + aead_ciphertext.len());
        out.extend_from_slice(&enc_len);
        out.extend_from_slice(&aead_ciphertext);
        out
    }
}

/// The receive half of an established V2 session. Owned by the peer read task.
pub struct V2Receiver {
    l: FsChaCha20,
    p: FsChaCha20Poly1305,
}

impl V2Receiver {
    /// Decrypt the 3-byte length prefix, returning the contents length. The
    /// remaining bytes to read for this packet are
    /// `contents_len + HEADER_LEN + AEAD_TAG_LEN`.
    pub fn decrypt_len(&mut self, enc_len: &[u8; LENGTH_FIELD_LEN]) -> usize {
        let dec = self.l.crypt(enc_len);
        (dec[0] as usize) | ((dec[1] as usize) << 8) | ((dec[2] as usize) << 16)
    }

    /// Decrypt a packet body (AEAD ciphertext of `header || contents` + tag),
    /// returning `(ignore_bit, contents)` or `None` on auth failure. Empty AAD
    /// (see [`V2Sender::encrypt_packet`]).
    pub fn decrypt_packet(&mut self, aead_ciphertext: &[u8]) -> Option<(bool, Vec<u8>)> {
        let plaintext = self.p.decrypt(&[], aead_ciphertext)?;
        if plaintext.is_empty() {
            return None;
        }
        let ignore = plaintext[0] & IGNORE_BIT != 0;
        Some((ignore, plaintext[HEADER_LEN..].to_vec()))
    }
}

/// Perform BIP 324-compatible ECDH using ElligatorSwift encoding.
/// `our_es` is our ElligatorSwift-encoded public key, `peer_es_bytes` is the peer's.
/// `initiator` should be true if we initiated the connection.
/// Returns the 32-byte BIP 324 shared secret.
pub fn ecdh_shared_secret(
    our_secret: &SecretKey,
    our_es_bytes: &[u8; 64],
    peer_es_bytes: &[u8; 64],
    initiator: bool,
) -> Option<[u8; 32]> {
    let our_es = ElligatorSwift::from_array(*our_es_bytes);
    let peer_es = ElligatorSwift::from_array(*peer_es_bytes);

    let (ell_a, ell_b, party) = if initiator {
        (our_es, peer_es, ElligatorSwiftParty::A)
    } else {
        (peer_es, our_es, ElligatorSwiftParty::B)
    };

    let shared = ElligatorSwift::shared_secret(ell_a, ell_b, *our_secret, party, None);
    Some(shared.to_secret_bytes())
}

/// A decrypted BIP 324 packet at the message layer.
///
/// The record layer (encrypt/decrypt) deals in raw `contents`; this type
/// encodes/decodes the message-type framing inside the contents:
/// `[1-byte short ID | 0x00 + 12-byte command][payload]`.
#[derive(Debug, Clone)]
pub struct V2Packet {
    /// Whether the receiver may ignore this message (decoy bit, carried in the
    /// record-layer header).
    pub ignore: bool,
    /// The message type (short ID or 12-byte command).
    pub msg_type: V2MessageType,
    /// The decrypted payload.
    pub payload: Vec<u8>,
}

/// Message type in a V2 packet — either a short 1-byte ID or a full 12-byte command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum V2MessageType {
    /// Short message ID (1 byte).
    Short(u8),
    /// Full command string (for messages without a short ID).
    Full(String),
}

impl V2Packet {
    /// Encode this packet's contents (message type + payload). This is the
    /// `contents` input to [`V2SessionKeys::encrypt_packet`]; the record layer
    /// adds the 1-byte header (with the ignore bit) itself.
    pub fn encode_contents(&self) -> Vec<u8> {
        let mut contents = Vec::with_capacity(1 + self.payload.len());

        match &self.msg_type {
            V2MessageType::Short(id) => {
                contents.push(*id);
            }
            V2MessageType::Full(cmd) => {
                contents.push(0x00); // Short ID 0 means "full command follows"
                let mut cmd_bytes = [0u8; 12];
                let cmd_b = cmd.as_bytes();
                let len = cmd_b.len().min(12);
                cmd_bytes[..len].copy_from_slice(&cmd_b[..len]);
                contents.extend_from_slice(&cmd_bytes);
            }
        }

        contents.extend_from_slice(&self.payload);
        contents
    }

    /// Decode packet contents (after record-layer decryption). `ignore` is the
    /// decoy bit returned by [`V2SessionKeys::decrypt_packet`].
    pub fn decode_contents(data: &[u8], ignore: bool) -> Option<Self> {
        if data.is_empty() {
            return None;
        }

        let type_byte = data[0];

        let (msg_type, payload_start) = if type_byte == 0x00 {
            // Full command
            if data.len() < 13 {
                return None;
            }
            let cmd_bytes = &data[1..13];
            let cmd_end = cmd_bytes.iter().position(|&b| b == 0).unwrap_or(12);
            let cmd = String::from_utf8_lossy(&cmd_bytes[..cmd_end]).to_string();
            (V2MessageType::Full(cmd), 13)
        } else {
            (V2MessageType::Short(type_byte), 1)
        };

        Some(V2Packet {
            ignore,
            msg_type,
            payload: data[payload_start..].to_vec(),
        })
    }
}

/// V2 transport session managing encryption state for a single peer connection.
pub struct V2Transport {
    pub state: V2State,
    pub keys: Option<V2SessionKeys>,
    pub is_initiator: bool,
    pub our_key_material: V2KeyMaterial,
    pub garbage: Vec<u8>,
    /// 4-byte P2P network magic mixed into the key-derivation salt.
    pub network_magic: [u8; 4],
}

impl V2Transport {
    /// Create a new V2 transport as initiator.
    pub fn new_initiator(network_magic: [u8; 4]) -> Self {
        V2Transport {
            state: V2State::AwaitingKeys,
            keys: None,
            is_initiator: true,
            our_key_material: V2KeyMaterial::generate(),
            garbage: Vec::new(),
            network_magic,
        }
    }

    /// Create a new V2 transport as responder.
    pub fn new_responder(network_magic: [u8; 4]) -> Self {
        V2Transport {
            state: V2State::AwaitingKeys,
            keys: None,
            is_initiator: false,
            our_key_material: V2KeyMaterial::generate(),
            garbage: Vec::new(),
            network_magic,
        }
    }

    /// Get the 64-byte public key to send to the peer.
    pub fn our_pubkey(&self) -> &[u8; 64] {
        &self.our_key_material.elligatorsw_pubkey
    }

    /// Process the peer's 64-byte ElligatorSwift public key and derive session keys.
    pub fn process_peer_pubkey(&mut self, peer_pubkey: &[u8; 64]) -> bool {
        let shared = match ecdh_shared_secret(
            &self.our_key_material.secret_key,
            &self.our_key_material.elligatorsw_pubkey,
            peer_pubkey,
            self.is_initiator,
        ) {
            Some(s) => s,
            None => return false,
        };

        self.keys = Some(V2SessionKeys::derive(
            &shared,
            &self.network_magic,
            self.is_initiator,
        ));
        self.state = V2State::AwaitingVersion;
        true
    }

    /// Process the peer's 64-byte ElligatorSwift key and take ownership of the
    /// derived session keys (consuming them from the transport). Returns `None`
    /// if the ECDH/key derivation failed.
    pub fn take_keys(&mut self, peer_pubkey: &[u8; 64]) -> Option<V2SessionKeys> {
        if !self.process_peer_pubkey(peer_pubkey) {
            return None;
        }
        self.keys.take()
    }

    /// Mark the transport as fully established (after version exchange).
    pub fn set_established(&mut self) {
        self.state = V2State::Established;
    }

    /// Fall back to V1 transport.
    pub fn set_fallback_v1(&mut self) {
        self.state = V2State::FallbackV1;
    }

    /// Get the session ID (for optional authentication comparison).
    pub fn session_id(&self) -> Option<&[u8; 32]> {
        self.keys.as_ref().map(|k| &k.session_id)
    }
}

impl fmt::Debug for V2Transport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("V2Transport")
            .field("state", &self.state)
            .field("is_initiator", &self.is_initiator)
            .field("has_keys", &self.keys.is_some())
            .finish()
    }
}

// --- Crypto helpers ---

/// HKDF-Extract using HMAC-SHA256.
fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> [u8; 32] {
    let mut engine = HmacEngine::<sha256::Hash>::new(salt);
    engine.input(ikm);
    Hmac::<sha256::Hash>::from_engine(engine).to_byte_array()
}

/// HKDF-Expand using HMAC-SHA256 (single block, 32 bytes output).
fn hkdf_expand(prk: &[u8; 32], info: &[u8]) -> [u8; 32] {
    let mut engine = HmacEngine::<sha256::Hash>::new(prk);
    engine.input(info);
    engine.input(&[0x01]); // counter byte
    Hmac::<sha256::Hash>::from_engine(engine).to_byte_array()
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    /// Mainnet network magic, used by the official BIP 324 test vectors.
    const MAINNET_MAGIC: [u8; 4] = [0xf9, 0xbe, 0xb4, 0xd9];

    #[test]
    fn test_short_msg_id_roundtrip() {
        // The full BIP 324 table (IDs 1..=28), in order. The numeric value must
        // equal the BIP-assigned ID and round-trip through command strings.
        let table = [
            (1u8, "addr"),
            (2, "block"),
            (3, "blocktxn"),
            (4, "cmpctblock"),
            (5, "feefilter"),
            (6, "filteradd"),
            (7, "filterclear"),
            (8, "filterload"),
            (9, "getblocks"),
            (10, "getblocktxn"),
            (11, "getdata"),
            (12, "getheaders"),
            (13, "headers"),
            (14, "inv"),
            (15, "mempool"),
            (16, "merkleblock"),
            (17, "notfound"),
            (18, "ping"),
            (19, "pong"),
            (20, "sendcmpct"),
            (21, "tx"),
            (22, "getcfilters"),
            (23, "cfilter"),
            (24, "getcfheaders"),
            (25, "cfheaders"),
            (26, "getcfcheckpt"),
            (27, "cfcheckpt"),
            (28, "addrv2"),
        ];

        for (id, cmd) in &table {
            let parsed = ShortMsgId::from_command(cmd).expect(cmd);
            assert_eq!(parsed as u8, *id, "wrong id for {cmd}");
            assert_eq!(parsed.to_command(), *cmd);
            assert_eq!(ShortMsgId::from_u8(*id), Some(parsed));
        }
    }

    #[test]
    fn test_short_msg_id_unknown() {
        // Messages without a short ID fall through to the full-command encoding.
        assert!(ShortMsgId::from_command("sendheaders").is_none());
        assert!(ShortMsgId::from_command("version").is_none());
        assert!(ShortMsgId::from_command("verack").is_none());
        assert!(ShortMsgId::from_command("").is_none());
        assert!(ShortMsgId::from_u8(0).is_none());
        assert!(ShortMsgId::from_u8(29).is_none());
    }

    #[test]
    fn test_v2_packet_encode_decode_short() {
        let packet = V2Packet {
            ignore: false,
            msg_type: V2MessageType::Short(ShortMsgId::Ping as u8),
            payload: vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08],
        };

        let encoded = packet.encode_contents();
        let decoded = V2Packet::decode_contents(&encoded, false).unwrap();

        assert!(!decoded.ignore);
        assert_eq!(
            decoded.msg_type,
            V2MessageType::Short(ShortMsgId::Ping as u8)
        );
        assert_eq!(
            decoded.payload,
            vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]
        );
    }

    #[test]
    fn test_v2_packet_encode_decode_full_command() {
        let packet = V2Packet {
            ignore: true,
            msg_type: V2MessageType::Full("customcmd".to_string()),
            payload: vec![42],
        };

        let encoded = packet.encode_contents();
        let decoded = V2Packet::decode_contents(&encoded, true).unwrap();

        assert!(decoded.ignore);
        assert_eq!(
            decoded.msg_type,
            V2MessageType::Full("customcmd".to_string())
        );
        assert_eq!(decoded.payload, vec![42]);
    }

    #[test]
    fn test_v2_key_material_generation() {
        let km = V2KeyMaterial::generate();
        assert_eq!(km.elligatorsw_pubkey.len(), 64);
        // Key should not be all zeros
        assert!(km.elligatorsw_pubkey.iter().any(|&b| b != 0));
    }

    // --- RFC 8439 primitive sanity checks ---

    #[test]
    fn test_rfc8439_chacha20_block() {
        // RFC 8439 §2.3.2 test vector.
        let key: [u8; 32] = (0u8..32).collect::<Vec<u8>>().try_into().unwrap();
        let nonce: [u8; 12] = hex::decode("000000090000004a00000000")
            .unwrap()
            .try_into()
            .unwrap();
        let block = chacha20_block(&key, &nonce, 1);
        assert_eq!(
            hex::encode(block),
            "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4e\
             d2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e"
        );
    }

    #[test]
    fn test_rfc8439_poly1305() {
        // RFC 8439 §2.5.2 test vector.
        let key: [u8; 32] =
            hex::decode("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b")
                .unwrap()
                .try_into()
                .unwrap();
        let msg = b"Cryptographic Forum Research Group";
        let tag = poly1305_mac(&key, msg);
        assert_eq!(hex::encode(tag), "a8061dc1305136c6c22b8baf0c0127a9");
    }

    #[test]
    fn test_aead_roundtrip_and_auth_failure() {
        let key = [7u8; 32];
        let nonce = [9u8; 12];
        let aad = b"aad bytes";
        let pt = b"hello bip324";
        let ct = aead_chacha20_poly1305_encrypt(&key, &nonce, aad, pt);
        assert_eq!(ct.len(), pt.len() + AEAD_TAG_LEN);
        let back = aead_chacha20_poly1305_decrypt(&key, &nonce, aad, &ct).unwrap();
        assert_eq!(back, pt);

        // Tampered ciphertext must fail.
        let mut bad = ct.clone();
        bad[0] ^= 1;
        assert!(aead_chacha20_poly1305_decrypt(&key, &nonce, aad, &bad).is_none());
        // Wrong AAD must fail.
        assert!(aead_chacha20_poly1305_decrypt(&key, &nonce, b"other", &ct).is_none());
    }

    // --- Official BIP 324 packet-encoding vectors ---

    /// Run all rows of the official BIP 324 packet encoding test vectors
    /// (bip-0324/packet_encoding_test_vectors.csv from the bips repository).
    /// Rows cover message indices 0, 1, 223 (rekey boundary), 448, 673, 999
    /// and 1024, including decoy (ignore) packets and large AAD.
    #[test]
    fn test_bip324_packet_encoding_vectors() {
        let csv = include_str!("../tests/data/bip324_packet_encoding_test_vectors.csv");
        let mut lines = csv.lines().map(|l| l.trim_end_matches('\r'));
        let header = lines.next().unwrap();
        assert!(header.starts_with("in_idx,"));

        let mut rows = 0;
        for line in lines {
            if line.is_empty() {
                continue;
            }
            let f: Vec<&str> = line.split(',').collect();
            assert_eq!(f.len(), 22, "unexpected CSV column count");

            let in_idx: u64 = f[0].parse().unwrap();
            let priv_ours: [u8; 32] = hex::decode(f[1]).unwrap().try_into().unwrap();
            let ellswift_ours: [u8; 64] = hex::decode(f[2]).unwrap().try_into().unwrap();
            let ellswift_theirs: [u8; 64] = hex::decode(f[3]).unwrap().try_into().unwrap();
            let initiating = f[4] == "1";
            let in_contents = hex::decode(f[5]).unwrap();
            let multiply: usize = f[6].parse().unwrap();
            let aad = hex::decode(f[7]).unwrap();
            let ignore = f[8] == "1";
            let mid_shared_secret = f[12];
            let mid_initiator_l = f[13];
            let mid_initiator_p = f[14];
            let mid_responder_l = f[15];
            let mid_responder_p = f[16];
            let mid_send_garbage_terminator = f[17];
            let mid_recv_garbage_terminator = f[18];
            let out_session_id = f[19];
            let out_ciphertext = f[20];
            let out_ciphertext_endswith = f[21];

            // ECDH through the production handshake code path.
            let secret = SecretKey::from_slice(&priv_ours).unwrap();
            let shared =
                ecdh_shared_secret(&secret, &ellswift_ours, &ellswift_theirs, initiating).unwrap();
            assert_eq!(
                hex::encode(shared),
                mid_shared_secret,
                "idx {in_idx}: shared secret"
            );

            // Raw HKDF outputs (validates salt + labels).
            let dk = derive_keys(&shared, &MAINNET_MAGIC);
            assert_eq!(
                hex::encode(dk.initiator_l),
                mid_initiator_l,
                "idx {in_idx}: initiator_L"
            );
            assert_eq!(
                hex::encode(dk.initiator_p),
                mid_initiator_p,
                "idx {in_idx}: initiator_P"
            );
            assert_eq!(
                hex::encode(dk.responder_l),
                mid_responder_l,
                "idx {in_idx}: responder_L"
            );
            assert_eq!(
                hex::encode(dk.responder_p),
                mid_responder_p,
                "idx {in_idx}: responder_P"
            );
            assert_eq!(
                hex::encode(dk.session_id),
                out_session_id,
                "idx {in_idx}: session_id"
            );

            // Directional session state through the production derivation.
            let mut keys = V2SessionKeys::derive(&shared, &MAINNET_MAGIC, initiating);
            assert_eq!(
                hex::encode(keys.send_garbage_terminator),
                mid_send_garbage_terminator,
                "idx {in_idx}: send garbage terminator"
            );
            assert_eq!(
                hex::encode(keys.recv_garbage_terminator),
                mid_recv_garbage_terminator,
                "idx {in_idx}: recv garbage terminator"
            );

            // Fast-forward: encrypt `in_idx` empty packets (the reference
            // generator does v2_enc_packet(peer, b"") in a loop).
            for _ in 0..in_idx {
                keys.encrypt_packet(b"", b"", false);
            }
            assert_eq!(keys.send_p.packet_counter(), in_idx);

            let mut contents = Vec::with_capacity(in_contents.len() * multiply);
            for _ in 0..multiply {
                contents.extend_from_slice(&in_contents);
            }

            let ciphertext = keys.encrypt_packet(&contents, &aad, ignore);
            assert_eq!(
                ciphertext.len(),
                LENGTH_FIELD_LEN + HEADER_LEN + contents.len() + AEAD_TAG_LEN
            );
            if !out_ciphertext.is_empty() {
                assert_eq!(
                    hex::encode(&ciphertext),
                    out_ciphertext,
                    "idx {in_idx}: ciphertext"
                );
            } else {
                let tail = hex::decode(out_ciphertext_endswith).unwrap();
                assert!(
                    ciphertext.ends_with(&tail),
                    "idx {in_idx}: ciphertext tail mismatch"
                );
            }

            // Decoy/normal packets alike must have advanced the counter.
            assert_eq!(keys.send_p.packet_counter(), in_idx + 1);

            rows += 1;
        }
        assert_eq!(rows, 7, "expected 7 vector rows");
    }

    #[test]
    fn test_v2_session_key_derivation() {
        let km_init = V2KeyMaterial::generate();
        let km_resp = V2KeyMaterial::generate();

        // Simulate ECDH using BIP 324 ElligatorSwift
        let shared_init = ecdh_shared_secret(
            &km_init.secret_key,
            &km_init.elligatorsw_pubkey,
            &km_resp.elligatorsw_pubkey,
            true,
        );
        let shared_resp = ecdh_shared_secret(
            &km_resp.secret_key,
            &km_resp.elligatorsw_pubkey,
            &km_init.elligatorsw_pubkey,
            false,
        );

        assert!(shared_init.is_some());
        assert!(shared_resp.is_some());

        let shared_init = shared_init.unwrap();
        let shared_resp = shared_resp.unwrap();

        // Both sides should derive the same shared secret
        assert_eq!(shared_init, shared_resp);

        // Derive session keys
        let keys_init = V2SessionKeys::derive(&shared_init, &MAINNET_MAGIC, true);
        let keys_resp = V2SessionKeys::derive(&shared_resp, &MAINNET_MAGIC, false);

        // Session IDs should match
        assert_eq!(keys_init.session_id, keys_resp.session_id);

        // Initiator's send cipher keys = Responder's recv cipher keys
        assert_eq!(
            keys_init.send_p.current_key(),
            keys_resp.recv_p.current_key()
        );
        assert_eq!(
            keys_init.recv_p.current_key(),
            keys_resp.send_p.current_key()
        );
        assert_eq!(
            keys_init.send_l.current_key(),
            keys_resp.recv_l.current_key()
        );
        assert_eq!(
            keys_init.recv_l.current_key(),
            keys_resp.send_l.current_key()
        );

        // Garbage terminators cross over.
        assert_eq!(
            keys_init.send_garbage_terminator,
            keys_resp.recv_garbage_terminator
        );
        assert_eq!(
            keys_init.recv_garbage_terminator,
            keys_resp.send_garbage_terminator
        );

        // Network binding: a different magic yields different keys.
        let keys_testnet = V2SessionKeys::derive(&shared_init, &[0x0b, 0x11, 0x09, 0x07], true);
        assert_ne!(keys_init.session_id, keys_testnet.session_id);
    }

    #[test]
    fn test_v2_transport_handshake() {
        let mut initiator = V2Transport::new_initiator(MAINNET_MAGIC);
        let mut responder = V2Transport::new_responder(MAINNET_MAGIC);

        assert_eq!(initiator.state, V2State::AwaitingKeys);
        assert_eq!(responder.state, V2State::AwaitingKeys);

        // Exchange public keys
        let init_pk = *initiator.our_pubkey();
        let resp_pk = *responder.our_pubkey();

        assert!(initiator.process_peer_pubkey(&resp_pk));
        assert!(responder.process_peer_pubkey(&init_pk));

        assert_eq!(initiator.state, V2State::AwaitingVersion);
        assert_eq!(responder.state, V2State::AwaitingVersion);

        // Session IDs should match
        assert_eq!(initiator.session_id(), responder.session_id());

        // Mark established
        initiator.set_established();
        responder.set_established();

        assert_eq!(initiator.state, V2State::Established);
        assert_eq!(responder.state, V2State::Established);
    }

    /// Symmetric loopback across rekey boundaries: both directions exchange
    /// >500 packets (crossing the 224 and 448 rekey boundaries), including
    /// > decoy packets which must advance the counters on both sides.
    #[test]
    fn test_v2_loopback_across_rekeys() {
        let mut initiator = V2Transport::new_initiator(MAINNET_MAGIC);
        let mut responder = V2Transport::new_responder(MAINNET_MAGIC);
        let init_pk = *initiator.our_pubkey();
        let resp_pk = *responder.our_pubkey();
        assert!(initiator.process_peer_pubkey(&resp_pk));
        assert!(responder.process_peer_pubkey(&init_pk));

        let mut ikeys = initiator.keys.clone().unwrap();
        let mut rkeys = responder.keys.clone().unwrap();

        const N: u64 = 600; // crosses rekeys at 224 and 448

        for i in 0..N {
            // Vary contents; every 50th packet is a decoy.
            let decoy = i % 50 == 7;
            let contents: Vec<u8> = (0..(i % 97) as u8).map(|b| b ^ (i as u8)).collect();
            let aad: &[u8] = if i == 0 { b"first-packet-aad" } else { b"" };

            // initiator -> responder
            let wire = ikeys.encrypt_packet(&contents, aad, decoy);
            let enc_len: [u8; 3] = wire[..3].try_into().unwrap();
            let clen = rkeys.decrypt_packet_len(&enc_len);
            assert_eq!(clen, contents.len(), "i->r length at packet {i}");
            assert_eq!(wire.len(), 3 + HEADER_LEN + clen + AEAD_TAG_LEN);
            let (ignore, got) = rkeys.decrypt_packet(&wire[3..], aad).unwrap();
            assert_eq!(ignore, decoy, "i->r ignore bit at packet {i}");
            assert_eq!(got, contents, "i->r contents at packet {i}");

            // responder -> initiator (different contents)
            let contents2: Vec<u8> = (0..((i * 3) % 113) as u8)
                .map(|b| b.wrapping_add(i as u8))
                .collect();
            let wire2 = rkeys.encrypt_packet(&contents2, b"", decoy);
            let enc_len2: [u8; 3] = wire2[..3].try_into().unwrap();
            let clen2 = ikeys.decrypt_packet_len(&enc_len2);
            assert_eq!(clen2, contents2.len(), "r->i length at packet {i}");
            let (ignore2, got2) = ikeys.decrypt_packet(&wire2[3..], b"").unwrap();
            assert_eq!(ignore2, decoy, "r->i ignore bit at packet {i}");
            assert_eq!(got2, contents2, "r->i contents at packet {i}");
        }

        // Counters advanced for every packet including decoys.
        assert_eq!(ikeys.send_p.packet_counter(), N);
        assert_eq!(rkeys.recv_p.packet_counter(), N);
        // Keys have been rotated away from their initial values (forward secrecy).
        let fresh = V2SessionKeys::derive(
            &ecdh_shared_secret(
                &initiator.our_key_material.secret_key,
                &initiator.our_key_material.elligatorsw_pubkey,
                &resp_pk,
                true,
            )
            .unwrap(),
            &MAINNET_MAGIC,
            true,
        );
        assert_ne!(ikeys.send_p.current_key(), fresh.send_p.current_key());
        assert_ne!(ikeys.send_l.current_key(), fresh.send_l.current_key());
    }

    /// A wrong AAD or tampered bytes must fail decryption at the record layer.
    #[test]
    fn test_v2_packet_auth_failure() {
        let shared = [0x42u8; 32];
        let mut a = V2SessionKeys::derive(&shared, &MAINNET_MAGIC, true);
        let mut b = V2SessionKeys::derive(&shared, &MAINNET_MAGIC, false);

        let wire = a.encrypt_packet(b"payload", b"the-aad", false);
        let mut tampered = wire.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 0x01;
        assert!(b.decrypt_packet(&tampered[3..], b"the-aad").is_none());
        // Counter advanced despite failure; a fresh responder with the correct
        // AAD and untampered bytes decrypts at counter 0.
        let mut b2 = V2SessionKeys::derive(&shared, &MAINNET_MAGIC, false);
        assert!(b2.decrypt_packet(&wire[3..], b"wrong-aad").is_none());
        let mut b3 = V2SessionKeys::derive(&shared, &MAINNET_MAGIC, false);
        let (ignore, contents) = b3.decrypt_packet(&wire[3..], b"the-aad").unwrap();
        assert!(!ignore);
        assert_eq!(contents, b"payload");
    }

    #[test]
    fn test_hkdf_deterministic() {
        let prk = hkdf_extract(b"salt", b"input_key_material");
        let prk2 = hkdf_extract(b"salt", b"input_key_material");
        assert_eq!(prk, prk2);

        let derived = hkdf_expand(&prk, b"info");
        let derived2 = hkdf_expand(&prk, b"info");
        assert_eq!(derived, derived2);

        // Different info should produce different keys
        let derived3 = hkdf_expand(&prk, b"other_info");
        assert_ne!(derived, derived3);
    }
}
