src/crypto/chunked_amount.rs:
// Copyright © Move Industries
// SPDX-License-Identifier: Apache-2.0
/// Number of bits per chunk.
pub const CHUNK_BITS: u32 = 64;
/// Number of chunks for an available balance.
pub const AVAILABLE_BALANCE_CHUNK_COUNT: usize = 4;
/// Number of chunks for a transfer amount.
pub const TRANSFER_AMOUNT_CHUNK_COUNT: usize = 8;
/// Maximum plaintext value for a confidential transfer.
/// Each chunk is 64 bits, transfer amount has 8 chunks.
/// Total: 64 * 8 = 512 bits.
pub const MAX_CONFIDENTIAL_TRANSFER_PLAINTEXT: u128 = (1u128 << 256) - 1; // 2^256 - 1 (4 chunks * 64 bits for balance)
/// ChunkedAmount splits a big amount into fixed-size (64-bit) chunks.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChunkedAmount {
    /// The chunks, each representing a 64-bit portion of the amount.
    chunks: Vec<u64>,
}
impl ChunkedAmount {
/// Create a ChunkedAmount from a raw amount, splitting into chunk_count 64-bit chunks.
    pub fn from_amount_with_chunks(amount: u128, chunk_count: usize) -> Self {
        let mut chunks = Vec::with_capacity(chunk_count);
        let mut remaining = amount;
        for _ in 0..chunk_count {
            let chunk = (remaining & ((1u128 << 64) - 1)) as u64;
            chunks.push(chunk);
            remaining >>= 64;
        }
        Self { chunks }
    }
    /// Create a ChunkedAmount for a balance (4 chunks).
    pub fn from_amount(amount: u128) -> Self {
        Self::from_amount_with_chunks(amount, AVAILABLE_BALANCE_CHUNK_COUNT)
    }
    /// Create a ChunkedAmount for a transfer amount (8 chunks).
    pub fn from_transfer_amount(amount: u128) -> Self {
        Self::from_amount_with_chunks(amount, TRANSFER_AMOUNT_CHUNK_COUNT)
    }
    /// Create from pre-split chunks.
    pub fn from_chunks(chunks: Vec<u64>) -> Self {
        Self { chunks }
    }
    /// Create from a list of bigint chunks (matching TS API which uses bigint).
    pub fn from_bigint_chunks(chunks: Vec<curve25519_dalek::scalar::Scalar>) -> Self {
        // Each Scalar chunk represents a u64 value
        let u64_chunks: Vec<u64> = chunks.iter().map(|s| {
            let bytes = s.to_bytes();
            u64::from_le_bytes(bytes[0..8].try_into().unwrap())
        }).collect();
        Self { chunks: u64_chunks }
    }
    /// Get the chunks.
    pub fn chunks(&self) -> &[u64] {
        &self.chunks
    }
    /// Get the number of chunks.
    pub fn len(&self) -> usize {
        self.chunks.len()
    }
    /// Check if empty.
    pub fn is_empty(&self) -> bool {
        self.chunks.is_empty()
    }
    /// Reconstruct the full amount from chunks.
    /// Note: this only works correctly if the amount fits in 128 bits (2 chunks).
    /// For larger amounts, use individual chunk access.
    pub fn to_amount(&self) -> u128 {
        let mut result: u128 = 0;
        for (i, &chunk) in self.chunks.iter().enumerate() {
            if i >= 2 {
                break; // u128 can only hold 2 * 64 bits
            }
            result |= (chunk as u128) << (i * 64);
        }
        result
    }
    /// Convert chunks to Scalars for cryptographic operations.
    pub fn to_scalars(&self) -> Vec<curve25519_dalek::scalar::Scalar> {
        use curve25519_dalek::scalar::Scalar;
        self.chunks.iter().map(|&v| Scalar::from(v)).collect()
    }
}
/// Extension: create ChunkedAmount from big bigint chunks (for normalization tests).
impl ChunkedAmount {
    /// Create from raw u64 chunks, matching TS ChunkedAmount.fromChunks([...]).
    pub fn from_raw_chunks(chunks: Vec<u64>) -> Self {
        Self { chunks }
    }
}

