// Copyright © Move Industries
// SPDX-License-Identifier: Apache-2.0
use crate::crypto::chunked_amount::{
    ChunkedAmount, AVAILABLE_BALANCE_CHUNK_COUNT, TRANSFER_AMOUNT_CHUNK_COUNT,
};
use crate::crypto::twisted_ed25519::{TwistedEd25519PrivateKey, TwistedEd25519PublicKey};
use crate::crypto::twisted_el_gamal::{TwistedElGamal, TwistedElGamalCiphertext};
use crate::utils::ed25519_gen_random;
use curve25519_dalek::scalar::Scalar;
/// Encrypted amount: holds chunked ciphertexts and can decrypt to get the amount.
#[derive(Clone, Debug)]
pub struct EncryptedAmount {
    chunked_amount: ChunkedAmount,
    ciphertext: Vec<TwistedElGamalCiphertext>,
    public_key: TwistedEd25519PublicKey,
    /// Randomness used per chunk (needed for proof generation).
    randomness: Vec<Scalar>,
}
impl EncryptedAmount {
    /// Create a new encrypted amount from a chunked amount and public key.
    pub fn new(chunked_amount: ChunkedAmount, public_key: TwistedEd25519PublicKey) -> Self {
        let randomness: Vec<Scalar> = (0..chunked_amount.len())
            .map(|_| ed25519_gen_random())
            .collect();
        let scalars = chunked_amount.to_scalars();
        let ciphertext: Vec<TwistedElGamalCiphertext> = scalars
            .iter()
            .zip(randomness.iter())
            .map(|(v, r)| TwistedElGamal::encrypt_chunk(*v, &public_key, *r))
            .collect();
        Self {
            chunked_amount,
            ciphertext,
            public_key,
            randomness,
        }
    }
    /// Create from amount and public key (for balance, 4 chunks).
    pub fn from_amount_and_public_key(amount: u128, public_key: &TwistedEd25519PublicKey) -> Self {
        let chunked = ChunkedAmount::from_amount(amount);
        Self::new(chunked, public_key.clone())
    }
    /// Create from ciphertext and private key (decrypt).
    /// This performs DLOG to recover the amount.
    /// Note: Full DLOG requires kangaroo tables. For testing with known amounts,
    /// use from_amount_and_public_key instead.
    pub fn from_ciphertext_and_private_key(
        ciphertext: &[TwistedElGamalCiphertext],
        private_key: &TwistedEd25519PrivateKey,
    ) -> Result<Self, String> {
        // For each chunk, we need to solve DLOG(v*H) to recover v.
        // This is where the Pollard kangaroo algorithm is needed.
        // For now, this requires a separate implementation.
        Err("DLOG decryption requires kangaroo table implementation. Use from_amount_and_public_key for testing.".to_string())
    }
    /// Get the decrypted amount (only works if chunked_amount is already known).
    pub fn get_amount(&self) -> u128 {
        self.chunked_amount.to_amount()
    }
    /// Get the ciphertext.
    pub fn get_ciphertext(&self) -> &[TwistedElGamalCiphertext] {
        &self.ciphertext
    }
    /// Get the ciphertext bytes (all chunks concatenated).
    pub fn get_ciphertext_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for ct in &self.ciphertext {
            out.extend_from_slice(&ct.to_bytes());
        }
        out
    }
    /// Get the chunked amount.
    pub fn chunked_amount(&self) -> &ChunkedAmount {
        &self.chunked_amount
    }
    /// Get the randomness used for encryption.
    pub fn randomness(&self) -> &[Scalar] {
        &self.randomness
    }
    /// Get the public key.
    pub fn public_key(&self) -> &TwistedEd25519PublicKey {
        &self.public_key
    }
}
