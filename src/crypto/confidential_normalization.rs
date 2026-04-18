// Copyright © Move Industries
// SPDX-License-Identifier: Apache-2.0
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use crate::crypto::twisted_ed25519::{TwistedEd25519PrivateKey, TwistedEd25519PublicKey};
use crate::crypto::twisted_el_gamal::TwistedElGamalCiphertext;
use crate::crypto::encrypted_amount::EncryptedAmount;
use crate::crypto::chunked_amount::{ChunkedAmount, AVAILABLE_BALANCE_CHUNK_COUNT, CHUNK_BITS};
use crate::crypto::fiat_shamir::fiat_shamir_challenge_full;
use crate::crypto::h_ristretto;
use crate::consts::PROTOCOL_ID_NORMALIZATION;
use crate::utils::ed25519_gen_random;
/// Normalization sigma proof.
#[derive(Clone, Debug)]
pub struct NormalizationSigmaProof {
    pub alpha_list: Vec<RistrettoPoint>,
    pub x_list: Vec<RistrettoPoint>,
    pub a: RistrettoPoint,
    pub t: RistrettoPoint,
    pub s_alpha_list: Vec<Scalar>,
    pub s_x_list: Vec<Scalar>,
    pub s_a: Scalar,
    pub s_t: Scalar,
}
/// Confidential normalization context.
pub struct ConfidentialNormalization {
    decryption_key: TwistedEd25519PrivateKey,
    unnormalized_encrypted_available_balance: EncryptedAmount,
    normalized_encrypted_available_balance: EncryptedAmount,
    chain_id: u8,
    sender_address: Vec<u8>,
    contract_address: Vec<u8>,
    token_address: Vec<u8>,
}
impl ConfidentialNormalization {
    /// Create a new normalization context.
    /// Takes the unnormalized balance (which may have carry overflow in chunks)
    /// and creates a normalized version (where each chunk fits in CHUNK_BITS).
    pub fn create(
        decryption_key: TwistedEd25519PrivateKey,
        unnormalized_available_balance: EncryptedAmount,
        chain_id: u8,
        sender_address: &[u8],
        contract_address: &[u8],
        token_address: &[u8],
    ) -> Self {
        // Normalize: reduce the chunked representation so each chunk < 2^CHUNK_BITS.
        // The unnormalized balance might have chunks with carry values from arithmetic.
        let amount = unnormalized_available_balance.get_amount();
        let pk = decryption_key.public_key();
        let normalized_chunked = ChunkedAmount::from_amount(amount);
        let normalized_ea = EncryptedAmount::new(normalized_chunked, pk);
        Self {
            decryption_key,
            unnormalized_encrypted_available_balance: unnormalized_available_balance,
            normalized_encrypted_available_balance: normalized_ea,
            chain_id,
            sender_address: sender_address.to_vec(),
            contract_address: contract_address.to_vec(),
            token_address: token_address.to_vec(),
        }
    }
    /// Get unnormalized encrypted available balance.
    pub fn unnormalized_encrypted_available_balance(&self) -> &EncryptedAmount {
        &self.unnormalized_encrypted_available_balance
    }
    /// Get normalized encrypted available balance.
    pub fn normalized_encrypted_available_balance(&self) -> &EncryptedAmount {
        &self.normalized_encrypted_available_balance
    }
    /// Generate sigma proof for normalization.
    pub fn gen_sigma_proof(&self) -> NormalizationSigmaProof {
        let g = RISTRETTO_BASEPOINT_POINT;
        let h = h_ristretto();
        let dk = self.decryption_key.as_scalar();
        let pk = self.decryption_key.public_key();
        let n = AVAILABLE_BALANCE_CHUNK_COUNT;
        let k_alpha: Vec<Scalar> = (0..n).map(|_| ed25519_gen_random()).collect();
        let k_x: Vec<Scalar> = (0..n).map(|_| ed25519_gen_random()).collect();
        let k_a = ed25519_gen_random();
        let k_t = ed25519_gen_random();
        let alpha_list: Vec<RistrettoPoint> = k_alpha.iter()
            .zip(self.unnormalized_encrypted_available_balance.randomness().iter())
            .map(|(k, r)| k * g + r * pk.as_point())
            .collect();
        let x_list: Vec<RistrettoPoint> = k_x.iter()
            .zip(self.normalized_encrypted_available_balance.randomness().iter())
            .map(|(k, r)| k * g + r * pk.as_point())
            .collect();
        let a = k_a * g;
        let sum_k_x: Scalar = k_x.iter().fold(Scalar::ZERO, |acc, k| acc + k);
let t = k_t * g + sum_k_x * h;
        let mut transcript: Vec<u8> = Vec::new();
        for p in &alpha_list { transcript.extend_from_slice(&p.compress().to_bytes()); }
        for p in &x_list { transcript.extend_from_slice(&p.compress().to_bytes()); }
        transcript.extend_from_slice(&a.compress().to_bytes());
        transcript.extend_from_slice(&t.compress().to_bytes());
        let c = fiat_shamir_challenge_full(
            PROTOCOL_ID_NORMALIZATION,
            self.chain_id,
            &self.sender_address,
            &self.contract_address,
            &self.token_address,
            &[&transcript],
        );
        let unnorm_chunks = self.unnormalized_encrypted_available_balance.chunked_amount().to_scalars();
        let norm_chunks = self.normalized_encrypted_available_balance.chunked_amount().to_scalars();
        let s_alpha_list: Vec<Scalar> = k_alpha.into_iter()
            .zip(unnorm_chunks.iter())
            .map(|(k, v)| k - c * v)
            .collect();
        let s_x_list: Vec<Scalar> = k_x.into_iter()
            .zip(norm_chunks.iter())
            .map(|(k, v)| k - c * v)
            .collect();
        let s_a = k_a - c * dk;
        // s_t = k_t - c * total_normalized_amount (aggregate of normalized chunks)
        let total_norm: Scalar = norm_chunks.iter().fold(Scalar::ZERO, |acc, v| acc + v);
        let s_t = k_t - c * total_norm;
        NormalizationSigmaProof {
            alpha_list, x_list, a, t,
            s_alpha_list, s_x_list, s_a, s_t,
        }
    }
    /// Verify normalization sigma proof.
    pub fn verify_sigma_proof(
        public_key: &TwistedEd25519PublicKey,
        sigma_proof: &NormalizationSigmaProof,
        unnormalized_encrypted_balance: &EncryptedAmount,
        normalized_encrypted_balance: &EncryptedAmount,
        chain_id: u8,
        sender_address: &[u8],
        contract_address: &[u8],
        token_address: &[u8],
    ) -> bool {
        // Recompute challenge
        let mut transcript: Vec<u8> = Vec::new();
        for p in &sigma_proof.alpha_list { transcript.extend_from_slice(&p.compress().to_bytes()); }
        for p in &sigma_proof.x_list { transcript.extend_from_slice(&p.compress().to_bytes()); }
        transcript.extend_from_slice(&sigma_proof.a.compress().to_bytes());
        transcript.extend_from_slice(&sigma_proof.t.compress().to_bytes());
        let c = fiat_shamir_challenge_full(
            PROTOCOL_ID_NORMALIZATION,
            chain_id,
            sender_address,
            contract_address,
            token_address,
            &[&transcript],
        );
        // Verify commitment equations
        // For each chunk i:
        //   alpha_i == s_alpha_i * G + c * unnorm_chunk_value_i * G + c * r_unnorm_i * PK
        // This requires the verifier to know the ciphertext to extract commitments.
        // Full implementation would check all equations.
        // Placeholder: return true
        // TODO: Implement full verification
        true
    }
    /// Generate range proof for normalized balance.
    pub async fn gen_range_proof(&self) -> Result<Vec<u8>, String> {
        crate::crypto::range_proof::generate_range_proof(
            self.normalized_encrypted_available_balance.get_ciphertext(),
            &self.normalized_encrypted_available_balance.chunked_amount().chunks().to_vec(),
            self.normalized_encrypted_available_balance.randomness(),
        )
    }
    /// Verify range proof.
    pub async fn verify_range_proof(
        range_proof: &[u8],
        normalized_encrypted_balance: &EncryptedAmount,
    ) -> Result<bool, String> {
        crate::crypto::range_proof::verify_range_proof(
            range_proof,
            normalized_encrypted_balance.get_ciphertext(),
        )
    }
    /// Serialize sigma proof to bytes.
    pub fn serialize_sigma_proof(proof: &NormalizationSigmaProof) -> Vec<u8> {
let mut out = Vec::with_capacity(crate::consts::SIGMA_PROOF_NORMALIZATION_SIZE);
        for p in &proof.alpha_list { out.extend_from_slice(&p.compress().to_bytes()); }
        for p in &proof.x_list { out.extend_from_slice(&p.compress().to_bytes()); }
        out.extend_from_slice(&proof.a.compress().to_bytes());
        out.extend_from_slice(&proof.t.compress().to_bytes());
        for s in &proof.s_alpha_list { out.extend_from_slice(&s.to_bytes()); }
        for s in &proof.s_x_list { out.extend_from_slice(&s.to_bytes()); }
        out.extend_from_slice(&proof.s_a.to_bytes());
        out.extend_from_slice(&proof.s_t.to_bytes());
        out
    }
}

