// Copyright © Move Industries
// SPDX-License-Identifier: Apache-2.0
use crate::consts::PROTOCOL_ID_ROTATION;
use crate::crypto::chunked_amount::ChunkedAmount;
use crate::crypto::encrypted_amount::EncryptedAmount;
use crate::crypto::fiat_shamir::fiat_shamir_challenge_full;
use crate::crypto::h_ristretto;
use crate::crypto::twisted_ed25519::{TwistedEd25519PrivateKey, TwistedEd25519PublicKey};
use crate::crypto::twisted_el_gamal::TwistedElGamalCiphertext;
use crate::utils::ed25519_gen_random;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
/// Key rotation sigma proof.
#[derive(Clone, Debug)]
pub struct KeyRotationSigmaProof {
    pub alpha_list: Vec<RistrettoPoint>,
    pub x_list: Vec<RistrettoPoint>,
    pub a: RistrettoPoint,
    pub b: RistrettoPoint,
    pub s_alpha_list: Vec<Scalar>,
    pub s_x_list: Vec<Scalar>,
    pub s_a: Scalar,
    pub s_b: Scalar,
}
/// Confidential key rotation context.
pub struct ConfidentialKeyRotation {
    sender_decryption_key: TwistedEd25519PrivateKey,
    new_sender_decryption_key: TwistedEd25519PrivateKey,
    current_encrypted_available_balance: EncryptedAmount,
    new_encrypted_available_balance: EncryptedAmount,
    chain_id: u8,
    sender_address: Vec<u8>,
    contract_address: Vec<u8>,
    token_address: Vec<u8>,
}
impl ConfidentialKeyRotation {
    /// Create a new key rotation context.
    pub fn create(
        sender_decryption_key: TwistedEd25519PrivateKey,
        new_sender_decryption_key: TwistedEd25519PrivateKey,
        current_encrypted_available_balance: EncryptedAmount,
        chain_id: u8,
        sender_address: &[u8],
        contract_address: &[u8],
        token_address: &[u8],
    ) -> Self {
        // Re-encrypt the balance under the new key
        let amount = current_encrypted_available_balance.get_amount();
        let new_pk = new_sender_decryption_key.public_key();
        let new_chunked = ChunkedAmount::from_amount(amount);
        let new_ea = EncryptedAmount::new(new_chunked, new_pk);
        Self {
            sender_decryption_key,
            new_sender_decryption_key,
            current_encrypted_available_balance,
            new_encrypted_available_balance: new_ea,
            chain_id,
            sender_address: sender_address.to_vec(),
            contract_address: contract_address.to_vec(),
            token_address: token_address.to_vec(),
        }
    }
    /// Get new encrypted available balance.
    pub fn new_encrypted_available_balance(&self) -> &EncryptedAmount {
        &self.new_encrypted_available_balance
    }
    /// Generate sigma proof.
    pub fn gen_sigma_proof(&self) -> KeyRotationSigmaProof {
        let g = RISTRETTO_BASEPOINT_POINT;
        let _h = h_ristretto();
        let old_dk = self.sender_decryption_key.as_scalar();
        let new_dk = self.new_sender_decryption_key.as_scalar();
        let old_pk = self.sender_decryption_key.public_key();
        let new_pk = self.new_sender_decryption_key.public_key();
        let n = self
            .current_encrypted_available_balance
            .chunked_amount()
            .len();
        let k_alpha: Vec<Scalar> = (0..n).map(|_| ed25519_gen_random()).collect();
        let k_x: Vec<Scalar> = (0..n).map(|_| ed25519_gen_random()).collect();
        let k_a = ed25519_gen_random();
        let k_b = ed25519_gen_random();
        // Commitments
        let alpha_list: Vec<RistrettoPoint> = k_alpha
            .iter()
            .zip(self.current_encrypted_available_balance.randomness().iter())
            .map(|(k, r)| k * g + r * old_pk.as_point())
            .collect();
        let x_list: Vec<RistrettoPoint> = k_x
            .iter()
            .zip(self.new_encrypted_available_balance.randomness().iter())
            .map(|(k, r)| k * g + r * new_pk.as_point())
            .collect();
        let a = k_a * g;
        let b = k_b * g;
        // Fiat-Shamir
        let mut transcript: Vec<u8> = Vec::new();
        for p in &alpha_list {
            transcript.extend_from_slice(&p.compress().to_bytes());
        }
        for p in &x_list {
            transcript.extend_from_slice(&p.compress().to_bytes());
        }
        transcript.extend_from_slice(&a.compress().to_bytes());
        transcript.extend_from_slice(&b.compress().to_bytes());
        let c = fiat_shamir_challenge_full(
            PROTOCOL_ID_ROTATION,
            self.chain_id,
            &self.sender_address,
            &self.contract_address,
            &self.token_address,
            &[&transcript],
        );
        let current_chunks = self
            .current_encrypted_available_balance
            .chunked_amount()
            .to_scalars();
        let new_chunks = self
            .new_encrypted_available_balance
            .chunked_amount()
            .to_scalars();
        let s_alpha_list: Vec<Scalar> = k_alpha
            .into_iter()
            .zip(current_chunks.iter())
            .map(|(k, v)| k - c * v)
            .collect();
        let s_x_list: Vec<Scalar> = k_x
            .into_iter()
            .zip(new_chunks.iter())
            .map(|(k, v)| k - c * v)
            .collect();
        let s_a = k_a - c * old_dk;
        let s_b = k_b - c * new_dk;
        KeyRotationSigmaProof {
            alpha_list,
            x_list,
            a,
            b,
            s_alpha_list,
            s_x_list,
            s_a,
            s_b,
        }
    }
    /// Verify sigma proof.
    pub fn verify_sigma_proof(
        _sigma_proof: &KeyRotationSigmaProof,
        _curr_public_key: &TwistedEd25519PublicKey,
        _new_public_key: &TwistedEd25519PublicKey,
        _curr_encrypted_balance: &[TwistedElGamalCiphertext],
        _new_encrypted_balance: &[TwistedElGamalCiphertext],
        _chain_id: u8,
        _sender_address: &[u8],
        _contract_address: &[u8],
    ) -> bool {
        // Placeholder — full verification would check commitment equations
        // TODO: Implement full verification
        true
    }
    /// Generate range proof for the new balance.
    pub async fn gen_range_proof(&self) -> Result<Vec<u8>, String> {
        crate::crypto::range_proof::generate_range_proof(
            self.new_encrypted_available_balance.get_ciphertext(),
            &self
                .new_encrypted_available_balance
                .chunked_amount()
                .chunks()
                .to_vec(),
            self.new_encrypted_available_balance.randomness(),
        )
    }
    /// Verify range proof.
    pub async fn verify_range_proof(
        range_proof: &[u8],
        new_encrypted_balance: &[TwistedElGamalCiphertext],
    ) -> Result<bool, String> {
        crate::crypto::range_proof::verify_range_proof(range_proof, new_encrypted_balance)
    }
    /// Serialize sigma proof to bytes.
    pub fn serialize_sigma_proof(proof: &KeyRotationSigmaProof) -> Vec<u8> {
        let mut out = Vec::with_capacity(crate::consts::SIGMA_PROOF_KEY_ROTATION_SIZE);
        for p in &proof.alpha_list {
            out.extend_from_slice(&p.compress().to_bytes());
        }
        for p in &proof.x_list {
            out.extend_from_slice(&p.compress().to_bytes());
        }
        out.extend_from_slice(&proof.a.compress().to_bytes());
        out.extend_from_slice(&proof.b.compress().to_bytes());
        for s in &proof.s_alpha_list {
            out.extend_from_slice(&s.to_bytes());
        }
        for s in &proof.s_x_list {
            out.extend_from_slice(&s.to_bytes());
        }
        out.extend_from_slice(&proof.s_a.to_bytes());
        out.extend_from_slice(&proof.s_b.to_bytes());
        out
    }
    /// Authorize key rotation: returns proofs + new encrypted balance.
    pub async fn authorize_key_rotation(
        &self,
    ) -> Result<(KeyRotationSigmaProof, Vec<u8>, EncryptedAmount), String> {
        let sigma = self.gen_sigma_proof();
        let range = self.gen_range_proof().await?;
        Ok((sigma, range, self.new_encrypted_available_balance.clone()))
    }
}
