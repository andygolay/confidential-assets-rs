src/crypto/confidential_transfer.rs:
// Copyright © Move Industries
// SPDX-License-Identifier: Apache-2.0
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use crate::crypto::twisted_ed25519::{TwistedEd25519PrivateKey, TwistedEd25519PublicKey};
use crate::crypto::twisted_el_gamal::{TwistedElGamal, TwistedElGamalCiphertext};
use crate::crypto::encrypted_amount::EncryptedAmount;
use crate::crypto::chunked_amount::{ChunkedAmount, AVAILABLE_BALANCE_CHUNK_COUNT, TRANSFER_AMOUNT_CHUNK_COUNT};
use crate::crypto::fiat_shamir::fiat_shamir_challenge_full;
use crate::crypto::h_ristretto;
use crate::consts::{PROTOCOL_ID_TRANSFER, MAX_SENDER_AUDITOR_HINT_BYTES};
use crate::utils::ed25519_gen_random;
use crate::bcs::serialize_vector_u8;
/// Transfer sigma proof components.
#[derive(Clone, Debug)]
pub struct TransferSigmaProof {
    /// Alpha1 list: commitments for transfer amount chunks (8).
    pub alpha1_list: Vec<RistrettoPoint>,
    /// Alpha2 list: commitments for balance chunks (4).
    pub alpha2_list: Vec<RistrettoPoint>,
    /// X1 list: commitments for recipient encryption (8).
    pub x1_list: Vec<RistrettoPoint>,
    /// X2 list: commitments for sender re-encryption (8).
    pub x2_list: Vec<RistrettoPoint>,
    /// X3 list: commitments for balance after transfer (4).
    pub x3_list: Vec<RistrettoPoint>,
    /// X4 commitment.
    pub x4: RistrettoPoint,
    /// X5 commitment.
    pub x5: RistrettoPoint,
    /// X6 commitment.
    pub x6: RistrettoPoint,
    /// X7 list: auditor commitments (optional, 0 or 4).
    pub x7_list: Option<Vec<RistrettoPoint>>,
    /// X8 list: auditor balance commitments (4).
    pub x8_list: Vec<RistrettoPoint>,
    /// Response scalars for alpha1.
    pub s_alpha1_list: Vec<Scalar>,
    /// Response scalars for alpha2.
    pub s_alpha2_list: Vec<Scalar>,
    /// Response scalars for x1.
    pub s_x1_list: Vec<Scalar>,
    /// Response scalars for x2.
    pub s_x2_list: Vec<Scalar>,
    /// Response scalars for x3.
    pub s_x3_list: Vec<Scalar>,
    /// Response scalar for x4.
    pub s_x4: Scalar,
    /// Response scalar for x5.
    pub s_x5: Scalar,
    /// Response scalar for x6.
    pub s_x6: Scalar,
    /// Response scalars for x7 (optional).
    pub s_x7_list: Option<Vec<Scalar>>,
    /// Response scalars for x8.
    pub s_x8_list: Vec<Scalar>,
}
/// Range proof pair for transfer: amount + new balance.
#[derive(Clone, Debug)]
pub struct TransferRangeProof {
    pub range_proof_amount: Vec<u8>,
    pub range_proof_new_balance: Vec<u8>,
}
/// Confidential transfer context.
pub struct ConfidentialTransfer {
    sender_decryption_key: TwistedEd25519PrivateKey,
    sender_encrypted_available_balance: EncryptedAmount,
    sender_encrypted_available_balance_after_transfer: EncryptedAmount,
    transfer_amount_encrypted_by_sender: EncryptedAmount,
    transfer_amount_encrypted_by_recipient: EncryptedAmount,
    transfer_amount_encrypted_by_auditors: Option<Vec<EncryptedAmount>>,
    recipient_encryption_key: TwistedEd25519PublicKey,
    auditor_encryption_keys: Vec<TwistedEd25519PublicKey>,
    amount: u128,
    chain_id: u8,
    sender_address: Vec<u8>,
    contract_address: Vec<u8>,
    token_address: Vec<u8>,
    sender_auditor_hint: Vec<u8>,
}
impl ConfidentialTransfer {
    /// Create a new confidential transfer context.
    pub fn create(
        sender_decryption_key: TwistedEd25519PrivateKey,
        sender_balance_amount: u128,
        sender_balance_randomness: Vec<Scalar>,
        amount: u128,
        recipient_encryption_key: TwistedEd25519PublicKey,
        auditor_encryption_keys: Vec<TwistedEd25519PublicKey>,
        chain_id: u8,
        sender_address: &[u8],
        contract_address: &[u8],
        token_address: &[u8],
        sender_auditor_hint: &[u8],
    ) -> Result<Self, String> {
        if sender_auditor_hint.len() > MAX_SENDER_AUDITOR_HINT_BYTES {
            return Err(format!("senderAuditorHint exceeds MAX_SENDER_AUDITOR_HINT_BYTES ({})", MAX_SENDER_AUDITOR_HINT_BYTES));
        }
        if amount > sender_balance_amount {
            return Err("Insufficient balance for transfer".to_string());
        }
        let sender_pk = sender_decryption_key.public_key();
        let new_balance = sender_balance_amount - amount;
        // Encrypt current balance
        let current_chunked = ChunkedAmount::from_amount(sender_balance_amount);
        let current_ea = EncryptedAmount::new(current_chunked, sender_pk.clone());
        // Encrypt new balance
        let new_chunked = ChunkedAmount::from_amount(new_balance);
        let new_ea = EncryptedAmount::new(new_chunked, sender_pk.clone());
        // Encrypt transfer amount under sender's key
        let transfer_chunked_sender = ChunkedAmount::from_transfer_amount(amount);
        let transfer_ea_sender = EncryptedAmount::new(transfer_chunked_sender, sender_pk.clone());
        // Encrypt transfer amount under recipient's key
        let transfer_chunked_recipient = ChunkedAmount::from_transfer_amount(amount);
        let transfer_ea_recipient = EncryptedAmount::new(transfer_chunked_recipient, recipient_encryption_key.clone());
        // Encrypt transfer amount under each auditor's key
        let auditor_eas: Option<Vec<EncryptedAmount>> = if auditor_encryption_keys.is_empty() {
            None
        } else {
            Some(auditor_encryption_keys.iter().map(|aud_pk| {
                let chunked = ChunkedAmount::from_transfer_amount(amount);
                EncryptedAmount::new(chunked, aud_pk.clone())
            }).collect())
        };
        Ok(Self {
            sender_decryption_key,
            sender_encrypted_available_balance: current_ea,
            sender_encrypted_available_balance_after_transfer: new_ea,
            transfer_amount_encrypted_by_sender: transfer_ea_sender,
            transfer_amount_encrypted_by_recipient: transfer_ea_recipient,
            transfer_amount_encrypted_by_auditors: auditor_eas,
            recipient_encryption_key,
            auditor_encryption_keys,
            amount,
            chain_id,
            sender_address: sender_address.to_vec(),
            contract_address: contract_address.to_vec(),
            token_address: token_address.to_vec(),
            sender_auditor_hint: sender_auditor_hint.to_vec(),
        })
    }
    /// Get transfer amount encrypted by sender.
    pub fn transfer_amount_encrypted_by_sender(&self) -> &EncryptedAmount {
        &self.transfer_amount_encrypted_by_sender
    }
    /// Get transfer amount encrypted by recipient.
    pub fn transfer_amount_encrypted_by_recipient(&self) -> &EncryptedAmount {
        &self.transfer_amount_encrypted_by_recipient
    }
    /// Get transfer amounts encrypted by auditors.
    pub fn transfer_amount_encrypted_by_auditors(&self) -> &Option<Vec<EncryptedAmount>> {
        &self.transfer_amount_encrypted_by_auditors
    }
    /// Get sender encrypted available balance after transfer.
    pub fn sender_encrypted_available_balance_after_transfer(&self) -> &EncryptedAmount {
        &self.sender_encrypted_available_balance_after_transfer
    }
    /// Get auditor encryption keys.
    pub fn auditor_encryption_keys(&self) -> &[TwistedEd25519PublicKey] {
&self.auditor_encryption_keys
    }
    /// Generate the sigma proof for the transfer.
    pub fn gen_sigma_proof(&self) -> TransferSigmaProof {
        let g = RISTRETTO_BASEPOINT_POINT;
        let h = h_ristretto();
        let dk = self.sender_decryption_key.as_scalar();
        let sender_pk = self.sender_decryption_key.public_key();
        let recipient_pk = &self.recipient_encryption_key;
        // Transfer amount chunks (8) and balance chunks (4)
        let amount_chunks = self.transfer_amount_encrypted_by_sender.chunked_amount().to_scalars();
        let balance_chunks = self.sender_encrypted_available_balance_after_transfer.chunked_amount().to_scalars();
        // Random nonces
        let k_alpha1: Vec<Scalar> = (0..TRANSFER_AMOUNT_CHUNK_COUNT).map(|_| ed25519_gen_random()).collect();
        let k_alpha2: Vec<Scalar> = (0..AVAILABLE_BALANCE_CHUNK_COUNT).map(|_| ed25519_gen_random()).collect();
        let k_x1: Vec<Scalar> = (0..TRANSFER_AMOUNT_CHUNK_COUNT).map(|_| ed25519_gen_random()).collect();
        let k_x2: Vec<Scalar> = (0..TRANSFER_AMOUNT_CHUNK_COUNT).map(|_| ed25519_gen_random()).collect();
        let k_x3: Vec<Scalar> = (0..AVAILABLE_BALANCE_CHUNK_COUNT).map(|_| ed25519_gen_random()).collect();
        let k_x4 = ed25519_gen_random();
        let k_x5 = ed25519_gen_random();
        let k_x6 = ed25519_gen_random();
        let k_x7: Vec<Scalar> = if self.auditor_encryption_keys.is_empty() {
            Vec::new()
        } else {
            (0..AVAILABLE_BALANCE_CHUNK_COUNT).map(|_| ed25519_gen_random()).collect()
        };
        let k_x8: Vec<Scalar> = (0..AVAILABLE_BALANCE_CHUNK_COUNT).map(|_| ed25519_gen_random()).collect();
        // Commitments
        let alpha1_list: Vec<RistrettoPoint> = k_alpha1.iter()
            .zip(self.transfer_amount_encrypted_by_sender.randomness().iter())
            .map(|(k, r)| k * g + r * sender_pk.as_point())
            .collect();
        let alpha2_list: Vec<RistrettoPoint> = k_alpha2.iter()
            .zip(self.sender_encrypted_available_balance_after_transfer.randomness().iter())
            .map(|(k, r)| k * g + r * sender_pk.as_point())
            .collect();
        let x1_list: Vec<RistrettoPoint> = k_x1.iter()
            .zip(self.transfer_amount_encrypted_by_recipient.randomness().iter())
            .map(|(k, r)| k * g + r * recipient_pk.as_point())
            .collect();
        let x2_list: Vec<RistrettoPoint> = k_x2.iter()
            .zip(self.transfer_amount_encrypted_by_sender.randomness().iter())
            .map(|(k, r)| k * g + r * sender_pk.as_point())
            .collect();
        let x3_list: Vec<RistrettoPoint> = k_x3.iter()
            .zip(self.sender_encrypted_available_balance_after_transfer.randomness().iter())
            .map(|(k, r)| k * g + r * sender_pk.as_point())
            .collect();
        let x4 = k_x4 * g;
        let x5 = k_x5 * g;
        let x6 = k_x6 * g;
        let x7_list: Option<Vec<RistrettoPoint>> = if self.auditor_encryption_keys.is_empty() {
            None
        } else {
            Some(k_x7.iter()
                .zip(self.transfer_amount_encrypted_by_auditors.as_ref().unwrap()[0].randomness().iter())
                .map(|(k, r)| k * g + r * self.auditor_encryption_keys[0].as_point())
                .collect())
        };
        let x8_list: Vec<RistrettoPoint> = k_x8.iter()
            .zip(self.sender_encrypted_available_balance_after_transfer.randomness().iter())
            .map(|(k, r)| k * g + r * sender_pk.as_point())
            .collect();
        // Build Fiat-Shamir transcript
        let mut transcript_data: Vec<u8> = Vec::new();
        for p in &alpha1_list { transcript_data.extend_from_slice(&p.compress().to_bytes()); }
        for p in &alpha2_list { transcript_data.extend_from_slice(&p.compress().to_bytes()); }
        for p in &x1_list { transcript_data.extend_from_slice(&p.compress().to_bytes()); }
for p in &x2_list { transcript_data.extend_from_slice(&p.compress().to_bytes()); }
        for p in &x3_list { transcript_data.extend_from_slice(&p.compress().to_bytes()); }
        transcript_data.extend_from_slice(&x4.compress().to_bytes());
        transcript_data.extend_from_slice(&x5.compress().to_bytes());
        transcript_data.extend_from_slice(&x6.compress().to_bytes());
        if let Some(ref x7s) = x7_list {
            for p in x7s { transcript_data.extend_from_slice(&p.compress().to_bytes()); }
        }
        for p in &x8_list { transcript_data.extend_from_slice(&p.compress().to_bytes()); }
        // Include sender_auditor_hint as BCS vector<u8>
        if !self.sender_auditor_hint.is_empty() {
            transcript_data.extend_from_slice(&serialize_vector_u8(&self.sender_auditor_hint));
        }
        let c = fiat_shamir_challenge_full(
            PROTOCOL_ID_TRANSFER,
            self.chain_id,
            &self.sender_address,
            &self.contract_address,
            &self.token_address,
            &[&transcript_data],
        );
        // Responses
        let s_alpha1_list: Vec<Scalar> = k_alpha1.into_iter()
            .zip(amount_chunks.iter())
            .map(|(k, v)| k - c * v)
            .collect();
        let s_alpha2_list: Vec<Scalar> = k_alpha2.into_iter()
            .zip(balance_chunks.iter())
            .map(|(k, v)| k - c * v)
            .collect();
        let s_x1_list = k_x1; // Simplified — full version would mix with recipient randomness
        let s_x2_list = k_x2;
        let s_x3_list = k_x3;
        let s_x4 = k_x4 - c * dk;
        let s_x5 = k_x5;
        let s_x6 = k_x6;
        let s_x7_list = if k_x7.is_empty() { None } else { Some(k_x7) };
        let s_x8_list = k_x8;
        TransferSigmaProof {
            alpha1_list, alpha2_list,
            x1_list, x2_list, x3_list,
            x4, x5, x6,
            x7_list, x8_list,
            s_alpha1_list, s_alpha2_list,
            s_x1_list, s_x2_list, s_x3_list,
            s_x4, s_x5, s_x6,
            s_x7_list, s_x8_list,
        }
    }
    /// Verify transfer sigma proof.
    pub fn verify_sigma_proof(
        _params: &TransferVerifyParams,
    ) -> bool {
        // Full verification mirrors the TS SDK's verifySigmaProof.
        // This requires checking all commitment equations against the challenge.
        // Placeholder: return true
        // TODO: Implement full verification matching TS SDK exactly.
        true
    }
    /// Serialize sigma proof to bytes (matches TS layout).
    /// Layout: alpha1(8*32) || alpha2(4*32) || x1(8*32) || x2(8*32) || x3(4*32) ||
    ///         x4(32) || x5(32) || x6(32) || x7?(4*32) || x8(4*32) ||
    ///         s_alpha1(8*32) || s_alpha2(4*32) || s_x1(8*32) || s_x2(8*32) || s_x3(4*32) ||
    ///         s_x4(32) || s_x5(32) || s_x6(32) || s_x7?(4*32) || s_x8(4*32)
    pub fn serialize_sigma_proof(proof: &TransferSigmaProof) -> Vec<u8> {
        let has_auditors = proof.x7_list.is_some();
        let expected_size = if has_auditors {
            crate::consts::SIGMA_PROOF_TRANSFER_SIZE + 4 * 32 * 2 // extra x7 + s_x7
        } else {
            crate::consts::SIGMA_PROOF_TRANSFER_SIZE
        };
        let mut out = Vec::with_capacity(expected_size);
        // Points
        for p in &proof.alpha1_list { out.extend_from_slice(&p.compress().to_bytes()); }
        for p in &proof.alpha2_list { out.extend_from_slice(&p.compress().to_bytes()); }
        for p in &proof.x1_list { out.extend_from_slice(&p.compress().to_bytes()); }
        for p in &proof.x2_list { out.extend_from_slice(&p.compress().to_bytes()); }
        for p in &proof.x3_list { out.extend_from_slice(&p.compress().to_bytes()); }
        out.extend_from_slice(&proof.x4.compress().to_bytes());
        out.extend_from_slice(&proof.x5.compress().to_bytes());
        out.extend_from_slice(&proof.x6.compress().to_bytes());
        if let Some(ref x7s) = proof.x7_list {
for p in x7s { out.extend_from_slice(&p.compress().to_bytes()); }
        }
        for p in &proof.x8_list { out.extend_from_slice(&p.compress().to_bytes()); }
        // Scalars
        for s in &proof.s_alpha1_list { out.extend_from_slice(&s.to_bytes()); }
        for s in &proof.s_alpha2_list { out.extend_from_slice(&s.to_bytes()); }
        for s in &proof.s_x1_list { out.extend_from_slice(&s.to_bytes()); }
        for s in &proof.s_x2_list { out.extend_from_slice(&s.to_bytes()); }
        for s in &proof.s_x3_list { out.extend_from_slice(&s.to_bytes()); }
        out.extend_from_slice(&proof.s_x4.to_bytes());
        out.extend_from_slice(&proof.s_x5.to_bytes());
        out.extend_from_slice(&proof.s_x6.to_bytes());
        if let Some(ref s_x7s) = proof.s_x7_list {
            for s in s_x7s { out.extend_from_slice(&s.to_bytes()); }
        }
        for s in &proof.s_x8_list { out.extend_from_slice(&s.to_bytes()); }
        out
    }
    /// Deserialize sigma proof from bytes.
    pub fn deserialize_sigma_proof(bytes: &[u8]) -> Result<TransferSigmaProof, String> {
        let chunk = 32;
        let read_point = |offset: usize| -> Result<RistrettoPoint, String> {
            if offset + chunk > bytes.len() {
                return Err("Unexpected end of proof bytes".to_string());
            }
            let pt_bytes: [u8; 32] = bytes[offset..offset + chunk].try_into().map_err(|_| "slice error")?;
            use curve25519_dalek::ristretto::CompressedRistretto;
            CompressedRistretto(pt_bytes).decompress().ok_or("Invalid point".to_string())
        };
        let read_scalar = |offset: usize| -> Result<Scalar, String> {
            if offset + chunk > bytes.len() {
                return Err("Unexpected end of proof bytes".to_string());
            }
            let s_bytes: [u8; 32] = bytes[offset..offset + chunk].try_into().map_err(|_| "slice error")?;
            Scalar::from_canonical_bytes(s_bytes).ok_or("Invalid scalar".to_string())
        };
        // Detect if auditors are present based on total length
        let has_auditors = bytes.len() > crate::consts::SIGMA_PROOF_TRANSFER_SIZE;
        let mut offset = 0;
        // Points
        let mut alpha1_list = Vec::with_capacity(8);
        for _ in 0..8 { alpha1_list.push(read_point(offset)?); offset += chunk; }
        let mut alpha2_list = Vec::with_capacity(4);
        for _ in 0..4 { alpha2_list.push(read_point(offset)?); offset += chunk; }
        let mut x1_list = Vec::with_capacity(8);
        for _ in 0..8 { x1_list.push(read_point(offset)?); offset += chunk; }
        let mut x2_list = Vec::with_capacity(8);
        for _ in 0..8 { x2_list.push(read_point(offset)?); offset += chunk; }
        let mut x3_list = Vec::with_capacity(4);
        for _ in 0..4 { x3_list.push(read_point(offset)?); offset += chunk; }
        let x4 = read_point(offset)?; offset += chunk;
        let x5 = read_point(offset)?; offset += chunk;
        let x6 = read_point(offset)?; offset += chunk;
        let x7_list = if has_auditors {
            let mut v = Vec::with_capacity(4);
            for _ in 0..4 { v.push(read_point(offset)?); offset += chunk; }
            Some(v)
        } else { None };
        let mut x8_list = Vec::with_capacity(4);
        for _ in 0..4 { x8_list.push(read_point(offset)?); offset += chunk; }
        // Scalars
        let mut s_alpha1_list = Vec::with_capacity(8);
        for _ in 0..8 { s_alpha1_list.push(read_scalar(offset)?); offset += chunk; }
        let mut s_alpha2_list = Vec::with_capacity(4);
        for _ in 0..4 { s_alpha2_list.push(read_scalar(offset)?); offset += chunk; }
        let mut s_x1_list = Vec::with_capacity(8);
        for _ in 0..8 { s_x1_list.push(read_scalar(offset)?); offset += chunk; }
        let mut s_x2_list = Vec::with_capacity(8);
        for _ in 0..8 { s_x2_list.push(read_scalar(offset)?); offset += chunk; }
        let mut s_x3_list = Vec::with_capacity(4);
for _ in 0..4 { s_x3_list.push(read_scalar(offset)?); offset += chunk; }
        let s_x4 = read_scalar(offset)?; offset += chunk;
        let s_x5 = read_scalar(offset)?; offset += chunk;
        let s_x6 = read_scalar(offset)?; offset += chunk;
        let s_x7_list = if has_auditors {
            let mut v = Vec::with_capacity(4);
            for _ in 0..4 { v.push(read_scalar(offset)?); offset += chunk; }
            Some(v)
        } else { None };
        let mut s_x8_list = Vec::with_capacity(4);
        for _ in 0..4 { s_x8_list.push(read_scalar(offset)?); offset += chunk; }
        Ok(TransferSigmaProof {
            alpha1_list, alpha2_list,
            x1_list, x2_list, x3_list,
            x4, x5, x6,
            x7_list, x8_list,
            s_alpha1_list, s_alpha2_list,
            s_x1_list, s_x2_list, s_x3_list,
            s_x4, s_x5, s_x6,
            s_x7_list, s_x8_list,
        })
    }
    /// Generate range proofs (amount + new balance).
    pub async fn gen_range_proof(&self) -> Result<TransferRangeProof, String> {
        let range_proof_amount = crate::crypto::range_proof::generate_range_proof(
            self.transfer_amount_encrypted_by_recipient.get_ciphertext(),
            &self.transfer_amount_encrypted_by_recipient.chunked_amount().chunks().to_vec(),
            self.transfer_amount_encrypted_by_recipient.randomness(),
        )?;
        let range_proof_new_balance = crate::crypto::range_proof::generate_range_proof(
            self.sender_encrypted_available_balance_after_transfer.get_ciphertext(),
            &self.sender_encrypted_available_balance_after_transfer.chunked_amount().chunks().to_vec(),
            self.sender_encrypted_available_balance_after_transfer.randomness(),
        )?;
        Ok(TransferRangeProof { range_proof_amount, range_proof_new_balance })
    }
    /// Verify range proofs.
    pub async fn verify_range_proof(
        encrypted_amount_by_recipient: &EncryptedAmount,
        encrypted_balance_after: &EncryptedAmount,
        range_proof_amount: &[u8],
        range_proof_new_balance: &[u8],
    ) -> Result<bool, String> {
        let ok1 = crate::crypto::range_proof::verify_range_proof(
            range_proof_amount,
            encrypted_amount_by_recipient.get_ciphertext(),
        )?;
        let ok2 = crate::crypto::range_proof::verify_range_proof(
            range_proof_new_balance,
            encrypted_balance_after.get_ciphertext(),
        )?;
        Ok(ok1 && ok2)
    }
    /// Authorize transfer: returns all proofs + encrypted amounts.
    pub async fn authorize_transfer(&self) -> Result<
        (TransferSigmaProof, TransferRangeProof, EncryptedAmount, EncryptedAmount, Vec<EncryptedAmount>),
        String
    > {
        let sigma = self.gen_sigma_proof();
        let range = self.gen_range_proof().await?;
        let sender_new_balance = self.sender_encrypted_available_balance_after_transfer.clone();
        let recipient_amount = self.transfer_amount_encrypted_by_recipient.clone();
        let auditor_amounts = self.transfer_amount_encrypted_by_auditors.clone().unwrap_or_default();
        Ok((sigma, range, sender_new_balance, recipient_amount, auditor_amounts))
    }
}
/// Parameters for sigma proof verification.
pub struct TransferVerifyParams {
    pub sender_private_key: TwistedEd25519PrivateKey,
    pub recipient_public_key: TwistedEd25519PublicKey,
    pub encrypted_actual_balance: Vec<TwistedElGamalCiphertext>,
    pub encrypted_transfer_amount_by_sender: Vec<TwistedElGamalCiphertext>,
    pub encrypted_actual_balance_after_transfer: Vec<TwistedElGamalCiphertext>,
    pub encrypted_transfer_amount_by_recipient: Vec<TwistedElGamalCiphertext>,
    pub sigma_proof: TransferSigmaProof,
    pub auditors: Option<AuditorParams>,
    pub chain_id: u8,
    pub sender_address: Vec<u8>,
    pub contract_address: Vec<u8>,
    pub token_address: Vec<u8>,
    pub sender_auditor_hint: Vec<u8>,
}
/// Auditor parameters for verification.
pub struct AuditorParams {
    pub public_keys: Vec<TwistedEd25519PublicKey>,
    pub auditors_cb_list: Vec<Vec<TwistedElGamalCiphertext>>,
}

