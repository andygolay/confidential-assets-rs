// Copyright © Move Industries
// SPDX-License-Identifier: Apache-2.0

//! Transaction builder for confidential asset operations.
//!
//! Mirrors the TS SDK's `confidentialAssetTxnBuilder.ts`. Constructs the
//! function arguments (proofs, ciphertexts, etc.) for each confidential
//! asset Move entry point.

use crate::crypto::{
    TwistedEd25519PrivateKey, TwistedEd25519PublicKey,
    ConfidentialWithdraw, ConfidentialTransfer, ConfidentialKeyRotation,
    ConfidentialNormalization,
};
use crate::crypto::confidential_registration::gen_registration_proof;
use crate::consts::{DEFAULT_CONFIDENTIAL_COIN_MODULE_ADDRESS, MODULE_NAME, MAX_SENDER_AUDITOR_HINT_BYTES};
use super::view_functions::{MovementClient, ViewFunctionError, get_balance, get_encryption_key, get_global_auditor_encryption_key, is_pending_balance_frozen, is_balance_normalized, get_chain_id_byte_for_proofs};

/// A built transaction payload ready for signing and submission.
/// Contains the function identifier and serialized arguments.
#[derive(Debug, Clone)]
pub struct TransactionPayload {
    pub module_address: String,
    pub module_name: String,
    pub function_name: String,
    pub type_arguments: Vec<String>,
    pub arguments: Vec<Vec<u8>>,
}

/// Builder for confidential asset transactions.
pub struct ConfidentialAssetTransactionBuilder<C: MovementClient> {
    pub client: C,
    pub confidential_asset_module_address: String,
}

impl<C: MovementClient + Sync> ConfidentialAssetTransactionBuilder<C> {
    pub fn new(client: C, confidential_asset_module_address: Option<&str>) -> Self {
        let addr = confidential_asset_module_address
            .unwrap_or(DEFAULT_CONFIDENTIAL_COIN_MODULE_ADDRESS)
            .to_string();
        Self {
            client,
            confidential_asset_module_address: addr,
        }
    }

    /// Build a `register` transaction.
    pub async fn register_balance(
        &self,
        sender: &[u8; 32],
        token_address: &[u8; 32],
        decryption_key: &TwistedEd25519PrivateKey,
    ) -> Result<TransactionPayload, ViewFunctionError> {
        let chain_id = get_chain_id_byte_for_proofs(&self.client).await?;
        let contract_bytes = hex::decode(&self.confidential_asset_module_address.trim_start_matches("0x"))
            .unwrap_or_default();
        let contract_address: &[u8] = &contract_bytes;

        let proof = gen_registration_proof(
            decryption_key,
            chain_id,
            sender,
            contract_address,
            token_address,
        );

        let public_key_bytes = decryption_key.public_key().to_bytes();

        Ok(TransactionPayload {
            module_address: self.confidential_asset_module_address.clone(),
            module_name: MODULE_NAME.to_string(),
            function_name: "register".to_string(),
            type_arguments: vec![],
            arguments: vec![
                token_address.to_vec(),
                public_key_bytes.to_vec(),
                proof.commitment.to_vec(),
                proof.response.to_vec(),
            ],
        })
    }

    /// Build a `deposit_to` transaction.
    pub fn deposit(
        &self,
        sender: &[u8; 32],
        token_address: &[u8; 32],
        amount: u64,
        recipient: Option<&[u8; 32]>,
    ) -> Result<TransactionPayload, ViewFunctionError> {
        let recipient_addr = recipient.copied().unwrap_or(*sender);

        Ok(TransactionPayload {
            module_address: self.confidential_asset_module_address.clone(),
            module_name: MODULE_NAME.to_string(),
            function_name: "deposit_to".to_string(),
            type_arguments: vec![],
            arguments: vec![
                token_address.to_vec(),
                recipient_addr.to_vec(),
                amount.to_le_bytes().to_vec(),
            ],
        })
    }

    /// Build a `withdraw_to` transaction.
    pub async fn withdraw(
        &self,
        sender: &[u8; 32],
        token_address: &[u8; 32],
        amount: u64,
        sender_decryption_key: &TwistedEd25519PrivateKey,
        recipient: Option<&[u8; 32]>,
    ) -> Result<TransactionPayload, ViewFunctionError> {
        validate_amount(amount)?;

        // Get sender's available balance from chain
        let balance = get_balance(
            &self.client,
            sender,
            token_address,
            sender_decryption_key,
            Some(&self.confidential_asset_module_address),
        ).await?;

        let chain_id = get_chain_id_byte_for_proofs(&self.client).await?;
        let contract_bytes = hex::decode(&self.confidential_asset_module_address.trim_start_matches("0x"))
            .unwrap_or_default();

        let confidential_withdraw = ConfidentialWithdraw::create(
            sender_decryption_key,
            balance.available.get_ciphertext(),
            amount,
            chain_id,
            sender,
            &contract_bytes,
            token_address,
        );

        let (proofs, encrypted_amount_after_withdraw) = confidential_withdraw.authorize_withdrawal();

        let recipient_addr = recipient.copied().unwrap_or(*sender);

        Ok(TransactionPayload {
            module_address: self.confidential_asset_module_address.clone(),
            module_name: MODULE_NAME.to_string(),
            function_name: "withdraw_to".to_string(),
            type_arguments: vec![],
            arguments: vec![
                token_address.to_vec(),
                recipient_addr.to_vec(),
                amount.to_le_bytes().to_vec(),
                encrypted_amount_after_withdraw.get_ciphertext_bytes(),
                proofs.range_proof,
                ConfidentialWithdraw::serialize_sigma_proof(&proofs.sigma_proof),
            ],
        })
    }

    /// Build a `rollover_pending_balance` (or `rollover_pending_balance_and_freeze`) transaction.
    pub async fn rollover_pending_balance(
        &self,
        sender: &[u8; 32],
        token_address: &[u8; 32],
        with_freeze_balance: bool,
        check_normalized: bool,
    ) -> Result<TransactionPayload, ViewFunctionError> {
        if check_normalized {
            let is_norm = is_balance_normalized(
                &self.client,
                sender,
                token_address,
                Some(&self.confidential_asset_module_address),
            ).await?;
            if !is_norm {
                return Err(ViewFunctionError::RpcError(
                    "Balance must be normalized before rollover".into(),
                ));
            }
        }

        let function_name = if with_freeze_balance {
            "rollover_pending_balance_and_freeze"
        } else {
            "rollover_pending_balance"
        };

        Ok(TransactionPayload {
            module_address: self.confidential_asset_module_address.clone(),
            module_name: MODULE_NAME.to_string(),
            function_name: function_name.to_string(),
            type_arguments: vec![],
            arguments: vec![token_address.to_vec()],
        })
    }

    /// Build a `confidential_transfer` transaction.
    pub async fn transfer(
        &self,
        sender: &[u8; 32],
        recipient: &[u8; 32],
        token_address: &[u8; 32],
        amount: u64,
        sender_decryption_key: &TwistedEd25519PrivateKey,
        additional_auditor_encryption_keys: &[TwistedEd25519PublicKey],
        sender_auditor_hint: &[u8],
    ) -> Result<TransactionPayload, ViewFunctionError> {
        validate_amount(amount)?;
        if sender_auditor_hint.len() > MAX_SENDER_AUDITOR_HINT_BYTES {
            return Err(ViewFunctionError::RpcError(
                format!("senderAuditorHint exceeds MAX_SENDER_AUDITOR_HINT_BYTES ({})", MAX_SENDER_AUDITOR_HINT_BYTES),
            ));
        }

        let chain_id = get_chain_id_byte_for_proofs(&self.client).await?;

        // Get auditor public key for the token
        let global_auditor_pub_key = get_global_auditor_encryption_key(
            &self.client,
            token_address,
            Some(&self.confidential_asset_module_address),
        ).await?;

        // Determine recipient encryption key
        let recipient_encryption_key = if sender == recipient {
            sender_decryption_key.public_key()
        } else {
            get_encryption_key(
                &self.client,
                recipient,
                token_address,
                Some(&self.confidential_asset_module_address),
            ).await?
        };

        // Check if recipient balance is frozen
        let is_frozen = is_pending_balance_frozen(
            &self.client,
            recipient,
            token_address,
            Some(&self.confidential_asset_module_address),
        ).await?;
        if is_frozen {
            return Err(ViewFunctionError::RpcError("Recipient balance is frozen".into()));
        }

        // Get sender's available balance
        let balance = get_balance(
            &self.client,
            sender,
            token_address,
            sender_decryption_key,
            Some(&self.confidential_asset_module_address),
        ).await?;

        let contract_bytes = hex::decode(&self.confidential_asset_module_address.trim_start_matches("0x"))
            .unwrap_or_default();

        // Assemble auditor keys
        let mut auditor_keys: Vec<TwistedEd25519PublicKey> = vec![];
        if let Some(auditor) = global_auditor_pub_key {
            auditor_keys.push(auditor);
        }
        auditor_keys.extend_from_slice(additional_auditor_encryption_keys);

        let confidential_transfer = ConfidentialTransfer::create(
            sender_decryption_key,
            balance.available.get_ciphertext(),
            amount,
            &recipient_encryption_key,
            &auditor_keys,
            chain_id,
            sender,
            &contract_bytes,
            token_address,
            sender_auditor_hint,
        );

        let (proofs, encrypted_amount_after_transfer, encrypted_amount_by_recipient, auditors_cb_list) =
            confidential_transfer.authorize_transfer();

        // Concatenate auditor keys and balances
        let auditor_encryption_keys_bytes: Vec<u8> = auditor_keys.iter()
            .flat_map(|k| k.to_bytes().to_vec())
            .collect();
        let auditor_balances_bytes: Vec<u8> = auditors_cb_list.iter()
            .flat_map(|cb| cb.get_ciphertext_bytes())
            .collect();

        Ok(TransactionPayload {
            module_address: self.confidential_asset_module_address.clone(),
            module_name: MODULE_NAME.to_string(),
            function_name: "confidential_transfer".to_string(),
            type_arguments: vec![],
            arguments: vec![
                token_address.to_vec(),
                recipient.to_vec(),
                encrypted_amount_after_transfer.get_ciphertext_bytes(),
                confidential_transfer.transfer_amount_encrypted_by_sender().get_ciphertext_bytes(),
                encrypted_amount_by_recipient.get_ciphertext_bytes(),
                auditor_encryption_keys_bytes,
                auditor_balances_bytes,
                proofs.range_proof.range_proof_new_balance,
                proofs.range_proof.range_proof_amount,
                ConfidentialTransfer::serialize_sigma_proof(&proofs.sigma_proof),
                sender_auditor_hint.to_vec(),
            ],
        })
    }

    /// Build a `rotate_encryption_key` (or `rotate_encryption_key_and_unfreeze`) transaction.
    pub async fn rotate_encryption_key(
        &self,
        sender: &[u8; 32],
        sender_decryption_key: &TwistedEd25519PrivateKey,
        new_sender_decryption_key: &TwistedEd25519PrivateKey,
        token_address: &[u8; 32],
        check_pending_balance_empty: bool,
    ) -> Result<TransactionPayload, ViewFunctionError> {
        let chain_id = get_chain_id_byte_for_proofs(&self.client).await?;

        let is_frozen = is_pending_balance_frozen(
            &self.client,
            sender,
            token_address,
            Some(&self.confidential_asset_module_address),
        ).await?;

        let balance = get_balance(
            &self.client,
            sender,
            token_address,
            sender_decryption_key,
            Some(&self.confidential_asset_module_address),
        ).await?;

        if check_pending_balance_empty && balance.pending_balance() > 0 {
            return Err(ViewFunctionError::RpcError(
                "Pending balance must be 0 before rotating encryption key".into(),
            ));
        }

        let contract_bytes = hex::decode(&self.confidential_asset_module_address.trim_start_matches("0x"))
            .unwrap_or_default();

        let key_rotation = ConfidentialKeyRotation::create(
            sender_decryption_key,
            new_sender_decryption_key,
            &balance.available,
            chain_id,
            sender,
            &contract_bytes,
            token_address,
        );

        let (proofs, new_encrypted_available_balance) = key_rotation.authorize_key_rotation();

        let new_public_key_bytes = new_sender_decryption_key.public_key().to_bytes();
        let method = if is_frozen {
            "rotate_encryption_key_and_unfreeze"
        } else {
            "rotate_encryption_key"
        };

        Ok(TransactionPayload {
            module_address: self.confidential_asset_module_address.clone(),
            module_name: MODULE_NAME.to_string(),
            function_name: method.to_string(),
            type_arguments: vec![],
            arguments: vec![
                token_address.to_vec(),
                new_public_key_bytes.to_vec(),
                new_encrypted_available_balance.get_ciphertext_bytes(),
                proofs.range_proof,
                ConfidentialKeyRotation::serialize_sigma_proof(&proofs.sigma_proof),
            ],
        })
    }

    /// Build a `normalize_balance` transaction.
    pub async fn normalize_balance(
        &self,
        sender: &[u8; 32],
        sender_decryption_key: &TwistedEd25519PrivateKey,
        token_address: &[u8; 32],
    ) -> Result<TransactionPayload, ViewFunctionError> {
        let chain_id = get_chain_id_byte_for_proofs(&self.client).await?;

        let balance = get_balance(
            &self.client,
            sender,
            token_address,
            sender_decryption_key,
            Some(&self.confidential_asset_module_address),
        ).await?;

        let contract_bytes = hex::decode(&self.confidential_asset_module_address.trim_start_matches("0x"))
            .unwrap_or_default();

        let normalization = ConfidentialNormalization::create(
            sender_decryption_key,
            &balance.available,
            chain_id,
            sender,
            &contract_bytes,
            token_address,
        );

        normalization.create_transaction_payload(
            sender,
            &self.confidential_asset_module_address,
            token_address,
        )
    }
}

fn validate_amount(amount: u64) -> Result<(), ViewFunctionError> {
    // u64 is always >= 0, so we only need to check for zero if desired
    Ok(())
}
