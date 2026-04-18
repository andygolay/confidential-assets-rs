// Copyright © Move Industries
// SPDX-License-Identifier: Apache-2.0

//! Transaction builder for confidential asset operations.
//!
//! Mirrors the TS SDK's `confidentialAssetTxnBuilder.ts`. Constructs entry
//! function payloads for each confidential asset Move entry point.
//!
//! TODO: Switch `aptos_sdk` types → `movement_sdk` types once the fork is ready.

use super::view_functions::{
    get_balance, get_chain_id_byte_for_proofs, get_encryption_key,
    get_global_auditor_encryption_key, is_balance_normalized, is_pending_balance_frozen,
};
use crate::consts::{
    DEFAULT_CONFIDENTIAL_COIN_MODULE_ADDRESS, MAX_SENDER_AUDITOR_HINT_BYTES, MODULE_NAME,
};
use crate::crypto::confidential_registration::gen_registration_proof;
use crate::crypto::{
    confidential_key_rotation::ConfidentialKeyRotation,
    confidential_normalization::ConfidentialNormalization,
    confidential_transfer::ConfidentialTransfer, confidential_withdraw::ConfidentialWithdraw,
    TwistedEd25519PrivateKey, TwistedEd25519PublicKey,
};
use aptos_sdk::{
    transaction::{EntryFunction, TransactionPayload},
    types::{AccountAddress, Identifier, MoveModuleId, TypeTag},
    Aptos, AptosError,
};

/// Helper: BCS-encode an AccountAddress.
fn bcs_addr(addr: &AccountAddress) -> Vec<u8> {
    bcs::to_bytes(addr).unwrap_or_default()
}

/// Helper: parse module address string to AccountAddress.
fn parse_module_address(addr: &str) -> AccountAddress {
    AccountAddress::from_hex(addr).unwrap_or(AccountAddress::ZERO)
}

// TODO: Switch `Aptos` → `Movement`
/// Builder for confidential asset transactions.
///
/// Returns `TransactionPayload` (aptos-sdk entry function) ready for
/// `aptos.sign_and_submit()` / `aptos.simulate()`.
pub struct ConfidentialAssetTransactionBuilder<'a> {
    pub client: &'a Aptos,
    pub confidential_asset_module_address: String,
}

impl<'a> ConfidentialAssetTransactionBuilder<'a> {
    pub fn new(client: &'a Aptos, confidential_asset_module_address: Option<&str>) -> Self {
        let addr = confidential_asset_module_address
            .unwrap_or(DEFAULT_CONFIDENTIAL_COIN_MODULE_ADDRESS)
            .to_string();
        Self {
            client,
            confidential_asset_module_address: addr,
        }
    }

    /// Build a `register` entry function payload.
    pub async fn register_balance(
        &self,
        sender: &AccountAddress,
        token_address: &AccountAddress,
        decryption_key: &TwistedEd25519PrivateKey,
    ) -> Result<TransactionPayload, AptosError> {
        let chain_id = get_chain_id_byte_for_proofs(self.client).await?;
        let contract_address = parse_module_address(&self.confidential_asset_module_address);
        let sender_bytes = sender.to_bytes();
        let token_bytes = token_address.to_bytes();

        let proof = gen_registration_proof(
            decryption_key,
            chain_id,
            &sender_bytes,
            contract_address.as_bytes(),
            &token_bytes,
        );

        let public_key_bytes = decryption_key.public_key().to_bytes();

        Ok(EntryFunction::new(
            MoveModuleId::new(
                contract_address,
                Identifier::new(MODULE_NAME).expect("valid module name"),
            ),
            "register",
            vec![],
            vec![
                bcs_addr(token_address),
                public_key_bytes.to_vec(),
                proof.commitment.to_vec(),
                proof.response.to_vec(),
            ],
        )
        .into())
    }

    /// Build a `deposit_to` entry function payload.
    pub fn deposit(
        &self,
        token_address: &AccountAddress,
        amount: u64,
        recipient: Option<&AccountAddress>,
    ) -> Result<TransactionPayload, AptosError> {
        let recipient_addr = recipient.copied().unwrap_or(*token_address);
        let module_addr = parse_module_address(&self.confidential_asset_module_address);

        Ok(EntryFunction::new(
            MoveModuleId::new(
                module_addr,
                Identifier::new(MODULE_NAME).expect("valid module name"),
            ),
            "deposit_to",
            vec![],
            vec![
                bcs_addr(token_address),
                bcs_addr(&recipient_addr),
                bcs::to_bytes(&amount).unwrap_or_default(),
            ],
        )
        .into())
    }

    /// Build a `withdraw_to` entry function payload.
    pub async fn withdraw(
        &self,
        sender: &AccountAddress,
        token_address: &AccountAddress,
        amount: u64,
        sender_decryption_key: &TwistedEd25519PrivateKey,
        recipient: Option<&AccountAddress>,
    ) -> Result<TransactionPayload, AptosError> {
        let sender_bytes = sender.to_bytes();
        let token_bytes = token_address.to_bytes();

        // Get sender's available balance from chain
        let balance = get_balance(
            self.client,
            sender,
            token_address,
            sender_decryption_key,
            Some(&self.confidential_asset_module_address),
        )
        .await?;

        let chain_id = get_chain_id_byte_for_proofs(self.client).await?;
        let contract_address = parse_module_address(&self.confidential_asset_module_address);

        let confidential_withdraw = ConfidentialWithdraw::create(
            sender_decryption_key,
            balance.available.get_ciphertext(),
            amount,
            chain_id,
            &sender_bytes,
            contract_address.as_bytes(),
            &token_bytes,
        );

        let (proofs, encrypted_amount_after_withdraw) =
            confidential_withdraw.authorize_withdrawal();

        let recipient_addr = recipient.copied().unwrap_or(*sender);
        let module_addr = parse_module_address(&self.confidential_asset_module_address);

        Ok(EntryFunction::new(
            MoveModuleId::new(
                module_addr,
                Identifier::new(MODULE_NAME).expect("valid module name"),
            ),
            "withdraw_to",
            vec![],
            vec![
                bcs_addr(token_address),
                bcs_addr(&recipient_addr),
                bcs::to_bytes(&amount).unwrap_or_default(),
                encrypted_amount_after_withdraw.get_ciphertext_bytes(),
                proofs.range_proof,
                ConfidentialWithdraw::serialize_sigma_proof(&proofs.sigma_proof),
            ],
        )
        .into())
    }

    /// Build a `rollover_pending_balance` (or `rollover_pending_balance_and_freeze`) entry function payload.
    pub async fn rollover_pending_balance(
        &self,
        sender: &AccountAddress,
        token_address: &AccountAddress,
        with_freeze_balance: bool,
        check_normalized: bool,
    ) -> Result<TransactionPayload, AptosError> {
        if check_normalized {
            let is_norm = is_balance_normalized(
                self.client,
                sender,
                token_address,
                Some(&self.confidential_asset_module_address),
            )
            .await?;
            if !is_norm {
                return Err(AptosError::Internal(
                    "Balance must be normalized before rollover",
                ));
            }
        }

        let function_name = if with_freeze_balance {
            "rollover_pending_balance_and_freeze"
        } else {
            "rollover_pending_balance"
        };

        let module_addr = parse_module_address(&self.confidential_asset_module_address);

        Ok(EntryFunction::new(
            MoveModuleId::new(
                module_addr,
                Identifier::new(MODULE_NAME).expect("valid module name"),
            ),
            function_name,
            vec![],
            vec![bcs_addr(token_address)],
        )
        .into())
    }

    /// Build a `confidential_transfer` entry function payload.
    pub async fn transfer(
        &self,
        sender: &AccountAddress,
        recipient: &AccountAddress,
        token_address: &AccountAddress,
        amount: u64,
        sender_decryption_key: &TwistedEd25519PrivateKey,
        additional_auditor_encryption_keys: &[TwistedEd25519PublicKey],
        sender_auditor_hint: &[u8],
    ) -> Result<TransactionPayload, AptosError> {
        if sender_auditor_hint.len() > MAX_SENDER_AUDITOR_HINT_BYTES {
            return Err(AptosError::Internal(format!(
                "senderAuditorHint exceeds MAX_SENDER_AUDITOR_HINT_BYTES ({})",
                MAX_SENDER_AUDITOR_HINT_BYTES
            )));
        }

        let sender_bytes = sender.to_bytes();
        let token_bytes = token_address.to_bytes();

        let chain_id = get_chain_id_byte_for_proofs(self.client).await?;

        // Get auditor public key for the token
        let global_auditor_pub_key = get_global_auditor_encryption_key(
            self.client,
            token_address,
            Some(&self.confidential_asset_module_address),
        )
        .await?;

        // Determine recipient encryption key
        let recipient_encryption_key = if sender == recipient {
            sender_decryption_key.public_key()
        } else {
            get_encryption_key(
                self.client,
                recipient,
                token_address,
                Some(&self.confidential_asset_module_address),
            )
            .await?
        };

        // Check if recipient balance is frozen
        let is_frozen = is_pending_balance_frozen(
            self.client,
            recipient,
            token_address,
            Some(&self.confidential_asset_module_address),
        )
        .await?;
        if is_frozen {
            return Err(AptosError::Internal(
                "Recipient balance is frozen".to_string(),
            ));
        }

        // Get sender's available balance
        let balance = get_balance(
            self.client,
            sender,
            token_address,
            sender_decryption_key,
            Some(&self.confidential_asset_module_address),
        )
        .await?;

        let contract_address = parse_module_address(&self.confidential_asset_module_address);

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
            &sender_bytes,
            contract_address.as_bytes(),
            &token_bytes,
            sender_auditor_hint,
        );

        let (
            proofs,
            encrypted_amount_after_transfer,
            encrypted_amount_by_recipient,
            auditors_cb_list,
        ) = confidential_transfer.authorize_transfer();

        // Concatenate auditor keys and balances
        let auditor_encryption_keys_bytes: Vec<u8> = auditor_keys
            .iter()
            .flat_map(|k| k.to_bytes().to_vec())
            .collect();
        let auditor_balances_bytes: Vec<u8> = auditors_cb_list
            .iter()
            .flat_map(|cb| cb.get_ciphertext_bytes())
            .collect();

        let module_addr = parse_module_address(&self.confidential_asset_module_address);

        Ok(EntryFunction::new(
            MoveModuleId::new(
                module_addr,
                Identifier::new(MODULE_NAME).expect("valid module name"),
            ),
            "confidential_transfer",
            vec![],
            vec![
                bcs_addr(token_address),
                bcs_addr(recipient),
                encrypted_amount_after_transfer.get_ciphertext_bytes(),
                confidential_transfer
                    .transfer_amount_encrypted_by_sender()
                    .get_ciphertext_bytes(),
                encrypted_amount_by_recipient.get_ciphertext_bytes(),
                auditor_encryption_keys_bytes,
                auditor_balances_bytes,
                proofs.range_proof.range_proof_new_balance,
                proofs.range_proof.range_proof_amount,
                ConfidentialTransfer::serialize_sigma_proof(&proofs.sigma_proof),
                sender_auditor_hint.to_vec(),
            ],
        )
        .into())
    }

    /// Build a `rotate_encryption_key` (or `rotate_encryption_key_and_unfreeze`) entry function payload.
    pub async fn rotate_encryption_key(
        &self,
        sender: &AccountAddress,
        sender_decryption_key: &TwistedEd25519PrivateKey,
        new_sender_decryption_key: &TwistedEd25519PrivateKey,
        token_address: &AccountAddress,
        check_pending_balance_empty: bool,
    ) -> Result<TransactionPayload, AptosError> {
        let chain_id = get_chain_id_byte_for_proofs(self.client).await?;

        let is_frozen = is_pending_balance_frozen(
            self.client,
            sender,
            token_address,
            Some(&self.confidential_asset_module_address),
        )
        .await?;

        let balance = get_balance(
            self.client,
            sender,
            token_address,
            sender_decryption_key,
            Some(&self.confidential_asset_module_address),
        )
        .await?;

        if check_pending_balance_empty && balance.pending_balance() > 0 {
            return Err(AptosError::Internal(
                "Pending balance must be 0 before rotating encryption key",
            ));
        }

        let sender_bytes = sender.to_bytes();
        let token_bytes = token_address.to_bytes();
        let contract_address = parse_module_address(&self.confidential_asset_module_address);

        let key_rotation = ConfidentialKeyRotation::create(
            sender_decryption_key,
            new_sender_decryption_key,
            &balance.available,
            chain_id,
            &sender_bytes,
            contract_address.as_bytes(),
            &token_bytes,
        );

        let (proofs, new_encrypted_available_balance) = key_rotation.authorize_key_rotation();

        let new_public_key_bytes = new_sender_decryption_key.public_key().to_bytes();
        let method = if is_frozen {
            "rotate_encryption_key_and_unfreeze"
        } else {
            "rotate_encryption_key"
        };

        let module_addr = parse_module_address(&self.confidential_asset_module_address);

        Ok(EntryFunction::new(
            MoveModuleId::new(
                module_addr,
                Identifier::new(MODULE_NAME).expect("valid module name"),
            ),
            method,
            vec![],
            vec![
                bcs_addr(token_address),
                new_public_key_bytes.to_vec(),
                new_encrypted_available_balance.get_ciphertext_bytes(),
                proofs.range_proof,
                ConfidentialKeyRotation::serialize_sigma_proof(&proofs.sigma_proof),
            ],
        )
        .into())
    }

    /// Build a `normalize_balance` entry function payload.
    pub async fn normalize_balance(
        &self,
        sender: &AccountAddress,
        sender_decryption_key: &TwistedEd25519PrivateKey,
        token_address: &AccountAddress,
    ) -> Result<TransactionPayload, AptosError> {
        let chain_id = get_chain_id_byte_for_proofs(self.client).await?;

        let balance = get_balance(
            self.client,
            sender,
            token_address,
            sender_decryption_key,
            Some(&self.confidential_asset_module_address),
        )
        .await?;

        let sender_bytes = sender.to_bytes();
        let token_bytes = token_address.to_bytes();
        let contract_address = parse_module_address(&self.confidential_asset_module_address);

        let normalization = ConfidentialNormalization::create(
            sender_decryption_key,
            &balance.available,
            chain_id,
            &sender_bytes,
            contract_address.as_bytes(),
            &token_bytes,
        );

        normalization.create_transaction_payload(
            &sender_bytes,
            &self.confidential_asset_module_address,
            &token_bytes,
        )
    }
}
