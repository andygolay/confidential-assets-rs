// Copyright © Move Industries
// SPDX-License-Identifier: Apache-2.0

//! High-level confidential asset API.
//!
//! Mirrors the TS SDK's `confidentialAsset.ts`. Wraps the transaction builder
//! and view functions into a convenient interface.

use crate::crypto::{
    TwistedEd25519PrivateKey, TwistedEd25519PublicKey, ConfidentialNormalization,
};
use crate::consts::DEFAULT_CONFIDENTIAL_COIN_MODULE_ADDRESS;
use crate::internal::transaction_builder::{ConfidentialAssetTransactionBuilder, TransactionPayload};
use crate::internal::view_functions::{
    MovementClient, ViewFunctionError, ConfidentialBalance,
    get_balance, get_encryption_key, get_global_auditor_encryption_key,
    is_balance_normalized, is_pending_balance_frozen, get_chain_id_byte_for_proofs,
};

/// High-level API for confidential asset operations.
///
/// This struct wraps the transaction builder and provides methods corresponding
/// to each confidential asset operation (register, deposit, withdraw, transfer, etc.).
///
/// Transaction submission is left to the caller — this API only builds the payloads.
/// Sign and submit using your preferred Movement client.
pub struct ConfidentialAsset<C: MovementClient> {
    pub transaction: ConfidentialAssetTransactionBuilder<C>,
    pub with_fee_payer: bool,
}

impl<C: MovementClient + Sync> ConfidentialAsset<C> {
    pub fn new(client: C, confidential_asset_module_address: Option<&str>, with_fee_payer: bool) -> Self {
        Self {
            transaction: ConfidentialAssetTransactionBuilder::new(client, confidential_asset_module_address),
            with_fee_payer,
        }
    }

    /// Get the confidential balance for an account.
    pub async fn get_balance(
        &self,
        account_address: &[u8; 32],
        token_address: &[u8; 32],
        decryption_key: &TwistedEd25519PrivateKey,
    ) -> Result<ConfidentialBalance, ViewFunctionError> {
        get_balance(
            &self.transaction.client,
            account_address,
            token_address,
            decryption_key,
            Some(&self.transaction.confidential_asset_module_address),
        ).await
    }

    /// Build a register balance transaction.
    pub async fn register_balance(
        &self,
        sender: &[u8; 32],
        token_address: &[u8; 32],
        decryption_key: &TwistedEd25519PrivateKey,
    ) -> Result<TransactionPayload, ViewFunctionError> {
        self.transaction.register_balance(sender, token_address, decryption_key).await
    }

    /// Build a deposit transaction.
    pub fn deposit(
        &self,
        sender: &[u8; 32],
        token_address: &[u8; 32],
        amount: u64,
        recipient: Option<&[u8; 32]>,
    ) -> Result<TransactionPayload, ViewFunctionError> {
        self.transaction.deposit(sender, token_address, amount, recipient)
    }

    /// Build a withdraw transaction.
    pub async fn withdraw(
        &self,
        sender: &[u8; 32],
        token_address: &[u8; 32],
        amount: u64,
        sender_decryption_key: &TwistedEd25519PrivateKey,
        recipient: Option<&[u8; 32]>,
    ) -> Result<TransactionPayload, ViewFunctionError> {
        self.transaction.withdraw(sender, token_address, amount, sender_decryption_key, recipient).await
    }

    /// Build a transfer transaction.
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
        self.transaction.transfer(
            sender,
            recipient,
            token_address,
            amount,
            sender_decryption_key,
            additional_auditor_encryption_keys,
            sender_auditor_hint,
        ).await
    }

    /// Build a rollover pending balance transaction.
    pub async fn rollover_pending_balance(
        &self,
        sender: &[u8; 32],
        token_address: &[u8; 32],
        sender_decryption_key: Option<&TwistedEd25519PrivateKey>,
        with_freeze_balance: bool,
    ) -> Result<Vec<TransactionPayload>, ViewFunctionError> {
        let mut payloads = Vec::new();

        // Check if normalization is needed
        let is_norm = is_balance_normalized(
            &self.transaction.client,
            sender,
            token_address,
            Some(&self.transaction.confidential_asset_module_address),
        ).await?;

        if !is_norm {
            let dk = sender_decryption_key.ok_or_else(|| {
                ViewFunctionError::RpcError(
                    "Rollover failed. Balance is not normalized and no sender decryption key was provided.".into(),
                )
            })?;

            let normalize_payload = self.transaction.normalize_balance(sender, dk, token_address).await?;
            payloads.push(normalize_payload);
        }

        let rollover_payload = self.transaction.rollover_pending_balance(
            sender,
            token_address,
            with_freeze_balance,
            false, // already checked above
        ).await?;
        payloads.push(rollover_payload);

        Ok(payloads)
    }

    /// Build a rotate encryption key transaction (with optional rollover first).
    pub async fn rotate_encryption_key(
        &self,
        sender: &[u8; 32],
        sender_decryption_key: &TwistedEd25519PrivateKey,
        new_sender_decryption_key: &TwistedEd25519PrivateKey,
        token_address: &[u8; 32],
    ) -> Result<Vec<TransactionPayload>, ViewFunctionError> {
        let mut payloads = Vec::new();

        // Check if pending balance needs rollover
        let balance = self.get_balance(sender, token_address, sender_decryption_key).await?;
        if balance.pending_balance() > 0 {
            let rollover_payloads = self.rollover_pending_balance(
                sender,
                token_address,
                Some(sender_decryption_key),
                true, // freeze after rollover
            ).await?;
            payloads.extend(rollover_payloads);
        }

        let rotate_payload = self.transaction.rotate_encryption_key(
            sender,
            sender_decryption_key,
            new_sender_decryption_key,
            token_address,
            true,
        ).await?;
        payloads.push(rotate_payload);

        Ok(payloads)
    }

    /// Build a normalize balance transaction.
    pub async fn normalize_balance(
        &self,
        sender: &[u8; 32],
        sender_decryption_key: &TwistedEd25519PrivateKey,
        token_address: &[u8; 32],
    ) -> Result<TransactionPayload, ViewFunctionError> {
        self.transaction.normalize_balance(sender, sender_decryption_key, token_address).await
    }

    /// Check if a user has registered a confidential balance.
    pub async fn has_user_registered(
        &self,
        account_address: &[u8; 32],
        token_address: &[u8; 32],
    ) -> Result<bool, ViewFunctionError> {
        crate::internal::view_functions::has_user_registered(
            &self.transaction.client,
            account_address,
            token_address,
            Some(&self.transaction.confidential_asset_module_address),
        ).await
    }

    /// Check if a user's balance is normalized.
    pub async fn is_balance_normalized(
        &self,
        account_address: &[u8; 32],
        token_address: &[u8; 32],
    ) -> Result<bool, ViewFunctionError> {
        is_balance_normalized(
            &self.transaction.client,
            account_address,
            token_address,
            Some(&self.transaction.confidential_asset_module_address),
        ).await
    }

    /// Check if a user's pending balance is frozen.
    pub async fn is_pending_balance_frozen(
        &self,
        account_address: &[u8; 32],
        token_address: &[u8; 32],
    ) -> Result<bool, ViewFunctionError> {
        is_pending_balance_frozen(
            &self.transaction.client,
            account_address,
            token_address,
            Some(&self.transaction.confidential_asset_module_address),
        ).await
    }

    /// Get the encryption key for an account.
    pub async fn get_encryption_key(
        &self,
        account_address: &[u8; 32],
        token_address: &[u8; 32],
    ) -> Result<TwistedEd25519PublicKey, ViewFunctionError> {
        get_encryption_key(
            &self.transaction.client,
            account_address,
            token_address,
            Some(&self.transaction.confidential_asset_module_address),
        ).await
    }

    /// Get the asset auditor encryption key for a token.
    pub async fn get_asset_auditor_encryption_key(
        &self,
        token_address: &[u8; 32],
    ) -> Result<Option<TwistedEd25519PublicKey>, ViewFunctionError> {
        get_global_auditor_encryption_key(
            &self.transaction.client,
            token_address,
            Some(&self.transaction.confidential_asset_module_address),
        ).await
    }
}
