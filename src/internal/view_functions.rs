// Copyright © Move Industries
// SPDX-License-Identifier: Apache-2.0

//! View functions for querying on-chain confidential asset state.
//!
//! Mirrors the TS SDK's `viewFunctions.ts`. Uses the Aptos Rust SDK client
//! to call on-chain view functions for encrypted balances, encryption keys, etc.
//!
//! TODO: Switch `aptos_sdk::Aptos` → `movement_sdk::Movement` once the fork is ready.

use crate::consts::{DEFAULT_CONFIDENTIAL_COIN_MODULE_ADDRESS, MODULE_NAME};
use crate::crypto::{
    encrypted_amount::EncryptedAmount, TwistedEd25519PublicKey, TwistedElGamalCiphertext,
};
use aptos_sdk::{types::AccountAddress, Aptos, AptosError};

/// Represents a confidential balance with both available and pending encrypted amounts.
#[derive(Debug, Clone)]
pub struct ConfidentialBalance {
    /// Available (actual) encrypted balance.
    pub available: EncryptedAmount,
    /// Pending encrypted balance.
    pub pending: EncryptedAmount,
}

impl ConfidentialBalance {
    /// Get the decrypted available balance amount.
    pub fn available_balance(&self) -> u128 {
        self.available.get_amount()
    }

    /// Get the decrypted pending balance amount.
    pub fn pending_balance(&self) -> u128 {
        self.pending.get_amount()
    }

    /// Get the encrypted available balance ciphertext.
    pub fn available_balance_ciphertext(&self) -> &[TwistedElGamalCiphertext] {
        self.available.get_ciphertext()
    }

    /// Get the encrypted pending balance ciphertext.
    pub fn pending_balance_ciphertext(&self) -> &[TwistedElGamalCiphertext] {
        self.pending.get_ciphertext()
    }
}

/// Helper to build a fully qualified function path.
fn func_path(module_address: &str, function_name: &str) -> String {
    format!("{}::{}::{}", module_address, MODULE_NAME, function_name)
}

/// BCS-encode an AccountAddress argument for view function calls.
fn bcs_address(addr: &AccountAddress) -> Vec<u8> {
    bcs::to_bytes(addr).unwrap_or_default()
}

/// Get the confidential balance for an account.
///
/// Calls on-chain `pending_balance` and `actual_balance` view functions,
/// then decrypts the ciphertexts using the provided decryption key.
// TODO: Switch `Aptos` → `Movement`
pub async fn get_balance(
    client: &Aptos,
    account_address: &AccountAddress,
    token_address: &AccountAddress,
    decryption_key: &crate::crypto::TwistedEd25519PrivateKey,
    module_address: Option<&str>,
) -> Result<ConfidentialBalance, AptosError> {
    let mod_addr = module_address.unwrap_or(DEFAULT_CONFIDENTIAL_COIN_MODULE_ADDRESS);

    // Fetch pending and available balances in parallel
    let pending_fn = func_path(mod_addr, "pending_balance");
    let actual_fn = func_path(mod_addr, "actual_balance");
    let args = vec![bcs_address(account_address), bcs_address(token_address)];
    let (pending_result, available_result) = tokio::join!(
        client.view_bcs_raw(&pending_fn, vec![], args.clone()),
        client.view_bcs_raw(&actual_fn, vec![], args),
    );

    let pending_bytes = pending_result?;
    let available_bytes = available_result?;

    // Deserialize ciphertext chunks and create encrypted amounts
    let pending_ct = deserialize_ciphertext_chunks(&pending_bytes)?;
    let available_ct = deserialize_ciphertext_chunks(&available_bytes)?;

    let pending = EncryptedAmount::from_ciphertext_and_private_key(&pending_ct, decryption_key)
        .map_err(|e| AptosError::Internal(format!("failed to decrypt pending: {}", e)))?;
    let available = EncryptedAmount::from_ciphertext_and_private_key(&available_ct, decryption_key)
        .map_err(|e| AptosError::Internal(format!("failed to decrypt available: {}", e)))?;

    Ok(ConfidentialBalance { available, pending })
}

/// Check if a user's balance is normalized.
// TODO: Switch `Aptos` → `Movement`
pub async fn is_balance_normalized(
    client: &Aptos,
    account_address: &AccountAddress,
    token_address: &AccountAddress,
    module_address: Option<&str>,
) -> Result<bool, AptosError> {
    let mod_addr = module_address.unwrap_or(DEFAULT_CONFIDENTIAL_COIN_MODULE_ADDRESS);
    client
        .view_bcs(
            &func_path(mod_addr, "is_normalized"),
            vec![],
            vec![bcs_address(account_address), bcs_address(token_address)],
        )
        .await
}

/// Check if a user's pending balance is frozen.
// TODO: Switch `Aptos` → `Movement`
pub async fn is_pending_balance_frozen(
    client: &Aptos,
    account_address: &AccountAddress,
    token_address: &AccountAddress,
    module_address: Option<&str>,
) -> Result<bool, AptosError> {
    let mod_addr = module_address.unwrap_or(DEFAULT_CONFIDENTIAL_COIN_MODULE_ADDRESS);
    client
        .view_bcs(
            &func_path(mod_addr, "is_frozen"),
            vec![],
            vec![bcs_address(account_address), bcs_address(token_address)],
        )
        .await
}

/// Check if a user has registered a confidential asset balance.
// TODO: Switch `Aptos` → `Movement`
pub async fn has_user_registered(
    client: &Aptos,
    account_address: &AccountAddress,
    token_address: &AccountAddress,
    module_address: Option<&str>,
) -> Result<bool, AptosError> {
    let mod_addr = module_address.unwrap_or(DEFAULT_CONFIDENTIAL_COIN_MODULE_ADDRESS);
    client
        .view_bcs(
            &func_path(mod_addr, "has_confidential_asset_store"),
            vec![],
            vec![bcs_address(account_address), bcs_address(token_address)],
        )
        .await
}

/// Get the encryption key for an account for a given token.
// TODO: Switch `Aptos` → `Movement`
pub async fn get_encryption_key(
    client: &Aptos,
    account_address: &AccountAddress,
    token_address: &AccountAddress,
    module_address: Option<&str>,
) -> Result<TwistedEd25519PublicKey, AptosError> {
    let mod_addr = module_address.unwrap_or(DEFAULT_CONFIDENTIAL_COIN_MODULE_ADDRESS);

    // View returns `CompressedPubkey { point: { data: bytes } }`
    let result: Vec<u8> = client
        .view_bcs(
            &func_path(mod_addr, "encryption_key"),
            vec![],
            vec![bcs_address(account_address), bcs_address(token_address)],
        )
        .await?;

    {
        let arr: [u8; 32] = result
            .try_into()
            .map_err(|_| AptosError::Internal("encryption key not 32 bytes".to_string()))?;
        TwistedEd25519PublicKey::from_bytes(&arr)
    }
    .map_err(|e| AptosError::Internal(format!("invalid encryption key: {}", e)))
}

/// Get the global auditor encryption key for a token, if set.
// TODO: Switch `Aptos` → `Movement`
pub async fn get_global_auditor_encryption_key(
    client: &Aptos,
    token_address: &AccountAddress,
    module_address: Option<&str>,
) -> Result<Option<TwistedEd25519PublicKey>, AptosError> {
    let mod_addr = module_address.unwrap_or(DEFAULT_CONFIDENTIAL_COIN_MODULE_ADDRESS);

    // `get_auditor` returns `Option<CompressedPubkey>` — BCS-encoded
    let result: Option<Vec<u8>> = client
        .view_bcs(
            &func_path(mod_addr, "get_auditor"),
            vec![],
            vec![bcs_address(token_address)],
        )
        .await?;

    match result {
        Some(bytes) if !bytes.is_empty() => {
            match {
                let arr: [u8; 32] = bytes
                    .try_into()
                    .map_err(|_| AptosError::Internal("auditor key not 32 bytes".to_string()))?;
                TwistedEd25519PublicKey::from_bytes(&arr)
            } {
                Ok(key) => Ok(Some(key)),
                Err(_) => Ok(None),
            }
        }
        _ => Ok(None),
    }
}

/// Get the chain ID byte used in Fiat-Shamir proof transcripts.
// TODO: Switch `Aptos` → `Movement`
pub async fn get_chain_id_byte_for_proofs(client: &Aptos) -> Result<u8, AptosError> {
    let id: u8 = client
        .view_bcs("0x1::chain_id::get", vec![], vec![])
        .await?;
    Ok(id)
}

/// Deserialize BCS-encoded ciphertext chunks from a view response.
/// Each chunk is a pair of 32-byte Ristretto points (left, right).
fn deserialize_ciphertext_chunks(
    bytes: &[u8],
) -> Result<Vec<TwistedElGamalCiphertext>, AptosError> {
    // The on-chain response is a `CompressedConfidentialBalance` containing
    // chunks of (left, right) pairs as 64-byte blocks.
    if bytes.len() % 64 != 0 {
        return Err(AptosError::Internal(format!(
            "ciphertext chunk size not multiple of 64 (got {})",
            bytes.len()
        )));
    }

    let mut ciphertexts = Vec::new();
    for chunk in bytes.chunks_exact(64) {
        use curve25519_dalek::ristretto::CompressedRistretto;
        
        let left = CompressedRistretto::from_slice(&chunk[..32])
            .map_err(|e| AptosError::Internal(format!("invalid left point: {}", e)))?
            .decompress()
            .ok_or_else(|| AptosError::Internal("invalid left point in ciphertext".to_string()))?;
        let right = CompressedRistretto::from_slice(&chunk[32..])
            .map_err(|e| AptosError::Internal(format!("invalid right point: {}", e)))?
            .decompress()
            .ok_or_else(|| AptosError::Internal("invalid right point in ciphertext".to_string()))?;
        ciphertexts.push(TwistedElGamalCiphertext::new(left, right));
    }
    Ok(ciphertexts)
}
