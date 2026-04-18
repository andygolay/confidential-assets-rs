// Copyright © Move Industries
// SPDX-License-Identifier: Apache-2.0

//! View functions for querying on-chain confidential asset state.
//!
//! These mirror the TS SDK's `viewFunctions.ts` and call on-chain view functions
//! to retrieve encrypted balances, encryption keys, normalization status, etc.

use crate::crypto::{TwistedEd25519PublicKey, EncryptedAmount, TwistedElGamalCiphertext};
use crate::consts::{DEFAULT_CONFIDENTIAL_COIN_MODULE_ADDRESS, MODULE_NAME};

/// A trait for making view function calls to the Movement blockchain.
///
/// Implement this with your preferred HTTP client (e.g., reqwest) to call
/// the Movement REST API's `/view` endpoint.
pub trait MovementClient {
    /// Call a view function on-chain and return the BCS-decoded result as bytes.
    /// The implementor is responsible for deserializing the response.
    fn view(
        &self,
        module_address: &str,
        module_name: &str,
        function_name: &str,
        type_arguments: &[&str],
        arguments: &[Vec<u8>],
    ) -> impl std::future::Future<Output = Result<Vec<Vec<u8>>, ViewFunctionError>> + Send;
}

/// Error type for view function calls.
#[derive(Debug, thiserror::Error)]
pub enum ViewFunctionError {
    #[error("RPC error: {0}")]
    RpcError(String),
    #[error("Deserialization error: {0}")]
    DeserializationError(String),
    #[error("No auditor set for token")]
    NoAuditor,
}

/// Represents a confidential balance with both available and pending encrypted amounts.
#[derive(Debug, Clone)]
pub struct ConfidentialBalance {
    pub available: EncryptedAmount,
    pub pending: EncryptedAmount,
}

impl ConfidentialBalance {
    /// Get the decrypted available balance amount.
    pub fn available_balance(&self) -> u64 {
        self.available.get_amount()
    }

    /// Get the decrypted pending balance amount.
    pub fn pending_balance(&self) -> u64 {
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

/// Parameters for view function calls.
#[derive(Debug, Clone)]
pub struct ViewFunctionParams<'a> {
    pub account_address: &'a [u8; 32],
    pub token_address: &'a [u8; 32],
    pub module_address: Option<&'a str>,
    pub ledger_version: Option<u64>,
}

/// Get the confidential balance for an account.
///
/// Calls on-chain `pending_balance` and `actual_balance` view functions,
/// decrypts the ciphertexts using the provided decryption key.
pub async fn get_balance(
    client: &dyn MovementClient,
    account_address: &[u8; 32],
    token_address: &[u8; 32],
    decryption_key: &crate::crypto::TwistedEd25519PrivateKey,
    module_address: Option<&str>,
) -> Result<ConfidentialBalance, ViewFunctionError> {
    let mod_addr = module_address.unwrap_or(DEFAULT_CONFIDENTIAL_COIN_MODULE_ADDRESS);

    // Fetch pending balance ciphertext
    let pending_bytes = client.view(
        mod_addr,
        MODULE_NAME,
        "pending_balance",
        &[],
        &[account_address.to_vec(), token_address.to_vec()],
    ).await?;

    // Fetch available balance ciphertext
    let available_bytes = client.view(
        mod_addr,
        MODULE_NAME,
        "actual_balance",
        &[],
        &[account_address.to_vec(), token_address.to_vec()],
    ).await?;

    // Deserialize ciphertexts and create encrypted amounts
    let pending_ct = deserialize_ciphertext_chunks(&pending_bytes)?;
    let available_ct = deserialize_ciphertext_chunks(&available_bytes)?;

    let pending = EncryptedAmount::from_ciphertext_and_private_key(&pending_ct, decryption_key);
    let available = EncryptedAmount::from_ciphertext_and_private_key(&available_ct, decryption_key);

    Ok(ConfidentialBalance { available, pending })
}

/// Check if a user's balance is normalized.
pub async fn is_balance_normalized(
    client: &dyn MovementClient,
    account_address: &[u8; 32],
    token_address: &[u8; 32],
    module_address: Option<&str>,
) -> Result<bool, ViewFunctionError> {
    let mod_addr = module_address.unwrap_or(DEFAULT_CONFIDENTIAL_COIN_MODULE_ADDRESS);
    let result = client.view(
        mod_addr,
        MODULE_NAME,
        "is_normalized",
        &[],
        &[account_address.to_vec(), token_address.to_vec()],
    ).await?;

    // Expect a single bool byte
    result.first()
        .and_then(|v| v.first())
        .map(|&b| b != 0)
        .ok_or_else(|| ViewFunctionError::DeserializationError("expected bool".into()))
}

/// Check if a user's pending balance is frozen.
pub async fn is_pending_balance_frozen(
    client: &dyn MovementClient,
    account_address: &[u8; 32],
    token_address: &[u8; 32],
    module_address: Option<&str>,
) -> Result<bool, ViewFunctionError> {
    let mod_addr = module_address.unwrap_or(DEFAULT_CONFIDENTIAL_COIN_MODULE_ADDRESS);
    let result = client.view(
        mod_addr,
        MODULE_NAME,
        "is_frozen",
        &[],
        &[account_address.to_vec(), token_address.to_vec()],
    ).await?;

    result.first()
        .and_then(|v| v.first())
        .map(|&b| b != 0)
        .ok_or_else(|| ViewFunctionError::DeserializationError("expected bool".into()))
}

/// Check if a user has registered a confidential asset balance.
pub async fn has_user_registered(
    client: &dyn MovementClient,
    account_address: &[u8; 32],
    token_address: &[u8; 32],
    module_address: Option<&str>,
) -> Result<bool, ViewFunctionError> {
    let mod_addr = module_address.unwrap_or(DEFAULT_CONFIDENTIAL_COIN_MODULE_ADDRESS);
    let result = client.view(
        mod_addr,
        MODULE_NAME,
        "has_confidential_asset_store",
        &[],
        &[account_address.to_vec(), token_address.to_vec()],
    ).await?;

    result.first()
        .and_then(|v| v.first())
        .map(|&b| b != 0)
        .ok_or_else(|| ViewFunctionError::DeserializationError("expected bool".into()))
}

/// Get the encryption key for an account for a given token.
pub async fn get_encryption_key(
    client: &dyn MovementClient,
    account_address: &[u8; 32],
    token_address: &[u8; 32],
    module_address: Option<&str>,
) -> Result<TwistedEd25519PublicKey, ViewFunctionError> {
    let mod_addr = module_address.unwrap_or(DEFAULT_CONFIDENTIAL_COIN_MODULE_ADDRESS);
    let result = client.view(
        mod_addr,
        MODULE_NAME,
        "encryption_key",
        &[],
        &[account_address.to_vec(), token_address.to_vec()],
    ).await?;

    // Expect 32-byte compressed Ristretto point
    let key_bytes = result.first()
        .ok_or_else(|| ViewFunctionError::DeserializationError("missing encryption key".into()))?;

    TwistedEd25519PublicKey::from_bytes(key_bytes)
        .map_err(|e| ViewFunctionError::DeserializationError(format!("invalid encryption key: {}", e)))
}

/// Get the global auditor encryption key for a token, if set.
pub async fn get_global_auditor_encryption_key(
    client: &dyn MovementClient,
    token_address: &[u8; 32],
    module_address: Option<&str>,
) -> Result<Option<TwistedEd25519PublicKey>, ViewFunctionError> {
    let mod_addr = module_address.unwrap_or(DEFAULT_CONFIDENTIAL_COIN_MODULE_ADDRESS);
    let result = client.view(
        mod_addr,
        MODULE_NAME,
        "get_auditor",
        &[],
        &[token_address.to_vec()],
    ).await?;

    // Move Option: if empty or zero bytes, no auditor set
    let bytes = result.first()
        .ok_or_else(|| ViewFunctionError::DeserializationError("missing auditor response".into()))?;

    if bytes.is_empty() {
        return Ok(None);
    }

    match TwistedEd25519PublicKey::from_bytes(bytes) {
        Ok(key) => Ok(Some(key)),
        Err(_) => Ok(None),
    }
}

/// Get the chain ID byte used in Fiat-Shamir proof transcripts.
pub async fn get_chain_id_byte_for_proofs(
    client: &dyn MovementClient,
) -> Result<u8, ViewFunctionError> {
    let result = client.view(
        "0x1",
        "chain_id",
        "get",
        &[],
        &[],
    ).await?;

    result.first()
        .and_then(|v| v.first())
        .map(|&b| b)
        .ok_or_else(|| ViewFunctionError::DeserializationError("expected chain_id u8".into()))
}

/// Deserialize BCS-encoded ciphertext chunks from a view response.
/// Each chunk is a pair of 32-byte Ristretto points (left, right).
fn deserialize_ciphertext_chunks(chunks_bytes: &[Vec<u8>]) -> Result<Vec<TwistedElGamalCiphertext>, ViewFunctionError> {
    let mut ciphertexts = Vec::new();
    for chunk in chunks_bytes {
        if chunk.len() != 64 {
            return Err(ViewFunctionError::DeserializationError(
                format!("expected 64-byte ciphertext chunk, got {}", chunk.len())
            ));
        }
        let mut left = [0u8; 32];
        let mut right = [0u8; 32];
        left.copy_from_slice(&chunk[..32]);
        right.copy_from_slice(&chunk[32..]);
        ciphertexts.push(TwistedElGamalCiphertext::new(left, right));
    }
    Ok(ciphertexts)
}
