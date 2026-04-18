// Copyright © Move Industries
// SPDX-License-Identifier: Apache-2.0

//! # Confidential Assets SDK
//!
//! Rust SDK for Movement Network confidential asset operations:
//! - Twisted Ed25519 key management
//! - Twisted ElGamal encryption/decryption
//! - Confidential registration, transfer, withdrawal, key rotation, normalization
//! - Fiat-Shamir sigma proofs
//! - Range proofs (placeholder for bulletproofs integration)
//!
//! TODO: Switch `aptos_sdk` references → `movement_sdk` once the fork is ready.
//!
//! ## Structure
//!
//! - `crypto` — Core cryptographic primitives (keys, encryption, proofs)
//! - `api` — High-level API for building confidential asset transactions
//! - `internal` — Transaction builder and on-chain view functions
//! - `bcs` — BCS serialization helpers
//! - `consts` — Protocol constants
//! - `helpers` — Utility functions
//! - `utils` — Scalar generation utilities

pub mod consts;
pub mod utils;
pub mod helpers;
pub mod bcs;
pub mod crypto;
pub mod internal;
pub mod api;

// Re-export main API types
pub use api::ConfidentialAsset;
pub use internal::transaction_builder::ConfidentialAssetTransactionBuilder;
pub use internal::view_functions::ConfidentialBalance;
pub use crypto::*;
pub use consts::*;
