// Copyright © Move Industries
// SPDX-License-Identifier: Apache-2.0

pub mod chunked_amount;
pub mod confidential_key_rotation;
pub mod confidential_normalization;
pub mod confidential_registration;
pub mod confidential_transfer;
pub mod confidential_withdraw;
pub mod encrypted_amount;
pub mod fiat_shamir;
pub mod range_proof;
pub mod scalar_ts;
pub mod twisted_ed25519;
pub mod twisted_el_gamal;

pub use chunked_amount::*;
pub use confidential_key_rotation::*;
pub use confidential_normalization::*;
pub use confidential_registration::*;
pub use confidential_transfer::*;
pub use confidential_withdraw::*;
pub use encrypted_amount::*;
pub use fiat_shamir::*;
pub use scalar_ts::{
    fix_alpha_limbs_weighted_lincomb, lin_comb_pow2_mod_l, mul_mod_l, scalar_pow2_mod_l, sub_mod_l,
    sub_mul_mod_l,
};
pub use twisted_ed25519::*;
pub use twisted_el_gamal::*;

use curve25519_dalek::ristretto::RistrettoPoint;

/// The secondary generator H (used for amount commitments).
/// This is a fixed RistrettoPoint derived from a domain-separated hash of "H_RISTRETTO".
/// Must match the on-chain Move constant exactly.
pub fn h_ristretto() -> RistrettoPoint {
    use sha2::{Digest, Sha512};

    let mut hasher = Sha512::new();
    hasher.update(b"MovementConfidentialAsset_H_RISTRETTO");
    let hash = hasher.finalize();
    RistrettoPoint::from_uniform_bytes(&hash.into())
}
