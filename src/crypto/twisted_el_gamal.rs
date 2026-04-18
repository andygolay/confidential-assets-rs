// Copyright © Move Industries
// SPDX-License-Identifier: Apache-2.0
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use crate::crypto::h_ristretto;
use crate::crypto::twisted_ed25519::{TwistedEd25519PrivateKey, TwistedEd25519PublicKey};
use crate::utils::ed25519_gen_random;
/// Twisted ElGamal ciphertext: C = r*G + v*H, D = r*PK
#[derive(Clone, Debug)]
pub struct TwistedElGamalCiphertext {
    /// C = r*G + v*H  (the "left" component)
    pub c: RistrettoPoint,
    /// D = r*PK  (the "right" component)
    pub d: RistrettoPoint,
}
impl TwistedElGamalCiphertext {
    pub fn new(c: RistrettoPoint, d: RistrettoPoint) -> Self {
        Self { c, d }
    }
    /// Get the C component bytes (32 bytes).
    pub fn c_bytes(&self) -> [u8; 32] {
        self.c.compress().to_bytes()
    }
    /// Get the D component bytes (32 bytes).
    pub fn d_bytes(&self) -> [u8; 32] {
        self.d.compress().to_bytes()
    }
    /// Serialize ciphertext as C || D (64 bytes).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(64);
        out.extend_from_slice(&self.c_bytes());
        out.extend_from_slice(&self.d_bytes());
        out
    }
    /// Deserialize ciphertext from C || D (64 bytes).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() != 64 {
            return Err(format!("Expected 64 bytes, got {}", bytes.len()));
        }
        let c_bytes: [u8; 32] = bytes[0..32].try_into().map_err(|_| "slice error")?;
        let d_bytes: [u8; 32] = bytes[32..64].try_into().map_err(|_| "slice error")?;
        use curve25519_dalek::ristretto::CompressedRistretto;
        let c = CompressedRistretto(c_bytes).decompress().ok_or("Invalid C point")?;
        let d = CompressedRistretto(d_bytes).decompress().ok_or("Invalid D point")?;
        Ok(Self { c, d })
    }
}
/// Twisted ElGamal encryption/decryption operations.
pub struct TwistedElGamal;
impl TwistedElGamal {
    /// Encrypt a scalar value v under a public key.
    /// Returns ciphertext (C, D) where C = r*G + v*H, D = r*PK.
    pub fn encrypt_with_pk(value: Scalar, public_key: &TwistedEd25519PublicKey) -> TwistedElGamalCiphertext {
        let r = ed25519_gen_random();
        let g = RISTRETTO_BASEPOINT_POINT;
        let h = h_ristretto();
        let c = r * g + value * h;
        let d = r * public_key.as_point();
        TwistedElGamalCiphertext::new(c, d)
    }
    /// Encrypt a single ciphertext for one chunk.
    pub fn encrypt_chunk(value: Scalar, public_key: &TwistedEd25519PublicKey, r: Scalar) -> TwistedElGamalCiphertext {
        let g = RISTRETTO_BASEPOINT_POINT;
        let h = h_ristretto();
        let c = r * g + value * h;
        let d = r * public_key.as_point();
        TwistedElGamalCiphertext::new(c, d)
    }
    /// Decrypt a ciphertext using the private key via Pollard's kangaroo (DLOG).
    /// For the Rust SDK we provide the homomorphic decryption (for when value is known).
    /// Full DLOG requires a kangaroo-table implementation.
    pub fn decrypt_with_pk(
        ciphertext: &TwistedElGamalCiphertext,
        private_key: &TwistedEd25519PrivateKey,
) -> RistrettoPoint {
        // shared_secret = dk * C - but we actually compute the value point:
        // C = r*G + v*H, D = r*PK
        // dk * C - dk * r*G ... no
        // Actually: v*H = C - dk^{-1} * D * G  ... wait:
        // D = r*PK = r*dk*G
        // dk*D = dk*r*dk*G = r*dk^2*G ... that's wrong
        //
        // Correct approach:
        // shared_secret = dk^{-1} * D  (no, that's r*G)
        // v*H = C - r*G where r*G = dk^{-1} * D ... no
        //
        // Actually from TS: decrypt computes C - dk * (dk_inv * D) = C - D*dk_inv^(-1)
        // Hmm, let me think:
        // D = r * PK where PK = dk * G
        // So dk_inv * D = dk_inv * r * dk * G = r * G
        // Therefore: C - r*G = v*H
        // So: v*H = C - dk_inv * D  ... wait dk_inv = 1/dk
        // dk_inv * D = (1/dk) * (r * dk * G) = r * G
        // So v*H = C - r*G = C - dk_inv * D
        // where dk_inv = Scalar::invert(dk)
        let dk = private_key.as_scalar();
        let dk_inv = dk.invert();
        let r_g = dk_inv * ciphertext.d;
        let v_h = ciphertext.c - r_g;
        v_h
        // To get the scalar v from v_h = v*H, we need DLOG which is the kangaroo step.
        // For chunked amounts where v fits in 64 bits, this is feasible.
    }
    /// Homomorphic addition of two ciphertexts.
    pub fn add(a: &TwistedElGamalCiphertext, b: &TwistedElGamalCiphertext) -> TwistedElGamalCiphertext {
        TwistedElGamalCiphertext::new(a.c + b.c, a.d + b.d)
    }
    /// Homomorphic subtraction of two ciphertexts.
    pub fn sub(a: &TwistedElGamalCiphertext, b: &TwistedElGamalCiphertext) -> TwistedElGamalCiphertext {
        TwistedElGamalCiphertext::new(a.c - b.c, a.d - b.d)
    }
    /// Re-encrypt a ciphertext under a new public key (for key rotation).
    /// Given C = r*G + v*H, D = r*old_pk
    /// New: C' = C + r'*G, D' = D + r'*new_pk
    /// Wait, that's not quite right. For key rotation we need:
    /// C stays the same (amount doesn't change)
    /// D' = r * new_pk
    /// But we don't know r. So we use:
    /// C' = C + delta_r * G  (but then we change the randomness)
    /// Actually the TS code does it differently.
    ///
    /// For re-keying: new_D = old_D + (old_pk_inv * new_pk - 1) * ...
    /// Actually, the simplest approach: we know dk_old, we decrypt v*H, then re-encrypt.
    /// But that loses the homomorphic property.
    ///
    // The actual key rotation in the TS code:
    // It creates new randomness and re-encrypts from the decrypted value.
    // See confidential_key_rotation.ts for the actual logic.
}

