# confidential-assets-rs

Rust SDK for [Movement Network](https://movementnetwork.xyz) confidential asset operations on MoveVM.

## Features

- **Twisted Ed25519** key management (Ristretto-based)
- **Twisted ElGamal** encryption/decryption with chunked amounts
- **Confidential Registration** — ZKPoK of decryption key
- **Confidential Transfer** — sender-to-recipient with optional auditor encryption
- **Confidential Withdraw** — decrypt and withdraw from confidential balance
- **Key Rotation** — rotate decryption keys with sigma proofs
- **Normalization** — normalize chunked balance representations
- **Fiat-Shamir** domain-separated challenges (SHA-512)
- **Range Proofs** — interface stubs for Bulletproofs integration

## Dependencies

- `curve25519-dalek` (Ristretto group)
- `sha2` / `sha3`
- `rand` (CSRNG)
- `bcs` (BCS serialization for Move)
- `serde` / `hex`

## Usage

```rust
use confidential_assets::crypto::twisted_ed25519::TwistedEd25519PrivateKey;
use confidential_assets::crypto::encrypted_amount::EncryptedAmount;
use confidential_assets::crypto::chunked_amount::ChunkedAmount;

let dk = TwistedEd25519PrivateKey::generate();
let pk = dk.public_key();
let ea = EncryptedAmount::new(ChunkedAmount::from_amount(1000), &pk);
assert_eq!(ea.get_amount(), 1000);
```

## Status

- ✅ Sigma proof generation for all operations
- ✅ Encryption/decryption round-trip
- ✅ Serialization/deserialization
- 🔲 Range proof integration (needs `bulletproofs` crate)
- 🔲 Full sigma proof verification (currently stubbed)

## License

Apache-2.0 © Move Industries
