# confidential-assets-rs

Rust SDK for [Movement Network](https://movementnetwork.xyz) Confidential Asset operations.

## Features

- **Twisted Ed25519** key management (Ristretto-based)
- **Twisted ElGamal** encryption/decryption with chunked amounts
- **Confidential Registration** — ZKPoK of decryption key (full verify)
- **Confidential Transfer** — sender-to-recipient with optional auditor encryption; sigma proof generation + verifier (see parity notes below)
- **Confidential Withdraw** — decrypt and withdraw from confidential balance
- **Key Rotation** — rotate decryption keys with sigma proofs
- **Normalization** — normalize chunked balance representations
- **Fiat-Shamir** domain-separated challenges (`fiat_shamir_challenge_ts` aligned with TS)
- **Range Proofs** — placeholders until WASM/native batch ZKP is wired (matches TS executor gap)

## Dependencies

- `curve25519-dalek` (Ristretto group)
- `sha2` / `sha3`
- `rand` (CSRNG)
- `bcs` (BCS serialization for Move)
- `serde` / `hex`
- `num-bigint` / `num-traits` (weighted scalar combos mod subgroup order, TS-style)

## Usage

```rust
use confidential_assets::crypto::twisted_ed25519::TwistedEd25519PrivateKey;
use confidential_assets::crypto::encrypted_amount::EncryptedAmount;
use confidential_assets::crypto::chunked_amount::ChunkedAmount;

let dk = TwistedEd25519PrivateKey::generate();
let pk = dk.public_key();
let ea = EncryptedAmount::new(ChunkedAmount::from_amount(1000), pk);
assert_eq!(ea.get_amount(), 1000);
```

## TypeScript SDK parity (`../ts-sdk/confidential-assets`)

| Area | TS SDK | This crate |
|------|--------|------------|
| Chunk encoding | `CHUNK_BITS = 16`, balance **8** chunks, transfer **4** chunks | **Same** (`chunked_amount`) |
| `bcsSerializeMoveVectorU8` | `utils/moveBcs` | `bcs_serialize_move_vector_u8` |
| Balance view cache keys + memoization | `utils/memoize` | `memoize` module |
| Variadic Fiat–Shamir | `fiatShamirChallenge` | `fiat_shamir_challenge_ts`, `dst_hash_ts` |
| Transfer sigma (56×32-byte base + auditors) | Full gen + `verifySigmaProof` | **Gen** + `verify_sigma_proof`; responses use weighted limb fixing (`alpha_limbs_lincomb_fixed`) so `lin_comb_pow2` on limb scalars matches aggregate subtraction mod l; **cross-check against TS** on the same inputs before production |
| Range proofs | WASM batch executor | Empty placeholder bytes in `authorize_transfer` until native/WASM integration |
| Withdraw / rotation / normalization verification | Implemented in TS | **Stubs** or simplified checks — align with TS before relying on-chain |

## Status

- ✅ Chunk layout and transfer sigma **serialization** size (`SIGMA_PROOF_TRANSFER_SIZE`)
- ✅ Registration proof verification (Fiat–Shamir transcript)
- ✅ Encryption/decryption tests for chunked amounts (kangaroo path for decryption)
- ✅ Weighted limb responses for transfer σ (α₁, α₃, α₄, α₆) consistent with verifier `lin_comb_pow2`
- 🔲 Range proof bytes (needs TS-compatible batch ZKP)
- 🔲 End-to-end **transfer verify** vs TS on fixed test vectors (recommended before mainnet)
- 🔲 Withdraw / rotation / normalization verifiers vs TS

## License

Apache-2.0 © Move Industries
