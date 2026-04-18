// Tests for confidential proof generation and verification
// Ported from confidential-assets/tests/units/confidentialProofs.test.ts
// Only non-skipped tests are included.
use confidential_assets::crypto::chunked_amount::{
    ChunkedAmount, AVAILABLE_BALANCE_CHUNK_COUNT, CHUNK_BITS,
};
use confidential_assets::crypto::confidential_key_rotation::ConfidentialKeyRotation;
use confidential_assets::crypto::confidential_normalization::ConfidentialNormalization;
use confidential_assets::crypto::confidential_transfer::ConfidentialTransfer;
use confidential_assets::crypto::confidential_withdraw::ConfidentialWithdraw;
use confidential_assets::crypto::encrypted_amount::EncryptedAmount;
use confidential_assets::crypto::twisted_ed25519::TwistedEd25519PrivateKey;

const ALICE_BALANCE: u128 = 18446744073709551716u128;
const TEST_CHAIN_ID: u8 = 1;

fn test_sender_addr() -> Vec<u8> {
    vec![0u8; 32]
}
fn test_token_addr() -> Vec<u8> {
    vec![0u8; 32]
}
fn test_contract_addr() -> Vec<u8> {
    let mut a = vec![0u8; 32];
    a[31] = 0x07;
    a
}

#[test]
fn generate_withdraw_sigma_proof() {
    let alice_dk = TwistedEd25519PrivateKey::generate();
    let alice_pk = alice_dk.public_key();
    let alice_chunked = ChunkedAmount::from_amount(ALICE_BALANCE);
    let alice_ea = EncryptedAmount::new(alice_chunked, alice_pk);
    let withdraw_amount: u128 = 1u128 << 16;

    let cw = ConfidentialWithdraw::create_with_balance(
        alice_dk,
        ALICE_BALANCE,
        alice_ea.get_ciphertext().to_vec(),
        alice_ea.randomness().to_vec(),
        withdraw_amount,
        TEST_CHAIN_ID,
        &test_sender_addr(),
        &test_contract_addr(),
        &test_token_addr(),
    )
    .expect("create_with_balance should succeed");

    let sigma = cw.gen_sigma_proof();
    // Verify sigma proof was generated (all fields non-empty)
    assert!(!sigma.alpha_list.is_empty());
    assert!(!sigma.x_list.is_empty());
}

#[test]
fn generate_transfer_sigma_proof() {
    let alice_dk = TwistedEd25519PrivateKey::generate();
    let bob_dk = TwistedEd25519PrivateKey::generate();
    let alice_pk = alice_dk.public_key();
    let bob_pk = bob_dk.public_key();
    let alice_chunked = ChunkedAmount::from_amount(ALICE_BALANCE);
    let alice_ea = EncryptedAmount::new(alice_chunked, alice_pk);
    let transfer_amount: u128 = 10;

    let ct = ConfidentialTransfer::create(
        alice_dk,
        ALICE_BALANCE,
        alice_ea.randomness().to_vec(),
        transfer_amount,
        bob_pk,
        vec![], // no auditors
        TEST_CHAIN_ID,
        &test_sender_addr(),
        &test_contract_addr(),
        &test_token_addr(),
        &[],
    )
    .expect("create should succeed");

    let sigma = ct.gen_sigma_proof();
    assert!(!sigma.alpha1_list.is_empty());
}

#[test]
fn transfer_sigma_proof_serialize_deserialize_roundtrip_no_auditors() {
    let alice_dk = TwistedEd25519PrivateKey::generate();
    let bob_dk = TwistedEd25519PrivateKey::generate();
    let alice_pk = alice_dk.public_key();
    let alice_chunked = ChunkedAmount::from_amount(ALICE_BALANCE);
    let alice_ea = EncryptedAmount::new(alice_chunked, alice_pk);

    let ct = ConfidentialTransfer::create(
        alice_dk,
        ALICE_BALANCE,
        alice_ea.randomness().to_vec(),
        10,
        bob_dk.public_key(),
        vec![],
        TEST_CHAIN_ID,
        &test_sender_addr(),
        &test_contract_addr(),
        &test_token_addr(),
        &[],
    )
    .expect("create should succeed");

    let sigma = ct.gen_sigma_proof();
    let bytes = ConfidentialTransfer::serialize_sigma_proof(&sigma);
    assert_eq!(bytes.len(), 56 * 32);
    let decoded =
        ConfidentialTransfer::deserialize_sigma_proof(&bytes).expect("deserialize should succeed");
    assert_eq!(decoded.alpha1_list.len(), 8);
    assert!(decoded.x7_list.is_none());
    assert_eq!(decoded.x8_list.len(), 4);
}

#[test]
fn transfer_sigma_proof_serialize_deserialize_roundtrip_with_auditors() {
    let alice_dk = TwistedEd25519PrivateKey::generate();
    let bob_dk = TwistedEd25519PrivateKey::generate();
    let auditor = TwistedEd25519PrivateKey::generate();
    let alice_pk = alice_dk.public_key();
    let alice_chunked = ChunkedAmount::from_amount(ALICE_BALANCE);
    let alice_ea = EncryptedAmount::new(alice_chunked, alice_pk);

    let ct = ConfidentialTransfer::create(
        alice_dk,
        ALICE_BALANCE,
        alice_ea.randomness().to_vec(),
        10,
        bob_dk.public_key(),
        vec![auditor.public_key()],
        TEST_CHAIN_ID,
        &test_sender_addr(),
        &test_contract_addr(),
        &test_token_addr(),
        &[],
    )
    .expect("create should succeed");

    let sigma = ct.gen_sigma_proof();
    let bytes = ConfidentialTransfer::serialize_sigma_proof(&sigma);
    let decoded =
        ConfidentialTransfer::deserialize_sigma_proof(&bytes).expect("deserialize should succeed");
    assert_eq!(decoded.alpha1_list.len(), 8);
    assert_eq!(decoded.x2_list.len(), 8);
    assert!(decoded.x7_list.is_some());
    assert_eq!(decoded.x7_list.as_ref().unwrap().len(), 4);
    assert_eq!(decoded.x8_list.len(), 4);
}

#[test]
fn generate_key_rotation_sigma_proof() {
    let alice_dk = TwistedEd25519PrivateKey::generate();
    let new_alice_dk = TwistedEd25519PrivateKey::generate();
    let alice_pk = alice_dk.public_key();
    let alice_chunked = ChunkedAmount::from_amount(ALICE_BALANCE);
    let alice_ea = EncryptedAmount::new(alice_chunked, alice_pk);

    let kr = ConfidentialKeyRotation::create(
        alice_dk,
        new_alice_dk,
        alice_ea,
        TEST_CHAIN_ID,
        &test_sender_addr(),
        &test_contract_addr(),
        &test_token_addr(),
    );

    let sigma = kr.gen_sigma_proof();
    assert!(!sigma.alpha_list.is_empty());
}

#[test]
fn generate_normalization_sigma_proof() {
    let alice_dk = TwistedEd25519PrivateKey::generate();
    let alice_pk = alice_dk.public_key();
    // Create unnormalized balance with overflow in chunks
    let unnormalized_chunks: Vec<u64> = (0..AVAILABLE_BALANCE_CHUNK_COUNT - 1)
        .map(|_| ((1u128 << CHUNK_BITS as u128) + 100u128) as u64)
        .chain(std::iter::once(0u64))
        .collect();
    let unnormalized_chunked = ChunkedAmount::from_raw_chunks(unnormalized_chunks);
    let unnormalized_ea = EncryptedAmount::new(unnormalized_chunked, alice_pk);

    let norm = ConfidentialNormalization::create(
        alice_dk,
        unnormalized_ea,
        TEST_CHAIN_ID,
        &test_sender_addr(),
        &test_contract_addr(),
        &test_token_addr(),
    );

    let sigma = norm.gen_sigma_proof();
    assert!(!sigma.alpha_list.is_empty());
}
