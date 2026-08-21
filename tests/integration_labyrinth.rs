//! End-to-end integration test for Labyrinth-Mesh v2.
//!
//! Covers the full cryptographic pipeline without any network I/O:
//!   Kyber-1024 KEM → session key agreement → sharks SSS → BLAKE3 auth tags
//!
//! Run with: `cargo test --test integration_labyrinth`

use labyrinth_core::v2::{
    generate_keypair, kem_decapsulate, kem_encapsulate, split_and_tag,
    verify_and_recover, AUTH_TAG_LEN, SHAMIR_K, SHAMIR_N,
};

/// Full loopback: KEM handshake → split+tag → verify+recover.
///
/// Steps tested:
///   1. `generate_keypair` produces non-empty key material.
///   2. `kem_encapsulate` / `kem_decapsulate` produce identical SessionKeys.
///   3. `split_and_tag` on a ≥64-byte payload produces SHAMIR_N shares, each
///      with an 8-byte auth tag and a non-empty share payload.
///   4. `verify_and_recover` with the first SHAMIR_K shares reconstructs the
///      exact original payload.
///   5. Corrupting any single tag causes `verify_and_recover` to return `None`.
#[test]
fn test_labyrinth_mesh_loopback() {
    // ── 1. Key generation ────────────────────────────────────────────────────
    let (pk_bytes, sk_bytes) = generate_keypair();
    assert!(!pk_bytes.is_empty(), "public key must not be empty");
    assert!(!sk_bytes.is_empty(), "secret key must not be empty");

    // ── 2. KEM roundtrip ─────────────────────────────────────────────────────
    let (ct_bytes, session_key_sender) =
        kem_encapsulate(&pk_bytes).expect("kem_encapsulate must succeed");
    assert!(!ct_bytes.is_empty(), "KEM ciphertext must not be empty");

    let session_key_receiver =
        kem_decapsulate(&sk_bytes, &ct_bytes).expect("kem_decapsulate must succeed");

    assert_eq!(
        session_key_sender.0, session_key_receiver.0,
        "sender and receiver session keys must match after KEM roundtrip"
    );

    // ── 3. split_and_tag ─────────────────────────────────────────────────────
    let payload =
        b"Labyrinth-Mesh integration test: the quick brown fox jumps over the lazy dog!!";
    assert!(
        payload.len() >= 64,
        "test payload must be at least 64 bytes"
    );

    let seq: u64 = 0x0102_0304_DEAD_BEEFu64;

    let shares = split_and_tag(payload, &session_key_sender, seq);

    assert_eq!(
        shares.len(),
        SHAMIR_N as usize,
        "split_and_tag must return exactly SHAMIR_N shares"
    );

    for (i, share) in shares.iter().enumerate() {
        assert_eq!(
            share.tag.len(),
            AUTH_TAG_LEN,
            "share[{i}] tag must be AUTH_TAG_LEN bytes"
        );
        assert!(
            !share.share_bytes.is_empty(),
            "share[{i}] payload must not be empty"
        );
    }

    // ── 4. verify_and_recover with first SHAMIR_K shares ─────────────────────
    // Consume the first K shares (indices 0..K-1).
    let subset: Vec<_> = shares.into_iter().take(SHAMIR_K as usize).collect();
    assert_eq!(subset.len(), SHAMIR_K as usize);

    let recovered = verify_and_recover(&subset, &session_key_receiver, seq)
        .expect("verify_and_recover must succeed with valid shares and correct seq");

    assert_eq!(
        recovered.as_slice(),
        payload.as_ref(),
        "recovered payload must be identical to the original"
    );

    // ── 5. Corrupted tag must return None ────────────────────────────────────
    let shares2 = split_and_tag(payload, &session_key_sender, seq);
    let mut corrupted: Vec<_> = shares2.into_iter().take(SHAMIR_K as usize).collect();

    // Flip the first byte of the first share's tag.
    corrupted[0].tag[0] ^= 0xFF;

    let result = verify_and_recover(&corrupted, &session_key_receiver, seq);
    assert!(
        result.is_none(),
        "verify_and_recover must return None when a tag is corrupted"
    );
}

/// Verify that different seq values produce different auth tags (replay detection).
#[test]
fn test_different_seq_different_tags() {
    let (pk_bytes, _sk_bytes) = generate_keypair();
    let (_ct, key) = kem_encapsulate(&pk_bytes).unwrap();
    let payload = b"replay protection test payload - must be at least 64 bytes long!!!";

    let shares_a = split_and_tag(payload, &key, 100);
    let shares_b = split_and_tag(payload, &key, 101);

    // Tags for the same share index but different seq must differ.
    assert_ne!(
        shares_a[0].tag, shares_b[0].tag,
        "different seq values must produce different auth tags"
    );
}

/// Verify that verify_and_recover returns None for a wrong seq.
#[test]
fn test_wrong_seq_rejected() {
    let (pk_bytes, sk_bytes) = generate_keypair();
    let (ct, key_sender) = kem_encapsulate(&pk_bytes).unwrap();
    let key_receiver = kem_decapsulate(&sk_bytes, &ct).unwrap();

    let payload = b"wrong seq test payload - length at least sixty-four bytes here!!";
    let seq = 42u64;

    let shares = split_and_tag(payload, &key_sender, seq);
    let subset: Vec<_> = shares.into_iter().take(SHAMIR_K as usize).collect();

    // Correct seq must succeed.
    let ok = verify_and_recover(&subset, &key_receiver, seq);
    assert!(ok.is_some(), "correct seq must succeed");

    // Re-create shares for the wrong-seq test (shares moved above).
    let shares2 = split_and_tag(payload, &key_sender, seq);
    let subset2: Vec<_> = shares2.into_iter().take(SHAMIR_K as usize).collect();

    // Wrong seq must fail.
    let bad = verify_and_recover(&subset2, &key_receiver, seq + 1);
    assert!(bad.is_none(), "wrong seq must be rejected");
}
