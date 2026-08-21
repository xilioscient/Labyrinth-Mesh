use blake3::Hasher as Blake3Hasher;
use pqcrypto_kyber::kyber1024::{
    decapsulate, encapsulate, keypair, Ciphertext, PublicKey, SecretKey, SharedSecret,
};
use pqcrypto_traits::kem::{
    Ciphertext as PqCiphertext, PublicKey as PqPublicKey, SecretKey as PqSecretKey,
    SharedSecret as PqSharedSecret,
};
use sharks::{Share, Sharks};

pub const MTU: usize = 1280;

pub const SHAMIR_K: u8 = 3;
pub const SHAMIR_N: u8 = 5;

pub const AUTH_TAG_LEN: usize = 8;

pub struct TaggedShare {
    pub share_bytes: Vec<u8>,
    pub tag: [u8; AUTH_TAG_LEN],
    pub index: u8,
}

pub fn auth_tag(key_session: &[u8; 32], seq: u64, frag_id: u8) -> [u8; AUTH_TAG_LEN] {
    let mut h = Blake3Hasher::new_keyed(key_session);
    h.update(&seq.to_le_bytes());
    h.update(&[frag_id]);
    let full = h.finalize();
    let mut tag = [0u8; AUTH_TAG_LEN];
    tag.copy_from_slice(&full.as_bytes()[..AUTH_TAG_LEN]);
    tag
}

pub fn verify_auth_tag(
    key_session: &[u8; 32],
    seq: u64,
    frag_id: u8,
    received: &[u8; AUTH_TAG_LEN],
) -> bool {
    let expected = auth_tag(key_session, seq, frag_id);
    let diff: u8 = expected.iter().zip(received.iter()).map(|(a, b)| a ^ b).fold(0, |acc, x| acc | x);
    diff == 0
}

pub struct SessionKey(pub [u8; 32]);

impl SessionKey {
    pub fn from_shared_secret(ss: &SharedSecret) -> Self {
        let ss_bytes = <SharedSecret as PqSharedSecret>::as_bytes(ss);
        let key = blake3::derive_key("dmpot-v2-session-key-v1", ss_bytes);
        SessionKey(key)
    }
}

pub fn kem_encapsulate(recipient_pk_bytes: &[u8]) -> Option<(Vec<u8>, SessionKey)> {
    let pk = <PublicKey as PqPublicKey>::from_bytes(recipient_pk_bytes).ok()?;
    let (ss, ct) = encapsulate(&pk);
    let session_key = SessionKey::from_shared_secret(&ss);
    Some((<Ciphertext as PqCiphertext>::as_bytes(&ct).to_vec(), session_key))
}

pub fn kem_decapsulate(sk_bytes: &[u8], ct_bytes: &[u8]) -> Option<SessionKey> {
    let sk = <SecretKey as PqSecretKey>::from_bytes(sk_bytes).ok()?;
    let ct = <Ciphertext as PqCiphertext>::from_bytes(ct_bytes).ok()?;
    let ss = decapsulate(&ct, &sk);
    Some(SessionKey::from_shared_secret(&ss))
}

pub fn generate_keypair() -> (Vec<u8>, Vec<u8>) {
    let (pk, sk) = keypair();
    (
        <PublicKey as PqPublicKey>::as_bytes(&pk).to_vec(),
        <SecretKey as PqSecretKey>::as_bytes(&sk).to_vec(),
    )
}

pub fn split_and_tag(
    secret: &[u8],
    session_key: &SessionKey,
    seq: u64,
) -> Vec<TaggedShare> {
    let sharks = Sharks(SHAMIR_K);
    let dealer = sharks.dealer(secret);
    let shares: Vec<Share> = dealer.take(SHAMIR_N as usize).collect();

    shares
        .into_iter()
        .enumerate()
        .map(|(idx, share)| {
            let share_bytes: Vec<u8> = (&share).into();
            let tag = auth_tag(&session_key.0, seq, idx as u8);
            TaggedShare { share_bytes, tag, index: idx as u8 }
        })
        .collect()
}

pub fn verify_and_recover(
    tagged_shares: &[TaggedShare],
    session_key: &SessionKey,
    seq: u64,
) -> Option<Vec<u8>> {
    for ts in tagged_shares {
        if !verify_auth_tag(&session_key.0, seq, ts.index, &ts.tag) {
            return None;
        }
    }

    let sharks = Sharks(SHAMIR_K);
    let shares: Vec<Share> = tagged_shares
        .iter()
        .filter_map(|ts| Share::try_from(ts.share_bytes.as_slice()).ok())
        .collect();

    if shares.len() < SHAMIR_K as usize {
        return None;
    }

    sharks.recover(&shares).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auth_tag_deterministic() {
        let key = [0xABu8; 32];
        let t1 = auth_tag(&key, 42, 3);
        let t2 = auth_tag(&key, 42, 3);
        assert_eq!(t1, t2);
        let t3 = auth_tag(&key, 42, 4);
        assert_ne!(t1, t3);
    }

    #[test]
    fn test_split_recover_roundtrip() {
        let (pk_bytes, sk_bytes) = generate_keypair();
        let (ct_bytes, session_key) = kem_encapsulate(&pk_bytes).unwrap();
        let session_key2 = kem_decapsulate(&sk_bytes, &ct_bytes).unwrap();
        assert_eq!(session_key.0, session_key2.0);

        let secret = b"Labyrinth-Mesh secret payload v2";
        let shares = split_and_tag(secret, &session_key, 1);
        assert_eq!(shares.len(), SHAMIR_N as usize);

        let subset: Vec<_> = shares.into_iter().take(3).collect();
        let recovered = verify_and_recover(&subset, &session_key2, 1).unwrap();
        assert_eq!(recovered, secret.as_slice());
    }

    #[test]
    fn test_bad_tag_rejected() {
        let key = SessionKey([0x11u8; 32]);
        let secret = b"test";
        let mut shares = split_and_tag(secret, &key, 0);
        shares[0].tag[0] ^= 0xFF;
        let result = verify_and_recover(&shares[..3], &key, 0);
        assert!(result.is_none());
    }
}
