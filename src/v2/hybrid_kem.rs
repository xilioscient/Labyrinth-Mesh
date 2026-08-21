use pqcrypto_kyber::kyber1024::{
    decapsulate, encapsulate, keypair as kyber_keypair, Ciphertext, PublicKey, SecretKey,
};
use pqcrypto_traits::kem::{
    Ciphertext as PqCt, PublicKey as PqPk, SecretKey as PqSk, SharedSecret as PqSs,
};
use x25519_dalek::{EphemeralSecret, PublicKey as X25519Pk, StaticSecret};
use zeroize::Zeroize;

pub const HYBRID_KYBER_PK_LEN: usize = 1568;
pub const HYBRID_KYBER_CT_LEN: usize = 1568;
pub const HYBRID_X25519_LEN: usize = 32;
pub const HYBRID_PK_WIRE_LEN: usize = HYBRID_KYBER_PK_LEN + HYBRID_X25519_LEN;
pub const HYBRID_KEM_WIRE_LEN: usize = HYBRID_KYBER_CT_LEN + HYBRID_X25519_LEN;

pub struct HybridReceiverKeypair {
    pub kyber_pk: Vec<u8>,
    kyber_sk: Vec<u8>,
    pub x25519_pk: [u8; 32],
    x25519_sk: [u8; 32],
}

impl HybridReceiverKeypair {
    pub fn generate() -> Self {
        let (kpk, ksk) = kyber_keypair();
        let kyber_pk = <PublicKey as PqPk>::as_bytes(&kpk).to_vec();
        let kyber_sk = <SecretKey as PqSk>::as_bytes(&ksk).to_vec();
        let xsk = StaticSecret::random_from_rng(rand_core::OsRng);
        let x25519_pk: [u8; 32] = X25519Pk::from(&xsk).to_bytes();
        let x25519_sk: [u8; 32] = xsk.to_bytes();
        HybridReceiverKeypair { kyber_pk, kyber_sk, x25519_pk, x25519_sk }
    }

    pub fn pk_wire(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HYBRID_PK_WIRE_LEN);
        out.extend_from_slice(&self.kyber_pk);
        out.extend_from_slice(&self.x25519_pk);
        out
    }

    pub fn decapsulate(&self, kyber_ct_bytes: &[u8], x25519_sender_pk: &[u8; 32]) -> Option<[u8; 32]> {
        let sk = <SecretKey as PqSk>::from_bytes(&self.kyber_sk).ok()?;
        let ct = <Ciphertext as PqCt>::from_bytes(kyber_ct_bytes).ok()?;
        let kyber_ss = decapsulate(&ct, &sk);
        let kyber_ss_bytes = <_ as PqSs>::as_bytes(&kyber_ss);

        let xsk = StaticSecret::from(self.x25519_sk);
        let spk = X25519Pk::from(*x25519_sender_pk);
        let x25519_ss = xsk.diffie_hellman(&spk);

        let mut ikm = Vec::with_capacity(kyber_ss_bytes.len() + 32);
        ikm.extend_from_slice(kyber_ss_bytes);
        ikm.extend_from_slice(x25519_ss.as_bytes());
        Some(blake3::derive_key("labyrinth-hybrid-v3 session", &ikm))
    }
}

impl Drop for HybridReceiverKeypair {
    fn drop(&mut self) {
        self.kyber_sk.zeroize();
        self.x25519_sk.zeroize();
    }
}

pub struct HybridSenderOutput {
    pub kyber_ct_bytes: Vec<u8>,
    pub x25519_sender_pk: [u8; 32],
    pub shared_secret: [u8; 32],
}

pub fn hybrid_encapsulate_from_wire(pk_wire: &[u8]) -> Option<HybridSenderOutput> {
    if pk_wire.len() != HYBRID_PK_WIRE_LEN {
        return None;
    }
    let kyber_pk_bytes = &pk_wire[..HYBRID_KYBER_PK_LEN];
    let x25519_pk: [u8; 32] = pk_wire[HYBRID_KYBER_PK_LEN..].try_into().ok()?;

    let pk = <PublicKey as PqPk>::from_bytes(kyber_pk_bytes).ok()?;
    let (kyber_ss, kyber_ct) = encapsulate(&pk);
    let kyber_ss_bytes = <_ as PqSs>::as_bytes(&kyber_ss);
    let kyber_ct_bytes = <Ciphertext as PqCt>::as_bytes(&kyber_ct).to_vec();

    let sender_sk = EphemeralSecret::random_from_rng(rand_core::OsRng);
    let sender_pk = X25519Pk::from(&sender_sk);
    let receiver_pk = X25519Pk::from(x25519_pk);
    let x25519_ss = sender_sk.diffie_hellman(&receiver_pk);

    let mut ikm = Vec::with_capacity(kyber_ss_bytes.len() + 32);
    ikm.extend_from_slice(kyber_ss_bytes);
    ikm.extend_from_slice(x25519_ss.as_bytes());
    let combined = blake3::derive_key("labyrinth-hybrid-v3 session", &ikm);

    Some(HybridSenderOutput {
        kyber_ct_bytes,
        x25519_sender_pk: sender_pk.to_bytes(),
        shared_secret: combined,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hybrid_roundtrip() {
        let kp = HybridReceiverKeypair::generate();
        let out = hybrid_encapsulate_from_wire(&kp.pk_wire()).unwrap();
        let x25519_spk: [u8; 32] = out.x25519_sender_pk;
        let recv_key = kp.decapsulate(&out.kyber_ct_bytes, &x25519_spk).unwrap();
        assert_eq!(recv_key, out.shared_secret);
    }
}
