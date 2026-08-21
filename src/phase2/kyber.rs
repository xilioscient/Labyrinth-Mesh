use aes_gcm_siv::{
    aead::{Aead, KeyInit},
    Aes256GcmSiv, Nonce,
};
use hkdf::Hkdf;
use pqcrypto_kyber::kyber1024::{
    decapsulate, encapsulate, keypair, Ciphertext, PublicKey, SecretKey, SharedSecret,
};
use pqcrypto_traits::kem::{
    Ciphertext  as PqCiphertext,
    PublicKey   as PqPublicKey,
    SecretKey   as PqSecretKey,
    SharedSecret as PqSharedSecret,
};
use rand::rngs::OsRng;
use rand::Rng;
use sha2::Sha256;
use zeroize::Zeroize;

pub const AES_SIV_NONCE_LEN: usize = 12;

pub const MAC_TAG_LEN: usize = 16;

pub const PQ_MAGIC: [u8; 4] = [0x8A, 0x2F, 0xC3, 0x7E];

#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct AESKey {
    inner: [u8; 32],
}

impl AESKey {
    pub fn new(key: [u8; 32]) -> Self { AESKey { inner: key } }
    pub fn as_slice(&self) -> &[u8; 32] { &self.inner }
    pub fn random() -> Self {
        let mut rng = OsRng;
        let mut k = [0u8; 32];
        rng.fill(&mut k);
        AESKey { inner: k }
    }
}

pub struct KyberKeyPair {
    pk_bytes: Vec<u8>,
    sk_bytes: Vec<u8>,
}

impl KyberKeyPair {
    pub fn generate() -> Self {
        let (pk, sk) = keypair();
        KyberKeyPair {
            pk_bytes: <PublicKey as PqPublicKey>::as_bytes(&pk).to_vec(),
            sk_bytes: <SecretKey as PqSecretKey>::as_bytes(&sk).to_vec(),
        }
    }

    pub fn public_key_bytes(&self) -> &[u8] { &self.pk_bytes }

    pub fn encapsulate_to(recipient_pk_bytes: &[u8]) -> Option<(Vec<u8>, AESKey)> {
        let pk = <PublicKey as PqPublicKey>::from_bytes(recipient_pk_bytes).ok()?;
        let (ss, ct) = encapsulate(&pk);
        let session_key = derive_session_key(&ss);
        Some((<Ciphertext as PqCiphertext>::as_bytes(&ct).to_vec(), session_key))
    }

    pub fn decapsulate(&self, ct_bytes: &[u8]) -> Option<AESKey> {
        let sk = <SecretKey as PqSecretKey>::from_bytes(&self.sk_bytes).ok()?;
        let ct = <Ciphertext as PqCiphertext>::from_bytes(ct_bytes).ok()?;
        let ss = decapsulate(&ct, &sk);
        Some(derive_session_key(&ss))
    }
}

impl Drop for KyberKeyPair {
    fn drop(&mut self) {
        self.sk_bytes.zeroize();
        self.pk_bytes.zeroize();
    }
}

pub fn derive_session_key(shared_secret: &SharedSecret) -> AESKey {
    let hk = Hkdf::<Sha256>::new(None, <SharedSecret as PqSharedSecret>::as_bytes(shared_secret));
    let mut key_bytes = [0u8; 32];
    hk.expand(b"dmpot-session-key-v1", &mut key_bytes)
        .expect("HKDF expand: output length <= 255*HashLen");
    AESKey::new(key_bytes)
}

pub fn derive_layer_key(master_key: &[u8; 32], layer_idx: u8) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, master_key);
    let mut key_bytes = [0u8; 32];
    let info = {
        let mut v = b"dmpot-layer-".to_vec();
        v.push(layer_idx);
        v
    };
    hk.expand(&info, &mut key_bytes)
        .expect("HKDF expand: output length <= 255*HashLen");
    key_bytes
}

pub fn aes_gcm_siv_encrypt(key: &[u8; 32], nonce: &[u8; 12], plaintext: &[u8]) -> Vec<u8> {
    let cipher = Aes256GcmSiv::new_from_slice(key).expect("key must be 32 bytes");
    let n = Nonce::from_slice(nonce);
    cipher.encrypt(n, plaintext).expect("GCM-SIV encrypt failed")
}

pub fn aes_gcm_siv_decrypt(key: &[u8; 32], nonce: &[u8; 12], ciphertext: &[u8]) -> Option<Vec<u8>> {
    let cipher = Aes256GcmSiv::new_from_slice(key).expect("key must be 32 bytes");
    let n = Nonce::from_slice(nonce);
    cipher.decrypt(n, ciphertext).ok()
}

#[allow(dead_code)]
pub fn wrap_single_layer(data: &[u8], key: &AESKey) -> Vec<u8> {
    let mut nonce = [0u8; AES_SIV_NONCE_LEN];
    OsRng.fill(&mut nonce);
    let ct = aes_gcm_siv_encrypt(key.as_slice(), &nonce, data);

    let mut out = Vec::with_capacity(4 + AES_SIV_NONCE_LEN + ct.len());
    out.extend_from_slice(&PQ_MAGIC);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    out
}

#[allow(dead_code)]
pub fn unwrap_single_layer(data: &[u8], key: &AESKey) -> Option<Vec<u8>> {
    let hdr_len = 4 + AES_SIV_NONCE_LEN;
    if data.len() < hdr_len + MAC_TAG_LEN { return None; }
    if data[0..4] != PQ_MAGIC { return None; }
    let nonce: &[u8; 12] = data[4..16].try_into().ok()?;
    let ct = &data[16..];
    aes_gcm_siv_decrypt(key.as_slice(), nonce, ct)
}

pub fn wrap_layers(data: &[u8], master_key: &AESKey, layers: u8) -> Vec<u8> {
    let mut current = data.to_vec();
    for layer_idx in 0..layers {
        let layer_key = derive_layer_key(master_key.as_slice(), layer_idx);
        let mut nonce = [0u8; AES_SIV_NONCE_LEN];
        OsRng.fill(&mut nonce);
        let ct = aes_gcm_siv_encrypt(&layer_key, &nonce, &current);

        let mut packet = Vec::with_capacity(4 + 4 + AES_SIV_NONCE_LEN + ct.len());
        packet.extend_from_slice(&PQ_MAGIC);
        packet.extend_from_slice(&(ct.len() as u32).to_le_bytes());
        packet.extend_from_slice(&nonce);
        packet.extend_from_slice(&ct);
        current = packet;
    }
    current
}

pub fn unwrap_layers(data: &[u8], master_key: &AESKey, layers: u8) -> Option<Vec<u8>> {
    let mut current = data.to_vec();
    for layer_idx in (0..layers).rev() {
        let layer_key = derive_layer_key(master_key.as_slice(), layer_idx);
        if current.len() < 4 + 4 + AES_SIV_NONCE_LEN + MAC_TAG_LEN {
            return None;
        }
        if current[0..4] != PQ_MAGIC { return None; }
        let ct_len = u32::from_le_bytes(current[4..8].try_into().ok()?) as usize;
        let nonce: &[u8; 12] = current[8..20].try_into().ok()?;
        if current.len() < 20 + ct_len { return None; }
        let ct = &current[20..20 + ct_len];
        current = aes_gcm_siv_decrypt(&layer_key, nonce, ct)?;
    }
    Some(current)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hkdf_derive_session_key() {
        let (pk1, _sk1) = keypair();
        let (pk2, _sk2) = keypair();
        let (ss1, _ct1) = encapsulate(&pk1);
        let (ss2, _ct2) = encapsulate(&pk2);
        let k1 = derive_session_key(&ss1);
        let k2 = derive_session_key(&ss2);
        assert_ne!(k1.as_slice(), k2.as_slice());
    }

    #[test]
    fn test_derive_layer_key_domain_separation() {
        let master = [0x42u8; 32];
        let k0 = derive_layer_key(&master, 0);
        let k1 = derive_layer_key(&master, 1);
        let k2 = derive_layer_key(&master, 2);
        assert_ne!(k0, k1);
        assert_ne!(k1, k2);
    }

    #[test]
    fn test_wrap_unwrap_single_layer() {
        let data = b"single layer test payload";
        let key = AESKey::random();
        let wrapped = wrap_single_layer(data, &key);
        let unwrapped = unwrap_single_layer(&wrapped, &key).expect("auth failure");
        assert_eq!(unwrapped, data);
    }

    #[test]
    fn test_wrap_unwrap_layers() {
        let data = b"multi layer onion test";
        let key = AESKey::random();
        let wrapped = wrap_layers(data, &key, 3);
        assert!(wrapped.len() > data.len());
        let unwrapped = unwrap_layers(&wrapped, &key, 3).expect("auth failure");
        assert_eq!(unwrapped, data);
    }

    #[test]
    fn test_kyber_kem_roundtrip() {
        let bob_kp = KyberKeyPair::generate();
        let (ct_bytes, alice_key) = KyberKeyPair::encapsulate_to(bob_kp.public_key_bytes())
            .expect("encapsulate failed");
        let bob_key = bob_kp.decapsulate(&ct_bytes).expect("decapsulate failed");
        assert_eq!(alice_key.as_slice(), bob_key.as_slice());
    }

    #[test]
    fn test_aes_gcm_siv_roundtrip() {
        let key = [0x11u8; 32];
        let nonce = [0x22u8; 12];
        let pt = b"test plaintext for GCM-SIV";
        let ct = aes_gcm_siv_encrypt(&key, &nonce, pt);
        let recovered = aes_gcm_siv_decrypt(&key, &nonce, &ct).expect("auth failure");
        assert_eq!(recovered, pt);
    }
}
