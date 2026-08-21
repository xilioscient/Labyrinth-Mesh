mod kyber;

pub use kyber::{
    AESKey, KyberKeyPair, PQ_MAGIC, AES_SIV_NONCE_LEN, MAC_TAG_LEN,
    derive_session_key, derive_layer_key,
    wrap_layers, unwrap_layers,
    aes_gcm_siv_encrypt, aes_gcm_siv_decrypt,
};

use rand::rngs::OsRng;
use rand::Rng;

pub const DEFAULT_ONION_LAYERS: u8 = 3;

#[derive(Debug, Clone, Copy)]
pub struct OnionHeader {
    pub magic: [u8; 4],
    pub length: u32,
    pub nonce: [u8; AES_SIV_NONCE_LEN],
}

impl OnionHeader {
    pub fn new(payload_len: usize) -> Self {
        let mut nonce = [0u8; AES_SIV_NONCE_LEN];
        OsRng.fill(&mut nonce);
        OnionHeader { magic: PQ_MAGIC, length: payload_len as u32, nonce }
    }

    pub fn serialize(&self) -> [u8; 20] {
        let mut buf = [0u8; 20];
        buf[0..4].copy_from_slice(&self.magic);
        buf[4..8].copy_from_slice(&self.length.to_le_bytes());
        buf[8..20].copy_from_slice(&self.nonce);
        buf
    }

    pub fn deserialize(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 20 { return None; }
        if bytes[0..4] != PQ_MAGIC { return None; }
        let length = u32::from_le_bytes(bytes[4..8].try_into().ok()?);
        let mut nonce = [0u8; AES_SIV_NONCE_LEN];
        nonce.copy_from_slice(&bytes[8..20]);
        Some(OnionHeader { magic: PQ_MAGIC, length, nonce })
    }
}

#[derive(Clone)]
pub struct EncapsulatedFragment {
    pub kem_ciphertext: Vec<u8>,
    pub onion_data: Vec<u8>,
}

impl EncapsulatedFragment {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + self.kem_ciphertext.len() + self.onion_data.len());
        out.extend_from_slice(&(self.kem_ciphertext.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.kem_ciphertext);
        out.extend_from_slice(&self.onion_data);
        out
    }

    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < 4 { return None; }
        let kem_len = u32::from_le_bytes(data[0..4].try_into().ok()?) as usize;
        if data.len() < 4 + kem_len { return None; }
        let kem_ciphertext = data[4..4 + kem_len].to_vec();
        let onion_data = data[4 + kem_len..].to_vec();
        Some(EncapsulatedFragment { kem_ciphertext, onion_data })
    }
}

pub fn encapsulate_fragment(
    fragment: &[u8],
    recipient_pk: &[u8],
    num_layers: u8,
) -> Option<EncapsulatedFragment> {
    let (kem_ciphertext, session_key) = KyberKeyPair::encapsulate_to(recipient_pk)?;
    let onion_data = wrap_layers(fragment, &session_key, num_layers);
    Some(EncapsulatedFragment { kem_ciphertext, onion_data })
}

pub fn decapsulate_fragment(
    encapsulated: &EncapsulatedFragment,
    recipient_kp: &KyberKeyPair,
    num_layers: u8,
) -> Option<Vec<u8>> {
    let session_key = recipient_kp.decapsulate(&encapsulated.kem_ciphertext)?;
    unwrap_layers(&encapsulated.onion_data, &session_key, num_layers)
}

pub fn encapsulate_with_key(fragment: &[u8], key: &AESKey, num_layers: u8) -> Vec<u8> {
    wrap_layers(fragment, key, num_layers)
}

pub fn decapsulate_with_key(data: &[u8], key: &AESKey, num_layers: u8) -> Option<Vec<u8>> {
    unwrap_layers(data, key, num_layers)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kem_encapsulate_decapsulate_roundtrip() {
        let recipient_kp = KyberKeyPair::generate();
        let fragment = b"Secret DMPOT fragment payload";

        let enc = encapsulate_fragment(fragment, recipient_kp.public_key_bytes(), 3)
            .expect("encapsulate failed");
        let dec = decapsulate_fragment(&enc, &recipient_kp, 3)
            .expect("decapsulate failed");

        assert_eq!(dec, fragment);
    }

    #[test]
    fn test_psk_mode_roundtrip() {
        let key = AESKey::random();
        let data = b"PSK mode test payload";
        let enc = encapsulate_with_key(data, &key, 3);
        let dec = decapsulate_with_key(&enc, &key, 3).expect("auth failure");
        assert_eq!(dec, data);
    }

    #[test]
    fn test_encapsulated_fragment_serialization() {
        let kp = KyberKeyPair::generate();
        let enc = encapsulate_fragment(b"test", kp.public_key_bytes(), 2).unwrap();
        let bytes = enc.to_bytes();
        let enc2 = EncapsulatedFragment::from_bytes(&bytes).unwrap();
        assert_eq!(enc.kem_ciphertext, enc2.kem_ciphertext);
        assert_eq!(enc.onion_data, enc2.onion_data);
    }

    #[test]
    fn test_onion_header_serialization() {
        let hdr = OnionHeader::new(1024);
        let bytes = hdr.serialize();
        let hdr2 = OnionHeader::deserialize(&bytes).unwrap();
        assert_eq!(hdr.magic, hdr2.magic);
        assert_eq!(hdr.length, hdr2.length);
        assert_eq!(hdr.nonce, hdr2.nonce);
    }

    #[test]
    fn test_wrong_key_decapsulate_fails() {
        let kp1 = KyberKeyPair::generate();
        let kp2 = KyberKeyPair::generate();
        let enc = encapsulate_fragment(b"secret", kp1.public_key_bytes(), 2).unwrap();
        let result = decapsulate_fragment(&enc, &kp2, 2);
        if let Some(dec) = result {
            assert_ne!(dec, b"secret".as_slice());
        }
    }
}
