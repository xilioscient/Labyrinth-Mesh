use aes_gcm::{Aes128Gcm, KeyInit};
use aes_gcm::aead::{Aead, Payload};
use aes_gcm::aead::generic_array::GenericArray;

pub fn tls_nonce(iv: &[u8; 12], seq: u64) -> [u8; 12] {
    let mut nonce = *iv;
    let seq_bytes = seq.to_be_bytes();
    for i in 0..8 {
        nonce[4 + i] ^= seq_bytes[i];
    }
    nonce
}

pub fn encrypt_record(plaintext: &[u8], inner_type: u8, key: &[u8; 16], iv: &[u8; 12], seq: u64) -> Vec<u8> {
    let mut pt = plaintext.to_vec();
    pt.push(inner_type);

    let nonce_bytes = tls_nonce(iv, seq);
    let ct_len = (pt.len() + 16) as u16;
    let aad = [0x17u8, 0x03, 0x03, (ct_len >> 8) as u8, ct_len as u8];

    let cipher = Aes128Gcm::new_from_slice(key).expect("aes key");
    cipher.encrypt(
        GenericArray::from_slice(&nonce_bytes),
        Payload { msg: &pt, aad: &aad },
    ).expect("aes encrypt")
}

pub fn decrypt_record(ciphertext: &[u8], key: &[u8; 16], iv: &[u8; 12], seq: u64) -> Option<(Vec<u8>, u8)> {
    if ciphertext.len() < 17 { return None; }

    let nonce_bytes = tls_nonce(iv, seq);
    let ct_len = ciphertext.len() as u16;
    let aad = [0x17u8, 0x03, 0x03, (ct_len >> 8) as u8, ct_len as u8];

    let cipher = Aes128Gcm::new_from_slice(key).ok()?;
    let mut pt = cipher.decrypt(
        GenericArray::from_slice(&nonce_bytes),
        Payload { msg: ciphertext, aad: &aad },
    ).ok()?;

    let inner_type = pt.pop()?;
    Some((pt, inner_type))
}

pub fn make_tls_record(content_type: u8, data: &[u8]) -> Vec<u8> {
    let mut rec = Vec::with_capacity(5 + data.len());
    rec.push(content_type);
    rec.extend_from_slice(&[0x03, 0x03]);
    rec.extend_from_slice(&(data.len() as u16).to_be_bytes());
    rec.extend_from_slice(data);
    rec
}

pub fn make_encrypted_record(plaintext: &[u8], inner_type: u8, key: &[u8; 16], iv: &[u8; 12], seq: u64) -> Vec<u8> {
    let ct = encrypt_record(plaintext, inner_type, key, iv, seq);
    make_tls_record(0x17, &ct)
}

pub fn u24_be(b: &[u8]) -> u32 {
    (b[0] as u32) << 16 | (b[1] as u32) << 8 | b[2] as u32
}
