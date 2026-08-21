use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::{Sha256, Digest};

type HmacSha256 = Hmac<Sha256>;

fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> [u8; 32] {
    let (prk, _) = Hkdf::<Sha256>::extract(Some(salt), ikm);
    let mut out = [0u8; 32];
    out.copy_from_slice(&prk);
    out
}

fn hkdf_expand_label(prk: &[u8], label: &str, context: &[u8], len: usize) -> Vec<u8> {
    let full = format!("tls13 {}", label);
    let mut info = Vec::new();
    info.extend_from_slice(&(len as u16).to_be_bytes());
    info.push(full.len() as u8);
    info.extend_from_slice(full.as_bytes());
    info.push(context.len() as u8);
    info.extend_from_slice(context);

    let hk = Hkdf::<Sha256>::from_prk(prk).expect("valid prk");
    let mut okm = vec![0u8; len];
    hk.expand(&info, &mut okm).expect("hkdf expand");
    okm
}

fn derive_secret(secret: &[u8], label: &str, transcript_hash: &[u8]) -> [u8; 32] {
    hkdf_expand_label(secret, label, transcript_hash, 32)
        .try_into()
        .expect("derive_secret len")
}

pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).expect("hmac key");
    mac.update(data);
    let out = mac.finalize().into_bytes();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&out);
    arr
}

pub fn sha256_hash(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    let out = h.finalize();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&out);
    arr
}

static SHA256_EMPTY: [u8; 32] = [
    0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
    0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
    0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
    0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
];

pub struct HandshakeKeys {
    pub client_key: [u8; 16],
    pub client_iv: [u8; 12],
    pub server_key: [u8; 16],
    pub server_iv: [u8; 12],
    pub client_finished_key: [u8; 32],
    pub server_finished_key: [u8; 32],
    pub handshake_secret: [u8; 32],
    pub client_hs_secret: [u8; 32],
}

pub fn compute_handshake_keys(shared_secret: &[u8], hello_hash: &[u8]) -> HandshakeKeys {
    let zeros32 = [0u8; 32];

    let early_secret = hkdf_extract(&zeros32, &zeros32);
    let derived = derive_secret(&early_secret, "derived", &SHA256_EMPTY);
    let handshake_secret = hkdf_extract(&derived, shared_secret);

    let client_hs_secret = derive_secret(&handshake_secret, "c hs traffic", hello_hash);
    let server_hs_secret = derive_secret(&handshake_secret, "s hs traffic", hello_hash);

    let client_key: [u8; 16] = hkdf_expand_label(&client_hs_secret, "key", &[], 16).try_into().unwrap();
    let client_iv: [u8; 12] = hkdf_expand_label(&client_hs_secret, "iv", &[], 12).try_into().unwrap();
    let server_key: [u8; 16] = hkdf_expand_label(&server_hs_secret, "key", &[], 16).try_into().unwrap();
    let server_iv: [u8; 12] = hkdf_expand_label(&server_hs_secret, "iv", &[], 12).try_into().unwrap();

    let client_finished_key: [u8; 32] = hkdf_expand_label(&client_hs_secret, "finished", &[], 32).try_into().unwrap();
    let server_finished_key: [u8; 32] = hkdf_expand_label(&server_hs_secret, "finished", &[], 32).try_into().unwrap();

    HandshakeKeys {
        client_key, client_iv,
        server_key, server_iv,
        client_finished_key, server_finished_key,
        handshake_secret,
        client_hs_secret,
    }
}

pub struct ApplicationKeys {
    pub client_key: [u8; 16],
    pub client_iv: [u8; 12],
    pub server_key: [u8; 16],
    pub server_iv: [u8; 12],
}

pub fn compute_application_keys(handshake_secret: &[u8], server_finished_hash: &[u8]) -> ApplicationKeys {
    let zeros32 = [0u8; 32];
    let derived2 = derive_secret(handshake_secret, "derived", &SHA256_EMPTY);
    let master_secret = hkdf_extract(&derived2, &zeros32);

    let client_ap_secret = derive_secret(&master_secret, "c ap traffic", server_finished_hash);
    let server_ap_secret = derive_secret(&master_secret, "s ap traffic", server_finished_hash);

    ApplicationKeys {
        client_key: hkdf_expand_label(&client_ap_secret, "key", &[], 16).try_into().unwrap(),
        client_iv: hkdf_expand_label(&client_ap_secret, "iv", &[], 12).try_into().unwrap(),
        server_key: hkdf_expand_label(&server_ap_secret, "key", &[], 16).try_into().unwrap(),
        server_iv: hkdf_expand_label(&server_ap_secret, "iv", &[], 12).try_into().unwrap(),
    }
}
