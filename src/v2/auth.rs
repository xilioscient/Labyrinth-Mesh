use pqcrypto_dilithium::dilithium3;
use pqcrypto_traits::sign::{DetachedSignature, PublicKey};

use crate::v2::tpm_identity::TpmIdentity;

pub use dilithium3::PublicKey as SignPk;
pub use dilithium3::SecretKey as SignSk;

pub const CTRL_MAGIC: [u8; 4] = [0x4C, 0x4D, 0x76, 0x33];

pub const KEM_PK_LEN: usize = 1600;
pub const SIGN_PK_LEN: usize = 1952;
pub const SIGN_SIG_LEN: usize = 3309;
pub const CTRL_V2_LEN: usize = 4 + KEM_PK_LEN + SIGN_PK_LEN + SIGN_SIG_LEN;

pub fn generate_sign_keypair() -> (SignPk, SignSk) {
    dilithium3::keypair()
}

pub fn sign_bytes(sk: &SignSk, msg: &[u8]) -> Vec<u8> {
    let sig = dilithium3::detached_sign(msg, sk);
    sig.as_bytes().to_vec()
}

pub fn verify_sign(pk: &SignPk, msg: &[u8], sig_bytes: &[u8]) -> bool {
    let sig = match dilithium3::DetachedSignature::from_bytes(sig_bytes) {
        Ok(s) => s,
        Err(_) => return false,
    };
    dilithium3::verify_detached_signature(&sig, msg, pk).is_ok()
}

pub fn pk_fingerprint(pk: &SignPk) -> String {
    let hash = blake3::hash(pk.as_bytes());
    hash.as_bytes()[..8]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

pub enum SigningBackend {
    Software { pk: Box<SignPk>, sk: Box<SignSk> },
    Hardware(TpmIdentity),
}

impl SigningBackend {
    pub fn software() -> Self {
        let (pk, sk) = generate_sign_keypair();
        Self::Software { pk: Box::new(pk), sk: Box::new(sk) }
    }

    pub fn try_hardware_or_software() -> Self {
        match TpmIdentity::new_or_load() {
            Ok(tpm) => {
                log::info!("TPM identity loaded — hardware signing active");
                Self::Hardware(tpm)
            }
            Err(e) => {
                log::debug!("TPM unavailable ({e}), falling back to Dilithium3");
                Self::software()
            }
        }
    }

    pub fn sign_data(&mut self, data: &[u8]) -> Result<Vec<u8>, String> {
        match self {
            Self::Software { sk, .. } => Ok(sign_bytes(sk, data)),
            Self::Hardware(tpm) => tpm.sign(data),
        }
    }

    pub fn pub_key_bytes(&self) -> Vec<u8> {
        match self {
            Self::Software { pk, .. } => pk.as_bytes().to_vec(),
            Self::Hardware(tpm) => tpm.pub_key_bytes().to_vec(),
        }
    }

    pub fn is_hardware(&self) -> bool {
        matches!(self, Self::Hardware(_))
    }
}

pub fn build_v2_ctrl(kem_pk: &[u8], sign_pk: &SignPk, sign_sk: &SignSk) -> Vec<u8> {
    let sig = sign_bytes(sign_sk, kem_pk);
    let mut msg = Vec::with_capacity(CTRL_V2_LEN);
    msg.extend_from_slice(&CTRL_MAGIC);
    msg.extend_from_slice(kem_pk);
    msg.extend_from_slice(sign_pk.as_bytes());
    msg.extend_from_slice(&sig);
    msg
}

pub fn parse_v2_ctrl(data: &[u8]) -> Option<(Vec<u8>, SignPk, bool)> {
    if data.len() != CTRL_V2_LEN {
        return None;
    }
    let magic = &data[..4];
    if magic != CTRL_MAGIC {
        return None;
    }
    let kem_pk = data[4..4 + KEM_PK_LEN].to_vec();
    let dil_pk_bytes = &data[4 + KEM_PK_LEN..4 + KEM_PK_LEN + SIGN_PK_LEN];
    let sig_bytes = &data[4 + KEM_PK_LEN + SIGN_PK_LEN..];

    let sign_pk = SignPk::from_bytes(dil_pk_bytes).ok()?;
    let valid = verify_sign(&sign_pk, &kem_pk, sig_bytes);
    Some((kem_pk, sign_pk, valid))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_verify_roundtrip() {
        let (pk, sk) = generate_sign_keypair();
        let msg = b"labyrinth test message";
        let sig = sign_bytes(&sk, msg);
        assert!(verify_sign(&pk, msg, &sig));
        assert!(!verify_sign(&pk, b"tampered", &sig));
    }

    #[test]
    fn fingerprint_is_stable() {
        let (pk, _) = generate_sign_keypair();
        let fp1 = pk_fingerprint(&pk);
        let fp2 = pk_fingerprint(&pk);
        assert_eq!(fp1, fp2);
        assert_eq!(fp1.len(), 23);
    }

    #[test]
    fn build_and_parse_v2_ctrl() {
        let kem_pk = vec![0xABu8; KEM_PK_LEN];
        let (sign_pk, sign_sk) = generate_sign_keypair();

        let msg = build_v2_ctrl(&kem_pk, &sign_pk, &sign_sk);
        assert_eq!(msg.len(), CTRL_V2_LEN);

        let (recovered_kem_pk, recovered_sign_pk, valid) = parse_v2_ctrl(&msg).unwrap();
        assert_eq!(recovered_kem_pk, kem_pk);
        assert_eq!(recovered_sign_pk.as_bytes(), sign_pk.as_bytes());
        assert!(valid);
    }

    #[test]
    fn tampered_ctrl_fails_verify() {
        let kem_pk = vec![0xABu8; KEM_PK_LEN];
        let (sign_pk, sign_sk) = generate_sign_keypair();
        let mut msg = build_v2_ctrl(&kem_pk, &sign_pk, &sign_sk);
        msg[10] ^= 0xFF;
        let (_, _, valid) = parse_v2_ctrl(&msg).unwrap();
        assert!(!valid);
    }
}
