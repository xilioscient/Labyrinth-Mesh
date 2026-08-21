mod gf256;

pub use gf256::GF256;

use rand::rngs::OsRng;
use rand::Rng;
use rayon::prelude::*;

pub const DMPOT_MAGIC: [u8; 2] = [0xD4, 0x5E];

#[derive(Debug, Clone, Copy)]
pub struct FragmentHeader {
    pub session_id: [u8; 16],
    pub x: u8,
    pub total: u8,
}

impl FragmentHeader {
    pub fn new(x: u8, total: u8) -> Self {
        let mut rng = OsRng;
        let mut session_id = [0u8; 16];
        rng.fill(&mut session_id);
        FragmentHeader { session_id, x, total }
    }

    pub fn serialize(&self) -> [u8; 18] {
        let mut buf = [0u8; 18];
        buf[0..16].copy_from_slice(&self.session_id);
        buf[16] = self.x;
        buf[17] = self.total;
        buf
    }

    pub fn deserialize(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 18 { return None; }
        let mut session_id = [0u8; 16];
        session_id.copy_from_slice(&bytes[0..16]);
        Some(FragmentHeader { session_id, x: bytes[16], total: bytes[17] })
    }
}

#[derive(Debug, Clone)]
pub struct DMPOTFragment {
    pub header: FragmentHeader,
    pub payload: Vec<u8>,
}

impl DMPOTFragment {
    pub fn new(header: FragmentHeader, payload: Vec<u8>) -> Self {
        DMPOTFragment { header, payload }
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(2 + 18 + self.payload.len());
        buf.extend_from_slice(&DMPOT_MAGIC);
        buf.extend_from_slice(&self.header.serialize());
        buf.extend_from_slice(&self.payload);
        buf
    }

    pub fn deserialize(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 20 { return None; }
        if bytes[0..2] != DMPOT_MAGIC { return None; }
        let header = FragmentHeader::deserialize(&bytes[2..20])?;
        Some(DMPOTFragment { header, payload: bytes[20..].to_vec() })
    }
}

pub fn split_payload(payload: &[u8], n: u8, k: u8) -> Vec<DMPOTFragment> {
    assert!(n >= k, "n must be >= k");
    assert!(n >= 2, "n must be at least 2");
    assert!(k >= 1, "k must be at least 1");

    let mut rng = OsRng;

    let session_id = {
        let mut id = [0u8; 16];
        rng.fill(&mut id);
        id
    };
    let mut fragments: Vec<DMPOTFragment> = (0..n)
        .map(|i| DMPOTFragment {
            header: FragmentHeader { session_id, x: i + 1, total: n },
            payload: Vec::with_capacity(payload.len()),
        })
        .collect();

    let all_shares: Vec<Vec<u8>> = payload
        .par_iter()
        .map(|&secret_byte| {
            let mut rng = rand::thread_rng();
            let secret = GF256::from(secret_byte);
            let mut coeffs = Vec::with_capacity(k as usize);
            coeffs.push(secret);
            for _ in 1..k {
                coeffs.push(GF256::random(&mut rng));
            }
            let mut byte_shares = Vec::with_capacity(n as usize);
            for i in 0..n as usize {
                let x = GF256::from(i as u8 + 1);
                let mut y = GF256::ZERO;
                let mut x_pow = GF256::ONE;
                for &c in &coeffs {
                    y = y.add(c.mul(x_pow));
                    x_pow = x_pow.mul(x);
                }
                byte_shares.push(y.to_u8());
            }
            byte_shares
        })
        .collect();

    for byte_shares in all_shares {
        for (i, share) in byte_shares.into_iter().enumerate() {
            fragments[i].payload.push(share);
        }
    }

    fragments
}

pub fn reconstruct_payload(fragments: &[DMPOTFragment]) -> Vec<u8> {
    assert!(!fragments.is_empty(), "need at least one fragment");

    let session_id = fragments[0].header.session_id;
    for f in fragments {
        assert_eq!(f.header.session_id, session_id, "session_id mismatch");
    }

    let payload_len = fragments[0].payload.len();
    if fragments.iter().any(|f| f.payload.len() != payload_len) {
        log::warn!("reconstruct_payload: fragment length mismatch — dropping");
        return Vec::new();
    }
    let mut reconstructed = Vec::with_capacity(payload_len);

    for byte_idx in 0..payload_len {
        let points: Vec<(GF256, GF256)> = fragments
            .iter()
            .map(|f| (GF256::from(f.header.x), GF256::from(f.payload[byte_idx])))
            .collect();

        let mut secret = GF256::ZERO;
        for (i, &(xi, yi)) in points.iter().enumerate() {
            let mut num = GF256::ONE;
            let mut den = GF256::ONE;
            for (j, &(xj, _)) in points.iter().enumerate() {
                if i != j {
                    num = num.mul(xj);
                    den = den.mul(xi.add(xj));
                }
            }
            let lagrange = num.div(den);
            secret = secret.add(yi.mul(lagrange));
        }
        reconstructed.push(secret.to_u8());
    }

    reconstructed
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_split_reconstruct_exact_k() {
        let payload = b"DMPOT Test Payload 12345";
        let (n, k) = (5u8, 3u8);
        let fragments = split_payload(payload, n, k);
        assert_eq!(fragments.len(), n as usize);

        let subset: Vec<_> = fragments.iter().take(k as usize).cloned().collect();
        assert_eq!(reconstruct_payload(&subset), payload.as_slice());
    }

    #[test]
    fn test_split_reconstruct_all_shares() {
        let payload = b"All shares reconstruction test";
        let fragments = split_payload(payload, 7, 4);
        assert_eq!(reconstruct_payload(&fragments), payload.as_slice());
    }

    #[test]
    fn test_split_reconstruct_different_k_subset() {
        let payload = b"Subset reconstruction";
        let fragments = split_payload(payload, 6, 3);
        let subset = vec![fragments[1].clone(), fragments[3].clone(), fragments[4].clone()];
        assert_eq!(reconstruct_payload(&subset), payload.as_slice());
    }

    #[test]
    fn test_fragment_serialization_round_trip() {
        let header = FragmentHeader::new(2, 5);
        let fragment = DMPOTFragment::new(header, vec![0xAA, 0xBB, 0xCC]);
        let serialized = fragment.serialize();
        let deserialized = DMPOTFragment::deserialize(&serialized).unwrap();
        assert_eq!(fragment.header.session_id, deserialized.header.session_id);
        assert_eq!(fragment.header.x, deserialized.header.x);
        assert_eq!(fragment.payload, deserialized.payload);
    }

    #[test]
    fn test_threshold_2_of_3() {
        let payload = b"k=2 threshold test";
        let fragments = split_payload(payload, 3, 2);
        let s01 = vec![fragments[0].clone(), fragments[1].clone()];
        let s12 = vec![fragments[1].clone(), fragments[2].clone()];
        let s02 = vec![fragments[0].clone(), fragments[2].clone()];
        assert_eq!(reconstruct_payload(&s01), payload.as_slice());
        assert_eq!(reconstruct_payload(&s12), payload.as_slice());
        assert_eq!(reconstruct_payload(&s02), payload.as_slice());
    }
}
