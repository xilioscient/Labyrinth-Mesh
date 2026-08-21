use sharks::{Share, Sharks};
use super::{hybrid_encapsulate_from_wire, HybridReceiverKeypair, SessionKey, HYBRID_PK_WIRE_LEN};

const SHARE_ENC_DOMAIN: &[u8] = b"tkem-share-enc";
const SESSION_KEY_DOMAIN: &str = "labyrinth-tkem-v1 session";

pub const TKEM_MIN_THRESHOLD: usize = 2;

pub const TKEM_PK_MAGIC:  [u8; 4] = [0x54, 0x4B, 0x50, 0x4B];
pub const TKEM_CT_MAGIC:  [u8; 4] = [0x54, 0x4B, 0x43, 0x54];

pub struct RelayPacket {
    pub relay_idx:  usize,
    pub kyber_ct:   Vec<u8>,
    pub x25519_spk: [u8; 32],
    pub enc_share:  Vec<u8>,
}

pub struct TkemSender {
    pub session_key:    SessionKey,
    pub relay_packets:  Vec<RelayPacket>,
}

fn derive_enc_key(kem_secret: &[u8; 32]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(SHARE_ENC_DOMAIN);
    h.update(kem_secret);
    *h.finalize().as_bytes()
}

fn xor_stream(data: &[u8], key: &[u8; 32]) -> Vec<u8> {
    data.iter().enumerate().map(|(i, &b)| b ^ key[i % 32]).collect()
}

pub fn tkem_send(relay_pks: &[Vec<u8>], threshold: usize) -> Option<TkemSender> {
    let n = relay_pks.len();
    if n == 0 || threshold < TKEM_MIN_THRESHOLD || threshold > n {
        return None;
    }

    let mut master = [0u8; 32];
    getrandom::getrandom(&mut master).ok()?;

    let sharks = Sharks(threshold as u8);
    let shares: Vec<Share> = sharks.dealer(&master).take(n).collect();
    let session_key_bytes = blake3::derive_key(SESSION_KEY_DOMAIN, &master);

    let relay_packets = relay_pks
        .iter()
        .zip(shares.iter())
        .enumerate()
        .map(|(i, (pk_wire, share))| {
            let encap = hybrid_encapsulate_from_wire(pk_wire)?;
            let share_bytes: Vec<u8> = share.into();
            let enc_key = derive_enc_key(&encap.shared_secret);
            let enc_share = xor_stream(&share_bytes, &enc_key);
            Some(RelayPacket {
                relay_idx:  i,
                kyber_ct:   encap.kyber_ct_bytes,
                x25519_spk: encap.x25519_sender_pk,
                enc_share,
            })
        })
        .collect::<Option<Vec<_>>>()?;

    Some(TkemSender {
        session_key: SessionKey(session_key_bytes),
        relay_packets,
    })
}

pub fn tkem_relay_decapsulate(
    relay_kp:   &HybridReceiverKeypair,
    kyber_ct:   &[u8],
    x25519_spk: &[u8; 32],
    enc_share:  &[u8],
) -> Option<Vec<u8>> {
    let kem_secret = relay_kp.decapsulate(kyber_ct, x25519_spk)?;
    let enc_key = derive_enc_key(&kem_secret);
    Some(xor_stream(enc_share, &enc_key))
}

pub fn tkem_recover(shares: &[Vec<u8>], threshold: usize) -> Option<SessionKey> {
    if shares.len() < threshold {
        return None;
    }
    let sharks = Sharks(threshold as u8);
    let parsed: Vec<Share> = shares
        .iter()
        .filter_map(|b| Share::try_from(b.as_slice()).ok())
        .collect();
    if parsed.len() < threshold {
        return None;
    }
    let master_vec = sharks.recover(&parsed).ok()?;
    let master: [u8; 32] = master_vec.try_into().ok()?;
    Some(SessionKey(blake3::derive_key(SESSION_KEY_DOMAIN, &master)))
}

pub fn encode_pk_bundle(relay_pks: &[Vec<u8>], threshold: usize) -> Vec<u8> {
    let n = relay_pks.len();
    let mut out = Vec::with_capacity(4 + 2 + n * HYBRID_PK_WIRE_LEN);
    out.extend_from_slice(&TKEM_PK_MAGIC);
    out.push(n as u8);
    out.push(threshold as u8);
    for pk in relay_pks {
        out.extend_from_slice(pk);
    }
    out
}

pub fn decode_pk_bundle(buf: &[u8]) -> Option<(Vec<Vec<u8>>, usize)> {
    if buf.len() < 6 || buf[0..4] != TKEM_PK_MAGIC { return None; }
    let n = buf[4] as usize;
    let threshold = buf[5] as usize;
    let expected = 6 + n * HYBRID_PK_WIRE_LEN;
    if buf.len() < expected { return None; }
    let pks = (0..n)
        .map(|i| buf[6 + i * HYBRID_PK_WIRE_LEN .. 6 + (i + 1) * HYBRID_PK_WIRE_LEN].to_vec())
        .collect();
    Some((pks, threshold))
}

pub fn encode_ct_bundle(packets: &[RelayPacket]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&TKEM_CT_MAGIC);
    out.push(packets.len() as u8);
    for p in packets {
        out.extend_from_slice(&p.kyber_ct);
        out.extend_from_slice(&p.x25519_spk);
        let slen = p.enc_share.len() as u16;
        out.extend_from_slice(&slen.to_le_bytes());
        out.extend_from_slice(&p.enc_share);
    }
    out
}

pub fn decode_and_recover(
    buf: &[u8],
    relay_kps: &[HybridReceiverKeypair],
    threshold: usize,
) -> Option<SessionKey> {
    use super::HYBRID_KYBER_CT_LEN;
    if buf.len() < 5 || buf[0..4] != TKEM_CT_MAGIC { return None; }
    let n = buf[4] as usize;
    if n != relay_kps.len() { return None; }
    let mut pos = 5;
    let mut shares: Vec<Vec<u8>> = Vec::with_capacity(n);
    for kp in relay_kps {
        if pos + HYBRID_KYBER_CT_LEN + 32 + 2 > buf.len() { return None; }
        let kyber_ct = &buf[pos..pos + HYBRID_KYBER_CT_LEN];
        pos += HYBRID_KYBER_CT_LEN;
        let x25519_spk: [u8; 32] = buf[pos..pos + 32].try_into().ok()?;
        pos += 32;
        let slen = u16::from_le_bytes(buf[pos..pos + 2].try_into().ok()?) as usize;
        pos += 2;
        if pos + slen > buf.len() { return None; }
        let enc_share = &buf[pos..pos + slen];
        pos += slen;
        if let Some(share) = tkem_relay_decapsulate(kp, kyber_ct, &x25519_spk, enc_share) {
            shares.push(share);
        }
    }
    tkem_recover(&shares, threshold)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::v2::HybridReceiverKeypair;

    #[test]
    fn tkem_send_recover_roundtrip() {
        let kps: Vec<HybridReceiverKeypair> = (0..3).map(|_| HybridReceiverKeypair::generate()).collect();
        let pks: Vec<Vec<u8>> = kps.iter().map(|kp| kp.pk_wire()).collect();

        let setup = tkem_send(&pks, 2).expect("tkem_send");
        let mut shares: Vec<Vec<u8>> = Vec::new();
        for p in &setup.relay_packets {
            let share = tkem_relay_decapsulate(
                &kps[p.relay_idx],
                &p.kyber_ct,
                &p.x25519_spk,
                &p.enc_share,
            ).expect("relay decap");
            shares.push(share);
        }

        let recovered = tkem_recover(&shares, 2).expect("recover");
        assert_eq!(recovered.0, setup.session_key.0);
    }

    #[test]
    fn tkem_threshold_2of3_works_with_any_two_shares() {
        let kps: Vec<HybridReceiverKeypair> = (0..3).map(|_| HybridReceiverKeypair::generate()).collect();
        let pks: Vec<Vec<u8>> = kps.iter().map(|kp| kp.pk_wire()).collect();
        let setup = tkem_send(&pks, 2).unwrap();

        let all_shares: Vec<Vec<u8>> = setup.relay_packets.iter().map(|p| {
            tkem_relay_decapsulate(&kps[p.relay_idx], &p.kyber_ct, &p.x25519_spk, &p.enc_share).unwrap()
        }).collect();

        for combo in [[0usize, 1], [0, 2], [1, 2]] {
            let subset: Vec<Vec<u8>> = combo.iter().map(|&i| all_shares[i].clone()).collect();
            let key = tkem_recover(&subset, 2).expect("2-of-3 combo");
            assert_eq!(key.0, setup.session_key.0, "combo {combo:?} failed");
        }
    }

    #[test]
    fn tkem_one_share_insufficient() {
        let kps: Vec<HybridReceiverKeypair> = (0..3).map(|_| HybridReceiverKeypair::generate()).collect();
        let pks: Vec<Vec<u8>> = kps.iter().map(|kp| kp.pk_wire()).collect();
        let setup = tkem_send(&pks, 2).unwrap();
        let one_share = vec![
            tkem_relay_decapsulate(
                &kps[0], &setup.relay_packets[0].kyber_ct,
                &setup.relay_packets[0].x25519_spk, &setup.relay_packets[0].enc_share,
            ).unwrap(),
        ];
        assert!(tkem_recover(&one_share, 2).is_none());
    }

    #[test]
    fn encode_decode_pk_bundle_roundtrip() {
        let kps: Vec<HybridReceiverKeypair> = (0..3).map(|_| HybridReceiverKeypair::generate()).collect();
        let pks: Vec<Vec<u8>> = kps.iter().map(|kp| kp.pk_wire()).collect();
        let encoded = encode_pk_bundle(&pks, 2);
        let (decoded_pks, decoded_thresh) = decode_pk_bundle(&encoded).expect("decode");
        assert_eq!(decoded_thresh, 2);
        assert_eq!(decoded_pks.len(), 3);
        for (orig, dec) in pks.iter().zip(decoded_pks.iter()) {
            assert_eq!(orig, dec);
        }
    }

    #[test]
    fn decode_and_recover_full_bundle() {
        let kps: Vec<HybridReceiverKeypair> = (0..3).map(|_| HybridReceiverKeypair::generate()).collect();
        let pks: Vec<Vec<u8>> = kps.iter().map(|kp| kp.pk_wire()).collect();
        let setup = tkem_send(&pks, 2).unwrap();
        let ct_bundle = encode_ct_bundle(&setup.relay_packets);
        let recovered = decode_and_recover(&ct_bundle, &kps, 2).expect("full bundle");
        assert_eq!(recovered.0, setup.session_key.0);
    }
}
