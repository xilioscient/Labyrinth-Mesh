use sha2::{Sha256, Digest};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use x25519_dalek::PublicKey as X25519Public;
use pqcrypto_kyber::kyber768;
use pqcrypto_traits::kem::{Ciphertext as KemCiphertext, SharedSecret as KemSharedSecret};

use super::client_hello::prepare_key_material;
use super::key_schedule::{
    compute_handshake_keys, compute_application_keys, hmac_sha256,
};
use super::record::{
    decrypt_record, make_encrypted_record, make_tls_record, u24_be,
};
use super::ChromeTlsStream;

pub async fn chrome_tls_connect(
    mut tcp: tokio::net::TcpStream,
    server_name: &str,
    pinned_der: &[u8],
) -> Option<ChromeTlsStream> {
    let (mut mat, ch_bytes) = prepare_key_material(server_name);

    tcp.write_all(&make_tls_record(0x16, &ch_bytes)).await.ok()?;

    let mut transcript = Sha256::new();
    transcript.update(&ch_bytes);

    let (sh_type, sh_data) = read_raw_record(&mut tcp).await?;
    if sh_type != 0x16 { return None; }

    let (sh_hs_type, sh_body) = next_hs_message(&sh_data)?;
    if sh_hs_type != 0x02 { return None; }

    let mut sh_hs_bytes = Vec::with_capacity(4 + sh_body.len());
    sh_hs_bytes.push(0x02);
    let l = sh_body.len() as u32;
    sh_hs_bytes.push((l >> 16) as u8);
    sh_hs_bytes.push((l >> 8) as u8);
    sh_hs_bytes.push(l as u8);
    sh_hs_bytes.extend_from_slice(&sh_body);
    transcript.update(&sh_hs_bytes);

    let (cipher, key_share_data) = parse_server_hello(&sh_body)?;
    if cipher != 0x1301 { return None; }

    let (group, server_key_bytes) = extract_key_share(&key_share_data)?;

    let shared_secret: Vec<u8> = match group {
        0x001d => {
            if server_key_bytes.len() != 32 { return None; }
            let server_pub = X25519Public::from(
                <[u8; 32]>::try_from(server_key_bytes).ok()?
            );
            let secret = mat.x25519_secret.take()?;
            secret.diffie_hellman(&server_pub).as_bytes().to_vec()
        }
        0x6399 => {
            if server_key_bytes.len() != 1120 { return None; }
            let server_x = X25519Public::from(
                <[u8; 32]>::try_from(&server_key_bytes[..32]).ok()?
            );
            let secret = mat.x25519_secret.take()?;
            let x_shared = secret.diffie_hellman(&server_x).as_bytes().to_vec();
            let ct = kyber768::Ciphertext::from_bytes(&server_key_bytes[32..]).ok()?;
            let k_shared = kyber768::decapsulate(&ct, &mat.kyber_sk);
            let mut hybrid = x_shared;
            hybrid.extend_from_slice(k_shared.as_bytes());
            hybrid
        }
        _ => return None,
    };

    let hello_hash: [u8; 32] = transcript.clone().finalize().as_slice().try_into().ok()?;
    let hs_keys = compute_handshake_keys(&shared_secret, &hello_hash);

    let post_fin_hash = read_encrypted_handshake(
        &mut tcp,
        &mut transcript,
        &hs_keys.server_key,
        &hs_keys.server_iv,
        &hs_keys.server_finished_key,
        pinned_der,
    ).await?;

    tcp.write_all(&make_tls_record(0x14, &[0x01])).await.ok()?;

    let verify = hmac_sha256(&hs_keys.client_finished_key, &post_fin_hash);
    let mut fin_hs = Vec::with_capacity(36);
    fin_hs.push(0x14u8);
    fin_hs.extend_from_slice(&[0x00, 0x00, 0x20]);
    fin_hs.extend_from_slice(&verify);
    tcp.write_all(&make_encrypted_record(&fin_hs, 0x16, &hs_keys.client_key, &hs_keys.client_iv, 0))
        .await.ok()?;

    let app_keys = compute_application_keys(&hs_keys.handshake_secret, &post_fin_hash);
    Some(ChromeTlsStream::new(tcp, app_keys))
}

async fn read_encrypted_handshake(
    tcp: &mut tokio::net::TcpStream,
    transcript: &mut Sha256,
    server_key: &[u8; 16],
    server_iv: &[u8; 12],
    server_finished_key: &[u8; 32],
    pinned_der: &[u8],
) -> Option<[u8; 32]> {
    let mut server_seq: u64 = 0;
    let mut hs_buf: Vec<u8> = Vec::new();
    let mut got_ee = false;
    let mut got_cert = false;
    let mut got_cert_verify = false;
    let mut pre_fin_hash = [0u8; 32];

    loop {
        let (ct, data) = read_raw_record(tcp).await?;
        if ct == 0x14 { continue; }
        if ct != 0x17 { return None; }

        let (plaintext, inner_type) = decrypt_record(&data, server_key, server_iv, server_seq)?;
        server_seq += 1;

        if inner_type == 0x15 { return None; }
        if inner_type != 0x16 { continue; }

        hs_buf.extend_from_slice(&plaintext);

        while hs_buf.len() >= 4 {
            let hs_type = hs_buf[0];
            let msg_len = u24_be(&hs_buf[1..4]) as usize;
            if hs_buf.len() < 4 + msg_len { break; }

            let full_msg = hs_buf[..4 + msg_len].to_vec();
            let body = hs_buf[4..4 + msg_len].to_vec();
            hs_buf.drain(..4 + msg_len);

            transcript.update(&full_msg);

            match hs_type {
                0x08 => { got_ee = true; }
                0x0b => {
                    let der = parse_first_cert_der(&body)?;
                    if der != pinned_der { return None; }
                    got_cert = true;
                }
                0x0f => { got_cert_verify = true; }
                0x14 => {
                    if !got_ee || !got_cert || !got_cert_verify { return None; }
                    if body.len() != 32 { return None; }
                    let expected = hmac_sha256(server_finished_key, &pre_fin_hash);
                    if body[..] != expected { return None; }
                    return transcript.clone().finalize().as_slice().try_into().ok();
                }
                _ => {}
            }

            if hs_type != 0x14 {
                pre_fin_hash = transcript.clone().finalize()
                    .as_slice().try_into().unwrap_or([0u8; 32]);
            }
        }
    }
}

async fn read_raw_record(tcp: &mut tokio::net::TcpStream) -> Option<(u8, Vec<u8>)> {
    let mut hdr = [0u8; 5];
    tcp.read_exact(&mut hdr).await.ok()?;
    let len = u16::from_be_bytes([hdr[3], hdr[4]]) as usize;
    let mut data = vec![0u8; len];
    tcp.read_exact(&mut data).await.ok()?;
    Some((hdr[0], data))
}

fn next_hs_message(data: &[u8]) -> Option<(u8, Vec<u8>)> {
    if data.len() < 4 { return None; }
    let len = u24_be(&data[1..4]) as usize;
    if data.len() < 4 + len { return None; }
    Some((data[0], data[4..4 + len].to_vec()))
}

fn parse_server_hello(body: &[u8]) -> Option<(u16, Vec<u8>)> {
    if body.len() < 40 { return None; }
    let sil = body[34] as usize;
    let base = 35 + sil;
    if body.len() < base + 5 { return None; }
    let cipher = u16::from_be_bytes([body[base], body[base + 1]]);
    let ext_total = u16::from_be_bytes([body[base + 3], body[base + 4]]) as usize;
    let ext_start = base + 5;
    if body.len() < ext_start + ext_total { return None; }
    let ks = parse_key_share_ext(&body[ext_start..ext_start + ext_total])?;
    Some((cipher, ks))
}

fn parse_key_share_ext(ext_bytes: &[u8]) -> Option<Vec<u8>> {
    let mut pos = 0;
    while pos + 4 <= ext_bytes.len() {
        let typ = u16::from_be_bytes([ext_bytes[pos], ext_bytes[pos + 1]]);
        let len = u16::from_be_bytes([ext_bytes[pos + 2], ext_bytes[pos + 3]]) as usize;
        pos += 4;
        if pos + len > ext_bytes.len() { return None; }
        if typ == 0x0033 { return Some(ext_bytes[pos..pos + len].to_vec()); }
        pos += len;
    }
    None
}

fn extract_key_share(data: &[u8]) -> Option<(u16, &[u8])> {
    if data.len() < 4 { return None; }
    let group = u16::from_be_bytes([data[0], data[1]]);
    let key_len = u16::from_be_bytes([data[2], data[3]]) as usize;
    if data.len() < 4 + key_len { return None; }
    Some((group, &data[4..4 + key_len]))
}

fn parse_first_cert_der(body: &[u8]) -> Option<Vec<u8>> {
    if body.is_empty() { return None; }
    let ctx_len = body[0] as usize;
    let pos = 1 + ctx_len;
    if body.len() < pos + 3 { return None; }
    let pos = pos + 3;
    if body.len() < pos + 3 { return None; }
    let cert_len = u24_be(&body[pos..pos + 3]) as usize;
    let pos = pos + 3;
    if body.len() < pos + cert_len { return None; }
    Some(body[pos..pos + cert_len].to_vec())
}
