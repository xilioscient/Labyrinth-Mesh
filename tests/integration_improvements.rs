use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::Duration;

use labyrinth_core::phase3::{self, Tls13Plugin, QuicPlugin, WebRtcPlugin, Http2Plugin, MorphPlugin};
use labyrinth_core::v2::{
    generate_keypair, kem_encapsulate, kem_decapsulate,
    split_and_tag, verify_and_recover,
    HybridReceiverKeypair,
    tkem_send, encode_pk_bundle, encode_ct_bundle, decode_and_recover,
    TKEM_PK_MAGIC,
};

#[test]
fn test_steganography_wrap_strip_all_protocols() {
    let key = [0xABu8; 32];
    let fake_share: Vec<u8> = (0u8..80).collect();

    for path_idx in 0..4 {
        let framed = phase3::wrap_for_path(path_idx, &fake_share, &key);
        assert!(framed.len() > fake_share.len(), "path {path_idx}: frame must be larger than payload");

        let stripped = phase3::try_strip_transport_frame(&framed)
            .unwrap_or_else(|| panic!("path {path_idx}: strip returned None"));
        assert_eq!(stripped, fake_share, "path {path_idx}: roundtrip mismatch");
    }
}

#[test]
fn test_steganography_auto_detect_protocol() {
    let key = [0x55u8; 32];
    let payload = b"test payload for auto-detection of protocol framing";

    let tls_framed   = Tls13Plugin.encapsulate(payload, &key);
    let quic_framed  = QuicPlugin.encapsulate(payload, &key);
    let ws_framed    = WebRtcPlugin.encapsulate(payload, &key);
    let http2_framed = Http2Plugin.encapsulate(payload, &key);

    for (name, framed) in [("tls", tls_framed), ("quic", quic_framed), ("ws", ws_framed), ("http2", http2_framed)] {
        let stripped = phase3::try_strip_transport_frame(&framed)
            .unwrap_or_else(|| panic!("{name}: auto-detect failed"));
        assert_eq!(stripped, payload, "{name}: stripped != original");
    }
}

#[test]
fn test_steganography_unframed_returns_none() {
    let raw_data: Vec<u8> = (0u8..100).collect();
    let result = phase3::try_strip_transport_frame(&raw_data);
    assert!(result.is_none(), "random bytes should not be detected as a protocol frame");
}

#[test]
fn test_v2_pipeline_with_steganography() {
    let (pk_bytes, sk_bytes) = generate_keypair();
    let (ct_bytes, sender_key) = kem_encapsulate(&pk_bytes).unwrap();
    let receiver_key = kem_decapsulate(&sk_bytes, &ct_bytes).unwrap();

    let payload = b"Labyrinth steganography integration: the full v2 pipeline with protocol morphing";
    let seq: u64 = 0xDEAD_BEEF_CAFE_1234;

    let shares = split_and_tag(payload, &sender_key, seq);
    assert_eq!(shares.len(), 5);

    let enc_key = [0x77u8; 32];
    let framed: Vec<Vec<u8>> = shares
        .iter()
        .enumerate()
        .map(|(i, _)| {
            let raw_share = {
                let mut pkt = Vec::new();
                pkt.extend_from_slice(&shares[i].tag);
                pkt.extend_from_slice(&seq.to_le_bytes());
                pkt.push(shares[i].index);
                pkt.extend_from_slice(&shares[i].share_bytes);
                pkt
            };
            phase3::wrap_for_path(i, &raw_share, &enc_key)
        })
        .collect();

    let unframed_shares: Vec<labyrinth_core::v2::TaggedShare> = framed
        .iter()
        .map(|f| {
            let inner = phase3::try_strip_transport_frame(f).expect("strip failed");
            use labyrinth_core::v2::AUTH_TAG_LEN;
            let mut tag = [0u8; AUTH_TAG_LEN];
            tag.copy_from_slice(&inner[..AUTH_TAG_LEN]);
            let _seq = u64::from_le_bytes(inner[AUTH_TAG_LEN..AUTH_TAG_LEN + 8].try_into().unwrap());
            let index = inner[AUTH_TAG_LEN + 8];
            let share_bytes = inner[AUTH_TAG_LEN + 9..].to_vec();
            labyrinth_core::v2::TaggedShare { tag, index, share_bytes }
        })
        .collect();

    let recovered = verify_and_recover(&unframed_shares[..3], &receiver_key, seq)
        .expect("reconstruct failed");
    assert_eq!(recovered.as_slice(), payload);
}

#[test]
fn test_threshold_kem_tcp_loopback() {
    use labyrinth_core::v2::HYBRID_PK_WIRE_LEN;

    let ctrl_addr: std::net::SocketAddr = "127.0.0.1:19200".parse().unwrap();
    let n_relays = 3;
    let threshold = 2;

    let relay_kps: Vec<HybridReceiverKeypair> = (0..n_relays)
        .map(|_| HybridReceiverKeypair::generate())
        .collect();
    let relay_pks: Vec<Vec<u8>> = relay_kps.iter().map(|kp| kp.pk_wire()).collect();
    let pk_bundle = encode_pk_bundle(&relay_pks, threshold);

    let kps_moved = relay_kps;
    let bundle_moved = pk_bundle.clone();

    let recv_handle = thread::spawn(move || -> [u8; 32] {
        let listener = TcpListener::bind(ctrl_addr).expect("bind");
        let (mut stream, _) = listener.accept().expect("accept");

        stream.write_all(&bundle_moved).and_then(|_| stream.flush()).expect("send pk bundle");

        let mut len_buf = [0u8; 4];
        stream.read_exact(&mut len_buf).expect("read ct len");
        let ct_len = u32::from_le_bytes(len_buf) as usize;
        let mut ct_buf = vec![0u8; ct_len];
        stream.read_exact(&mut ct_buf).expect("read ct bundle");

        let sk = decode_and_recover(&ct_buf, &kps_moved, threshold).expect("recover failed");
        sk.0
    });

    thread::sleep(Duration::from_millis(50));

    let sender_sk = {
        let mut stream = TcpStream::connect(ctrl_addr).expect("connect");

        let mut magic = [0u8; 4];
        stream.read_exact(&mut magic).expect("read magic");
        assert_eq!(magic, TKEM_PK_MAGIC, "unexpected magic");

        let mut header = [0u8; 2];
        stream.read_exact(&mut header).expect("read header");
        let n = header[0] as usize;
        let recv_thresh = header[1] as usize;
        assert_eq!(n, n_relays);
        assert_eq!(recv_thresh, threshold);

        let mut pk_buf = vec![0u8; n * HYBRID_PK_WIRE_LEN];
        stream.read_exact(&mut pk_buf).expect("read pks");

        let pks: Vec<Vec<u8>> = (0..n)
            .map(|i| pk_buf[i * HYBRID_PK_WIRE_LEN..(i + 1) * HYBRID_PK_WIRE_LEN].to_vec())
            .collect();

        let setup = tkem_send(&pks, threshold).expect("tkem_send");
        let ct_bundle = encode_ct_bundle(&setup.relay_packets);
        let ct_len = ct_bundle.len() as u32;
        stream.write_all(&ct_len.to_le_bytes()).expect("send ct len");
        stream.write_all(&ct_bundle).expect("send ct bundle");
        stream.flush().expect("flush");

        setup.session_key.0
    };

    let receiver_sk = recv_handle.join().expect("receiver panicked");
    assert_eq!(sender_sk, receiver_sk, "sender and receiver must derive identical session keys");
}

#[test]
fn test_threshold_kem_2of3_security_property() {
    let relay_kps: Vec<HybridReceiverKeypair> = (0..3)
        .map(|_| HybridReceiverKeypair::generate())
        .collect();
    let pks: Vec<Vec<u8>> = relay_kps.iter().map(|kp| kp.pk_wire()).collect();
    let setup = tkem_send(&pks, 2).unwrap();

    let all_shares: Vec<Vec<u8>> = setup.relay_packets.iter().map(|p| {
        use labyrinth_core::v2::tkem_relay_decapsulate;
        tkem_relay_decapsulate(&relay_kps[p.relay_idx], &p.kyber_ct, &p.x25519_spk, &p.enc_share).unwrap()
    }).collect();

    let expected = setup.session_key.0;

    for pair in [[0usize, 1], [0, 2], [1, 2]] {
        use labyrinth_core::v2::tkem_recover;
        let subset: Vec<Vec<u8>> = pair.iter().map(|&i| all_shares[i].clone()).collect();
        let sk = tkem_recover(&subset, 2).expect("2-of-3 must work");
        assert_eq!(sk.0, expected, "pair {pair:?} gave wrong key");
    }

    use labyrinth_core::v2::tkem_recover;
    let one = vec![all_shares[0].clone()];
    assert!(tkem_recover(&one, 2).is_none(), "1 share must be insufficient");
}
