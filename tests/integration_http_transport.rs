use labyrinth_core::http_transport;

#[test]
fn test_tls_bundle_generation() {
    let bundle = http_transport::generate_tls_bundle();
    assert!(!bundle.cert_der.is_empty());
    assert!(!bundle.key_der.is_empty());
    assert!(!bundle.cert_pem.is_empty());
    assert!(!bundle.key_pem.is_empty());
    assert_ne!(bundle.fingerprint, [0u8; 32]);

    let fp2 = *blake3::hash(&bundle.cert_der).as_bytes();
    assert_eq!(bundle.fingerprint, fp2);
}

#[test]
fn test_bucket_pad_unpad_roundtrip() {
    let payloads: &[&[u8]] = &[
        b"short",
        &vec![0xABu8; 100],
        &vec![0x55u8; 510],
        &vec![0xFFu8; 1022],
        &vec![0x00u8; 2046],
        &vec![0x01u8; 4094],
    ];

    for payload in payloads {
        let padded = http_transport::bucket_pad(payload);
        let unpacked = http_transport::bucket_unpad(&padded).expect("unpad failed");
        assert_eq!(&unpacked, payload, "roundtrip failed for payload len {}", payload.len());
    }
}

#[test]
fn test_bucket_pad_sizes() {
    static BUCKETS: &[usize] = &[512, 1024, 2048, 4096, 8192];

    for payload_len in [1, 50, 100, 300, 509, 510, 511, 1000, 1021, 1022, 2044, 4090] {
        let payload = vec![0u8; payload_len];
        let padded = http_transport::bucket_pad(&payload);
        let expected = BUCKETS
            .iter()
            .copied()
            .find(|&b| b >= payload_len + 2)
            .unwrap_or(payload_len + 2);
        assert_eq!(padded.len(), expected, "wrong bucket for payload len {payload_len}");
    }
}

#[test]
fn test_bucket_unpad_truncated_returns_none() {
    assert!(http_transport::bucket_unpad(&[]).is_none());
    assert!(http_transport::bucket_unpad(&[0]).is_none());
    let too_short = [0u8, 200u8, 0u8];
    assert!(http_transport::bucket_unpad(&too_short).is_none());
}

#[test]
fn test_sample_iat_ms_range() {
    for _ in 0..500 {
        let iat = http_transport::sample_iat_ms();
        assert!(iat >= 2, "iat {iat} below minimum");
        assert!(iat <= 5001, "iat {iat} above maximum");
    }
}

#[test]
fn test_chrome_headers_content_length() {
    let headers = http_transport::chrome_headers(1024);
    let cl = headers.iter().find(|(k, _)| *k == "content-length");
    assert!(cl.is_some(), "content-length header missing");
    assert_eq!(cl.unwrap().1, "1024");

    let ua = headers.iter().find(|(k, _)| *k == "user-agent");
    assert!(ua.is_some(), "user-agent missing");
    assert!(ua.unwrap().1.contains("Mozilla"));
}

#[test]
fn test_https_loopback_e2e() {
    use std::sync::mpsc;
    use std::thread;
    use std::time::Duration;

    let bind_addr: std::net::SocketAddr = "127.0.0.1:19444".parse().unwrap();

    let bundle = http_transport::generate_tls_bundle();
    let cert_der_server = bundle.cert_der.clone();
    let key_der_server = bundle.key_der.clone();
    let cert_der_client = bundle.cert_der.clone();

    let (tx, rx) = mpsc::sync_channel::<Vec<u8>>(16);

    thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("test tokio rt");
        rt.block_on(http_transport::run_https_share_server(
            bind_addr,
            cert_der_server,
            key_der_server,
            tx,
        ));
    });

    thread::sleep(Duration::from_millis(200));

    let payload = b"labyrinth-http-e2e-test-payload";
    let client = http_transport::build_chrome_client(&cert_der_client);
    let url = format!("https://{}/s", bind_addr);
    let padded = http_transport::bucket_pad(payload);
    client.post_share(&url, padded);

    let received = rx
        .recv_timeout(Duration::from_secs(3))
        .expect("no share received within timeout");
    assert_eq!(received.as_slice(), payload, "received payload mismatch");
}
