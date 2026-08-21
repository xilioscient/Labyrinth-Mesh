use rcgen::{CertificateParams, DistinguishedName, KeyPair};

pub struct TlsBundle {
    pub cert_pem: String,
    pub key_pem: String,
    pub cert_der: Vec<u8>,
    pub key_der: Vec<u8>,
    pub fingerprint: [u8; 32],
}

pub fn generate_tls_bundle() -> TlsBundle {
    let key = KeyPair::generate().expect("tls keygen");
    let mut params = CertificateParams::default();
    params.distinguished_name = DistinguishedName::new();
    params.distinguished_name.push(rcgen::DnType::CommonName, "labyrinth");
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let cert = params.self_signed(&key).expect("self-sign");
    let cert_der = cert.der().to_vec();
    let key_der = key.serialize_der();
    let fingerprint = *blake3::hash(&cert_der).as_bytes();
    TlsBundle {
        cert_pem: cert.pem(),
        key_pem: key.serialize_pem(),
        cert_der,
        key_der,
        fingerprint,
    }
}

static BUCKET_SIZES: &[usize] = &[512, 1024, 2048, 4096, 8192];

pub fn bucket_pad(data: &[u8]) -> Vec<u8> {
    let target = BUCKET_SIZES
        .iter()
        .copied()
        .find(|&b| b >= data.len() + 2)
        .unwrap_or(data.len() + 2);
    let mut out = Vec::with_capacity(target);
    out.extend_from_slice(&(data.len() as u16).to_be_bytes());
    out.extend_from_slice(data);
    out.resize(target, 0xAB);
    out
}

pub fn bucket_unpad(data: &[u8]) -> Option<Vec<u8>> {
    if data.len() < 2 {
        return None;
    }
    let len = u16::from_be_bytes([data[0], data[1]]) as usize;
    if 2 + len > data.len() {
        return None;
    }
    Some(data[2..2 + len].to_vec())
}

pub fn sample_iat_ms() -> u64 {
    static BUCKETS: &[(u32, u64, u64)] = &[
        (40, 2, 15),
        (30, 15, 80),
        (20, 80, 400),
        (8, 400, 1500),
        (2, 1500, 5000),
    ];
    let total: u32 = BUCKETS.iter().map(|(w, _, _)| w).sum();
    let mut pick = rand::random::<u32>() % total;
    for &(w, lo, hi) in BUCKETS {
        if pick < w {
            return lo + rand::random::<u64>() % (hi - lo + 1);
        }
        pick -= w;
    }
    50
}

pub fn chrome_headers(content_len: usize) -> Vec<(&'static str, String)> {
    vec![
        ("user-agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36".to_string()),
        ("accept", "*/*".to_string()),
        ("accept-encoding", "gzip, deflate, br".to_string()),
        ("accept-language", "en-US,en;q=0.9".to_string()),
        ("cache-control", "no-cache".to_string()),
        ("content-type", "application/octet-stream".to_string()),
        ("content-length", content_len.to_string()),
    ]
}

#[derive(Clone)]
pub struct ChromeClient {
    rt: std::sync::Arc<tokio::runtime::Runtime>,
    pinned_der: std::sync::Arc<Vec<u8>>,
}

pub fn build_chrome_client(cert_der: &[u8]) -> ChromeClient {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(2)
        .build()
        .expect("chrome client runtime");
    ChromeClient {
        rt: std::sync::Arc::new(rt),
        pinned_der: std::sync::Arc::new(cert_der.to_vec()),
    }
}

impl ChromeClient {
    pub fn post_share(&self, url: &str, padded_body: Vec<u8>) -> bool {
        let url = url.to_string();
        let pinned = self.pinned_der.clone();
        self.rt
            .block_on(chrome_post_opt(url, padded_body, pinned))
            .is_some()
    }
}

async fn chrome_post_opt(
    url: String,
    body: Vec<u8>,
    pinned_der: std::sync::Arc<Vec<u8>>,
) -> Option<()> {
    use crate::chrome_tls::chrome_tls_connect;
    use http_body_util::Full;
    use hyper_util::rt::{TokioExecutor, TokioIo};

    let addr_str = url
        .strip_prefix("https://")
        .and_then(|s| s.split('/').next())?;
    let addr: std::net::SocketAddr = addr_str.parse().ok()?;

    let tcp = tokio::net::TcpStream::connect(addr).await.ok()?;
    let tls = chrome_tls_connect(tcp, "labyrinth", &pinned_der).await?;
    let io = TokioIo::new(tls);

    let (mut sender, conn) = hyper::client::conn::http2::Builder::new(TokioExecutor::new())
        .initial_stream_window_size(6_291_456)
        .initial_connection_window_size(15_728_640)
        .max_header_list_size(262_144)
        .handshake(io)
        .await
        .ok()?;

    tokio::spawn(async move { conn.await.ok(); });

    let len = body.len();
    let full = Full::new(bytes::Bytes::from(body));
    let mut req = hyper::Request::builder()
        .method(hyper::Method::POST)
        .uri(&url)
        .body(full)
        .ok()?;

    for (name, val) in chrome_headers(len) {
        if let (Ok(hn), Ok(hv)) = (
            name.parse::<hyper::header::HeaderName>(),
            val.parse::<hyper::header::HeaderValue>(),
        ) {
            req.headers_mut().insert(hn, hv);
        }
    }

    sender.send_request(req).await.ok()?;
    Some(())
}

async fn handle_share_inner(
    axum::extract::State(tx): axum::extract::State<std::sync::mpsc::SyncSender<Vec<u8>>>,
    body: bytes::Bytes,
) -> axum::http::StatusCode {
    if let Some(inner) = bucket_unpad(&body) {
        let _ = tx.send(inner);
    }
    axum::http::StatusCode::OK
}

pub async fn run_https_share_server(
    addr: std::net::SocketAddr,
    cert_der: Vec<u8>,
    key_der: Vec<u8>,
    tx: std::sync::mpsc::SyncSender<Vec<u8>>,
) {
    rustls::crypto::ring::default_provider().install_default().ok();
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use tokio_rustls::TlsAcceptor;
    use hyper_util::{rt::{TokioExecutor, TokioIo}, service::TowerToHyperService};

    let mut tls_cfg = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(cert_der)],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_der)),
        )
        .expect("rustls server config");
    tls_cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    let acceptor = TlsAcceptor::from(std::sync::Arc::new(tls_cfg));
    let app = axum::Router::new()
        .route("/s", axum::routing::post(handle_share_inner))
        .with_state(tx);

    let listener = tokio::net::TcpListener::bind(addr).await.expect("https bind");

    loop {
        let Ok((tcp, _)) = listener.accept().await else { continue; };
        let Ok(tls) = acceptor.accept(tcp).await else { continue; };
        let io = TokioIo::new(tls);
        let svc = TowerToHyperService::new(app.clone());
        tokio::spawn(async move {
            hyper_util::server::conn::auto::Builder::new(TokioExecutor::new())
                .serve_connection(io, svc)
                .await
                .ok();
        });
    }
}
