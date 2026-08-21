use clap::{Args, Parser, Subcommand};
use serde::{Deserialize, Serialize};
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::path::PathBuf;
use std::sync::{mpsc, Arc, atomic::{AtomicBool, Ordering}};
use std::thread;
use std::time::Duration;

use rand::Rng;

use labyrinth_core::file_transfer::{FileReceiver, FileSender, FileTransferConfig};
use labyrinth_core::http_transport;
use labyrinth_core::metrics::{dashboard_metrics, noop_metrics, SharedMetrics};
use labyrinth_core::phase3;
use labyrinth_core::scheduler::PathScheduler;
use labyrinth_core::state_persistence;
use labyrinth_core::v2::{
    auth::{build_v2_ctrl, parse_v2_ctrl, pk_fingerprint, generate_sign_keypair, CTRL_MAGIC, CTRL_V2_LEN},
    hybrid_encapsulate_from_wire, HybridReceiverKeypair,
    HYBRID_KEM_WIRE_LEN, HYBRID_KYBER_CT_LEN,
    split_and_tag, verify_and_recover,
    KeyRatchet, SessionKey, TaggedShare,
    AUTH_TAG_LEN, SHAMIR_K,
    ReplayWindow,
    tkem_send, decode_and_recover, encode_ct_bundle, encode_pk_bundle,
    TKEM_MIN_THRESHOLD, TKEM_PK_MAGIC,
};

#[derive(Deserialize, Serialize, Default, Debug)]
struct ConfigFile {
    #[serde(default)]
    send: SendConfig,
    #[serde(default)]
    recv: RecvConfig,
    #[serde(default)]
    common: CommonConfig,
}

#[derive(Deserialize, Serialize, Default, Debug)]
struct SendConfig {
    to: Option<String>,
    remotes: Option<String>,
    jitter_min: Option<u64>,
    jitter_max: Option<u64>,
    stagger: Option<u64>,
}

#[derive(Deserialize, Serialize, Default, Debug)]
struct RecvConfig {
    ctrl: Option<String>,
    udp: Option<String>,
}

#[derive(Deserialize, Serialize, Default, Debug)]
struct CommonConfig {
    mgmt: Option<String>,
}

fn load_config(path: Option<&PathBuf>) -> ConfigFile {
    let p = match path {
        Some(p) => p.clone(),
        None => {
            if let Ok(env) = std::env::var("LABYRINTH_CONFIG") {
                PathBuf::from(env)
            } else {
                let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
                PathBuf::from(home).join(".labyrinth").join("config.toml")
            }
        }
    };
    match std::fs::read_to_string(&p) {
        Ok(s) => toml::from_str(&s).unwrap_or_else(|e| {
            eprintln!("[labyrinth] warning: config file {:?} parse error: {e}", p);
            ConfigFile::default()
        }),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => ConfigFile::default(),
        Err(e) => {
            eprintln!("[labyrinth] warning: could not read config {:?}: {e}", p);
            ConfigFile::default()
        }
    }
}

#[derive(Parser)]
#[command(
    name = "labyrinth",
    about = "Labyrinth-Mesh — post-quantum resilient multi-path tunnel",
    version
)]
struct Cli {
    /// Config file path (default: ~/.labyrinth/config.toml)
    #[arg(long, short = 'c', global = true)]
    config: Option<PathBuf>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Send data through the tunnel (file or stdin)
    Send(SendArgs),
    /// Receive data from the tunnel (file or stdout)
    Recv(RecvArgs),
    /// Query the management plane and print live metrics
    Status(StatusArgs),
    /// Interactive setup wizard
    Setup,
}

#[derive(Args)]
struct SendArgs {
    /// Receiver control address for KEM key exchange
    #[arg(long, default_value = "127.0.0.1:8199")]
    to: SocketAddr,

    /// File to send (reads stdin when omitted)
    #[arg(long, short = 'f')]
    file: Option<PathBuf>,

    /// UDP remote addresses, comma-separated
    #[arg(long, default_value = "127.0.0.1:8200")]
    remotes: String,

    /// Inter-batch jitter minimum (ms)
    #[arg(long, default_value_t = 200)]
    jitter_min: u64,

    /// Inter-batch jitter maximum (ms)
    #[arg(long, default_value_t = 1200)]
    jitter_max: u64,

    /// Intra-batch share stagger (ms)
    #[arg(long, default_value_t = 5)]
    stagger: u64,

    /// Start management plane on this address
    #[arg(long)]
    mgmt: Option<String>,

    /// Expected receiver signing key fingerprint (e.g. "ab:cd:ef:01:02:03:04:05").
    /// If set, the connection is aborted when the receiver's Dilithium pk does not match.
    #[arg(long)]
    receiver_key: Option<String>,

    /// Threshold KEM: minimum relay shares required to reconstruct session key.
    /// When set, the receiver must have been started with --tkem-relays >= this value.
    /// Security: session key requires compromising this many relay sub-keys simultaneously.
    #[arg(long)]
    tkem_threshold: Option<usize>,

    /// Use real HTTPS/HTTP2 transport instead of raw UDP.
    /// Receiver must also be started with --http. Shares are POSTed via TLS 1.3 + HTTP/2
    /// with Chrome-like headers and empirical size bucketing. Zero external configuration.
    #[arg(long, default_value_t = false)]
    http: bool,
}

#[derive(Args)]
struct RecvArgs {
    /// TCP control listen address (serves receiver public key)
    #[arg(long, default_value = "127.0.0.1:8199")]
    ctrl: SocketAddr,

    /// UDP listen address
    #[arg(long, default_value = "127.0.0.1:8200")]
    udp: SocketAddr,

    /// Write received data to this file (writes stdout when omitted)
    #[arg(long, short = 'o')]
    output: Option<PathBuf>,

    /// Start management plane on this address
    #[arg(long)]
    mgmt: Option<String>,

    /// Enable Dilithium3 signing of KEM public key (prevents MITM on ctrl channel).
    /// Prints fingerprint to stderr on startup.
    #[arg(long)]
    sign: bool,

    /// Threshold KEM: number of independent relay sub-keypairs to generate.
    /// Session key requires >= --tkem-threshold shares from distinct relay sub-keys.
    /// Eliminates single-point-of-compromise in the KEM setup phase.
    #[arg(long, default_value_t = 1)]
    tkem_relays: usize,

    /// Use real HTTPS/HTTP2 transport instead of raw UDP.
    /// Generates a self-signed TLS cert at startup; fingerprint is exchanged via the
    /// existing Dilithium3-signed ctrl channel. Sender must also use --http.
    #[arg(long, default_value_t = false)]
    http: bool,
}

#[derive(Args)]
struct StatusArgs {
    /// Management plane address
    #[arg(long, default_value = "127.0.0.1:9090")]
    mgmt: String,

    /// Output format: text or json
    #[arg(long, default_value = "text")]
    format: String,
}

static SHUTDOWN: AtomicBool = AtomicBool::new(false);

extern "C" fn handle_shutdown(_: libc::c_int) {
    SHUTDOWN.store(true, Ordering::Relaxed);
}

fn install_shutdown_handlers() {
    unsafe {
        libc::signal(libc::SIGTERM, handle_shutdown as *const () as libc::sighandler_t);
        libc::signal(libc::SIGINT, handle_shutdown as *const () as libc::sighandler_t);
    }
}

fn jitter(min_ms: u64, max_ms: u64) -> Duration {
    let ms = if max_ms <= min_ms {
        min_ms
    } else {
        rand::thread_rng().gen_range(min_ms..=max_ms)
    };
    Duration::from_millis(ms)
}

fn parse_remotes(s: &str) -> Vec<SocketAddr> {
    s.split(',').filter_map(|p| p.trim().parse().ok()).collect()
}

fn start_mgmt(addr_str: &str, num_paths: usize) -> SharedMetrics {
    use labyrinth_core::management_plane::ManagementServer;
    use labyrinth_core::phase4::MultiPathController;
    use std::sync::{Arc, Mutex};

    let addr: SocketAddr = addr_str
        .parse()
        .unwrap_or_else(|_| "127.0.0.1:9090".parse().unwrap());
    let metrics = dashboard_metrics(num_paths);
    let ret = metrics.clone();
    let ctrl = Arc::new(Mutex::new(
        MultiPathController::new(vec![]).expect("dummy controller"),
    ));
    let server = ManagementServer::new(metrics, addr, ctrl);
    thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("tokio rt");
        rt.block_on(async move {
            if let Err(e) = server.start().await {
                log::error!("management plane: {e}");
                return;
            }
            loop { tokio::time::sleep(Duration::from_secs(3600)).await; }
        });
    });
    ret
}

fn fetch_kem_pk(ctrl: SocketAddr, expected_fp: Option<&str>) -> Vec<u8> {
    let mut stream = TcpStream::connect(ctrl).expect("connect ctrl");

    let mut magic = [0u8; 4];
    stream.read_exact(&mut magic).unwrap();

    if magic == CTRL_MAGIC {
        let rest_len = CTRL_V2_LEN - 4;
        let mut rest = vec![0u8; rest_len];
        stream.read_exact(&mut rest).unwrap();

        let mut full = Vec::with_capacity(CTRL_V2_LEN);
        full.extend_from_slice(&magic);
        full.extend_from_slice(&rest);

        match parse_v2_ctrl(&full) {
            Some((kem_pk, sign_pk, valid)) => {
                if !valid {
                    eprintln!("[labyrinth] ABORT: receiver Dilithium signature is invalid — possible MITM!");
                    std::process::exit(2);
                }
                let fp = pk_fingerprint(&sign_pk);
                if let Some(expected) = expected_fp {
                    if fp != expected {
                        eprintln!("[labyrinth] ABORT: receiver key fingerprint mismatch");
                        eprintln!("  expected: {expected}");
                        eprintln!("  received: {fp}");
                        std::process::exit(2);
                    }
                    eprintln!("[labyrinth] receiver identity verified: {fp}");
                } else {
                    eprintln!("[labyrinth] receiver signed (TOFU) — fingerprint: {fp}");
                    eprintln!("[labyrinth] use --receiver-key {fp} to verify on future connections");
                }
                kem_pk
            }
            None => {
                eprintln!("[labyrinth] ABORT: malformed v2 ctrl message");
                std::process::exit(2);
            }
        }
    } else {
        let n = u32::from_le_bytes(magic) as usize;
        let mut pk = vec![0u8; n];
        stream.read_exact(&mut pk).unwrap();
        if expected_fp.is_some() {
            eprintln!("[labyrinth] warning: receiver does not support Dilithium (v1 protocol) — --receiver-key ignored");
        }
        pk
    }
}

fn fetch_tkem_session(ctrl: SocketAddr, threshold: usize) -> Option<SessionKey> {
    use labyrinth_core::v2::HYBRID_PK_WIRE_LEN;
    let mut stream = TcpStream::connect(ctrl).ok()?;
    let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(10)));

    let mut magic = [0u8; 4];
    stream.read_exact(&mut magic).ok()?;
    if magic != TKEM_PK_MAGIC {
        eprintln!("[labyrinth] error: receiver does not support threshold KEM (expected TKEM_PK_MAGIC)");
        return None;
    }

    let mut header = [0u8; 2];
    stream.read_exact(&mut header).ok()?;
    let n = header[0] as usize;
    let recv_threshold = header[1] as usize;

    if n == 0 || threshold > recv_threshold {
        eprintln!("[labyrinth] error: receiver threshold ({recv_threshold}) < requested ({threshold})");
        return None;
    }

    let mut pk_buf = vec![0u8; n * HYBRID_PK_WIRE_LEN];
    stream.read_exact(&mut pk_buf).ok()?;

    let relay_pks: Vec<Vec<u8>> = (0..n)
        .map(|i| pk_buf[i * HYBRID_PK_WIRE_LEN..(i + 1) * HYBRID_PK_WIRE_LEN].to_vec())
        .collect();

    let setup = tkem_send(&relay_pks, threshold)?;
    let ct_bundle = encode_ct_bundle(&setup.relay_packets);

    let ct_len = ct_bundle.len() as u32;
    stream.write_all(&ct_len.to_le_bytes()).ok()?;
    stream.write_all(&ct_bundle).ok()?;
    stream.flush().ok()?;

    eprintln!("[labyrinth] threshold KEM session established ({}/{} relays, threshold={})", n, n, threshold);
    Some(setup.session_key)
}

fn http_key_exchange(ctrl: SocketAddr, expected_fp: Option<&str>) -> (SessionKey, Vec<u8>) {
    let mut stream = TcpStream::connect(ctrl).expect("http_key_exchange: connect ctrl");
    let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(10)));

    let mut magic = [0u8; 4];
    stream.read_exact(&mut magic).expect("read magic");

    let pk_wire = if magic == CTRL_MAGIC {
        let rest_len = CTRL_V2_LEN - 4;
        let mut rest = vec![0u8; rest_len];
        stream.read_exact(&mut rest).expect("read v2 ctrl rest");
        let mut full = Vec::with_capacity(CTRL_V2_LEN);
        full.extend_from_slice(&magic);
        full.extend_from_slice(&rest);
        match parse_v2_ctrl(&full) {
            Some((kem_pk, sign_pk, valid)) => {
                if !valid {
                    eprintln!("[labyrinth] ABORT: Dilithium signature invalid — possible MITM");
                    std::process::exit(2);
                }
                let fp = pk_fingerprint(&sign_pk);
                if let Some(expected) = expected_fp {
                    if fp != expected {
                        eprintln!("[labyrinth] ABORT: receiver key fingerprint mismatch");
                        eprintln!("  expected: {expected}");
                        eprintln!("  received: {fp}");
                        std::process::exit(2);
                    }
                    eprintln!("[labyrinth] receiver identity verified: {fp}");
                } else {
                    eprintln!("[labyrinth] receiver signed (TOFU) — fingerprint: {fp}");
                }
                kem_pk
            }
            None => {
                eprintln!("[labyrinth] ABORT: malformed v2 ctrl");
                std::process::exit(2);
            }
        }
    } else {
        let n = u32::from_le_bytes(magic) as usize;
        let mut pk = vec![0u8; n];
        stream.read_exact(&mut pk).expect("read pk");
        pk
    };

    let mut cert_len_buf = [0u8; 4];
    stream.read_exact(&mut cert_len_buf).expect("read cert len");
    let cert_len = u32::from_le_bytes(cert_len_buf) as usize;
    let mut cert_der = vec![0u8; cert_len];
    stream.read_exact(&mut cert_der).expect("read cert der");

    let sender_out = hybrid_encapsulate_from_wire(&pk_wire).expect("hybrid KEM encapsulate");
    let mut kem_wire = Vec::with_capacity(HYBRID_KEM_WIRE_LEN);
    kem_wire.extend_from_slice(&sender_out.kyber_ct_bytes);
    kem_wire.extend_from_slice(&sender_out.x25519_sender_pk);

    let kem_len = kem_wire.len() as u32;
    stream.write_all(&kem_len.to_le_bytes()).expect("write kem len");
    stream.write_all(&kem_wire).expect("write kem wire");
    stream.flush().expect("flush");

    eprintln!("[labyrinth] HTTP mode: KEM session established via TCP ctrl");
    (SessionKey(sender_out.shared_secret), cert_der)
}

fn cmd_send(args: SendArgs, cfg: &ConfigFile) {
    let remotes_str = args.remotes.as_str();
    let remotes = parse_remotes(
        if remotes_str != "127.0.0.1:8200" {
            remotes_str
        } else {
            cfg.send.remotes.as_deref().unwrap_or(remotes_str)
        },
    );
    if remotes.is_empty() {
        eprintln!("error: --remotes contains no valid addresses");
        std::process::exit(1);
    }

    let mgmt_addr = args.mgmt.as_deref().or(cfg.common.mgmt.as_deref());
    let metrics = match mgmt_addr {
        Some(addr) => start_mgmt(addr, remotes.len()),
        None => noop_metrics(),
    };

    let receiver_fp = args.receiver_key.as_deref();
    let http_mode = args.http;

    let (ratchet, kem_wire_opt, http_client_opt) = if http_mode {
        let (sk, cert_der) = http_key_exchange(args.to, receiver_fp);
        let client = http_transport::build_chrome_client(&cert_der);
        (KeyRatchet::new(sk.0), None, Some((client, cert_der)))
    } else if let Some(threshold) = args.tkem_threshold {
        if threshold < TKEM_MIN_THRESHOLD {
            eprintln!("error: --tkem-threshold must be >= {TKEM_MIN_THRESHOLD}");
            std::process::exit(1);
        }
        let sk = fetch_tkem_session(args.to, threshold)
            .unwrap_or_else(|| { eprintln!("error: threshold KEM handshake failed"); std::process::exit(1) });
        (KeyRatchet::new(sk.0), None, None)
    } else {
        let pk_wire = fetch_kem_pk(args.to, receiver_fp);
        let sender_out = hybrid_encapsulate_from_wire(&pk_wire).expect("hybrid KEM encapsulate");
        let mut w = Vec::with_capacity(HYBRID_KEM_WIRE_LEN);
        w.extend_from_slice(&sender_out.kyber_ct_bytes);
        w.extend_from_slice(&sender_out.x25519_sender_pk);
        (KeyRatchet::new(sender_out.shared_secret), Some(w), None)
    };

    let sock = if !http_mode {
        Some(UdpSocket::bind("0.0.0.0:0").expect("bind udp"))
    } else {
        None
    };

    if let Some(kem_wire) = kem_wire_opt {
        for r in &remotes {
            sock.as_ref().unwrap().send_to(&kem_wire, r).expect("send kem ct");
        }
    }

    let jitter_min = args.jitter_min;
    let jitter_max = args.jitter_max;
    let stagger = args.stagger;

    let scheduler = PathScheduler::new(&remotes, metrics.clone());

    let mut seq: u64 = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_micros() as u64)
        .unwrap_or(u64::MAX / 2);
    let mut batches: u64 = 0;

    let send_one = |payload: &[u8], seq: u64, metrics: &SharedMetrics| {
        let batch_key = SessionKey(ratchet.key_for_packet());
        let shares = split_and_tag(payload, &batch_key, seq);
        let dest_addrs = scheduler.assign_paths(shares.len());
        let session_key: [u8; 32] = batch_key.0;
        let mut handles = Vec::with_capacity(shares.len());
        for (i, share) in shares.into_iter().enumerate() {
            let dest = dest_addrs.get(i).copied()
                .unwrap_or_else(|| remotes[i % remotes.len().max(1)]);
            let path_idx = remotes.iter().position(|r| r == &dest).unwrap_or(i);
            let mut pkt = Vec::with_capacity(AUTH_TAG_LEN + 8 + 1 + share.share_bytes.len());
            pkt.extend_from_slice(&share.tag);
            pkt.extend_from_slice(&seq.to_le_bytes());
            pkt.push(share.index);
            pkt.extend_from_slice(&share.share_bytes);
            let key = session_key;
            let stagger_max = stagger;
            let metrics_c = metrics.clone();
            if http_mode {
                let client = http_client_opt.as_ref().unwrap().0.clone();
                let url = format!("https://{}/s", dest);
                let padded = http_transport::bucket_pad(&pkt);
                let padded_len = padded.len();
                handles.push(thread::spawn(move || {
                    if stagger_max > 0 {
                        let ms = rand::thread_rng().gen_range(0..=stagger_max);
                        thread::sleep(Duration::from_millis(ms));
                    }
                    let iat = http_transport::sample_iat_ms();
                    thread::sleep(Duration::from_millis(iat));
                    client.post_share(&url, padded);
                    metrics_c.on_fragment_sent(path_idx, padded_len);
                }));
            } else {
                handles.push(thread::spawn(move || {
                    if stagger_max > 0 {
                        let ms = rand::thread_rng().gen_range(0..=stagger_max);
                        thread::sleep(Duration::from_millis(ms));
                    }
                    let s = UdpSocket::bind("0.0.0.0:0").expect("share socket");
                    let framed = phase3::wrap_for_path(path_idx, &pkt, &key);
                    s.send_to(&framed, dest).ok();
                    metrics_c.on_fragment_sent(path_idx, framed.len());
                }));
            }
        }
        for h in handles { let _ = h.join(); }
        thread::sleep(jitter(jitter_min, jitter_max));
    };

    if let Some(path) = args.file.as_ref() {
        let ft = FileTransferConfig { input_path: Some(path.clone()), ..Default::default() };
        let sender = FileSender::new(ft, noop_metrics());
        eprintln!("[labyrinth] sending {} B", sender.file_size().unwrap_or(0));
        for chunk in sender.send_chunks() {
            let data = chunk.unwrap_or_else(|e| { eprintln!("file-in error: {e}"); vec![] });
            if data.is_empty() { continue; }
            send_one(&data, seq, &metrics);
            seq += 1;
            batches += 1;
        }
        eprintln!("[labyrinth] file sent: {batches} batch(es)");
    } else {
        const CHUNK: usize = 4096;
        let mut buf = vec![0u8; CHUNK];
        eprintln!("[labyrinth] session ready — type messages (Ctrl+D to close)");
        loop {
            let n = match io::stdin().read(&mut buf) {
                Ok(0) => break,
                Ok(n) => n,
                Err(e) => { log::error!("stdin: {e}"); break; }
            };
            if buf[..n].iter().all(|&b| matches!(b, b'\n' | b'\r' | b' ')) { continue; }
            send_one(&buf[..n], seq, &metrics);
            seq += 1;
            batches += 1;
        }
        eprintln!("[labyrinth] {batches} batch(es) sent");
    }
}

fn cmd_recv(args: RecvArgs, cfg: &ConfigFile) {
    install_shutdown_handlers();

    let http_mode = args.http;

    let mgmt_addr = args.mgmt.as_deref().or(cfg.common.mgmt.as_deref());
    let metrics = match mgmt_addr {
        Some(addr) => start_mgmt(addr, 1),
        None => noop_metrics(),
    };

    let hybrid_kp = Arc::new(HybridReceiverKeypair::generate());

    let tls_bundle = if http_mode {
        Some(http_transport::generate_tls_bundle())
    } else {
        None
    };

    let (tkem_tx, tkem_rx): (mpsc::Sender<SessionKey>, mpsc::Receiver<SessionKey>) = mpsc::channel();
    let tkem_n = args.tkem_relays;
    let tkem_threshold = tkem_n.min(3).max(TKEM_MIN_THRESHOLD.min(tkem_n));

    let tkem_state = if tkem_n >= TKEM_MIN_THRESHOLD {
        let kps: Vec<HybridReceiverKeypair> = (0..tkem_n).map(|_| HybridReceiverKeypair::generate()).collect();
        eprintln!("[labyrinth] threshold KEM: {tkem_n} relay sub-keys, threshold={tkem_threshold}");
        Some((Arc::new(kps), tkem_threshold))
    } else {
        None
    };

    {
        let tx = if tkem_state.is_some() || http_mode { Some(tkem_tx) } else { None };
        let kps_arc = tkem_state.as_ref().map(|(kps, t)| (Arc::clone(kps), *t));
        let pk = hybrid_kp.pk_wire();
        let sign = args.sign;
        let ctrl = args.ctrl;
        let cert_der_for_ctrl = tls_bundle.as_ref().map(|t| t.cert_der.clone());
        let kp_for_ctrl = if http_mode { Some(Arc::clone(&hybrid_kp)) } else { None };
        thread::spawn(move || {
            let listener = TcpListener::bind(ctrl).expect("bind ctrl");
            log::info!("KEM ctrl listening on {ctrl}");
            loop {
                if let Ok((mut stream, peer)) = listener.accept() {
                    let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
                    let _ = stream.set_write_timeout(Some(Duration::from_secs(10)));
                    if let Some((ref kps, threshold)) = kps_arc {
                        let relay_pks: Vec<Vec<u8>> = kps.iter().map(|kp| kp.pk_wire()).collect();
                        let pk_bundle = encode_pk_bundle(&relay_pks, threshold);
                        if stream.write_all(&pk_bundle).and_then(|_| stream.flush()).is_err() {
                            log::debug!("tkem pk bundle send error to {peer}");
                            continue;
                        }
                        let mut len_buf = [0u8; 4];
                        if stream.read_exact(&mut len_buf).is_err() { continue; }
                        let ct_len = u32::from_le_bytes(len_buf) as usize;
                        let mut ct_buf = vec![0u8; ct_len];
                        if stream.read_exact(&mut ct_buf).is_err() { continue; }
                        if let Some(sk) = decode_and_recover(&ct_buf, kps, threshold) {
                            log::info!("threshold KEM session from {peer} ({}/{} relays)", threshold, kps.len());
                            if let Some(ref tx) = tx { let _ = tx.send(sk); }
                        }
                    } else if http_mode {
                        let pk2 = pk.clone();
                        let sign2 = sign;
                        let cert2 = cert_der_for_ctrl.clone().unwrap_or_default();
                        let kp2 = kp_for_ctrl.clone().unwrap();
                        let tx2 = tx.clone();
                        thread::spawn(move || {
                            let v2_msg: Option<Vec<u8>> = if sign2 {
                                let (spk, ssk) = generate_sign_keypair();
                                eprintln!("[labyrinth] receiver signing key: {}", pk_fingerprint(&spk));
                                Some(build_v2_ctrl(&pk2, &spk, &ssk))
                            } else {
                                None
                            };
                            let res = if let Some(msg) = v2_msg {
                                stream.write_all(&msg).and_then(|_| stream.flush())
                            } else {
                                stream.write_all(&(pk2.len() as u32).to_le_bytes())
                                    .and_then(|_| stream.write_all(&pk2))
                                    .and_then(|_| stream.flush())
                            };
                            if res.is_err() {
                                log::debug!("ctrl pk send error to {peer}");
                                return;
                            }
                            let cert_len = cert2.len() as u32;
                            if stream.write_all(&cert_len.to_le_bytes()).is_err() { return; }
                            if stream.write_all(&cert2).is_err() { return; }
                            if stream.flush().is_err() { return; }

                            let mut kem_len_buf = [0u8; 4];
                            if stream.read_exact(&mut kem_len_buf).is_err() { return; }
                            let kem_len = u32::from_le_bytes(kem_len_buf) as usize;
                            if kem_len != HYBRID_KEM_WIRE_LEN { return; }
                            let mut kem_buf = vec![0u8; kem_len];
                            if stream.read_exact(&mut kem_buf).is_err() { return; }

                            let kyber_ct = &kem_buf[..HYBRID_KYBER_CT_LEN];
                            let x25519_spk: [u8; 32] = match kem_buf[HYBRID_KYBER_CT_LEN..].try_into() {
                                Ok(v) => v,
                                Err(_) => return,
                            };
                            if let Some(session_bytes) = kp2.decapsulate(kyber_ct, &x25519_spk) {
                                log::info!("HTTP mode KEM session established from {peer}");
                                if let Some(tx) = tx2 {
                                    let _ = tx.send(SessionKey(session_bytes));
                                }
                            }
                        });
                    } else {
                        let pk2 = pk.clone();
                        let sign2 = sign;
                        thread::spawn(move || {
                            let v2_msg: Option<Vec<u8>> = if sign2 {
                                let (spk, ssk) = generate_sign_keypair();
                                eprintln!("[labyrinth] receiver signing key: {}", pk_fingerprint(&spk));
                                Some(build_v2_ctrl(&pk2, &spk, &ssk))
                            } else { None };
                            let res = if let Some(msg) = v2_msg {
                                stream.write_all(&msg).and_then(|_| stream.flush())
                            } else {
                                stream.write_all(&(pk2.len() as u32).to_le_bytes())
                                    .and_then(|_| stream.write_all(&pk2))
                                    .and_then(|_| stream.flush())
                            };
                            if let Err(e) = res { log::debug!("ctrl send error to {peer}: {e}"); }
                        });
                    }
                }
            }
        });
    }

    let (http_share_tx, http_share_rx) = std::sync::mpsc::sync_channel::<Vec<u8>>(512);

    if http_mode {
        let cert_der = tls_bundle.as_ref().unwrap().cert_der.clone();
        let key_der = tls_bundle.as_ref().unwrap().key_der.clone();
        let bind_addr = args.udp;
        let htx = http_share_tx;
        thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("https tokio rt");
            eprintln!("[labyrinth] HTTPS receiver on {bind_addr}");
            rt.block_on(http_transport::run_https_share_server(bind_addr, cert_der, key_der, htx));
        });
    }

    let sock = if !http_mode {
        let s = UdpSocket::bind(args.udp).expect("bind udp recv");
        s.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
        eprintln!("[labyrinth] listening on udp/{}", args.udp);
        Some(s)
    } else {
        None
    };

    let mut file_rx: Option<FileReceiver> = args.output.as_ref().map(|p| {
        FileReceiver::new(
            FileTransferConfig { output_path: Some(p.clone()), ..Default::default() },
            noop_metrics(),
        )
    });

    let mut buf = vec![0u8; 65535];
    let mut session_key: Option<SessionKey> = None;
    let mut pending: Vec<TaggedShare> = Vec::new();
    let mut replay = ReplayWindow::from_saved(state_persistence::load_seq(args.udp));
    let mut batch_seq: Option<u64> = None;

    eprintln!("[labyrinth] replay window starts at seq={}", replay.last_accepted());

    loop {
        if SHUTDOWN.load(Ordering::Relaxed) { break; }

        if let Ok(tkem_sk) = tkem_rx.try_recv() {
            if session_key.is_some() {
                pending.clear();
                batch_seq = None;
                eprintln!("[labyrinth] session re-keying");
            } else {
                eprintln!("[labyrinth] session established");
            }
            session_key = Some(tkem_sk);
            metrics.on_kem_handshake_complete(0);
        }

        let n = if http_mode {
            match http_share_rx.try_recv() {
                Ok(data) => {
                    let n = data.len().min(buf.len());
                    buf[..n].copy_from_slice(&data[..n]);
                    n
                }
                Err(_) => {
                    thread::sleep(Duration::from_millis(1));
                    continue;
                }
            }
        } else {
            match sock.as_ref().unwrap().recv(&mut buf) {
                Ok(n) => n,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock
                       || e.kind() == io::ErrorKind::TimedOut => continue,
                Err(e) => { log::error!("recv: {e}"); break; }
            }
        };
        let raw = &buf[..n];

        if !http_mode && tkem_state.is_none() && raw.len() == HYBRID_KEM_WIRE_LEN {
            let kyber_ct = &raw[..HYBRID_KYBER_CT_LEN];
            if let Ok(x25519_spk) = raw[HYBRID_KYBER_CT_LEN..].try_into() as Result<[u8; 32], _> {
                if let Some(session_bytes) = hybrid_kp.decapsulate(kyber_ct, &x25519_spk) {
                    if session_key.is_some() {
                        pending.clear();
                        batch_seq = None;
                        eprintln!("[labyrinth] re-keying — new sender");
                    } else {
                        eprintln!("[labyrinth] hybrid KEM session established");
                    }
                    session_key = Some(SessionKey(session_bytes));
                    metrics.on_kem_handshake_complete(0);
                }
                continue;
            }
        }

        let stripped = if http_mode { None } else { phase3::try_strip_transport_frame(raw) };
        let data: &[u8] = stripped.as_deref().unwrap_or(raw);

        const HDR: usize = AUTH_TAG_LEN + 8 + 1;
        if data.len() < HDR { continue; }

        let mut tag = [0u8; AUTH_TAG_LEN];
        tag.copy_from_slice(&data[..AUTH_TAG_LEN]);
        let pkt_seq = u64::from_le_bytes(data[AUTH_TAG_LEN..AUTH_TAG_LEN + 8].try_into().unwrap());
        let index = data[AUTH_TAG_LEN + 8];
        let share_bytes = data[HDR..].to_vec();

        if replay.is_processed(pkt_seq) {
            if pkt_seq != replay.last_accepted() {
                log::warn!("replay dropped: seq={pkt_seq} (last={})", replay.last_accepted());
                metrics.on_replay_detected(pkt_seq, [0u8; 16]);
            }
            continue;
        }

        {
            let mut sid = [0u8; 16];
            sid[..8].copy_from_slice(&pkt_seq.to_le_bytes());
            metrics.on_fragment_recv(sid, index, share_bytes.len());
        }

        match batch_seq {
            None => { batch_seq = Some(pkt_seq); }
            Some(e) if e != pkt_seq => { pending.clear(); batch_seq = Some(pkt_seq); }
            _ => {}
        }
        pending.push(TaggedShare { share_bytes, tag, index });

        if pending.len() >= SHAMIR_K as usize {
            let sk = match session_key.as_ref() {
                Some(sk) => sk,
                None => { pending.clear(); continue; }
            };
            let cur_seq = batch_seq.unwrap();
            match verify_and_recover(&pending[..SHAMIR_K as usize], sk, cur_seq) {
                Some(plaintext) => {
                    replay.mark_processed(cur_seq);
                    let mut sid = [0u8; 16];
                    sid[..8].copy_from_slice(&cur_seq.to_le_bytes());
                    metrics.on_fragment_reconstructed(sid, plaintext.len());
                    state_persistence::save_seq(args.udp, replay.last_accepted());
                    pending.clear();
                    batch_seq = None;
                    if let Some(ref mut rx) = file_rx {
                        rx.write_chunk(&plaintext)
                            .unwrap_or_else(|e| panic!("file-out write error: {e}"));
                    } else {
                        io::stdout().write_all(&plaintext).unwrap();
                        io::stdout().flush().unwrap();
                    }
                }
                None => {
                    log::warn!("BLAKE3 verification failed seq={cur_seq}");
                    pending.clear();
                    batch_seq = None;
                }
            }
        }
    }

    if let Some(mut rx) = file_rx {
        match rx.finalize() {
            Ok(s) => eprintln!("[labyrinth] file saved: {} bytes", s.total_bytes),
            Err(e) => eprintln!("[labyrinth] finalize error: {e}"),
        }
    }
}

#[derive(Deserialize)]
struct HealthResp {
    status: String,
    paths_active: usize,
    paths_total: usize,
}

#[derive(Deserialize)]
struct MetricsResp {
    session_count: usize,
    fragments_sent: u64,
    fragments_recv: u64,
    reconstructed_count: u64,
    ratchet_step: u64,
    replay_detected_count: u64,
    last_bps: f64,
}

fn cmd_status(args: StatusArgs, cfg: &ConfigFile) {
    let raw = args.mgmt.as_str();
    let addr = if raw == "127.0.0.1:9090" {
        cfg.common.mgmt.as_deref().unwrap_or(raw)
    } else {
        raw
    };
    let base = if addr.starts_with("http") {
        addr.to_string()
    } else {
        format!("http://{addr}")
    };

    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(3))
        .build()
        .expect("http client");

    let health: Option<HealthResp> = client.get(format!("{base}/health")).send()
        .and_then(|r| r.json()).ok();
    let metrics: Option<MetricsResp> = client.get(format!("{base}/metrics")).send()
        .and_then(|r| r.json()).ok();

    if health.is_none() && metrics.is_none() {
        eprintln!("error: could not reach management plane at {base}");
        std::process::exit(1);
    }

    if args.format == "json" {
        let h = client.get(format!("{base}/health")).send().and_then(|r| r.text()).unwrap_or_default();
        let m = client.get(format!("{base}/metrics")).send().and_then(|r| r.text()).unwrap_or_default();
        println!("{{\"health\":{h},\"metrics\":{m}}}");
        return;
    }

    if let Some(h) = &health {
        println!("Health:      {} ({}/{} paths active)", h.status, h.paths_active, h.paths_total);
    }
    if let Some(m) = &metrics {
        let bps = if m.last_bps >= 1_000_000.0 { format!("{:.2} Mbps", m.last_bps / 1_000_000.0) }
            else if m.last_bps >= 1_000.0 { format!("{:.1} Kbps", m.last_bps / 1_000.0) }
            else { format!("{:.0} bps", m.last_bps) };
        println!("Sessions:    {}", m.session_count);
        println!("Throughput:  {bps}");
        println!("Ratchet:     step {}", m.ratchet_step);
        println!("Frags sent:  {}", m.fragments_sent);
        println!("Frags recv:  {}", m.fragments_recv);
        println!("Reconstruct: {}", m.reconstructed_count);
        println!("Replays:     {}", m.replay_detected_count);
    }
}

fn prompt(question: &str, default: &str) -> String {
    print!("{question} [{default}]: ");
    io::stdout().flush().unwrap();
    let mut line = String::new();
    io::stdin().read_line(&mut line).unwrap();
    let t = line.trim();
    if t.is_empty() { default.to_string() } else { t.to_string() }
}

fn cmd_setup() {
    println!("=== Labyrinth-Mesh setup wizard ===\n");

    let mode = prompt("Mode? (send/recv)", "recv");
    let mgmt = prompt("Enable management plane? (yes/no)", "yes");
    let mgmt_addr = if mgmt == "yes" {
        prompt("Management plane address", "0.0.0.0:9090")
    } else {
        String::new()
    };

    let mgmt_arg = if !mgmt_addr.is_empty() { format!(" --mgmt {mgmt_addr}") } else { String::new() };

    println!("\n─── Suggested command ───");
    match mode.as_str() {
        "send" => {
            let to = prompt("Receiver control address", "127.0.0.1:8199");
            let remotes = prompt("UDP remote addresses (comma-separated)", "127.0.0.1:8200");
            let file = prompt("File to send (leave blank for stdin)", "");
            let file_arg = if file.is_empty() { String::new() } else { format!(" --file {file}") };
            let sign = prompt("Verify receiver identity? (yes/no)", "no");
            let sign_arg = if sign == "yes" {
                let fp = prompt("Expected receiver key fingerprint (from receiver startup output)", "");
                if fp.is_empty() { String::new() } else { format!(" --receiver-key {fp}") }
            } else { String::new() };
            println!("\n  labyrinth send --to {to} --remotes {remotes}{file_arg}{sign_arg}{mgmt_arg}\n");
        }
        _ => {
            let ctrl = prompt("Control listen address", "0.0.0.0:8199");
            let udp = prompt("UDP listen address", "0.0.0.0:8200");
            let output = prompt("Output file (leave blank for stdout)", "");
            let out_arg = if output.is_empty() { String::new() } else { format!(" --output {output}") };
            let sign = prompt("Enable Dilithium signing? (yes/no)", "yes");
            let sign_arg = if sign == "yes" { " --sign".to_string() } else { String::new() };
            println!("\n  labyrinth recv --ctrl {ctrl} --udp {udp}{out_arg}{sign_arg}{mgmt_arg}\n");
        }
    }

    let home = std::env::var("HOME").unwrap_or_else(|_| "/home/user".into());
    let config_path = format!("{home}/.labyrinth/config.toml");
    println!("─── Config file: {config_path} ───");
    println!(
        r#"[send]
# to = "127.0.0.1:8199"
# remotes = "127.0.0.1:8200"
# jitter_min = 200
# jitter_max = 1200

[recv]
# ctrl = "0.0.0.0:8199"
# udp = "0.0.0.0:8200"

[common]
# mgmt = "0.0.0.0:9090"
"#
    );
}

fn main() {
    labyrinth_core::log_capture::init_with_capture();
    let cli = Cli::parse();
    let cfg = load_config(cli.config.as_ref());
    match cli.command {
        Commands::Send(args) => cmd_send(args, &cfg),
        Commands::Recv(args) => cmd_recv(args, &cfg),
        Commands::Status(args) => cmd_status(args, &cfg),
        Commands::Setup => cmd_setup(),
    }
}
