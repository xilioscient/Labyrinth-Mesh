
use rand::Rng;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::Duration;

static SHUTDOWN: AtomicBool = AtomicBool::new(false);

extern "C" fn handle_shutdown(_: libc::c_int) {
    SHUTDOWN.store(true, Ordering::SeqCst);
}

fn install_shutdown_handlers() {
    unsafe {
        libc::signal(libc::SIGTERM, handle_shutdown as *const () as libc::sighandler_t);
        libc::signal(libc::SIGINT,  handle_shutdown as *const () as libc::sighandler_t);
    }
}

use labyrinth_core::file_transfer::{parse_file_args, FileTransferConfig, FileSender, FileReceiver};
use labyrinth_core::http_transport;
use labyrinth_core::management_plane::ManagementServer;
use labyrinth_core::metrics::{dashboard_metrics, noop_metrics, SharedMetrics};
use labyrinth_core::phase3;
use labyrinth_core::phase4::MultiPathController;
use labyrinth_core::scheduler::PathScheduler;

use labyrinth_core::v2::{
    auth::{CTRL_MAGIC, CTRL_V2_LEN, parse_v2_ctrl},
    hybrid_encapsulate_from_wire, HybridReceiverKeypair,
    HYBRID_KEM_WIRE_LEN, HYBRID_KYBER_CT_LEN,
    split_and_tag, verify_and_recover,
    KeyRatchet, SessionKey, TaggedShare,
    AUTH_TAG_LEN, SHAMIR_K, SHAMIR_N,
    ReplayWindow,
};

#[allow(dead_code)]
struct Config {
    mode: Mode,
    ctrl_listen: SocketAddr,
    recv_ctrl: SocketAddr,
    udp_listen: SocketAddr,
    udp_remotes: Vec<SocketAddr>,
    jitter_min_ms: u64,
    jitter_max_ms: u64,
    share_stagger_ms: u64,
    file_in: Option<PathBuf>,
    file_out: Option<PathBuf>,
    cbr_target_bps: u64,
    cbr_enabled: bool,
    http_mode: bool,
}

enum Mode { Send, Receive }

impl Config {
    fn from_env() -> Self {
        let mode = match std::env::var("LABYRINTH_MODE").as_deref() {
            Ok("recv") => Mode::Receive,
            _ => Mode::Send,
        };
        let ctrl_listen = parse_env_addr("LABYRINTH_CTRL",       "0.0.0.0:8199");
        let recv_ctrl   = parse_env_addr("LABYRINTH_RECV_CTRL",  "127.0.0.1:8199");
        let udp_listen  = parse_env_addr("LABYRINTH_UDP_LISTEN", "0.0.0.0:8200");
        let udp_remotes: Vec<SocketAddr> = std::env::var("LABYRINTH_REMOTES")
            .unwrap_or_else(|_| "127.0.0.1:8200".into())
            .split(',')
            .filter_map(|s| s.trim().parse().ok())
            .collect();
        let jitter_min_ms    = env_u64("LABYRINTH_JITTER_MIN_MS",    200);
        let jitter_max_ms    = env_u64("LABYRINTH_JITTER_MAX_MS",   1200);
        let share_stagger_ms = env_u64("LABYRINTH_SHARE_STAGGER_MS",   5);

        let (file_in, file_out) = parse_file_args();

        let cbr_target_bps = env_u64("LABYRINTH_CBR_BPS", 0);
        let cbr_enabled = std::env::var("LABYRINTH_CBR_ENABLED")
            .map(|v| v == "1" || v.to_lowercase() == "true")
            .unwrap_or(false);
        let http_mode = std::env::var("LABYRINTH_HTTP_MODE")
            .map(|v| v == "1" || v.to_lowercase() == "true")
            .unwrap_or(false);

        Config {
            mode, ctrl_listen, recv_ctrl, udp_listen, udp_remotes,
            jitter_min_ms, jitter_max_ms, share_stagger_ms,
            file_in, file_out, cbr_target_bps, cbr_enabled, http_mode,
        }
    }
}

fn parse_env_addr(var: &str, default: &str) -> SocketAddr {
    std::env::var(var)
        .unwrap_or_else(|_| default.into())
        .parse()
        .unwrap_or_else(|e| { eprintln!("error: {var} is not a valid SocketAddr: {e}"); std::process::exit(1) })
}

fn env_u64(var: &str, default: u64) -> u64 {
    std::env::var(var).ok().and_then(|s| s.parse().ok()).unwrap_or(default)
}

fn jitter_ms(min_ms: u64, max_ms: u64) -> Duration {
    let ms = if max_ms <= min_ms {
        min_ms
    } else {
        rand::thread_rng().gen_range(min_ms..=max_ms)
    };
    Duration::from_millis(ms)
}

fn spawn_pk_server(ctrl_listen: SocketAddr, pk: Vec<u8>) {
    thread::spawn(move || {
        let listener = match TcpListener::bind(ctrl_listen) {
            Ok(l) => l,
            Err(e) => { log::error!("KEM ctrl bind failed on {ctrl_listen}: {e}"); return; }
        };
        log::info!("KEM ctrl listening on {ctrl_listen}");
        loop {
            if SHUTDOWN.load(Ordering::Acquire) { break; }
            match listener.accept() {
                Ok((mut stream, peer)) => {
                    let pk = pk.clone();
                    thread::spawn(move || {
                        if stream.write_all(&(pk.len() as u32).to_le_bytes()).is_ok()
                            && stream.write_all(&pk).is_ok()
                        {
                            let _ = stream.flush();
                            log::info!("KEM pk sent to {peer} ({} bytes)", pk.len());
                        }
                    });
                }
                Err(e) => {
                    log::warn!("ctrl accept error: {e}");
                }
            }
        }
    });
}

fn spawn_http_ctrl_server(
    ctrl: SocketAddr,
    kp: Arc<HybridReceiverKeypair>,
    cert_der: Vec<u8>,
    tx: mpsc::Sender<SessionKey>,
) {
    thread::spawn(move || {
        let listener = match TcpListener::bind(ctrl) {
            Ok(l) => l,
            Err(e) => { log::error!("HTTP ctrl bind failed on {ctrl}: {e}"); return; }
        };
        log::info!("HTTP KEM ctrl listening on {ctrl}");
        loop {
            if SHUTDOWN.load(Ordering::Acquire) { break; }
            match listener.accept() {
                Ok((mut stream, peer)) => {
                    let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
                    let _ = stream.set_write_timeout(Some(Duration::from_secs(10)));
                    let pk = kp.pk_wire();
                    let cert2 = cert_der.clone();
                    let kp2 = Arc::clone(&kp);
                    let tx2 = tx.clone();
                    thread::spawn(move || {
                        let pk_len = pk.len() as u32;
                        if stream.write_all(&pk_len.to_le_bytes()).is_err() { return; }
                        if stream.write_all(&pk).is_err() { return; }
                        if stream.flush().is_err() { return; }
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
                            log::info!("HTTP KEM session established from {peer}");
                            let _ = tx2.send(SessionKey(session_bytes));
                        }
                    });
                }
                Err(e) => log::warn!("HTTP ctrl accept error: {e}"),
            }
        }
    });
}

fn run_sender_http(cfg: &Config, metrics: SharedMetrics) {
    let mut stream = match TcpStream::connect(cfg.recv_ctrl) {
        Ok(s) => s,
        Err(e) => { log::error!("HTTP KEM connect to {} failed: {e}", cfg.recv_ctrl); return; }
    };
    let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(10)));

    let mut magic = [0u8; 4];
    if stream.read_exact(&mut magic).is_err() { log::error!("HTTP KEM: read magic failed"); return; }

    let pk_wire = if magic == CTRL_MAGIC {
        let rest_len = CTRL_V2_LEN - 4;
        let mut rest = vec![0u8; rest_len];
        if stream.read_exact(&mut rest).is_err() { return; }
        let mut full = Vec::with_capacity(CTRL_V2_LEN);
        full.extend_from_slice(&magic);
        full.extend_from_slice(&rest);
        match parse_v2_ctrl(&full) {
            Some((kem_pk, _, valid)) => {
                if !valid { log::error!("HTTP KEM: Dilithium signature invalid"); return; }
                kem_pk
            }
            None => { log::error!("HTTP KEM: malformed v2 ctrl"); return; }
        }
    } else {
        let n = u32::from_le_bytes(magic) as usize;
        let mut pk = vec![0u8; n];
        if stream.read_exact(&mut pk).is_err() { return; }
        pk
    };

    let mut cert_len_buf = [0u8; 4];
    if stream.read_exact(&mut cert_len_buf).is_err() { return; }
    let cert_len = u32::from_le_bytes(cert_len_buf) as usize;
    let mut cert_der = vec![0u8; cert_len];
    if stream.read_exact(&mut cert_der).is_err() { return; }

    let sender_out = match hybrid_encapsulate_from_wire(&pk_wire) {
        Some(o) => o,
        None => { log::error!("hybrid KEM encapsulate failed"); return; }
    };
    let mut kem_wire = Vec::with_capacity(HYBRID_KEM_WIRE_LEN);
    kem_wire.extend_from_slice(&sender_out.kyber_ct_bytes);
    kem_wire.extend_from_slice(&sender_out.x25519_sender_pk);
    let kem_len = kem_wire.len() as u32;
    if stream.write_all(&kem_len.to_le_bytes()).is_err() { return; }
    if stream.write_all(&kem_wire).is_err() { return; }
    if stream.flush().is_err() { return; }

    log::info!("HTTP mode: KEM session established with {}", cfg.recv_ctrl);

    let ratchet = KeyRatchet::new(sender_out.shared_secret);
    let client = http_transport::build_chrome_client(&cert_der);

    let mut seq: u64 = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_micros() as u64)
        .unwrap_or(u64::MAX / 2);
    let mut batches: u64 = 0;

    if let Some(path) = cfg.file_in.as_ref() {
        let ft_cfg = FileTransferConfig { input_path: Some(path.clone()), ..Default::default() };
        let sender = FileSender::new(ft_cfg, noop_metrics());
        for chunk_result in sender.send_chunks() {
            let chunk = chunk_result.unwrap_or_else(|e| { log::error!("file-in: {e}"); vec![] });
            if chunk.is_empty() { continue; }
            send_batch_http(&chunk, seq, &ratchet, cfg, &client, &metrics);
            seq += 1;
            batches += 1;
        }
        log::info!("HTTP file transfer complete: {batches} batch(es)");
    } else {
        const CHUNK: usize = 4096;
        let mut buf = vec![0u8; CHUNK];
        eprintln!("[lm] HTTP session ready — type messages and press Enter; Ctrl+D to close");
        loop {
            let n = match io::stdin().read(&mut buf) {
                Ok(0) => break,
                Ok(n) => n,
                Err(e) => { log::error!("stdin: {e}"); break; }
            };
            if buf[..n].iter().all(|&b| b == b'\n' || b == b'\r' || b == b' ') { continue; }
            send_batch_http(&buf[..n], seq, &ratchet, cfg, &client, &metrics);
            seq += 1;
            batches += 1;
        }
        log::info!("HTTP stdin closed — {batches} batch(es) sent");
    }
}

fn send_batch_http(
    plaintext: &[u8],
    seq: u64,
    ratchet: &KeyRatchet,
    cfg: &Config,
    client: &http_transport::ChromeClient,
    metrics: &SharedMetrics,
) {
    let batch_key = SessionKey(ratchet.key_for_packet());
    let shares = split_and_tag(plaintext, &batch_key, seq);
    let mut handles = Vec::with_capacity(shares.len());

    for (i, share) in shares.into_iter().enumerate() {
        let dest = cfg.udp_remotes[i % cfg.udp_remotes.len().max(1)];
        let url = format!("https://{}/s", dest);
        let stagger_max = cfg.share_stagger_ms;
        let metrics_c = metrics.clone();

        let mut pkt = Vec::with_capacity(AUTH_TAG_LEN + 8 + 1 + share.share_bytes.len());
        pkt.extend_from_slice(&share.tag);
        pkt.extend_from_slice(&seq.to_le_bytes());
        pkt.push(share.index);
        pkt.extend_from_slice(&share.share_bytes);

        let padded = http_transport::bucket_pad(&pkt);
        let padded_len = padded.len();
        let c = client.clone();

        handles.push(thread::spawn(move || {
            if stagger_max > 0 {
                let ms = rand::thread_rng().gen_range(0..=stagger_max);
                thread::sleep(Duration::from_millis(ms));
            }
            let iat = http_transport::sample_iat_ms();
            thread::sleep(Duration::from_millis(iat));
            c.post_share(&url, padded);
            metrics_c.on_fragment_sent(0, padded_len);
        }));
    }

    for h in handles { let _ = h.join(); }
    thread::sleep(jitter_ms(cfg.jitter_min_ms, cfg.jitter_max_ms));
}

fn fetch_pk(recv_ctrl: SocketAddr) -> Result<Vec<u8>, io::Error> {
    let mut stream = TcpStream::connect(recv_ctrl)?;
    let mut len = [0u8; 4];
    stream.read_exact(&mut len)?;
    let n = u32::from_le_bytes(len) as usize;
    let mut pk = vec![0u8; n];
    stream.read_exact(&mut pk)?;
    log::info!("Fetched receiver pk ({n} bytes)");
    Ok(pk)
}

fn load_seq(listen: SocketAddr) -> u64 {
    labyrinth_core::state_persistence::load_seq(listen)
}

fn save_seq(listen: SocketAddr, seq: u64) {
    labyrinth_core::state_persistence::save_seq(listen, seq);
}

fn start_mgmt_plane(addr_str: &str, num_paths: usize) -> SharedMetrics {
    let addr: SocketAddr = addr_str
        .parse()
        .unwrap_or_else(|_| "127.0.0.1:9090".parse().unwrap());

    let metrics = dashboard_metrics(num_paths);
    let metrics_ret = metrics.clone();

    let ctrl = Arc::new(Mutex::new(
        MultiPathController::new(vec![]).expect("dummy controller"),
    ));

    let server = ManagementServer::new(metrics, addr, ctrl);

    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("tokio runtime for management plane");
        rt.block_on(async move {
            if let Err(e) = server.start().await {
                log::error!("Management plane failed to start: {e}");
                return;
            }
            log::info!("Management plane listening on {addr}");
            loop {
                tokio::time::sleep(Duration::from_secs(3600)).await;
            }
        });
    });

    metrics_ret
}

fn run_sender(cfg: &Config, metrics: SharedMetrics) {
    if cfg.http_mode {
        run_sender_http(cfg, metrics);
        return;
    }
    let pk_wire = match fetch_pk(cfg.recv_ctrl) {
        Ok(pk) => pk,
        Err(e) => { log::error!("failed to fetch receiver pk from {}: {e}", cfg.recv_ctrl); return; }
    };
    let sender_out = hybrid_encapsulate_from_wire(&pk_wire).expect("hybrid KEM encapsulate");
    let ratchet = KeyRatchet::new(sender_out.shared_secret);

    log::info!(
        "Labyrinth sender (hybrid KEM): {}-of-{} split, {} remote(s), jitter {}–{}ms",
        SHAMIR_K, SHAMIR_N,
        cfg.udp_remotes.len(),
        cfg.jitter_min_ms, cfg.jitter_max_ms,
    );

    let sock = UdpSocket::bind("0.0.0.0:0").expect("bind udp sender");

    let mut kem_wire = Vec::with_capacity(HYBRID_KEM_WIRE_LEN);
    kem_wire.extend_from_slice(&sender_out.kyber_ct_bytes);
    kem_wire.extend_from_slice(&sender_out.x25519_sender_pk);
    for r in &cfg.udp_remotes {
        sock.send_to(&kem_wire, r).expect("send kem ct");
    }
    log::debug!("hybrid KEM wire ({} B) sent to {} remote(s)", kem_wire.len(), cfg.udp_remotes.len());

    let scheduler = PathScheduler::new(&cfg.udp_remotes, metrics.clone());

    let mut seq: u64 = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_micros() as u64)
        .unwrap_or(u64::MAX / 2);
    let mut batches: u64 = 0;

    if let Some(path) = cfg.file_in.as_ref() {
        let ft_cfg = FileTransferConfig {
            input_path: Some(path.clone()),
            ..Default::default()
        };
        let sender = FileSender::new(ft_cfg, noop_metrics());
        let total = sender.file_size().unwrap_or(0);
        log::info!("Sending file: {} B in chunks", total);
        for chunk_result in sender.send_chunks() {
            let chunk = chunk_result.unwrap_or_else(|e| { log::error!("file-in: {e}"); vec![] });
            if chunk.is_empty() { continue; }
            send_batch(&chunk, seq, &ratchet, cfg, &scheduler, &metrics);
            seq += 1;
            batches += 1;
            log::debug!("  chunk {batches} — {} B (seq={})", chunk.len(), seq - 1);
        }
        log::info!("File transfer complete: {batches} batch(es)");
    } else {
        const CHUNK: usize = 4096;
        let mut buf = vec![0u8; CHUNK];
        eprintln!("[lm] session ready — type messages and press Enter; Ctrl+D to close");
        loop {
            let n = match io::stdin().read(&mut buf) {
                Ok(0) => break,
                Ok(n) => n,
                Err(e) => { log::error!("stdin: {e}"); break; }
            };
            if buf[..n].iter().all(|&b| b == b'\n' || b == b'\r' || b == b' ') {
                continue;
            }
            send_batch(&buf[..n], seq, &ratchet, cfg, &scheduler, &metrics);
            seq += 1;
            batches += 1;
            log::info!("Batch {batches} sent ({n} B, seq={})", seq - 1);
        }
        log::info!("Stdin closed — {batches} batch(es) sent in this session");
    }
}

fn send_batch(
    plaintext: &[u8],
    seq: u64,
    ratchet: &KeyRatchet,
    cfg: &Config,
    scheduler: &PathScheduler,
    metrics: &SharedMetrics,
) {
    let batch_key = SessionKey(ratchet.key_for_packet());
    let shares = split_and_tag(plaintext, &batch_key, seq);
    let dest_addrs = scheduler.assign_paths(shares.len());
    let session_key: [u8; 32] = batch_key.0;

    let mut handles = Vec::with_capacity(shares.len());

    for (i, share) in shares.into_iter().enumerate() {
        let dest = dest_addrs.get(i).copied().unwrap_or_else(|| {
            cfg.udp_remotes[i % cfg.udp_remotes.len().max(1)]
        });
        let path_idx = cfg.udp_remotes.iter().position(|r| r == &dest).unwrap_or(i);

        let mut pkt = Vec::with_capacity(AUTH_TAG_LEN + 8 + 1 + share.share_bytes.len());
        pkt.extend_from_slice(&share.tag);
        pkt.extend_from_slice(&seq.to_le_bytes());
        pkt.push(share.index);
        pkt.extend_from_slice(&share.share_bytes);

        let key = session_key;
        let stagger_max = cfg.share_stagger_ms;
        let metrics_c = metrics.clone();
        let share_index = share.index as usize;

        handles.push(thread::spawn(move || {
            if stagger_max > 0 {
                let ms = rand::thread_rng().gen_range(0..=stagger_max);
                thread::sleep(Duration::from_millis(ms));
            }
            let s = UdpSocket::bind("0.0.0.0:0").expect("share socket");
            let framed = phase3::wrap_for_path(path_idx, &pkt, &key);
            s.send_to(&framed, dest).ok();
            metrics_c.on_fragment_sent(path_idx, framed.len());
            log::debug!("share[{}] → {} ({} B seq={})", share_index, dest, framed.len(), seq);
        }));
    }

    for h in handles {
        let _ = h.join();
    }

    thread::sleep(jitter_ms(cfg.jitter_min_ms, cfg.jitter_max_ms));
}

fn run_receiver(cfg: &Config, metrics: SharedMetrics) {
    install_shutdown_handlers();

    let hybrid_kp = Arc::new(HybridReceiverKeypair::generate());
    log::info!("Labyrinth receiver (hybrid KEM): pk_wire={} bytes", hybrid_kp.pk_wire().len());

    let tls_bundle = if cfg.http_mode {
        Some(http_transport::generate_tls_bundle())
    } else {
        None
    };

    let (session_tx, session_rx) = mpsc::channel::<SessionKey>();

    if cfg.http_mode {
        let cert_der = tls_bundle.as_ref().unwrap().cert_der.clone();
        spawn_http_ctrl_server(cfg.ctrl_listen, Arc::clone(&hybrid_kp), cert_der, session_tx);
    } else {
        spawn_pk_server(cfg.ctrl_listen, hybrid_kp.pk_wire());
    }

    let (http_share_tx, http_share_rx) = mpsc::sync_channel::<Vec<u8>>(512);

    if cfg.http_mode {
        let cert_der = tls_bundle.as_ref().unwrap().cert_der.clone();
        let key_der = tls_bundle.as_ref().unwrap().key_der.clone();
        let bind_addr = cfg.udp_listen;
        let htx = http_share_tx;
        thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("https tokio rt");
            eprintln!("[lm] HTTPS receiver on {bind_addr}");
            rt.block_on(http_transport::run_https_share_server(bind_addr, cert_der, key_der, htx));
        });
    }

    let sock = if !cfg.http_mode {
        let s = UdpSocket::bind(cfg.udp_listen).expect("bind udp recv");
        s.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
        log::info!("UDP listening on {}", cfg.udp_listen);
        Some(s)
    } else {
        None
    };

    let mut file_rx: Option<FileReceiver> = cfg.file_out.as_ref().map(|p| {
        FileReceiver::new(
            FileTransferConfig { output_path: Some(p.clone()), ..Default::default() },
            noop_metrics(),
        )
    });

    let mut buf = vec![0u8; 65535];
    let mut session_key: Option<SessionKey> = None;
    let mut pending: Vec<TaggedShare> = Vec::new();

    let mut replay = ReplayWindow::from_saved(load_seq(cfg.udp_listen));
    log::info!("Replay window starts at seq={}", replay.last_accepted());

    let mut batch_seq: Option<u64> = None;

    loop {
        if SHUTDOWN.load(Ordering::Acquire) {
            log::info!("shutdown signal — exiting recv loop");
            break;
        }

        if let Ok(sk) = session_rx.try_recv() {
            if session_key.is_some() {
                pending.clear();
                batch_seq = None;
                log::info!("session re-keying");
            } else {
                log::info!("session established");
            }
            session_key = Some(sk);
            metrics.on_kem_handshake_complete(0);
        }

        let n = if cfg.http_mode {
            match http_share_rx.try_recv() {
                Ok(data) => {
                    let n = data.len().min(buf.len());
                    buf[..n].copy_from_slice(&data[..n]);
                    n
                }
                Err(_) => { thread::sleep(Duration::from_millis(1)); continue; }
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

        if !cfg.http_mode && raw.len() == HYBRID_KEM_WIRE_LEN {
            let kyber_ct = &raw[..HYBRID_KYBER_CT_LEN];
            if let Ok(x25519_spk) = raw[HYBRID_KYBER_CT_LEN..].try_into() as Result<[u8; 32], _> {
                if let Some(session_bytes) = hybrid_kp.decapsulate(kyber_ct, &x25519_spk) {
                    if session_key.is_some() {
                        log::info!("re-keying: new sender, session key updated");
                        pending.clear();
                        batch_seq = None;
                    } else {
                        log::info!("hybrid KEM decapsulated — session established");
                    }
                    session_key = Some(SessionKey(session_bytes));
                    metrics.on_kem_handshake_complete(0);
                }
                continue;
            }
        }

        let stripped = if cfg.http_mode { None } else { phase3::try_strip_transport_frame(raw) };
        let data: &[u8] = stripped.as_deref().unwrap_or(raw);

        const HDR: usize = AUTH_TAG_LEN + 8 + 1;
        if data.len() < HDR { continue; }

        let mut tag = [0u8; AUTH_TAG_LEN];
        tag.copy_from_slice(&data[..AUTH_TAG_LEN]);
        let pkt_seq = u64::from_le_bytes(
            data[AUTH_TAG_LEN..AUTH_TAG_LEN + 8].try_into().unwrap(),
        );
        let index = data[AUTH_TAG_LEN + 8];
        let share_bytes = data[HDR..].to_vec();

        if replay.is_processed(pkt_seq) {
            if pkt_seq == replay.last_accepted() {
                log::debug!("extra share: seq={pkt_seq} — already reconstructed");
            } else {
                log::warn!("replay dropped: seq={pkt_seq} (last={})", replay.last_accepted());
                metrics.on_replay_detected(pkt_seq, [0u8; 16]);
            }
            continue;
        }

        {
            let mut sid = [0u8; 16];
            sid[..8].copy_from_slice(&pkt_seq.to_le_bytes());
            let share_len = if data.len() > AUTH_TAG_LEN + 8 + 1 { data.len() - AUTH_TAG_LEN - 8 - 1 } else { 0 };
            metrics.on_fragment_recv(sid, index, share_len);
        }

        match batch_seq {
            None => { batch_seq = Some(pkt_seq); }
            Some(expected) if expected != pkt_seq => {
                log::warn!(
                    "seq changed mid-batch ({expected} → {pkt_seq}) — \
                     discarding {} stale share(s)",
                    pending.len(),
                );
                pending.clear();
                batch_seq = Some(pkt_seq);
            }
            _ => {}
        }

        pending.push(TaggedShare { share_bytes, tag, index });
        log::debug!(
            "Share[{index}] seq={pkt_seq} accepted ({}/{} needed)",
            pending.len(), SHAMIR_K,
        );

        if pending.len() >= SHAMIR_K as usize {
            let sk = match session_key.as_ref() {
                Some(sk) => sk,
                None => { pending.clear(); continue; }
            };
            let cur_seq = batch_seq.unwrap();

            match verify_and_recover(&pending[..SHAMIR_K as usize], sk, cur_seq) {
                Some(plaintext) => {
                    replay.mark_processed(cur_seq);
                    let plaintext_len = plaintext.len();
                    let mut sid = [0u8; 16];
                    sid[..8].copy_from_slice(&cur_seq.to_le_bytes());
                    metrics.on_fragment_reconstructed(sid, plaintext_len);

                    save_seq(cfg.udp_listen, replay.last_accepted());
                    pending.clear();
                    batch_seq = None;
                    if let Some(ref mut rx) = file_rx {
                        rx.write_chunk(&plaintext)
                            .unwrap_or_else(|e| panic!("file-out write error: {e}"));
                        log::info!(
                            "Reconstructed {} bytes (seq={}) → file buffer",
                            plaintext.len(), cur_seq,
                        );
                    } else {
                        io::stdout().write_all(&plaintext).unwrap();
                        io::stdout().flush().unwrap();
                        log::info!(
                            "Reconstructed {} bytes (seq={}) → stdout",
                            plaintext.len(), cur_seq,
                        );
                    }
                }
                None => {
                    log::warn!(
                        "BLAKE3 verification failed for seq={} — discarding batch",
                        cur_seq,
                    );
                    pending.clear();
                    batch_seq = None;
                }
            }
        }
    }

    if let Some(mut rx) = file_rx {
        match rx.finalize() {
            Ok(s) => log::info!(
                "file-out finalized: {} bytes, BLAKE3 {:02x?}",
                s.total_bytes, &s.blake3_hash[..4]
            ),
            Err(e) => log::error!("file-out finalize failed: {e}"),
        }
    }
}

fn main() {
    labyrinth_core::log_capture::init_with_capture();

    let cfg = Config::from_env();

    let metrics = if let Ok(addr) = std::env::var("DMPOT_MGMT_ADDR") {
        let num_paths = match cfg.mode {
            Mode::Send    => cfg.udp_remotes.len().max(1),
            Mode::Receive => 1,
        };
        eprintln!("Dashboard available: ./ESbin/dashboard --mgmt {addr}");
        start_mgmt_plane(&addr, num_paths)
    } else {
        noop_metrics()
    };

    match cfg.mode {
        Mode::Send    => run_sender(&cfg, metrics),
        Mode::Receive => run_receiver(&cfg, metrics),
    }
}
