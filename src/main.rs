#![allow(dead_code, unused_imports)]

mod error;
mod phase1;
mod phase2;
mod phase3;
mod phase4;
mod phase5;

use error::DmpotError;
use phase1::{split_payload, reconstruct_payload, DMPOTFragment, FragmentHeader};
use phase2::{KyberKeyPair, encapsulate_fragment, decapsulate_fragment, EncapsulatedFragment};
use phase3::{ProtocolMorpher, ProtocolType};
use phase4::{
    MultiPathController, FragmentReassembler, PathInfo,
    build_wire_packet, parse_wire_packet, UdpReceiver,
    DEFAULT_MAX_SESSIONS, DEFAULT_MAX_BYTES_PER_SESSION,
};
use phase5::{AntiDebugGuard, setup_panic_hook};
#[cfg(target_os = "linux")]
use phase5::MemoryIntegrityChecker;

use sha2::{Sha256, Digest};
use std::io::{self, BufRead, Read as IoRead, Write as IoWrite};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::mpsc;
use std::time::Duration;

use labyrinth_core::file_transfer::{parse_file_args, FileTransferConfig, FileSender, FileReceiver};
use labyrinth_core::metrics::noop_metrics;

const PHASE2_OVERHEAD: usize = 1680;

const DEFAULT_CHUNK_SIZE: usize = 8192 - PHASE2_OVERHEAD;

#[allow(dead_code)]
struct Config {
    mode: Mode,
    n: u8,
    k: u8,
    onion_layers: u8,
    remote_addrs: Vec<SocketAddr>,
    local_listen: SocketAddr,
    ctrl_listen: SocketAddr,
    receiver_ctrl: SocketAddr,
    protocol: ProtocolType,
    antidebug: bool,
    chunk_size: usize,
    ctrl_timeout_secs: u64,
    skip_fingerprint: bool,
    max_sessions: usize,
    max_bytes_per_session: usize,
    file_in: Option<PathBuf>,
    file_out: Option<PathBuf>,
    cbr_target_bps: u64,
    cbr_enabled: bool,
}

enum Mode { Send, Receive }

impl Config {
    fn from_env() -> Self {
        let mode = match std::env::var("DMPOT_MODE").as_deref() {
            Ok("recv") | Ok("receive") => Mode::Receive,
            _ => Mode::Send,
        };
        let n: u8 = std::env::var("DMPOT_N").ok()
            .and_then(|s| s.parse().ok()).unwrap_or(5);
        let k: u8 = std::env::var("DMPOT_K").ok()
            .and_then(|s| s.parse().ok()).unwrap_or(3);
        let onion_layers: u8 = std::env::var("DMPOT_LAYERS").ok()
            .and_then(|s| s.parse().ok()).unwrap_or(3);
        let remote_addrs: Vec<SocketAddr> = std::env::var("DMPOT_REMOTES")
            .unwrap_or_else(|_| "127.0.0.1:7001,127.0.0.1:7002,127.0.0.1:7003".into())
            .split(',').filter_map(|s| s.trim().parse().ok()).collect();
        let local_listen: SocketAddr = std::env::var("DMPOT_LISTEN")
            .unwrap_or_else(|_| "0.0.0.0:7000".into())
            .parse()
            .unwrap_or_else(|e| { eprintln!("DMPOT_LISTEN: invalid address: {e}"); std::process::exit(1) });
        let ctrl_listen: SocketAddr = std::env::var("DMPOT_CTRL_LISTEN")
            .unwrap_or_else(|_| "0.0.0.0:7099".into())
            .parse()
            .unwrap_or_else(|e| { eprintln!("DMPOT_CTRL_LISTEN: invalid address: {e}"); std::process::exit(1) });
        let receiver_ctrl: SocketAddr = std::env::var("DMPOT_RECEIVER_HOST")
            .unwrap_or_else(|_| "127.0.0.1:7099".into())
            .parse()
            .unwrap_or_else(|e| { eprintln!("DMPOT_RECEIVER_HOST: invalid address: {e}"); std::process::exit(1) });
        let protocol = match std::env::var("DMPOT_PROTOCOL").as_deref() {
            Ok("webrtc") => ProtocolType::WebRtc,
            Ok("quic")   => ProtocolType::Quic,
            Ok("http2")  => ProtocolType::Http2,
            _            => ProtocolType::Tls13,
        };
        let antidebug = std::env::var("DMPOT_ANTIDEBUG")
            .map(|v| v != "0" && v.to_lowercase() != "false").unwrap_or(true);
        let chunk_size: usize = std::env::var("DMPOT_CHUNK_SIZE").ok()
            .and_then(|s| s.parse().ok()).unwrap_or(DEFAULT_CHUNK_SIZE);
        let ctrl_timeout_secs: u64 = std::env::var("DMPOT_CTRL_TIMEOUT").ok()
            .and_then(|s| s.parse().ok()).unwrap_or(30);
        let skip_fingerprint = std::env::var("DMPOT_SKIP_FINGERPRINT")
            .map(|v| v == "1" || v.to_lowercase() == "true").unwrap_or(false);
        let max_sessions: usize = std::env::var("DMPOT_MAX_SESSIONS").ok()
            .and_then(|s| s.parse().ok()).unwrap_or(DEFAULT_MAX_SESSIONS);
        let max_bytes_per_session: usize = std::env::var("DMPOT_MAX_BYTES_SESSION").ok()
            .and_then(|s| s.parse().ok()).unwrap_or(DEFAULT_MAX_BYTES_PER_SESSION);

        let (file_in, file_out) = parse_file_args();

        let cbr_target_bps: u64 = std::env::var("DMPOT_CBR_BPS").ok()
            .and_then(|s| s.parse().ok()).unwrap_or(0);
        let cbr_enabled = std::env::var("DMPOT_CBR_ENABLED")
            .map(|v| v == "1" || v.to_lowercase() == "true").unwrap_or(false);

        Config {
            mode, n, k, onion_layers, remote_addrs, local_listen, ctrl_listen,
            receiver_ctrl, protocol, antidebug, chunk_size, ctrl_timeout_secs,
            skip_fingerprint, max_sessions, max_bytes_per_session,
            file_in, file_out, cbr_target_bps, cbr_enabled,
        }
    }
}


fn pk_fingerprint(pk: &[u8]) -> String {
    let hash = Sha256::digest(pk);
    let hex_parts: Vec<String> = hash.iter().take(16).map(|b| format!("{:02x}", b)).collect();
    format!("SHA256:{}", hex_parts.join(":"))
}


fn confirm_fingerprint(
    label: &str,
    fingerprint: &str,
    skip: bool,
) -> Result<(), DmpotError> {
    eprintln!();
    eprintln!("┌────────────────────────────────────────────────────────────┐");
    eprintln!("│  {} PUBLIC KEY FINGERPRINT", label);
    eprintln!("│  {}", fingerprint);
    eprintln!("│  Verify this matches on BOTH endpoints before proceeding.  │");
    eprintln!("└────────────────────────────────────────────────────────────┘");

    if skip {
        eprintln!("  (DMPOT_SKIP_FINGERPRINT=1 — auto-accepting)");
        return Ok(());
    }

    eprint!("  Accept this key? [yes/no]: ");
    io::stderr().flush().ok();

    let mut line = String::new();
    io::stdin().lock().read_line(&mut line)
        .map_err(DmpotError::Io)?;

    if line.trim().eq_ignore_ascii_case("yes") {
        Ok(())
    } else {
        Err(DmpotError::FingerprintRejected)
    }
}

fn send_pk_to_sender(
    ctrl_addr: SocketAddr,
    pk: &[u8],
    timeout: Duration,
    skip_fp: bool,
) -> Result<(), DmpotError> {

    let fp = pk_fingerprint(pk);
    eprintln!();
    eprintln!("┌────────────────────────────────────────────────────────────┐");
    eprintln!("│  RECEIVER PUBLIC KEY FINGERPRINT (share this with sender)  │");
    eprintln!("│  {}", fp);
    eprintln!("└────────────────────────────────────────────────────────────┘");

    let listener = TcpListener::bind(ctrl_addr)
        .map_err(|e| DmpotError::KeyExchange(format!("bind {ctrl_addr}: {e}")))?;
    log::info!("Waiting for sender key-exchange on {ctrl_addr} (timeout {}s)", timeout.as_secs());

    let (tx, rx) = mpsc::channel::<io::Result<(TcpStream, SocketAddr)>>();
    std::thread::spawn(move || { let _ = tx.send(listener.accept()); });

    let (mut stream, peer) = rx.recv_timeout(timeout)
        .map_err(|_| DmpotError::KeyExchangeTimeout(timeout.as_secs()))?
        .map_err(|e| DmpotError::KeyExchange(format!("accept: {e}")))?;

    log::info!("Key-exchange connection from {peer}");
    stream.set_write_timeout(Some(timeout))
        .map_err(|e| DmpotError::KeyExchange(format!("set_write_timeout: {e}")))?;
    stream.write_all(&(pk.len() as u32).to_le_bytes())
        .map_err(|e| DmpotError::KeyExchange(format!("write pk len: {e}")))?;
    stream.write_all(pk)
        .map_err(|e| DmpotError::KeyExchange(format!("write pk bytes: {e}")))?;
    stream.flush()
        .map_err(|e| DmpotError::KeyExchange(format!("flush: {e}")))?;

    log::info!("Public key ({} bytes) sent to sender", pk.len());

    if !skip_fp {
        eprintln!("  (receiver: key sent — waiting for operator to confirm on sender side)");
    }
    Ok(())
}

fn get_receiver_pk(
    receiver_ctrl: SocketAddr,
    timeout: Duration,
    skip_fp: bool,
) -> Result<Vec<u8>, DmpotError> {
    let mut stream = TcpStream::connect_timeout(&receiver_ctrl, timeout)
        .map_err(|e| DmpotError::KeyExchange(format!("connect {receiver_ctrl}: {e}")))?;
    stream.set_read_timeout(Some(timeout))
        .map_err(|e| DmpotError::KeyExchange(format!("set_read_timeout: {e}")))?;

    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf)
        .map_err(|e| DmpotError::KeyExchange(format!("read pk len: {e}")))?;
    let pk_len = u32::from_le_bytes(len_buf) as usize;
    if pk_len == 0 || pk_len > 8192 {
        return Err(DmpotError::KeyExchange(format!("pk_len {pk_len} out of range [1, 8192]")));
    }
    let mut pk_bytes = vec![0u8; pk_len];
    stream.read_exact(&mut pk_bytes)
        .map_err(|e| DmpotError::KeyExchange(format!("read pk bytes: {e}")))?;

    let fp = pk_fingerprint(&pk_bytes);
    confirm_fingerprint("RECEIVER", &fp, skip_fp)?;

    log::info!("Receiver public key accepted ({pk_len} bytes, {})", fp);
    Ok(pk_bytes)
}

fn run_sender(cfg: &Config) -> Result<(), DmpotError> {
    log::info!("DMPOT sender: n={} k={} layers={} chunk={} protocol={:?}",
        cfg.n, cfg.k, cfg.onion_layers, cfg.chunk_size, cfg.protocol);

    let timeout = Duration::from_secs(cfg.ctrl_timeout_secs);
    let receiver_pk = get_receiver_pk(cfg.receiver_ctrl, timeout, cfg.skip_fingerprint)?;

    let paths: Vec<PathInfo> = cfg.remote_addrs
        .iter()
        .enumerate()
        .map(|(i, &remote)| {
            let local: SocketAddr = format!("0.0.0.0:{}", 8000 + i)
                .parse()
                .unwrap_or_else(|_| { eprintln!("invalid port for path {i}"); std::process::exit(1) });
            PathInfo { local_addr: local, remote_addr: remote, weight: 1, active: true }
        })
        .collect();

    let mut controller = MultiPathController::new(paths)?;
    let mut morpher = ProtocolMorpher::new(cfg.protocol);

    let mut payload = Vec::new();
    if let Some(path) = cfg.file_in.as_ref() {
        let ft_cfg = FileTransferConfig {
            input_path: Some(path.clone()),
            chunk_size: cfg.chunk_size,
            ..Default::default()
        };
        for chunk in FileSender::new(ft_cfg, noop_metrics()).send_chunks() {
            payload.extend(chunk.map_err(|e| {
                DmpotError::Io(io::Error::other(e.to_string()))
            })?);
        }
    } else {
        io::stdin().read_to_end(&mut payload)?;
    }
    if payload.is_empty() {
        return Err(DmpotError::EmptyPayload);
    }

    let chunks: Vec<&[u8]> = payload.chunks(cfg.chunk_size).collect();
    log::info!("Payload {} bytes → {} chunks of up to {} bytes",
        payload.len(), chunks.len(), cfg.chunk_size);

    for (chunk_idx, chunk) in chunks.iter().enumerate() {
        log::debug!("Chunk {}/{}: {} bytes", chunk_idx + 1, chunks.len(), chunk.len());
        let fragments = split_payload(chunk, cfg.n, cfg.k);
        let session_id = fragments[0].header.session_id;

        for frag in &fragments {
            let enc = encapsulate_fragment(&frag.payload, &receiver_pk, cfg.onion_layers)
                .ok_or(DmpotError::EncapFailed)?;
            let enc_bytes = enc.to_bytes();
            let orig_len = enc_bytes.len() as u32;

            let morph_result = morpher.morph(&enc_bytes);
            let morphed = morph_result.packet.payload;

            let wire = build_wire_packet(
                &session_id, frag.header.x, frag.header.total, orig_len, &morphed,
            );

            match controller.send_fragment(&wire) {
                Ok(n) => log::debug!("  frag x={} → {n}B", frag.header.x),
                Err(e) => log::error!("  send error x={}: {e}", frag.header.x),
            }

            let delay = morph_result.packet.delay;
            if !delay.is_zero() { std::thread::sleep(delay); }
        }
    }

    log::info!("All {} chunks / {} fragments dispatched", chunks.len(), chunks.len() * cfg.n as usize);
    Ok(())
}

fn run_receiver(cfg: &Config) -> Result<(), DmpotError> {
    log::info!("DMPOT receiver: listen={} k={}", cfg.local_listen, cfg.k);

    let recipient_kp = KyberKeyPair::generate();
    log::info!("Kyber-1024 keypair ready ({} bytes pk)", recipient_kp.public_key_bytes().len());

    let timeout = Duration::from_secs(cfg.ctrl_timeout_secs);
    send_pk_to_sender(
        cfg.ctrl_listen,
        recipient_kp.public_key_bytes(),
        timeout,
        cfg.skip_fingerprint,
    )?;

    let mut udp_rx = UdpReceiver::bind(cfg.local_listen)?;
    udp_rx.set_timeout(Duration::from_secs(30))?;

    let mut reassembler = FragmentReassembler::with_limits(
        cfg.k,
        Duration::from_secs(30),
        cfg.max_sessions,
        cfg.max_bytes_per_session,
    );

    let mut file_rx: Option<FileReceiver> = cfg.file_out.as_ref().map(|p| {
        FileReceiver::new(
            FileTransferConfig {
                output_path: Some(p.clone()),
                chunk_size: cfg.chunk_size,
                ..Default::default()
            },
            noop_metrics(),
        )
    });

    loop {
        let packet = match udp_rx.recv_packet() {
            Ok(p) => p.to_vec(),
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock
                       || e.kind() == io::ErrorKind::TimedOut => {
                log::debug!("Receiver timeout — waiting");
                continue;
            }
            Err(e) => return Err(DmpotError::Io(e)),
        };

        let (session_id, x, total, orig_len, morphed_data) = match parse_wire_packet(&packet) {
            Some(r) => r,
            None => { log::debug!("Ignoring non-DMPOT packet"); continue; }
        };

        let real_len = orig_len as usize;
        if real_len > morphed_data.len() {
            log::warn!("orig_len {} > packet data {}; discarding", real_len, morphed_data.len());
            continue;
        }
        let enc_bytes = &morphed_data[..real_len];

        let enc = match EncapsulatedFragment::from_bytes(enc_bytes) {
            Some(e) => e,
            None => { log::debug!("Cannot parse EncapsulatedFragment x={}", x); continue; }
        };

        let share_bytes = match decapsulate_fragment(&enc, &recipient_kp, cfg.onion_layers) {
            Some(s) => s,
            None => { log::warn!("Decapsulation failed x={}", x); continue; }
        };

        if let Some(shares) = reassembler.feed_share(session_id, x, total, share_bytes) {
            log::info!("Quorum ({} shares) — reconstructing chunk", shares.len());

            let frags: Vec<DMPOTFragment> = shares
                .into_iter()
                .map(|(xi, pl)| DMPOTFragment {
                    header: FragmentHeader { session_id, x: xi, total },
                    payload: pl,
                })
                .collect();

            let plaintext = reconstruct_payload(&frags);
            if let Some(ref mut rx) = file_rx {
                rx.write_chunk(&plaintext).map_err(|e| {
                    DmpotError::Io(io::Error::other(e.to_string()))
                })?;
                log::info!("Chunk reconstructed: {} bytes → file buffer", plaintext.len());
            } else {
                io::stdout().write_all(&plaintext)?;
                io::stdout().flush()?;
                log::info!("Chunk reconstructed: {} bytes → stdout", plaintext.len());
            }
        }
    }
}

fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let cfg = Config::from_env();

    if let Ok(addr) = std::env::var("DMPOT_MGMT_ADDR") {
        eprintln!("Dashboard available: cargo run --bin dashboard -- --mgmt {addr}");
    }
    setup_panic_hook();

    let _guard = if cfg.antidebug {
        log::info!("Anti-debug monitor active");
        Some(AntiDebugGuard::start(Duration::from_millis(500)))
    } else {
        None
    };

    #[cfg(target_os = "linux")]
    let _integrity = MemoryIntegrityChecker::start(Duration::from_secs(30));

    let result = match cfg.mode {
        Mode::Send    => run_sender(&cfg),
        Mode::Receive => run_receiver(&cfg),
    };

    match result {
        Ok(()) => log::info!("DMPOT exiting cleanly"),
        Err(DmpotError::FingerprintRejected) => {
            eprintln!("Aborted: operator rejected the receiver fingerprint.");
            std::process::exit(2);
        }
        Err(e) => {
            log::error!("Fatal: {e}");
            std::process::exit(1);
        }
    }
}
