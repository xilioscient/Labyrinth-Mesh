#![allow(dead_code)]

use std::collections::HashMap;
use std::net::{SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

pub const DMPOT_MAGIC: [u8; 2] = [0xD4, 0x5E];

#[repr(u32)]
#[derive(Debug, Clone, Copy)]
pub enum XdpAction {
    Aborted  = 0,
    Drop     = 1,
    Pass     = 2,
    Tx       = 3,
    Redirect = 4,
}

pub const DMPOT_XDP_SOURCE: &str = r#"
// SPDX-License-Identifier: MIT
// DMPOT XDP Fragment Interceptor — corrected version

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define DMPOT_MAGIC_0  0xD4
#define DMPOT_MAGIC_1  0x5E
#define DMPOT_HEADER_SIZE 24   /* magic(2) + session_id(16) + idx(1) + total(1) + orig_len(4) */

/* Ring buffer for user-space notification (256 KB) */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 18);  /* 256 KB */
} dmpot_ringbuf SEC(".maps");

/* Fragment tracking: session_hash → fragment_count */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 1024);
} fragment_tracker SEC(".maps");

/* DEVMAP for XDP_REDIRECT across interfaces */
struct {
    __uint(type, BPF_MAP_TYPE_DEVMAP);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
    __uint(max_entries, 64);
} redirect_devmap SEC(".maps");

struct dmpot_header {
    __u8  magic[2];
    __u8  session_id[16];
    __u8  fragment_index;
    __u8  total_fragments;
};

struct dmpot_event {
    __u32 session_hash;
    __u32 fragment_index;
    __u32 total_fragments;
    __u32 ingress_ifindex;
    __u64 timestamp_ns;
};

SEC("xdp/dmpot_xdp_handler")
int dmpot_xdp_handler(struct xdp_md *ctx)
{
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    /* --- FIX 1: Skip L2/L3/L4 headers to reach DMPOT payload -------- */
    /* ETH_HLEN(14) + sizeof(iphdr)(20) + sizeof(udphdr)(8) = 42         */
    struct ethhdr  *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IP)) return XDP_PASS;

    struct iphdr *ip = (struct iphdr *)(eth + 1);
    if ((void *)(ip + 1) > data_end) return XDP_PASS;

    if (ip->protocol != IPPROTO_UDP) return XDP_PASS;

    /* ip->ihl gives the IP header length in 32-bit words */
    struct udphdr *udp = (struct udphdr *)((void *)ip + ip->ihl * 4);
    if ((void *)(udp + 1) > data_end) return XDP_PASS;

    void *payload = (void *)(udp + 1);

    /* --- FIX 5: Explicit bounds check before accessing payload -------- */
    if (payload + DMPOT_HEADER_SIZE > data_end) return XDP_PASS;

    __u8 magic0, magic1;

    /* --- FIX 4: bpf_probe_read_kernel replaces deprecated bpf_probe_read */
    bpf_probe_read_kernel(&magic0, sizeof(magic0), payload + 0);
    bpf_probe_read_kernel(&magic1, sizeof(magic1), payload + 1);

    if (magic0 != DMPOT_MAGIC_0 || magic1 != DMPOT_MAGIC_1) return XDP_PASS;

    struct dmpot_header hdr;
    bpf_probe_read_kernel(&hdr, sizeof(hdr), payload);

    /* --- FIX 2: #pragma unroll — BPF verifier rejects loops on kernel < 5.3 */
    __u32 session_hash = 0;
    #pragma unroll
    for (int i = 0; i < 16; i++) {
        session_hash ^= ((__u32)hdr.session_id[i]) << ((i % 4) * 8);
    }

    /* Track fragment count for this session */
    __u32 *count = bpf_map_lookup_elem(&fragment_tracker, &session_hash);
    __u32  one   = 1;
    if (count) {
        __u32 new_count = *count + 1;
        bpf_map_update_elem(&fragment_tracker, &session_hash, &new_count, BPF_EXIST);
    } else {
        bpf_map_update_elem(&fragment_tracker, &session_hash, &one, BPF_NOEXIST);
    }

    /* Publish event to ring buffer for user-space reassembly */
    struct dmpot_event *evt = bpf_ringbuf_reserve(&dmpot_ringbuf, sizeof(*evt), 0);
    if (evt) {
        evt->session_hash    = session_hash;
        evt->fragment_index  = hdr.fragment_index;
        evt->total_fragments = hdr.total_fragments;
        evt->ingress_ifindex = ctx->ingress_ifindex;
        evt->timestamp_ns    = bpf_ktime_get_ns();
        bpf_ringbuf_submit(evt, 0);
    }

    /* --- FIX 3: bpf_redirect_map with DEVMAP for multi-path redirect --- */
    __u32 nfrags = hdr.total_fragments > 0 ? hdr.total_fragments : 1;
    __u32 target_iface_key = hdr.fragment_index % nfrags;
    return bpf_redirect_map(&redirect_devmap, target_iface_key, XDP_PASS);
}

char _license[] SEC("license") = "MIT";
"#;

#[repr(C, packed)]
pub struct EthHeader {
    pub dst: [u8; 6],
    pub src: [u8; 6],
    pub ether_type: u16,
}

#[repr(C, packed)]
pub struct IpHeader {
    pub version_ihl: u8,
    pub tos: u8,
    pub total_len: u16,
    pub id: u16,
    pub flags_frag: u16,
    pub ttl: u8,
    pub protocol: u8,
    pub checksum: u16,
    pub src_addr: [u8; 4],
    pub dst_addr: [u8; 4],
}

#[repr(C, packed)]
pub struct UdpHeader {
    pub src_port: u16,
    pub dst_port: u16,
    pub length: u16,
    pub checksum: u16,
}

#[repr(C, packed)]
pub struct DmpotWireHeader {
    pub magic: [u8; 2],
    pub session_id: [u8; 16],
    pub fragment_index: u8,
    pub total_fragments: u8,
    pub orig_len: u32,
}

#[cfg(target_os = "linux")]
pub fn load_xdp_program(interface: &str, bpf_obj_bytes: &[u8]) -> Result<XdpHandle, String> {
    use aya::{
        programs::{Xdp, XdpFlags},
        Bpf,
    };

    let mut bpf = Bpf::load(bpf_obj_bytes)
        .map_err(|e| format!("Bpf::load failed: {e}"))?;

    let program: &mut Xdp = bpf
        .program_mut("dmpot_xdp_handler")
        .ok_or("program 'dmpot_xdp_handler' not found")?
        .try_into()
        .map_err(|e| format!("try_into Xdp: {e}"))?;

    program.load().map_err(|e| format!("program.load: {e}"))?;
    program
        .attach(interface, XdpFlags::default())
        .map_err(|e| format!("program.attach({interface}): {e}"))?;

    log::info!("XDP program attached to {interface}");
    Ok(XdpHandle { _bpf: Box::new(bpf) })
}

#[cfg(target_os = "linux")]
pub struct XdpHandle {
    _bpf: Box<aya::Bpf>,
}

#[cfg(not(target_os = "linux"))]
pub fn load_xdp_program(_interface: &str, _bpf_obj_bytes: &[u8]) -> Result<(), String> {
    Err("XDP is only supported on Linux".to_string())
}

#[derive(Debug, Clone)]
pub struct PathInfo {
    pub local_addr: SocketAddr,
    pub remote_addr: SocketAddr,
    pub weight: u32,
    pub active: bool,
}

pub struct MultiPathController {
    paths: Vec<PathInfo>,
    sockets: Vec<UdpSocket>,
    current: usize,
    sent_counts: Vec<u64>,
}

impl MultiPathController {
    pub fn new(paths: Vec<PathInfo>) -> std::io::Result<Self> {
        let mut sockets = Vec::with_capacity(paths.len());
        for path in &paths {
            let sock = UdpSocket::bind(path.local_addr)?;
            sock.set_nonblocking(true)?;
            sockets.push(sock);
        }
        let n = paths.len();
        Ok(MultiPathController {
            paths,
            sockets,
            current: 0,
            sent_counts: vec![0; n],
        })
    }

    pub fn select_path(&mut self) -> Option<usize> {
        if self.paths.is_empty() { return None; }
        let total_weight: u32 = self.paths.iter()
            .filter(|p| p.active)
            .map(|p| p.weight)
            .sum();
        if total_weight == 0 { return None; }

        for _ in 0..self.paths.len() {
            let idx = self.current % self.paths.len();
            self.current = self.current.wrapping_add(1);
            if self.paths[idx].active {
                return Some(idx);
            }
        }
        None
    }

    pub fn send_fragment(&mut self, fragment_bytes: &[u8]) -> std::io::Result<usize> {
        let idx = self.select_path()
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "no active path"))?;
        let remote = self.paths[idx].remote_addr;
        let n = self.sockets[idx].send_to(fragment_bytes, remote)?;
        self.sent_counts[idx] += 1;
        Ok(n)
    }

    pub fn scatter_fragments(&mut self, fragments: &[Vec<u8>]) -> std::io::Result<()> {
        for frag in fragments {
            self.send_fragment(frag)?;
        }
        Ok(())
    }

    pub fn deactivate_path(&mut self, idx: usize) {
        if idx < self.paths.len() {
            self.paths[idx].active = false;
        }
    }

    pub fn sent_counts(&self) -> &[u64] { &self.sent_counts }

    pub fn path_count(&self) -> usize { self.paths.len() }

    pub fn active_path_count(&self) -> usize {
        self.paths.iter().filter(|p| p.active).count()
    }

    pub fn activate_path(&mut self, idx: usize) {
        if idx < self.paths.len() {
            self.paths[idx].active = true;
        }
    }
}

pub const DEFAULT_MAX_SESSIONS: usize = 1024;

pub const DEFAULT_MAX_BYTES_PER_SESSION: usize = 16 * 1024 * 1024;

#[derive(Debug)]
struct SessionState {
    fragments: HashMap<u8, Vec<u8>>,
    total: u8,
    threshold_k: u8,
    created: Instant,
    total_bytes: usize,
}

pub struct FragmentReassembler {
    sessions: HashMap<[u8; 16], SessionState>,
    timeout: Duration,
    threshold_k: u8,
    max_sessions: usize,
    max_bytes_per_session: usize,
}

impl FragmentReassembler {
    pub fn new(threshold_k: u8, timeout: Duration) -> Self {
        FragmentReassembler::with_limits(
            threshold_k,
            timeout,
            DEFAULT_MAX_SESSIONS,
            DEFAULT_MAX_BYTES_PER_SESSION,
        )
    }

    pub fn with_limits(
        threshold_k: u8,
        timeout: Duration,
        max_sessions: usize,
        max_bytes_per_session: usize,
    ) -> Self {
        FragmentReassembler {
            sessions: HashMap::new(),
            timeout,
            threshold_k,
            max_sessions,
            max_bytes_per_session,
        }
    }

    pub fn feed(&mut self, packet: &[u8]) -> Option<Vec<(u8, Vec<u8>)>> {
        self.evict_stale();

        if packet.len() < 24 { return None; }
        if packet[0..2] != DMPOT_MAGIC { return None; }

        let mut session_id = [0u8; 16];
        session_id.copy_from_slice(&packet[2..18]);
        let fragment_x = packet[18];
        let total = packet[19];
        let payload = packet[24..].to_vec();

        self.feed_share(session_id, fragment_x, total, payload)
    }

    pub fn feed_share(
        &mut self,
        session_id: [u8; 16],
        x: u8,
        total: u8,
        payload: Vec<u8>,
    ) -> Option<Vec<(u8, Vec<u8>)>> {
        self.evict_stale();

        let is_new_session = !self.sessions.contains_key(&session_id);

        if is_new_session && self.sessions.len() >= self.max_sessions {
            log::warn!(
                "Reassembler at capacity ({} sessions) — dropping new session {:02x?}",
                self.max_sessions, &session_id[..4]
            );
            return None;
        }

        let k = self.threshold_k;
        let max_bytes = self.max_bytes_per_session;
        let state = self.sessions.entry(session_id).or_insert_with(|| SessionState {
            fragments: HashMap::new(),
            total,
            threshold_k: k,
            created: Instant::now(),
            total_bytes: 0,
        });

        if state.total_bytes + payload.len() > max_bytes {
            log::warn!(
                "Session {:02x?} exceeded max bytes ({} > {}) — evicting",
                &session_id[..4], state.total_bytes + payload.len(), max_bytes
            );
            self.sessions.remove(&session_id);
            return None;
        }

        state.total_bytes += payload.len();
        state.fragments.insert(x, payload);

        if state.fragments.len() >= state.threshold_k as usize {
            let result: Vec<(u8, Vec<u8>)> = state.fragments
                .iter()
                .map(|(&xi, p)| (xi, p.clone()))
                .collect();
            self.sessions.remove(&session_id);
            return Some(result);
        }

        None
    }

    fn evict_stale(&mut self) {
        let timeout = self.timeout;
        self.sessions.retain(|_, s| s.created.elapsed() < timeout);
    }

    pub fn active_sessions(&self) -> usize { self.sessions.len() }
}

pub struct UdpReceiver {
    socket: UdpSocket,
    buf: Vec<u8>,
}

impl UdpReceiver {
    pub fn bind(addr: SocketAddr) -> std::io::Result<Self> {
        let socket = UdpSocket::bind(addr)?;
        Ok(UdpReceiver { socket, buf: vec![0u8; 65535] })
    }

    pub fn set_timeout(&self, timeout: Duration) -> std::io::Result<()> {
        self.socket.set_read_timeout(Some(timeout))
    }

    pub fn recv_packet(&mut self) -> std::io::Result<&[u8]> {
        let (n, _) = self.socket.recv_from(&mut self.buf)?;
        Ok(&self.buf[..n])
    }
}

pub fn build_wire_packet(session_id: &[u8; 16], x: u8, total: u8, orig_len: u32, data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(24 + data.len());
    out.extend_from_slice(&DMPOT_MAGIC);
    out.extend_from_slice(session_id);
    out.push(x);
    out.push(total);
    out.extend_from_slice(&orig_len.to_le_bytes());
    out.extend_from_slice(data);
    out
}

type WirePacketFields<'a> = ([u8; 16], u8, u8, u32, &'a [u8]);

pub fn parse_wire_packet(packet: &[u8]) -> Option<WirePacketFields<'_>> {
    if packet.len() < 24 { return None; }
    if packet[0..2] != DMPOT_MAGIC { return None; }
    let mut session_id = [0u8; 16];
    session_id.copy_from_slice(&packet[2..18]);
    let x = packet[18];
    let total = packet[19];
    let orig_len = u32::from_le_bytes(packet[20..24].try_into().ok()?);
    Some((session_id, x, total, orig_len, &packet[24..]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;

    #[test]
    fn test_wire_packet_roundtrip() {
        let sid = [0x42u8; 16];
        let data = b"payload bytes";
        let orig_len = data.len() as u32;
        let pkt = build_wire_packet(&sid, 3, 5, orig_len, data);
        let (sid2, x, total, ol, payload) = parse_wire_packet(&pkt).unwrap();
        assert_eq!(sid2, sid);
        assert_eq!(x, 3);
        assert_eq!(total, 5);
        assert_eq!(ol, orig_len);
        assert_eq!(payload, data);
    }

    #[test]
    fn test_fragment_reassembler_basic() {
        let mut reassembler = FragmentReassembler::new(2, Duration::from_secs(60));
        let sid = [0x01u8; 16];

        let pkt1 = build_wire_packet(&sid, 1, 3, 9, b"share_one");
        let pkt2 = build_wire_packet(&sid, 2, 3, 9, b"share_two");

        assert!(reassembler.feed(&pkt1).is_none());
        let result = reassembler.feed(&pkt2);
        assert!(result.is_some());
        let shares = result.unwrap();
        assert_eq!(shares.len(), 2);
    }

    #[test]
    fn test_feed_share_direct() {
        let mut r = FragmentReassembler::new(2, Duration::from_secs(60));
        let sid = [0xAAu8; 16];
        assert!(r.feed_share(sid, 1, 3, b"s1".to_vec()).is_none());
        let result = r.feed_share(sid, 2, 3, b"s2".to_vec());
        assert!(result.is_some());
    }

    #[test]
    fn test_dmpot_magic_rejection() {
        let mut r = FragmentReassembler::new(2, Duration::from_secs(60));
        let bad = b"XXXX garbage data padding padding padding padded";
        assert!(r.feed(bad).is_none());
    }

    #[test]
    fn test_stale_session_eviction() {
        let mut r = FragmentReassembler::new(3, Duration::from_millis(1));
        let sid = [0xFFu8; 16];
        let pkt = build_wire_packet(&sid, 1, 3, 4, b"data");
        r.feed(&pkt);
        assert_eq!(r.active_sessions(), 1);
        std::thread::sleep(Duration::from_millis(5));
        r.feed(&build_wire_packet(&[0x00u8; 16], 1, 3, 5, b"other"));
        assert_eq!(r.active_sessions(), 1);
    }
}
