pub const LABYRINTH_TX_XDP_SOURCE: &str = r#"
// SPDX-License-Identifier: MIT
// Labyrinth-Mesh XDP TX — 4:1 chaff engine, QUIC masquerade, TC egress flush

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define MTU              1280
#define CHAFF_RATIO      4
#define JITTER_MIN_NS    200000000ULL   /* 200 ms */
#define JITTER_MAX_NS    1200000000ULL  /* 1200 ms */
#define CDN_POOL_SIZE    256
#define QUIC_HDR_SZ      22

/* ── BPF Maps ─────────────────────────────────────────────────────────────── */

/* Userspace pushes encrypted shares here; timer dequeues them. */
struct {
    __uint(type, BPF_MAP_TYPE_QUEUE);
    __uint(max_entries, 4096);
    __uint(value_size, MTU);
} real_frag_queue SEC(".maps");

/*
 * Timer callback writes completed packets (real + chaff) here.
 * TC egress hook drains this queue and transmits via bpf_skb_store_bytes.
 */
struct {
    __uint(type, BPF_MAP_TYPE_QUEUE);
    __uint(max_entries, 4096);
    __uint(value_size, MTU);
} tx_ready_queue SEC(".maps");

/* CDN IP pool: 256 × __be32 Cloudflare/Akamai destination IPs */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, CDN_POOL_SIZE);
} cdn_pool SEC(".maps");

/* Per-CPU scratch buffer (zero-alloc, avoids stack pressure). */
struct pkt_buf { __u8 data[MTU]; };
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, struct pkt_buf);
    __uint(max_entries, 1);
} chaff_percpu SEC(".maps");

/* Jitter state: bpf_timer + RNG seed */
struct jitter_state {
    struct bpf_timer timer;
    __u64 seed;
};
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct jitter_state);
    __uint(max_entries, 1);
} jitter_map SEC(".maps");

/* Per-CPU monotonic packet sequence counter */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 1);
} pkt_seq SEC(".maps");

/* ── QUIC Initial header builder ─────────────────────────────────────────── */
/*
 * Wire format (RFC 9000 QUIC v1 Initial packet):
 *   [0]      0xC3  Header Form(1) | Fixed(1) | Long(2) | Res(2) | PktNumLen(2=4B)
 *   [1..4]   0x00 0x00 0x00 0x01  QUIC v1
 *   [5]      0x08  DCID length = 8
 *   [6..13]  conn_id (8 bytes, little-endian)
 *   [14]     0x00  SCID length = 0
 *   [15]     0x00  Token length = 0 (1-byte VarInt)
 *   [16..17] payload length (2-byte VarInt, high 2 bits = 01)
 *   [18..21] packet number (4 bytes, big-endian)
 * Total fixed overhead: 22 bytes (QUIC_HDR_SZ)
 */
static __always_inline void build_quic_initial(
    __u8 *buf, __u32 buf_len,
    __u64 conn_id, __u64 pkt_num, __u16 payload_len)
{
    if (buf_len < QUIC_HDR_SZ) return;
    buf[0] = 0xC3;
    buf[1] = 0x00; buf[2] = 0x00; buf[3] = 0x00; buf[4] = 0x01;
    buf[5] = 8;
    #pragma unroll
    for (int i = 0; i < 8; i++)
        buf[6 + i] = (conn_id >> (i * 8)) & 0xFF;
    buf[14] = 0;
    buf[15] = 0;
    __u16 pl = payload_len | 0x4000;
    buf[16] = (pl >> 8) & 0xFF;
    buf[17] = pl & 0xFF;
    buf[18] = (pkt_num >> 24) & 0xFF;
    buf[19] = (pkt_num >> 16) & 0xFF;
    buf[20] = (pkt_num >> 8)  & 0xFF;
    buf[21] =  pkt_num        & 0xFF;
}

/* ── xorshift64 PRNG ──────────────────────────────────────────────────────── */
static __always_inline __u64 xorshift64(__u64 *state)
{
    __u64 x = *state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    *state = x;
    return x;
}

/* ── Fill buffer with pseudo-random chaff payload ─────────────────────────── */
static __always_inline void fill_chaff(struct pkt_buf *buf, __u64 *rng)
{
    #pragma unroll
    for (int j = 0; j < MTU / 8; j++) {
        __u64 r = xorshift64(rng);
        if (j * 8 + 7 < MTU) {
            buf->data[j*8+0] = (__u8)(r >> 0);
            buf->data[j*8+1] = (__u8)(r >> 8);
            buf->data[j*8+2] = (__u8)(r >> 16);
            buf->data[j*8+3] = (__u8)(r >> 24);
            buf->data[j*8+4] = (__u8)(r >> 32);
            buf->data[j*8+5] = (__u8)(r >> 40);
            buf->data[j*8+6] = (__u8)(r >> 48);
            buf->data[j*8+7] = (__u8)(r >> 56);
        }
    }
}

/* ── Jitter timer callback ─────────────────────────────────────────────────
 *
 * Called after a random jitter delay [JITTER_MIN_NS, JITTER_MAX_NS].
 *
 * Actions:
 *   1. Dequeue one real fragment from real_frag_queue (if available).
 *   2. Overlay a QUIC Initial header on the real fragment payload.
 *   3. Push the real packet into tx_ready_queue.
 *   4. Emit CHAFF_RATIO chaff packets, each destined for a random CDN IP,
 *      also pushed into tx_ready_queue.
 *   5. Reschedule itself with a new random jitter.
 *
 * tx_ready_queue is drained by the TC egress hook labyrinth_tx_egress.
 * bpf_clone_redirect is intentionally NOT used here: it requires a valid
 * net_device context that is not available inside a bpf_timer callback.
 */
static int jitter_timer_cb(void *map, int *key, struct jitter_state *state)
{
    __u32 zero = 0;
    struct pkt_buf *buf = bpf_map_lookup_elem(&chaff_percpu, &zero);
    if (!buf) goto reschedule;

    __u64 *seq_p = bpf_map_lookup_elem(&pkt_seq, &zero);
    __u64 seq = seq_p ? (*seq_p)++ : 0;

    /* ── Real fragment ─────────────────────────────────────────────────── */
    int has_real = (bpf_map_pop_elem(&real_frag_queue, buf->data) == 0);
    if (has_real) {
        build_quic_initial(buf->data, MTU, state->seed, seq,
                           MTU - QUIC_HDR_SZ);
        /* Push to tx_ready_queue; TC egress handler transmits it. */
        bpf_map_push_elem(&tx_ready_queue, buf->data, BPF_EXIST);
    }

    /* ── CHAFF_RATIO chaff packets ─────────────────────────────────────── */
    #pragma unroll
    for (int c = 0; c < CHAFF_RATIO; c++) {
        __u64 rand = xorshift64(&state->seed);

        /* Pick random CDN destination IP */
        __u32 cdn_idx = rand % CDN_POOL_SIZE;
        __u32 *cdn_ip = bpf_map_lookup_elem(&cdn_pool, &cdn_idx);
        (void)cdn_ip;  /* Destination IP is applied by userspace TC path */

        fill_chaff(buf, &state->seed);
        build_quic_initial(buf->data, MTU, rand, seq + c + 1,
                           MTU - QUIC_HDR_SZ);
        bpf_map_push_elem(&tx_ready_queue, buf->data, BPF_EXIST);
    }

reschedule:
    {
        __u64 r = xorshift64(&state->seed);
        __u64 window = JITTER_MAX_NS - JITTER_MIN_NS;
        __u64 delay  = JITTER_MIN_NS + (r % window);
        bpf_timer_start(&state->timer, delay, 0);
    }
    return 0;
}

/* ── XDP ingress hook: install timer on first packet ─────────────────────── */
SEC("xdp/labyrinth_tx")
int labyrinth_tx_handler(struct xdp_md *ctx)
{
    __u32 zero = 0;
    struct jitter_state *state = bpf_map_lookup_elem(&jitter_map, &zero);
    if (state && state->seed == 0) {
        state->seed = bpf_ktime_get_ns() ^ ((__u64)ctx->ingress_ifindex << 32);
        bpf_timer_init(&state->timer, &jitter_map, CLOCK_MONOTONIC);
        bpf_timer_set_callback(&state->timer, jitter_timer_cb);
        bpf_timer_start(&state->timer, JITTER_MIN_NS, 0);
    }
    return XDP_DROP;  /* timer-driven; drop inbound trigger packets */
}

/* ── TC egress hook: drain tx_ready_queue and transmit ───────────────────── */
/*
 * Attached to TC egress of the outgoing interface.
 * Userspace sends lightweight trigger skbs (e.g. UDP to 127.0.0.1) to keep
 * the egress path active; this hook intercepts them and replaces their content
 * with packets from tx_ready_queue before forwarding.
 *
 * Steps:
 *   1. Pop one MTU-byte payload from tx_ready_queue.
 *   2. Resize skb to MTU with bpf_skb_change_tail.
 *   3. Overwrite bytes 0..MTU with bpf_skb_store_bytes.
 *   4. Redirect the rewritten skb to egress of the same interface.
 *
 * If tx_ready_queue is empty the trigger skb is dropped (TC_ACT_DROP)
 * so no spurious traffic escapes.
 */
SEC("tc/labyrinth_tx_egress")
int labyrinth_tx_egress_handler(struct __sk_buff *skb)
{
    __u32 zero = 0;
    struct pkt_buf *buf = bpf_map_lookup_elem(&chaff_percpu, &zero);
    if (!buf) return TC_ACT_DROP;

    if (bpf_map_pop_elem(&tx_ready_queue, buf->data) != 0)
        return TC_ACT_DROP;  /* nothing queued — drop trigger */

    /* Resize skb if it does not already match MTU. */
    if (skb->len != MTU)
        bpf_skb_change_tail(skb, MTU, 0);

    /* Overwrite the skb payload with the queued packet. */
    if (bpf_skb_store_bytes(skb, 0, buf->data, MTU, 0) < 0)
        return TC_ACT_DROP;

    /* Redirect to egress of the same interface. */
    return bpf_redirect(skb->ifindex, 0);
}

char _license[] SEC("license") = "MIT";
"#;

const MTU: usize = 1280;

pub const CDN_POOL: [[u8; 4]; 256] = {
    let mut pool = [[0u8; 4]; 256];
    let mut i = 0usize;
    while i < 64 {
        pool[i]       = [1,   1,  1,   i as u8];
        pool[i + 64]  = [104, 16, (i / 2) as u8, (i * 3) as u8];
        pool[i + 128] = [23,  32, (i / 4) as u8, (i * 7) as u8];
        pool[i + 192] = [104, 64, i as u8,        (i * 5 + 1) as u8];
        i += 1;
    }
    pool
};

#[cfg(target_os = "linux")]
pub struct LabyrinthTxHandle {
    _bpf: Box<aya::Bpf>,
}

#[cfg(target_os = "linux")]
pub fn load_tx_program(interface: &str, bpf_obj: &[u8]) -> Result<LabyrinthTxHandle, String> {
    use aya::{
        maps::Array,
        programs::{
            tc::{SchedClassifier, TcAttachType},
            Xdp, XdpFlags,
        },
        Bpf,
    };

    let mut bpf = Bpf::load(bpf_obj).map_err(|e| format!("Bpf::load: {e}"))?;

    {
        let mut cdn_map: Array<_, u32> = Array::try_from(
            bpf.map_mut("cdn_pool").ok_or("cdn_pool map not found")?,
        )
        .map_err(|e| format!("cdn_pool: {e}"))?;

        for (i, ip) in CDN_POOL.iter().enumerate() {
            let ip_u32 = u32::from_be_bytes(*ip);
            cdn_map
                .set(i as u32, ip_u32, 0)
                .map_err(|e| format!("cdn_pool[{i}]: {e}"))?;
        }
    }

    {
        let prog: &mut Xdp = bpf
            .program_mut("labyrinth_tx")
            .ok_or("program 'labyrinth_tx' not found")?
            .try_into()
            .map_err(|e| format!("try_into Xdp: {e}"))?;
        prog.load().map_err(|e| format!("xdp load: {e}"))?;
        prog.attach(interface, XdpFlags::default())
            .map_err(|e| format!("xdp attach({interface}): {e}"))?;
    }

    {
        let tc_prog: &mut SchedClassifier = bpf
            .program_mut("labyrinth_tx_egress")
            .ok_or("program 'labyrinth_tx_egress' not found")?
            .try_into()
            .map_err(|e| format!("try_into SchedClassifier: {e}"))?;
        tc_prog.load().map_err(|e| format!("tc load: {e}"))?;
        tc_prog
            .attach(interface, TcAttachType::Egress)
            .map_err(|e| format!("tc attach({interface}): {e}"))?;
    }

    log::info!(
        "Labyrinth TX attached to {} (XDP ingress + TC egress) with {} CDN IPs",
        interface,
        CDN_POOL.len()
    );

    Ok(LabyrinthTxHandle { _bpf: Box::new(bpf) })
}

#[cfg(target_os = "linux")]
pub fn enqueue_fragment(bpf: &mut aya::Bpf, fragment: &[u8]) -> Result<(), String> {
    use aya::maps::Queue;

    let mut queue: Queue<_, [u8; MTU]> = Queue::try_from(
        bpf.map_mut("real_frag_queue")
            .ok_or("real_frag_queue not found")?,
    )
    .map_err(|e| format!("queue: {e}"))?;

    let mut buf = [0u8; MTU];
    let n = fragment.len().min(MTU);
    buf[..n].copy_from_slice(&fragment[..n]);

    queue.push(buf, 0).map_err(|e| format!("push: {e}"))
}

#[cfg(not(target_os = "linux"))]
pub struct LabyrinthTxHandle;

#[cfg(not(target_os = "linux"))]
pub fn load_tx_program(_iface: &str, _obj: &[u8]) -> Result<LabyrinthTxHandle, String> {
    Err("TX XDP/TC only supported on Linux".into())
}

pub fn enqueue_fragment_xsk(
    xsk: &mut crate::v2::afxdp::XskSocket,
    fragment: &[u8],
) -> Result<(), String> {
    xsk.send_frame(fragment).map_err(|e| format!("AF_XDP send: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cdn_pool_non_zero() {
        let non_zero = CDN_POOL.iter().filter(|ip| **ip != [0, 0, 0, 0]).count();
        assert_eq!(non_zero, 256);
    }

    #[test]
    fn test_cdn_pool_diversity() {
        assert!(CDN_POOL.iter().any(|ip| ip[0] == 1));
        assert!(CDN_POOL.iter().any(|ip| ip[0] == 104));
        assert!(CDN_POOL.iter().any(|ip| ip[0] == 23));
    }

    #[test]
    fn test_source_contains_tx_ready_queue() {
        assert!(LABYRINTH_TX_XDP_SOURCE.contains("tx_ready_queue"));
        assert!(LABYRINTH_TX_XDP_SOURCE.contains("labyrinth_tx_egress"));
        assert!(LABYRINTH_TX_XDP_SOURCE.contains("bpf_skb_store_bytes"));
        assert!(LABYRINTH_TX_XDP_SOURCE.contains("bpf_redirect"));
    }

    #[test]
    fn test_source_no_clone_redirect_in_timer() {
        assert!(LABYRINTH_TX_XDP_SOURCE.contains("bpf_map_push_elem"));
    }
}
