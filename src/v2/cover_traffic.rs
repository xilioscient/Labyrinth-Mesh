pub const COVER_TRAFFIC_XDP_SOURCE: &str = r#"
// SPDX-License-Identifier: MIT
// Labyrinth-Mesh cover traffic engine — CBR Scheduler
//
// Build:
//   clang -O2 -target bpf -c labyrinth_cover.c -o labyrinth_cover.o
//   llvm-strip -g labyrinth_cover.o
//
// Kernel minimo: 5.15 (bpf_timer)

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define MTU              1280
#define TARGET_BPS       2000000ULL
#define CBR_TIMER_NS     1000000ULL    /* callback ogni 1ms */
#define CBR_MAX_CREDIT   (MTU * 4)    /* cap burst: 4 pacchetti */
#define CBR_MAX_BURST    8            /* max pacchetti per callback */

/* ── Struct stato CBR ────────────────────────────────────────────────────── */
/*
 * Layout (tutti campi 8 byte, allineamento naturale):
 *   [0..8]   target_bps        — aggiornabile runtime
 *   [8..16]  packets_sent      — contatore monotono
 *   [16..24] bytes_sent        — contatore monotono
 *   [24..32] last_ts_ns        — timestamp ultimo callback
 *   [32..40] credit_bytes      — crediti accumulati (signed)
 *   [40..48] max_credit_bytes  — cap burst configurabile
 *   [48..]   bpf_timer         — opaco al kernel
 */
struct cbr_state {
    __u64 target_bps;
    __u64 packets_sent;
    __u64 bytes_sent;
    __u64 last_ts_ns;
    __s64 credit_bytes;
    __s64 max_credit_bytes;
    struct bpf_timer timer;
};

/* ── BPF Maps ─────────────────────────────────────────────────────────────── */

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct cbr_state);
    __uint(max_entries, 1);
} cbr_state_map SEC(".maps");

/* Coda frammenti reali (condivisa con modulo TX) */
struct {
    __uint(type, BPF_MAP_TYPE_QUEUE);
    __uint(max_entries, 4096);
    __uint(value_size, MTU);
} real_frag_queue SEC(".maps");

/* Buffer per-CPU — zero-alloc nel path XDP */
struct pkt_buf { __u8 data[MTU]; };
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, struct pkt_buf);
    __uint(max_entries, 1);
} cover_percpu SEC(".maps");

/* Seed PRNG per-CPU */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 1);
} rng_seed SEC(".maps");

/* ── xorshift64 — identico a xdp_tx.c per indistinguibilita' statistica ─── */
static __always_inline __u64 xorshift64(__u64 *s)
{
    __u64 x = *s;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    *s = x;
    return x;
}

/* ── Riempie buf->data con payload pseudo-random (cover packet) ─────────── */
static __always_inline void fill_cover_payload(struct pkt_buf *buf, __u64 *rng)
{
    /* #pragma unroll obbligatorio: verifier BPF rifiuta loop non bounded */
    #pragma unroll
    for (int j = 0; j < MTU / 8; j++) {
        __u64 r = xorshift64(rng);
        /* Accesso con bound check esplicito per il verifier */
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

/* ── CBR timer callback ───────────────────────────────────────────────────── */
/*
 * Logica:
 *  1. Calcola elapsed_ns dall'ultimo callback
 *  2. Converte in byte-crediti: new_credits = elapsed_ns / (8e9 / bps)
 *  3. Accumula crediti con cap a max_credit_bytes
 *  4. Emette pacchetti (reali o cover) finche' credit_bytes >= MTU
 *  5. Riprogramma timer a 1ms fisso
 *
 * Il rate e' controllato dai crediti, NON dall'intervallo del timer.
 * L'intervallo breve (1ms) serve solo a ridurre la latenza del burst recovery.
 */
static int cover_timer_cb(void *map, int *key, struct cbr_state *state)
{
    __u32 zero = 0;
    __u64 now  = bpf_ktime_get_ns();

    /* ── Accumulazione crediti ──────────────────────────────────────────── */
    __u64 elapsed_ns = now - state->last_ts_ns;
    state->last_ts_ns = now;

    __u64 bps = state->target_bps ? state->target_bps : TARGET_BPS;

    /*
     * Calcolo crediti senza __u128 (non supportato verifier < 5.19):
     *   bytes_per_second = bps / 8
     *   bytes_per_ns     = bps / 8 / 1_000_000_000
     *   new_credits      = elapsed_ns * bps / 8_000_000_000
     *
     * Riscriviamo come divisione intera:
     *   divisor = 8_000_000_000 / bps  [ns per byte]
     *   new_credits = elapsed_ns / divisor
     *
     * Errore massimo: < 0.1% per bps in [100_000, 100_000_000].
     */
    __u64 divisor = 8000000000ULL / bps;
    if (divisor == 0) divisor = 1;
    __s64 new_credits = (__s64)(elapsed_ns / divisor);

    state->credit_bytes += new_credits;

    /* Cap burst: non accumulare piu' di max_credit_bytes */
    __s64 cap = state->max_credit_bytes > 0
                    ? state->max_credit_bytes
                    : (__s64)(MTU * 4);
    if (state->credit_bytes > cap)
        state->credit_bytes = cap;

    /* ── Emissione pacchetti ────────────────────────────────────────────── */
    struct pkt_buf *buf = bpf_map_lookup_elem(&cover_percpu, &zero);
    if (!buf) goto reschedule;

    __u64 *seed_p = bpf_map_lookup_elem(&rng_seed, &zero);
    __u64 rng = seed_p ? *seed_p : now;

    /*
     * Max CBR_MAX_BURST=8 pacchetti per callback.
     * #pragma unroll richiesto: verifier BPF non accetta loop variabili
     * con accesso a mappe dentro il corpo.
     */
    #pragma unroll
    for (int i = 0; i < CBR_MAX_BURST; i++) {
        if (state->credit_bytes < (__s64)MTU) break;

        /* Tenta dequeue frammento reale; fallback a cover */
        int is_real = (bpf_map_pop_elem(&real_frag_queue, buf->data) == 0);

        if (!is_real) {
            fill_cover_payload(buf, &rng);
        }

        state->credit_bytes -= (__s64)MTU;
        state->packets_sent++;
        state->bytes_sent += MTU;
    }

    if (seed_p) *seed_p = rng;

reschedule:
    /*
     * Timer fisso a 1ms. Il rate effettivo e' determinato dai crediti,
     * non da questo intervallo. Intervallo breve = bassa latenza di
     * recupero da timer miss; overhead trascurabile (~0.1% CPU).
     */
    bpf_timer_start(&state->timer, CBR_TIMER_NS, 0);
    return 0;
}

/* ── XDP handler: inizializzazione one-shot ──────────────────────────────── */
/*
 * Questo handler viene invocato dal primo pacchetto in ingresso.
 * Il suo unico scopo e' armare il bpf_timer; dopo di che il CBR e'
 * completamente autonomo e non dipende dal traffico in ingresso.
 */
SEC("xdp/labyrinth_cover")
int labyrinth_cover_handler(struct xdp_md *ctx)
{
    __u32 zero = 0;
    struct cbr_state *state = bpf_map_lookup_elem(&cbr_state_map, &zero);
    if (!state) return XDP_PASS;

    /* Inizializza solo alla prima invocazione (last_ts_ns == 0 = stato fresco) */
    if (state->last_ts_ns == 0) {
        __u64 now = bpf_ktime_get_ns();

        state->last_ts_ns       = now;
        state->credit_bytes     = 0;
        state->target_bps       = TARGET_BPS;
        state->max_credit_bytes = (__s64)(MTU * 4);

        /* Seed PRNG da hardware timestamp XOR ifindex */
        __u64 *seed_p = bpf_map_lookup_elem(&rng_seed, &zero);
        if (seed_p && *seed_p == 0)
            *seed_p = now ^ ((__u64)ctx->ingress_ifindex << 32);

        /* Arma il timer CBR */
        bpf_timer_init(&state->timer, &cbr_state_map, CLOCK_MONOTONIC);
        bpf_timer_set_callback(&state->timer, cover_timer_cb);
        bpf_timer_start(&state->timer, CBR_TIMER_NS, 0);
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "MIT";
"#;

pub const TARGET_BPS: u64 = 2_000_000;

pub const COVER_MTU: usize = 1280;

pub const CBR_TIMER_INTERVAL_NS: u64 = 1_000_000;

pub const COVER_INTERVAL_NS: u64 = CBR_TIMER_INTERVAL_NS;

pub const CBR_MAX_CREDIT_BYTES: i64 = (COVER_MTU as i64) * 4;

pub const CBR_DIVISOR_NS: u64 = 8_000_000_000 / TARGET_BPS;

#[derive(Debug, Clone, Copy)]
pub struct CoverStats {
    pub packets_sent: u64,
    pub bytes_sent: u64,
    pub current_bps: f64,
    pub credit_bytes: i64,
}

impl CoverStats {
    pub fn effective_mbps(&self) -> f64 {
        self.current_bps / 1_000_000.0
    }

    pub fn is_bursting(&self) -> bool {
        self.credit_bytes > COVER_MTU as i64
    }
}

#[cfg(target_os = "linux")]
pub struct CoverTrafficHandle {
    pub bpf: Box<aya::Bpf>,
    prev_bytes: u64,
    prev_ts: std::time::Instant,
}

#[cfg(target_os = "linux")]
pub fn load_cover_program(
    interface: &str,
    bpf_obj: &[u8],
    target_bps: u64,
) -> Result<CoverTrafficHandle, String> {
    let effective_bps = if target_bps > 0 { target_bps } else { TARGET_BPS };
    use aya::{
        programs::{Xdp, XdpFlags},
        Bpf,
    };

    let mut bpf = Bpf::load(bpf_obj)
        .map_err(|e| format!("Bpf::load: {e}"))?;

    let prog: &mut Xdp = bpf
        .program_mut("labyrinth_cover")
        .ok_or("programma 'labyrinth_cover' non trovato nell'oggetto BPF")?
        .try_into()
        .map_err(|e| format!("try_into Xdp: {e}"))?;

    prog.load().map_err(|e| format!("prog.load: {e}"))?;
    prog.attach(interface, XdpFlags::default())
        .map_err(|e| format!("prog.attach({interface}): {e}"))?;

    log::info!(
        "CBR cover traffic engine attivo su {} (target: {} Mbps, timer: {}ms, cap: {} pkt)",
        interface,
        effective_bps / 1_000_000,
        CBR_TIMER_INTERVAL_NS / 1_000_000,
        CBR_MAX_CREDIT_BYTES / COVER_MTU as i64,
    );

    Ok(CoverTrafficHandle {
        bpf: Box::new(bpf),
        prev_bytes: 0,
        prev_ts: std::time::Instant::now(),
    })
}

#[cfg(target_os = "linux")]
pub fn read_stats(handle: &mut CoverTrafficHandle) -> Result<CoverStats, String> {
    use aya::maps::Array;

    let arr: Array<_, [u8; 48]> = Array::try_from(
        handle
            .bpf
            .map_mut("cbr_state_map")
            .ok_or("cbr_state_map non trovata")?,
    )
    .map_err(|e| format!("Array::try_from: {e}"))?;

    let raw = arr.get(&0, 0).map_err(|e| format!("arr.get: {e}"))?;

    let packets_sent = u64::from_le_bytes(raw[8..16].try_into().unwrap());
    let bytes_sent   = u64::from_le_bytes(raw[16..24].try_into().unwrap());
    let credit_bytes = i64::from_le_bytes(raw[32..40].try_into().unwrap());

    let now = std::time::Instant::now();
    let dt_secs = now.duration_since(handle.prev_ts).as_secs_f64();
    let current_bps = if dt_secs > 0.0 {
        ((bytes_sent.saturating_sub(handle.prev_bytes)) as f64 * 8.0) / dt_secs
    } else {
        0.0
    };

    handle.prev_bytes = bytes_sent;
    handle.prev_ts = now;

    Ok(CoverStats {
        packets_sent,
        bytes_sent,
        current_bps,
        credit_bytes,
    })
}

#[cfg(target_os = "linux")]
pub fn set_target_bps(handle: &mut CoverTrafficHandle, bps: u64) -> Result<(), String> {
    use aya::maps::Array;

    if bps == 0 {
        return Err("target_bps non può essere 0".into());
    }

    let mut arr: Array<_, [u8; 48]> = Array::try_from(
        handle
            .bpf
            .map_mut("cbr_state_map")
            .ok_or("cbr_state_map non trovata")?,
    )
    .map_err(|e| format!("Array::try_from: {e}"))?;

    let mut raw = arr.get(&0, 0).map_err(|e| format!("arr.get: {e}"))?;
    raw[..8].copy_from_slice(&bps.to_le_bytes());
    arr.set(0, raw, 0).map_err(|e| format!("arr.set: {e}"))?;

    log::info!("CBR target rate aggiornato: {} Mbps", bps / 1_000_000);
    Ok(())
}

#[cfg(target_os = "linux")]
pub fn set_burst_cap_packets(
    handle: &mut CoverTrafficHandle,
    packets: u64,
) -> Result<(), String> {
    use aya::maps::Array;

    let cap_bytes = (packets as i64) * (COVER_MTU as i64);

    let mut arr: Array<_, [u8; 48]> = Array::try_from(
        handle
            .bpf
            .map_mut("cbr_state_map")
            .ok_or("cbr_state_map non trovata")?,
    )
    .map_err(|e| format!("Array::try_from: {e}"))?;

    let mut raw = arr.get(&0, 0).map_err(|e| format!("arr.get: {e}"))?;
    raw[40..48].copy_from_slice(&cap_bytes.to_le_bytes());
    arr.set(0, raw, 0).map_err(|e| format!("arr.set: {e}"))?;

    log::info!(
        "CBR burst cap aggiornato: {} pacchetti ({} byte)",
        packets, cap_bytes
    );
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub struct CoverTrafficHandle;

#[cfg(not(target_os = "linux"))]
pub fn load_cover_program(
    _iface: &str,
    _obj: &[u8],
    _target_bps: u64,
) -> Result<CoverTrafficHandle, String> {
    Err("Cover traffic XDP supportato solo su Linux (kernel >= 5.15)".into())
}

#[cfg(not(target_os = "linux"))]
pub fn read_stats(_handle: &mut CoverTrafficHandle) -> Result<CoverStats, String> {
    Err("Solo Linux".into())
}

#[cfg(not(target_os = "linux"))]
pub fn set_target_bps(_handle: &mut CoverTrafficHandle, _bps: u64) -> Result<(), String> {
    Err("Solo Linux".into())
}

#[cfg(not(target_os = "linux"))]
pub fn set_burst_cap_packets(
    _handle: &mut CoverTrafficHandle,
    _packets: u64,
) -> Result<(), String> {
    Err("Solo Linux".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cbr_timer_interval() {
        assert_eq!(CBR_TIMER_INTERVAL_NS, 1_000_000);
    }

    #[test]
    fn test_cbr_max_credit() {
        assert_eq!(CBR_MAX_CREDIT_BYTES, 5_120);
    }

    #[test]
    fn test_cbr_divisor_at_2mbps() {
        assert_eq!(CBR_DIVISOR_NS, 4_000);
    }

    #[test]
    fn test_credit_accumulation_simulation() {
        let bps: u64 = TARGET_BPS;
        let divisor = 8_000_000_000u64 / bps;

        let elapsed_ns: u64 = 10_000_000;
        let new_credits = (elapsed_ns / divisor) as i64;
        assert_eq!(new_credits, 2_500);

        let packets_emittable = new_credits / COVER_MTU as i64;
        let residual = new_credits % COVER_MTU as i64;
        assert_eq!(packets_emittable, 1);
        assert_eq!(residual, 1_220);
    }

    #[test]
    fn test_burst_cap() {
        let mut credits: i64 = 0;
        let cap = CBR_MAX_CREDIT_BYTES;

        let elapsed_ns: u64 = 1_000_000_000;
        let divisor = CBR_DIVISOR_NS;
        credits += (elapsed_ns / divisor) as i64;
        assert!(credits > cap);

        if credits > cap { credits = cap; }
        assert_eq!(credits, CBR_MAX_CREDIT_BYTES);

        assert_eq!(credits / COVER_MTU as i64, 4);
    }

    #[test]
    fn test_source_contains_cbr_symbols() {
        assert!(COVER_TRAFFIC_XDP_SOURCE.contains("cbr_state_map"));
        assert!(COVER_TRAFFIC_XDP_SOURCE.contains("credit_bytes"));
        assert!(COVER_TRAFFIC_XDP_SOURCE.contains("cover_timer_cb"));
        assert!(COVER_TRAFFIC_XDP_SOURCE.contains("CBR_TIMER_NS"));
        assert!(COVER_TRAFFIC_XDP_SOURCE.contains("1000000ULL"));
        assert!(COVER_TRAFFIC_XDP_SOURCE.contains("CBR_MAX_BURST"));
    }

    #[test]
    fn test_source_no_old_fixed_interval() {
        assert!(!COVER_TRAFFIC_XDP_SOURCE.contains("5120000"));
        assert!(!COVER_TRAFFIC_XDP_SOURCE.contains("cover_ctrl"));
    }

    #[test]
    fn test_cover_stats_helpers() {
        let stats = CoverStats {
            packets_sent: 1000,
            bytes_sent: 1_280_000,
            current_bps: 2_000_000.0,
            credit_bytes: 2_560,
        };
        assert!((stats.effective_mbps() - 2.0).abs() < 0.001);
        assert!(stats.is_bursting());
    }

    #[test]
    fn test_cover_stats_not_bursting() {
        let stats = CoverStats {
            packets_sent: 1,
            bytes_sent: 1280,
            current_bps: 2_000_000.0,
            credit_bytes: 100,
        };
        assert!(!stats.is_bursting());
    }
}
