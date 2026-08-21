use std::collections::VecDeque;
use std::net::{SocketAddr, UdpSocket};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rand::Rng;

use crate::metrics::SharedMetrics;

const PROBE_MAGIC: [u8; 2] = [0xC3, 0x7A];
const PROBE_LEN: usize = 20;
const PROBE_INTERVAL_MS: u64 = 500;
const ALPHA: f64 = 0.3;
const BACKOFF_INIT_MS: u64 = 1_000;
const BACKOFF_MAX_MS: u64 = 60_000;
const RTT_WINDOW: usize = 128;
const INITIAL_SCORE: f64 = 0.5;
const DEAD_LOSS_THRESHOLD: f64 = 0.85;
const DEAD_FLOOR_SCORE: f64 = 0.001;

struct PathState {
    remote: SocketAddr,
    ewma_score: f64,
    rtt_samples: VecDeque<u64>,
    probe_sent: u64,
    probe_errors: u64,
    dead: bool,
    backoff_ms: u64,
    next_retry_at: Option<Instant>,
}

impl PathState {
    fn new(remote: SocketAddr) -> Self {
        Self {
            remote,
            ewma_score: INITIAL_SCORE,
            rtt_samples: VecDeque::with_capacity(RTT_WINDOW),
            probe_sent: 0,
            probe_errors: 0,
            dead: false,
            backoff_ms: BACKOFF_INIT_MS,
            next_retry_at: None,
        }
    }

    fn loss_rate(&self) -> f64 {
        if self.probe_sent == 0 {
            return 0.0;
        }
        (self.probe_errors as f64 / self.probe_sent as f64).min(1.0)
    }

    fn recompute_score(&mut self) {
        let reliability = 1.0 - self.loss_rate();
        let rtt_component = if self.rtt_samples.is_empty() {
            1.0
        } else {
            let mut sorted: Vec<u64> = self.rtt_samples.iter().copied().collect();
            sorted.sort_unstable();
            let median_us = sorted[sorted.len() / 2];
            (1.0 / (median_us as f64 / 1000.0).max(0.001)).min(10.0) / 10.0
        };
        let new_score = ALPHA * rtt_component + (1.0 - ALPHA) * reliability;
        self.ewma_score = 0.7 * self.ewma_score + 0.3 * new_score;
    }

    fn is_in_backoff(&self) -> bool {
        self.dead && self.next_retry_at.is_some_and(|t| Instant::now() < t)
    }

    fn effective_score(&self) -> f64 {
        if self.is_in_backoff() {
            0.0
        } else if self.dead {
            DEAD_FLOOR_SCORE
        } else {
            self.ewma_score.max(DEAD_FLOOR_SCORE)
        }
    }
}

pub struct PathSnapshot {
    pub idx: usize,
    pub remote: SocketAddr,
    pub score: f64,
    pub rtt_p50_us: Option<u64>,
    pub rtt_p95_us: Option<u64>,
    pub loss_rate: f64,
    pub dead: bool,
    pub backoff_ms: u64,
}

pub struct PathScheduler {
    state: Arc<Mutex<Vec<PathState>>>,
    metrics: SharedMetrics,
}

impl PathScheduler {
    pub fn new(remotes: &[SocketAddr], metrics: SharedMetrics) -> Self {
        let states: Vec<PathState> = remotes.iter().map(|&r| PathState::new(r)).collect();
        let state = Arc::new(Mutex::new(states));
        let sched = Self { state: state.clone(), metrics: metrics.clone() };

        let remotes_owned = remotes.to_vec();
        let probe_state = state;
        let probe_metrics = metrics;

        std::thread::spawn(move || {
            run_probe_loop(remotes_owned, probe_state, probe_metrics);
        });

        sched
    }

    pub fn assign_paths(&self, n_shares: usize) -> Vec<SocketAddr> {
        let states = self.state.lock().unwrap_or_else(|e| e.into_inner());

        if states.is_empty() {
            return Vec::new();
        }

        let scored: Vec<(f64, SocketAddr)> = states
            .iter()
            .map(|s| (s.effective_score(), s.remote))
            .collect();

        let total: f64 = scored.iter().map(|(s, _)| s).sum();

        if total <= 0.0 {
            return (0..n_shares)
                .map(|i| states[i % states.len()].remote)
                .collect();
        }

        let mut result = Vec::with_capacity(n_shares);
        let mut rng = rand::thread_rng();

        for _ in 0..n_shares {
            let pick = rng.gen::<f64>() * total;
            let mut cumulative = 0.0;
            let mut chosen = scored[0].1;
            for (score, remote) in &scored {
                cumulative += score;
                if pick <= cumulative {
                    chosen = *remote;
                    break;
                }
            }
            result.push(chosen);
        }

        result
    }

    pub fn snapshot(&self) -> Vec<PathSnapshot> {
        let states = self.state.lock().unwrap_or_else(|e| e.into_inner());
        states
            .iter()
            .enumerate()
            .map(|(i, s)| {
                let mut sorted: Vec<u64> = s.rtt_samples.iter().copied().collect();
                sorted.sort_unstable();
                let p50 = if sorted.is_empty() {
                    None
                } else {
                    Some(sorted[sorted.len() / 2])
                };
                let p95 = if sorted.is_empty() {
                    None
                } else {
                    Some(sorted[(sorted.len() * 95) / 100])
                };
                PathSnapshot {
                    idx: i,
                    remote: s.remote,
                    score: s.ewma_score,
                    rtt_p50_us: p50,
                    rtt_p95_us: p95,
                    loss_rate: s.loss_rate(),
                    dead: s.dead,
                    backoff_ms: s.backoff_ms,
                }
            })
            .collect()
    }
}

fn build_probe(path_idx: u8, seq: u64) -> [u8; PROBE_LEN] {
    let mut buf = [0u8; PROBE_LEN];
    buf[0..2].copy_from_slice(&PROBE_MAGIC);
    buf[2] = path_idx;
    buf[3..11].copy_from_slice(&seq.to_le_bytes());
    let ns = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    buf[11..19].copy_from_slice(&ns.to_le_bytes());
    buf
}

fn is_hard_error(e: &std::io::Error) -> bool {
    e.raw_os_error().is_some_and(|code| {
        matches!(
            code,
            libc::ECONNREFUSED | libc::ENETUNREACH | libc::EHOSTUNREACH | libc::EADDRNOTAVAIL
        )
    })
}

fn run_probe_loop(
    remotes: Vec<SocketAddr>,
    state: Arc<Mutex<Vec<PathState>>>,
    metrics: SharedMetrics,
) {
    let mut seq: u64 = 0;

    loop {
        std::thread::sleep(Duration::from_millis(PROBE_INTERVAL_MS));

        for (idx, &remote) in remotes.iter().enumerate() {
            let probe = build_probe(idx as u8, seq);

            let sock = match UdpSocket::bind("0.0.0.0:0") {
                Ok(s) => s,
                Err(_) => continue,
            };

            let _ = sock.set_read_timeout(Some(Duration::from_millis(50)));

            let send_start = Instant::now();
            let send_result = sock.send_to(&probe, remote);
            let send_us = send_start.elapsed().as_micros() as u64;

            let mut locked = state.lock().unwrap_or_else(|e| e.into_inner());
            let path = &mut locked[idx];
            path.probe_sent += 1;

            match send_result {
                Err(ref e) if is_hard_error(e) => {
                    path.probe_errors += 1;
                    let was_dead = path.dead;
                    if path.loss_rate() > DEAD_LOSS_THRESHOLD {
                        path.dead = true;
                        path.backoff_ms = (path.backoff_ms * 2).min(BACKOFF_MAX_MS);
                        path.next_retry_at =
                            Some(Instant::now() + Duration::from_millis(path.backoff_ms));
                    }
                    if !was_dead && path.dead {
                        metrics.on_path_state_change(idx, false);
                        log::warn!(
                            "scheduler: path {idx} ({remote}) marked dead (loss {:.0}%)",
                            path.loss_rate() * 100.0
                        );
                    }
                }
                Ok(_) => {
                    if send_us > 0 {
                        if path.rtt_samples.len() >= RTT_WINDOW {
                            path.rtt_samples.pop_front();
                        }
                        path.rtt_samples.push_back(send_us);
                    }
                    let was_dead = path.dead;
                    if was_dead {
                        path.dead = false;
                        path.backoff_ms = BACKOFF_INIT_MS;
                        path.next_retry_at = None;
                        metrics.on_path_state_change(idx, true);
                        log::info!("scheduler: path {idx} ({remote}) recovered");
                    }
                }
                _ => {}
            }

            path.recompute_score();
            seq = seq.wrapping_add(1);
        }
    }
}
