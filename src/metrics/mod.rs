use std::collections::VecDeque;
use std::sync::{Arc, RwLock};
use std::time::Instant;

#[derive(Clone, Debug)]
pub enum MetricEvent {
    FragmentSent { path_idx: usize, bytes: usize },
    FragmentRecv { session_short: [u8; 4], x: u8 },
    Reconstructed { session_short: [u8; 4], bytes: usize },
    KeyRatchet { step: u64 },
    ReplayDetected { seq: u64 },
    PathDown { idx: usize },
    PathUp { idx: usize },
    KemHandshake { latency_ms: u64 },
    Error { module: &'static str, msg: String },
    FileProgress { percent: f32 },
}

#[derive(Clone, Debug)]
pub struct PathMetrics {
    pub idx: usize,
    pub active: bool,
    pub bytes_sent: u64,
    pub bytes_recv: u64,
    pub packets_sent: u64,
    pub packets_recv: u64,
}

impl PathMetrics {
    fn new(idx: usize) -> Self {
        Self { idx, active: true, bytes_sent: 0, bytes_recv: 0, packets_sent: 0, packets_recv: 0 }
    }
}

#[derive(Clone, Debug)]
pub struct FileTransferProgress {
    pub bytes_sent: usize,
    pub total_bytes: usize,
    pub started_at: Instant,
}

impl FileTransferProgress {
    pub fn percent(&self) -> f32 {
        if self.total_bytes == 0 {
            return 0.0;
        }
        (self.bytes_sent as f32 / self.total_bytes as f32) * 100.0
    }

    pub fn eta_secs(&self) -> f64 {
        if self.bytes_sent == 0 {
            return f64::INFINITY;
        }
        let elapsed = self.started_at.elapsed().as_secs_f64();
        let rate = self.bytes_sent as f64 / elapsed;
        if rate == 0.0 {
            return f64::INFINITY;
        }
        let remaining = self.total_bytes.saturating_sub(self.bytes_sent) as f64;
        remaining / rate
    }
}

const ERROR_CAP: usize = 100;
const EVENT_CAP: usize = 200;

#[derive(Clone, Debug)]
pub struct MetricsState {
    pub paths: Vec<PathMetrics>,
    pub session_count: usize,
    pub fragments_sent: u64,
    pub fragments_recv: u64,
    pub reconstructed_count: u64,
    pub ratchet_step: u64,
    pub replay_detected_count: u64,
    pub last_bps: f64,
    pub last_ratchet_packet: u64,
    pub errors: VecDeque<(Instant, String)>,
    pub events: VecDeque<MetricEvent>,
    pub file_transfer: Option<FileTransferProgress>,
}

impl MetricsState {
    fn new(num_paths: usize) -> Self {
        Self {
            paths: (0..num_paths).map(PathMetrics::new).collect(),
            session_count: 0,
            fragments_sent: 0,
            fragments_recv: 0,
            reconstructed_count: 0,
            ratchet_step: 0,
            replay_detected_count: 0,
            last_bps: 0.0,
            last_ratchet_packet: 0,
            errors: VecDeque::new(),
            events: VecDeque::new(),
            file_transfer: None,
        }
    }

    fn push_event(&mut self, ev: MetricEvent) {
        if self.events.len() >= EVENT_CAP {
            self.events.pop_front();
        }
        self.events.push_back(ev);
    }

    fn push_error(&mut self, msg: String) {
        if self.errors.len() >= ERROR_CAP {
            self.errors.pop_front();
        }
        self.errors.push_back((Instant::now(), msg));
    }
}

pub trait MetricsHook: Send + Sync {
    fn as_any(&self) -> Option<&dyn std::any::Any> { None }
    fn on_fragment_sent(&self, _path_idx: usize, _bytes: usize) {}
    fn on_fragment_recv(&self, _session_id: [u8; 16], _x: u8, _bytes: usize) {}
    fn on_fragment_reconstructed(&self, _session_id: [u8; 16], _plaintext_bytes: usize) {}
    fn on_key_ratchet(&self, _step: u64, _packet_count: u64) {}
    fn on_replay_detected(&self, _seq: u64, _session_id: [u8; 16]) {}
    fn on_path_state_change(&self, _path_idx: usize, _active: bool) {}
    fn on_kem_handshake_complete(&self, _latency_ms: u64) {}
    fn on_cbr_tick(&self, _credit_bytes: i64, _packets_sent: u64, _current_bps: f64) {}
    fn on_error(&self, _module: &'static str, _msg: String) {}
    fn on_file_transfer_progress(&self, _bytes_sent: usize, _total_bytes: usize) {}
}

pub struct NoopMetrics;

impl MetricsHook for NoopMetrics {}

pub struct DashboardMetrics {
    pub state: Arc<RwLock<MetricsState>>,
}

impl DashboardMetrics {
    pub fn new(num_paths: usize) -> Self {
        Self { state: Arc::new(RwLock::new(MetricsState::new(num_paths))) }
    }

    pub fn snapshot(&self) -> MetricsState {
        self.state.read().unwrap_or_else(|e| e.into_inner()).clone()
    }
}

impl MetricsHook for DashboardMetrics {
    fn as_any(&self) -> Option<&dyn std::any::Any> { Some(self) }

    fn on_fragment_sent(&self, path_idx: usize, bytes: usize) {
        let mut s = self.state.write().unwrap_or_else(|e| e.into_inner());
        s.fragments_sent += 1;
        if let Some(p) = s.paths.get_mut(path_idx) {
            p.bytes_sent += bytes as u64;
            p.packets_sent += 1;
        }
        s.push_event(MetricEvent::FragmentSent { path_idx, bytes });
    }

    fn on_fragment_recv(&self, session_id: [u8; 16], x: u8, bytes: usize) {
        let mut s = self.state.write().unwrap_or_else(|e| e.into_inner());
        s.fragments_recv += 1;
        let session_short = [session_id[0], session_id[1], session_id[2], session_id[3]];
        if let Some(p) = s.paths.first_mut() {
            p.bytes_recv += bytes as u64;
            p.packets_recv += 1;
        }
        s.push_event(MetricEvent::FragmentRecv { session_short, x });
    }

    fn on_fragment_reconstructed(&self, session_id: [u8; 16], plaintext_bytes: usize) {
        let mut s = self.state.write().unwrap_or_else(|e| e.into_inner());
        s.reconstructed_count += 1;
        let session_short = [session_id[0], session_id[1], session_id[2], session_id[3]];
        s.push_event(MetricEvent::Reconstructed { session_short, bytes: plaintext_bytes });
    }

    fn on_key_ratchet(&self, step: u64, packet_count: u64) {
        let mut s = self.state.write().unwrap_or_else(|e| e.into_inner());
        s.ratchet_step = step;
        s.last_ratchet_packet = packet_count;
        s.push_event(MetricEvent::KeyRatchet { step });
    }

    fn on_replay_detected(&self, seq: u64, _session_id: [u8; 16]) {
        let mut s = self.state.write().unwrap_or_else(|e| e.into_inner());
        s.replay_detected_count += 1;
        s.push_event(MetricEvent::ReplayDetected { seq });
    }

    fn on_path_state_change(&self, path_idx: usize, active: bool) {
        let mut s = self.state.write().unwrap_or_else(|e| e.into_inner());
        if let Some(p) = s.paths.get_mut(path_idx) {
            p.active = active;
        }
        let ev = if active {
            MetricEvent::PathUp { idx: path_idx }
        } else {
            MetricEvent::PathDown { idx: path_idx }
        };
        s.push_event(ev);
    }

    fn on_kem_handshake_complete(&self, latency_ms: u64) {
        let mut s = self.state.write().unwrap_or_else(|e| e.into_inner());
        s.session_count += 1;
        s.push_event(MetricEvent::KemHandshake { latency_ms });
    }

    fn on_cbr_tick(&self, _credit_bytes: i64, packets_sent: u64, current_bps: f64) {
        let mut s = self.state.write().unwrap_or_else(|e| e.into_inner());
        s.last_bps = current_bps;
        let _ = packets_sent;
    }

    fn on_error(&self, module: &'static str, msg: String) {
        let mut s = self.state.write().unwrap_or_else(|e| e.into_inner());
        s.push_error(format!("[{module}] {msg}"));
        s.push_event(MetricEvent::Error { module, msg });
    }

    fn on_file_transfer_progress(&self, bytes_sent: usize, total_bytes: usize) {
        let mut s = self.state.write().unwrap_or_else(|e| e.into_inner());
        let ft = s.file_transfer.get_or_insert_with(|| FileTransferProgress {
            bytes_sent: 0,
            total_bytes,
            started_at: Instant::now(),
        });
        ft.bytes_sent = bytes_sent;
        ft.total_bytes = total_bytes;
        let percent = ft.percent();
        s.push_event(MetricEvent::FileProgress { percent });
    }
}

pub type SharedMetrics = Arc<dyn MetricsHook>;

pub fn noop_metrics() -> SharedMetrics {
    Arc::new(NoopMetrics)
}

pub fn dashboard_metrics(num_paths: usize) -> SharedMetrics {
    Arc::new(DashboardMetrics::new(num_paths))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_session(b: u8) -> [u8; 16] {
        [b; 16]
    }

    #[test]
    fn fragment_sent_updates_counters() {
        let m = DashboardMetrics::new(3);
        m.on_fragment_sent(1, 512);
        m.on_fragment_sent(1, 256);
        let s = m.snapshot();
        assert_eq!(s.fragments_sent, 2);
        assert_eq!(s.paths[1].bytes_sent, 768);
        assert_eq!(s.paths[1].packets_sent, 2);
        assert_eq!(s.events.len(), 2);
    }

    #[test]
    fn fragment_recv_updates_counters() {
        let m = DashboardMetrics::new(2);
        m.on_fragment_recv(make_session(0xAB), 3, 400);
        let s = m.snapshot();
        assert_eq!(s.fragments_recv, 1);
        assert_eq!(s.paths[0].bytes_recv, 400);
        matches!(s.events.back().unwrap(), MetricEvent::FragmentRecv { x: 3, .. });
    }

    #[test]
    fn reconstruction_increments_count() {
        let m = DashboardMetrics::new(1);
        m.on_fragment_reconstructed(make_session(1), 1024);
        m.on_fragment_reconstructed(make_session(2), 512);
        assert_eq!(m.snapshot().reconstructed_count, 2);
    }

    #[test]
    fn key_ratchet_updates_step() {
        let m = DashboardMetrics::new(1);
        m.on_key_ratchet(7, 1000);
        let s = m.snapshot();
        assert_eq!(s.ratchet_step, 7);
        assert_eq!(s.last_ratchet_packet, 1000);
    }

    #[test]
    fn replay_detected_increments() {
        let m = DashboardMetrics::new(1);
        m.on_replay_detected(99, make_session(0));
        m.on_replay_detected(100, make_session(0));
        assert_eq!(m.snapshot().replay_detected_count, 2);
    }

    #[test]
    fn path_state_change_toggles_active() {
        let m = DashboardMetrics::new(4);
        assert!(m.snapshot().paths[2].active);
        m.on_path_state_change(2, false);
        assert!(!m.snapshot().paths[2].active);
        m.on_path_state_change(2, true);
        assert!(m.snapshot().paths[2].active);
    }

    #[test]
    fn kem_handshake_increments_session_count() {
        let m = DashboardMetrics::new(1);
        m.on_kem_handshake_complete(42);
        m.on_kem_handshake_complete(17);
        assert_eq!(m.snapshot().session_count, 2);
    }

    #[test]
    fn cbr_tick_updates_bps() {
        let m = DashboardMetrics::new(1);
        m.on_cbr_tick(8192, 50, 1_000_000.0);
        assert!((m.snapshot().last_bps - 1_000_000.0).abs() < f64::EPSILON);
    }

    #[test]
    fn error_appended_to_both_queues() {
        let m = DashboardMetrics::new(1);
        m.on_error("crypto", "bad tag".to_string());
        let s = m.snapshot();
        assert_eq!(s.errors.len(), 1);
        assert!(s.errors[0].1.contains("bad tag"));
        matches!(s.events.back().unwrap(), MetricEvent::Error { .. });
    }

    #[test]
    fn errors_cap_at_100() {
        let m = DashboardMetrics::new(1);
        for i in 0..120u32 {
            m.on_error("mod", format!("err {i}"));
        }
        assert_eq!(m.snapshot().errors.len(), 100);
    }

    #[test]
    fn events_cap_at_200() {
        let m = DashboardMetrics::new(1);
        for _ in 0..250 {
            m.on_fragment_sent(0, 1);
        }
        assert_eq!(m.snapshot().events.len(), 200);
    }

    #[test]
    fn file_transfer_progress_recorded() {
        let m = DashboardMetrics::new(1);
        m.on_file_transfer_progress(500, 1000);
        let s = m.snapshot();
        let ft = s.file_transfer.unwrap();
        assert_eq!(ft.bytes_sent, 500);
        assert_eq!(ft.total_bytes, 1000);
        assert!((ft.percent() - 50.0).abs() < 0.01);
    }

    #[test]
    fn file_transfer_eta_infinite_at_zero_sent() {
        let ft = FileTransferProgress {
            bytes_sent: 0,
            total_bytes: 1000,
            started_at: Instant::now(),
        };
        assert_eq!(ft.eta_secs(), f64::INFINITY);
    }

    #[test]
    fn noop_metrics_compiles_and_runs() {
        let m = noop_metrics();
        m.on_fragment_sent(0, 100);
        m.on_error("x", "y".into());
    }

    #[test]
    fn dashboard_metrics_factory() {
        let m = dashboard_metrics(2);
        m.on_fragment_sent(0, 64);
    }
}
