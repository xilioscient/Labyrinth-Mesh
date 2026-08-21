use std::collections::VecDeque;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use axum::{
    extract::{Path, Request, State},
    http::{header, StatusCode},
    middleware::Next,
    response::{
        sse::{Event, KeepAlive, Sse},
        IntoResponse, Response,
    },
    routing::{get, post},
    Json, Router,
};
use futures_util::stream::{self, Stream};
use serde::Serialize;
use thiserror::Error;
use tower_http::cors::{AllowOrigin, CorsLayer};

use crate::metrics::{DashboardMetrics, MetricsState, SharedMetrics};
use crate::phase4::MultiPathController;

#[derive(Error, Debug)]
pub enum ManagementError {
    #[error("bind failed: {0}")]
    Bind(#[from] std::io::Error),
    #[error("metrics cast failed: SharedMetrics is not a DashboardMetrics")]
    MetricsCastFailed,
}

const RTT_CAP: usize = 1000;
const RTT_MIN_SAMPLES: usize = 20;

pub struct RttTracker {
    samples: VecDeque<Duration>,
}

impl RttTracker {
    pub fn new() -> Self {
        Self { samples: VecDeque::with_capacity(RTT_CAP) }
    }

    pub fn record(&mut self, rtt: Duration) {
        if self.samples.len() >= RTT_CAP {
            self.samples.pop_front();
        }
        self.samples.push_back(rtt);
    }

    pub fn p95(&mut self) -> Option<Duration> {
        let n = self.samples.len();
        if n < RTT_MIN_SAMPLES {
            return None;
        }
        let k = (n * 95) / 100;
        let slice = self.samples.make_contiguous();
        let (_, pivot, _) = slice.select_nth_unstable_by(k, |a, b| a.cmp(b));
        Some(*pivot)
    }
}

impl Default for RttTracker {
    fn default() -> Self { Self::new() }
}

pub struct ManagementServer {
    pub metrics: SharedMetrics,
    pub bind_addr: SocketAddr,
    pub controller: Arc<Mutex<MultiPathController>>,
}

impl ManagementServer {
    pub fn new(
        metrics: SharedMetrics,
        bind_addr: SocketAddr,
        controller: Arc<Mutex<MultiPathController>>,
    ) -> Self {
        Self { metrics, bind_addr, controller }
    }

    pub async fn start(self) -> Result<(), ManagementError> {
        let metrics_state: Arc<RwLock<MetricsState>> = self
            .metrics
            .as_any()
            .and_then(|any| any.downcast_ref::<DashboardMetrics>())
            .ok_or(ManagementError::MetricsCastFailed)?
            .state
            .clone();

        let auth_token = std::env::var("LABYRINTH_MGMT_TOKEN")
            .ok()
            .filter(|s| !s.is_empty());
        if auth_token.is_some() {
            log::info!("management plane: Bearer token auth enabled");
        }

        let state = AppState {
            metrics_state,
            controller: self.controller,
            rtt: Arc::new(Mutex::new(RttTracker::new())),
            log_buffer: crate::log_capture::global_buffer(),
            auth_token,
        };

        let app = build_router(state);
        let listener = tokio::net::TcpListener::bind(self.bind_addr)
            .await
            .map_err(ManagementError::Bind)?;

        log::info!("management plane listening on {}", self.bind_addr);

        tokio::spawn(async move {
            if let Err(e) = axum::serve(listener, app).await {
                log::error!("management plane server error: {e}");
            }
        });

        Ok(())
    }
}

pub fn mgmt_addr() -> SocketAddr {
    std::env::var("DMPOT_MGMT_ADDR")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| "127.0.0.1:9090".parse().unwrap())
}

#[derive(Clone)]
struct AppState {
    metrics_state: Arc<RwLock<MetricsState>>,
    controller: Arc<Mutex<MultiPathController>>,
    rtt: Arc<Mutex<RttTracker>>,
    log_buffer: Option<crate::log_capture::LogBuffer>,
    auth_token: Option<String>,
}

fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(hi), Some(lo)) = (
                char::from(bytes[i + 1]).to_digit(16),
                char::from(bytes[i + 2]).to_digit(16),
            ) {
                out.push(char::from((hi * 16 + lo) as u8));
                i += 3;
                continue;
            }
        } else if bytes[i] == b'+' {
            out.push(' ');
            i += 1;
            continue;
        }
        out.push(char::from(bytes[i]));
        i += 1;
    }
    out
}

async fn require_auth(State(state): State<AppState>, req: Request, next: Next) -> Response {
    if state.auth_token.is_none() || req.uri().path() == "/health" {
        return next.run(req).await;
    }
    let expected = state.auth_token.as_deref().unwrap_or("");
    let from_header = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(str::to_owned);
    let from_query = req.uri().query().and_then(|q| {
        q.split('&')
            .find(|p| p.starts_with("token="))
            .map(|p| percent_decode(p.trim_start_matches("token=")))
    });
    let provided_owned = from_header.or(from_query);
    let provided = provided_owned.as_deref();

    let ok = provided
        .map(|tok| {
            tok.len() == expected.len()
                && tok
                    .bytes()
                    .zip(expected.bytes())
                    .fold(0u8, |acc, (a, b)| acc | (a ^ b))
                    == 0
        })
        .unwrap_or(false);

    if ok {
        next.run(req).await
    } else {
        (
            StatusCode::UNAUTHORIZED,
            [(header::WWW_AUTHENTICATE, "Bearer")],
            Json(serde_json::json!({"error": "unauthorized"})),
        )
            .into_response()
    }
}

fn build_router(state: AppState) -> Router<()> {
    Router::new()
        .route("/health", get(health))
        .route("/metrics", get(metrics_summary))
        .route("/metrics/paths", get(metrics_paths))
        .route("/metrics/rtt/p95", get(rtt_p95))
        .route("/metrics/stream", get(metrics_stream))
        .route("/metrics/prometheus", get(prometheus_metrics))
        .route("/logs", get(server_logs))
        .route("/path/:idx/deactivate", post(deactivate))
        .route("/path/:idx/activate", post(activate))
        .layer(axum::middleware::from_fn_with_state(state.clone(), require_auth))
        .layer(
            CorsLayer::new()
                .allow_origin(AllowOrigin::list([
                    "http://localhost:8080".parse().unwrap(),
                    "http://127.0.0.1:8080".parse().unwrap(),
                    "http://localhost:9090".parse().unwrap(),
                    "http://127.0.0.1:9090".parse().unwrap(),
                ]))
                .allow_methods([
                    axum::http::Method::GET,
                    axum::http::Method::POST,
                ])
                .allow_headers([
                    header::AUTHORIZATION,
                    header::CONTENT_TYPE,
                ]),
        )
        .with_state(state)
}

#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
    paths_active: usize,
    paths_total: usize,
}

#[derive(Serialize)]
struct MetricsSummaryResponse {
    session_count: usize,
    fragments_sent: u64,
    fragments_recv: u64,
    reconstructed_count: u64,
    ratchet_step: u64,
    replay_detected_count: u64,
    last_bps: f64,
    last_ratchet_packet: u64,
    paths: Vec<PathMetricsDto>,
}

#[derive(Serialize)]
struct PathMetricsDto {
    idx: usize,
    active: bool,
    bytes_sent: u64,
    bytes_recv: u64,
    packets_sent: u64,
    packets_recv: u64,
}

impl From<&crate::metrics::PathMetrics> for PathMetricsDto {
    fn from(p: &crate::metrics::PathMetrics) -> Self {
        Self {
            idx: p.idx,
            active: p.active,
            bytes_sent: p.bytes_sent,
            bytes_recv: p.bytes_recv,
            packets_sent: p.packets_sent,
            packets_recv: p.packets_recv,
        }
    }
}

#[derive(Serialize)]
struct OkResponse {
    ok: bool,
}

#[derive(Serialize)]
struct RttP95Response {
    p95_ms: Option<f64>,
}

async fn health(State(s): State<AppState>) -> impl IntoResponse {
    let snap = s.metrics_state.read().unwrap_or_else(|e| e.into_inner());
    let total = snap.paths.len();
    let active = snap.paths.iter().filter(|p| p.active).count();
    let status = if active == total && total > 0 {
        "ok"
    } else if active > 0 {
        "degraded"
    } else {
        "critical"
    };
    Json(HealthResponse { status, paths_active: active, paths_total: total })
}

fn snapshot_to_summary(snap: &MetricsState) -> MetricsSummaryResponse {
    MetricsSummaryResponse {
        session_count: snap.session_count,
        fragments_sent: snap.fragments_sent,
        fragments_recv: snap.fragments_recv,
        reconstructed_count: snap.reconstructed_count,
        ratchet_step: snap.ratchet_step,
        replay_detected_count: snap.replay_detected_count,
        last_bps: snap.last_bps,
        last_ratchet_packet: snap.last_ratchet_packet,
        paths: snap.paths.iter().map(PathMetricsDto::from).collect(),
    }
}

async fn metrics_summary(State(s): State<AppState>) -> impl IntoResponse {
    let snap = s.metrics_state.read().unwrap_or_else(|e| e.into_inner());
    Json(snapshot_to_summary(&snap))
}

async fn metrics_stream(
    State(s): State<AppState>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let ms = s.metrics_state;
    let stream = stream::unfold(ms, |ms| async move {
        tokio::time::sleep(Duration::from_secs(1)).await;
        let event = {
            let snap = ms.read().unwrap_or_else(|e| e.into_inner());
            let json = serde_json::to_string(&snapshot_to_summary(&snap)).unwrap_or_default();
            Ok::<_, Infallible>(Event::default().data(json))
        };
        Some((event, ms))
    });
    Sse::new(stream).keep_alive(KeepAlive::new().interval(Duration::from_secs(30)).text("ping"))
}

async fn metrics_paths(State(s): State<AppState>) -> impl IntoResponse {
    let snap = s.metrics_state.read().unwrap_or_else(|e| e.into_inner());
    let paths: Vec<PathMetricsDto> = snap.paths.iter().map(PathMetricsDto::from).collect();
    Json(paths)
}

async fn prometheus_metrics(State(s): State<AppState>) -> impl IntoResponse {
    let snap = s.metrics_state.read().unwrap_or_else(|e| e.into_inner());
    let mut out = String::with_capacity(1024);

    macro_rules! metric {
        ($name:literal, $type:literal, $help:literal, $value:expr) => {
            out.push_str(concat!("# HELP ", $name, " ", $help, "\n"));
            out.push_str(concat!("# TYPE ", $name, " ", $type, "\n"));
            out.push_str(&format!(concat!($name, " {}\n\n"), $value));
        };
    }

    metric!(
        "labyrinth_fragments_sent_total", "counter",
        "Total UDP fragments sent across all paths",
        snap.fragments_sent
    );
    metric!(
        "labyrinth_fragments_received_total", "counter",
        "Total UDP fragments received",
        snap.fragments_recv
    );
    metric!(
        "labyrinth_reconstructed_total", "counter",
        "Total payloads successfully reconstructed from shares",
        snap.reconstructed_count
    );
    metric!(
        "labyrinth_replay_detected_total", "counter",
        "Total replay attacks detected and dropped",
        snap.replay_detected_count
    );
    metric!(
        "labyrinth_ratchet_step", "gauge",
        "Current key ratchet step",
        snap.ratchet_step
    );
    metric!(
        "labyrinth_session_count", "gauge",
        "Number of active sessions",
        snap.session_count
    );
    metric!(
        "labyrinth_throughput_bps", "gauge",
        "Current throughput in bits per second",
        snap.last_bps
    );

    for path in &snap.paths {
        let labels = format!("{{path=\"{}\"}}", path.idx);
        let active = if path.active { 1u8 } else { 0u8 };
        out.push_str(&format!(
            "# HELP labyrinth_path_active Whether the path is active (1) or not (0)\n\
             # TYPE labyrinth_path_active gauge\n\
             labyrinth_path_active{labels} {active}\n\n"
        ));
        out.push_str(&format!(
            "# TYPE labyrinth_path_bytes_sent_total counter\n\
             labyrinth_path_bytes_sent_total{labels} {}\n\n",
            path.bytes_sent
        ));
        out.push_str(&format!(
            "# TYPE labyrinth_path_bytes_received_total counter\n\
             labyrinth_path_bytes_received_total{labels} {}\n\n",
            path.bytes_recv
        ));
    }

    ([(header::CONTENT_TYPE, "text/plain; version=0.0.4; charset=utf-8")], out)
}

async fn server_logs(State(s): State<AppState>) -> impl IntoResponse {
    let entries: Vec<crate::log_capture::LogEntry> = s
        .log_buffer
        .map(|buf| buf.lock().unwrap_or_else(|e| e.into_inner()).iter().cloned().collect())
        .unwrap_or_default();
    Json(entries)
}

async fn rtt_p95(State(s): State<AppState>) -> impl IntoResponse {
    let p95_ms = s
        .rtt
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .p95()
        .map(|d| d.as_secs_f64() * 1000.0);
    Json(RttP95Response { p95_ms })
}

async fn deactivate(
    State(s): State<AppState>,
    Path(idx): Path<usize>,
) -> impl IntoResponse {
    let mut ctrl = s.controller.lock().unwrap_or_else(|e| e.into_inner());
    if idx >= ctrl.path_count() {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "path index out of range"})),
        )
            .into_response();
    }
    ctrl.deactivate_path(idx);
    (StatusCode::OK, Json(OkResponse { ok: true })).into_response()
}

async fn activate(
    State(s): State<AppState>,
    Path(idx): Path<usize>,
) -> impl IntoResponse {
    let mut ctrl = s.controller.lock().unwrap_or_else(|e| e.into_inner());
    if idx >= ctrl.path_count() {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "path index out of range"})),
        )
            .into_response();
    }
    ctrl.activate_path(idx);
    (StatusCode::OK, Json(OkResponse { ok: true })).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metrics::dashboard_metrics;
    use crate::phase4::PathInfo;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    fn make_state(num_paths: usize) -> AppState {
        let dm = {
            let shared = dashboard_metrics(num_paths);
            let any = shared.as_any().unwrap();
            let dm_ref = any.downcast_ref::<DashboardMetrics>().unwrap();
            dm_ref.state.clone()
        };
        let paths: Vec<PathInfo> = (0..num_paths)
            .map(|_| PathInfo {
                local_addr: "127.0.0.1:0".parse().unwrap(),
                remote_addr: "127.0.0.1:19999".parse().unwrap(),
                weight: 1,
                active: true,
            })
            .collect();
        let ctrl = MultiPathController::new(paths).expect("bind paths");
        AppState {
            metrics_state: dm,
            controller: Arc::new(Mutex::new(ctrl)),
            rtt: Arc::new(Mutex::new(RttTracker::new())),
            log_buffer: None,
            auth_token: None,
        }
    }

    #[tokio::test]
    async fn health_all_active_returns_ok() {
        let app = build_router(make_state(3));
        let resp = app
            .oneshot(Request::get("/health").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(json["status"], "ok");
        assert_eq!(json["paths_active"], 3);
        assert_eq!(json["paths_total"], 3);
    }

    #[tokio::test]
    async fn health_degraded_when_one_path_down() {
        let state = make_state(2);
        state.metrics_state.write().unwrap().paths[0].active = false;
        let app = build_router(state);
        let resp = app
            .oneshot(Request::get("/health").body(Body::empty()).unwrap())
            .await
            .unwrap();
        let bytes = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(json["status"], "degraded");
    }

    #[tokio::test]
    async fn health_critical_when_no_paths() {
        let state = make_state(1);
        state.metrics_state.write().unwrap().paths[0].active = false;
        let app = build_router(state);
        let resp = app
            .oneshot(Request::get("/health").body(Body::empty()).unwrap())
            .await
            .unwrap();
        let bytes = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(json["status"], "critical");
    }

    #[tokio::test]
    async fn metrics_summary_excludes_events_and_errors() {
        let app = build_router(make_state(1));
        let resp = app
            .oneshot(Request::get("/metrics").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert!(json.get("events").is_none());
        assert!(json.get("errors").is_none());
        assert!(json["fragments_sent"].is_number());
    }

    #[tokio::test]
    async fn prometheus_endpoint_returns_text() {
        let app = build_router(make_state(2));
        let resp = app
            .oneshot(Request::get("/metrics/prometheus").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let ct = resp.headers().get(header::CONTENT_TYPE).unwrap().to_str().unwrap();
        assert!(ct.contains("text/plain"));
        let bytes = axum::body::to_bytes(resp.into_body(), 8192).await.unwrap();
        let body = std::str::from_utf8(&bytes).unwrap();
        assert!(body.contains("labyrinth_fragments_sent_total"));
        assert!(body.contains("labyrinth_throughput_bps"));
        assert!(body.contains("labyrinth_path_active{path=\"0\"}"));
    }

    #[tokio::test]
    async fn auth_health_is_always_public() {
        let mut state = make_state(1);
        state.auth_token = Some("secret-token".into());
        let app = build_router(state);
        let resp = app
            .oneshot(Request::get("/health").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn auth_metrics_requires_token() {
        let mut state = make_state(1);
        state.auth_token = Some("secret-token".into());
        let app = build_router(state);
        let resp = app
            .oneshot(Request::get("/metrics").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn auth_metrics_accepts_valid_token() {
        let mut state = make_state(1);
        state.auth_token = Some("secret-token".into());
        let app = build_router(state);
        let resp = app
            .oneshot(
                Request::get("/metrics")
                    .header("Authorization", "Bearer secret-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn metrics_paths_returns_vec() {
        let app = build_router(make_state(4));
        let resp = app
            .oneshot(Request::get("/metrics/paths").body(Body::empty()).unwrap())
            .await
            .unwrap();
        let bytes = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert!(json.is_array());
        assert_eq!(json.as_array().unwrap().len(), 4);
    }

    #[tokio::test]
    async fn deactivate_valid_path() {
        let app = build_router(make_state(2));
        let resp = app
            .oneshot(Request::post("/path/0/deactivate").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(resp.into_body(), 256).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(json["ok"], true);
    }

    #[tokio::test]
    async fn deactivate_out_of_range_returns_404() {
        let app = build_router(make_state(2));
        let resp = app
            .oneshot(Request::post("/path/99/deactivate").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn activate_path_after_deactivate() {
        let app = build_router(make_state(2));
        let _ = app
            .clone()
            .oneshot(Request::post("/path/1/deactivate").body(Body::empty()).unwrap())
            .await
            .unwrap();
        let resp = app
            .oneshot(Request::post("/path/1/activate").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(resp.into_body(), 256).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(json["ok"], true);
    }

    #[tokio::test]
    async fn rtt_p95_null_when_insufficient_samples() {
        let app = build_router(make_state(1));
        let resp = app
            .oneshot(Request::get("/metrics/rtt/p95").body(Body::empty()).unwrap())
            .await
            .unwrap();
        let bytes = axum::body::to_bytes(resp.into_body(), 256).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert!(json["p95_ms"].is_null());
    }

    #[tokio::test]
    async fn rtt_p95_returns_value_after_enough_samples() {
        let state = make_state(1);
        {
            let mut rtt = state.rtt.lock().unwrap();
            for ms in 1u64..=50 {
                rtt.record(Duration::from_millis(ms));
            }
        }
        let app = build_router(state);
        let resp = app
            .oneshot(Request::get("/metrics/rtt/p95").body(Body::empty()).unwrap())
            .await
            .unwrap();
        let bytes = axum::body::to_bytes(resp.into_body(), 256).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert!(!json["p95_ms"].is_null());
        let p95 = json["p95_ms"].as_f64().unwrap();
        assert!((40.0..=50.0).contains(&p95), "p95 = {p95}");
    }

    #[test]
    fn rtt_tracker_cap() {
        let mut t = RttTracker::new();
        for ms in 0..1200u64 { t.record(Duration::from_millis(ms)); }
        assert_eq!(t.samples.len(), RTT_CAP);
    }

    #[test]
    fn rtt_tracker_none_below_min_samples() {
        let mut t = RttTracker::new();
        for ms in 0..RTT_MIN_SAMPLES as u64 - 1 { t.record(Duration::from_millis(ms)); }
        assert!(t.p95().is_none());
    }

    #[test]
    fn metrics_cast_failed_on_noop() {
        use crate::metrics::noop_metrics;
        let noop = noop_metrics();
        assert!(noop.as_any().and_then(|a| a.downcast_ref::<DashboardMetrics>()).is_none());
    }
}
