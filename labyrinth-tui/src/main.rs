use std::collections::VecDeque;
use std::io;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use clap::Parser;
use crossterm::{
    event::{self, Event, KeyCode, KeyModifiers},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Layout, Rect},
    style::{Color, Style},
    symbols,
    text::{Line, Span},
    widgets::{Block, Borders, Clear, LineGauge, List, ListItem, Paragraph},
    Frame, Terminal,
};
use serde::Deserialize;
use thiserror::Error;

#[derive(Parser)]
#[command(name = "labyrinth-tui", about = "Labyrinth-Mesh live dashboard", version)]
struct Cli {
    /// Management plane address
    #[arg(long, default_value = "127.0.0.1:9090")]
    mgmt: String,
}

#[derive(Error, Debug)]
pub enum DashError {
    #[error("HTTP: {0}")]
    Http(#[from] reqwest::Error),
    #[error("IO: {0}")]
    Io(#[from] io::Error),
}

#[derive(Deserialize, Clone, Debug)]
struct HealthResp {
    status: String,
    paths_active: usize,
    paths_total: usize,
}

impl Default for HealthResp {
    fn default() -> Self {
        Self { status: "unknown".into(), paths_active: 0, paths_total: 0 }
    }
}

#[derive(Deserialize, Clone, Debug, Default)]
struct MetricsResp {
    session_count: usize,
    fragments_sent: u64,
    fragments_recv: u64,
    reconstructed_count: u64,
    ratchet_step: u64,
    replay_detected_count: u64,
    last_bps: f64,
    last_ratchet_packet: u64,
}

#[allow(dead_code)]
#[derive(Deserialize, Clone, Debug, Default)]
struct PathResp {
    idx: usize,
    active: bool,
    packets_sent: u64,
    bytes_sent: u64,
    bytes_recv: u64,
    packets_recv: u64,
}

struct AppState {
    health: HealthResp,
    metrics: MetricsResp,
    paths: Vec<PathResp>,
    events: VecDeque<String>,
    last_update: Instant,
    connecting: bool,
}

impl AppState {
    fn new() -> Self {
        Self {
            health: HealthResp::default(),
            metrics: MetricsResp::default(),
            paths: Vec::new(),
            events: VecDeque::new(),
            last_update: Instant::now(),
            connecting: true,
        }
    }

    fn push(&mut self, msg: impl Into<String>) {
        if self.events.len() >= 50 { self.events.pop_front(); }
        self.events.push_back(format!("{} {}", hms(), msg.into()));
    }
}

struct App {
    mgmt: String,
    state: AppState,
    paused: bool,
    show_failover: bool,
    client: reqwest::blocking::Client,
    prev_replay: u64,
    prev_ratchet: u64,
    prev_reconstructed: u64,
    prev_health: String,
}

impl App {
    fn new(mgmt: String) -> Self {
        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_millis(300))
            .build()
            .unwrap_or_default();
        Self {
            mgmt,
            state: AppState::new(),
            paused: false,
            show_failover: false,
            client,
            prev_replay: 0,
            prev_ratchet: 0,
            prev_reconstructed: 0,
            prev_health: String::new(),
        }
    }

    fn poll(&mut self) {
        let base = &self.mgmt;
        let mut ok = false;

        if let Ok(h) = self.client.get(format!("{base}/health"))
            .send().and_then(|r| r.json::<HealthResp>())
        {
            if h.status != self.prev_health {
                let s = h.status.clone();
                self.state.push(format!("[INFO] Health → {s}"));
                self.prev_health = s;
            }
            self.state.health = h;
            ok = true;
        }

        if let Ok(m) = self.client.get(format!("{base}/metrics"))
            .send().and_then(|r| r.json::<MetricsResp>())
        {
            if m.replay_detected_count > self.prev_replay {
                let n = m.replay_detected_count;
                self.state.push(format!("[WARN] Replay detected (total: {n})"));
                self.prev_replay = n;
            }
            if m.ratchet_step > self.prev_ratchet {
                let s = m.ratchet_step;
                self.state.push(format!("[INFO] Key ratchet → step {s}"));
                self.prev_ratchet = s;
            }
            if m.reconstructed_count > self.prev_reconstructed {
                let delta = m.reconstructed_count - self.prev_reconstructed;
                self.state.push(format!("[INFO] Reconstructed {delta} chunk(s)"));
                self.prev_reconstructed = m.reconstructed_count;
            }
            self.state.metrics = m;
            ok = true;
        }

        if let Ok(p) = self.client.get(format!("{base}/metrics/paths"))
            .send().and_then(|r| r.json::<Vec<PathResp>>())
        {
            self.state.paths = p;
        }

        self.state.last_update = Instant::now();
        self.state.connecting = !ok;
    }

    fn toggle_path(&mut self, idx: usize) {
        let active = self.state.paths.get(idx).map(|p| p.active).unwrap_or(false);
        let verb = if active { "deactivate" } else { "activate" };
        let url = format!("{}/{idx}/{verb}", self.mgmt);
        match self.client.post(&url).body("").send() {
            Ok(r) if r.status().is_success() =>
                self.state.push(format!("[INFO] Path {idx} {verb}d")),
            Ok(r) =>
                self.state.push(format!("[WARN] Path {idx} {verb} failed ({})", r.status())),
            Err(_) =>
                self.state.push(format!("[ERR]  Path {idx} {verb}: no response")),
        }
    }

    fn handle_key(&mut self, code: KeyCode, mods: KeyModifiers) -> bool {
        match code {
            KeyCode::Char('q') => return true,
            KeyCode::Char('c') if mods.contains(KeyModifiers::CONTROL) => return true,
            KeyCode::Esc if self.show_failover => self.show_failover = false,
            KeyCode::Char('p') => {
                self.paused = !self.paused;
                self.state.push(if self.paused {
                    "[INFO] Polling paused"
                } else {
                    "[INFO] Polling resumed"
                });
            }
            KeyCode::Char('r') => {
                self.prev_replay = 0;
                self.prev_ratchet = 0;
                self.prev_reconstructed = 0;
                self.state.push("[INFO] Local counters reset");
            }
            KeyCode::Char('f') => self.show_failover = !self.show_failover,
            KeyCode::Char(c) if self.show_failover => {
                if let Some(idx) = c.to_digit(10) {
                    self.toggle_path(idx as usize);
                }
            }
            _ => {}
        }
        false
    }

    fn run(mut self) -> Result<(), DashError> {
        enable_raw_mode()?;
        let mut stdout = io::stdout();
        execute!(stdout, EnterAlternateScreen)?;
        let backend = CrosstermBackend::new(stdout);
        let mut terminal = Terminal::new(backend)?;
        let _guard = TermGuard;

        let poll_interval = Duration::from_millis(500);
        let key_timeout = Duration::from_millis(50);
        let mut last_poll = Instant::now()
            .checked_sub(poll_interval)
            .unwrap_or(Instant::now());

        loop {
            if event::poll(key_timeout)? {
                if let Event::Key(k) = event::read()? {
                    if self.handle_key(k.code, k.modifiers) { break; }
                }
            }
            if !self.paused && last_poll.elapsed() >= poll_interval {
                self.poll();
                last_poll = Instant::now();
            }
            let mgmt = self.mgmt.clone();
            terminal.draw(|f| draw(f, &self.state, self.paused, self.show_failover, &mgmt))?;
        }
        Ok(())
    }
}

struct TermGuard;
impl Drop for TermGuard {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        let _ = execute!(io::stdout(), LeaveAlternateScreen);
    }
}

fn draw(f: &mut Frame, s: &AppState, paused: bool, failover: bool, mgmt: &str) {
    let area = f.size();
    let chunks = Layout::vertical([
        Constraint::Length(1),
        Constraint::Min(10),
        Constraint::Length(7),
        Constraint::Length(1),
    ]).split(area);

    draw_header(f, chunks[0], s, paused);
    draw_body(f, chunks[1], s);
    draw_events(f, chunks[2], s);
    draw_footer(f, chunks[3]);

    if s.connecting { draw_connecting(f, area, mgmt); }
    if failover { draw_failover(f, area, s); }
}

fn draw_header(f: &mut Frame, area: Rect, s: &AppState, paused: bool) {
    let ago = s.last_update.elapsed().as_secs();
    let pause = if paused { "  ⏸ PAUSED" } else { "" };
    let title = format!(
        " Labyrinth-Mesh ── status: {} ── ratchet: {} ── {ago}s ago{pause}",
        s.health.status, s.metrics.ratchet_step
    );
    let style = match s.health.status.as_str() {
        "ok"      => Style::default().fg(Color::Green),
        "degraded"=> Style::default().fg(Color::Yellow),
        "unknown" => Style::default().fg(Color::DarkGray),
        _         => Style::default().fg(Color::Red),
    };
    f.render_widget(Paragraph::new(title).style(style), area);
}

fn draw_body(f: &mut Frame, area: Rect, s: &AppState) {
    let rows = Layout::vertical([Constraint::Percentage(50), Constraint::Percentage(50)]).split(area);
    let r1 = Layout::horizontal([Constraint::Percentage(45), Constraint::Percentage(55)]).split(rows[0]);
    let r2 = Layout::horizontal([Constraint::Percentage(45), Constraint::Percentage(55)]).split(rows[1]);
    draw_paths(f, r1[0], s);
    draw_crypto(f, r1[1], s);
    draw_sessions(f, r2[0], s);
    draw_transfer(f, r2[1]);
}

fn draw_paths(f: &mut Frame, area: Rect, s: &AppState) {
    let block = Block::default().title(" PATHS ").borders(Borders::ALL);
    let inner = block.inner(area);
    f.render_widget(block, area);
    if s.paths.is_empty() {
        f.render_widget(Paragraph::new("No paths"), inner);
        return;
    }
    let max_pkts = s.paths.iter().map(|p| p.packets_sent).max().unwrap_or(0);
    let vis = s.paths.len().min(inner.height as usize);
    if vis == 0 { return; }
    let constraints: Vec<Constraint> = (0..vis).map(|_| Constraint::Length(1)).collect();
    let rows = Layout::vertical(constraints).split(inner);
    for (i, path) in s.paths.iter().take(vis).enumerate() {
        let ratio = if !path.active { 0.0 }
            else if max_pkts == 0 { 1.0 }
            else { (path.packets_sent as f64 / max_pkts as f64).clamp(0.0, 1.0) };
        let pct = (ratio * 100.0) as u8;
        let color = if !path.active { Color::DarkGray }
            else if pct > 70 { Color::Green }
            else if pct > 30 { Color::Yellow }
            else { Color::Red };
        let gauge = LineGauge::default()
            .ratio(ratio)
            .label(format!("path[{}] {:>3}%", path.idx, pct))
            .gauge_style(Style::default().fg(color))
            .line_set(symbols::line::THICK);
        f.render_widget(gauge, rows[i]);
    }
}

fn draw_crypto(f: &mut Frame, area: Rect, s: &AppState) {
    let m = &s.metrics;
    let lines = vec![
        Line::from(format!("Throughput:       {}", fmt_bps(m.last_bps))),
        Line::from(format!("Ratchet step:     {}", m.ratchet_step)),
        Line::from(format!("Last pkt@ratchet: {}", m.last_ratchet_packet)),
        Line::from(format!("Reconstructed:    {}", m.reconstructed_count)),
        Line::from(format!("Replay detected:  {}", m.replay_detected_count)),
        Line::from(format!("Frags sent:       {}", m.fragments_sent)),
        Line::from(format!("Frags recv:       {}", m.fragments_recv)),
    ];
    f.render_widget(
        Paragraph::new(lines).block(Block::default().title(" CRYPTO ").borders(Borders::ALL)),
        area,
    );
}

fn draw_sessions(f: &mut Frame, area: Rect, s: &AppState) {
    let lines = vec![
        Line::from(format!("Active sessions:  {}", s.metrics.session_count)),
        Line::from(format!("Paths:            {}/{}", s.health.paths_active, s.health.paths_total)),
        Line::from(format!("Frags sent:       {}", s.metrics.fragments_sent)),
        Line::from(format!("Frags recv:       {}", s.metrics.fragments_recv)),
        Line::from(format!("Reconstructed:    {}", s.metrics.reconstructed_count)),
    ];
    f.render_widget(
        Paragraph::new(lines).block(Block::default().title(" SESSIONS ").borders(Borders::ALL)),
        area,
    );
}

fn draw_transfer(f: &mut Frame, area: Rect) {
    f.render_widget(
        Paragraph::new("No transfer active")
            .block(Block::default().title(" FILE TRANSFER ").borders(Borders::ALL)),
        area,
    );
}

fn draw_events(f: &mut Frame, area: Rect, s: &AppState) {
    let items: Vec<ListItem> = s.events.iter().map(|e| {
        let style = if e.contains("[WARN]") { Style::default().fg(Color::Yellow) }
            else if e.contains("[ERR]") { Style::default().fg(Color::Red) }
            else { Style::default().fg(Color::Gray) };
        ListItem::new(Line::from(Span::styled(e.as_str(), style)))
    }).collect();
    f.render_widget(
        List::new(items).block(Block::default().title(" EVENTS ").borders(Borders::ALL)),
        area,
    );
}

fn draw_footer(f: &mut Frame, area: Rect) {
    f.render_widget(
        Paragraph::new(" q: quit   p: pause   r: reset   f: failover ")
            .style(Style::default().fg(Color::DarkGray)),
        area,
    );
}

fn draw_connecting(f: &mut Frame, area: Rect, mgmt: &str) {
    let popup = centered(60, 25, area);
    f.render_widget(Clear, popup);
    f.render_widget(
        Paragraph::new(format!("Connecting to {mgmt} …\n\nWaiting for management plane."))
            .block(Block::default().title(" Connecting ").borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Yellow)))
            .style(Style::default().fg(Color::Yellow)),
        popup,
    );
}

fn draw_failover(f: &mut Frame, area: Rect, s: &AppState) {
    let popup = centered(55, 65, area);
    f.render_widget(Clear, popup);
    let block = Block::default()
        .title(" Failover — 0-9: toggle   Esc: close ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan));
    let items: Vec<ListItem> = s.paths.iter().enumerate().map(|(i, p)| {
        let (icon, style) = if p.active {
            ("● ACTIVE  ", Style::default().fg(Color::Green))
        } else {
            ("○ INACTIVE", Style::default().fg(Color::Red))
        };
        ListItem::new(Line::from(Span::styled(
            format!("  [{i}] {icon}   sent: {:>8}B  recv: {:>8}B", p.bytes_sent, p.bytes_recv),
            style,
        )))
    }).collect();
    if items.is_empty() {
        f.render_widget(Paragraph::new("No paths").block(block), popup);
    } else {
        f.render_widget(List::new(items).block(block), popup);
    }
}

fn centered(pct_x: u16, pct_y: u16, r: Rect) -> Rect {
    let pv = (100u16.saturating_sub(pct_y)) / 2;
    let ph = (100u16.saturating_sub(pct_x)) / 2;
    let mid = Layout::vertical([
        Constraint::Percentage(pv), Constraint::Percentage(pct_y), Constraint::Percentage(pv),
    ]).split(r)[1];
    Layout::horizontal([
        Constraint::Percentage(ph), Constraint::Percentage(pct_x), Constraint::Percentage(ph),
    ]).split(mid)[1]
}

fn fmt_bps(bps: f64) -> String {
    if bps >= 1_000_000.0 { format!("{:.2} Mbps", bps / 1_000_000.0) }
    else if bps >= 1_000.0 { format!("{:.1} Kbps", bps / 1_000.0) }
    else { format!("{:.0} bps", bps) }
}

fn hms() -> String {
    let s = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    format!("{:02}:{:02}:{:02}", (s / 3600) % 24, (s / 60) % 60, s % 60)
}

fn main() {
    let cli = Cli::parse();
    let mgmt = if cli.mgmt.starts_with("http") {
        cli.mgmt
    } else {
        format!("http://{}", cli.mgmt)
    };
    eprintln!("Labyrinth-Mesh TUI — {mgmt}");
    eprintln!("Keys: q quit  p pause  f failover  r reset");
    if let Err(e) = App::new(mgmt).run() {
        eprintln!("TUI error: {e}");
        std::process::exit(1);
    }
}
