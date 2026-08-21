use std::collections::VecDeque;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

pub type LogBuffer = Arc<Mutex<VecDeque<LogEntry>>>;

static GLOBAL_BUF: OnceLock<LogBuffer> = OnceLock::new();

const CAP: usize = 500;

#[derive(Clone, serde::Serialize)]
pub struct LogEntry {
    pub ts_ms: u64,
    pub level: &'static str,
    pub target: String,
    pub msg: String,
}

pub fn init_with_capture() {
    let buf: LogBuffer = Arc::new(Mutex::new(VecDeque::with_capacity(CAP)));
    if GLOBAL_BUF.set(buf).is_err() {
        return;
    }

    let inner = env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or("info"),
    )
    .build();
    let max_level = inner.filter();

    let buf = GLOBAL_BUF.get().unwrap().clone();

    log::set_boxed_logger(Box::new(CapturingLogger { inner, buf }))
        .expect("log::set_logger called twice");
    log::set_max_level(max_level);
}

pub fn global_buffer() -> Option<LogBuffer> {
    GLOBAL_BUF.get().cloned()
}

struct CapturingLogger {
    inner: env_logger::Logger,
    buf: LogBuffer,
}

impl log::Log for CapturingLogger {
    fn enabled(&self, metadata: &log::Metadata) -> bool {
        self.inner.enabled(metadata)
    }

    fn log(&self, record: &log::Record) {
        self.inner.log(record);

        if record.level() > log::Level::Info {
            return;
        }

        let ts_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        let level: &'static str = match record.level() {
            log::Level::Error => "error",
            log::Level::Warn  => "warn",
            log::Level::Info  => "info",
            log::Level::Debug => "debug",
            log::Level::Trace => "trace",
        };

        let entry = LogEntry {
            ts_ms,
            level,
            target: record.target().to_string(),
            msg: record.args().to_string(),
        };

        if let Ok(mut g) = self.buf.lock() {
            if g.len() >= CAP {
                g.pop_front();
            }
            g.push_back(entry);
        }
    }

    fn flush(&self) {
        self.inner.flush();
    }
}
