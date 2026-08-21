use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::PathBuf;
use std::time::Instant;

use thiserror::Error;

use crate::metrics::SharedMetrics;

pub const DEFAULT_CHUNK_SIZE: usize = 6512;

#[derive(Debug, Clone)]
pub struct FileTransferConfig {
    pub input_path: Option<PathBuf>,
    pub output_path: Option<PathBuf>,
    pub chunk_size: usize,
    pub verify_integrity: bool,
}

impl Default for FileTransferConfig {
    fn default() -> Self {
        Self {
            input_path: None,
            output_path: None,
            chunk_size: DEFAULT_CHUNK_SIZE,
            verify_integrity: true,
        }
    }
}

#[derive(Error, Debug)]
pub enum FileTransferError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("integrity check failed: expected {expected:?}, got {got:?}")]
    IntegrityCheckFailed { expected: [u8; 32], got: [u8; 32] },
    #[error("no input path specified (use --file-in)")]
    NoInputPath,
    #[error("no output path specified (use --file-out)")]
    NoOutputPath,
}

pub struct FileSender {
    pub config: FileTransferConfig,
    pub metrics: SharedMetrics,
}

impl FileSender {
    pub fn new(config: FileTransferConfig, metrics: SharedMetrics) -> Self {
        Self { config, metrics }
    }

    pub fn file_size(&self) -> Result<u64, FileTransferError> {
        let path = self.config.input_path.as_ref().ok_or(FileTransferError::NoInputPath)?;
        Ok(std::fs::metadata(path)?.len())
    }

    pub fn send_chunks(&self) -> impl Iterator<Item = Result<Vec<u8>, FileTransferError>> {
        let path = self.config.input_path.clone();
        let chunk_size = self.config.chunk_size;
        let metrics = self.metrics.clone();
        SendChunksIter::build(path, chunk_size, metrics)
    }
}

struct ActiveChunkIter {
    reader: BufReader<File>,
    chunk_size: usize,
    total_size: u64,
    bytes_sent: usize,
    metrics: SharedMetrics,
}

impl Iterator for ActiveChunkIter {
    type Item = Result<Vec<u8>, FileTransferError>;

    fn next(&mut self) -> Option<Self::Item> {
        let mut buf = vec![0u8; self.chunk_size];
        match self.reader.read(&mut buf) {
            Ok(0) => None,
            Ok(n) => {
                buf.truncate(n);
                self.bytes_sent += n;
                self.metrics
                    .on_file_transfer_progress(self.bytes_sent, self.total_size as usize);
                Some(Ok(buf))
            }
            Err(e) => Some(Err(FileTransferError::Io(e))),
        }
    }
}

enum SendChunksIter {
    Error(Option<FileTransferError>),
    Active(ActiveChunkIter),
}

impl SendChunksIter {
    fn build(
        path: Option<PathBuf>,
        chunk_size: usize,
        metrics: SharedMetrics,
    ) -> Self {
        let result = (|| -> Result<Self, FileTransferError> {
            let p = path.ok_or(FileTransferError::NoInputPath)?;
            let file = File::open(&p)?;
            let total_size = file.metadata()?.len();
            Ok(Self::Active(ActiveChunkIter {
                reader: BufReader::new(file),
                chunk_size,
                total_size,
                bytes_sent: 0,
                metrics,
            }))
        })();
        result.unwrap_or_else(|e| Self::Error(Some(e)))
    }
}

impl Iterator for SendChunksIter {
    type Item = Result<Vec<u8>, FileTransferError>;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            Self::Error(slot) => slot.take().map(Err),
            Self::Active(it) => it.next(),
        }
    }
}

pub struct FileReceiver {
    pub config: FileTransferConfig,
    pub metrics: SharedMetrics,
    pub hasher: blake3::Hasher,
    buffer: Vec<u8>,
    chunk_count: usize,
    started_at: Instant,
}

impl FileReceiver {
    pub fn new(config: FileTransferConfig, metrics: SharedMetrics) -> Self {
        Self {
            config,
            metrics,
            hasher: blake3::Hasher::new(),
            buffer: Vec::new(),
            chunk_count: 0,
            started_at: Instant::now(),
        }
    }

    pub fn write_chunk(&mut self, data: &[u8]) -> Result<(), FileTransferError> {
        self.hasher.update(data);
        self.buffer.extend_from_slice(data);
        self.chunk_count += 1;
        self.metrics.on_file_transfer_progress(self.buffer.len(), 0);
        Ok(())
    }

    pub fn finalize(&mut self) -> Result<FileTransferSummary, FileTransferError> {
        let output_path = self.config.output_path.as_ref()
            .ok_or(FileTransferError::NoOutputPath)?
            .clone();

        {
            let mut writer = BufWriter::new(File::create(&output_path)?);
            writer.write_all(&self.buffer)?;
            writer.flush()?;
        }

        let computed_hash = *self.hasher.clone().finalize().as_bytes();

        if self.config.verify_integrity {
            let mut re_hasher = blake3::Hasher::new();
            let mut f = File::open(&output_path)?;
            let mut rbuf = vec![0u8; self.config.chunk_size];
            loop {
                let n = f.read(&mut rbuf)?;
                if n == 0 { break; }
                re_hasher.update(&rbuf[..n]);
            }
            let disk_hash = *re_hasher.finalize().as_bytes();
            if disk_hash != computed_hash {
                return Err(FileTransferError::IntegrityCheckFailed {
                    expected: computed_hash,
                    got: disk_hash,
                });
            }
        }

        Ok(FileTransferSummary {
            total_bytes: self.buffer.len(),
            chunks: self.chunk_count,
            blake3_hash: computed_hash,
            elapsed_secs: self.started_at.elapsed().as_secs_f64(),
        })
    }
}

#[derive(Debug, Clone)]
pub struct FileTransferSummary {
    pub total_bytes: usize,
    pub chunks: usize,
    pub blake3_hash: [u8; 32],
    pub elapsed_secs: f64,
}

pub fn parse_file_args() -> (Option<PathBuf>, Option<PathBuf>) {
    let args: Vec<String> = std::env::args().collect();
    let mut file_in: Option<PathBuf> = None;
    let mut file_out: Option<PathBuf> = None;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--file-in" if i + 1 < args.len() => {
                let p = PathBuf::from(&args[i + 1]);
                if p.components().any(|c| c == std::path::Component::ParentDir) {
                    eprintln!("warning: --file-in path contains '..' traversal: {}", p.display());
                }
                file_in = Some(p);
                i += 2;
            }
            "--file-out" if i + 1 < args.len() => {
                let p = PathBuf::from(&args[i + 1]);
                if p.is_absolute() {
                    eprintln!("warning: --file-out uses absolute path: {}", p.display());
                }
                if p.components().any(|c| c == std::path::Component::ParentDir) {
                    eprintln!("warning: --file-out path contains '..' traversal: {}", p.display());
                }
                file_out = Some(p);
                i += 2;
            }
            _ => i += 1,
        }
    }
    (file_in, file_out)
}

#[cfg(feature = "io-uring")]
impl FileReceiver {
    pub async fn finalize_uring(&mut self) -> Result<FileTransferSummary, FileTransferError> {
        use tokio::task::spawn_blocking;

        let output_path = self
            .config
            .output_path
            .as_ref()
            .ok_or(FileTransferError::NoOutputPath)?
            .clone();

        let data = self.buffer.clone();
        let computed_hash = *self.hasher.clone().finalize().as_bytes();
        let chunk_count = self.chunk_count;
        let elapsed = self.started_at.elapsed().as_secs_f64();
        let total_bytes = data.len();
        let verify = self.config.verify_integrity;

        spawn_blocking(move || {
            tokio_uring::start(async move {
                let file = tokio_uring::fs::File::create(&output_path)
                    .await
                    .map_err(FileTransferError::Io)?;

                let mut pos: u64 = 0;
                let mut remaining = data;
                while !remaining.is_empty() {
                    let len = remaining.len();
                    let (res, buf) = file.write_at(remaining, pos).await;
                    let n = res.map_err(FileTransferError::Io)?;
                    pos += n as u64;
                    remaining = buf[n..].to_vec();
                    if n == 0 && remaining.len() == len {
                        break;
                    }
                }

                file.sync_all().await.map_err(FileTransferError::Io)?;

                if verify {
                    let rf = tokio_uring::fs::File::open(&output_path)
                        .await
                        .map_err(FileTransferError::Io)?;
                    let mut re_hasher = blake3::Hasher::new();
                    let mut rpos: u64 = 0;
                    loop {
                        let rbuf = vec![0u8; 65536];
                        let (res, buf) = rf.read_at(rbuf, rpos).await;
                        let n = res.map_err(FileTransferError::Io)?;
                        if n == 0 {
                            break;
                        }
                        re_hasher.update(&buf[..n]);
                        rpos += n as u64;
                    }
                    let disk_hash = *re_hasher.finalize().as_bytes();
                    if disk_hash != computed_hash {
                        return Err(FileTransferError::IntegrityCheckFailed {
                            expected: computed_hash,
                            got: disk_hash,
                        });
                    }
                }

                Ok(FileTransferSummary {
                    total_bytes,
                    chunks: chunk_count,
                    blake3_hash: computed_hash,
                    elapsed_secs: elapsed,
                })
            })
        })
        .await
        .map_err(|e| FileTransferError::Io(std::io::Error::new(std::io::ErrorKind::Other, e)))?
    }
}

#[cfg(feature = "io-uring")]
pub async fn read_file_uring(path: &std::path::Path) -> Result<Vec<u8>, std::io::Error> {
    use tokio::task::spawn_blocking;
    let p = path.to_path_buf();
    spawn_blocking(move || {
        tokio_uring::start(async move {
            let file = tokio_uring::fs::File::open(&p).await?;
            let meta_len = std::fs::metadata(&p)
                .map(|m| m.len() as usize)
                .unwrap_or(65536);
            let mut out = Vec::with_capacity(meta_len);
            let mut pos: u64 = 0;
            loop {
                let buf = vec![0u8; 65536];
                let (res, rbuf) = file.read_at(buf, pos).await;
                let n = res?;
                if n == 0 {
                    break;
                }
                out.extend_from_slice(&rbuf[..n]);
                pos += n as u64;
            }
            Ok(out)
        })
    })
    .await
    .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metrics::noop_metrics;

    fn tmp(tag: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("labyrinth_ft_{}_{}", tag, std::process::id()));
        p
    }

    #[test]
    fn round_trip_single_chunk() {
        let path = tmp("single");
        let cfg = FileTransferConfig { output_path: Some(path.clone()), ..Default::default() };
        let mut rx = FileReceiver::new(cfg, noop_metrics());

        rx.write_chunk(b"hello, troskji!").unwrap();
        let summary = rx.finalize().unwrap();

        assert_eq!(std::fs::read(&path).unwrap(), b"hello, troskji!");
        assert_eq!(summary.total_bytes, 15);
        assert_eq!(summary.chunks, 1);
        assert!(summary.elapsed_secs >= 0.0);

        let expected_hash = *blake3::hash(b"hello, troskji!").as_bytes();
        assert_eq!(summary.blake3_hash, expected_hash);

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn round_trip_multiple_chunks() {
        let path = tmp("multi");
        let cfg = FileTransferConfig { output_path: Some(path.clone()), ..Default::default() };
        let mut rx = FileReceiver::new(cfg, noop_metrics());

        let parts: &[&[u8]] = &[b"alpha", b"beta", b"gamma"];
        for part in parts {
            rx.write_chunk(part).unwrap();
        }
        let summary = rx.finalize().unwrap();

        let full: Vec<u8> = parts.iter().copied().flatten().copied().collect();
        assert_eq!(std::fs::read(&path).unwrap(), full);
        assert_eq!(summary.total_bytes, full.len());
        assert_eq!(summary.chunks, 3);

        let mut h = blake3::Hasher::new();
        for part in parts { h.update(part); }
        assert_eq!(summary.blake3_hash, *h.finalize().as_bytes());

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn verify_integrity_passes_on_clean_write() {
        let path = tmp("integrity_ok");
        let cfg = FileTransferConfig {
            output_path: Some(path.clone()),
            verify_integrity: true,
            ..Default::default()
        };
        let mut rx = FileReceiver::new(cfg, noop_metrics());
        rx.write_chunk(b"integrity test payload").unwrap();
        assert!(rx.finalize().is_ok());
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn no_output_path_returns_error() {
        let mut rx = FileReceiver::new(FileTransferConfig::default(), noop_metrics());
        rx.write_chunk(b"data").unwrap();
        assert!(matches!(rx.finalize(), Err(FileTransferError::NoOutputPath)));
    }

    #[test]
    fn sender_file_size() {
        let path = tmp("size");
        std::fs::write(&path, b"0123456789").unwrap();
        let cfg = FileTransferConfig { input_path: Some(path.clone()), ..Default::default() };
        let sender = FileSender::new(cfg, noop_metrics());
        assert_eq!(sender.file_size().unwrap(), 10);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn sender_no_path_yields_error_item() {
        let sender = FileSender::new(FileTransferConfig::default(), noop_metrics());
        let mut it = sender.send_chunks();
        assert!(matches!(it.next(), Some(Err(FileTransferError::NoInputPath))));
        assert!(it.next().is_none());
    }

    #[test]
    fn sender_chunks_are_lazy_and_reconstruct() {
        let path = tmp("lazy");
        let data: Vec<u8> = (0u8..200).collect();
        std::fs::write(&path, &data).unwrap();

        let cfg = FileTransferConfig {
            input_path: Some(path.clone()),
            chunk_size: 30,
            ..Default::default()
        };
        let sender = FileSender::new(cfg, noop_metrics());
        let chunks: Vec<Vec<u8>> = sender
            .send_chunks()
            .map(|r| r.unwrap())
            .collect();

        assert_eq!(chunks.len(), 7);
        let reconstructed: Vec<u8> = chunks.into_iter().flatten().collect();
        assert_eq!(reconstructed, data);

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn sender_to_receiver_round_trip() {
        let in_path = tmp("rt_in");
        let out_path = tmp("rt_out");
        let original: Vec<u8> = (0u8..=255).cycle().take(1024).collect();
        std::fs::write(&in_path, &original).unwrap();

        let send_cfg = FileTransferConfig {
            input_path: Some(in_path.clone()),
            chunk_size: 100,
            ..Default::default()
        };
        let recv_cfg = FileTransferConfig {
            output_path: Some(out_path.clone()),
            verify_integrity: true,
            ..Default::default()
        };

        let sender = FileSender::new(send_cfg, noop_metrics());
        let mut receiver = FileReceiver::new(recv_cfg, noop_metrics());

        for chunk in sender.send_chunks() {
            receiver.write_chunk(&chunk.unwrap()).unwrap();
        }
        let summary = receiver.finalize().unwrap();

        assert_eq!(std::fs::read(&out_path).unwrap(), original);
        assert_eq!(summary.total_bytes, 1024);

        let expected_hash = *blake3::hash(&original).as_bytes();
        assert_eq!(summary.blake3_hash, expected_hash);

        std::fs::remove_file(&in_path).ok();
        std::fs::remove_file(&out_path).ok();
    }

    #[test]
    fn sender_exact_chunk_boundary() {
        let path = tmp("exact");
        let data = vec![0u8; 90];
        std::fs::write(&path, &data).unwrap();

        let cfg = FileTransferConfig {
            input_path: Some(path.clone()),
            chunk_size: 30,
            ..Default::default()
        };
        let sender = FileSender::new(cfg, noop_metrics());
        let chunks: Vec<_> = sender.send_chunks().collect();
        assert_eq!(chunks.len(), 3);
        for c in &chunks {
            assert_eq!(c.as_ref().unwrap().len(), 30);
        }
        std::fs::remove_file(&path).ok();
    }
}
