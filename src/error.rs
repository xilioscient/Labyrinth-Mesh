use thiserror::Error;

#[derive(Error, Debug)]
pub enum DmpotError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("KEM encapsulation failed")]
    EncapFailed,
    #[error("KEM decapsulation failed")]
    DecapFailed,
    #[error("key exchange error: {0}")]
    KeyExchange(String),
    #[error("invalid wire packet: {0}")]
    InvalidPacket(String),
    #[error("no active paths")]
    NoActivePaths,
    #[error("empty payload")]
    EmptyPayload,
    #[error("fingerprint rejected by operator")]
    FingerprintRejected,
    #[error("key exchange timeout after {0}s")]
    KeyExchangeTimeout(u64),
    #[error("reassembler limit exceeded: {0}")]
    ReassemblerLimit(String),
}
