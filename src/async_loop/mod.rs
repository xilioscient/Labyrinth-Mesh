use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Duration;
use std::io;

use bytes::Bytes;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

use crate::metrics::SharedMetrics;
use crate::phase1::{DMPOTFragment, FragmentHeader, reconstruct_payload};
use crate::phase4::{FragmentReassembler, parse_wire_packet};

const MAX_UDP_PAYLOAD: usize = 65535;

#[derive(Debug)]
pub struct RawFragment {
    pub session_id: [u8; 16],
    pub x: u8,
    pub total: u8,
    pub orig_len: u32,
    pub data: Bytes,
}

#[derive(Debug, PartialEq, Eq)]
pub enum BackpressureAction {
    Accept,
    DropRedundant,
    DropOldest,
}

pub struct AsyncDmpotReceiver {
    socket: UdpSocket,
    reassembler_tx: mpsc::Sender<RawFragment>,
    metrics: SharedMetrics,
    pub max_in_flight: usize,
    pub threshold_k: u8,
}

impl AsyncDmpotReceiver {
    pub async fn bind(
        addr: SocketAddr,
        tx: mpsc::Sender<RawFragment>,
        metrics: SharedMetrics,
    ) -> io::Result<Self> {
        let socket = UdpSocket::bind(addr).await?;
        Ok(Self {
            socket,
            reassembler_tx: tx,
            metrics,
            max_in_flight: 256,
            threshold_k: 2,
        })
    }

    pub async fn run(self) -> io::Result<()> {
        let mut buf = vec![0u8; MAX_UDP_PAYLOAD];
        let mut session_frags: HashMap<[u8; 16], usize> = HashMap::new();

        loop {
            let (n, _peer) = self.socket.recv_from(&mut buf).await?;

            let Some((session_id, x, total, orig_len, payload)) = parse_wire_packet(&buf[..n])
            else {
                continue;
            };

            self.metrics.on_fragment_recv(session_id, x, payload.len());

            let in_flight = *session_frags.get(&session_id).unwrap_or(&0);

            match self.backpressure_check(in_flight, self.threshold_k) {
                BackpressureAction::Accept => {
                    let frag = RawFragment {
                        session_id,
                        x,
                        total,
                        orig_len,
                        data: Bytes::copy_from_slice(payload),
                    };
                    if self.reassembler_tx.send(frag).await.is_ok() {
                        *session_frags.entry(session_id).or_insert(0) += 1;
                    }
                }
                BackpressureAction::DropRedundant => {
                    log::debug!(
                        "backpressure DropRedundant: session {:02x?}, in_flight={}, k={}",
                        &session_id[..4],
                        in_flight,
                        self.threshold_k,
                    );
                }
                BackpressureAction::DropOldest => {
                    log::debug!(
                        "backpressure DropOldest: session {:02x?}, in_flight={}",
                        &session_id[..4],
                        in_flight,
                    );
                    session_frags
                        .entry(session_id)
                        .and_modify(|v| *v = v.saturating_sub(1));
                    let frag = RawFragment {
                        session_id,
                        x,
                        total,
                        orig_len,
                        data: Bytes::copy_from_slice(payload),
                    };
                    let _ = self.reassembler_tx.send(frag).await;
                }
            }
        }
    }

    fn backpressure_check(&self, session_frags_in_flight: usize, k: u8) -> BackpressureAction {
        if session_frags_in_flight < self.max_in_flight {
            BackpressureAction::Accept
        } else if session_frags_in_flight > k as usize {
            BackpressureAction::DropRedundant
        } else {
            BackpressureAction::DropOldest
        }
    }
}

pub struct AsyncReassemblerWorker {
    rx: mpsc::Receiver<RawFragment>,
    reassembler: FragmentReassembler,
    metrics: SharedMetrics,
    output_tx: mpsc::Sender<(Vec<u8>, [u8; 16])>,
}

impl AsyncReassemblerWorker {
    pub fn new(
        rx: mpsc::Receiver<RawFragment>,
        output_tx: mpsc::Sender<(Vec<u8>, [u8; 16])>,
        metrics: SharedMetrics,
        threshold_k: u8,
        session_timeout: Duration,
    ) -> Self {
        Self {
            rx,
            reassembler: FragmentReassembler::new(threshold_k, session_timeout),
            metrics,
            output_tx,
        }
    }

    pub async fn run(mut self) {
        while let Some(frag) = self.rx.recv().await {
            let session_id = frag.session_id;
            let total = frag.total;
            let x = frag.x;
            let payload = frag.data.to_vec();

            if let Some(shares) = self.reassembler.feed_share(session_id, x, total, payload) {
                let frags: Vec<DMPOTFragment> = shares
                    .into_iter()
                    .map(|(sx, sp)| DMPOTFragment::new(FragmentHeader::new(sx, total), sp))
                    .collect();

                let plaintext = reconstruct_payload(&frags);
                let plaintext_len = plaintext.len();

                let _ = self.output_tx.send((plaintext, session_id)).await;
                self.metrics.on_fragment_reconstructed(session_id, plaintext_len);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metrics::noop_metrics;

    async fn make_receiver(max_in_flight: usize, threshold_k: u8) -> AsyncDmpotReceiver {
        let (tx, _rx) = mpsc::channel(64);
        let mut r =
            AsyncDmpotReceiver::bind("127.0.0.1:0".parse().unwrap(), tx, noop_metrics())
                .await
                .expect("bind failed");
        r.max_in_flight = max_in_flight;
        r.threshold_k = threshold_k;
        r
    }

    #[tokio::test]
    async fn accept_when_below_max_in_flight() {
        let r = make_receiver(256, 2).await;
        assert_eq!(r.backpressure_check(0, 2), BackpressureAction::Accept);
        assert_eq!(r.backpressure_check(255, 2), BackpressureAction::Accept);
    }

    #[tokio::test]
    async fn drop_redundant_when_frags_exceed_k_and_channel_full() {
        let r = make_receiver(3, 2).await;
        assert_eq!(r.backpressure_check(3, 2), BackpressureAction::DropRedundant);
        assert_eq!(r.backpressure_check(5, 2), BackpressureAction::DropRedundant);
    }

    #[tokio::test]
    async fn drop_redundant_with_higher_k() {
        let r = make_receiver(4, 3).await;
        assert_eq!(r.backpressure_check(5, 3), BackpressureAction::DropRedundant);
    }

    #[tokio::test]
    async fn drop_oldest_when_full_but_frags_not_exceeding_k() {
        let r = make_receiver(3, 5).await;
        assert_eq!(r.backpressure_check(3, 5), BackpressureAction::DropOldest);
        assert_eq!(r.backpressure_check(4, 5), BackpressureAction::DropOldest);
    }

    #[tokio::test]
    async fn never_drop_when_in_flight_below_k() {
        let r = make_receiver(256, 10).await;
        for i in 0..10usize {
            assert_eq!(
                r.backpressure_check(i, 10),
                BackpressureAction::Accept,
                "in_flight={i} should be Accept"
            );
        }
    }

    #[test]
    fn raw_fragment_fields() {
        let sid = [0xABu8; 16];
        let frag = RawFragment {
            session_id: sid,
            x: 3,
            total: 5,
            orig_len: 1024,
            data: Bytes::from_static(b"hello"),
        };
        assert_eq!(frag.x, 3);
        assert_eq!(frag.total, 5);
        assert_eq!(&frag.data[..], b"hello");
    }

    #[tokio::test]
    async fn boundary_exactly_at_k_is_not_redundant() {
        let r = make_receiver(2, 2).await;
        assert_eq!(r.backpressure_check(2, 2), BackpressureAction::DropOldest);
    }

    #[tokio::test]
    async fn boundary_k_plus_one_is_redundant() {
        let r = make_receiver(2, 2).await;
        assert_eq!(r.backpressure_check(3, 2), BackpressureAction::DropRedundant);
    }
}
