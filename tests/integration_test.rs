//! End-to-end loopback integration test for the full DMPOT pipeline.
//!
//! Spins up a receiver thread and a sender thread; verifies the reconstructed
//! plaintext matches the original payload.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::thread;
use std::time::Duration;

use labyrinth_core::phase1::{split_payload, reconstruct_payload, DMPOTFragment, FragmentHeader};
use labyrinth_core::phase2::{KyberKeyPair, encapsulate_fragment, decapsulate_fragment, EncapsulatedFragment};
use labyrinth_core::phase4::{
    FragmentReassembler, build_wire_packet, parse_wire_packet,
};

const CTRL_ADDR: &str = "127.0.0.1:17099";
const UDP_RECV:  &str = "127.0.0.1:17001";
const N: u8 = 5;
const K: u8 = 3;
const LAYERS: u8 = 2;

fn recv_pk_from_receiver(ctrl_addr: SocketAddr) -> Vec<u8> {
    let mut stream = TcpStream::connect(ctrl_addr).expect("connect ctrl");
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).unwrap();
    let pk_len = u32::from_le_bytes(len_buf) as usize;
    let mut pk = vec![0u8; pk_len];
    stream.read_exact(&mut pk).unwrap();
    pk
}

fn send_pk_via_tcp(ctrl_addr: SocketAddr, pk: &[u8]) {
    let listener = TcpListener::bind(ctrl_addr).expect("bind ctrl");
    let (mut stream, _) = listener.accept().expect("accept ctrl");
    stream.write_all(&(pk.len() as u32).to_le_bytes()).unwrap();
    stream.write_all(pk).unwrap();
    stream.flush().unwrap();
}

#[test]
fn test_full_pipeline_loopback() {
    let original_payload = b"DMPOT integration test: the quick brown fox jumps over the lazy dog";

    let ctrl: SocketAddr = CTRL_ADDR.parse().unwrap();
    let udp_recv: SocketAddr = UDP_RECV.parse().unwrap();
    let udp_send: SocketAddr = "0.0.0.0:17002".parse().unwrap();

    // ── Receiver thread ──────────────────────────────────────────────────────
    let _payload_clone = original_payload.to_vec();
    let recv_handle = thread::spawn(move || -> Vec<u8> {
        let kp = KyberKeyPair::generate();
        let pk = kp.public_key_bytes().to_vec();

        // TCP: send pk to sender
        send_pk_via_tcp(ctrl, &pk);

        // UDP: collect fragments
        let socket = UdpSocket::bind(udp_recv).expect("bind udp recv");
        socket.set_read_timeout(Some(Duration::from_secs(10))).unwrap();

        let mut reassembler = FragmentReassembler::new(K, Duration::from_secs(10));
        let mut buf = vec![0u8; 65535];

        loop {
            let (n, _) = match socket.recv_from(&mut buf) {
                Ok(x) => x,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock
                       || e.kind() == std::io::ErrorKind::TimedOut => {
                    panic!("Receiver timed out waiting for fragments");
                }
                Err(e) => panic!("recv_from: {e}"),
            };

            let packet = &buf[..n];
            let (session_id, x, total, orig_len, morphed_data) =
                match parse_wire_packet(packet) {
                    Some(r) => r,
                    None => continue,
                };

            let real_len = (orig_len as usize).min(morphed_data.len());
            let enc = match EncapsulatedFragment::from_bytes(&morphed_data[..real_len]) {
                Some(e) => e,
                None => continue,
            };

            let share = match decapsulate_fragment(&enc, &kp, LAYERS) {
                Some(s) => s,
                None => continue,
            };

            if let Some(shares) = reassembler.feed_share(session_id, x, total, share) {
                let frags: Vec<DMPOTFragment> = shares
                    .into_iter()
                    .map(|(xi, pl)| DMPOTFragment {
                        header: FragmentHeader { session_id, x: xi, total },
                        payload: pl,
                    })
                    .collect();
                return reconstruct_payload(&frags);
            }
        }
    });

    // Give the receiver thread time to bind TCP + UDP before sender starts
    thread::sleep(Duration::from_millis(50));

    // ── Sender thread ─────────────────────────────────────────────────────────
    let send_handle = thread::spawn(move || {
        let receiver_pk = recv_pk_from_receiver(ctrl);

        let fragments = split_payload(original_payload, N, K);
        let session_id = fragments[0].header.session_id;

        let sock = UdpSocket::bind(udp_send).expect("bind udp send");

        for frag in &fragments {
            let enc = encapsulate_fragment(&frag.payload, &receiver_pk, LAYERS)
                .expect("encapsulate");
            let enc_bytes = enc.to_bytes();
            let orig_len = enc_bytes.len() as u32;
            let wire = build_wire_packet(
                &session_id, frag.header.x, frag.header.total, orig_len, &enc_bytes,
            );
            sock.send_to(&wire, udp_recv).expect("send_to");
        }
    });

    send_handle.join().expect("sender panicked");
    let reconstructed = recv_handle.join().expect("receiver panicked");

    assert_eq!(reconstructed, original_payload.as_slice(),
        "Reconstructed payload does not match original");
}
