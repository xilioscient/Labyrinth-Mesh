use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

pub const RATCHET_INTERVAL: u64 = 10_000;

const RATCHET_KDF_CONTEXT: &str = "dmpot-v2 key-ratchet step 2025";

pub fn ratchet_key(current_key: &[u8; 32], ratchet_counter: u64) -> [u8; 32] {
    let mut ikm = Vec::with_capacity(32 + 8);
    ikm.extend_from_slice(current_key);
    ikm.extend_from_slice(&ratchet_counter.to_le_bytes());
    blake3::derive_key(RATCHET_KDF_CONTEXT, &ikm)
}

pub struct KeyRatchet {
    current_key: std::sync::Mutex<[u8; 32]>,
    packet_count: Arc<AtomicU64>,
    ratchet_step: AtomicU64,
}

impl KeyRatchet {
    pub fn new(initial_key: [u8; 32]) -> Self {
        KeyRatchet {
            current_key: std::sync::Mutex::new(initial_key),
            packet_count: Arc::new(AtomicU64::new(0)),
            ratchet_step: AtomicU64::new(0),
        }
    }

    pub fn key_for_packet(&self) -> [u8; 32] {
        let pkt = self.packet_count.fetch_add(1, Ordering::SeqCst);

        if (pkt + 1).is_multiple_of(RATCHET_INTERVAL) {
            let step = self.ratchet_step.fetch_add(1, Ordering::SeqCst) + 1;
            let mut key = self.current_key.lock().unwrap();
            *key = ratchet_key(&key, step);
            log::debug!("Key ratchet step {step} at packet {pkt}");
            *key
        } else {
            *self.current_key.lock().unwrap()
        }
    }

    pub fn force_ratchet(&self) {
        let step = self.ratchet_step.fetch_add(1, Ordering::SeqCst) + 1;
        let mut key = self.current_key.lock().unwrap();
        *key = ratchet_key(&key, step);
        log::info!("Forced key ratchet step {step}");
    }

    pub fn current_step(&self) -> u64 {
        self.ratchet_step.load(Ordering::SeqCst)
    }

    pub fn packets_processed(&self) -> u64 {
        self.packet_count.load(Ordering::SeqCst)
    }
}

#[cfg(target_os = "linux")]
pub fn push_key_to_bpf(
    bpf: &mut aya::Bpf,
    session_id: u32,
    new_key: &[u8; 32],
    ratchet_step: u64,
) -> Result<(), String> {
    use aya::maps::Array;

    let mut arr: Array<_, [u8; 40]> = Array::try_from(
        bpf.map_mut("session_keys").ok_or("session_keys not found")?
    ).map_err(|e| format!("Array: {e}"))?;

    let mut value = [0u8; 40];
    value[..32].copy_from_slice(new_key);
    value[32..40].copy_from_slice(&ratchet_step.to_le_bytes());
    arr.set(session_id, value, 0).map_err(|e| format!("set: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ratchet_produces_different_keys() {
        let k0 = [0x42u8; 32];
        let k1 = ratchet_key(&k0, 1);
        let k2 = ratchet_key(&k0, 2);
        let k1b = ratchet_key(&k1, 2);

        assert_ne!(k0, k1);
        assert_ne!(k1, k2);
        assert_ne!(k1b, k2);
    }

    #[test]
    fn test_ratchet_deterministic() {
        let k = [0xAAu8; 32];
        assert_eq!(ratchet_key(&k, 7), ratchet_key(&k, 7));
    }

    #[test]
    fn test_key_ratchet_auto_advance() {
        let initial = [0x11u8; 32];
        let ratchet = KeyRatchet::new(initial);

        for _ in 0..(RATCHET_INTERVAL - 1) {
            let k = ratchet.key_for_packet();
            assert_eq!(k, initial);
        }
        assert_eq!(ratchet.current_step(), 0);

        let k_after = ratchet.key_for_packet();
        assert_eq!(ratchet.current_step(), 1);
        assert_ne!(k_after, initial);
    }

    #[test]
    fn test_force_ratchet() {
        let ratchet = KeyRatchet::new([0x99u8; 32]);
        let k0 = ratchet.key_for_packet();
        ratchet.force_ratchet();
        let k1 = ratchet.key_for_packet();
        assert_ne!(k0, k1);
        assert_eq!(ratchet.current_step(), 1);
    }
}
