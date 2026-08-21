use chacha20::cipher::{KeyIvInit, StreamCipher};
use chacha20::{ChaCha20, Key as ChaChaKey, Nonce as ChaChaNonce};
use rand::rngs::OsRng;
use rand::Rng;
use std::time::{Duration, Instant};

pub const TLS_MIN_SIZE: usize = 128;
pub const TLS_MAX_SIZE: usize = 1024;
pub const TLS_MEAN_SIZE: usize = 480;

pub const SRTP_MIN_SIZE: usize = 40;
pub const SRTP_MAX_SIZE: usize = 1500;
pub const SRTP_MEAN_SIZE: usize = 350;

pub const TLS_IAT_MEAN_MS: f64 = 87.0;
pub const TLS_IAT_STDDEV_MS: f64 = 23.0;

pub const WEBRTC_IAT_MEAN_MS: f64 = 20.0;
pub const WEBRTC_IAT_STDDEV_MS: f64 = 8.0;

#[derive(Debug, Clone, Copy)]
pub struct PaddingProfile {
    pub min_size: usize,
    pub max_size: usize,
    pub mean_size: usize,
    pub protocol: ProtocolType,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ProtocolType {
    #[default]
    Tls13,
    WebRtc,
    Quic,
    Http2,
}

#[derive(Debug, Clone)]
pub struct MarkovState {
    current_state: f64,
    transition_matrix: Vec<Vec<f64>>,
    state_space: Vec<f64>,
}

impl MarkovState {
    fn build_matrix(states: usize, min_ms: f64, step_ms: f64, seed: &[u8; 32]) -> Self {
        let nonce = [0u8; 12];
        let mut ks = vec![0u8; states * states * 4];
        let mut cipher = ChaCha20::new(
            ChaChaKey::from_slice(seed.as_slice()),
            ChaChaNonce::from_slice(nonce.as_slice()),
        );
        cipher.apply_keystream(&mut ks);

        let state_space: Vec<f64> = (0..states)
            .map(|i| min_ms + i as f64 * step_ms)
            .collect();

        let mut matrix = vec![vec![0.0f64; states]; states];
        let mut byte_idx = 0usize;

        for row in matrix.iter_mut() {
            let mut sum = 0.0f64;
            for cell in row.iter_mut() {
                let v = u32::from_le_bytes([
                    ks[byte_idx], ks[byte_idx + 1],
                    ks[byte_idx + 2], ks[byte_idx + 3],
                ]) as f64 / u32::MAX as f64;
                byte_idx += 4;
                *cell = v;
                sum += v;
            }
            for p in row.iter_mut() { *p /= sum; }
        }

        MarkovState {
            current_state: state_space[states / 2],
            transition_matrix: matrix,
            state_space,
        }
    }

    pub fn new_tls_seeded(session_key: &[u8; 32]) -> Self {
        Self::build_matrix(20, 20.0, 9.0, session_key)
    }

    pub fn new_webrtc_seeded(session_key: &[u8; 32]) -> Self {
        Self::build_matrix(15, 5.0, 3.0, session_key)
    }

    pub fn new_tls() -> Self {
        let mut seed = [0u8; 32];
        OsRng.fill(&mut seed);
        Self::new_tls_seeded(&seed)
    }
    pub fn new_webrtc() -> Self {
        let mut seed = [0u8; 32];
        OsRng.fill(&mut seed);
        Self::new_webrtc_seeded(&seed)
    }

    pub fn next_iat(&mut self) -> Duration {
        let current_idx = self.find_closest_state(self.current_state);
        let rand_val: f64 = OsRng.gen();
        let mut cumulative = 0.0f64;
        let mut next_idx = current_idx;
        for (j, &prob) in self.transition_matrix[current_idx].iter().enumerate() {
            cumulative += prob;
            if rand_val <= cumulative {
                next_idx = j;
                break;
            }
        }
        self.current_state = self.state_space[next_idx];
        Duration::from_millis(self.current_state as u64)
    }

    pub fn generate_iat(&mut self, protocol: ProtocolType) -> Duration {
        let iat = self.next_iat();
        match protocol {
            ProtocolType::Tls13 => iat.clamp(Duration::from_millis(20), Duration::from_millis(200)),
            ProtocolType::WebRtc => iat.clamp(Duration::from_millis(5), Duration::from_millis(50)),
            ProtocolType::Quic => iat.clamp(Duration::from_millis(10), Duration::from_millis(100)),
            ProtocolType::Http2 => iat.clamp(Duration::from_millis(50), Duration::from_millis(300)),
        }
    }

    fn find_closest_state(&self, value: f64) -> usize {
        self.state_space
            .iter()
            .enumerate()
            .min_by(|(_, &a), (_, &b)| {
                (a - value)
                    .abs()
                    .partial_cmp(&(b - value).abs())
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
            .map(|(i, _)| i)
            .unwrap_or(0)
    }
}

pub struct TrafficShaper {
    markov: MarkovState,
    protocol: ProtocolType,
    last_transmit: Option<Instant>,
    profile: PaddingProfile,
    session_key: [u8; 32],
    pad_counter: u64,
}

impl TrafficShaper {
    pub fn new(protocol: ProtocolType) -> Self {
        let mut session_key = [0u8; 32];
        OsRng.fill(&mut session_key);
        Self::new_with_key(protocol, &session_key)
    }

    pub fn new_with_key(protocol: ProtocolType, session_key: &[u8; 32]) -> Self {
        let markov = match protocol {
            ProtocolType::Tls13 | ProtocolType::Quic | ProtocolType::Http2 =>
                MarkovState::new_tls_seeded(session_key),
            ProtocolType::WebRtc =>
                MarkovState::new_webrtc_seeded(session_key),
        };
        let profile = PaddingProfile {
            protocol,
            min_size: match protocol {
                ProtocolType::Tls13  => TLS_MIN_SIZE,
                ProtocolType::WebRtc => SRTP_MIN_SIZE,
                ProtocolType::Quic   => 120,
                ProtocolType::Http2  => 100,
            },
            max_size: match protocol {
                ProtocolType::Tls13  => TLS_MAX_SIZE,
                ProtocolType::WebRtc => SRTP_MAX_SIZE,
                ProtocolType::Quic   => 1200,
                ProtocolType::Http2  => 16384,
            },
            mean_size: match protocol {
                ProtocolType::Tls13  => TLS_MEAN_SIZE,
                ProtocolType::WebRtc => SRTP_MEAN_SIZE,
                ProtocolType::Quic   => 500,
                ProtocolType::Http2  => 1500,
            },
        };
        TrafficShaper {
            markov,
            protocol,
            last_transmit: None,
            profile,
            session_key: *session_key,
            pad_counter: 0,
        }
    }

    pub fn shape_packet(&mut self, packet: &[u8]) -> Vec<u8> {
        let target = self.compute_target_size();
        if packet.len() >= target {
            return packet.to_vec();
        }
        let pad_len = target - packet.len();
        let padding = self.generate_csprng_padding(pad_len);
        let mut out = packet.to_vec();
        out.extend_from_slice(&padding);
        out
    }

    pub fn strip_padding(shaped: &[u8], original_len: usize) -> &[u8] {
        &shaped[..original_len.min(shaped.len())]
    }

    fn generate_csprng_padding(&mut self, length: usize) -> Vec<u8> {
        let mut nonce = [0u8; 12];
        nonce[0..8].copy_from_slice(&self.pad_counter.to_le_bytes());
        nonce[8..12].copy_from_slice(b"PAD\0");
        self.pad_counter += 1;

        let mut buf = vec![0u8; length];
        let mut cipher = ChaCha20::new(
            ChaChaKey::from_slice(self.session_key.as_slice()),
            ChaChaNonce::from_slice(nonce.as_slice()),
        );
        cipher.apply_keystream(&mut buf);
        buf
    }

    fn compute_target_size(&self) -> usize {
        let u1: f64 = OsRng.gen_range(0.0001..1.0);
        let u2: f64 = OsRng.gen_range(0.0001..1.0);
        let z = (-2.0 * u1.ln()).sqrt() * ((2.0 * std::f64::consts::PI * u2).sin());
        let mean = self.profile.mean_size as f64;
        let stddev = (self.profile.max_size - self.profile.min_size) as f64 / 6.0;
        let target = (mean + z * stddev).round() as usize;
        target.clamp(self.profile.min_size, self.profile.max_size)
    }

    pub fn get_next_iat(&mut self) -> Duration {
        self.markov.generate_iat(self.protocol)
    }

    pub fn record_transmit(&mut self) -> Duration {
        let wait = self.get_next_iat();
        self.last_transmit = Some(Instant::now());
        wait
    }

    pub fn profile(&self) -> &PaddingProfile { &self.profile }
    pub fn protocol(&self) -> ProtocolType { self.protocol }
    pub fn session_key(&self) -> [u8; 32] { self.session_key }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tls_shaper_size_bounds() {
        let mut shaper = TrafficShaper::new(ProtocolType::Tls13);
        let shaped = shaper.shape_packet(b"Test");
        assert!(shaped.len() >= TLS_MIN_SIZE);
        assert!(shaped.len() <= TLS_MAX_SIZE);
    }

    #[test]
    fn test_webrtc_shaper_size_bounds() {
        let mut shaper = TrafficShaper::new(ProtocolType::WebRtc);
        let shaped = shaper.shape_packet(b"Test");
        assert!(shaped.len() >= SRTP_MIN_SIZE);
        assert!(shaped.len() <= SRTP_MAX_SIZE);
    }

    #[test]
    fn test_no_truncation_on_large_packet() {
        let mut shaper = TrafficShaper::new(ProtocolType::Tls13);
        let big = vec![0xABu8; TLS_MAX_SIZE + 100];
        let shaped = shaper.shape_packet(&big);
        assert_eq!(shaped.len(), big.len());
    }

    #[test]
    fn test_padding_is_not_all_zeros() {
        let mut shaper = TrafficShaper::new(ProtocolType::Tls13);
        let shaped = shaper.shape_packet(b"A");
        let zero_count = shaped.iter().filter(|&&b| b == 0).count();
        assert!(zero_count < shaped.len() / 20 + 5);
    }

    #[test]
    fn test_iat_generation_bounds_tls() {
        let mut shaper = TrafficShaper::new(ProtocolType::Tls13);
        for _ in 0..50 {
            let iat = shaper.get_next_iat();
            assert!(iat.as_millis() >= 20, "IAT below TLS min");
            assert!(iat.as_millis() <= 200, "IAT above TLS max");
        }
    }

    #[test]
    fn test_markov_determinism_with_same_seed() {
        let seed = [0x42u8; 32];
        let m1 = MarkovState::new_tls_seeded(&seed);
        let m2 = MarkovState::new_tls_seeded(&seed);
        assert_eq!(m1.current_state, m2.current_state);
        assert_eq!(m1.transition_matrix, m2.transition_matrix);
    }

    #[test]
    fn test_find_closest_state_correct() {
        let seed = [0u8; 32];
        let ms = MarkovState::new_tls_seeded(&seed);
        let idx = ms.find_closest_state(ms.state_space[0]);
        assert_eq!(idx, 0);
    }
}
