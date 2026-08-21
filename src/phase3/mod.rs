mod shaper;
mod plugin;

pub use shaper::{
    TrafficShaper, ProtocolType, PaddingProfile,
    MarkovState, TLS_MIN_SIZE, TLS_MAX_SIZE, TLS_MEAN_SIZE,
    SRTP_MIN_SIZE, SRTP_MAX_SIZE, SRTP_MEAN_SIZE,
    TLS_IAT_MEAN_MS, TLS_IAT_STDDEV_MS,
    WEBRTC_IAT_MEAN_MS, WEBRTC_IAT_STDDEV_MS,
};

pub use plugin::{
    MorphPlugin, PluginRegistry,
    Tls13Plugin, QuicPlugin, WebRtcPlugin, Http2Plugin,
    TLS_RECORD_OVERHEAD, QUIC_INITIAL_OVERHEAD, SRTP_OVERHEAD, HTTP2_FRAME_OVERHEAD,
    FRAME_LEN_PREFIX,
};

pub fn wrap_for_path(path_idx: usize, share_packet: &[u8], session_key: &[u8; 32]) -> Vec<u8> {
    match path_idx % 4 {
        0 => Tls13Plugin.encapsulate(share_packet, session_key),
        1 => QuicPlugin.encapsulate(share_packet, session_key),
        2 => WebRtcPlugin.encapsulate(share_packet, session_key),
        _ => Http2Plugin.encapsulate(share_packet, session_key),
    }
}

pub fn try_strip_transport_frame(data: &[u8]) -> Option<Vec<u8>> {
    strip_tls(data)
        .or_else(|| strip_quic(data))
        .or_else(|| strip_websocket(data))
        .or_else(|| strip_http2(data))
}

fn frame_extract(inner: &[u8]) -> Option<Vec<u8>> {
    if inner.len() < FRAME_LEN_PREFIX { return None; }
    let share_len = u32::from_le_bytes(inner[0..4].try_into().ok()?) as usize;
    if inner.len() < FRAME_LEN_PREFIX + share_len { return None; }
    Some(inner[FRAME_LEN_PREFIX..FRAME_LEN_PREFIX + share_len].to_vec())
}

fn strip_tls(data: &[u8]) -> Option<Vec<u8>> {
    if data.len() >= TLS_RECORD_OVERHEAD + FRAME_LEN_PREFIX
        && data[0] == 0x17 && data[1] == 0x03 && data[2] == 0x03 {
        frame_extract(&data[TLS_RECORD_OVERHEAD..])
    } else {
        None
    }
}

fn strip_quic(data: &[u8]) -> Option<Vec<u8>> {
    if data.len() >= QUIC_INITIAL_OVERHEAD + FRAME_LEN_PREFIX && data[0] & 0xC0 == 0x40 {
        frame_extract(&data[QUIC_INITIAL_OVERHEAD..])
    } else {
        None
    }
}

fn strip_websocket(data: &[u8]) -> Option<Vec<u8>> {
    if data.len() < 6 || data[0] != 0x82 || data[1] & 0x80 == 0 { return None; }
    let len7 = (data[1] & 0x7F) as usize;
    let header_end = if len7 < 126 { 2 } else { 4 };
    if data.len() < header_end + 4 { return None; }
    let mask = [data[header_end], data[header_end+1], data[header_end+2], data[header_end+3]];
    let unmasked: Vec<u8> = data[header_end + 4..]
        .iter()
        .enumerate()
        .map(|(i, &b)| b ^ mask[i % 4])
        .collect();
    frame_extract(&unmasked)
}

fn strip_http2(data: &[u8]) -> Option<Vec<u8>> {
    if data.len() >= HTTP2_FRAME_OVERHEAD + FRAME_LEN_PREFIX
        && data[3] == 0x00 && data[5] & 0x80 == 0 {
        frame_extract(&data[HTTP2_FRAME_OVERHEAD..])
    } else {
        None
    }
}

use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct MorphedPacket {
    pub payload: Vec<u8>,
    pub protocol: ProtocolType,
    pub delay: Duration,
    pub shaped_at: Instant,
}

pub struct MorphingResult {
    pub packet: MorphedPacket,
    pub original_size: usize,
    pub target_size: usize,
    pub overhead: usize,
}

pub struct ProtocolMorpher {
    registry: PluginRegistry,
    current_protocol: ProtocolType,
    shaper: TrafficShaper,
    last_shape: Option<Instant>,
}

impl ProtocolMorpher {
    pub fn new(protocol: ProtocolType) -> Self {
        ProtocolMorpher {
            registry: PluginRegistry::default(),
            current_protocol: protocol,
            shaper: TrafficShaper::new(protocol),
            last_shape: None,
        }
    }

    pub fn morph(&mut self, packet: &[u8]) -> MorphingResult {
        let original_size = packet.len();
        let sk = self.shaper.session_key();
        let shaped = self.registry.get(self.current_protocol).encapsulate(packet, &sk);
        let target_size = shaped.len();
        let delay = self.shaper.record_transmit();
        self.last_shape = Some(Instant::now());

        MorphingResult {
            packet: MorphedPacket {
                payload: shaped,
                protocol: self.current_protocol,
                delay,
                shaped_at: Instant::now(),
            },
            original_size,
            target_size,
            overhead: target_size.saturating_sub(original_size),
        }
    }

    pub fn morph_batch(&mut self, packets: &[Vec<u8>]) -> Vec<MorphedPacket> {
        packets.iter().map(|p| self.morph(p).packet).collect()
    }

    pub fn get_stats(&self) -> ProtocolStats {
        ProtocolStats {
            protocol: self.current_protocol,
            min_size: self.shaper.profile().min_size,
            max_size: self.shaper.profile().max_size,
            mean_size: self.shaper.profile().mean_size,
        }
    }

    pub fn switch_plugin(&mut self, protocol: ProtocolType) {
        self.current_protocol = protocol;
        self.shaper = TrafficShaper::new(protocol);
    }

    pub fn switch_protocol(&mut self, protocol: ProtocolType) {
        self.switch_plugin(protocol);
    }

    pub fn current_mtu_overhead(&self) -> usize {
        self.registry.get(self.current_protocol).mtu_overhead()
    }

    pub fn registry_mut(&mut self) -> &mut PluginRegistry {
        &mut self.registry
    }
}

#[derive(Debug, Clone)]
pub struct ProtocolStats {
    pub protocol: ProtocolType,
    pub min_size: usize,
    pub max_size: usize,
    pub mean_size: usize,
}

pub struct SteganographicEmbedder {
    #[allow(dead_code)]
    cover_protocol: ProtocolType,
    embedding_rate: f64,
}

impl SteganographicEmbedder {
    pub fn new(cover_protocol: ProtocolType, rate: f64) -> Self {
        SteganographicEmbedder { cover_protocol, embedding_rate: rate.clamp(0.1, 0.9) }
    }

    pub fn embed(&self, cover: &mut [u8], covert: &[u8]) {
        let capacity = (cover.len() as f64 * self.embedding_rate) as usize;
        let mut ci = 0;
        for cell in cover.iter_mut().take(capacity) {
            if ci < covert.len() {
                *cell = (*cell & 0xFE) | (covert[ci] & 0x01);
                ci += 1;
            }
        }
    }

    pub fn extract(&self, cover: &[u8], expected_len: usize) -> Vec<u8> {
        cover
            .chunks(8)
            .take(expected_len)
            .map(|chunk| {
                chunk.iter().enumerate().fold(0u8, |acc, (i, &b)| acc | ((b & 0x01) << i))
            })
            .collect()
    }
}

pub struct TrafficAnalyzer {
    sizes: Vec<usize>,
    iats: Vec<Duration>,
    protocol: ProtocolType,
}

impl TrafficAnalyzer {
    pub fn new(protocol: ProtocolType) -> Self {
        TrafficAnalyzer { sizes: Vec::new(), iats: Vec::new(), protocol }
    }

    pub fn record_packet(&mut self, size: usize, iat: Duration) {
        self.sizes.push(size);
        self.iats.push(iat);
    }

    pub fn compute_stats(&self) -> AnalysisResult {
        let size_mean = if self.sizes.is_empty() {
            0.0
        } else {
            self.sizes.iter().sum::<usize>() as f64 / self.sizes.len() as f64
        };
        let size_stddev = if self.sizes.len() < 2 {
            0.0
        } else {
            let v = self.sizes.iter().map(|&s| (s as f64 - size_mean).powi(2)).sum::<f64>()
                / (self.sizes.len() - 1) as f64;
            v.sqrt()
        };
        let iat_mean = if self.iats.is_empty() {
            Duration::ZERO
        } else {
            let total: u64 = self.iats.iter().map(|d| d.as_nanos() as u64).sum();
            Duration::from_nanos(total / self.iats.len() as u64)
        };
        AnalysisResult {
            protocol: self.protocol,
            packet_count: self.sizes.len(),
            size_mean,
            size_stddev,
            iat_mean,
            evasion_score: self.compute_evasion_score(size_mean, size_stddev),
        }
    }

    fn compute_evasion_score(&self, size_mean: f64, size_stddev: f64) -> f64 {
        let expected_mean = match self.protocol {
            ProtocolType::Tls13  => TLS_MEAN_SIZE as f64,
            ProtocolType::WebRtc => SRTP_MEAN_SIZE as f64,
            ProtocolType::Quic   => 500.0,
            ProtocolType::Http2  => 1500.0,
        };
        let expected_stddev = match self.protocol {
            ProtocolType::Tls13  => TLS_IAT_STDDEV_MS,
            ProtocolType::WebRtc => WEBRTC_IAT_STDDEV_MS,
            ProtocolType::Quic   => 30.0,
            ProtocolType::Http2  => 100.0,
        };
        let me = (size_mean - expected_mean).abs() / expected_mean;
        let se = (size_stddev - expected_stddev).abs() / expected_stddev;
        1.0 - ((me + se) / 2.0).min(1.0)
    }
}

#[derive(Debug, Clone)]
pub struct AnalysisResult {
    pub protocol: ProtocolType,
    pub packet_count: usize,
    pub size_mean: f64,
    pub size_stddev: f64,
    pub iat_mean: Duration,
    pub evasion_score: f64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_morphing() {
        let mut morpher = ProtocolMorpher::new(ProtocolType::Tls13);
        let result = morpher.morph(b"test");
        assert!(result.target_size >= TLS_MIN_SIZE);
        assert!(result.packet.protocol == ProtocolType::Tls13);
    }

    #[test]
    fn test_batch_morphing() {
        let mut morpher = ProtocolMorpher::new(ProtocolType::WebRtc);
        let packets = vec![b"pkt1".to_vec(), b"pkt2".to_vec()];
        let morphed = morpher.morph_batch(&packets);
        assert_eq!(morphed.len(), 2);
        assert!(morphed[0].payload.len() >= SRTP_MIN_SIZE);
    }

    #[test]
    fn test_analyzer() {
        let mut analyzer = TrafficAnalyzer::new(ProtocolType::Tls13);
        analyzer.record_packet(480, Duration::from_millis(87));
        analyzer.record_packet(500, Duration::from_millis(90));
        let stats = analyzer.compute_stats();
        assert!(stats.evasion_score > 0.5);
    }

    #[test]
    fn test_switch_plugin_changes_overhead() {
        let mut morpher = ProtocolMorpher::new(ProtocolType::Tls13);
        let tls_oh = morpher.current_mtu_overhead();
        morpher.switch_plugin(ProtocolType::Quic);
        let quic_oh = morpher.current_mtu_overhead();
        assert_eq!(tls_oh, TLS_RECORD_OVERHEAD);
        assert_eq!(quic_oh, QUIC_INITIAL_OVERHEAD);
        assert_ne!(tls_oh, quic_oh);
    }

    #[test]
    fn test_switch_protocol_backward_compat() {
        let mut morpher = ProtocolMorpher::new(ProtocolType::Tls13);
        morpher.switch_protocol(ProtocolType::Http2);
        assert_eq!(morpher.current_mtu_overhead(), HTTP2_FRAME_OVERHEAD);
    }

    #[test]
    fn test_morph_uses_plugin_encapsulate() {
        let mut morpher = ProtocolMorpher::new(ProtocolType::Tls13);
        morpher.switch_plugin(ProtocolType::WebRtc);
        let result = morpher.morph(b"small");
        assert!(result.target_size >= SRTP_MIN_SIZE);
        assert_eq!(result.packet.protocol, ProtocolType::WebRtc);
    }
}
