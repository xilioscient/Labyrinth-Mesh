use chacha20::cipher::{KeyIvInit, StreamCipher};
use chacha20::{ChaCha20, Key as ChaChaKey, Nonce as ChaChaNonce};
use super::shaper::{ProtocolType, SRTP_MEAN_SIZE, TLS_MEAN_SIZE};

pub const TLS_RECORD_OVERHEAD: usize = 5;
pub const QUIC_INITIAL_OVERHEAD: usize = 11;
pub const SRTP_OVERHEAD: usize = 6;
pub const HTTP2_FRAME_OVERHEAD: usize = 9;
pub const FRAME_LEN_PREFIX: usize = 4;

pub trait MorphPlugin: Send + Sync {
    fn protocol_name(&self) -> &'static str;
    fn encapsulate(&self, payload: &[u8], session_key: &[u8; 32]) -> Vec<u8>;
    fn decapsulate(&self, packet: &[u8], session_key: &[u8; 32], orig_len: usize) -> Option<Vec<u8>>;
    fn mtu_overhead(&self) -> usize;
    fn target_packet_size(&self) -> usize;
}

fn csprng_pad(seed: &[u8; 32], counter: u64, length: usize) -> Vec<u8> {
    let mut nonce = [0u8; 12];
    nonce[0..8].copy_from_slice(&counter.to_le_bytes());
    nonce[8..12].copy_from_slice(b"PAD\0");
    let mut buf = vec![0u8; length];
    let mut cipher = ChaCha20::new(
        ChaChaKey::from_slice(seed),
        ChaChaNonce::from_slice(&nonce),
    );
    cipher.apply_keystream(&mut buf);
    buf
}

fn build_inner(payload: &[u8], session_key: &[u8; 32], target_size: usize) -> Vec<u8> {
    let share_len = payload.len();
    let prefixed_len = FRAME_LEN_PREFIX + share_len;
    let padding_len = target_size.saturating_sub(prefixed_len);
    let mut inner = Vec::with_capacity(prefixed_len + padding_len);
    inner.extend_from_slice(&(share_len as u32).to_le_bytes());
    inner.extend_from_slice(payload);
    if padding_len > 0 {
        let pad = csprng_pad(session_key, share_len as u64, padding_len);
        inner.extend_from_slice(&pad);
    }
    inner
}

fn extract_inner(inner: &[u8], orig_len: usize) -> Option<Vec<u8>> {
    if inner.len() < FRAME_LEN_PREFIX { return None; }
    let share_len = u32::from_le_bytes(inner[0..4].try_into().ok()?) as usize;
    if orig_len > 0 && share_len != orig_len { return None; }
    if inner.len() < FRAME_LEN_PREFIX + share_len { return None; }
    Some(inner[FRAME_LEN_PREFIX..FRAME_LEN_PREFIX + share_len].to_vec())
}

pub struct Tls13Plugin;
pub struct QuicPlugin;
pub struct WebRtcPlugin;
pub struct Http2Plugin;

impl MorphPlugin for Tls13Plugin {
    fn protocol_name(&self) -> &'static str { "tls1.3" }

    fn encapsulate(&self, payload: &[u8], session_key: &[u8; 32]) -> Vec<u8> {
        let inner = build_inner(payload, session_key, TLS_MEAN_SIZE - TLS_RECORD_OVERHEAD);
        let inner_len = inner.len();
        let mut out = Vec::with_capacity(TLS_RECORD_OVERHEAD + inner_len);
        out.push(0x17);
        out.push(0x03);
        out.push(0x03);
        out.push((inner_len >> 8) as u8);
        out.push(inner_len as u8);
        out.extend_from_slice(&inner);
        out
    }

    fn decapsulate(&self, packet: &[u8], _key: &[u8; 32], orig_len: usize) -> Option<Vec<u8>> {
        if packet.len() < TLS_RECORD_OVERHEAD + FRAME_LEN_PREFIX { return None; }
        if packet[0] != 0x17 || packet[1] != 0x03 || packet[2] != 0x03 { return None; }
        extract_inner(&packet[TLS_RECORD_OVERHEAD..], orig_len)
    }

    fn mtu_overhead(&self) -> usize { TLS_RECORD_OVERHEAD }
    fn target_packet_size(&self) -> usize { TLS_MEAN_SIZE }
}

impl MorphPlugin for QuicPlugin {
    fn protocol_name(&self) -> &'static str { "quic" }

    fn encapsulate(&self, payload: &[u8], session_key: &[u8; 32]) -> Vec<u8> {
        let inner = build_inner(payload, session_key, 500 - QUIC_INITIAL_OVERHEAD);
        let inner_len = inner.len();
        let mut out = Vec::with_capacity(QUIC_INITIAL_OVERHEAD + inner_len);
        out.push(0x41);
        out.extend_from_slice(&session_key[0..8]);
        out.push(session_key[8]);
        out.push(session_key[9]);
        out.extend_from_slice(&inner);
        out
    }

    fn decapsulate(&self, packet: &[u8], _key: &[u8; 32], orig_len: usize) -> Option<Vec<u8>> {
        if packet.len() < QUIC_INITIAL_OVERHEAD + FRAME_LEN_PREFIX { return None; }
        if packet[0] & 0xC0 != 0x40 { return None; }
        extract_inner(&packet[QUIC_INITIAL_OVERHEAD..], orig_len)
    }

    fn mtu_overhead(&self) -> usize { QUIC_INITIAL_OVERHEAD }
    fn target_packet_size(&self) -> usize { 500 }
}

impl MorphPlugin for WebRtcPlugin {
    fn protocol_name(&self) -> &'static str { "webrtc" }

    fn encapsulate(&self, payload: &[u8], session_key: &[u8; 32]) -> Vec<u8> {
        let inner = build_inner(payload, session_key, SRTP_MEAN_SIZE - SRTP_OVERHEAD - 4);
        let inner_len = inner.len();
        let mask: [u8; 4] = [session_key[0], session_key[1], session_key[2], session_key[3]];
        let masked: Vec<u8> = inner.iter().enumerate().map(|(i, &b)| b ^ mask[i % 4]).collect();
        let mut out = Vec::with_capacity(2 + 4 + masked.len());
        out.push(0x82);
        if inner_len < 126 {
            out.push(0x80 | inner_len as u8);
        } else {
            out.push(0x80 | 126u8);
            out.push((inner_len >> 8) as u8);
            out.push(inner_len as u8);
        }
        out.extend_from_slice(&mask);
        out.extend_from_slice(&masked);
        out
    }

    fn decapsulate(&self, packet: &[u8], _key: &[u8; 32], orig_len: usize) -> Option<Vec<u8>> {
        if packet.len() < 6 { return None; }
        if packet[0] != 0x82 { return None; }
        if packet[1] & 0x80 == 0 { return None; }
        let len7 = (packet[1] & 0x7F) as usize;
        let header_end = if len7 < 126 { 2 } else { 4 };
        if packet.len() < header_end + 4 { return None; }
        let mask = [packet[header_end], packet[header_end+1], packet[header_end+2], packet[header_end+3]];
        let unmasked: Vec<u8> = packet[header_end+4..]
            .iter()
            .enumerate()
            .map(|(i, &b)| b ^ mask[i % 4])
            .collect();
        extract_inner(&unmasked, orig_len)
    }

    fn mtu_overhead(&self) -> usize { SRTP_OVERHEAD }
    fn target_packet_size(&self) -> usize { SRTP_MEAN_SIZE }
}

impl MorphPlugin for Http2Plugin {
    fn protocol_name(&self) -> &'static str { "http2" }

    fn encapsulate(&self, payload: &[u8], session_key: &[u8; 32]) -> Vec<u8> {
        let inner = build_inner(payload, session_key, 1500 - HTTP2_FRAME_OVERHEAD);
        let inner_len = inner.len();
        let stream_id = (u32::from_le_bytes([session_key[4], session_key[5], session_key[6], session_key[7]]) & 0x7FFFFFFF).max(1);
        let mut out = Vec::with_capacity(HTTP2_FRAME_OVERHEAD + inner_len);
        out.push(((inner_len >> 16) & 0xFF) as u8);
        out.push(((inner_len >> 8) & 0xFF) as u8);
        out.push((inner_len & 0xFF) as u8);
        out.push(0x00);
        out.push(0x00);
        out.push(((stream_id >> 24) & 0x7F) as u8);
        out.push(((stream_id >> 16) & 0xFF) as u8);
        out.push(((stream_id >> 8) & 0xFF) as u8);
        out.push((stream_id & 0xFF) as u8);
        out.extend_from_slice(&inner);
        out
    }

    fn decapsulate(&self, packet: &[u8], _key: &[u8; 32], orig_len: usize) -> Option<Vec<u8>> {
        if packet.len() < HTTP2_FRAME_OVERHEAD + FRAME_LEN_PREFIX { return None; }
        if packet[3] != 0x00 { return None; }
        if packet[5] & 0x80 != 0 { return None; }
        extract_inner(&packet[HTTP2_FRAME_OVERHEAD..], orig_len)
    }

    fn mtu_overhead(&self) -> usize { HTTP2_FRAME_OVERHEAD }
    fn target_packet_size(&self) -> usize { 1500 }
}

pub struct PluginRegistry {
    tls13:  Box<dyn MorphPlugin>,
    quic:   Box<dyn MorphPlugin>,
    webrtc: Box<dyn MorphPlugin>,
    http2:  Box<dyn MorphPlugin>,
}

impl PluginRegistry {
    #[allow(clippy::should_implement_trait)]
    pub fn default() -> Self {
        Self {
            tls13:  Box::new(Tls13Plugin),
            quic:   Box::new(QuicPlugin),
            webrtc: Box::new(WebRtcPlugin),
            http2:  Box::new(Http2Plugin),
        }
    }

    pub fn get(&self, protocol: ProtocolType) -> &dyn MorphPlugin {
        match protocol {
            ProtocolType::Tls13  => &*self.tls13,
            ProtocolType::Quic   => &*self.quic,
            ProtocolType::WebRtc => &*self.webrtc,
            ProtocolType::Http2  => &*self.http2,
        }
    }

    pub fn register(&mut self, protocol: ProtocolType, plugin: Box<dyn MorphPlugin>) {
        match protocol {
            ProtocolType::Tls13  => self.tls13  = plugin,
            ProtocolType::Quic   => self.quic   = plugin,
            ProtocolType::WebRtc => self.webrtc = plugin,
            ProtocolType::Http2  => self.http2  = plugin,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; 32] = [0x42u8; 32];
    const PAYLOAD: &[u8] = b"Hello DMPOT plugin system";

    #[test]
    fn registry_get_returns_correct_plugin_for_every_protocol() {
        let reg = PluginRegistry::default();
        assert_eq!(reg.get(ProtocolType::Tls13).protocol_name(),  "tls1.3");
        assert_eq!(reg.get(ProtocolType::Quic).protocol_name(),   "quic");
        assert_eq!(reg.get(ProtocolType::WebRtc).protocol_name(), "webrtc");
        assert_eq!(reg.get(ProtocolType::Http2).protocol_name(),  "http2");
    }

    #[test]
    fn encapsulate_decapsulate_roundtrip_all_protocols() {
        let reg = PluginRegistry::default();
        let protos = [
            ProtocolType::Tls13,
            ProtocolType::Quic,
            ProtocolType::WebRtc,
            ProtocolType::Http2,
        ];
        for proto in protos {
            let plugin = reg.get(proto);
            let enc = plugin.encapsulate(PAYLOAD, &KEY);
            assert!(enc.len() > PAYLOAD.len(), "plugin {} did not grow payload", plugin.protocol_name());
            let dec = plugin.decapsulate(&enc, &KEY, PAYLOAD.len()).expect("decap failed");
            assert_eq!(dec, PAYLOAD, "roundtrip failed for {}", plugin.protocol_name());
        }
    }

    #[test]
    fn encapsulate_produces_correct_magic_bytes() {
        let key = [0u8; 32];
        assert_eq!(Tls13Plugin.encapsulate(b"x", &key)[0], 0x17);
        assert_eq!(QuicPlugin.encapsulate(b"x", &key)[0] & 0xC0, 0x40);
        assert_eq!(WebRtcPlugin.encapsulate(b"x", &key)[0], 0x82);
        assert_eq!(Http2Plugin.encapsulate(b"x", &key)[3], 0x00);
    }

    #[test]
    fn decapsulate_returns_none_when_packet_too_short() {
        let reg = PluginRegistry::default();
        let result = reg.get(ProtocolType::Tls13).decapsulate(b"short", &KEY, 100);
        assert!(result.is_none());
    }

    #[test]
    fn mtu_overhead_values_are_canonical() {
        let reg = PluginRegistry::default();
        assert_eq!(reg.get(ProtocolType::Tls13).mtu_overhead(),  TLS_RECORD_OVERHEAD);
        assert_eq!(reg.get(ProtocolType::Quic).mtu_overhead(),   QUIC_INITIAL_OVERHEAD);
        assert_eq!(reg.get(ProtocolType::WebRtc).mtu_overhead(), SRTP_OVERHEAD);
        assert_eq!(reg.get(ProtocolType::Http2).mtu_overhead(),  HTTP2_FRAME_OVERHEAD);
    }

    #[test]
    fn registry_register_replaces_slot_and_leaves_others_intact() {
        struct NullPlugin;
        impl MorphPlugin for NullPlugin {
            fn protocol_name(&self) -> &'static str { "null" }
            fn encapsulate(&self, p: &[u8], _: &[u8; 32]) -> Vec<u8> { p.to_vec() }
            fn decapsulate(&self, p: &[u8], _: &[u8; 32], n: usize) -> Option<Vec<u8>> {
                Some(p[..n.min(p.len())].to_vec())
            }
            fn mtu_overhead(&self) -> usize { 0 }
            fn target_packet_size(&self) -> usize { 0 }
        }

        let mut reg = PluginRegistry::default();
        reg.register(ProtocolType::Tls13, Box::new(NullPlugin));
        assert_eq!(reg.get(ProtocolType::Tls13).protocol_name(), "null");
        assert_eq!(reg.get(ProtocolType::Quic).protocol_name(),   "quic");
        assert_eq!(reg.get(ProtocolType::WebRtc).protocol_name(), "webrtc");
        assert_eq!(reg.get(ProtocolType::Http2).protocol_name(),  "http2");
    }
}
