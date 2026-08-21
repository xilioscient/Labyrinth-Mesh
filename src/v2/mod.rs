pub mod afxdp;
pub mod auth;
pub mod bpf_lsm;
pub mod cover_traffic;
pub mod tpm_identity;
pub mod hybrid_kem;
pub mod ratchet;
pub mod replay;
pub mod sss_pq;
pub mod threshold_kem;
pub mod xdp_rx;
pub mod xdp_tx;

pub use auth::{
    build_v2_ctrl, generate_sign_keypair, parse_v2_ctrl, pk_fingerprint,
    sign_bytes, verify_sign,
    SignPk, SignSk, SigningBackend,
    CTRL_MAGIC, CTRL_V2_LEN, KEM_PK_LEN, SIGN_PK_LEN, SIGN_SIG_LEN,
};

pub use tpm_identity::TpmIdentity;

pub use bpf_lsm::{load_lsm_policy, LsmHandle, LABYRINTH_LSM_SOURCE};

pub use sss_pq::{
    auth_tag, generate_keypair, kem_decapsulate, kem_encapsulate, split_and_tag,
    verify_and_recover, verify_auth_tag, SessionKey, TaggedShare, AUTH_TAG_LEN,
    MTU, SHAMIR_K, SHAMIR_N,
};

pub use ratchet::{ratchet_key, KeyRatchet, RATCHET_INTERVAL};

pub use hybrid_kem::{
    hybrid_encapsulate_from_wire, HybridReceiverKeypair, HybridSenderOutput,
    HYBRID_KEM_WIRE_LEN, HYBRID_KYBER_CT_LEN, HYBRID_PK_WIRE_LEN,
};

pub use replay::ReplayWindow;

pub use threshold_kem::{
    tkem_send, tkem_relay_decapsulate, tkem_recover,
    encode_pk_bundle, decode_pk_bundle, encode_ct_bundle, decode_and_recover,
    TkemSender, RelayPacket,
    TKEM_MIN_THRESHOLD, TKEM_PK_MAGIC, TKEM_CT_MAGIC,
};

pub use cover_traffic::{
    load_cover_program, read_stats, set_burst_cap_packets, set_target_bps,
    CBR_DIVISOR_NS, CBR_MAX_CREDIT_BYTES, CBR_TIMER_INTERVAL_NS, COVER_INTERVAL_NS,
    COVER_MTU, COVER_TRAFFIC_XDP_SOURCE, CoverStats, CoverTrafficHandle, TARGET_BPS,
};

pub use afxdp::{XskSocket, FRAME_SIZE as XSK_FRAME_SIZE, RING_SIZE as XSK_RING_SIZE};

pub use xdp_tx::{CDN_POOL, LABYRINTH_TX_XDP_SOURCE, enqueue_fragment_xsk};

pub use xdp_rx::{LABYRINTH_RX_XDP_SOURCE, VerifiedFragment};
