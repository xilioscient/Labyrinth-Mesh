# Labyrinth-Mesh

**Post-quantum resilient multi-path tunnel** — Hybrid KEM (X25519 + Kyber-1024) · BLAKE3 auth · Shamir 3-of-5 SSS · Dilithium3 identity · Threshold KEM · Adaptive Scheduler · TLS 1.3 + HTTP/2 steganography

---

## What it does

Labyrinth-Mesh takes any payload, splits it into 5 shares using Shamir Secret Sharing over GF(2⁸), authenticates each share with BLAKE3, negotiates the session key via Hybrid KEM (X25519 + Kyber-1024 combined), and dispatches shares over N separate paths. The receiver reconstructs the original from any 3 of the 5 shares.

The session key combines classical and post-quantum primitives — secure against both RSA-breaking and quantum adversaries simultaneously. Each share is independently timed and routed; no single path carries enough information to reconstruct the payload.

**`--http` mode** replaces raw UDP with real TLS 1.3 + HTTP/2 transport. The receiver generates a self-signed cert at runtime, exchanges it over the Dilithium3-signed control channel, and the sender connects using a custom TLS 1.3 stack with a Chrome 124 ClientHello (JA3/JA4 fingerprint identical to Chrome 124). Shares are POSTed with Chrome headers and bucket-padded sizes.

---

## Quickstart (3 terminals)

```bash
# T1 — receiver
labyrinth recv --ctrl 0.0.0.0:8199 --udp 0.0.0.0:8200 --mgmt 0.0.0.0:9090

# T2 — live TUI
labyrinth-tui --mgmt 127.0.0.1:9090

# T3 — sender (Ctrl+D to close)
labyrinth send --to 127.0.0.1:8199
```

HTTP/2 mode (TLS fingerprint identical to Chrome 124 — JA3/JA4):

```bash
# T1
labyrinth recv --ctrl 0.0.0.0:8199 --udp 0.0.0.0:443 --http --sign

# T2
labyrinth send --to 127.0.0.1:8199 --remotes 127.0.0.1:443 --http
```

---

## Binaries

| Binary | Description |
|---|---|
| `labyrinth` | CLI: `send` `recv` `status` `setup` |
| `labyrinth-tui` | Ratatui TUI dashboard, 500ms polling |
| `labyrinth-server` | Standalone management plane |
| `labyrinth_mesh` | Mesh node configured via env vars |

---

## CLI — `labyrinth`

### `labyrinth send`

```
--to <addr>           Receiver ctrl address (KEM exchange)  [default: 127.0.0.1:8199]
--file, -f <path>     File to send (default: stdin)
--remotes <list>      Comma-separated UDP/HTTPS destinations  [default: 127.0.0.1:8200]
--receiver-key        Dilithium3 fingerprint of receiver (TOFU if omitted)
--tkem-threshold <n>  Threshold KEM: min relay shares needed  (requires receiver --tkem-relays)
--http                Use TLS 1.3 + HTTP/2 transport instead of raw UDP
--jitter-min <ms>     Minimum inter-batch jitter  [default: 200]
--jitter-max <ms>     Maximum inter-batch jitter  [default: 1200]
--stagger <ms>        Max per-share random delay  [default: 5]
--mgmt <addr>         Start management plane on this address
```

Examples:

```bash
labyrinth send --to 192.168.1.10:8199 --file secret.pdf
labyrinth send --to 127.0.0.1:8199 --remotes 127.0.0.1:443 --http --file payload.bin
labyrinth send --to 127.0.0.1:8199 --tkem-threshold 2
echo "hello" | labyrinth send --to 127.0.0.1:8199
```

### `labyrinth recv`

```
--ctrl <addr>        TCP listen for KEM key exchange  [default: 0.0.0.0:8199]
--udp <addr>         UDP / HTTPS listen address  [default: 0.0.0.0:8200]
--output, -o <path>  Output file (default: stdout)
--sign               Generate Dilithium3 keypair and print fingerprint
--tkem-relays <n>    Threshold KEM: number of independent relay sub-keypairs  [default: 1]
--http               Use TLS 1.3 + HTTP/2 transport (auto-generates self-signed cert)
--mgmt <addr>        Start management plane on this address
```

Examples:

```bash
labyrinth recv --output /tmp/received.pdf --mgmt 0.0.0.0:9090
labyrinth recv --sign
labyrinth recv --tkem-relays 3
labyrinth recv --ctrl 0.0.0.0:8199 --udp 0.0.0.0:443 --http --sign
```

### `labyrinth status`

```bash
labyrinth status
labyrinth status --mgmt 10.0.0.5:9090 --format json
```

### `labyrinth setup`

```bash
labyrinth setup    # interactive wizard
```

---

## TUI — `labyrinth-tui`

```bash
labyrinth-tui --mgmt 127.0.0.1:9090
```

| Key | Action |
|---|---|
| `q` / `Ctrl+C` | Quit |
| `p` | Pause / resume polling |
| `f` | Failover popup (show paths) |
| `0`–`9` | Toggle path in popup |
| `Esc` | Close popup |
| `r` | Reset local delta counters |

---

## Management Plane HTTP API

| Endpoint | Method | Description |
|---|---|---|
| `/health` | GET | `{"status":"ok"/"degraded"/"critical", ...}` |
| `/metrics` | GET | Session, fragment, ratchet, replay counters |
| `/metrics/paths` | GET | Per-path bytes/packets array |
| `/metrics/stream` | GET | SSE JSON stream every 1s |
| `/metrics/rtt/p95` | GET | RTT 95th percentile |
| `/logs` | GET | Last 500 process log entries |
| `/path/{idx}/activate` | POST | Reactivate path idx |
| `/path/{idx}/deactivate` | POST | Deactivate path idx |

```bash
curl 127.0.0.1:9090/health
curl 127.0.0.1:9090/metrics
curl -H "Authorization: Bearer TOKEN" 127.0.0.1:9090/metrics/stream
curl -X POST 127.0.0.1:9090/path/1/deactivate
```

---

## Security Stack

```
Payload
  │
  ▼
GF(2⁸) Shamir SSS        n=5 shares, k=3 threshold
  │
  ▼
Hybrid KEM                X25519 + Kyber-1024 combined
  │                        key = BLAKE3-derive(kyber_ss ‖ x25519_ss)
  │  + BLAKE3 auth tag    8 bytes per share, constant-time verify
  │  + Key ratchet        rotation every 10,000 packets via BLAKE3-KDF
  │  + Replay window      128-bit sliding bitmap
  │  + Dilithium3         optional receiver identity (post-quantum sig)
  │  + Threshold KEM      K-of-N sub-key ceremony, info-theoretically secure
  ▼
Transport
  │  UDP mode:  phase3 wire-format framing (TLS1.3 / QUIC / WS / HTTP2)
  │             + Markov IAT + ChaCha20 padding + CBR cover traffic (XDP)
  │
  │  HTTP mode: real TLS 1.3 + HTTP/2, ALPN negotiated
  │             self-signed cert + Dilithium3-pinned via ctrl channel
  │             Chrome headers + bucket padding [512,1024,2048,4096,8192]B
  │             empirical Chrome IAT distribution
  ▼
Network paths (multi-path, adaptive scheduler)
```

**Threat model:** on-path DPI with ML classifiers, quantum adversaries breaking RSA/ECDH, replay attacks, relay node compromise, temporal traffic analysis.

---

## Adaptive Multi-Path Scheduler

The scheduler measures RTT and loss for each path via lightweight probe packets, computes an EWMA score, and assigns Shamir shares proportionally to path quality. Dead paths (loss > 85%) enter exponential backoff (1s → 60s) and are automatically re-admitted when they recover.

---

## Threshold KEM

Eliminates the single point of compromise in KEM setup. The receiver generates N independent sub-keypairs; the sender Shamir-splits a master secret across them. The session key is only derivable from ≥ K of the N sub-keys. Even if K−1 relay sub-keys are compromised (and one is quantum-broken), the session key remains information-theoretically secret.

```bash
labyrinth recv --tkem-relays 3
labyrinth send --to 127.0.0.1:8199 --tkem-threshold 2
```

---

## Build & Test

```bash
cargo build --workspace                      # debug
cargo build --release --workspace            # release (LTO + codegen-units=1)
cargo build --release -p labyrinth-cli       # CLI only

cargo test --workspace                       # all tests
cargo test -p labyrinth-core --lib           # unit tests
cargo test --test integration_http_transport -- --test-threads=1
cargo test --test integration_labyrinth
cargo test --test integration_improvements
```

---

## Environment Variables — `labyrinth_mesh`

| Variable | Default | Description |
|---|---|---|
| `LABYRINTH_MODE` | `send` | `send` or `recv` |
| `LABYRINTH_CTRL` | `0.0.0.0:8199` | TCP listen for KEM (receiver) |
| `LABYRINTH_RECV_CTRL` | `127.0.0.1:8199` | TCP connect for KEM (sender) |
| `LABYRINTH_UDP_LISTEN` | `0.0.0.0:8200` | UDP / HTTPS listen (receiver) |
| `LABYRINTH_REMOTES` | `127.0.0.1:8200` | Destinations, comma-separated |
| `LABYRINTH_HTTP_MODE` | `false` | `1` → TLS 1.3 + HTTP/2 mode |
| `LABYRINTH_JITTER_MIN_MS` | `200` | Minimum inter-batch jitter (ms) |
| `LABYRINTH_JITTER_MAX_MS` | `1200` | Maximum inter-batch jitter (ms) |
| `LABYRINTH_SHARE_STAGGER_MS` | `5` | Max per-share random delay (ms) |
| `LABYRINTH_CBR_ENABLED` | `false` | `1` → XDP cover traffic (Linux ≥ 5.15) |
| `LABYRINTH_AFXDP_IFACE` | _(off)_ | Interface for AF_XDP zero-copy data plane (Linux ≥ 5.7, root) |
| `LABYRINTH_AFXDP_QUEUE` | `0` | NIC RX queue index for AF_XDP socket |
| `LABYRINTH_CBR_BPS` | `0` (= 2 Mbps) | CBR rate in bit/s |
| `DMPOT_MGMT_ADDR` | _(off)_ | Start management plane |
| `LABYRINTH_BIND` | `0.0.0.0:9090` | `labyrinth-server` bind address |

---

## Repository Structure

```
labyrinth-core/        Core library
  src/
    v2/                Hybrid KEM, Shamir, BLAKE3, ratchet, replay, threshold KEM
      afxdp.rs         AF_XDP zero-copy socket — UMEM, fill/completion/RX/TX rings via libc
      tpm_identity.rs  TPM 2.0 ECC P-256 hardware signing key + PCR-sealed session keys
      bpf_lsm.rs       eBPF LSM — kernel-enforced ptrace block + socket family whitelist
    phase1/            GF(2⁸) arithmetic
    phase3/            Protocol framing (TLS1.3/QUIC/WS/HTTP2) + Markov IAT
    phase4/            XDP/eBPF cover traffic + MultiPathController
    phase5/            Anti-debug, memory integrity
    chrome_tls/         Custom TLS 1.3 stack — Chrome 124 ClientHello, JA3/JA4 identical
  http_transport/    TLS bundle, bucket padding, Chrome headers, HTTPS server
    scheduler/         Adaptive multi-path scheduler (EWMA)
    management_plane/  Axum HTTP API + SSE
    metrics/           SharedMetrics
    file_transfer/     FileSender / FileReceiver + BLAKE3 verify
    log_capture/       500-entry ring buffer

labyrinth-cli/         `labyrinth` CLI (clap subcommands)
labyrinth-tui/         `labyrinth-tui` Ratatui dashboard
labyrinth-server/      `labyrinth-server` standalone management plane

docker-compose.yml     Backend container
quickstart.sh          One-liner bootstrap
```

---

## Key Dependencies

```
pqcrypto-kyber     = "0.7"   Kyber-768 KEM (hybrid PQ key share, Chrome 124)
pqcrypto-kyber     = "0.7"   Kyber-1024 KEM (session KEM, NIST PQC Level 5)
x25519-dalek       = "2"     X25519 ECDH (hybrid KEM + TLS key share)
pqcrypto-dilithium = "0.5"   Dilithium3 post-quantum signatures
blake3             = "1.5"   Auth tags + KDF + ratchet
sharks             = "0.5"   Shamir Secret Sharing over GF(256)
aes-gcm            = "0.10"  AES-128-GCM for custom TLS 1.3 AEAD
hmac               = "0.12"  HMAC-SHA256 for TLS 1.3 Finished messages
rcgen              = "0.13"  Runtime self-signed cert generation
tokio-rustls       = "0.26"  Async TLS 1.3 server (receiver side)
hyper              = "1"     HTTP/2 client + server
axum               = "0.7"   Management plane + share endpoint
aya                = "0.12"  eBPF userspace loader (cover traffic + LSM)
tokio              = "1"     Async runtime

# Optional features (--features <name>)
tss-esapi          = "8"     TPM 2.0 key management (--features tpm)
p256               = "0.14"  ECDSA P-256 verification for TPM signatures (--features tpm)
tokio-uring        = "0.5"   io_uring async file I/O (--features io-uring, Linux only)
```

## v2 Architecture (AF_XDP + TPM + eBPF LSM + io_uring)

```
NIC
 │
 ▼ XDP hook (labyrinth_rx)
Verified fragment ──── AF_XDP path ──→ UMEM (zero-copy, src/v2/afxdp.rs)
                   └── ringbuf path ──→ verified_ringbuf (fallback)
                          │
                          ▼ Rust userspace
                        Kyber/Shamir/BLAKE3 decrypt
                          │
                          ▼ Identity
                        TPM ECC P-256 signing (non-extractable hardware key)
                        Dilithium3 fallback if /dev/tpm0 absent
                          │
                          ▼ Kernel policy
                        eBPF LSM (ptrace blocked, socket families whitelisted)
                          │
                          ▼ File I/O
                        io_uring write_at() loop (--features io-uring)
```

Linux ≥ 5.7 required for eBPF LSM. AF_XDP works on Linux ≥ 5.1 with XDP driver support. TPM 2.0 requires `/dev/tpm0` or `/dev/tpmrm0`.

# not audited, use at your own risk
