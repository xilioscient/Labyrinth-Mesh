# Comandi — riferimento rapido

## Binari disponibili

| Binario | Come avviarlo | Scopo |
|---|---|---|
| `labyrinth` | `cargo run -p labyrinth-cli --` | CLI con subcomandi |
| `labyrinth-tui` | `cargo run -p labyrinth-tui --` | Dashboard TUI ratatui |
| `labyrinth-server` | `cargo run -p labyrinth-server --` | Management plane standalone |
| `labyrinth_mesh` | `cargo run --bin labyrinth_mesh` | Nodo mesh (env vars) |

---

## CLI — `labyrinth`

### Receiver

```bash
# Base
labyrinth recv --ctrl 0.0.0.0:8199 --udp 0.0.0.0:8200

# Con file di output
labyrinth recv --ctrl 0.0.0.0:8199 --udp 0.0.0.0:8200 --output /tmp/out.bin

# Con management plane
labyrinth recv --ctrl 0.0.0.0:8199 --udp 0.0.0.0:8200 --mgmt 0.0.0.0:9090

# Con firma Dilithium3 (antiMITM sul canale ctrl)
labyrinth recv --ctrl 0.0.0.0:8199 --udp 0.0.0.0:8200 --sign

# Threshold KEM: 3 sub-chiavi relay, almeno 2 necessarie per ricostruire la session key
labyrinth recv --ctrl 0.0.0.0:8199 --udp 0.0.0.0:8200 --tkem-relays 3
```

### Sender

```bash
# stdin interattivo
labyrinth send --to 127.0.0.1:8199

# Da file
labyrinth send --to 127.0.0.1:8199 --file dati.bin

# Con path multipli (steganografia distribuita)
labyrinth send --to 127.0.0.1:8199 --remotes 10.0.0.2:8200,10.0.0.3:8200,10.0.0.4:8200

# Con management plane
labyrinth send --to 127.0.0.1:8199 --mgmt 127.0.0.1:9090

# Con verifica identità receiver (fingerprint da --sign)
labyrinth send --to 127.0.0.1:8199 --receiver-key ab:cd:ef:01:02:03:04:05

# Threshold KEM: stabilisce la session key via TCP con 2-of-3 relay sub-chiavi
# Richiede che il receiver sia avviato con --tkem-relays 3
labyrinth send --to 127.0.0.1:8199 --tkem-threshold 2

# Threshold KEM + file + path multipli
labyrinth send --to 127.0.0.1:8199 --file dati.bin \
  --remotes 10.0.0.2:8200,10.0.0.3:8200 \
  --tkem-threshold 2
```

### Status

```bash
labyrinth status                              # default 127.0.0.1:9090
labyrinth status --mgmt 10.0.0.5:9090
labyrinth status --mgmt 10.0.0.5:9090 --format json
```

### Setup wizard

```bash
labyrinth setup    # guida interattiva
```

---

## TUI — `labyrinth-tui`

```bash
labyrinth-tui                        # default 127.0.0.1:9090
labyrinth-tui --mgmt 10.0.0.5:9090
```

| Tasto | Azione |
|---|---|
| `q` / `Ctrl+C` | Esci |
| `p` | Pausa / riprendi polling |
| `f` | Popup failover (lista path) |
| `0`–`9` | (nel popup) toggle path |
| `Esc` | Chiudi popup |
| `r` | Reset contatori delta locali |

---

## Standalone server — `labyrinth-server`

```bash
labyrinth-server                         # 0.0.0.0:9090, 1 path
labyrinth-server --bind 0.0.0.0:9090 --paths 3
LABYRINTH_BIND=0.0.0.0:9090 labyrinth-server
```

---

## Nodo mesh — `labyrinth_mesh` (env vars)

```bash
# Receiver
LABYRINTH_MODE=recv cargo run --bin labyrinth_mesh

# Sender
LABYRINTH_MODE=send \
LABYRINTH_REMOTES=10.0.0.2:8200,10.0.0.3:8200 \
cargo run --bin labyrinth_mesh

# Con management plane
DMPOT_MGMT_ADDR=0.0.0.0:9090 LABYRINTH_MODE=recv cargo run --bin labyrinth_mesh

# Con cover traffic XDP (kernel ≥ 5.15, richiede root)
LABYRINTH_CBR_ENABLED=1 LABYRINTH_CBR_BPS=2000000 \
LABYRINTH_MODE=recv cargo run --bin labyrinth_mesh
```

---

## Docker

```bash
./quickstart.sh            # avvia il backend
./quickstart.sh --stop     # ferma tutti i container
./quickstart.sh --logs     # log in coda
./quickstart.sh --status   # stato dei container
```

Dopo l'avvio:
- API management plane → `http://localhost:9090`
- TUI → `labyrinth-tui --mgmt localhost:9090`

---

## Scenario a 3 terminali (CLI)

```bash
# T1 — receiver con management plane + threshold KEM 3 relay
labyrinth recv --ctrl 0.0.0.0:8199 --udp 0.0.0.0:8200 \
  --mgmt 0.0.0.0:9090 --tkem-relays 3

# T2 — TUI live
labyrinth-tui --mgmt 127.0.0.1:9090

# T3 — sender con threshold KEM + path multipli + steganografia automatica
labyrinth send --to 127.0.0.1:8199 \
  --remotes 127.0.0.1:8200,127.0.0.1:8201,127.0.0.1:8202 \
  --tkem-threshold 2
```

---

## Scenario senza Threshold KEM (modalità standard)

```bash
# T1
labyrinth recv --ctrl 0.0.0.0:8199 --udp 0.0.0.0:8200 --sign

# T2 (fingerprint da T1)
labyrinth send --to 127.0.0.1:8199 --receiver-key ab:cd:ef:01:02:03:04:05
```

---

## Scenario HTTPS/HTTP2 — traffico indistinguibile da browser

Il receiver genera un certificato TLS self-signed a runtime. Il fingerprint viene
scambiato via il canale TCP già firmato Dilithium3. Il sender usa TLS 1.3 + HTTP/2
con header Chrome reali e padding a bucket per eliminare la fingerprint sulla dimensione.

```bash
# T1 — receiver in modalità HTTPS
labyrinth recv --ctrl 0.0.0.0:8199 --udp 0.0.0.0:443 --http --sign

# T2 — sender in modalità HTTPS
labyrinth send --to 127.0.0.1:8199 --remotes 127.0.0.1:443 --http

# Con file
labyrinth send --to 127.0.0.1:8199 --remotes 127.0.0.1:443 --http --file dati.bin

# Combinato: HTTPS + Threshold KEM (massima resistenza)
labyrinth recv --ctrl 0.0.0.0:8199 --udp 0.0.0.0:443 --http --tkem-relays 3
labyrinth send --to 127.0.0.1:8199 --remotes 127.0.0.1:443 --http --tkem-threshold 2
```

---

## Management plane — API curl

```bash
curl 127.0.0.1:9090/health                          # stato globale
curl 127.0.0.1:9090/metrics                         # contatori
curl 127.0.0.1:9090/metrics/paths                   # per-path
curl 127.0.0.1:9090/metrics/stream                  # SSE live (ogni 1s)
curl 127.0.0.1:9090/logs                            # ultimi 500 log del processo
curl -X POST 127.0.0.1:9090/path/0/deactivate       # disattiva path 0
curl -X POST 127.0.0.1:9090/path/0/activate         # riattiva path 0
```

Con token di autenticazione:

```bash
TOKEN=miosegreto
curl -H "Authorization: Bearer $TOKEN" 127.0.0.1:9090/metrics
curl "127.0.0.1:9090/metrics?token=$TOKEN"
```

---

## Variabili d'ambiente — `labyrinth_mesh`

| Variabile | Default | Descrizione |
|---|---|---|
| `LABYRINTH_MODE` | `send` | `send` o `recv` |
| `LABYRINTH_CTRL` | `0.0.0.0:8199` | TCP key exchange listen (receiver) |
| `LABYRINTH_RECV_CTRL` | `127.0.0.1:8199` | TCP key exchange connect (sender) |
| `LABYRINTH_UDP_LISTEN` | `0.0.0.0:8200` | Porta UDP ascolto (receiver) |
| `LABYRINTH_REMOTES` | `127.0.0.1:8200` | Destinazioni UDP, virgola-separated |
| `LABYRINTH_JITTER_MIN_MS` | `200` | Jitter minimo inter-batch (ms) |
| `LABYRINTH_JITTER_MAX_MS` | `1200` | Jitter massimo inter-batch (ms) |
| `LABYRINTH_SHARE_STAGGER_MS` | `5` | Stagger intra-batch tra share (ms) |
| `LABYRINTH_CBR_ENABLED` | `false` | `1` → cover traffic XDP (Linux ≥ 5.15) |
| `LABYRINTH_CBR_BPS` | `0` (= 2 Mbps) | Rate CBR in bit/s |
| `DMPOT_MGMT_ADDR` | _(disabilitato)_ | Avvia management plane HTTP |
| `LABYRINTH_BIND` | `0.0.0.0:9090` | Solo `labyrinth-server`: bind address |

---

## Pulizia porte

```bash
fuser -k 8199/tcp 8200/udp 9090/tcp 2>/dev/null || true
```

---

## Build e test

```bash
cargo build --workspace                           # dev (tutti i crate)
cargo build --release --workspace                 # release ottimizzata
cargo build --release -p labyrinth-cli            # solo CLI

cargo test --workspace                            # tutti i test
cargo test -p labyrinth-core --lib                # solo unit test core
cargo test --test integration_improvements        # test steganografia + Threshold KEM
cargo test --test integration_http_transport      # test HTTP transport (padding, TLS bundle, IAT)
cargo test --test integration_labyrinth           # test pipeline v2
```
