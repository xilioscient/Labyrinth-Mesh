# ─── Stage 1: dependency cache ────────────────────────────────────────────────
# Copy Cargo manifests first so this layer is cached unless deps change.
FROM rust:1.82-bookworm AS deps

RUN apt-get update && apt-get install -y --no-install-recommends \
        clang llvm libelf-dev linux-libc-dev pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY Cargo.toml Cargo.lock build.rs ./
COPY labyrinth-cli/Cargo.toml  ./labyrinth-cli/
COPY labyrinth-tui/Cargo.toml  ./labyrinth-tui/
COPY labyrinth-server/Cargo.toml ./labyrinth-server/

# Stub every source file so cargo can fetch and compile all dependencies.
# build.rs gracefully emits empty stub .o files when C sources are missing.
RUN mkdir -p src/bin labyrinth-cli/src labyrinth-tui/src labyrinth-server/src \
    && printf 'fn main(){}' | tee \
        src/bin/labyrinth_mesh.rs \
        src/bin/dashboard.rs \
        labyrinth-cli/src/main.rs \
        labyrinth-tui/src/main.rs \
        labyrinth-server/src/main.rs \
    && printf '' > src/lib.rs \
    && cargo build --release --bin labyrinth_mesh 2>/dev/null; true

# ─── Stage 2: full build ───────────────────────────────────────────────────────
FROM deps AS builder

COPY src/ ./src/
# Touch the binary source so cargo detects the change and relinks.
RUN touch src/bin/labyrinth_mesh.rs \
    && cargo build --release --bin labyrinth_mesh

# ─── Stage 3: minimal runtime ─────────────────────────────────────────────────
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates libssl3 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/labyrinth_mesh /usr/local/bin/labyrinth_mesh

WORKDIR /app

# Defaults — all overridable via docker-compose environment:
ENV RUST_LOG=info
ENV LABYRINTH_MODE=recv
ENV LABYRINTH_CTRL=0.0.0.0:8199
ENV LABYRINTH_UDP_LISTEN=0.0.0.0:8200
ENV LABYRINTH_JITTER_MIN_MS=200
ENV LABYRINTH_JITTER_MAX_MS=1200
ENV LABYRINTH_SHARE_STAGGER_MS=5
ENV DMPOT_MGMT_ADDR=0.0.0.0:9090

EXPOSE 8199/tcp
EXPOSE 8200/udp
EXPOSE 9090/tcp

CMD ["/usr/local/bin/labyrinth_mesh"]
