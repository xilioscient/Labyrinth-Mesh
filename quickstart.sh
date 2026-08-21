#!/usr/bin/env bash
# Labyrinth-Mesh — one-line bootstrap
# Usage: ./quickstart.sh [--stop | --logs | --status]
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; NC='\033[0m'

err()  { echo -e "${RED}ERROR: $*${NC}" >&2; exit 1; }
ok()   { echo -e "${GREEN}✓ $*${NC}"; }
info() { echo -e "${CYAN}→ $*${NC}"; }

# ── Guard: docker ─────────────────────────────────────────────────────────────
command -v docker >/dev/null || err "Docker not found. Install it from https://docs.docker.com/get-docker/"
docker compose version >/dev/null 2>&1 || err "Docker Compose v2 not found."

# ── Subcommands ───────────────────────────────────────────────────────────────
case "${1:-}" in
  --stop)
    info "Stopping Labyrinth-Mesh…"
    docker compose down
    ok "Stopped."
    exit 0
    ;;
  --logs)
    docker compose logs -f
    exit 0
    ;;
  --status)
    docker compose ps
    exit 0
    ;;
esac

# ── Build & start ─────────────────────────────────────────────────────────────
info "Building images (first run may take several minutes)…"
docker compose build

info "Starting services…"
docker compose up -d

info "Waiting for backend to be healthy…"
for i in $(seq 1 30); do
  if docker compose ps backend | grep -q "healthy"; then
    break
  fi
  sleep 2
done

echo ""
echo "╔════════════════════════════════════════════════╗"
echo "║          LABYRINTH-MESH is running             ║"
echo "╠════════════════════════════════════════════════╣"
echo "║  TUI         →  labyrinth-tui --mgmt :9090    ║"
echo "║  API         →  http://localhost:9090          ║"
echo "║  Tunnel UDP  →  :8200                          ║"
echo "║  KEM ctrl    →  :8199                          ║"
echo "╠════════════════════════════════════════════════╣"
echo "║  ./quickstart.sh --logs    # live logs         ║"
echo "║  ./quickstart.sh --stop    # shut down         ║"
echo "╚════════════════════════════════════════════════╝"
