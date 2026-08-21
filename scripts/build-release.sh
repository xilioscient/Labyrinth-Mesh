#!/usr/bin/env bash
set -euo pipefail

VERSION="${1:-1.0.0}"
TARGET="x86_64-unknown-linux-gnu"
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DIST="$REPO_ROOT/dist"

mkdir -p "$DIST"

cargo build --release --workspace --target "$TARGET" 2>&1

BINS=(
    "target/$TARGET/release/labyrinth"
    "target/$TARGET/release/labyrinth-tui"
    "target/$TARGET/release/labyrinth-server"
    "target/$TARGET/release/labyrinth_mesh"
)

for BIN in "${BINS[@]}"; do
    strip "$REPO_ROOT/$BIN" 2>/dev/null || true
done

ARCHIVE="$DIST/Labyrinth-Mesh-v${VERSION}-${TARGET}.tar.gz"

tar -czf "$ARCHIVE" \
    -C "$REPO_ROOT/target/$TARGET/release" \
    labyrinth \
    labyrinth-tui \
    labyrinth-server \
    labyrinth_mesh

echo "Archive: $ARCHIVE"
sha256sum "$ARCHIVE" | tee "$DIST/SHA256SUMS"
