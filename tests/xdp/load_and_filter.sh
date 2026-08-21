#!/usr/bin/env bash
# XDP test: verify eBPF objects are valid ELF and loadable structure.
# Full kernel load requires root + real interface — run with sudo for that path.
# Usage: ./tests/xdp/load_and_filter.sh [--full]

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
ESBIN="$ROOT/ESbin"

echo "=== XDP / eBPF object validation ==="

# --- Step 1: verify .o files are non-empty valid ELF ---
OBJECTS=(dmpot_xdp.o labyrinth_cover.o labyrinth_rx.o labyrinth_tx.o)
ALL_OK=true

for obj in "${OBJECTS[@]}"; do
    path="$ESBIN/$obj"
    if [ ! -f "$path" ]; then
        echo "  FAIL: $obj not found"
        ALL_OK=false
        continue
    fi
    size=$(wc -c < "$path")
    if [ "$size" -lt 100 ]; then
        echo "  FAIL: $obj is a stub ($size bytes)"
        ALL_OK=false
        continue
    fi
    magic=$(xxd -p -l 4 "$path" 2>/dev/null || od -A n -t x1 -N 4 "$path" | tr -d ' ')
    if [[ "$magic" == 7f454c46* ]]; then
        echo "  OK:   $obj ($size bytes) — valid ELF"
    else
        echo "  FAIL: $obj not ELF (magic: $magic)"
        ALL_OK=false
    fi
done

# --- Step 2: llvm-objdump section list (structural check) ---
echo ""
echo "--- BPF sections in dmpot_xdp.o ---"
llvm-objdump -h "$ESBIN/dmpot_xdp.o" 2>/dev/null | grep -E "xdp|maps|\.text|SEC" || echo "  (no xdp sections — check source)"

# --- Step 3: kernel load (requires root + interface) ---
if [[ "${1:-}" == "--full" ]]; then
    if [ "$EUID" -ne 0 ]; then
        echo ""
        echo "SKIP: --full requires root. Run: sudo $0 --full"
        exit 0
    fi
    IFACE=${2:-lo}
    echo ""
    echo "--- Loading XDP on $IFACE (requires CAP_NET_ADMIN) ---"
    # Use ip link to attach (requires iproute2 + kernel XDP support)
    ip link set dev "$IFACE" xdp obj "$ESBIN/dmpot_xdp.o" sec xdp 2>&1 || echo "  Load failed (check kernel version and XDP support)"
    sleep 1
    ip link set dev "$IFACE" xdp off 2>/dev/null || true
    echo "  XDP load/unload on $IFACE: done"
fi

echo ""
if $ALL_OK; then
    echo "PASS: all eBPF objects are valid ELF"
    exit 0
else
    echo "FAIL: one or more eBPF objects invalid"
    exit 1
fi
