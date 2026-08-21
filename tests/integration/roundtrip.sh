#!/usr/bin/env bash
# Integration test: sender → receiver roundtrip with hash verification.
# Usage: ./tests/integration/roundtrip.sh [runs] [size_mb]
#   runs:    number of roundtrips (default 5)
#   size_mb: file size in MB (default 1)

set -euo pipefail

RUNS=${1:-5}
SIZE_MB=${2:-1}
BIN="$(cd "$(dirname "$0")/../.." && pwd)/ESbin/labyrinth_mesh"
PASS=0
FAIL=0

echo "=== Roundtrip integration test: ${RUNS} runs, ${SIZE_MB}MB each ==="

dd if=/dev/urandom of=/tmp/rt_input.bin bs=1M count="$SIZE_MB" 2>/dev/null
INPUT_HASH=$(sha256sum /tmp/rt_input.bin | cut -d' ' -f1)

for i in $(seq 1 "$RUNS"); do
    rm -f /tmp/rt_output.bin /tmp/labyrinth_seq_8200

    LABYRINTH_MODE=recv \
      LABYRINTH_CTRL=0.0.0.0:8199 \
      LABYRINTH_UDP_LISTEN=0.0.0.0:8200 \
      "$BIN" --file-out /tmp/rt_output.bin 2>/dev/null &
    RECV_PID=$!
    sleep 1

    LABYRINTH_MODE=send \
      LABYRINTH_RECV_CTRL=127.0.0.1:8199 \
      LABYRINTH_REMOTES=127.0.0.1:8200 \
      LABYRINTH_JITTER_MIN_MS=0 \
      LABYRINTH_JITTER_MAX_MS=0 \
      LABYRINTH_SHARE_STAGGER_MS=0 \
      "$BIN" --file-in /tmp/rt_input.bin 2>/dev/null
    sleep 1

    kill -TERM "$RECV_PID" 2>/dev/null; wait "$RECV_PID" 2>/dev/null

    if [ -f /tmp/rt_output.bin ]; then
        OUTPUT_HASH=$(sha256sum /tmp/rt_output.bin | cut -d' ' -f1)
        if [ "$INPUT_HASH" = "$OUTPUT_HASH" ]; then
            echo "  run $i/$RUNS: PASS"
            PASS=$((PASS+1))
        else
            echo "  run $i/$RUNS: FAIL (hash mismatch)"
            FAIL=$((FAIL+1))
        fi
    else
        echo "  run $i/$RUNS: FAIL (no output file)"
        FAIL=$((FAIL+1))
    fi
done

echo ""
echo "=== Results: ${PASS}/${RUNS} passed, ${FAIL} failed ==="
[ "$FAIL" -eq 0 ] && exit 0 || exit 1
