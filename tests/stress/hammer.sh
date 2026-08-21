#!/usr/bin/env bash
# Stress test: rapid sequential sends, count crashes and verify 0 panics.
# Usage: ./tests/stress/hammer.sh [sends] [payload_kb]
#   sends:      number of send sessions (default 100)
#   payload_kb: payload size in KB per send (default 4)

set -euo pipefail

SENDS=${1:-100}
PAYLOAD_KB=${2:-4}
BIN="$(cd "$(dirname "$0")/../.." && pwd)/ESbin/labyrinth_mesh"

echo "=== Stress test: ${SENDS} sends, ${PAYLOAD_KB}KB payload ==="

dd if=/dev/urandom of=/tmp/hammer_payload.bin bs=1K count="$PAYLOAD_KB" 2>/dev/null

rm -f /tmp/labyrinth_seq_8200

LABYRINTH_MODE=recv \
  LABYRINTH_CTRL=0.0.0.0:8199 \
  LABYRINTH_UDP_LISTEN=0.0.0.0:8200 \
  "$BIN" > /dev/null 2>/tmp/hammer_recv.log &
RECV_PID=$!
sleep 1

CRASHES=0
START=$(date +%s)

for i in $(seq 1 "$SENDS"); do
    LABYRINTH_MODE=send \
      LABYRINTH_RECV_CTRL=127.0.0.1:8199 \
      LABYRINTH_REMOTES=127.0.0.1:8200 \
      LABYRINTH_JITTER_MIN_MS=0 \
      LABYRINTH_JITTER_MAX_MS=0 \
      LABYRINTH_SHARE_STAGGER_MS=0 \
      "$BIN" --file-in /tmp/hammer_payload.bin 2>/dev/null
    EXIT=$?
    if [ "$EXIT" -ne 0 ]; then
        echo "  send $i: EXIT=$EXIT (crash/error)"
        CRASHES=$((CRASHES+1))
    fi
done

END=$(date +%s)
ELAPSED=$((END - START))

kill -TERM "$RECV_PID" 2>/dev/null; wait "$RECV_PID" 2>/dev/null

RECONSTRUCTED=$(grep -c "Reconstructed" /tmp/hammer_recv.log 2>/dev/null || echo 0)

echo ""
echo "=== Results ==="
echo "  Sends:         $SENDS"
echo "  Crashes:       $CRASHES"
echo "  Reconstructed: $RECONSTRUCTED"
echo "  Duration:      ${ELAPSED}s"

if [ "$CRASHES" -eq 0 ]; then
    echo "PASS: 0 crashes in $SENDS sends"
    exit 0
else
    echo "FAIL: $CRASHES crash(es)"
    exit 1
fi
