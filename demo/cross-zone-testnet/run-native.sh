#!/usr/bin/env bash
# Run the demo as NATIVE binaries (no Docker), so it runs at native speed on
# Apple Silicon. Two real zones (each a sequencer + indexer) against the local
# Bedrock node; confirm results over RPC (see README).
#
#   ./run-native.sh                # happy path (zone B allows the route)
#   ./run-native.sh unauthorized   # refused (zone B has no authorized route)
#
# Build the binaries first (once):
#   cd ~/logos/lez-demo-v024
#   CARGO_TARGET_DIR=.cargo-target-demo cargo build --release \
#     -p sequencer_service -p indexer_service -p cross_zone_lock
#
# Stop everything with ./stop-native.sh
set -euo pipefail
cd "$(dirname "$0")"

BIN="../../.cargo-target-demo/release"
for b in sequencer_service indexer_service cross_zone_lock; do
  if [ ! -x "$BIN/$b" ]; then
    echo "Missing $BIN/$b — build first (see the header of this script)." >&2
    exit 1
  fi
done

# The zones settle on the local Bedrock; it must be online first.
if ! curl -s -m 5 http://localhost:18080/cryptarchia/info | grep -q '"state":"Online"'; then
  echo "Local Bedrock is not online at http://localhost:18080." >&2
  echo "Start it first with ./start-bedrock.sh and wait for \"state\":\"Online\"." >&2
  exit 1
fi

ZB_CONFIG="configs/sequencer_b.json"
if [ "${1:-}" = "unauthorized" ]; then
  ZB_CONFIG="configs/sequencer_b_unauthorized.json"
  echo "REFUSED variant: zone B authorizes no route."
fi

export RISC0_DEV_MODE=1
export RUST_LOG="${RUST_LOG:-info}"

# Kill any leftover demo processes from a prior run that would hold the ports.
pkill -f "release/sequencer_service" 2>/dev/null || true
pkill -f "release/indexer_service" 2>/dev/null || true
sleep 1

# Fresh channels and fresh state every run (a fresh home regenerates the Bedrock
# signing key, so channels cannot be reused).
./prepare.sh
rm -rf data logs
mkdir -p data logs

TARGET_ZONE="$(python3 -c "import json;print(json.load(open('configs/sequencer_b.json'))['bedrock_config']['channel_id'])")"

echo "Starting zone A sequencer (:3040)..."
"$BIN/sequencer_service" configs/sequencer_a.json --port 3040 --home data/seq_a > logs/seq_a.log 2>&1 &
echo $! > logs/seq_a.pid

echo "Starting zone B sequencer (:3041)..."
"$BIN/sequencer_service" "$ZB_CONFIG" --port 3041 --home data/seq_b > logs/seq_b.log 2>&1 &
echo $! > logs/seq_b.pid

echo "Starting zone B indexer (:8779)..."
"$BIN/indexer_service" configs/indexer_b.json --port 8779 --data-dir data/idx_b \
  > logs/idx_b.log 2>&1 &
echo $! > logs/idx_b.pid

cat <<EOF

Three processes started. Logs are in logs/ (tail -f logs/seq_a.log).

Check both zones are producing blocks (run twice, ~10s apart):
  curl -s -X POST http://localhost:3040 -H 'content-type: application/json' \\
    --data '{"jsonrpc":"2.0","id":1,"method":"getLastBlockId","params":[]}'
  curl -s -X POST http://localhost:3041 -H 'content-type: application/json' \\
    --data '{"jsonrpc":"2.0","id":1,"method":"getLastBlockId","params":[]}'

Then submit the lock:
  $BIN/cross_zone_lock --sequencer-url http://localhost:3040 --target-zone $TARGET_ZONE

The mint lands on zone B ~2 min later. Confirm it in the log and over RPC (README).
Stop everything: ./stop-native.sh
EOF
