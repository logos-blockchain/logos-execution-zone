#!/usr/bin/env bash
# Stop the native Bedrock node started by start-bedrock-native.sh.
set -uo pipefail
cd "$(dirname "$0")"
if [ -f logs/bedrock.pid ]; then
  pid="$(cat logs/bedrock.pid)"
  kill "$pid" 2>/dev/null && echo "stopped native Bedrock (pid $pid)"
  rm -f logs/bedrock.pid
else
  pkill -f "release/logos-blockchain-node" 2>/dev/null && echo "stopped stray logos-blockchain-node" || echo "nothing to stop"
fi
