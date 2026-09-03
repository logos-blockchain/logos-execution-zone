#!/usr/bin/env bash
# Stop the native demo processes started by run-native.sh.
set -uo pipefail
cd "$(dirname "$0")"
for p in logs/seq_a.pid logs/seq_b.pid logs/idx_b.pid; do
  if [ -f "$p" ]; then
    pid="$(cat "$p")"
    kill "$pid" 2>/dev/null && echo "stopped pid $pid ($p)"
    rm -f "$p"
  fi
done
echo "done"
