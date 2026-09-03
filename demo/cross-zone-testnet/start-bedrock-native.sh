#!/usr/bin/env bash
# Build (once) and run the Bedrock L1 node NATIVELY as an arm64 binary, so it runs
# at native speed on Apple Silicon instead of hanging under amd64 emulation.
#
# It builds `logos-blockchain-node` from the logos-blockchain repo at tag 0.2.1
# (matching the 0.2.1-lssa image's config schema), then runs it with the same
# node-config.yaml / deployment-settings.yaml the Docker setup used.
#
#   ./start-bedrock-native.sh     # build if needed, then run on http://localhost:18080
#   ./stop-bedrock-native.sh      # stop it
#
# Prerequisites (one time): Xcode CLT (`xcode-select --install`) and `cmake`
# (`brew install cmake`). Rust 1.96.0 is pinned by the repo's rust-toolchain.toml.
# The first build is heavy (the whole node workspace) — do it well before a demo.
set -euo pipefail
cd "$(dirname "$0")"
DEMO_DIR="$(pwd)"
BEDROCK_CFG="$DEMO_DIR/../../bedrock"
LB_REPO="${LB_REPO:-$HOME/logos/logos-blockchain}"
LB_REF="${LB_REF:-0.2.1}"
BIN="$LB_REPO/target/release/logos-blockchain-node"

mkdir -p logs

# 1. Build the node binary if it is not present.
if [ ! -x "$BIN" ]; then
  if [ ! -d "$LB_REPO/.git" ]; then
    echo "Cloning logos-blockchain into $LB_REPO ..."
    git clone https://github.com/logos-blockchain/logos-blockchain "$LB_REPO"
  fi
  git -C "$LB_REPO" fetch --tags --quiet
  git -C "$LB_REPO" checkout "$LB_REF"
  echo "Building logos-blockchain-node at $LB_REF (first build is heavy) ..."
  ( cd "$LB_REPO" && cargo build --locked --release -p logos-blockchain-node )
fi

# 2. Validate our config files against the built node before running.
export POL_PROOF_DEV_MODE=true
if ! "$BIN" "$BEDROCK_CFG/node-config.yaml" \
      --deployment "$BEDROCK_CFG/deployment-settings.yaml" --check-config 2>/dev/null; then
  echo "Config check failed at ref $LB_REF. Retry with LB_REF=0.2.2 ./start-bedrock-native.sh" >&2
  exit 1
fi

# 3. Run it in a dedicated working dir (it creates ./state, ./state/logs, ./db there).
RUN_DIR="$DEMO_DIR/bedrock-run"
mkdir -p "$RUN_DIR"
( cd "$RUN_DIR" && exec "$BIN" "$BEDROCK_CFG/node-config.yaml" \
    --deployment "$BEDROCK_CFG/deployment-settings.yaml" ) > logs/bedrock.log 2>&1 &
echo $! > logs/bedrock.pid

echo
echo "Native Bedrock started (pid $(cat logs/bedrock.pid)). Log: logs/bedrock.log"
echo "Wait ~30s, then confirm it is online:"
echo "  curl -s http://localhost:18080/cryptarchia/info   # expect \"state\":\"Online\""
echo "Then start the zones: ./run-native.sh"
