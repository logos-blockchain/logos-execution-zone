#!/usr/bin/env bash
# Start a local self-hosted Bedrock L1 node (the one the integration tests use).
# It boots from its own genesis at slot 0 with a 1-second bootstrap period, so it
# comes online in seconds and our zones sync it instantly, no multi-million-slot
# backfill like the live testnet chain.
#
#   ./start-bedrock.sh      # bring it up on http://localhost:18080
#   ./stop-bedrock.sh       # tear it down
#
# On Apple Silicon the image is amd64, so it runs under emulation (fine, no risc0).
set -euo pipefail
cd "$(dirname "$0")/../../bedrock"

export DOCKER_DEFAULT_PLATFORM=linux/amd64
PORT="${PORT:-18080}" docker compose up -d

echo
echo "Local Bedrock starting on http://localhost:18080 (amd64 emulated)."
echo "Give it ~30-60s, then confirm it is online:"
echo "  curl -s http://localhost:18080/cryptarchia/info"
echo "Expect JSON with \"state\":\"Online\". Then run ./run-native.sh."
