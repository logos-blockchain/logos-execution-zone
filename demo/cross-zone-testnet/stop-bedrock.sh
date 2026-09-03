#!/usr/bin/env bash
# Tear down the local Bedrock node started by start-bedrock.sh.
set -uo pipefail
cd "$(dirname "$0")/../../bedrock"
export DOCKER_DEFAULT_PLATFORM=linux/amd64
docker compose down -v
echo "Local Bedrock stopped."
