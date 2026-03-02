#!/bin/sh

# This is an entrypoint script for the indexer_service Docker container,
# it's not meant to be executed outside of the container.

set -e

CONFIG="/etc/indexer_service/indexer_config.json"

# Check config file exists
if [ ! -f "$CONFIG" ]; then
  echo "Config file not found: $CONFIG" >&2
  exit 1
fi

# Parse home dir
HOME_DIR=$(jq -r '.home' "$CONFIG")

if [ -z "$HOME_DIR" ] || [ "$HOME_DIR" = "null" ]; then
  echo "'home' key missing in config" >&2
  exit 1
fi

# Give permissions to the data directory and switch to non-root user
if [ "$(id -u)" = "0" ]; then
  mkdir -p "$HOME_DIR"
  chown -R indexer_service_user:indexer_service_user "$HOME_DIR"
  exec gosu indexer_service_user "$@"
fi
