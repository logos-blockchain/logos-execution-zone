#!/bin/sh

set -e

# `hostname -i` may return multiple addresses (IPv4 + IPv6) on newer runners.
# cfgsync expects a single, stable host identifier, so pick the first IPv4.
HOST_IP="$(hostname -i | tr ' ' '\n' | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | head -n1)"
if [ -z "$HOST_IP" ]; then
  HOST_IP="$(hostname -i | awk '{print $1}')"
fi

export CFG_FILE_PATH="/config.yaml" \
       CFG_SERVER_ADDR="http://cfgsync:4400" \
       CFG_HOST_IP="$HOST_IP" \
       CFG_HOST_IDENTIFIER="validator-$HOST_IP" \
       LOG_LEVEL="INFO" \
       POL_PROOF_DEV_MODE=true

/usr/bin/logos-blockchain-cfgsync-client && \
    exec /usr/bin/logos-blockchain-node /config.yaml
