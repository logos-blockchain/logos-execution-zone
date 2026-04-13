#!/bin/sh

set -e

export CFG_FILE_PATH="/config.yaml" \
       CFG_SERVER_ADDR="http://cfgsync:4400" \
       CFG_HOST_IP=$(hostname -i) \
       CFG_HOST_IDENTIFIER="validator-$(hostname -i)" \
       LOG_LEVEL="INFO" \
       POL_PROOF_DEV_MODE=true

/usr/bin/logos-blockchain-cfgsync-client

# Use the static deployment-settings.yaml (mounted from host) with consensus
# params pre-configured for single-node integration tests. Only the
# chain_start_time needs to be set dynamically to "now".
sed -i "s/PLACEHOLDER_CHAIN_START_TIME/$(date -u '+%Y-%m-%d %H:%M:%S.000000 +00:00:00')/" \
    /etc/logos-blockchain/deployment-settings.yaml

exec /usr/bin/logos-blockchain-node /config.yaml --deployment /etc/logos-blockchain/deployment-settings.yaml
