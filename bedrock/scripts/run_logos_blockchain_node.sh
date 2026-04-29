#!/bin/sh

set -e

export POL_PROOF_DEV_MODE=true

# Use static configs mounted from host. Both node-config.yaml and
# deployment-settings.yaml have matching validator keys so the node
# can produce blocks as a single-validator network.
# Copy deployment-settings to a writable path because sed -i can't
# rename on a bind-mounted file.
cp /etc/logos-blockchain/deployment-settings.yaml /deployment-settings.yaml

# Set chain_start_time to "now" so the chain starts immediately.
sed -i "s/PLACEHOLDER_CHAIN_START_TIME/$(date -u '+%Y-%m-%d %H:%M:%S.000000 +00:00:00')/" \
    /deployment-settings.yaml

exec /usr/bin/logos-blockchain-node \
    /etc/logos-blockchain/node-config.yaml \
    --deployment /deployment-settings.yaml
