#!/bin/sh

set -e

export POL_PROOF_DEV_MODE=true

# Use static configs mounted from host. Both node-config.yaml and
# deployment-settings.yaml have matching validator keys so the node
# can produce blocks as a single-validator network.
exec /usr/bin/logos-blockchain-node \
    /etc/logos-blockchain/node-config.yaml \
    --deployment /etc/logos-blockchain/deployment-settings.yaml
