#!/bin/sh

set -e

export CFG_FILE_PATH="/config.yaml" \
       CFG_SERVER_ADDR="http://cfgsync:4400" \
       CFG_HOST_IP=$(hostname -i) \
       CFG_HOST_IDENTIFIER="validator-$(hostname -i)" \
       LOG_LEVEL="INFO" \
       POL_PROOF_DEV_MODE=true

/usr/bin/logos-blockchain-cfgsync-client

# Wait for deployment settings to be available (generated after all nodes register)
echo "Waiting for deployment settings from cfgsync..."
RETRIES=0
MAX_RETRIES=60
until curl -sf "${CFG_SERVER_ADDR}/deployment-settings" -o /deployment-settings.yaml; do
    RETRIES=$((RETRIES + 1))
    if [ "$RETRIES" -ge "$MAX_RETRIES" ]; then
        echo "Failed to download deployment settings after ${MAX_RETRIES} attempts"
        exit 1
    fi
    echo "Deployment settings not ready yet, retrying in 1s... (${RETRIES}/${MAX_RETRIES})"
    sleep 1
done
echo "Deployment settings downloaded successfully"

exec /usr/bin/logos-blockchain-node /config.yaml --deployment /deployment-settings.yaml
