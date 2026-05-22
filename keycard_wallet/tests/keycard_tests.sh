#!/bin/bash
# Run wallet_with_keycard.sh first

source venv/bin/activate # Load the appropriate virtual environment

export KEYCARD_PIN=111111

# Tests wallet keycard available
#   - Checks whether smart reader and keycard are both available.
echo "Test: wallet keycard available"
wallet keycard available

# Install a new mnemonic phrase to keycard
echo "Test: wallet keycard load"
export KEYCARD_MNEMONIC="fashion degree mountain wool question damp current pond grow dolphin chronic then"
wallet keycard load
unset KEYCARD_MNEMONIC

echo "Test: wallet auth-transfer init --account-id \"m/44'/60'/0'/0/0\""
wallet auth-transfer init --account-id "m/44'/60'/0'/0/0"

echo "Test: wallet account get --account-id \"m/44'/60'/0'/0/0\""
wallet account get --account-id "m/44'/60'/0'/0/0"

echo "Test: wallet pinata claim --to \"m/44'/60'/0'/0/0\""
wallet pinata claim --to "m/44'/60'/0'/0/0"

echo "Test: wallet account get --account-id \"m/44'/60'/0'/0/0\""
wallet account get --account-id "m/44'/60'/0'/0/0"

echo "Test: wallet auth-transfer init and send between two keycard accounts"
wallet auth-transfer init --account-id "m/44'/60'/0'/0/1"
wallet auth-transfer send --amount 40 --from "m/44'/60'/0'/0/0" --to "m/44'/60'/0'/0/1"

echo "Test: wallet account get --account-id \"m/44'/60'/0'/0/0\""
wallet account get --account-id "m/44'/60'/0'/0/0"

echo "Test: wallet account get --account-id \"m/44'/60'/0'/0/1\""
wallet account get --account-id "m/44'/60'/0'/0/1"

# Send from keycard account to a local wallet account
echo "Test: create local wallet account"
LOCAL_ACCOUNT_ID=$(wallet account new public 2>&1 | grep -oP '(?<=Public/)\S+')
echo "Created local account: Public/${LOCAL_ACCOUNT_ID}"

echo "Test: wallet auth-transfer init local account"
wallet auth-transfer init --account-id "Public/${LOCAL_ACCOUNT_ID}"


echo "Test: wallet auth-transfer send from keycard to local account"
wallet auth-transfer send --amount 10 --from "m/44'/60'/0'/0/0" --to "Public/${LOCAL_ACCOUNT_ID}"

echo "Test: wallet account get --account-id \"m/44'/60'/0'/0/0\""
wallet account get --account-id "m/44'/60'/0'/0/0"

echo "Test: wallet account get --account-id \"Public/${LOCAL_ACCOUNT_ID}\""
wallet account get --account-id "Public/${LOCAL_ACCOUNT_ID}"

# Create a local wallet account, fund it, and send to keycard account (co-signed: local key + keycard)

echo "Test: wallet auth-transfer send from local account to keycard account"
wallet auth-transfer send --amount 10 --from "Public/${LOCAL_ACCOUNT_ID}" --to "m/44'/60'/0'/0/1"

echo "Test: wallet account get --account-id \"Public/${LOCAL_ACCOUNT_ID}\""
wallet account get --account-id "Public/${LOCAL_ACCOUNT_ID}"

echo "Test: wallet account get --account-id \"m/44'/60'/0'/0/1\""
wallet account get --account-id "m/44'/60'/0'/0/1"

# Send from keycard account to a local wallet account (foreign recipient — no signature needed)
echo "Test: wallet account get --account-id \"m/44'/60'/0'/0/0\""
wallet account get --account-id "Public/7wHg9sbJwc6h3NP1S9bekfAzB8CHifEcxKswCKUt3YQo"

echo "Test: wallet auth-transfer send from keycard to local account"
wallet auth-transfer send --amount 10 --from "m/44'/60'/0'/0/0" --to "Public/7wHg9sbJwc6h3NP1S9bekfAzB8CHifEcxKswCKUt3YQo"

echo "Test: wallet account get --account-id \"m/44'/60'/0'/0/0\""
wallet account get --account-id "m/44'/60'/0'/0/0"

echo "Test: wallet account get --account-id \"m/44'/60'/0'/0/0\""
wallet account get --account-id "Public/7wHg9sbJwc6h3NP1S9bekfAzB8CHifEcxKswCKUt3YQo"
