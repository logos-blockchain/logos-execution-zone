#!/bin/bash
# Run wallet_with_keycard.sh first

source venv/bin/activate # Load the appropriate virtual environment

source venv/bin/activate
export KEYCARD_PIN=111111

# =============================================================================
# Keycard setup
# =============================================================================
echo "=== Test: wallet keycard available ==="
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

echo "=== Test: account get path 0 ==="
wallet account get --account-id "m/44'/60'/0'/0/0"
echo "=== Test: account get path 1 ==="
wallet account get --account-id "m/44'/60'/0'/0/1"
echo ""
echo "=== Test (1): Shielded auth-transfer to owned private account ==="

wallet auth-transfer send --amount 2 \
  --from "m/44'/60'/0'/0/0" \
  --to-npk "55204e2934045b044f06d8222b454d46b54788f33c7dec4f6733d441703bb0e6" \
  --to-vpk "02a8626b0c0ad9383c5678dad48c3969b4174fb377cdb03a6259648032c774cec8"
echo "Shielded auth-transfer sent"

sleep 15
wallet account get --account-id "m/44'/60'/0'/0/0"

# =============================================================================
# Test (2): Deshielded auth-transfer — private account → keycard recipient
#     A fresh private account is funded, then sends native tokens to keycard
#     path 1. The private sender is handled by the ZK circuit; the keycard
#     recipient does not sign — resolve() derives its account ID from the card.
# =============================================================================
echo ""
echo "=== Test (2): Deshielded auth-transfer: private account → keycard path 1 ==="

PRIV_SENDER=$(wallet account new private | grep -o 'Private/[^[:space:]]*' | head -1)
echo "Fresh private sender account: $PRIV_SENDER"

wallet auth-transfer init --account-id "$PRIV_SENDER"

echo "Test: wallet pinata claim to private sender"
wallet pinata claim --to "$PRIV_SENDER"

sleep 15

echo "priv-sender state after claim:"
wallet account get --account-id "$PRIV_SENDER"

wallet auth-transfer send \
  --from   "$PRIV_SENDER" \
  --to     "m/44'/60'/0'/0/1" \
  --amount 5
echo "Deshielded transfer of 5: $PRIV_SENDER → keycard path 1"

sleep 15

echo "priv-sender state (balance should have decreased by 5):"
wallet account get --account-id "$PRIV_SENDER"
echo "Keycard path 1 state (balance should have increased by 5):"
wallet account get --account-id "m/44'/60'/0'/0/1"