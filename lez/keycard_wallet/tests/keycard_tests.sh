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

echo ""
echo "=== Test: Keycard account to Keycard account ==="
wallet auth-transfer init --account-id "m/44'/60'/0'/0/1"
wallet auth-transfer send --amount 40 --from "m/44'/60'/0'/0/0" --to "m/44'/60'/0'/0/1"

echo "Test: wallet account get --account-id \"m/44'/60'/0'/0/0\""
wallet account get --account-id "m/44'/60'/0'/0/0"

echo "Test: wallet account get --account-id \"m/44'/60'/0'/0/1\""
wallet account get --account-id "m/44'/60'/0'/0/1"

echo ""
echo "=== Test: Keycard account to public local account ==="
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

echo ""
echo "=== Test: public local account to Keycard account ==="

echo "Test: wallet auth-transfer send from local account to keycard account"
wallet auth-transfer send --amount 10 --from "Public/${LOCAL_ACCOUNT_ID}" --to "m/44'/60'/0'/0/1"

echo "Test: wallet account get --account-id \"Public/${LOCAL_ACCOUNT_ID}\""
wallet account get --account-id "Public/${LOCAL_ACCOUNT_ID}"

echo "Test: wallet account get --account-id \"m/44'/60'/0'/0/1\""
wallet account get --account-id "m/44'/60'/0'/0/1"

echo ""
echo "=== Test: Keycard account to foreign recipient (no signature required) ==="
echo "Test: wallet account get --account-id \"m/44'/60'/0'/0/0\""
wallet account get --account-id "Public/7wHg9sbJwc6h3NP1S9bekfAzB8CHifEcxKswCKUt3YQo"

echo "Test: wallet auth-transfer send from keycard to local account"
wallet auth-transfer send --amount 10 --from "m/44'/60'/0'/0/0" --to "Public/7wHg9sbJwc6h3NP1S9bekfAzB8CHifEcxKswCKUt3YQo"

echo "Test: wallet account get --account-id \"m/44'/60'/0'/0/0\""
wallet account get --account-id "m/44'/60'/0'/0/0"

echo "Test: wallet account get --account-id \"m/44'/60'/0'/0/0\""
wallet account get --account-id "Public/7wHg9sbJwc6h3NP1S9bekfAzB8CHifEcxKswCKUt3YQo"

echo ""
echo "=== Test: Shielded auth-transfer to owned private account ==="

SHIELDED_RECV=$(wallet account new private | grep -o 'Private/[^[:space:]]*' | head -1)
echo "Private recipient: $SHIELDED_RECV"
SHIELDED_KEYS=$(wallet account show-keys --account-id "$SHIELDED_RECV")
SHIELDED_NPK=$(echo "$SHIELDED_KEYS" | head -1)
SHIELDED_VPK=$(echo "$SHIELDED_KEYS" | tail -1)

wallet auth-transfer send --amount 2 \
  --from "m/44'/60'/0'/0/0" \
  --to-npk "$SHIELDED_NPK" \
  --to-vpk "$SHIELDED_VPK"
echo "Shielded auth-transfer sent"

sleep 15
wallet account get --account-id "m/44'/60'/0'/0/0"

echo ""
echo "=== Test: Deshielded auth-transfer: private account → keycard path 1 ==="

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
