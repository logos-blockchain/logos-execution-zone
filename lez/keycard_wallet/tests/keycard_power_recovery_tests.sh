#!/bin/bash
# Power-recovery variant of keycard_tests.sh.
#
# Forces a card power cycle before each keycard-backed wallet command to verify
# commands survive mid-session power loss.

source venv/bin/activate

export KEYCARD_PIN=111111

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

unpower() {
    python "$SCRIPT_DIR/force_unpower.py"
}

echo "Test: wallet keycard available"
wallet keycard available

echo ""
echo "Test: wallet keycard load (after power cycle)"
export KEYCARD_MNEMONIC="fashion degree mountain wool question damp current pond grow dolphin chronic then"
unpower
wallet keycard load
unset KEYCARD_MNEMONIC

echo ""
echo "Test: wallet auth-transfer init --account-id \"m/44'/60'/0'/0/0\" (after power cycle)"
unpower
wallet auth-transfer init --account-id "m/44'/60'/0'/0/0"

echo ""
echo "Test: wallet account get --account-id \"m/44'/60'/0'/0/0\" (after power cycle)"
unpower
wallet account get --account-id "m/44'/60'/0'/0/0"

echo ""
echo "Test: wallet pinata claim --to \"m/44'/60'/0'/0/0\" (after power cycle)"
unpower
wallet pinata claim --to "m/44'/60'/0'/0/0"

echo ""
echo "Test: wallet account get --account-id \"m/44'/60'/0'/0/0\" (after power cycle)"
unpower
wallet account get --account-id "m/44'/60'/0'/0/0"

echo ""
echo "Test: wallet auth-transfer init and send between two keycard accounts (after power cycle)"
unpower
wallet auth-transfer init --account-id "m/44'/60'/0'/0/1"
unpower
wallet auth-transfer send --amount 40 --from "m/44'/60'/0'/0/0" --to "m/44'/60'/0'/0/1"

echo ""
echo "Test: wallet account get --account-id \"m/44'/60'/0'/0/0\" (after power cycle)"
unpower
wallet account get --account-id "m/44'/60'/0'/0/0"

echo ""
echo "Test: wallet account get --account-id \"m/44'/60'/0'/0/1\" (after power cycle)"
unpower
wallet account get --account-id "m/44'/60'/0'/0/1"

echo ""
echo "Test: create local wallet account"
LOCAL_ACCOUNT_ID=$(wallet account new public 2>&1 | grep -oP '(?<=Public/)\S+')
echo "Created local account: Public/${LOCAL_ACCOUNT_ID}"

echo ""
echo "Test: wallet auth-transfer init local account"
wallet auth-transfer init --account-id "Public/${LOCAL_ACCOUNT_ID}"

echo ""
echo "Test: wallet auth-transfer send from keycard to local account (after power cycle)"
unpower
wallet auth-transfer send --amount 10 --from "m/44'/60'/0'/0/0" --to "Public/${LOCAL_ACCOUNT_ID}"

echo ""
echo "Test: wallet account get --account-id \"m/44'/60'/0'/0/0\" (after power cycle)"
unpower
wallet account get --account-id "m/44'/60'/0'/0/0"

echo ""
echo "Test: wallet account get --account-id \"Public/${LOCAL_ACCOUNT_ID}\" (after power cycle)"
unpower
wallet account get --account-id "Public/${LOCAL_ACCOUNT_ID}"

echo ""
echo "Test: wallet auth-transfer send from local account to keycard account (after power cycle)"
unpower
wallet auth-transfer send --amount 10 --from "Public/${LOCAL_ACCOUNT_ID}" --to "m/44'/60'/0'/0/1"

echo ""
echo "Test: wallet account get --account-id \"Public/${LOCAL_ACCOUNT_ID}\" (after power cycle)"
unpower
wallet account get --account-id "Public/${LOCAL_ACCOUNT_ID}"

echo ""
echo "Test: wallet account get --account-id \"m/44'/60'/0'/0/1\" (after power cycle)"
unpower
wallet account get --account-id "m/44'/60'/0'/0/1"

echo ""
echo "Test: wallet auth-transfer send from keycard to foreign account (after power cycle)"
wallet account get --account-id "Public/7wHg9sbJwc6h3NP1S9bekfAzB8CHifEcxKswCKUt3YQo"
unpower
wallet auth-transfer send --amount 10 --from "m/44'/60'/0'/0/0" --to "Public/7wHg9sbJwc6h3NP1S9bekfAzB8CHifEcxKswCKUt3YQo"

echo ""
echo "Test: wallet account get --account-id \"m/44'/60'/0'/0/0\" (after power cycle)"
unpower
wallet account get --account-id "m/44'/60'/0'/0/0"

echo ""
echo "Test: wallet account get foreign account (after power cycle)"
unpower
wallet account get --account-id "Public/7wHg9sbJwc6h3NP1S9bekfAzB8CHifEcxKswCKUt3YQo"
