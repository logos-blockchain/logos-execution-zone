#!/bin/bash
# Power-recovery variant of keycard_tests.sh.
#
# Forces a card power cycle before each keycard-backed wallet command to verify
# commands survive mid-session power loss.

export KEYCARD_PIN=111111
export KEYCARD_CA_PUBLIC_KEY=025877220aaae6e54a6f974602d5995c0fe24a3ea7ddabd8644bec795b9da00743

# A genesis-funded account of this wallet, used to fund the keycard accounts.
FUNDED_ACCOUNT="${FUNDED_ACCOUNT:-my-account}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

unpower() {
    cargo run -q --manifest-path "$SCRIPT_DIR/../Cargo.toml" --bin force_unpower
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
echo "Test: fund keycard account via wallet auth-transfer send (after power cycle)"
unpower
wallet auth-transfer send --amount 200 --from "$FUNDED_ACCOUNT" --to "m/44'/60'/0'/0/0"

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
