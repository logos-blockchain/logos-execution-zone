#!/usr/bin/env bash
# keycard_tests.sh — end-to-end keycard + token + AMM tests.
#
# Prerequisites:
#   1. Run wallet_with_keycard.sh once to install dependencies.
#   2. Reset the local chain so all accounts are uninitialized.
#   3. Keycard reader inserted with card loaded (wallet keycard load has been run).
#
# Non-keycard account-creation commands use "|| true" because label conflicts are
# harmless on re-runs against the same wallet storage — the existing labeled account
# (which is uninitialized on a fresh chain) is reused.

source venv/bin/activate
export KEYCARD_PIN=111111

# =============================================================================
# Keycard setup
# =============================================================================
echo "=== Test: wallet keycard available ==="
wallet keycard available

echo "=== Test: wallet keycard load ==="
wallet keycard load --mnemonic "fashion degree mountain wool question damp current pond grow dolphin chronic then"

# Register keycard account at path 0.
# auth-transfer init is idempotent: skips gracefully if nonce > 0.
echo "=== Test: auth-transfer init path 0 ==="
wallet auth-transfer init --key-path "m/44'/60'/0'/0/0"

echo "=== Test: account get path 0 ==="
wallet account get --key-path "m/44'/60'/0'/0/0"

echo "=== Test: pinata claim path 0 ==="
wallet pinata claim --key-path "m/44'/60'/0'/0/0"

echo "=== Test: account get path 0 (after claim) ==="
wallet account get --key-path "m/44'/60'/0'/0/0"

echo "=== Test: auth-transfer init path 1 ==="
wallet auth-transfer init --key-path "m/44'/60'/0'/0/1"

echo "=== Test: auth-transfer send path 0 → path 1 ==="
wallet auth-transfer send --amount 40 \
  --from-key-path "m/44'/60'/0'/0/0" \
  --to-key-path   "m/44'/60'/0'/0/1"

echo "=== Test: account get path 0 ==="
wallet account get --key-path "m/44'/60'/0'/0/0"
echo "=== Test: account get path 1 ==="
wallet account get --key-path "m/44'/60'/0'/0/1"

# =============================================================================
# (1) Shielded auth-transfer to an owned private account; verify decoded state.
#
# Use --to-label (ShieldedOwned path) so the wallet decodes the received note
# after sync and the balance is visible locally.
# =============================================================================
echo ""
echo "=== Test (1): Shielded auth-transfer to owned private account ==="

wallet auth-transfer send --amount 2 \
  --from-key-path "m/44'/60'/0'/0/0" \
  --to-npk "55204e2934045b044f06d8222b454d46b54788f33c7dec4f6733d441703bb0e6" \
  --to-vpk "02a8626b0c0ad9383c5678dad48c3969b4174fb377cdb03a6259648032c774cec8"
echo "Shielded auth-transfer sent"

# TODO: add a time delay here

wallet account get --key-path "m/44'/60'/0'/0/0"