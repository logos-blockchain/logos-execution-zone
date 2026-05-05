#!/usr/bin/env bash
# keycard_test_3.sh — tests for `wallet keycard get-private-keys`.
#
# Prerequisites:
#   1. Run wallet_with_keycard.sh once to install dependencies.
#   2. Keycard reader inserted with card loaded (wallet keycard load has been run).

source venv/bin/activate
export KEYCARD_PIN=111111

echo "=== Test: wallet keycard get-private-keys path 0 ==="
wallet keycard get-private-keys --key-path "m/44'/60'/0'/0/0"

echo "=== Test: wallet keycard get-private-keys path 1 ==="
wallet keycard get-private-keys --key-path "m/44'/60'/0'/0/1"

echo ""
echo "=== All get-private-keys tests finished ==="
