#!/usr/bin/env bash
# keycard_test_3.sh — tests for `wallet keycard get-private-keys`.
#
# Prerequisites:
#   1. Keycard reader inserted with card loaded (wallet keycard load has been run).

cargo install --path lez/wallet --force --features keycard-debug

export KEYCARD_PIN=111111
export KEYCARD_CA_PUBLIC_KEY=025877220aaae6e54a6f974602d5995c0fe24a3ea7ddabd8644bec795b9da00743

echo "=== Test: wallet keycard get-private-keys path 10 ==="
wallet keycard get-private-keys --key-path "m/44'/60'/0'/0/10" --reveal

echo "=== Test: wallet keycard get-private-keys path 11 ==="
wallet keycard get-private-keys --key-path "m/44'/60'/0'/0/11" --reveal

echo ""
echo "=== All get-private-keys tests finished ==="
