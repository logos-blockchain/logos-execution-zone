# Run wallet_with_keycard.sh first

source venv/bin/activate # Load the appropriate virtual environment

export KEYCARD_PIN=111111

# Tests wallet keycard available
#   - Checks whether smart reader and keycard are both available.
echo "Test: wallet keycard available"
wallet keycard available

# Install a new mnemonic phrase to keycard
echo 'Test: wallet keycard load --mnemonic "fashion degree mountain wool question damp current pond grow dolphin chronic then"'
wallet keycard load --mnemonic "fashion degree mountain wool question damp current pond grow dolphin chronic then"

echo "Test: wallet auth-transfer init --key-path \"m/44'/60'/0'/0/0\""
wallet auth-transfer init --key-path "m/44'/60'/0'/0/0"

echo "Test: wallet account get --key-path \"m/44'/60'/0'/0/0\""
wallet account get --key-path "m/44'/60'/0'/0/0"

echo "Test: wallet pinata claim --key-path \"m/44'/60'/0'/0/0\""
wallet pinata claim --key-path "m/44'/60'/0'/0/0"

echo "Test: wallet account get --key-path \"m/44'/60'/0'/0/0\""
wallet account get --key-path "m/44'/60'/0'/0/0"

#echo "Initialize new account (auth-transfer init) and send"
wallet auth-transfer init --key-path "m/44'/60'/0'/0/1"
wallet auth-transfer send --amount 40 --from-key-path "m/44'/60'/0'/0/0" --to-key-path "m/44'/60'/0'/0/1"

echo "Test: wallet account get --key-path \"m/44'/60'/0'/0/0\""
wallet account get --key-path "m/44'/60'/0'/0/0"

echo "Test: wallet account get --key-path \"m/44'/60'/0'/0/1\""
wallet account get --key-path "m/44'/60'/0'/0/1"
