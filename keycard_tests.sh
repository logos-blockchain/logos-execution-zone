# Run wallet_with_keycard.sh first

source venv/bin/activate # Load the appropriate virtual environment

# Tests wallet keycard available
#   - Checks whether smart reader and keycard are both available.
echo "Test: wallet keycard available"
wallet keycard available

echo 'Test: wallet keycard load --pin 111111 --mnemonic "final empty hair duty next drastic normal miss wreck wreck strategy omit"'
# Install a new mnemonic phrase to keycard
wallet keycard load --pin 111111 --mnemonic "fashion degree mountain wool question damp current pond grow dolphin chronic then"
# Commented out to avoid resetting card constantly

echo "Test: wallet auth-transfer --pin 111111 --key-path \"m/44'/60/0\'/0/0\""
wallet auth-transfer init --pin 111111 --key-path "m/44'/60'/0'/0/0"

echo "Test: wallet account get --pin 111111 --key-path \"m/44'/60'/0'/0/0\""
wallet account get --pin 111111 --key-path "m/44'/60'/0'/0/0"


echo "Test: wallet pinata claim --pin 111111 --key-path \"m/44'/60'/0'/0/0\""
wallet pinata claim --pin 111111 --key-path "m/44'/60'/0'/0/0"


echo "Test: wallet account get --pin 111111 --key-path \"m/44'/60'/0'/0/0\""
wallet account get --pin 111111 --key-path "m/44'/60'/0'/0/0"

echo "Initialize new account (auth-transfer init) and send"
wallet auth-transfer init --pin 111111 --key-path "m/44'/60'/0'/0/1"
wallet auth-transfer send --amount 40 --pin 111111 --from-key-path "m/44'/60'/0'/0/0" --to-key-path "m/44'/60'/0'/0/1"

echo "Test: wallet account get --pin 111111 --key-path \"m/44'/60'/0'/0/0\""
wallet account get --pin 111111 --key-path "m/44'/60'/0'/0/0"

echo "Test: wallet account get --pin 111111 --key-path \"m/44'/60'/0'/0/1\""
wallet account get --pin 111111 --key-path "m/44'/60'/0'/0/1"
