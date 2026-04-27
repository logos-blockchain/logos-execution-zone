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


# initialize account keys (outside of keycard)
# Eventually use for tokens and shielded
wallet account new private
wallet account new public
wallet account new public
wallet account new public
wallet account new public

# Initialize Token A
wallet token new --definition-account-id "Public/4rXJzAEVn9Av1bK1RR4orTJP8dJDzRuoTBRsXVn1pwcK" --supply-account-id "Public/3PfkXqePVRnet5H1PbnfgeWykBrqX3KPPeMBESJt4QEd" --total-supply 1000 --name LEZT

# Initialize Token B
wallet token new --definition-account-id "Public/DjJx9ccoRyv1xxmHmpFy8mATeKq3Es1DnobjT4EZ4ab2" --supply-account-id "Public/EKgmwG9n7jMYkKaTYdZa7ELyYZq5f43oBKuCiu3t3Tm8" --total-supply 1000 --name LEET

# Send Token A to a new wallet account

# Send from non keycard account to an account owned by keycard.
wallet token send --from "Public/3PfkXqePVRnet5H1PbnfgeWykBrqX3KPPeMBESJt4QEd" --to "Public/6iYPF671bMDEkADFvHgcJDrYHJMqZv6cYbxVMsUU7LFE" --amount 400
# This fails due to lack of initialization for Token Account


wallet auth-transfer send --amount 40 --pin 111111 --from-key-path "m/44'/60'/0'/0/0" --to-npk "55204e2934045b044f06d8222b454d46b54788f33c7dec4f6733d441703bb0e6" --to-vpk "02a8626b0c0ad9383c5678dad48c3969b4174fb377cdb03a6259648032c774cec8"
