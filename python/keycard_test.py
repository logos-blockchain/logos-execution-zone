import keycard_wallet as keycard_wallet
import time # For testing

pin = '111111'

my_wallet = keycard_wallet.KeycardWallet()
print("Setup communication with card...", my_wallet.setup_communication(pin))

print("Load mnemonic...", my_wallet.load_mnemonic())

print("Public key", my_wallet.get_public_key_for_path())

print("Signature", my_wallet.sign_message_for_path())

print("Disconnection", my_wallet.disconnect())