import keycard_wallet as keycard_wallet
import time # For testing

pin = '111111'
path0 = "m/44'/60'/0'/0/0"
path1 = "m/44'/61'/0'/0/0"
path2 = "m/44'/62'/0'/0/0"
path3 = "m/44'/63'/0'/0/0"
path4 = "m/44'/64'/0'/0/0"

my_wallet = keycard_wallet.KeycardWallet()
print("Setup communication with card...", my_wallet.setup_communication(pin))

print("Load mnemonic...", my_wallet.load_mnemonic())

print("Public key", my_wallet.get_public_key_for_path(path0))
print("Public key", my_wallet.get_public_key_for_path(path1))
print("Public key", my_wallet.get_public_key_for_path(path2))
print("Public key", my_wallet.get_public_key_for_path(path3))
print("Public key", my_wallet.get_public_key_for_path(path4))

print("Signature", my_wallet.sign_message_for_path())

print("Disconnection", my_wallet.disconnect())