import keycard_wallet as keycard_wallet
import time # For testing



my_wallet = keycard_wallet.KeycardWallet()
print("Setup communication with card...", my_wallet.setup_communication())

#my_wallet.load_account_keys()

#pub_key = my_wallet.get_public_signing_key()

# TODO: now I want to specify LEE
#print(f"Public key: {list(pub_key)}")

#my_wallet.debug_key_export()
#priv_key = my_wallet.get_private_signing_key()
#print(f"Private key: {list(priv_key)}")

#my_wallet.remove_account_keys()

print("Disconnection", my_wallet.disconnect()) # To not do a stupid

"""
my_wallet.setup_communication()



# TODO: issues here
#priv_key = my_wallet.get_private_key()
#print(f"Private key: {list(priv_key)}")


#signature = my_wallet.sign_message_current_key()
#print(f"Signature: {signature.signature.hex()}")

#signature = my_wallet.sign_message_with_path("m/44'/60'/0'/0/1")
#print(f"Signature: {signature.signature.hex()}")

my_wallet.disconnect() # To not do a stupid
"""


