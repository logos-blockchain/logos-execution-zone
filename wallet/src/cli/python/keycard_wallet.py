from smartcard.System import readers  
from keycard.exceptions import APDUError, TransportError
from ecdsa import VerifyingKey, SECP256k1  

from keycard.keycard import KeyCard

from mnemonic import Mnemonic  
from keycard import constants  
  
import keycard

PIN = '123456'
DEFAULT_PAIRING_PASSWORD = "KeycardDefaultPairing"

class KeycardWallet:
    def __init__(self):
        self.card = KeyCard()
        self.pairing_index = None
        self.pairing_key = None

    def _is_smart_card_reader_detected(self) -> bool:  
        try:  
            return len(readers()) > 0  
        except Exception:
            return False
    
    def _is_keycard_detected(self) -> bool:
        try:
            KeyCard().select()
            return True
        except (TransportError, APDUError, Exception):  
            # No readers, no card, or card doesn't respond.  
            return False
  
    # Wrapped
    def is_unpaired_keycard_available(self) -> bool:
        if not self._is_smart_card_reader_detected():
            return False
        elif not self._is_keycard_detected():
            return False
        return True

    # Wrapped
    def setup_communication(self, pin = PIN, password = DEFAULT_PAIRING_PASSWORD) -> bool:
        try:   
            self.card.select()  
                
            if not self.card.is_initialized:
                # TODO: need to be able to initialize a card.
                return False
            
            if self.pairing_index is None: 
                pairing_index, pairing_key = self.card.pair(password) #Testing   
                self.pairing_index = pairing_index
                self.pairing_key = pairing_key 
               
            self.card.open_secure_channel(pairing_index, pairing_key)  
            self.card.verify_pin(PIN)      
            return True
        except Exception as e:  
            print(f"Error: {e}")  
            return False

    """
    # Needs to be more robust to handle card removal and reinsertion
    def is_selected_card_available(self) -> bool:
        if self.transport.connection is None:
                return False
        
        try:
            #TODO: fix this up Try a lightweight operation  
            # Card is present
            self.card.send_apdu(cla=0x00, ins=0xA4, p1=0x04, p2=0x00, data=b'')
           # return True  
        except Exception:  
            return False
        
        # TODO: attempt to prevent a new card from being inserted
        return self.card.is_selected  

    """

    # Wrapped
    def disconnect(self) -> bool:
        try:
            self.card.unpair(self.pairing_index)
            self.pairing_index = None
            self.pairing_key = None
            return True
        except Exception as e:
            print(f"Error during disconnect: {e}")
            return False

    # TODO: add path?
    # Wrapped
    def get_public_signing_key(self):
        uncompressed_pub_key = self.card.export_current_key(public_only=True).public_key

        # Convert to VerifyingKey object  
        vk = VerifyingKey.from_string(uncompressed_pub_key, curve=SECP256k1)  
      
        return vk.to_string("compressed")[1:]
    
    """
    # TODO: don't think this possible; blocked by firmware
    def get_private_signing_key(self):  
        try:
            exported = self.card.export_current_key(public_only=False)  
            print(f"Exported key: {exported}")  
            print(f"Public key: {exported.public_key.hex() if exported.public_key else 'None'}")  
            print(f"Private key: {exported.private_key.hex() if exported.private_key else 'None'}")  
            print(f"Chain code: {exported.chain_code.hex() if exported.chain_code else 'None'}")  
            
            if exported.private_key is None:  
                raise ValueError("No private key returned - key may not be loaded on card")  
                
            return exported.private_key  
        except Exception as e:  
            print(f"Error exporting key: {e}")  
            raise
    """
    # TODO: delete this function
    def debug_key_export(self):  
        """Debug why key export fails with SW=6985"""  
        
        # 1. Check if a key exists  
        try:  
            status = self.card.status  
            print(f"Status: {status}")  
        except Exception as e:  
            print(f"Cannot get status: {e}")  
        
        # 2. Try public key export first  
        try:  
            exported = self.card.export_current_key(public_only=True)  
            print(f"Public key export: {exported.public_key.hex() if exported.public_key else 'None'}")  
        except Exception as e:  
            print(f"Public key export failed: {e}")  
        
        # 3. Check if key needs to be generated  
        try:  
            key_uid = self. card.generate_key()  
            print(f"Generated key UID: {key_uid.hex()}")  
        except Exception as e:  
            print(f"Key generation failed: {e}")  
        
        # 4. Try private export again  
        try:  
            exported = self.card.export_current_key(public_only=False)
            if exported.private_key:  
                print(f"Private key: {exported.private_key.hex()}")  
            else:  
                print("Private key is None - key may not allow export")  
        except Exception as e:  
            print(f"Private key export failed: {e}")
    
    #TODO: check well formed?
    # Wrapped
    def change_path(self, path):
        self.card.derive_key(path)

    # Message must be 32 bytes
    # TODO: rename to current_path
    # Wrapped
    def sign_message_current_key(self, message = b"TestMessageMustBe32Bytes!\x00\x00\x00\x00\x00\x00\x00"):
        # Message must be sent bytes
        return self.card.sign(message, constants.SigningAlgorithm.SCHNORR_BIP340)
    

    # Does not update the path
    # Wrapped
    def sign_message_with_path(self, path, message = b"TestMessageMustBe32Bytes!\x00\x00\x00\x00\x00\x00\x00"):
        # must be sent bytes
        return self.card.sign_with_path(message, path, False, constants.SigningAlgorithm.SCHNORR_BIP340)
    
    # Wrapped
    def remove_account_keys(self):
        self.card.remove_key()

    # TODO: update to accept a different language?
    def load_account_keys(self, mnemonic) :
        mnemo = Mnemonic("english")  
        seed = mnemo.to_seed(mnemonic, passphrase="")  
        
        # Load the seed onto the card  
        result = self.card.load_key(
            key_type= constants.LoadKeyType.BIP39_SEED,  
            lee_seed=seed  
        )