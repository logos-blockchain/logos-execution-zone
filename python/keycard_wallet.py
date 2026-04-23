from smartcard.System import readers  
from keycard.exceptions import APDUError, TransportError
from ecdsa import VerifyingKey, SECP256k1  

from keycard.keycard import KeyCard

from mnemonic import Mnemonic  
from keycard import constants  
  
import keycard

PIN = '123456'
PUK = '123456123456'
DEFAULT_PAIRING_PASSWORD = "KeycardDefaultPairing"
DEFAULT_MNEMONIC = "fashion degree mountain wool question damp current pond grow dolphin chronic then"
DEFAULT_PASSPHRASE = ""

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
                return False
            
            if self.pairing_index is None: 
                pairing_index, pairing_key = self.card.pair(password)   
                self.pairing_index = pairing_index
                self.pairing_key = pairing_key 

               
            self.card.open_secure_channel(pairing_index, pairing_key)  
            self.card.verify_pin(pin)

            return True
        except Exception as e:  
            print(f"Error: {e}")  
            return False

    def load_mnemonic(self, mnemonic = DEFAULT_MNEMONIC, passphrase = DEFAULT_PASSPHRASE) -> bool:
        try:
            # Convert mnemonic to seed  
            mnemo = Mnemonic("english")  
            seed = mnemo.to_seed(mnemonic, passphrase)  

            print(f"PIN verified: {self.card.is_pin_verified}")  
            print(f"Secure channel open: {self.card.is_secure_channel_open}")  
            print(f"Card initialized: {self.card.status.get('initialized', False)}")  
            print(f"Seed length: {len(seed)}")

            # Load the LEE seed onto the card  
            result = self.card.load_key(  
                key_type = constants.LoadKeyType.BIP39_SEED,  
                bip39_seed = seed  
            )

            return True
        except Exception as e:
            print(f"Error during disconnect: {e}")
            return False

    def disconnect(self) -> bool:
        try:
            if not self.card.is_secure_channel_open:
                return None
            
            self.card.unpair(self.pairing_index)
            self.pairing_index = None
            self.pairing_key = None

            return True
        except Exception as e:
            print(f"Error during unpair: {e}")
            return False
        
    def get_public_key_for_path(self, path: str = "m/44'/60'/0'/0/0") -> str | None:
        try:
            if not self.card.is_secure_channel_open or not self.card.is_pin_verified:
                return None

            public_key = self.card.export_key(  
                derivation_option = constants.DerivationOption.DERIVE,  
                public_only = True,  
                keypath = path  
            )   

            return public_key.public_key.hex()
        
        except Exception as e:
            print(f"Error getting public key: {e}")
            return None

    def sign_message_for_path(self, message: bytes = b"DefaultMessageTestDefaultMessage", path: str = "m/44'/60'/0'/0/0") -> str | None:
        try:
            if not self.card.is_secure_channel_open or not self.card.is_pin_verified:
                return None
            
            signature = self.card.sign_with_path(
                digest = message,
                path= path,
                make_current = False
            )

            return signature.signature.hex()

        except Exception as e:
            print(f"Error signing message: {e}")
            return None