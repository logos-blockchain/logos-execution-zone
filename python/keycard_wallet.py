from smartcard.System import readers  
from keycard.exceptions import APDUError, TransportError
from ecdsa import VerifyingKey, SECP256k1  

from keycard.keycard import KeyCard

from mnemonic import Mnemonic  
from keycard import constants  
  
import keycard

DEFAULT_PAIRING_PASSWORD = "KeycardDefaultPairing"

class KeycardWallet:
    def __init__(self):
        self.card = KeyCard()

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
  
    def is_unpaired_keycard_available(self) -> bool:
        if not self._is_smart_card_reader_detected():
            return False
        elif not self._is_keycard_detected():
            return False
        return True

    def setup_communication(self, pin: str, password = DEFAULT_PAIRING_PASSWORD) -> bool:
        try:   
            self.card.select()  
                
            if not self.card.is_initialized:
                return False
            
            pairing_index, pairing_key = self.card.pair(password)
            self.pairing_index = pairing_index

            self.card.open_secure_channel(pairing_index, pairing_key)  
            self.card.verify_pin(pin)

            return True
        except Exception as e:  
            print(f"Error: {e}")  
            return False

    def load_mnemonic(self, mnemonic: str) -> bool:
        try:
            # Convert mnemonic to seed  
            mnemo = Mnemonic("english")  
            seed = mnemo.to_seed(mnemonic)  

            # Load the LEE seed onto the card  
            result = self.card.load_key(  
                key_type = constants.LoadKeyType.LEE_SEED,  
                lee_seed = seed  
            )

            #TODO: this appears to be the issue.
            return True
        except Exception as e:
            print(f"Error during disconnect: {e}")
            return False

    def disconnect(self) -> bool:
        try:
            if not self.card.is_secure_channel_open:
                return None
            
            self.card.unpair(self.pairing_index)

            return True
        except Exception as e:
            print(f"Error during unpair: {e}")
            return False
        
    def get_public_key_for_path(self, path: str = "m/44'/60'/0'/0/0") -> bytes | None:
        try:
            if not self.card.is_secure_channel_open or not self.card.is_pin_verified:
                return None

            public_key = self.card.export_key(  
                derivation_option = constants.DerivationOption.DERIVE,  
                public_only = True,  
                keypath = path  
            )   

            public_key = public_key.public_key
            public_key = VerifyingKey.from_string(public_key[1:], curve=SECP256k1)  
            public_key = public_key.to_string("compressed")[1:]

            return public_key
        
        except Exception as e:
            print(f"Error getting public key: {e}")
            return None


    def sign_message_for_path(self, message: bytes, path: str = "m/44'/60'/0'/0/0") -> bytes | None:
        try:
            if not self.card.is_secure_channel_open or not self.card.is_pin_verified:
                return None

            signature = self.card.sign_with_path(
                digest = message,
                path = path,
                algorithm = constants.SigningAlgorithm.SCHNORR_BIP340,
                make_current = False
            )

            return signature.signature

        except Exception as e:
            print(f"Error signing message: {e}")
            return None