from smartcard.System import readers
from keycard.exceptions import APDUError, TransportError
from ecdsa import VerifyingKey, SECP256k1

from keycard.keycard import KeyCard
from keycard.commands.export_lee_key import export_lee_key
from mnemonic import Mnemonic
from keycard import constants

import os
import secrets

DEFAULT_PAIRING_PASSWORD = "KeycardDefaultPairing"

def _pairing_password() -> str:
    return os.environ.get("KEYCARD_PAIRING_PASSWORD", DEFAULT_PAIRING_PASSWORD)

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

    def initialize(self, pin: str, pairing_password: str | None = None) -> bool:
        try:
            self.card.select()

            if self.card.is_initialized:
                raise RuntimeError("Card is already initialized")

            puk = ''.join(secrets.choice('0123456789') for _ in range(12))
            self.card.init(pin, puk, pairing_password or _pairing_password())
            print(f"Keycard PUK: {puk}")
            print("Record this PUK and store it somewhere safe. It cannot be recovered.")
            return True
        except Exception as e:
            raise RuntimeError(f"Error initializing keycard: {e}") from e

    def _reconnect(self) -> None:
        self.card = KeyCard()
        self.card.select()

    def _pair(self, pin: str, password: str) -> tuple[int, bytes]:
        self.card.select()

        if not self.card.is_initialized:
            raise RuntimeError("Card is not initialized — run 'wallet keycard init' first")

        pairing_index, pairing_key = self.card.pair(password)
        self.pairing_index = pairing_index
        self.pairing_key = pairing_key

        try:
            self.card.open_secure_channel(pairing_index, pairing_key)
            self.card.verify_pin(pin)
        except Exception as e:
            try:
                self.card.unpair(pairing_index)
            except Exception:
                pass
            raise RuntimeError(f"Error opening secure channel after fresh pair: {e}") from e

        return pairing_index, pairing_key

    def pair(self, pin: str, password: str | None = None) -> tuple[int, bytes]:
        password = password or _pairing_password()
        try:
            return self._pair(pin, password)
        except TransportError as e:
            print(f"Transport error during fresh pair ({e}), attempting card reset and retry...")
            try:
                self._reconnect()
                result = self._pair(pin, password)
                print("Retry succeeded after card reset.")
                return result
            except TransportError as e2:
                raise RuntimeError(
                    "Card lost power and did not recover after reset. "
                    "Try reseating the card in the reader."
                ) from e2

    def _setup_communication_with_pairing(self, pin: str, pairing_index: int, pairing_key: bytes) -> bool:
        self.card.select()

        if not self.card.is_initialized:
            raise RuntimeError("Card is not initialized — run 'wallet keycard init' first")

        self.pairing_index = pairing_index
        self.pairing_key = pairing_key

        try:
            self.card.open_secure_channel(pairing_index, pairing_key)
            self.card.verify_pin(pin)
        except Exception as e:
            raise RuntimeError(f"Error setting up communication with stored pairing: {e}") from e

        return True

    def setup_communication_with_pairing(self, pin: str, pairing_index: int, pairing_key: bytes) -> bool:
        try:
            return self._setup_communication_with_pairing(pin, pairing_index, pairing_key)
        except TransportError as e:
            print(f"Transport error during stored pairing ({e}), attempting card reset and retry...")
            try:
                self._reconnect()
                result = self._setup_communication_with_pairing(pin, pairing_index, pairing_key)
                print("Retry succeeded after card reset.")
                return result
            except TransportError as e2:
                raise RuntimeError(
                    "Card lost power and did not recover after reset. "
                    "Try reseating the card in the reader."
                ) from e2

    def close_session(self) -> bool:
        return True

    def load_mnemonic(self, mnemonic: str) -> bool:
        try:
            # Convert mnemonic to seed  
            mnemo = Mnemonic("english")
            if not mnemo.check(mnemonic):
                raise RuntimeError("Invalid mnemonic phrase — check spelling and word count")
            seed = mnemo.to_seed(mnemonic)

            # Load the LEE seed onto the card  
            result = self.card.load_key(  
                key_type = constants.LoadKeyType.LEE_SEED,  
                lee_seed = seed  
            )
            return True
        except Exception as e:
            raise RuntimeError(f"Error loading mnemonic: {e}") from e

    def disconnect(self) -> bool:
        try:
            if not self.card.is_secure_channel_open:
                return False
            
            self.card.unpair(self.pairing_index)

            return True
        except Exception as e:
            raise RuntimeError(f"Error during disconnect: {e}") from e
        
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
            raise RuntimeError(f"Error getting public key: {e}") from e


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
            raise RuntimeError(f"Error signing message: {e}") from e

    def get_private_keys_for_path(self, path: str = "m/44'/60'/0'/0/0") -> bytes | None:
        try:
            if not self.card.is_secure_channel_open or not self.card.is_pin_verified:
                return None

            private_keys = export_lee_key(
                self.card,
                constants.DerivationOption.DERIVE,
                path
            )

            nsk = private_keys.lee_nsk
            vsk = private_keys.lee_vsk

            return (nsk, vsk)
        
        except Exception as e:
            raise RuntimeError(f"Error getting private keys: {e}") from e
            
