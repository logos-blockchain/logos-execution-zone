from types import TracebackType
from typing import Optional, Union

from . import constants
from . import commands
from .apdu import APDUResponse
from .constants import DerivationOption, PairingMode
from .card_interface import CardInterface
from .exceptions import APDUError
from .parsing.application_info import ApplicationInfo
from .parsing.exported_key import ExportedKey
from .parsing.signature_result import SignatureResult
from .transport import Transport
from .secure_channel import SecureChannel


class KeyCard(CardInterface):
    '''
    High-level interface for interacting with a Keycard device.

    This class provides convenient methods to manage pairing, secure channels,
    and card operations.
    '''

    def __init__(self, transport: Optional[Transport] = None):
        '''
        Initializes the KeyCard interface.

        Args:
            transport (Transport): Instance used for APDU communication.

        Raises:
            ValueError: If transport is None.
        '''
        self.transport = transport if transport else Transport()
        self.card_public_key: Optional[bytes] = None
        self.session: Optional[SecureChannel] = None
        self._is_pin_verified: bool = False

    def __enter__(self) -> 'KeyCard':
        self.transport.connect()
        return self

    def __exit__(
        self,
        type_: type[BaseException] | None,
        value: BaseException | None,
        traceback: TracebackType | None
    ) -> None:
        if self.transport:
            self.transport.disconnect()

    @property
    def is_selected(self) -> bool:
        '''
        Checks if a card is selected and has a public key.

        Returns:
            bool: True if a card is selected, False otherwise.
        '''
        return self.card_public_key is not None

    @property
    def is_session_open(self) -> bool:
        '''
        Checks if a secure session is currently open.

        Returns:
            bool: True if a secure session is established, False otherwise.
        '''
        return self.session is not None

    @property
    def is_secure_channel_open(self) -> bool:
        '''
        Checks if a secure channel is currently open.

        Returns:
            bool: True if a secure channel is established, False otherwise.
        '''
        return self.session is not None and self.session.authenticated

    @property
    def is_initialized(self) -> bool:
        '''
        Checks if the Keycard is initialized.

        Returns:
            bool: True if the Keycard is initialized, False otherwise.
        '''
        return self._is_initialized

    @property
    def is_pin_verified(self) -> bool:
        '''
        Checks if the user PIN has been verified.

        Returns:
            bool: True if the PIN is verified, False otherwise.
        '''
        return self._is_pin_verified

    def select(self) -> 'ApplicationInfo':
        '''
        Selects the Keycard applet and retrieves application metadata.

        Returns:
            ApplicationInfo: Object containing ECC public key and card info.
        '''
        info = commands.select(self)
        self.card_public_key = info.ecc_public_key
        self._is_initialized = info.is_initialized
        return info

    def init(self, pin: str, puk: str, pairing_secret: str) -> None:
        '''
        Initializes the card with security credentials.

        Args:
            pin (bytes): The PIN code in bytes.
            puk (bytes): The PUK code in bytes.
            pairing_secret (bytes): The shared secret for pairing.
        '''
        commands.init(
            self,
            pin,
            puk,
            pairing_secret,
        )

    def ident(self, challenge: Optional[bytes] = None) -> bytes:
        '''
        Sends an identity challenge to the card.

        Args:
            challenge (bytes): A challenge (nonce or data) to send to the
                card. If None, a random 32-byte challenge is generated.

        Returns:
            bytes: The public key extracted from the card's identity response.
        '''
        return commands.ident(self, challenge)

    def open_secure_channel(
        self,
        pairing_index: int,
        pairing_key: bytes,
        mutually_authenticate: Optional[bool] = True
    ) -> None:
        '''
        Opens a secure session with the card.

        Args:
            pairing_index (int): Index of the pairing slot to use.
            pairing_key (bytes): The shared pairing key (32 bytes).
            mutually_authenticate (bool): Execute mutually authenticate when
                a secure channel has been opened
        '''
        self.session = commands.open_secure_channel(
            self,
            pairing_index,
            pairing_key,
        )

        if mutually_authenticate:
            self.mutually_authenticate()

    def mutually_authenticate(self) -> None:
        '''
        Performs mutual authentication between host and card.

        Raises:
            APDUError: If the authentication fails.
        '''
        commands.mutually_authenticate(self)

    def pair(
        self,
        shared_secret: bytes,
        pairing_mode: Optional[PairingMode] = PairingMode.ANY
    ) -> tuple[int, bytes]:
        '''
        Pairs with the card using an ECDH-derived shared secret.

        Args:
            shared_secret (bytes): 32-byte ECDH shared secret.

        Returns:
            tuple[int, bytes]: The pairing index and client cryptogram.
        '''
        return commands.pair(self, shared_secret, pairing_mode)

    def verify_pin(self, pin: str) -> bool:
        '''
        Verifies the user PIN with the card.

        Args:
            pin (str): The user-entered PIN.

        Returns:
            bool: True if PIN is valid, otherwise False.
        '''
        result = commands.verify_pin(self, pin.encode('utf-8'))
        self._is_pin_verified = True
        return result

    @property
    def status(self) -> dict[str, int | bool] | list[int]:
        '''
        Retrieves the application status using the secure session.

        Returns:
            dict: A dictionary with:
                - pin_retry_count (int)
                - puk_retry_count (int)
                - initialized (bool)

        Raises:
            RuntimeError: If the secure session is not open.
        '''
        if self.session is None:
            raise RuntimeError('Secure session not established')

        return commands.get_status(self)

    @property
    def get_key_path(self) -> dict[str, int | bool] | list[int]:
        '''
        Returns the current key derivation path from the card.

        Returns:
            list of int: List of 32-bit integers representing the key path.

        Raises:
            RuntimeError: If the secure session is not open.
        '''
        if self.session is None:
            raise RuntimeError('Secure session not established')

        return commands.get_status(self, key_path=True)

    def unpair(self, index: int) -> None:
        '''
        Removes a pairing slot from the card.

        Args:
            index (int): Index of the pairing slot to remove.
        '''
        commands.unpair(self, index)

    def factory_reset(self) -> None:
        '''
        Sends the FACTORY_RESET command to the card.

        Raises:
            APDUError: If the card returns a failure status word.
        '''
        commands.factory_reset(self)

    def generate_key(self) -> bytes:
        '''
        Generates a new key on the card and returns the key UID.

        Returns:
            bytes: Key UID (SHA-256 of the public key)

        Raises:
            APDUError: If the response status word is not 0x9000
        '''
        return commands.generate_key(self)

    def change_pin(self, new_value: str) -> None:
        '''
        Changes the user PIN on the card.

        Args:
            new_value (str): The new PIN value to set.

        Raises:
            ValueError: If input format is invalid.
            APDUError: If the response status word is not 0x9000.
        '''
        commands.change_secret(self, new_value, constants.PinType.USER)

    def change_puk(self, new_value: str) -> None:
        '''
        Changes the PUK on the card.

        Args:
            new_value (str): The new PUK value to set.

        Raises:
            ValueError: If input format is invalid.
            APDUError: If the response status word is not 0x9000.
        '''
        commands.change_secret(self, new_value, constants.PinType.PUK)

    def change_pairing_secret(self, new_value: str | bytes) -> None:
        '''
        Changes the pairing secret on the card.

        Args:
            new_value (str): The new pairing secret value to set.

        Raises:
            ValueError: If input format is invalid.
            APDUError: If the response status word is not 0x9000.
        '''
        commands.change_secret(self, new_value, constants.PinType.PAIRING)

    def unblock_pin(self, puk: str | bytes, new_pin: str | bytes) -> None:
        '''
        Unblocks the user PIN using the provided PUK and sets a new PIN.

        Args:
            puk_and_pin (str | bytes): Concatenation of PUK (12 digits) +
                new PIN (6 digits)

        Raises:
            ValueError: If the format is invalid.
            APDUError: If the card returns an error.
        '''
        if isinstance(puk, str):
            puk = puk.encode("utf-8")
        if isinstance(new_pin, str):
            new_pin = new_pin.encode("utf-8")

        commands.unblock_pin(self, puk + new_pin)

    def remove_key(self) -> None:
        '''
        Removes the current key from the card.

        Raises:
            APDUError: If the response status word is not 0x9000.
        '''
        commands.remove_key(self)

    def store_data(
        self,
        data: bytes,
        slot: constants.StorageSlot = constants.StorageSlot.PUBLIC
    ) -> None:
        """
        Stores data on the card in the specified slot.

        Args:
            data (bytes): The data to store (max 127 bytes).
            slot (StorageSlot): Where to store the data (PUBLIC, NDEF, CASH)

        Raises:
            ValueError: If slot is invalid or data is too long.
        """
        commands.store_data(self, data, slot)

    def get_data(
        self,
        slot: constants.StorageSlot = constants.StorageSlot.PUBLIC
    ) -> bytes:
        """
        Gets the data on the card previously stored with the store data command
        in the specified slot.

        Args:
            slot (StorageSlot): Where to retrieve the data (PUBLIC, NDEF, CASH)

        Raises:
            ValueError: If slot is invalid or data is too long.
        """
        return commands.get_data(self, slot)

    def export_key(
        self,
        derivation_option: constants.DerivationOption,
        public_only: bool,
        keypath: Optional[Union[str, bytes, bytearray]] = None,
        make_current: bool = False,
        source: constants.DerivationSource = constants.DerivationSource.MASTER
    ) -> ExportedKey:
        """
        Export a key from the card.

        This is a proxy for :func:`keycard.commands.export_key`, provided here
        for convenience.

        Args:
            derivation_option: One of the derivation options
                (CURRENT, DERIVE, DERIVE_AND_MAKE_CURRENT).
            public_only: If True, only the public key will be returned.
            keypath: BIP32-style string (e.g. "m/44'/60'/0'/0/0") or packed
                bytes. If derivation_option is CURRENT, this can be omitted.
            make_current: If True, updates the card’s current derivation path.
            source: Which node to derive from: MASTER, PARENT, or CURRENT.

        Returns:
            ExportedKey: An object containing the public key, and optionally
                the private key and chain code.

        See Also:
            - :func:`keycard.commands.export_key` - for the lower-level
                implementation
            - :class:`keycard.types.ExportedKey` - return value
                structure
        """
        return commands.export_key(
            self,
            derivation_option=derivation_option,
            public_only=public_only,
            keypath=keypath,
            make_current=make_current,
            source=source
        )

    def export_current_key(self, public_only: bool = False) -> ExportedKey:
        """
        Exports the current key from the card.

        This is a convenience method that uses the CURRENT derivation option
        and does not require a keypath.

        Args:
            public_only (bool): If True, only the public key will be returned.

        Returns:
            ExportedKey: An object containing the public key, and optionally
                the private key and chain code.
        """
        return self.export_key(
            derivation_option=constants.DerivationOption.CURRENT,
            public_only=public_only
        )

    def sign(
        self,
        digest: bytes,
        algorithm: constants.SigningAlgorithm = constants.SigningAlgorithm.ECDSA_SECP256K1,
    ) -> SignatureResult:
        """
        Sign using the currently loaded keypair.
        Requires PIN verification and secure channel.

        Args:
            digest (bytes): 32-byte hash to sign
            algorithm (SigningAlgorithm): Signing algorithm to use. Defaults to
                ECDSA_SECP256K1. Other options include SCHNORR_BIP340.

        Returns:
            SignatureResult: Parsed signature result, including the signature
                (DER or raw), algorithm, and optional recovery ID or
                public key.
        """
        return commands.sign(self, digest, DerivationOption.CURRENT, algorithm)

    def sign_with_path(
        self,
        digest: bytes,
        path: str,
        make_current: bool = False,
        algorithm: constants.SigningAlgorithm = constants.SigningAlgorithm.ECDSA_SECP256K1,
    ) -> SignatureResult:
        """
        Sign using a derived keypath. Optionally updates the current path.

        Args:
            digest (bytes): 32-byte hash to sign
            path (str): BIP-32-style path (e.g. "m/44'/60'/0'/0/0")
            make_current (bool): whether to update current path on card
            algorithm (SigningAlgorithm): Signing algorithm to use. Defaults to
                ECDSA_SECP256K1. Other options include SCHNORR_BIP340.

        Returns:
            SignatureResult: Parsed signature result, including the signature
                (DER or raw), algorithm, and optional recovery ID or
                public key.
        """
        p1 = (
            DerivationOption.DERIVE_AND_MAKE_CURRENT
            if make_current else DerivationOption.DERIVE
        )
        return commands.sign(self, digest, p1, algorithm, derivation_path=path)

    def sign_pinless(
        self,
        digest: bytes,
        algorithm: constants.SigningAlgorithm = constants.SigningAlgorithm.ECDSA_SECP256K1,
    ) -> SignatureResult:
        """
        Sign using the predefined PIN-less path.
        Does not require secure channel or PIN.

        Args:
            digest (bytes): 32-byte hash to sign
            algorithm (SigningAlgorithm): Signing algorithm to use. Defaults to
                ECDSA_SECP256K1. Other options include SCHNORR_BIP340.

        Returns:
            SignatureResult: Parsed signature result, including the signature
                (DER or raw), algorithm, and optional recovery ID or
                public key.

        Raises:
            APDUError: if no PIN-less path is set
        """
        return commands.sign(self, digest, DerivationOption.PINLESS, algorithm)

    def load_key(
        self,
        key_type: constants.LoadKeyType,
        public_key: Optional[bytes] = None,
        private_key: Optional[bytes] = None,
        chain_code: Optional[bytes] = None,
        bip39_seed: Optional[bytes] = None,
        lee_seed: Optional[bytes] = None
    ) -> bytes:
        """
        Load a key into the card for signing purposes.

        Args:
            key_type: Key type
            public_key: Optional ECC public key (tag 0x80).
            private_key: ECC private key (tag 0x81).
            chain_code: Optional chain code (tag 0x82, only for extended key).
            bip39_seed: 16 to 64-byte BIP39 seed (only for key_type=BIP39_SEED).
            lee_seed: 16 to 64-byte LEE seed (only for key_type=BIP39_SEED).

        Returns:
            UID of the loaded key (SHA-256 of public key).
        """
        return commands.load_key(
            self,
            key_type=key_type,
            public_key=public_key,
            private_key=private_key,
            chain_code=chain_code,
            bip39_seed=bip39_seed,
            lee_seed=lee_seed
        )

    def set_pinless_path(self, path: str) -> None:
        """
        Set a PIN-less path on the card. Allows signing without PIN/auth if the
        current derived key matches this path.

        Args:
            path (str): BIP-32-style path (e.g., "m/44'/60'/0'/0/0"). An empty
                        string disables the pinless path.
        """
        commands.set_pinless_path(self, path)

    def generate_mnemonic(self, checksum_size: int = 6) -> list[int]:
        """
        Generate a BIP39 mnemonic using the card's RNG.

        Args:
            checksum_size (int): Number of checksum bits
                (between 4 and 8 inclusive).

        Returns:
            List[int]: List of integers (0-2047) corresponding to wordlist
                indexes.
        """
        return commands.generate_mnemonic(self, checksum_size)

    def derive_key(self, path: str = '') -> None:
        """
        Set the derivation path for subsequent SIGN and EXPORT KEY commands.

        Args:
            path (str): BIP-32-style path (e.g., "m/44'/60'/0'/0/0") or
                        "../0/1" (parent) or "./0" (current).
        """
        commands.derive_key(self, path)

    def send_apdu(
        self,
        ins: int,
        p1: int = 0x00,
        p2: int = 0x00,
        data: bytes = b'',
        cla: Optional[int] = None
    ) -> bytes:
        if cla is None:
            cla = constants.CLA_PROPRIETARY

        response: APDUResponse = self.transport.send_apdu(
            bytes([cla, ins, p1, p2, len(data)]) + data
        )

        if response.status_word != constants.SW_SUCCESS:
            raise APDUError(response.status_word)

        return bytes(response.data)

    def send_secure_apdu(
        self,
        ins: int,
        p1: int = 0x00,
        p2: int = 0x00,
        data: bytes = b''
    ) -> bytes:
        if not self.session or not self.session.authenticated:
            raise RuntimeError('Secure channel not established')

        encrypted = self.session.wrap_apdu(
            cla=constants.CLA_PROPRIETARY,
            ins=ins,
            p1=p1,
            p2=p2,
            data=data
        )

        response: APDUResponse = self.transport.send_apdu(
            bytes([
                constants.CLA_PROPRIETARY,
                ins,
                p1,
                p2,
                len(encrypted)
            ]) + encrypted
        )

        if response.status_word != 0x9000:
            raise APDUError(response.status_word)

        plaintext, sw = self.session.unwrap_response(response)

        if sw != 0x9000:
            raise APDUError(sw)

        return plaintext
