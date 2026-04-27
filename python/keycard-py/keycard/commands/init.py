from os import urandom
from ecdsa import SigningKey, VerifyingKey, ECDH, SECP256k1

from .. import constants
from ..card_interface import CardInterface
from ..crypto.aes import aes_cbc_encrypt
from ..crypto.generate_pairing_token import generate_pairing_token
from ..exceptions import NotSelectedError
from ..preconditions import require_selected


@require_selected
def init(
    card: CardInterface,
    pin: str | bytes,
    puk: str | bytes,
    pairing_secret: str | bytes
) -> None:
    '''
    Initializes a Keycard device with PIN, PUK, and pairing secret.

    Establishes an ephemeral ECDH key exchange and sends encrypted
    credentials to the card.

    Args:
        transport: The transport used to send APDU commands to the card.
        card_public_key (bytes): The card's ECC public key, usually
            retrieved via select().
        pin (bytes): The personal identification number (PIN) as bytes.
        puk (bytes): The personal unblocking key (PUK) as bytes.
        pairing_secret (bytes): A 32-byte shared secret or a passphrase that
            will be converted into one.

    Raises:
        NotSelectedError: If no card public key is provided.
        ValueError: If the encrypted data exceeds a single APDU length.
        APDUError: If the card returns a failure status word.
    '''
    if card.card_public_key is None:
        raise NotSelectedError('Card not selected. Call select() first.')

    if not isinstance(pin, bytes):
        pin = pin.encode('ascii')
    if not isinstance(puk, bytes):
        puk = puk.encode('ascii')
    if not isinstance(pairing_secret, bytes):
        pairing_secret = generate_pairing_token(pairing_secret)

    ephemeral_key = SigningKey.generate(curve=SECP256k1)
    our_pubkey_bytes: bytes = \
        ephemeral_key.verifying_key.to_string('uncompressed')
    card_pubkey = VerifyingKey.from_string(
        card.card_public_key,
        curve=SECP256k1
    )
    ecdh = ECDH(
        curve=SECP256k1,
        private_key=ephemeral_key,
        public_key=card_pubkey
    )
    shared_secret = ecdh.generate_sharedsecret_bytes()

    plaintext: bytes = pin + puk + pairing_secret
    iv: bytes = urandom(16)
    ciphertext: bytes = aes_cbc_encrypt(shared_secret, iv, plaintext)
    data: bytes = (
        bytes([len(our_pubkey_bytes)])
        + our_pubkey_bytes
        + iv
        + ciphertext
    )

    if len(data) > 255:
        raise ValueError('Data too long for single APDU')

    card.send_apdu(
        ins=constants.INS_INIT,
        data=data
    )
