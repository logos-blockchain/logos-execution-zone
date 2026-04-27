import hashlib
from os import urandom
from typing import Optional

from .. import constants
from ..card_interface import CardInterface
from ..crypto.generate_pairing_token import generate_pairing_token
from ..exceptions import InvalidResponseError
from ..preconditions import require_initialized


@require_initialized
def pair(
    card: CardInterface,
    shared_secret: str | bytes,
    pairing_mode: Optional[constants.PairingMode] = constants.PairingMode.ANY
) -> tuple[int, bytes]:
    '''
    Performs an ECDH-based pairing handshake with the card.

    Args:
        card: The keycard interface.
        shared_secret: A 32-byte secret or a passphrase convertible to one.
        pairing_mode: Mode for pairing: ANY, EPHEMERAL, PERSISTENT

    Returns:
        tuple[int, bytes]: Pairing index and derived 32-byte pairing key.

    Raises:
        ValueError: If the shared secret is not 32 bytes.
        APDUError: If the card returns a non-success status word.
        InvalidResponseError: If response lengths or values are unexpected.
    '''
    if isinstance(shared_secret, str):
        shared_secret = generate_pairing_token(shared_secret)

    if len(shared_secret) != 32:
        raise ValueError('Shared secret must be 32 bytes')

    client_challenge = urandom(32)

    response = card.send_apdu(
        ins=constants.INS_PAIR,
        p2=pairing_mode,
        data=client_challenge
    )

    if len(response) != 64:
        raise InvalidResponseError('Unexpected response length')

    card_cryptogram = response[:32]
    card_challenge = response[32:]

    expected = hashlib.sha256(shared_secret + client_challenge).digest()

    if card_cryptogram != expected:
        raise InvalidResponseError('Card cryptogram mismatch')

    client_cryptogram = hashlib.sha256(shared_secret + card_challenge).digest()

    response = card.send_apdu(
        ins=constants.INS_PAIR,
        p1=0x01,
        data=client_cryptogram
    )

    if len(response) != 33:
        raise InvalidResponseError('Unexpected response length')

    pairing_index = response[0]
    salt = response[1:]

    pairing_key = hashlib.sha256(shared_secret + salt).digest()

    return pairing_index, pairing_key
