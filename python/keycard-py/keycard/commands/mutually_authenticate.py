import os
from ..card_interface import CardInterface
from .. import constants
from ..preconditions import require_secure_channel
from typing import Optional


@require_secure_channel
def mutually_authenticate(
    card: CardInterface,
    client_challenge: Optional[bytes] = None
) -> None:
    '''
    Performs mutual authentication between the client and the Keycard.

    Preconditions:
        - Secure Channel must be opened

    The card will respond with a cryptographic challenge. The secure
    session will verify the response. If the response is not exactly
    32 bytes, or if the response has an unexpected status word, the
    function raises an error.

    Args:
        transport: A Transport instance for sending APDUs.
        session: A SecureChannel instance used for wrapping/unwrapping.
        client_challenge (bytes, optional): Optional challenge bytes.
            If not provided, a random 32-byte value will be generated.

    Raises:
        APDUError: If the response status word is not 0x9000.
        ValueError: If the decrypted response is not exactly 32 bytes.
    '''
    client_challenge = client_challenge or os.urandom(32)

    response: bytes = card.send_secure_apdu(
        ins=constants.INS_MUTUALLY_AUTHENTICATE,
        data=client_challenge
    )

    if len(response) != 32:
        raise ValueError(
            'Response to MUTUALLY AUTHENTICATE is not 32 bytes')
