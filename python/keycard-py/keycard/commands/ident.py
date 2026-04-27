import os
from typing import Optional

from .. import constants
from ..card_interface import CardInterface
from ..parsing.identity import parse
from ..preconditions import require_selected


@require_selected
def ident(card: CardInterface, challenge: Optional[bytes]) -> bytes:
    '''
    Sends a challenge to the card to receive a signed identity response.

    Args:
        transport: An instance of the Transport class to communicate with
            the card.
        challenge (bytes): A challenge (nonce or data) to send to the card.
            If None, a random 32-byte challenge is generated.

    Returns:
        bytes: The public key extracted from the card's identity response.

    Raises:
        APDUError: If the response status word is not successful (0x9000).
    '''
    challenge = challenge or os.urandom(32)

    response: bytes = card.send_apdu(
        ins=constants.INS_IDENT,
        data=challenge
    )

    return parse(challenge, response)
