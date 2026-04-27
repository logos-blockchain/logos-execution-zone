from .. import constants
from ..card_interface import CardInterface
from ..preconditions import require_pin_verified


@require_pin_verified
def unpair(card: CardInterface, index: int) -> None:
    '''
    Sends the UNPAIR command to remove a pairing index from the card.

    Preconditions:
        - Secure Channel must be opened
        - PIN must be verified

    This function securely communicates with the card using the established
    session to instruct it to forget a specific pairing index.

    Args:
        transport: The transport interface used to send APDUs.
        secure_session: The active SecureChannel object used to wrap APDUs.
        index (int): The pairing index (0–15) to unpair from the card.

    Raises:
        ValueError: If transport or secure_session is not provided, or if
            the session is not authenticated.
        APDUError: If the response status word indicates an error.
    '''
    card.send_secure_apdu(
        ins=constants.INS_UNPAIR,
        p1=index,
    )
