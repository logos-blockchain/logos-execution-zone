from .. import constants
from ..card_interface import CardInterface
from ..exceptions import APDUError
from ..preconditions import require_secure_channel


@require_secure_channel
def verify_pin(card: CardInterface, pin: str | bytes) -> bool:
    '''
    Verifies the user PIN with the card using a secure session.

    Preconditions:
        - Secure Channel must be opened
        - PIN must be verified

    Sends the VERIFY PIN APDU command through the secure session. Returns
    True if the PIN is correct, False if incorrect with remaining attempts,
    and raises an error if blocked or another APDU error occurs.

    Args:
        transport: The transport instance used to send the command.
        session: An established SecureChannel object.
        pin (str): The PIN string to be verified.

    Returns:
        bool: True if the PIN is correct, False if incorrect but still allowed.

    Raises:
        ValueError: If no secure session is provided.
        RuntimeError: If the PIN is blocked (no attempts remaining).
        APDUError: For other status word errors returned by the card.
    '''
    if not isinstance(pin, bytes):
        pin = pin.encode('ascii')

    try:
        card.send_secure_apdu(
            ins=constants.INS_VERIFY_PIN,
            data=pin
        )
    except APDUError as e:
        if (e.sw & 0xFFF0) == 0x63C0:
            attempts = e.sw & 0x000F
            if attempts == 0:
                raise RuntimeError('PIN is blocked')
            return False
        raise e

    return True
