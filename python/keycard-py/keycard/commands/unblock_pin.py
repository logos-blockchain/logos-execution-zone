from .. import constants
from ..card_interface import CardInterface
from ..preconditions import require_secure_channel


@require_secure_channel
def unblock_pin(card: CardInterface, puk_and_pin: bytes | str) -> None:
    """
    Unblocks the user PIN using the provided PUK and sets a new PIN.

    Args:
        card: The card session object.
        puk_and_pin (bytes | str): Concatenation of PUK (12 digits) + new PIN
            (6 digits)

    Raises:
        ValueError: If the format is invalid.
        APDUError: If the card returns an error.
    """
    if isinstance(puk_and_pin, str):
        if not puk_and_pin.isdigit():
            raise ValueError("PUK and PIN must be numeric digits.")
        puk_and_pin = puk_and_pin.encode("utf-8")

    if len(puk_and_pin) != 18:
        raise ValueError(
            "Data must be exactly 18 digits (12-digit PUK + 6-digit PIN).")

    card.send_secure_apdu(
        ins=constants.INS_UNBLOCK_PIN,
        data=puk_and_pin
    )
