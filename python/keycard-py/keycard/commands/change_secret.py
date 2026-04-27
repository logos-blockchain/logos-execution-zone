from .. import constants
from ..card_interface import CardInterface
from ..preconditions import require_pin_verified
from ..crypto.generate_pairing_token import generate_pairing_token


@require_pin_verified
def change_secret(
    card: CardInterface,
    new_value: bytes | str,
    pin_type: constants.PinType
) -> None:
    """
    Changes the specified secret (PIN, PUK, PAIRING) or secret on the card.

    Preconditions:
        - Secure Channel must be opened
        - User PIN must be verified

    Args:
        card: The card session object.
        new_value (bytes | str): The new PIN/PUK/secret.
        pin_type (PinType): Type of PIN (USER, PUK, or PAIRING)

    Raises:
        ValueError: If input format is invalid.
        APDUError: If the card returns an error status word.
    """
    if pin_type == constants.PinType.PAIRING:
        if isinstance(new_value, str):
            new_value = generate_pairing_token(new_value)
        elif len(new_value) != 32:
            raise ValueError("Pairing secret must be 32 bytes.")
    elif isinstance(new_value, str):
        new_value = new_value.encode("utf-8")

    if pin_type == constants.PinType.USER and len(new_value) != 6:
        raise ValueError("User PIN must be exactly 6 digits.")
    elif pin_type == constants.PinType.PUK and len(new_value) != 12:
        raise ValueError("PUK must be exactly 12 digits.")

    card.send_secure_apdu(
        ins=constants.INS_CHANGE_SECRET,
        p1=pin_type.value,
        data=new_value
    )
