from .. import constants
from ..card_interface import CardInterface
from ..preconditions import require_pin_verified


@require_pin_verified
def store_data(
    card: CardInterface,
    data: bytes,
    slot: constants.StorageSlot = constants.StorageSlot.PUBLIC
) -> None:
    """
    Stores data on the card in the specified slot.

    Args:
        card: The card session object.
        data (bytes): The data to store (max 127 bytes).
        slot (StorageSlot): Where to store the data (PUBLIC, NDEF, CASH)

    Raises:
        ValueError: If slot is invalid or data is too long.
    """
    if len(data) > 127:
        raise ValueError("Data too long. Maximum allowed is 127 bytes.")

    card.send_secure_apdu(
        ins=constants.INS_STORE_DATA,
        p1=slot.value,
        data=data
    )
