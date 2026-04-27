from .. import constants
from ..card_interface import CardInterface
from ..preconditions import require_selected


@require_selected
def get_data(
    card: CardInterface,
    slot: constants.StorageSlot = constants.StorageSlot.PUBLIC
) -> bytes:
    """
    Gets the data on the card previously stored with the store data command
    in the specified slot.

    If the secure channel is open, it uses the secure APDU command.
    Otherwise, it uses the proprietary APDU command.

    Args:
        card: The card session object.
        slot (StorageSlot): Where to store the data (PUBLIC, NDEF, CASH)

    Raises:
        ValueError: If slot is invalid or data is too long.
    """
    if card.is_secure_channel_open:
        return card.send_secure_apdu(
            ins=constants.INS_GET_DATA,
            p1=slot.value
        )

    return card.send_apdu(
        cla=constants.CLA_PROPRIETARY,
        ins=constants.INS_GET_DATA,
        p1=slot.value
    )
