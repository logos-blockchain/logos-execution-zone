from ..card_interface import CardInterface
from ..preconditions import require_pin_verified


@require_pin_verified
def remove_key(card: CardInterface) -> None:
    '''
    Removes the key from the card, returning it to an uninitialized state.

    '''
    card.send_secure_apdu(ins=0xD3)
