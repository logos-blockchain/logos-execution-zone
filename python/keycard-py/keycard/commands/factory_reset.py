from .. import constants
from ..card_interface import CardInterface
from ..preconditions import require_selected


@require_selected
def factory_reset(card: CardInterface) -> None:
    '''
    Sends the FACTORY_RESET command to the card.
    '''
    card.send_apdu(
        ins=constants.INS_FACTORY_RESET,
        p1=0xAA,
        p2=0x55
    )
