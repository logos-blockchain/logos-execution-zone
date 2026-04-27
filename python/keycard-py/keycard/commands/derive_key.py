from ..card_interface import CardInterface
from ..constants import INS_DERIVE_KEY
from ..parsing.keypath import KeyPath
from ..preconditions import require_pin_verified


@require_pin_verified
def derive_key(card: CardInterface, path: str = '') -> None:
    """
    Set the derivation path for subsequent SIGN and EXPORT KEY commands.

    Args:
        card (CardInterface): The card interface.
        path (str): BIP-32-style path (e.g., "m/44'/60'/0'/0/0") or
                    "../0/1" (parent) or "./0" (current).

    Raises:
        APDUError: if the derivation fails or the format is invalid.
    """
    keypath = KeyPath(path)
    card.send_secure_apdu(
        ins=INS_DERIVE_KEY,
        p1=keypath.source,
        data=keypath.data
    )
