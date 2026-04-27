from ..card_interface import CardInterface
from ..constants import INS_SET_PINLESS_PATH
from ..parsing.keypath import KeyPath
from ..preconditions import require_pin_verified


@require_pin_verified
def set_pinless_path(card: CardInterface, path: str) -> None:
    """
    Set a PIN-less path on the card. Allows signing without PIN/auth if the
    current derived key matches this path.

    Args:
        card (CardInterface): The card interface.
        path (str): BIP-32-style path (e.g., "m/44'/60'/0'/0/0"). An empty
                    string disables the pinless path.

    Raises:
        APDUError: if the card rejects the input (invalid path)
    """
    keypath = KeyPath(path).data if path else b""
    card.send_secure_apdu(
        ins=INS_SET_PINLESS_PATH,
        data=keypath
    )
