from ..card_interface import CardInterface
from ..constants import INS_GENERATE_MNEMONIC
from ..preconditions import require_secure_channel


@require_secure_channel
def generate_mnemonic(
    card: CardInterface,
    checksum_size: int = 6
) -> list[int]:
    """
    Generate a BIP39 mnemonic using the card's RNG.

    Args:
        card (CardInterface): The card interface.
        checksum_size (int): Number of checksum bits
            (between 4 and 8 inclusive).

    Returns:
        List[int]: List of integers (0-2047) corresponding to wordlist
            indexes.

    Raises:
        ValueError: If checksum size is outside the allowed range.
        APDUError: If the card rejects the request.
    """
    if not (4 <= checksum_size <= 8):
        raise ValueError("Checksum size must be between 4 and 8")

    response = card.send_secure_apdu(
        ins=INS_GENERATE_MNEMONIC,
        p1=checksum_size
    )

    if len(response) % 2 != 0:
        raise ValueError("Response must contain an even number of bytes")

    return [
        (response[i] << 8) | response[i + 1]
        for i in range(0, len(response), 2)
    ]
