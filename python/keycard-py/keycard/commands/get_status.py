from .. import constants
from ..card_interface import CardInterface
from ..parsing import tlv
from ..preconditions import require_secure_channel


@require_secure_channel
def get_status(
    card: CardInterface,
    key_path: bool = False
) -> dict[str, int | bool] | list[int]:
    '''
    Query the application status or key path from the Keycard.

    Requires an open Secure Channel.

    Args:
        transport: Transport instance used to send APDU bytes.
        session: An established SecureChannel instance.
        key_path (bool): If True, returns the current key path.
            If False (default), returns application status.

    Returns:
        If key_path is False:
            dict with keys:
                - pin_retry_count (int)
                - puk_retry_count (int)
                - initialized (bool)

        If key_path is True:
            List of 32-bit integers representing the current key path.

    Raises:
        APDUError: If the response status word is not 0x9000.
        ValueError: If the application status template (tag 0xA3) is missing.
    '''
    response: bytes = card.send_secure_apdu(
        ins=constants.INS_GET_STATUS,
        p1=0x01 if key_path else 0x00,
    )

    if key_path:
        return [
            int.from_bytes(response[i:i+4], 'big')
            for i in range(0, len(response), 4)
        ]

    outer = tlv.parse_tlv(response)

    if 0xA3 not in outer:
        raise ValueError('Missing tag 0xA3 (Application Status Template)')

    inner = tlv.parse_tlv(outer[0xA3][0])

    pin_retry = inner[0x02][0] or b'\xff'
    puk_retry = inner[0x02][1] or b'\xff'
    initialized = inner[0x01][0] != b'\x00'

    return {
        'pin_retry_count': pin_retry[0] if pin_retry else 0xff,
        'puk_retry_count': puk_retry[0] if puk_retry else 0xff,
        'initialized': initialized
    }
