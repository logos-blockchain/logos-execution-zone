from dataclasses import dataclass
from typing import Optional, Union

from .. import constants
from ..card_interface import CardInterface
from ..constants import DerivationOption, DerivationSource
from ..parsing import tlv
from ..preconditions import require_pin_verified


@dataclass
class ExportedLeeKey:
    """Represents a LEE key template containing LEE_NSK and LEE_VSK."""
    lee_nsk: Optional[bytes] = None
    lee_vsk: Optional[bytes] = None


@require_pin_verified
def export_lee_key(
    card: CardInterface,
    derivation_option: constants.DerivationOption,
    keypath: Optional[Union[str, bytes, bytearray]] = None,
    make_current: bool = False,
    source: DerivationSource = DerivationSource.MASTER
) -> ExportedLeeKey:
    """
    Export a LEE key template from the card.

    The output is a key template (tag 0xA1) containing LEE_NSK (tag 0x83)
    and LEE_VSK (tag 0x84).

    If derivation_option == CURRENT, keypath can be omitted or empty.

    Args:
        card: The card object
        derivation_option: e.g. DERIVE, CURRENT, DERIVE_AND_MAKE_CURRENT
        keypath: BIP32-style string or packed bytes, or None if CURRENT
        make_current: Whether to update the card's current path
        source: MASTER (0x00), PARENT (0x40), CURRENT (0x80)

    Returns:
        ExportedLeeKey with lee_nsk and lee_vsk fields
    """
    if keypath is None:
        if derivation_option != constants.DerivationOption.CURRENT:
            raise ValueError(
                "Keypath required unless using CURRENT derivation")
        data = b""
    elif isinstance(keypath, str):
        from ..parsing.keypath import KeyPath
        data = KeyPath(keypath).data
    elif isinstance(keypath, (bytes, bytearray)):
        if len(keypath) % 4 != 0:
            raise ValueError("Byte keypath must be a multiple of 4")
        data = bytes(keypath)
    else:
        raise TypeError("Keypath must be a string or bytes")

    if make_current:
        p1 = DerivationOption.DERIVE_AND_MAKE_CURRENT
    else:
        p1 = derivation_option
    p1 |= source

    response = card.send_secure_apdu(
        ins=constants.INS_EXPORT_LEE_KEY,
        p1=p1,
        p2=0x00,
        data=data
    )

    outer = tlv.parse_tlv(response)
    tpl = outer.get(0xA1)
    if not tpl:
        raise ValueError("Missing keypair template (tag 0xA1)")

    inner = tlv.parse_tlv(tpl[0])

    return ExportedLeeKey(
        lee_nsk=inner.get(0x83, [None])[0],
        lee_vsk=inner.get(0x84, [None])[0],
    )
