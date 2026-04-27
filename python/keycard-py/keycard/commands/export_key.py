from typing import Optional, Union

from .. import constants
from ..card_interface import CardInterface
from ..constants import DerivationOption, KeyExportOption, DerivationSource
from ..parsing import tlv
from ..parsing.exported_key import ExportedKey
from ..parsing.keypath import KeyPath
from ..preconditions import require_pin_verified


@require_pin_verified
def export_key(
    card: CardInterface,
    derivation_option: constants.DerivationOption,
    public_only: bool,
    keypath: Optional[Union[str, bytes, bytearray]] = None,
    make_current: bool = False,
    source: DerivationSource = DerivationSource.MASTER
) -> ExportedKey:
    """
    Export a key (public or private) from the card using an optional keypath.

    If derivation_option == CURRENT, keypath can be omitted or empty.

    Args:
        card: The card object
        derivation_option: e.g. DERIVE, CURRENT, DERIVE_AND_MAKE_CURRENT
        public_only: If True, export only public key
        keypath: BIP32-style string or packed bytes, or None if CURRENT
        make_current: Whether to update the card's current path
        source: MASTER (0x00), PARENT (0x40), CURRENT (0x80)

    Returns:
        dict with optional 'public_key', 'private_key', 'chain_code'
    """
    if keypath is None:
        if derivation_option != constants.DerivationOption.CURRENT:
            raise ValueError(
                "Keypath required unless using CURRENT derivation")
        data = b""
    elif isinstance(keypath, str):
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

    if public_only:
        p2 = KeyExportOption.PUBLIC_ONLY
    else:
        p2 = KeyExportOption.PRIVATE_AND_PUBLIC

    response = card.send_secure_apdu(
        ins=constants.INS_EXPORT_KEY,
        p1=p1,
        p2=p2,
        data=data
    )

    outer = tlv.parse_tlv(response)
    tpl = outer.get(0xA1)
    if not tpl:
        raise ValueError("Missing keypair template (tag 0xA1)")

    inner = tlv.parse_tlv(tpl[0])

    return ExportedKey(
        public_key=inner.get(0x80, [None])[0],
        private_key=inner.get(0x81, [None])[0],
        chain_code=inner.get(0x82, [None])[0],
    )
