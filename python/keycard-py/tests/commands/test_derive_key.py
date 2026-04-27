from keycard.commands import derive_key
from keycard.constants import INS_DERIVE_KEY, DerivationSource
from keycard.parsing.keypath import KeyPath


def test_derive_key_valid_master(card):
    key_path = KeyPath("m/44'/60'/0'/0/0")
    derive_key(card, key_path.to_string())

    card.send_secure_apdu.assert_called_once_with(
        ins=INS_DERIVE_KEY,
        p1=DerivationSource.MASTER,
        data=key_path.data
    )
