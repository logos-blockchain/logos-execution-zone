from keycard.commands.set_pinless_path import set_pinless_path
from keycard.constants import INS_SET_PINLESS_PATH
from keycard.parsing.keypath import KeyPath


def test_set_pinless_path(card):
    path = "m/44'/60'/0'/0/0"
    expected_data = KeyPath(path).data

    set_pinless_path(card, path)

    card.send_secure_apdu.assert_called_once_with(
        ins=INS_SET_PINLESS_PATH,
        data=expected_data
    )


def test_set_pinless_path_empty(card):
    set_pinless_path(card, "")

    card.send_secure_apdu.assert_called_once_with(
        ins=INS_SET_PINLESS_PATH,
        data=b""
    )
