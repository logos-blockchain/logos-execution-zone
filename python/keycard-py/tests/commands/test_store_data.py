import pytest

from keycard.commands import store_data
from keycard import constants


def test_store_data_calls_send_secure_apdu_with_correct_args(card):
    store_data(card, b"hello", constants.StorageSlot.PUBLIC)

    card.send_secure_apdu.assert_called_once_with(
        ins=constants.INS_STORE_DATA,
        p1=constants.StorageSlot.PUBLIC.value,
        data=b'hello'
    )


def test_store_data_uses_default_slot(card):
    store_data(card, b'world')

    card.send_secure_apdu.assert_called_once_with(
        ins=constants.INS_STORE_DATA,
        p1=constants.StorageSlot.PUBLIC,
        data=b'world'
    )


def test_store_data_raises_value_error_on_too_long_data(card):
    with pytest.raises(ValueError, match="Data too long"):
        store_data(card, b'a' * 128, constants.StorageSlot.PUBLIC)
