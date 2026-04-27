import pytest
from keycard.commands.get_data import get_data
from keycard import constants


def test_get_data_secure_channel(card):
    card.is_secure_channel_open = True
    card.send_secure_apdu.return_value = b"secure_data"
    result = get_data(card, slot=constants.StorageSlot.PUBLIC)
    card.send_secure_apdu.assert_called_once_with(
        ins=constants.INS_GET_DATA,
        p1=constants.StorageSlot.PUBLIC,
    )
    assert result == card.send_secure_apdu.return_value


def test_get_data_proprietary_channel(card):
    card.is_secure_channel_open = False
    card.send_apdu.return_value = b"proprietary_data"
    result = get_data(card, slot=constants.StorageSlot.NDEF)
    card.send_apdu.assert_called_once_with(
        ins=constants.INS_GET_DATA,
        p1=constants.StorageSlot.NDEF.value,
        cla=constants.CLA_PROPRIETARY
    )
    assert result == card.send_apdu.return_value


def test_get_data_invalid_slot(card):
    with pytest.raises(AttributeError):
        get_data(card, slot="INVALID_SLOT")
