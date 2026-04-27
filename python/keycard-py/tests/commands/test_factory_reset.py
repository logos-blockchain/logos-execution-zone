import pytest
from unittest.mock import Mock
from keycard import constants
from keycard.commands.factory_reset import factory_reset
from keycard.exceptions import APDUError


def test_factory_reset_success(card):
    mock_response = Mock()
    mock_response.status_word = 0x9000
    card.send_apdu.return_value = mock_response

    factory_reset(card)
    card.send_apdu.assert_called_once_with(
        ins=constants.INS_FACTORY_RESET,
        p1=0xAA,
        p2=0x55
    )


def test_factory_reset_failure(card):
    card.send_apdu.side_effect = APDUError(0x6A80)

    with pytest.raises(APDUError):
        factory_reset(card)
