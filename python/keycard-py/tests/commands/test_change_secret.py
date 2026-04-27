import sys
import pytest

from unittest.mock import Mock, patch
from keycard import constants
from keycard.card_interface import CardInterface
from keycard.exceptions import APDUError
from keycard.commands.change_secret import change_secret


@pytest.fixture
def mock_card():
    card = Mock(spec=CardInterface)
    card.send_secure_apdu = Mock()
    return card


def test_change_secret_pairing_str_success(mock_card):
    change_secret_module = sys.modules['keycard.commands.change_secret']
    with patch.object(
        change_secret_module, 'generate_pairing_token'
    ) as mock_generate:
        mock_generate.return_value = bytes(32)
        change_secret(mock_card, 'pairingtoken', constants.PinType.PAIRING)
        mock_generate.assert_called_once_with('pairingtoken')
        mock_card.send_secure_apdu.assert_called_once_with(
            ins=constants.INS_CHANGE_SECRET,
            p1=constants.PinType.PAIRING.value,
            data=mock_generate.return_value
        )


def test_change_secret_user_pin_str_success(mock_card):
    pin = '123456'
    change_secret(mock_card, pin, constants.PinType.USER)
    mock_card.send_secure_apdu.assert_called_once_with(
        ins=constants.INS_CHANGE_SECRET,
        p1=constants.PinType.USER.value,
        data=pin.encode('utf-8')
    )


def test_change_secret_user_pin_invalid_length(mock_card):
    with pytest.raises(ValueError, match="User PIN must be exactly 6 digits."):
        change_secret(mock_card, b'12345', constants.PinType.USER)
    with pytest.raises(ValueError, match="User PIN must be exactly 6 digits."):
        change_secret(mock_card, '12345', constants.PinType.USER)


def test_change_secret_puk_success(mock_card):
    puk = b'123456789012'
    change_secret(mock_card, puk, constants.PinType.PUK)
    mock_card.send_secure_apdu.assert_called_once_with(
        ins=constants.INS_CHANGE_SECRET,
        p1=constants.PinType.PUK.value,
        data=puk
    )


def test_change_secret_puk_str_success(mock_card):
    puk = '123456789012'
    change_secret(mock_card, puk, constants.PinType.PUK)
    mock_card.send_secure_apdu.assert_called_once_with(
        ins=constants.INS_CHANGE_SECRET,
        p1=constants.PinType.PUK.value,
        data=puk.encode('utf-8')
    )


def test_change_secret_puk_invalid_length(mock_card):
    with pytest.raises(ValueError, match="PUK must be exactly 12 digits."):
        change_secret(mock_card, b'1234567890', constants.PinType.PUK)
    with pytest.raises(ValueError, match="PUK must be exactly 12 digits."):
        change_secret(mock_card, '1234567890', constants.PinType.PUK)


def test_change_secret_pairing_bytes_success(mock_card):
    secret = b'a' * 32
    change_secret(mock_card, secret, constants.PinType.PAIRING)
    mock_card.send_secure_apdu.assert_called_once_with(
        ins=constants.INS_CHANGE_SECRET,
        p1=constants.PinType.PAIRING.value,
        data=secret
    )


def test_change_secret_pairing_bytes_invalid_length(mock_card):
    with pytest.raises(ValueError, match="Pairing secret must be 32 bytes."):
        change_secret(mock_card, b'a' * 31, constants.PinType.PAIRING)


def test_change_secret_raises_apdu_error(mock_card):
    mock_card.send_secure_apdu.side_effect = APDUError(0x6A80)
    with pytest.raises(APDUError):
        change_secret(mock_card, b'123456', constants.PinType.USER)
