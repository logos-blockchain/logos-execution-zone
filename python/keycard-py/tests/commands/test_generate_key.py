import pytest
from keycard import constants
from keycard.commands.generate_key import generate_key
from keycard.exceptions import APDUError


def test_generate_key_success(card):
    mock_id = b'\x01' * 32
    card.send_secure_apdu.return_value = mock_id
    result = generate_key(card)
    assert result == mock_id
    card.send_secure_apdu.assert_called_once_with(
        ins=constants.INS_GENERATE_KEY)


def test_generate_key_apdu_error(card):
    card.send_secure_apdu.side_effect = APDUError(0x6A80)

    with pytest.raises(APDUError):
        generate_key(card)
