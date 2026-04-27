import pytest
from keycard.commands.verify_pin import verify_pin
from keycard.exceptions import APDUError
from keycard import constants


def test_verify_pin_success(card):
    assert verify_pin(card, '1234') is True
    card.send_secure_apdu.assert_called_once_with(
        ins=constants.INS_VERIFY_PIN,
        data=b'1234'
    )


def test_verify_pin_incorrect_but_allowed(card):
    card.send_secure_apdu.side_effect = APDUError(0x63C2)
    assert verify_pin(card, '0000') is False


def test_verify_pin_blocked(card):
    card.send_secure_apdu.side_effect = APDUError(0x63C0)
    with pytest.raises(RuntimeError, match='PIN is blocked'):
        verify_pin(card, '0000')


def test_verify_pin_other_apdu_error(card):
    card.send_secure_apdu.side_effect = APDUError(0x6A80)
    with pytest.raises(APDUError):
        verify_pin(card, '0000')
