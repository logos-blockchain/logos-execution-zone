import pytest
from keycard.commands.unblock_pin import unblock_pin
from keycard import constants


def test_unblock_pin_with_valid_str(card):
    puk = '123456789012'
    pin = '123456'
    unblock_pin(card, puk + pin)
    card.send_secure_apdu.assert_called_once_with(
        ins=constants.INS_UNBLOCK_PIN,
        data=(puk + pin).encode('utf-8')
    )


def test_unblock_pin_with_valid_bytes(card):
    data = b'123456789012123456'
    unblock_pin(card, data)
    card.send_secure_apdu.assert_called_once_with(
        ins=constants.INS_UNBLOCK_PIN,
        data=data
    )


@pytest.mark.parametrize('bad_input', [
    '12345678901212345',      # Too short
    '1234567890121234567',    # Too long
    b'12345678901212345',     # Too short (bytes)
    b'1234567890121234567',   # Too long (bytes)
])
def test_unblock_pin_invalid_length(card, bad_input):
    with pytest.raises(ValueError, match='exactly 18 digits'):
        unblock_pin(card, bad_input)


@pytest.mark.parametrize('bad_input', [
    '12345678901A123456',     # Non-digit in PUK
    '12345678901212345A',     # Non-digit in PIN
    'ABCDEFGHIJKL123456',     # All non-digits in PUK
])
def test_unblock_pin_invalid_digits(card, bad_input):
    with pytest.raises(ValueError, match='must be numeric digits'):
        unblock_pin(card, bad_input)
