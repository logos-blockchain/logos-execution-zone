import pytest

from keycard import constants
from keycard.commands.mutually_authenticate import mutually_authenticate
from keycard.exceptions import APDUError


def test_mutually_authenticate_success(card):
    client_challenge = bytes(32)
    card.send_secure_apdu.return_value = bytes(32)

    mutually_authenticate(card, client_challenge)

    card.send_secure_apdu.assert_called_once_with(
        ins=constants.INS_MUTUALLY_AUTHENTICATE,
        data=client_challenge
    )


def test_mutually_authenticate_invalid_status_word(card):
    card.send_secure_apdu.side_effect = APDUError(0x6F00)

    with pytest.raises(APDUError, match='APDU failed with SW=6F00'):
        mutually_authenticate(card, bytes(32))


def test_mutually_authenticate_invalid_response_length(card):
    client_challenge = b'\xAA' * 32
    response = b'\xBB' * 16  # Invalid length

    card.send_secure_apdu.return_value = response

    with pytest.raises(
        ValueError,
        match='Response to MUTUALLY AUTHENTICATE is not 32 bytes'
    ):
        mutually_authenticate(card, client_challenge)


def test_mutually_authenticate_auto_challenge(card, monkeypatch):
    fake_challenge = b'\xCC' * 32
    monkeypatch.setattr('os.urandom', lambda n: fake_challenge)

    card.send_secure_apdu.return_value = fake_challenge

    mutually_authenticate(card)

    card.send_secure_apdu.assert_called_once()
