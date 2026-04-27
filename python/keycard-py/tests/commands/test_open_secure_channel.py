import sys
import pytest
from unittest.mock import MagicMock, patch
from ecdsa import SECP256k1

from keycard.card_interface import CardInterface
from keycard.commands.open_secure_channel import open_secure_channel
from keycard.exceptions import APDUError


@pytest.fixture
def mock_ecdsa():
    open_secure_channel_module = sys.modules[
        'keycard.commands.open_secure_channel'
    ]
    with (
        patch.object(
            open_secure_channel_module,
            'SecureChannel'
        ) as mock_secure_channel,
        patch.object(
            open_secure_channel_module,
            'VerifyingKey'
        ) as mock_verifying_key,
        patch.object(
            open_secure_channel_module,
            'ECDH'
        ) as mock_ecdh,
        patch.object(
            open_secure_channel_module,
            'SigningKey'
        ) as mock_signing_key,
    ):
        yield {
            'secure_channel': mock_secure_channel,
            'verifying_key': mock_verifying_key,
            'ecdh': mock_ecdh,
            'signing_key': mock_signing_key,
        }


def test_open_secure_channel_success(mock_ecdsa):
    mock_verifying_key = mock_ecdsa['verifying_key']
    mock_ecdh = mock_ecdsa['ecdh']
    mock_signing_key = mock_ecdsa['signing_key']
    mock_secure_channel = mock_ecdsa['secure_channel']

    pairing_index = 1
    pairing_key = b'pairing_key'
    card = MagicMock(spec=CardInterface)
    card.card_public_key = b'\x04' + b'\x01' * 64

    salt = b'A' * 32
    seed_iv = b'B' * 16
    response_data = salt + seed_iv
    card.send_apdu.return_value = response_data

    # Mock SigningKey.generate
    mock_signing_key_instance = MagicMock()
    mock_signing_key_instance.verifying_key.to_string.return_value = \
        b'\x04' + b'\x02' * 64
    mock_signing_key.generate.return_value = mock_signing_key_instance

    mock_verifying_key.from_string.return_value = MagicMock()
    mock_ecdh_instance = MagicMock()
    mock_ecdh.return_value = mock_ecdh_instance
    mock_ecdh_instance.generate_sharedsecret_bytes.return_value = (
        b'shared_secret'
    )
    mock_secure_channel.open.return_value = 'secure_session'

    result = open_secure_channel(
        card,
        pairing_index,
        pairing_key
    )

    card.send_apdu.assert_called_once()
    mock_verifying_key.from_string.assert_called_once_with(
        card.card_public_key, curve=SECP256k1
    )
    mock_ecdh.assert_called_once()
    mock_ecdh_instance.generate_sharedsecret_bytes.assert_called_once()
    mock_secure_channel.open.assert_called_once_with(
        b'shared_secret', pairing_key, salt, seed_iv
    )
    assert result == 'secure_session'


def test_open_secure_channel_raises_apdu_error(card, mock_ecdsa):
    mock_signing_key = mock_ecdsa['signing_key']

    # Mock SigningKey.generate
    mock_signing_key_instance = MagicMock()
    mock_signing_key_instance.verifying_key.to_string.return_value = \
        b'\x04' + b'\x02' * 64
    mock_signing_key.generate.return_value = mock_signing_key_instance

    pairing_index = 1
    pairing_key = b'pairing_key'
    card.card_public_key = b'\x04' + b'\x01' * 64
    card.send_apdu.side_effect = APDUError(0x6A80)

    with pytest.raises(APDUError):
        open_secure_channel(
            card,
            pairing_index,
            pairing_key
        )
