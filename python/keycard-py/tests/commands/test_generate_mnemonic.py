import pytest
from keycard.constants import INS_GENERATE_MNEMONIC
from keycard.commands.generate_mnemonic import generate_mnemonic


def test_generate_mnemonic_valid(card):
    card.send_secure_apdu.return_value = bytes([
        0x00, 0x00,
        0x07, 0xFF,
        0x05, 0x39,
        0x00, 0x2A
    ])

    result = generate_mnemonic(card, checksum_size=6)

    card.send_secure_apdu.assert_called_once_with(
        ins=INS_GENERATE_MNEMONIC,
        p1=6
    )

    assert result == [0, 2047, 1337, 42]


def test_generate_mnemonic_invalid_checksum(card):
    with pytest.raises(
        ValueError,
        match="Checksum size must be between 4 and 8"
    ):
        generate_mnemonic(card, checksum_size=2)


def test_generate_mnemonic_odd_length_response(card):
    # Simulate invalid odd-length byte response
    card.send_secure_apdu.return_value = b'\x00\x01\x02'

    with pytest.raises(
        ValueError,
        match="Response must contain an even number of bytes"
    ):
        generate_mnemonic(card, checksum_size=6)
