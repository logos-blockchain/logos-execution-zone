from keycard.commands.get_status import get_status


def test_get_application_status(card):
    card.send_secure_apdu.return_value = bytes.fromhex(
        'A309020103020102010101')

    result = get_status(card)

    assert result['pin_retry_count'] == 3
    assert result['puk_retry_count'] == 2
    assert result['initialized'] is True


def test_get_key_path_status(card):
    key_path = [0x8000002C, 0x8000003C]

    card.send_secure_apdu.return_value = b''.join(
        i.to_bytes(4, 'big') for i in key_path
    )

    result = get_status(card, key_path=True)

    assert result == key_path
