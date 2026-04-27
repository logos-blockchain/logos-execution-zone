from keycard.commands.remove_key import remove_key


def test_remove_key_calls_send_secure_apdu_with_correct_ins(card):
    remove_key(card)
    card.send_secure_apdu.assert_called_once_with(ins=0xD3)


def test_remove_key_returns_none(card):
    result = remove_key(card)
    assert result is None
