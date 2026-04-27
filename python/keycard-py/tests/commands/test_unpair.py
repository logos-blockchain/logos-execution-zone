import pytest
from keycard.commands.unpair import unpair
from keycard.apdu import APDUResponse
from keycard.exceptions import APDUError
from keycard import constants


def test_unpair_success(card):
    card.send_secure_apdu.return_value = APDUResponse(b'', 0x9000)

    unpair(card, 1)

    card.send_secure_apdu.assert_called_once_with(
        ins=constants.INS_UNPAIR,
        p1=0x01,
    )


def test_unpair_apdu_error(card):
    card.send_secure_apdu.side_effect = APDUError(0x6A84)

    with pytest.raises(APDUError) as excinfo:
        unpair(card, 1)

    assert excinfo.value.sw == 0x6A84
