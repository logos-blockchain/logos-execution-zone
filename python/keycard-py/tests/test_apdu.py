import pytest
from keycard.apdu import encode_lv, APDUResponse


def test_encode_lv_valid():
    value = bytes(10)
    result = encode_lv(value)
    assert result == b"\x0A" + value


def test_encode_lv_too_long():
    value = bytes(256)
    with pytest.raises(ValueError):
        encode_lv(value)


def test_encode_lv_empty():
    value = bytes()
    result = encode_lv(value)
    assert result == b"\x00"


def test_encode_lv_single_byte():
    value = bytes([0xFF])
    result = encode_lv(value)
    assert result == b"\x01\xFF"


def test_encode_lv_max_length():
    value = bytes(255)
    result = encode_lv(value)
    assert result == b"\xFF" + value


def test_apdu_response_success():
    r = APDUResponse([0x01, 0x02], 0x9000)
    assert r.data == [0x01, 0x02]
    assert r.status_word == 0x9000


def test_apdu_response_error_status():
    r = APDUResponse([], 0x6A82)
    assert r.status_word == 0x6A82
    assert isinstance(r.status_word, int)


def test_apdu_response_all_status_range():
    for sw in [0x9000, 0x6A80, 0x6A84, 0x6982]:
        r = APDUResponse([0x00], sw)
        assert r.status_word == sw
        assert r.data == [0x00]
