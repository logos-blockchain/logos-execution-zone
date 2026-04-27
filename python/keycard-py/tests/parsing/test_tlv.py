import pytest

from keycard.exceptions import InvalidResponseError
from keycard.parsing import tlv


def test_parse_ber_length_short_form():
    data = bytes([0x05])
    length, consumed = tlv._parse_ber_length(data, 0)
    assert length == 5
    assert consumed == 1


def test_parse_ber_length_long_form_1byte():
    data = bytes([0x81, 0x10])
    length, consumed = tlv._parse_ber_length(data, 0)
    assert length == 0x10
    assert consumed == 2


def test_parse_ber_length_long_form_2bytes():
    data = bytes([0x82, 0x01, 0xF4])
    length, consumed = tlv._parse_ber_length(data, 0)
    assert length == 500
    assert consumed == 3


def test_parse_ber_length_unsupported_length():
    data = bytes([0x85, 0, 0, 0, 0, 0])
    with pytest.raises(InvalidResponseError):
        tlv._parse_ber_length(data, 0)


def test_parse_ber_length_exceeds_buffer():
    data = bytes([0x82, 0x01])
    with pytest.raises(InvalidResponseError):
        tlv._parse_ber_length(data, 0)


def test_parse_tlv_single():
    data = bytes([0x01, 0x03, ord('a'), ord('b'), ord('c')])
    result = tlv.parse_tlv(data)
    assert 0x01 in result
    assert result[0x01][0] == b'abc'


def test_parse_tlv_multiple_tags():
    data = bytes([
        0x01, 0x02, ord('h'), ord('i'),
        0x02, 0x01, ord('x')])
    result = tlv.parse_tlv(data)
    assert result[0x01][0] == b'hi'
    assert result[0x02][0] == b'x'


def test_parse_tlv_repeated_tag():
    data = bytes([
        0x01, 0x01, ord('a'),
        0x01, 0x02, ord('b'), ord('c')
    ])
    result = tlv.parse_tlv(data)
    assert result[0x01][0] == b'a'
    assert result[0x01][1] == b'bc'


def test_parse_tlv_long_length():
    data = bytes([0x10, 0x82, 0x01, 0x01]) + b'a' * 257
    result = tlv.parse_tlv(data)
    assert result[0x10][0] == b'a' * 257


def test_parse_tlv_incomplete_value():
    data = bytes([0x01, 0x05, ord('a'), ord('b'), ord('c')])
    with pytest.raises(InvalidResponseError):
        tlv.parse_tlv(data)


def test_encode_tlv_short():
    tag = 0x01
    value = b'\xAB\xCD'
    encoded = tlv.encode_tlv(tag, value)
    assert encoded == b'\x01\x02\xAB\xCD'


def test_encode_tlv_1byte_long_form():
    tag = 0x02
    value = b'\x00' * 130  # >127 triggers long form
    encoded = tlv.encode_tlv(tag, value)
    assert encoded[:2] == b'\x02\x81'
    assert encoded[2] == 130
    assert encoded[3:] == value


def test_encode_tlv_2byte_long_form():
    tag = 0x03
    value = b'\xFF' * 300  # >255 triggers 2-byte length
    encoded = tlv.encode_tlv(tag, value)
    assert encoded[:3] == b'\x03\x82\x01'
    assert encoded[3] == 0x2C  # 300 = 0x012C
    assert encoded[4:] == value


def test_encode_tlv_empty_value():
    tag = 0x04
    value = b""
    encoded = tlv.encode_tlv(tag, value)
    assert encoded == b'\x04\x00'


def test_encode_tlv_max_short_length():
    tag = 0x10
    value = b"A" * 127
    encoded = tlv.encode_tlv(tag, value)
    assert encoded[1] == 127
    assert len(encoded) == 2 + 127


def test_encode_tlv_max_1byte_long_form():
    tag = 0x20
    value = b"A" * 255
    encoded = tlv.encode_tlv(tag, value)
    assert encoded[1:3] == b'\x81\xFF'
