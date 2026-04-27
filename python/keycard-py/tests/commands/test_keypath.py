import pytest
from keycard.parsing.keypath import KeyPath
from keycard.constants import DerivationSource


def test_keypath_from_string_master():
    path = KeyPath("m/44'/60'/0'/0/0")
    assert path.source == DerivationSource.MASTER
    assert path.data == bytes.fromhex(
        '8000002c8000003c800000000000000000000000')
    assert path.to_string() == "m/44'/60'/0'/0/0"


def test_keypath_from_string_parent():
    path = KeyPath('../1/2/3')
    assert path.source == DerivationSource.PARENT
    assert path.to_string() == '../1/2/3'


def test_keypath_from_string_current_default():
    path = KeyPath('1/2/3')
    assert path.source == DerivationSource.CURRENT
    assert path.to_string() == './1/2/3'


def test_keypath_from_bytes():
    data = bytes.fromhex('8000002c00000001')
    path = KeyPath(data, source=DerivationSource.PARENT)
    assert path.source == DerivationSource.PARENT
    assert path.data == data
    assert path.to_string() == "../44'/1"


def test_keypath_empty_string_raises():
    with pytest.raises(ValueError, match="Empty path"):
        KeyPath('')


def test_keypath_invalid_component():
    with pytest.raises(ValueError, match="Invalid component: abc"):
        KeyPath('m/abc')


def test_keypath_too_many_components():
    long_path = 'm/' + '/'.join('0' for _ in range(11))
    with pytest.raises(ValueError, match="Too many components"):
        KeyPath(long_path)


def test_keypath_invalid_byte_length():
    with pytest.raises(ValueError, match="Byte path must be a multiple of 4"):
        KeyPath(b'\x00\x01')


def test_keypath_invalid_type():
    with pytest.raises(TypeError, match="Path must be a string or bytes"):
        KeyPath(123)
