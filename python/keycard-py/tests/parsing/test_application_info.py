import pytest
from keycard.exceptions import InvalidResponseError
from keycard.parsing.application_info import ApplicationInfo


class DummyCapabilities:
    CREDENTIALS_MANAGEMENT = 1
    SECURE_CHANNEL = 2

    @staticmethod
    def parse(val):
        return val


def test_parse_simple_pubkey(monkeypatch):
    monkeypatch.setattr(
        'keycard.parsing.application_info.Capabilities',
        DummyCapabilities
    )
    data = bytes([0x80, 0x04, 0x01, 0x02, 0x03, 0x04])
    info = ApplicationInfo.parse(data)

    assert info.ecc_public_key == b'\x01\x02\x03\x04'
    assert info.capabilities == 3
    assert info.instance_uid is None
    assert info.key_uid is None
    assert info.version_major == 0
    assert info.version_minor == 0


def test_str_method():
    info = ApplicationInfo(
        capabilities=7,
        ecc_public_key=b'\x01\x02',
        instance_uid=b'\xAA\xBB',
        key_uid=b'\xCC\xDD',
        version_major=2,
        version_minor=5,
    )
    s = str(info)

    assert '2.5' in s
    assert 'aabb' in s
    assert 'ccdd' in s
    assert '0102' in s
    assert '7' in s


def test_parse_tlv_success(monkeypatch):
    def dummy_parse_tlv(data):
        if data == b'\xA4\x0C' + b'\x01'*12:
            return {
                0xA4: [
                    b'\x8F\x02\xAA\xBB'
                    b'\x80\x02\x01\x02'
                    b'\x8E\x02\xCC\xDD'
                    b'\x8D\x01\x07'
                    b'\x02\x02\x02\x05'
                ]
            }
        return {
            0x8F: [b'\xAA\xBB'],
            0x80: [b'\x01\x02'],
            0x8E: [b'\xCC\xDD'],
            0x8D: [b'\x07'],
            0x02: [b'\x02\x05']
        }

    class DummyCapabilities:
        @staticmethod
        def parse(val):
            return val

    monkeypatch.setattr(
        'keycard.parsing.application_info.parse_tlv',
        dummy_parse_tlv
    )
    monkeypatch.setattr(
        'keycard.parsing.application_info.Capabilities',
        DummyCapabilities
    )

    # Simulate TLV-encoded data
    data = b'\xA4\x0C' + b'\x01'*12
    info = ApplicationInfo.parse(data)

    assert info.instance_uid == b'\xAA\xBB'
    assert info.ecc_public_key == b'\x01\x02'
    assert info.key_uid == b'\xCC\xDD'
    assert info.capabilities == 7
    assert info.version_major == 2
    assert info.version_minor == 5


def test_parse_tlv_missing_a4(monkeypatch):
    def dummy_parse_tlv(data):
        # No 0xA4 tag present
        return {}

    monkeypatch.setattr(
        'keycard.parsing.application_info.parse_tlv',
        dummy_parse_tlv
    )
    with pytest.raises(InvalidResponseError):
        ApplicationInfo.parse(b'\x00\x01\x02')


def test_parse_tlv_missing_fields(monkeypatch):
    def dummy_parse_tlv(data):
        # Missing some tags
        return {
            0xA4: [b'']
        }

    class DummyCapabilities:
        @staticmethod
        def parse(val):
            return val

    monkeypatch.setattr(
        'keycard.parsing.application_info.parse_tlv',
        dummy_parse_tlv
    )
    monkeypatch.setattr(
        'keycard.parsing.application_info.Capabilities',
        DummyCapabilities
    )

    # Should raise KeyError due to missing tags in inner_tlv
    with pytest.raises(KeyError):
        ApplicationInfo.parse(b'\xA4\x01\x00')


def test_parse_pubkey_empty(monkeypatch):
    monkeypatch.setattr(
        'keycard.parsing.application_info.Capabilities',
        DummyCapabilities
    )
    # No pubkey bytes
    data = bytes([0x80, 0x00])
    info = ApplicationInfo.parse(data)
    assert info.ecc_public_key == b''
    assert info.capabilities == 1  # Only CREDENTIALS_MANAGEMENT
    assert info.instance_uid is None
    assert info.key_uid is None
    assert info.version_major == 0
    assert info.version_minor == 0


def test_is_initialized_property():
    info = ApplicationInfo(
        capabilities=1,
        ecc_public_key=None,
        instance_uid=None,
        key_uid=None,
        version_major=0,
        version_minor=0,
    )
    assert not info.is_initialized

    info.key_uid = b'\x01'
    assert info.is_initialized
