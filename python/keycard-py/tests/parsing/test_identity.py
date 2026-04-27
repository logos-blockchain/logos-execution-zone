import pytest
from keycard.parsing.identity import parse, InvalidResponseError
from keycard.parsing import identity


def make_tlv(tag, value):
    return bytes([tag, len(value)]) + value


def fake_parse_tlv(data):
    if data == b'outer':
        return {0xA0: [b'inner']}
    elif data == b'inner':
        return {0x8A: [b'cert'], 0x30: [b'sig']}
    return {}


def test_parse_success(monkeypatch):
    monkeypatch.setattr(
        identity,
        "parse_tlv",
        lambda data:
            {0xA0: [b'inner']} if data == b'data'
            else {0x8A: [b'c'*95], 0x30: [b's'*64]})
    monkeypatch.setattr(
        identity,
        "_verify",
        lambda certificate, signature, challenge: None
    )
    monkeypatch.setattr(
        identity,
        "_recover_public_key",
        lambda certificate: b'pubkey'
    )

    challenge = b'challenge'
    data = b'data'
    result = parse(challenge, data)
    assert result == b'pubkey'


def test_parse_malformed_index(monkeypatch):
    monkeypatch.setattr(
        identity,
        "parse_tlv",
        lambda data: {0xA0: [b'inner']} if data == b'data' else {}
    )
    challenge = b'challenge'
    data = b'data'
    with pytest.raises(
        InvalidResponseError,
        match="Malformed identity response"
    ):
        parse(challenge, data)


def test_parse_certificate_too_short(monkeypatch):
    monkeypatch.setattr(
        identity,
        "parse_tlv",
        lambda data:
            {0xA0: [b'inner']} if data == b'data'
            else {0x8A: [b'c'*10], 0x30: [b's'*64]}
    )
    challenge = b'challenge'
    data = b'data'
    with pytest.raises(
        InvalidResponseError,
        match="Malformed identity response"
    ):
        parse(challenge, data)


def test_parse_signature_too_short(monkeypatch):
    monkeypatch.setattr(
        identity,
        "parse_tlv",
        lambda data:
            {0xA0: [b'inner']} if data == b'data'
            else {0x8A: [b'c'*95], 0x30: [b's'*10]})
    challenge = b'challenge'
    data = b'data'
    with pytest.raises(
        InvalidResponseError,
        match="Malformed identity response"
    ):
        parse(challenge, data)
