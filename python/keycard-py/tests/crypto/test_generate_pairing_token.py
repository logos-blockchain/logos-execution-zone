import hashlib
import unicodedata
from keycard.crypto.generate_pairing_token import generate_pairing_token


def test_generate_pairing_token_deterministic():
    passphrase = "correct horse battery staple"
    expected = hashlib.pbkdf2_hmac(
        'sha256',
        unicodedata.normalize('NFKD', passphrase).encode('utf-8'),
        unicodedata.normalize(
            'NFKD', 'Keycard Pairing Password Salt').encode('utf-8'),
        50000,
        dklen=32
    )
    assert generate_pairing_token(passphrase) == expected


def test_generate_pairing_token_unicode_normalization():
    token_plain = generate_pairing_token("é")
    token_composed = generate_pairing_token("é")
    assert token_plain == token_composed


def test_generate_pairing_token_output_length():
    token = generate_pairing_token("whatever")
    assert isinstance(token, bytes)
    assert len(token) == 32
