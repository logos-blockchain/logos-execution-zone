import pytest
from keycard.crypto import aes


def test_aes_cbc_encrypt_decrypt_roundtrip():
    key = b'0123456789abcdef'
    iv = b'abcdef9876543210'
    data = b'hello world 1234'
    ciphertext = aes.aes_cbc_encrypt(key, iv, data)
    decrypted = aes.aes_cbc_decrypt(key, iv, ciphertext)
    assert decrypted == data


def test_aes_cbc_encrypt_padding():
    key = b'0123456789abcdef'
    iv = b'abcdef9876543210'
    data = b'abc'
    ciphertext = aes.aes_cbc_encrypt(key, iv, data)
    assert len(ciphertext) % 16 == 0
    decrypted = aes.aes_cbc_decrypt(key, iv, ciphertext)
    assert decrypted == data


def test_aes_cbc_encrypt_no_padding():
    key = b'0123456789abcdef'
    iv = b'abcdef9876543210'
    data = b'1234567890abcdef'
    ciphertext = aes.aes_cbc_encrypt(key, iv, data, padding=False)
    assert len(ciphertext) == 16
    with pytest.raises(ValueError):
        aes.aes_cbc_decrypt(key, iv, ciphertext)


def test_aes_cbc_decrypt_invalid_padding():
    key = b'0123456789abcdef'
    iv = b'abcdef9876543210'
    data = b'1234567890abcdef'
    ciphertext = aes.aes_cbc_encrypt(key, iv, data, padding=False)
    with pytest.raises(ValueError):
        aes.aes_cbc_decrypt(key, iv, ciphertext)


@pytest.mark.parametrize('data', [
    b'',
    b'a',
    b'short',
    b'exactly16bytes!!',
    b'longer data that is not a multiple of block size',
])
def test_various_lengths(data):
    key = b'0123456789abcdef'
    iv = b'abcdef9876543210'
    ciphertext = aes.aes_cbc_encrypt(key, iv, data)
    decrypted = aes.aes_cbc_decrypt(key, iv, ciphertext)
    assert decrypted == data
