from .padding import iso7816_pad, iso7816_unpad

import pyaes


def aes_cbc_encrypt(
    key: bytes,
    iv: bytes,
    data: bytes,
    padding: bool = True
) -> bytes:
    if padding:
        data = iso7816_pad(data, 16)
    aes = pyaes.AESModeOfOperationCBC(key, iv=iv)

    ciphertext = b''
    for i in range(0, len(data), 16):
        block = data[i:i+16]
        ciphertext += aes.encrypt(block)

    return ciphertext


def aes_cbc_decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    aes = pyaes.AESModeOfOperationCBC(key, iv=iv)

    decrypted = b''
    for i in range(0, len(ciphertext), 16):
        block = ciphertext[i:i+16]
        decrypted += aes.decrypt(block)

    return iso7816_unpad(decrypted)
