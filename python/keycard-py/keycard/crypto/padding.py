def iso7816_pad(data: bytes, block_size: int) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    return data + b'\x80' + b'\x00' * (pad_len - 1)


def iso7816_unpad(padded: bytes) -> bytes:
    if b'\x80' not in padded:
        raise ValueError("Invalid ISO7816 padding")
    return padded[:padded.rindex(b'\x80')]
