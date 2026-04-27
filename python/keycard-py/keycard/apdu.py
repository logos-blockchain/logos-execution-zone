'''
This module provides classes and functions for handling APDU (Application
Protocol Data Unit) responses and encoding data in LV (Length-Value) format.
'''

from dataclasses import dataclass


@dataclass
class APDUResponse:
    '''
    Represents a response to an APDU (Application Protocol Data Unit) command.

    Attributes:
        data (bytes): The response data returned from the APDU command.
        status_word (int): The status word indicating the result of the APDU
            command.
    '''
    data: bytes
    status_word: int

    def __str__(self) -> str:
        return (
            f'APDUResponse(data={bytes(self.data).hex()}, '
            f'status_word={hex(self.status_word)})'
        )


def encode_lv(value: bytes) -> bytes:
    '''
    Encodes the given bytes using LV (Length-Value) encoding.

    The function prepends the length of the input bytes as a single byte,
    followed by the value itself. The maximum supported length is 255 bytes.

    Args:
        value (bytes): The data to encode.

    Returns:
        bytes: The LV-encoded bytes.

    Raises:
        ValueError: If the input exceeds 255 bytes in length.
    '''
    if len(value) > 255:
        raise ValueError('LV encoding supports up to 255 bytes')

    return bytes([len(value)]) + value
