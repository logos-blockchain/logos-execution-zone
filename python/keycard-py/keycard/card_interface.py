from typing import Optional, Protocol, runtime_checkable


@runtime_checkable
class CardInterface(Protocol):
    '''
    Abstract base class representing a Keycard interface for command functions.
    '''
    card_public_key: Optional[bytes]

    @property
    def is_initialized(self) -> bool: ...

    @property
    def is_secure_channel_open(self) -> bool: ...

    @property
    def is_pin_verified(self) -> bool: ...

    @property
    def is_selected(self) -> bool: ...

    def send_apdu(
        self,
        ins: int,
        p1: int = 0x00,
        p2: int = 0x00,
        data: bytes = b'',
        cla: Optional[int] = None
    ) -> bytes: ...

    def send_secure_apdu(
        self,
        ins: int,
        p1: int = 0x00,
        p2: int = 0x00,
        data: bytes = b''
    ) -> bytes: ...
