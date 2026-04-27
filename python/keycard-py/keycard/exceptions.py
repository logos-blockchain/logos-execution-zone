class KeyCardError(Exception):
    """Base exception for Keycard SDK"""

    pass


class APDUError(KeyCardError):
    """Raised when APDU returns non-success status word."""

    def __init__(self, sw: int):
        self.sw = sw
        super().__init__(f"APDU failed with SW={sw:04X}")


class InvalidResponseError(KeyCardError):
    """Raised when response parsing fails."""

    pass


class NotInitializedError(KeyCardError):
    """Raised when trying to use card public key before select()."""

    pass


class NotSelectedError(KeyCardError):
    """Raised when trying to use card before select()."""

    pass


class TransportError(KeyCardError):
    """Raised there are no readers"""
    pass


class InvalidStateError(KeyCardError):
    """Raised when a precondition is not met."""
    def __init__(self, message: str):
        super().__init__(message)
