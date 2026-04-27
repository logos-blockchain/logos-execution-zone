from enum import IntFlag


class Capabilities(IntFlag):
    """
    An enumeration representing the various capabilities supported by a device
    or application.

    Attributes:
        SECURE_CHANNEL (int): Indicates support for secure channel
            communication (0x01).
        KEY_MANAGEMENT (int): Indicates support for key management operations
            (0x02).
        CREDENTIALS_MANAGEMENT (int): Indicates support for credentials
            management (0x04).
        NDEF (int): Indicates support for NDEF (NFC Data Exchange Format)
            operations (0x08).
    """
    SECURE_CHANNEL = 0x01
    KEY_MANAGEMENT = 0x02
    CREDENTIALS_MANAGEMENT = 0x04
    NDEF = 0x08

    @classmethod
    def parse(cls, value: int) -> "Capabilities":
        """
        Parses an integer value and returns a corresponding Capabilities
        instance.

        Args:
            value (int): The integer value representing the capabilities.

        Returns:
            Capabilities: An instance of the Capabilities class corresponding
            to the given value.
        """
        return cls(value)

    def __str__(self) -> str:
        return " | ".join(
            name
            for name, member in self.__class__.__members__.items()
            if member in self
        )
