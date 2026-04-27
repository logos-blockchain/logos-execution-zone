from dataclasses import dataclass
from typing import Optional

from ..exceptions import InvalidResponseError
from .capabilities import Capabilities
from .tlv import parse_tlv


@dataclass
class ApplicationInfo:
    """
    Represents parsed application information from a TLV-encoded response.

    Attributes:
        capabilities (Optional[int]): Parsed capabilities value, if present.
        ecc_public_key (Optional[bytes]): ECC public key bytes, if present.
        instance_uid (Optional[bytes]): Unique identifier for the application
            instance, if present.
        key_uid (Optional[bytes]): Unique identifier for the key, if present.
        version_major (int): Major version number of the application.
        version_minor (int): Minor version number of the application.
    """
    capabilities: Optional[int]
    ecc_public_key: Optional[bytes]
    instance_uid: Optional[bytes]
    key_uid: Optional[bytes]
    version_major: int
    version_minor: int

    @property
    def is_initialized(self) -> bool:
        """
        Checks if the application is initialized based on the presence of
        the key_uid.

        Returns:
            bool: True if the key_uid is present, False otherwise.
        """
        return self.key_uid is not None

    @staticmethod
    def parse(data: bytes) -> "ApplicationInfo":
        """
        Parses a byte sequence containing TLV-encoded application information
        and returns an ApplicationInfo instance.

        Args:
            data (bytes): The TLV-encoded response data to parse.

        Returns:
            ApplicationInfo: An instance populated with the parsed application
                information fields.

        The function extracts the following fields from the TLV data:
            - version_major (int): Major version number (from tag 0x02).
            - version_minor (int): Minor version number (from tag 0x02).
            - instance_uid (bytes or None): Instance UID (from tag 0x8F).
            - key_uid (bytes or None): Key UID (from tag 0x8E).
            - ecc_public_key (bytes or None): ECC public key (from tag 0x80).
            - capabilities (Capabilities or None): Capabilities object
                (from tag 0x8D).

        Raises:
            Any exceptions raised by ApplicationInfo._parse_response or
            Capabilities.parse.
        """
        version_major = version_minor = 0
        instance_uid = None
        key_uid = None
        ecc_public_key = None
        capabilities = 0

        if data[0] == 0x80:
            length = data[1]
            pubkey = data[2:2+length]
            ecc_public_key = bytes(pubkey)
            capabilities += Capabilities.CREDENTIALS_MANAGEMENT

            if pubkey:
                capabilities += Capabilities.SECURE_CHANNEL
            capabilities = Capabilities.parse(capabilities)
        else:
            tlv = parse_tlv(data)
            if 0xA4 not in tlv:
                raise InvalidResponseError(
                    "Invalid top-level tag, expected 0xA4")

            inner_tlv = parse_tlv(tlv[0xA4][0])

            instance_uid = bytes(inner_tlv[0x8F][0])
            ecc_public_key = bytes(inner_tlv[0x80][0])
            key_uid = inner_tlv[0x8E][0]
            capabilities = Capabilities.parse(inner_tlv[0x8D][0][0])
            for value in inner_tlv[0x02]:
                if len(value) == 2:
                    version_major, version_minor = value[0], value[1]

        return ApplicationInfo(
            capabilities=capabilities,
            ecc_public_key=ecc_public_key,
            instance_uid=instance_uid,
            key_uid=key_uid,
            version_major=version_major,
            version_minor=version_minor,
        )

    def __str__(self) -> str:
        return (
            f"ApplicationInfo(version="
            f"{self.version_major}.{self.version_minor}, "
            f"instance_uid="
            f"{self.instance_uid.hex() if self.instance_uid else None}, "
            f"key_uid="
            f"{self.key_uid.hex() if self.key_uid else None}, "
            f"ecc_public_key="
            f"{self.ecc_public_key.hex() if self.ecc_public_key else None}, "
            f"capabilities="
            f"{self.capabilities})"
        )
