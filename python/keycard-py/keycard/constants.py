"""
This module defines constants used for communication with the Keycard applet
via APDU commands.
"""

from enum import IntEnum


# Applet AID
KEYCARD_AID: bytes = bytes.fromhex('A000000804000101')

CLAISO7816: int = 0x00
CLA_PROPRIETARY: int = 0x80

# APDU instructions
INS_SELECT: int = 0xA4
INS_INIT: int = 0xFE
INS_IDENT: int = 0x14
INS_OPEN_SECURE_CHANNEL: int = 0x10
INS_MUTUALLY_AUTHENTICATE: int = 0x11
INS_PAIR: int = 0x12
INS_UNPAIR: int = 0x13
INS_VERIFY_PIN: int = 0x20
INS_GET_STATUS: int = 0xF2
INS_FACTORY_RESET: int = 0xFD
INS_GENERATE_KEY: int = 0xD4
INS_CHANGE_SECRET: int = 0x21
INS_UNBLOCK_PIN: int = 0x22
INS_STORE_DATA: int = 0xE2
INS_GET_DATA: int = 0xCA
INS_SIGN: int = 0xC0
INS_SET_PINLESS_PATH = 0xC1
INS_EXPORT_KEY: int = 0xC2
INS_LOAD_KEY: int = 0xD0
INS_DERIVE_KEY = 0xD1
INS_GENERATE_MNEMONIC = 0xD2
INS_EXPORT_LEE_KEY = 0xC3

# Status words
SW_SUCCESS: int = 0x9000


class PinType(IntEnum):
    USER = 0x00
    PUK = 0x01
    PAIRING = 0x02


class StorageSlot(IntEnum):
    PUBLIC = 0x00
    NDEF = 0x01
    CASH = 0x02


class DerivationOption(IntEnum):
    CURRENT = 0x00
    DERIVE = 0x01
    DERIVE_AND_MAKE_CURRENT = 0x02
    PINLESS = 0x03


class KeyExportOption(IntEnum):
    PRIVATE_AND_PUBLIC = 0x00
    PUBLIC_ONLY = 0x01
    EXTENDED_PUBLIC = 0x02


class DerivationSource(IntEnum):
    MASTER = 0x00
    PARENT = 0x40
    CURRENT = 0x80


class SigningAlgorithm(IntEnum):
    ECDSA_SECP256K1 = 0x00
    EDDSA_ED25519 = 0x01
    BLS12_381 = 0x02
    SCHNORR_BIP340 = 0x03


class LoadKeyType(IntEnum):
    ECC = 0x01
    EXTENDED_ECC = 0x02
    BIP39_SEED = 0x03


class PairingMode(IntEnum):
    ANY = 0x00
    EPHEMERAL = 0x01
    PERSISTENT = 0x02
