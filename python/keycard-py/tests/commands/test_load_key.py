import pytest
from keycard.commands.load_key import load_key
from keycard import constants
from hashlib import sha256
from keycard.parsing import tlv


def test_load_key_bip39(card):
    seed = b"\xAA" * 64
    fake_uid = b"\xBB" * 32
    card.send_secure_apdu.return_value = fake_uid

    result = load_key(
        card,
        key_type=constants.LoadKeyType.BIP39_SEED,
        bip39_seed=seed
    )

    card.send_secure_apdu.assert_called_once_with(
        ins=constants.INS_LOAD_KEY,
        p1=constants.LoadKeyType.BIP39_SEED,
        p2=0,
        data=seed
    )
    assert result == fake_uid


def test_load_key_pair(card):
    public_key = b'\x04' + b'\x01' * 64
    private_key = b'\x02' * 32
    uid = sha256(public_key).digest()
    card.send_secure_apdu.return_value = uid

    encoded = tlv.encode_tlv(
        0xA1,
        tlv.encode_tlv(0x80, public_key) +
        tlv.encode_tlv(0x81, private_key)
    )

    result = load_key(
        card,
        key_type=constants.LoadKeyType.ECC,
        public_key=public_key,
        private_key=private_key
    )

    card.send_secure_apdu.assert_called_once_with(
        ins=constants.INS_LOAD_KEY,
        p1=constants.LoadKeyType.ECC,
        p2=0,
        data=encoded
    )
    assert result == uid


def test_bip39_seed_too_short(card):
    with pytest.raises(ValueError, match="BIP39/LEE seed must be 16-64 bytes"):
        load_key(
            card,
            key_type=constants.LoadKeyType.BIP39_SEED,
            bip39_seed=b"\xAA" * 8
        )


def test_bip39_seed_missing(card):
    with pytest.raises(ValueError, match="Either bip39_seed or lee_seed must be provided for key_type = BIP39_SEED"):
        load_key(
            card,
            key_type=constants.LoadKeyType.BIP39_SEED
        )


def test_ecc_missing_private_key(card):
    with pytest.raises(ValueError, match="Private key.*required"):
        load_key(
            card,
            key_type=constants.LoadKeyType.ECC,
            public_key=b"\x04" + b"\x01" * 64
        )


def test_extended_ecc_missing_private_key(card):
    with pytest.raises(ValueError, match="Private key.*required"):
        load_key(
            card,
            key_type=constants.LoadKeyType.EXTENDED_ECC,
            public_key=b"\x04" + b"\x02" * 64,
            chain_code=b"\x00" * 32
        )
