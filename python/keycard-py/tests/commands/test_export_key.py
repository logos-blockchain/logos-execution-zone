import pytest
from keycard.commands.export_key import export_key
from keycard.constants import DerivationOption, DerivationSource
from keycard.parsing.exported_key import ExportedKey


def test_export_key_success_public_only(card):
    public_key = b'\x04' + b'\x01' * 64
    inner_tlv = b'\x80' + bytes([len(public_key)]) + public_key
    outer_tlv = b'\xA1' + bytes([len(inner_tlv)]) + inner_tlv
    card.send_secure_apdu.return_value = outer_tlv

    result = export_key(
        card,
        derivation_option=DerivationOption.CURRENT,
        public_only=True,
        keypath=None,
        make_current=False,
        source=DerivationSource.MASTER
    )

    assert isinstance(result, ExportedKey)
    assert result.public_key == public_key
    assert result.private_key is None
    assert result.chain_code is None


def test_export_key_with_path_string(card):
    public_key = b'\x04' + b'\x02' * 64
    inner_tlv = b'\x80' + bytes([len(public_key)]) + public_key
    outer_tlv = b'\xA1' + bytes([len(inner_tlv)]) + inner_tlv
    card.send_secure_apdu.return_value = outer_tlv

    result = export_key(
        card,
        derivation_option=DerivationOption.DERIVE,
        public_only=True,
        keypath="m/44'/60'/0'/0/0",
        make_current=True,
        source=DerivationSource.MASTER
    )

    assert isinstance(result, ExportedKey)
    assert result.public_key == public_key


def test_export_key_invalid_keypath_length_bytes(card):
    with pytest.raises(
        ValueError,
        match="Byte keypath must be a multiple of 4"
    ):
        export_key(
            card,
            derivation_option=DerivationOption.DERIVE,
            public_only=True,
            keypath=b'\x01\x02\x03',
            make_current=False,
            source=DerivationSource.PARENT
        )


def test_export_key_requires_keypath_if_not_current(card):
    with pytest.raises(
        ValueError,
        match="Keypath required unless using CURRENT derivation"
    ):
        export_key(
            card,
            derivation_option=DerivationOption.DERIVE,
            public_only=True,
            keypath=None,
            make_current=False,
            source=DerivationSource.CURRENT
        )


def test_export_key_invalid_keypath_type(card):
    with pytest.raises(TypeError, match="Keypath must be a string or bytes"):
        export_key(
            card,
            derivation_option=DerivationOption.DERIVE,
            public_only=True,
            keypath=123,
            make_current=False,
            source=DerivationSource.CURRENT
        )


def test_export_key_missing_keypair_template(card):
    card.send_secure_apdu.return_value = b'\xA0\x00'

    with pytest.raises(ValueError, match="Missing keypair template"):
        export_key(
            card,
            derivation_option=DerivationOption.CURRENT,
            public_only=True,
            keypath=None,
            make_current=False,
            source=DerivationSource.MASTER
        )
