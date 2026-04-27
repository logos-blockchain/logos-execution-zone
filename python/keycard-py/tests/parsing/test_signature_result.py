from keycard.parsing.signature_result import SignatureResult
from keycard.constants import SigningAlgorithm
from unittest import mock


def test_signature_result_with_minimal_r_s():
    r = 1
    s = 1
    digest = b'\x01' * 32
    public_key = b'\x02' + b'\x01' * 32
    sig = SignatureResult(
        digest=digest,
        algo=SigningAlgorithm.ECDSA_SECP256K1,
        r=r,
        s=s,
        public_key=public_key,
        recovery_id=0
    )
    assert sig.r == b'\x01'
    assert sig.s == b'\x01'
    assert sig.signature == b'\x01\x01'


def test_signature_result_with_large_r_s():
    r = 2**255
    s = 2**255 - 1
    digest = b'\x01' * 32
    public_key = b'\x02' + b'\x01' * 32
    sig = SignatureResult(
        digest=digest,
        algo=SigningAlgorithm.ECDSA_SECP256K1,
        r=r,
        s=s,
        public_key=public_key,
        recovery_id=2
    )
    assert sig.r == r.to_bytes((r.bit_length() + 7) // 8, 'big')
    assert sig.s == s.to_bytes((s.bit_length() + 7) // 8, 'big')
    assert sig.recovery_id == 2


def test_signature_result_signature_der_property():
    r = 123
    s = 456
    digest = b'\x01' * 32
    public_key = b'\x02' + b'\x01' * 32

    with mock.patch(
        'keycard.parsing.signature_result.util.sigencode_der'
    ) as mock_sigencode_der:
        mock_sigencode_der.return_value = b'der'
        sig = SignatureResult(
            digest=digest,
            algo=SigningAlgorithm.ECDSA_SECP256K1,
            r=r,
            s=s,
            public_key=public_key,
            recovery_id=3
        )
        der = sig.signature_der
        assert der == b'der'
        mock_sigencode_der.assert_called_once_with(r, s, 3)


def test_signature_result_repr_exists():
    r = int.from_bytes(b'\x01' * 32, 'big')
    s = int.from_bytes(b'\x01' * 32, 'big')
    digest = b'\x01' * 32
    public_key = b'\x02' + b'\x01' * 32
    sig = SignatureResult(
        digest=digest,
        algo=SigningAlgorithm.ECDSA_SECP256K1,
        r=r,
        s=s,
        public_key=public_key,
        recovery_id=0
    )
    assert isinstance(repr(sig), str)


def test_signature_result_public_key_and_recovery_id_priority():
    r = 5
    s = 6
    digest = b'\x01' * 32
    public_key = b'\x02' + b'\x01' * 32
    sig = SignatureResult(
        digest=digest,
        algo=SigningAlgorithm.ECDSA_SECP256K1,
        r=r,
        s=s,
        public_key=public_key,
        recovery_id=7
    )
    assert sig.public_key == public_key
    assert sig.recovery_id == 7


def test_signature_result_missing_public_key_calls_recover():
    r = 10
    s = 20
    digest = b'\x01' * 32
    with mock.patch.object(
        SignatureResult,
        "_recover_public_key",
        return_value=b'\x02' + b'\x02' * 32
    ) as mock_pubkey:
        sig = SignatureResult(
            digest=digest,
            algo=SigningAlgorithm.ECDSA_SECP256K1,
            r=r,
            s=s,
            public_key=None,
            recovery_id=9
        )
        assert sig.public_key == b'\x02' + b'\x02' * 32
        assert sig.recovery_id == 9
        mock_pubkey.assert_called_once_with(digest)
