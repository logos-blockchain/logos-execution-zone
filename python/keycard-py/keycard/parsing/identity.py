from hashlib import sha256
from ecdsa import VerifyingKey, SECP256k1, util

from ..exceptions import InvalidResponseError
from ..parsing.tlv import parse_tlv


def parse(challenge: bytes, data: bytes) -> bytes:
    tlvs = parse_tlv(data)

    inner_tlvs = parse_tlv(tlvs[0xA0][0])

    try:
        certificate = inner_tlvs[0x8A][0]
        signature = inner_tlvs[0x30][0]
    except (IndexError, KeyError):
        raise InvalidResponseError('Malformed identity response')

    signature = b'\x30' + len(signature).to_bytes(1, 'big') + signature
    if len(certificate) < 95 or len(signature) < 65:
        raise InvalidResponseError('Malformed identity response')

    _verify(certificate, signature, challenge)
    return _recover_public_key(certificate)


def _verify(certificate: bytes, signature: bytes, challenge: bytes) -> None:
    pub_key = certificate[:33]
    vk = VerifyingKey.from_string(pub_key, curve=SECP256k1)
    vk.verify_digest(signature, challenge, sigdecode=util.sigdecode_der)


def _recover_public_key(certificate: bytes) -> bytes:
    signature = certificate[33:]
    v = signature[-1]
    digest = sha256(certificate).digest()

    vk = VerifyingKey.from_public_key_recovery_with_digest(
        signature[:-1], digest, SECP256k1)

    public_key = vk[v] if isinstance(vk, list) else vk
    der: bytes = public_key.to_der('compressed')
    return der
