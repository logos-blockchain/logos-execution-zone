from dataclasses import dataclass
from ecdsa import VerifyingKey, util, SECP256k1
from typing import Optional

from ..constants import SigningAlgorithm


@dataclass
class SignatureResult:
    algo: SigningAlgorithm
    r: bytes
    s: bytes
    recovery_id: Optional[int] = None
    public_key: Optional[bytes] = None

    def __init__(
        self,
        digest: bytes,
        algo: SigningAlgorithm,
        r: int,
        s: int,
        recovery_id: Optional[int] = None,
        public_key: Optional[bytes] = None
    ) -> None:
        self.algo = algo
        self.r = r.to_bytes((r.bit_length() + 7) // 8, 'big')
        self.s = s.to_bytes((s.bit_length() + 7) // 8, 'big')
        if public_key is None and recovery_id is None:
            raise ValueError(
                "Public key and recovery id not returned from card")

        self.public_key = (
            public_key
            if public_key is not None
            else self._recover_public_key(digest)
        )

        self.recovery_id = (
            recovery_id
            if recovery_id is not None
            else self._recover_v(digest)
        )

    @property
    def signature(self) -> bytes:
        return self.r + self.s

    @property
    def signature_der(self) -> bytes:
        signature: bytes = util.sigencode_der(
            int.from_bytes(self.r, 'big'),
            int.from_bytes(self.s, 'big'),
            self.recovery_id
        )
        return signature

    def _recover_public_key(self, digest: bytes) -> bytes:
        if self.recovery_id is None:
            raise ValueError("Recovery ID is required for public key recovery")

        public_key = VerifyingKey.from_public_key_recovery_with_digest(
            self.signature_der,
            digest,
            SECP256k1,
            sigdecode=util.sigdecode_der)
        public_key_bytes: bytes = public_key.to_string()
        return public_key_bytes

    def _recover_v(self, digest: bytes) -> int:
        if self.public_key is None:
            raise ValueError("Public key is required for recovery ID")

        public_keys = VerifyingKey.from_public_key_recovery_with_digest(
            self.signature, digest, SECP256k1)

        index = 0
        for public_key in public_keys:
            if self.public_key[1:] == public_key.to_string():
                return index
            index += 1

        raise RuntimeError("Recovery ID not found")
