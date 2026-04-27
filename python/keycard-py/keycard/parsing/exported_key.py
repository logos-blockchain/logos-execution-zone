from dataclasses import dataclass
from typing import Optional


@dataclass
class ExportedKey:
    public_key: Optional[bytes] = None
    private_key: Optional[bytes] = None
    chain_code: Optional[bytes] = None

    @property
    def is_extended(self) -> bool:
        return self.chain_code is not None

    @property
    def has_private(self) -> bool:
        return self.private_key is not None
