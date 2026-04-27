from typing import Union

from ..constants import DerivationSource


class KeyPath:
    MAX_COMPONENTS = 10

    def __init__(
        self,
        path: Union[str, bytes, bytearray],
        source: DerivationSource = DerivationSource.MASTER
    ):
        if isinstance(path, str):
            if path == '':
                raise ValueError("Empty path")
            self.source, components = self._parse_path_string(path)
            if len(components) > self.MAX_COMPONENTS:
                raise ValueError("Too many components in derivation path")
            self.data = self._encode_components(components)
        elif isinstance(path, (bytes, bytearray)):
            if len(path) % 4 != 0:
                raise ValueError("Byte path must be a multiple of 4")
            self.source = source
            self.data = bytes(path)
        else:
            raise TypeError("Path must be a string or bytes")

    def _parse_path_string(
        self,
        path: str
    ) -> tuple[DerivationSource, list[int]]:
        tokens = path.split('/')
        if not tokens:
            raise ValueError("Empty path")

        first = tokens[0]
        if first == "m":
            source = DerivationSource.MASTER
            tokens = tokens[1:]
        elif first == "..":
            source = DerivationSource.PARENT
            tokens = tokens[1:]
        elif first == ".":
            source = DerivationSource.CURRENT
            tokens = tokens[1:]
        else:
            source = DerivationSource.CURRENT

        components = [self._parse_component(token) for token in tokens]
        return source, components

    def _parse_component(self, token: str) -> int:
        if token.endswith("'"):
            token = token[:-1]
            hardened = True
        else:
            hardened = False

        if not token.isdigit():
            raise ValueError(f"Invalid component: {token}")

        value = int(token)
        if hardened:
            value |= 0x80000000
        return value

    def _encode_components(self, components: list[int]) -> bytes:
        return b''.join(comp.to_bytes(4, 'big') for comp in components)

    def to_string(self) -> str:
        prefix = {
            DerivationSource.MASTER: 'm',
            DerivationSource.PARENT: '..',
            DerivationSource.CURRENT: '.'
        }.get(self.source, '.')

        components = []
        for i in range(0, len(self.data), 4):
            chunk = self.data[i:i+4]
            val = int.from_bytes(chunk, 'big')
            if val & 0x80000000:
                components.append(f"{val & 0x7FFFFFFF}'")
            else:
                components.append(str(val))

        return '/'.join([prefix] + components)
