from types import TracebackType
from smartcard.System import readers
from smartcard.pcsc.PCSCReader import PCSCReader

from .apdu import APDUResponse
from .exceptions import TransportError


class Transport:
    def __init__(self) -> None:
        self.connection: PCSCReader = None

    def __enter__(self) -> 'Transport':
        self.connect()
        return self

    def __exit__(
        self,
        type_: type[BaseException] | None,
        value: BaseException | None,
        traceback: TracebackType | None
    ) -> None:
        self.disconnect()

    def connect(self, index: int = 0) -> None:
        r = readers()
        if not r:
            raise TransportError('No smart card readers found')
        self.connection = r[index].createConnection()
        self.connection.connect()

    def disconnect(self) -> None:
        if self.connection:
            self.connection.disconnect()
            self.connection = None

    def send_apdu(self, apdu: bytes) -> APDUResponse:
        if not self.connection:
            self.connect()

        apdu_list = list(apdu)

        response, sw1, sw2 = self.connection.transmit(apdu_list)

        sw = (sw1 << 8) | sw2
        return APDUResponse(response, sw)
