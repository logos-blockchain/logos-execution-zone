from .. import constants
from ..card_interface import CardInterface
from ..parsing.application_info import ApplicationInfo


def select(card: CardInterface) -> ApplicationInfo:
    '''
    Selects the Keycard application on the smart card and retrieves
    application information.

    Sends a SELECT APDU command using the Keycard AID, checks for a
    successful response, parses the returned application information,
    and returns it.

    Args:
        transport: The transport instance used to send the APDU command.

    Returns:
        ApplicationInfo: Parsed information about the selected Keycard
            application.

    Raises:
        APDUError: If the card returns a status word indicating failure.
    '''
    result = card.send_apdu(
        cla=constants.CLAISO7816,
        ins=constants.INS_SELECT,
        p1=0x04,
        p2=0x00,
        data=constants.KEYCARD_AID
    )

    return ApplicationInfo.parse(result)
