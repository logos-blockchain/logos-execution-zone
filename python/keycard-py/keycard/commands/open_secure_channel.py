from ecdsa import SigningKey, VerifyingKey, SECP256k1, ECDH

from .. import constants
from ..card_interface import CardInterface
from ..exceptions import NotSelectedError
from ..secure_channel import SecureChannel
from ..preconditions import require_initialized


@require_initialized
def open_secure_channel(
    card: CardInterface,
    pairing_index: int,
    pairing_key: bytes
) -> SecureChannel:
    '''
    Opens a secure session with the Keycard using ECDH and a pairing key.

    This function performs an ephemeral ECDH key exchange with the card,
    sends the ephemeral public key, and receives cryptographic material
    from the card to derive a secure session.

    Args:
        transport: The transport used to communicate with the card.
        card_public_key (bytes): The ECC public key of the card, retrieved
            via select().
        pairing_index (int): The index of the previously established
            pairing slot.
        pairing_key (bytes): The shared 32-byte pairing key.

    Returns:
        SecureChannel: A newly established secure session with the card.

    Raises:
        NotSelectedError: If no card public key is provided.
        APDUError: If the card returns a failure status word.
    '''
    if not card.card_public_key:
        raise NotSelectedError('Card not selected or missing public key')

    ephemeral_key = SigningKey.generate(curve=SECP256k1)
    eph_pub_bytes = ephemeral_key.verifying_key.to_string('uncompressed')
    response: bytes = card.send_apdu(
        ins=constants.INS_OPEN_SECURE_CHANNEL,
        p1=pairing_index,
        data=eph_pub_bytes
    )

    salt = bytes(response[:32])
    seed_iv = bytes(response[32:])

    public_key = VerifyingKey.from_string(
        card.card_public_key,
        curve=SECP256k1
    )
    ecdh = ECDH(
        curve=SECP256k1,
        private_key=ephemeral_key,
        public_key=public_key
    )
    shared_secret = ecdh.generate_sharedsecret_bytes()

    return SecureChannel.open(
        shared_secret,
        pairing_key,
        salt,
        seed_iv,
    )
