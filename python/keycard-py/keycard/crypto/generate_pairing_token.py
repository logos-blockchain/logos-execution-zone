
import hashlib
import unicodedata


SALT = 'Keycard Pairing Password Salt'
NUMBER_OF_ITERATIONS = 50000
DKLEN = 32


def generate_pairing_token(passphrase: str) -> bytes:
    norm_pass = unicodedata.normalize('NFKD', passphrase).encode('utf-8')
    salt = unicodedata.normalize('NFKD', SALT).encode('utf-8')
    return hashlib.pbkdf2_hmac(
        'sha256', norm_pass, salt, NUMBER_OF_ITERATIONS, dklen=DKLEN)
