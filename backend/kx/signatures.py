"""SignatureAuthenticator: Ed25519 long-term identity keys used to authenticate public values."""
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

SIGNATURE_BYTES = 64


class Identity:
    """A party's long-term signing identity. The public half is assumed to be known in advance
    by the other party (as if fingerprints had been compared in person); a full PKI is out of scope."""

    def __init__(self):
        self._private = Ed25519PrivateKey.generate()
        self.public = self._private.public_key()

    def sign(self, data: bytes) -> bytes:
        return self._private.sign(data)


def verify(public_key, data: bytes, signature: bytes) -> bool:
    try:
        public_key.verify(signature, data)
        return True
    except InvalidSignature:
        return False
