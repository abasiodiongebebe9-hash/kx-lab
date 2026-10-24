"""KeyGenerator and protocol modules: finite-field DH, ECDH (P-256, X25519) and RSA key transport.

DH, ECDH and X25519 share one interface (new_keypair / public_bytes / derive). RSA key transport has
a different shape, because one side invents the secret, so it has its own methods.
"""
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dh, ec, padding, rsa, x25519

from .dh_group import G, P_2048, Q_2048

DH_BYTES = 256


def validate_dh_public(value: int, p: int = P_2048, q: int = Q_2048) -> None:
    """Reject out-of-range values and values outside the expected subgroup (safe-prime group)."""
    if not (2 <= value <= p - 2):
        raise ValueError("public value out of range")
    if pow(value, q, p) != 1:
        raise ValueError("public value is not in the expected subgroup")


class DHProtocol:
    name = "DH-2048"
    kind = "agreement"
    description = "Finite-field Diffie-Hellman, 2048-bit RFC 3526 group"

    def __init__(self):
        self._numbers = dh.DHParameterNumbers(P_2048, G)
        self._params = self._numbers.parameters()

    def new_keypair(self):
        return self._params.generate_private_key()

    def public_bytes(self, private) -> bytes:
        return private.public_key().public_numbers().y.to_bytes(DH_BYTES, "big")

    def derive(self, private, peer_public: bytes) -> bytes:
        y = int.from_bytes(peer_public, "big")
        validate_dh_public(y)
        peer = dh.DHPublicNumbers(y, self._numbers).public_key()
        return private.exchange(peer)


class ECDHP256Protocol:
    name = "ECDH-P256"
    kind = "agreement"
    description = "Elliptic curve Diffie-Hellman on NIST P-256"

    def new_keypair(self):
        return ec.generate_private_key(ec.SECP256R1())

    def public_bytes(self, private) -> bytes:
        return private.public_key().public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
        )

    def derive(self, private, peer_public: bytes) -> bytes:
        # from_encoded_point checks that the point really lies on the curve
        peer = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), peer_public)
        return private.exchange(ec.ECDH(), peer)


class X25519Protocol:
    name = "ECDH-X25519"
    kind = "agreement"
    description = "Elliptic curve Diffie-Hellman on Curve25519"

    def new_keypair(self):
        return x25519.X25519PrivateKey.generate()

    def public_bytes(self, private) -> bytes:
        return private.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )

    def derive(self, private, peer_public: bytes) -> bytes:
        peer = x25519.X25519PublicKey.from_public_bytes(peer_public)
        return private.exchange(peer)  # raises ValueError on an all-zero (low-order) result


class RSATransportProtocol:
    name = "RSA-2048"
    kind = "transport"
    description = "RSA-2048 key transport with OAEP (SHA-256)"

    def __init__(self):
        self._oaep = padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None
        )

    def new_keypair(self):
        return rsa.generate_private_key(public_exponent=65537, key_size=2048)

    def public_bytes(self, private) -> bytes:
        return private.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def load_public(self, data: bytes):
        return serialization.load_der_public_key(data)

    def encrypt(self, public_key, secret: bytes) -> bytes:
        return public_key.encrypt(secret, self._oaep)

    def decrypt(self, private, ciphertext: bytes) -> bytes:
        return private.decrypt(ciphertext, self._oaep)


PROTOCOLS = {
    p.name: p for p in (DHProtocol(), ECDHP256Protocol(), X25519Protocol(), RSATransportProtocol())
}
