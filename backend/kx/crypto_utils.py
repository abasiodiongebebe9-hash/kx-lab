"""EncryptionEngine: key derivation (HKDF-SHA256) and message encryption (AES-256-GCM)."""
import hashlib
import os
import time

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

INFO = b"kx-lab session key"


class Timer:
    """Context manager measuring elapsed milliseconds with a monotonic clock."""

    def __enter__(self):
        self._t0 = time.perf_counter()
        self.ms = 0.0
        return self

    def __exit__(self, *exc):
        self.ms = (time.perf_counter() - self._t0) * 1000.0
        return False


def derive_key(shared_secret: bytes) -> bytes:
    """Turn a raw shared secret into a uniformly random 256-bit session key."""
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=INFO).derive(shared_secret)


def encrypt_message(key: bytes, plaintext: bytes):
    """Encrypt with AES-256-GCM. Returns (nonce, ciphertext_with_tag). A fresh nonce is used every time."""
    nonce = os.urandom(12)
    return nonce, AESGCM(key).encrypt(nonce, plaintext, None)


def decrypt_message(key: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
    """Decrypt with AES-256-GCM. Raises cryptography.exceptions.InvalidTag if the key is wrong."""
    return AESGCM(key).decrypt(nonce, ciphertext, None)


def fingerprint(key: bytes) -> str:
    """Short, safe-to-display fingerprint of a key (first 8 bytes of its SHA-256)."""
    return hashlib.sha256(key).hexdigest()[:16]


def short_hex(data: bytes, edge: int = 6) -> str:
    """Readable form of a long value: first and last bytes plus the length."""
    if data is None:
        return ""
    if len(data) <= edge * 2:
        return data.hex()
    return f"{data[:edge].hex()}...{data[-edge:].hex()} ({len(data)} bytes)"
