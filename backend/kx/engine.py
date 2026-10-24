"""Exchange engine and MITMSimulator.

run_exchange() drives one complete key exchange between Alice and Bob, optionally with Mallory
sitting in the middle and optionally with Ed25519 signatures on the exchanged values. It returns
a plain dictionary containing every step (for the timeline), the verdict and the metrics.
"""
import os
import time

from cryptography.exceptions import InvalidTag

from .crypto_utils import (Timer, decrypt_message, derive_key, encrypt_message,
                           fingerprint, short_hex)
from .protocols import PROTOCOLS
from .signatures import SIGNATURE_BYTES, Identity, verify

DEFAULT_MESSAGE = "Hello Bob, this is a secret."


class Recorder:
    """Collects timeline steps and the attack log."""

    def __init__(self):
        self.steps = []
        self.attack_log = []

    def add(self, actor, action, note, value=None, ms=None, warn=False):
        n = len(self.steps) + 1
        self.steps.append({
            "step_no": n,
            "actor": actor,
            "action": action,
            "note": note,
            "value_hex": short_hex(value) if value is not None else "",
            "elapsed_ms": round(ms, 3) if ms is not None else None,
            "warning": bool(warn),
        })
        return n

    def log_replacement(self, step_no, original: bytes, substituted: bytes):
        self.attack_log.append({
            "step_no": step_no,
            "original_value": original.hex(),
            "substituted_value": substituted.hex(),
            "detected": False,
        })

    def mark_last_detected(self):
        if self.attack_log:
            self.attack_log[-1]["detected"] = True


def _new_result(proto, mitm, signatures, message):
    return {
        "protocol": proto.name,
        "mitm": mitm,
        "signatures": signatures,
        "message": message,
        "keys_match": None,
        "mallory_knows_key": False,
        "attack_outcome": "none",
        "bob_read": None,
        "mallory_read": None,
        "fingerprints": {},
        "metrics": {},
    }


def _finish(result, rec, started, metrics):
    metrics["total_ms"] = round((time.perf_counter() - started) * 1000.0, 3)
    for k in ("keygen_ms", "secret_ms"):
        if k in metrics and metrics[k] is not None:
            metrics[k] = round(metrics[k], 3)
    result["metrics"] = metrics
    result["steps"] = rec.steps
    result["attack_log"] = rec.attack_log
    return result


def _detected(result, rec, started, metrics, who):
    rec.mark_last_detected()
    rec.add("system", "stop",
            f"{who} rejected the tampered value, so the exchange stopped. No key was derived from it.",
            warn=True)
    result["attack_outcome"] = "detected"
    return _finish(result, rec, started, metrics)


def run_exchange(protocol_name, mitm=False, signatures=False, message=DEFAULT_MESSAGE):
    if protocol_name not in PROTOCOLS:
        raise ValueError("unknown protocol")
    proto = PROTOCOLS[protocol_name]
    started = time.perf_counter()
    rec = Recorder()
    result = _new_result(proto, mitm, signatures, message)
    if proto.kind == "transport":
        return _run_rsa(proto, mitm, signatures, message, rec, result, started)
    return _run_agreement(proto, mitm, signatures, message, rec, result, started)


# ----------------------------------------------------------------------------------------------
# Diffie-Hellman family (DH, ECDH P-256, X25519): both parties contribute to the secret
# ----------------------------------------------------------------------------------------------
def _run_agreement(proto, mitm, signatures, message, rec, result, started):
    metrics = {}
    alice_id, bob_id = Identity(), Identity()
    if signatures:
        rec.add("system", "setup",
                "Alice and Bob already know each other's long-term signature verification keys "
                "(as if they had compared fingerprints in person).")

    with Timer() as t_ka:
        alice = proto.new_keypair()
    with Timer() as t_kb:
        bob = proto.new_keypair()
    metrics["keygen_ms"] = t_ka.ms
    rec.add("alice", "generate_key", f"Alice generates a fresh {proto.name} key pair.", ms=t_ka.ms)
    rec.add("bob", "generate_key", f"Bob generates a fresh {proto.name} key pair.", ms=t_kb.ms)

    mallory = None
    if mitm:
        with Timer() as t_km:
            mallory = proto.new_keypair()
        rec.add("mallory", "generate_key",
                "Mallory generates her own key pair, ready to impersonate both parties.",
                ms=t_km.ms, warn=True)

    # ---- message 1: Alice -> Bob
    a_pub = proto.public_bytes(alice)
    a_sig = alice_id.sign(a_pub) if signatures else None
    rec.add("alice", "send_value",
            "Alice sends her public value to Bob" + (" and signs it." if signatures else "."), a_pub)
    got_a = a_pub
    if mitm:
        got_a = proto.public_bytes(mallory)
        n = rec.add("mallory", "replace",
                    "Mallory intercepts Alice's value and substitutes her own.", got_a, warn=True)
        rec.log_replacement(n, a_pub, got_a)
    if signatures:
        ok = verify(alice_id.public, got_a, a_sig)
        rec.add("bob", "verify",
                "Bob checks Alice's signature: " + ("valid." if ok else "INVALID, the value was altered in transit."),
                warn=not ok)
        if not ok:
            metrics.update(first_message_bytes=len(a_pub), second_message_bytes=0,
                           signature_bytes=SIGNATURE_BYTES,
                           bytes_transmitted=len(a_pub) + SIGNATURE_BYTES)
            return _detected(result, rec, started, metrics, "Bob")

    # ---- message 2: Bob -> Alice
    b_pub = proto.public_bytes(bob)
    b_sig = bob_id.sign(b_pub) if signatures else None
    rec.add("bob", "send_value",
            "Bob sends his public value to Alice" + (" and signs it." if signatures else "."), b_pub)
    got_b = b_pub
    if mitm:
        got_b = proto.public_bytes(mallory)
        n = rec.add("mallory", "replace",
                    "Mallory intercepts Bob's value and substitutes her own.", got_b, warn=True)
        rec.log_replacement(n, b_pub, got_b)
    if signatures:
        ok = verify(bob_id.public, got_b, b_sig)
        rec.add("alice", "verify",
                "Alice checks Bob's signature: " + ("valid." if ok else "INVALID, the value was altered in transit."),
                warn=not ok)
        if not ok:
            metrics.update(first_message_bytes=len(a_pub), second_message_bytes=len(b_pub),
                           signature_bytes=SIGNATURE_BYTES * 2,
                           bytes_transmitted=len(a_pub) + len(b_pub) + SIGNATURE_BYTES * 2)
            return _detected(result, rec, started, metrics, "Alice")

    metrics.update(first_message_bytes=len(a_pub), second_message_bytes=len(b_pub),
                   signature_bytes=SIGNATURE_BYTES * 2 if signatures else 0)
    metrics["bytes_transmitted"] = len(a_pub) + len(b_pub) + metrics["signature_bytes"]

    # ---- shared secrets and session keys
    with Timer() as t_a:
        secret_a = proto.derive(alice, got_b)
    with Timer() as t_b:
        secret_b = proto.derive(bob, got_a)
    metrics["secret_ms"] = t_b.ms
    rec.add("alice", "derive_secret", "Alice combines her private key with the value she received.", ms=t_a.ms)
    rec.add("bob", "derive_secret", "Bob combines his private key with the value he received.", ms=t_b.ms)
    key_a, key_b = derive_key(secret_a), derive_key(secret_b)
    result["keys_match"] = key_a == key_b
    result["fingerprints"] = {"alice": fingerprint(key_a), "bob": fingerprint(key_b)}
    rec.add("system", "derive_key",
            "Both sides run HKDF-SHA256 on the raw secret to get a 256-bit session key. "
            f"Key fingerprints: Alice {fingerprint(key_a)}, Bob {fingerprint(key_b)}. "
            + ("They MATCH." if key_a == key_b else "They DIFFER."),
            warn=key_a != key_b)

    # ---- chat message
    nonce, ct = encrypt_message(key_a, message.encode())
    rec.add("alice", "encrypt", "Alice encrypts the message with AES-256-GCM and sends it.", ct)
    if not mitm:
        text = decrypt_message(key_b, nonce, ct).decode()
        result["bob_read"] = text
        rec.add("bob", "decrypt", f"Bob decrypts it successfully: \"{text}\"")
        return _finish(result, rec, started, metrics)

    # Mallory is active and undetected: she holds one key with Alice and another with Bob
    key_ma = derive_key(proto.derive(mallory, a_pub))
    key_mb = derive_key(proto.derive(mallory, b_pub))
    result["mallory_knows_key"] = True
    result["attack_outcome"] = "succeeded"
    result["fingerprints"]["mallory_with_alice"] = fingerprint(key_ma)
    result["fingerprints"]["mallory_with_bob"] = fingerprint(key_mb)
    try:
        decrypt_message(key_b, nonce, ct)
        direct_ok = True
    except InvalidTag:
        direct_ok = False
    rec.add("bob", "decrypt",
            "Bob tries to decrypt Alice's original ciphertext with his key: "
            + ("it works." if direct_ok else "authentication fails, because his key differs from Alice's."),
            warn=not direct_ok)
    plaintext = decrypt_message(key_ma, nonce, ct)
    result["mallory_read"] = plaintext.decode()
    rec.add("mallory", "decrypt",
            f"Mallory decrypts the message with the key she shares with Alice and reads: \"{plaintext.decode()}\"",
            warn=True)
    nonce2, ct2 = encrypt_message(key_mb, plaintext)
    bob_text = decrypt_message(key_b, nonce2, ct2).decode()
    result["bob_read"] = bob_text
    rec.add("mallory", "relay",
            "Mallory re-encrypts the message for Bob so that neither victim notices anything wrong.", ct2, warn=True)
    rec.add("bob", "decrypt", f"Bob decrypts the relayed message and sees: \"{bob_text}\"")
    return _finish(result, rec, started, metrics)


# ----------------------------------------------------------------------------------------------
# RSA key transport: Bob publishes a key, Alice invents the secret and encrypts it
# ----------------------------------------------------------------------------------------------
def _run_rsa(proto, mitm, signatures, message, rec, result, started):
    metrics = {}
    alice_id, bob_id = Identity(), Identity()
    if signatures:
        rec.add("system", "setup",
                "Alice and Bob already know each other's long-term signature verification keys.")

    with Timer() as t_kb:
        bob_priv = proto.new_keypair()
    metrics["keygen_ms"] = t_kb.ms
    rec.add("bob", "generate_key", "Bob generates an RSA-2048 key pair.", ms=t_kb.ms)
    bob_pub = proto.public_bytes(bob_priv)
    bob_sig = bob_id.sign(bob_pub) if signatures else None

    mallory_priv = None
    if mitm:
        with Timer() as t_km:
            mallory_priv = proto.new_keypair()
        rec.add("mallory", "generate_key", "Mallory generates her own RSA key pair.", ms=t_km.ms, warn=True)

    # ---- message 1: Bob -> Alice (public key)
    rec.add("bob", "send_value",
            "Bob sends his RSA public key to Alice" + (" and signs it." if signatures else "."), bob_pub)
    got_pub = bob_pub
    if mitm:
        got_pub = proto.public_bytes(mallory_priv)
        n = rec.add("mallory", "replace",
                    "Mallory intercepts Bob's public key and substitutes her own.", got_pub, warn=True)
        rec.log_replacement(n, bob_pub, got_pub)
    if signatures:
        ok = verify(bob_id.public, got_pub, bob_sig)
        rec.add("alice", "verify",
                "Alice checks Bob's signature on the key: " + ("valid." if ok else "INVALID, the key was replaced."),
                warn=not ok)
        if not ok:
            metrics.update(first_message_bytes=len(bob_pub), second_message_bytes=0,
                           signature_bytes=SIGNATURE_BYTES,
                           bytes_transmitted=len(bob_pub) + SIGNATURE_BYTES)
            return _detected(result, rec, started, metrics, "Alice")

    # ---- message 2: Alice -> Bob (encrypted secret)
    secret = os.urandom(32)
    with Timer() as t_enc:
        ct = proto.encrypt(proto.load_public(got_pub), secret)
    rec.add("alice", "encrypt",
            "Alice invents a random 32-byte secret and encrypts it with the public key she received (RSA-OAEP).",
            ct, ms=t_enc.ms)
    ct_sig = alice_id.sign(ct) if signatures else None
    got_ct = ct
    mallory_secret = None
    if mitm:
        mallory_secret = proto.decrypt(mallory_priv, ct)
        got_ct = proto.encrypt(bob_priv.public_key(), mallory_secret)
        n = rec.add("mallory", "replace",
                    "Mallory decrypts the secret with her own private key, then re-encrypts it under Bob's real key.",
                    got_ct, warn=True)
        rec.log_replacement(n, ct, got_ct)
    if signatures:
        ok = verify(alice_id.public, got_ct, ct_sig)
        rec.add("bob", "verify",
                "Bob checks Alice's signature on the ciphertext: " + ("valid." if ok else "INVALID."), warn=not ok)
        if not ok:
            metrics.update(first_message_bytes=len(bob_pub), second_message_bytes=len(ct),
                           signature_bytes=SIGNATURE_BYTES * 2,
                           bytes_transmitted=len(bob_pub) + len(ct) + SIGNATURE_BYTES * 2)
            return _detected(result, rec, started, metrics, "Bob")

    metrics.update(first_message_bytes=len(bob_pub), second_message_bytes=len(ct),
                   signature_bytes=SIGNATURE_BYTES * 2 if signatures else 0)
    metrics["bytes_transmitted"] = len(bob_pub) + len(ct) + metrics["signature_bytes"]

    with Timer() as t_dec:
        secret_b = proto.decrypt(bob_priv, got_ct)
    metrics["secret_ms"] = t_dec.ms
    rec.add("bob", "derive_secret", "Bob decrypts the ciphertext with his private key to recover the secret.",
            ms=t_dec.ms)
    key_a, key_b = derive_key(secret), derive_key(secret_b)
    result["keys_match"] = key_a == key_b
    result["fingerprints"] = {"alice": fingerprint(key_a), "bob": fingerprint(key_b)}
    rec.add("system", "derive_key",
            "Both sides run HKDF-SHA256 on the secret. "
            f"Key fingerprints: Alice {fingerprint(key_a)}, Bob {fingerprint(key_b)}. "
            + ("They MATCH." if key_a == key_b else "They DIFFER."))

    nonce, ct_msg = encrypt_message(key_a, message.encode())
    rec.add("alice", "encrypt", "Alice encrypts the message with AES-256-GCM and sends it.", ct_msg)
    text = decrypt_message(key_b, nonce, ct_msg).decode()
    result["bob_read"] = text
    rec.add("bob", "decrypt", f"Bob decrypts it successfully: \"{text}\"")
    if mitm:
        key_m = derive_key(mallory_secret)
        plaintext = decrypt_message(key_m, nonce, ct_msg).decode()
        result["mallory_knows_key"] = True
        result["attack_outcome"] = "succeeded"
        result["mallory_read"] = plaintext
        result["fingerprints"]["mallory"] = fingerprint(key_m)
        rec.add("mallory", "decrypt",
                f"Mallory holds the same key as Alice and Bob (fingerprint {fingerprint(key_m)}) and reads: \"{plaintext}\"."
                " The keys match, yet the exchange is compromised.",
                warn=True)
    return _finish(result, rec, started, metrics)
