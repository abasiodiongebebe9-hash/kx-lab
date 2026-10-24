"""Unit tests for the cryptographic modules and the exchange engine (run with: python -m unittest)."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cryptography.exceptions import InvalidTag

from kx.crypto_utils import decrypt_message, derive_key, encrypt_message
from kx.dh_group import P_2048
from kx.engine import run_exchange
from kx.protocols import PROTOCOLS, validate_dh_public
from kx.signatures import Identity, verify

AGREEMENT = ["DH-2048", "ECDH-P256", "ECDH-X25519"]
ALL = AGREEMENT + ["RSA-2048"]


class TestPrimitives(unittest.TestCase):
    def test_t01_dh_secrets_match(self):
        p = PROTOCOLS["DH-2048"]
        a, b = p.new_keypair(), p.new_keypair()
        self.assertEqual(p.derive(a, p.public_bytes(b)), p.derive(b, p.public_bytes(a)))

    def test_t02_ecdh_secrets_match(self):
        for name in ("ECDH-P256", "ECDH-X25519"):
            p = PROTOCOLS[name]
            a, b = p.new_keypair(), p.new_keypair()
            self.assertEqual(p.derive(a, p.public_bytes(b)), p.derive(b, p.public_bytes(a)), name)

    def test_t03_rsa_oaep_roundtrip(self):
        p = PROTOCOLS["RSA-2048"]
        priv = p.new_keypair()
        secret = os.urandom(32)
        ct = p.encrypt(p.load_public(p.public_bytes(priv)), secret)
        self.assertEqual(p.decrypt(priv, ct), secret)
        self.assertNotEqual(ct, p.encrypt(priv.public_key(), secret), "OAEP must be randomised")

    def test_t04_aes_gcm_correct_key(self):
        key = derive_key(os.urandom(32))
        nonce, ct = encrypt_message(key, b"hello")
        self.assertEqual(decrypt_message(key, nonce, ct), b"hello")

    def test_t05_aes_gcm_wrong_key_rejected(self):
        nonce, ct = encrypt_message(derive_key(b"a" * 32), b"hello")
        with self.assertRaises(InvalidTag):
            decrypt_message(derive_key(b"b" * 32), nonce, ct)

    def test_t06_signature_detects_change(self):
        ident = Identity()
        sig = ident.sign(b"public value")
        self.assertTrue(verify(ident.public, b"public value", sig))
        self.assertFalse(verify(ident.public, b"public valuE", sig))
        self.assertFalse(verify(Identity().public, b"public value", sig))

    def test_t07_hkdf_is_deterministic_and_256_bit(self):
        self.assertEqual(derive_key(b"x" * 32), derive_key(b"x" * 32))
        self.assertEqual(len(derive_key(b"x" * 32)), 32)

    def test_t08_dh_validation_rejects_bad_values(self):
        for bad in (0, 1, P_2048 - 1, P_2048, P_2048 + 5):
            with self.assertRaises(ValueError, msg=str(bad)):
                validate_dh_public(bad)
        validate_dh_public(pow(2, 12345, P_2048))   # a genuine value is accepted

    def test_t09_x25519_rejects_low_order_point(self):
        with self.assertRaises(ValueError):
            PROTOCOLS["ECDH-X25519"].derive(PROTOCOLS["ECDH-X25519"].new_keypair(), bytes(32))

    def test_t10_p256_rejects_point_not_on_curve(self):
        bad = b"\x04" + b"\x01" * 64
        with self.assertRaises(ValueError):
            PROTOCOLS["ECDH-P256"].derive(PROTOCOLS["ECDH-P256"].new_keypair(), bad)


class TestExchangeEngine(unittest.TestCase):
    def test_t11_honest_exchange_all_protocols(self):
        for name in ALL:
            r = run_exchange(name)
            self.assertTrue(r["keys_match"], name)
            self.assertEqual(r["attack_outcome"], "none", name)
            self.assertFalse(r["mallory_knows_key"], name)
            self.assertEqual(r["bob_read"], r["message"], name)

    def test_t12_mitm_without_signatures_succeeds(self):
        for name in AGREEMENT:
            r = run_exchange(name, mitm=True)
            self.assertEqual(r["attack_outcome"], "succeeded", name)
            self.assertFalse(r["keys_match"], name)          # Alice and Bob hold different keys
            self.assertEqual(r["mallory_read"], r["message"], name)
            self.assertEqual(len(r["attack_log"]), 2, name)
        r = run_exchange("RSA-2048", mitm=True)
        self.assertEqual(r["attack_outcome"], "succeeded")
        self.assertTrue(r["keys_match"])                     # same key, but Mallory holds a copy
        self.assertEqual(r["mallory_read"], r["message"])

    def test_t13_mitm_with_signatures_is_detected(self):
        for name in ALL:
            r = run_exchange(name, mitm=True, signatures=True)
            self.assertEqual(r["attack_outcome"], "detected", name)
            self.assertIsNone(r["keys_match"], name)         # exchange stopped before keys were derived
            self.assertFalse(r["mallory_knows_key"], name)
            self.assertIsNone(r["mallory_read"], name)
            self.assertTrue(r["attack_log"][-1]["detected"], name)

    def test_t14_signatures_without_attacker_still_work(self):
        for name in ALL:
            r = run_exchange(name, signatures=True)
            self.assertTrue(r["keys_match"], name)
            self.assertEqual(r["attack_outcome"], "none", name)
            self.assertEqual(r["metrics"]["signature_bytes"], 128, name)

    def test_t15_message_sizes(self):
        expected = {"ECDH-X25519": (32, 32), "ECDH-P256": (65, 65), "DH-2048": (256, 256), "RSA-2048": (294, 256)}
        for name, (first, second) in expected.items():
            m = run_exchange(name)["metrics"]
            self.assertEqual((m["first_message_bytes"], m["second_message_bytes"]), (first, second), name)
            self.assertEqual(m["bytes_transmitted"], first + second, name)

    def test_t16_unknown_protocol_rejected(self):
        with self.assertRaises(ValueError):
            run_exchange("NOPE")


if __name__ == "__main__":
    unittest.main(verbosity=2)
