"""Integration tests: the REST API, authentication, authorisation and the database (run with: python -m unittest)."""
import os
import sys
import tempfile
import unittest
import warnings

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import create_app

warnings.simplefilter("ignore", ResourceWarning)   # Flask test client leaves static files open; harmless


class ApiTestCase(unittest.TestCase):
    def setUp(self):
        fd, self.db_path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        self.app = create_app(self.db_path, "test-secret-" + "x" * 32)
        self.client = self.app.test_client()

    def tearDown(self):
        os.remove(self.db_path)

    def register(self, name, password="password123"):
        return self.client.post("/api/auth/register",
                                json={"username": name, "email": f"{name}@example.com", "password": password})

    def login(self, name, password="password123"):
        r = self.client.post("/api/auth/login", json={"username": name, "password": password})
        return r

    def headers(self, name):
        self.register(name)
        token = self.login(name).get_json()["token"]
        return {"Authorization": "Bearer " + token}


class TestAuth(ApiTestCase):
    def test_t17_register_and_login(self):
        r = self.register("alice1")
        self.assertEqual(r.status_code, 201)
        self.assertEqual(r.get_json()["role"], "admin")          # first account is the administrator
        self.assertEqual(self.register("bob22").get_json()["role"], "user")
        self.assertEqual(self.login("alice1").status_code, 200)

    def test_t18_wrong_password_and_unknown_user(self):
        self.register("alice1")
        self.assertEqual(self.login("alice1", "wrongpassword").status_code, 401)
        self.assertEqual(self.login("nobody").status_code, 401)

    def test_t19_duplicate_and_invalid_registration(self):
        self.register("alice1")
        self.assertEqual(self.register("alice1").status_code, 409)
        self.assertEqual(self.register("ab").status_code, 400)                     # username too short
        self.assertEqual(self.register("validname", "short").status_code, 400)     # password too short
        bad = self.client.post("/api/auth/register", json={"username": "okname", "email": "nope", "password": "password123"})
        self.assertEqual(bad.status_code, 400)

    def test_t20_password_is_hashed_in_database(self):
        self.register("alice1", "password123")
        row = self.app.config["DB"].get_user_by_username("alice1")
        self.assertTrue(row["password_hash"].startswith("scrypt$"))
        self.assertNotIn("password123", row["password_hash"])

    def test_t21_protected_routes_need_a_valid_token(self):
        self.assertEqual(self.client.get("/api/exchanges").status_code, 401)
        self.assertEqual(self.client.get("/api/exchanges", headers={"Authorization": "Bearer garbage"}).status_code, 401)
        self.assertEqual(self.client.post("/api/exchanges", json={"protocol": "DH-2048"}).status_code, 401)

    def test_t22_sql_injection_attempt_is_harmless(self):
        self.register("alice1")
        r = self.login("alice1' OR '1'='1", "x")
        self.assertEqual(r.status_code, 401)
        self.assertEqual(self.app.config["DB"].count_users(), 1)


class TestExchangesApi(ApiTestCase):
    def test_t23_run_exchange_and_history(self):
        h = self.headers("alice1")
        r = self.client.post("/api/exchanges", json={"protocol": "ECDH-X25519", "mitm": True, "signatures": False}, headers=h)
        self.assertEqual(r.status_code, 201)
        body = r.get_json()
        self.assertEqual(body["attack_outcome"], "succeeded")
        hist = self.client.get("/api/exchanges", headers=h).get_json()
        self.assertEqual(hist["stats"], {"total": 1, "attacks_succeeded": 1, "attacks_detected": 0})
        detail = self.client.get("/api/exchanges/" + body["session_id"], headers=h).get_json()
        self.assertEqual(len(detail["attack_log"]), 2)
        self.assertIsNotNone(detail["benchmark"])

    def test_t24_detected_attack_is_recorded(self):
        h = self.headers("alice1")
        self.client.post("/api/exchanges", json={"protocol": "RSA-2048", "mitm": True, "signatures": True}, headers=h)
        stats = self.client.get("/api/exchanges", headers=h).get_json()["stats"]
        self.assertEqual(stats["attacks_detected"], 1)

    def test_t25_input_validation(self):
        h = self.headers("alice1")
        post = lambda body: self.client.post("/api/exchanges", json=body, headers=h).status_code
        self.assertEqual(post({"protocol": "MD5"}), 400)
        self.assertEqual(post({"protocol": "DH-2048", "mitm": "yes"}), 400)
        self.assertEqual(post({"protocol": "DH-2048", "message": "x" * 500}), 400)

    def test_t26_users_cannot_read_each_others_sessions(self):
        h1 = self.headers("alice1")
        h2 = self.headers("bob22")
        sid = self.client.post("/api/exchanges", json={"protocol": "ECDH-P256"}, headers=h1).get_json()["session_id"]
        self.assertEqual(self.client.get("/api/exchanges/" + sid, headers=h2).status_code, 404)
        self.assertEqual(self.client.get("/api/exchanges/" + sid, headers=h1).status_code, 200)

    def test_t27_admin_routes_require_admin_role(self):
        h_admin = self.headers("alice1")        # first account
        h_user = self.headers("bob22")
        self.assertEqual(self.client.get("/api/admin/users", headers=h_user).status_code, 403)
        self.assertEqual(self.client.get("/api/admin/sessions", headers=h_user).status_code, 403)
        users = self.client.get("/api/admin/users", headers=h_admin)
        self.assertEqual(users.status_code, 200)
        self.assertNotIn("password_hash", users.get_data(as_text=True))

    def test_t28_benchmark_run_and_latest(self):
        h = self.headers("alice1")
        r = self.client.post("/api/benchmarks/run", json={"runs": 2}, headers=h)
        self.assertEqual(r.status_code, 201)
        latest = self.client.get("/api/benchmarks/latest", headers=h).get_json()
        self.assertEqual({row["protocol"] for row in latest}, {"DH-2048", "ECDH-P256", "ECDH-X25519", "RSA-2048"})
        self.assertEqual(self.client.post("/api/benchmarks/run", json={"runs": 9999}, headers=h).status_code, 400)

    def test_t29_security_headers_and_static_files(self):
        def fetch(path):
            r = self.client.get(path)
            r.close()
            return r
        r = fetch("/")
        self.assertEqual(r.status_code, 200)
        self.assertIn("default-src 'self'", r.headers["Content-Security-Policy"])
        self.assertEqual(r.headers["X-Content-Type-Options"], "nosniff")
        self.assertEqual(fetch("/style.css").status_code, 200)
        self.assertEqual(fetch("/app.js").status_code, 200)
        self.assertEqual(fetch("/schema.sql").status_code, 404)

    def test_t30_no_private_material_stored(self):
        h = self.headers("alice1")
        sid = self.client.post("/api/exchanges", json={"protocol": "DH-2048", "mitm": True}, headers=h).get_json()["session_id"]
        import sqlite3
        con = sqlite3.connect(self.db_path)
        dump = "\n".join(str(row) for t in ("exchange_sessions", "benchmarks", "attack_logs")
                         for row in con.execute(f"SELECT * FROM {t}"))
        con.close()
        # no PEM/DER private key blocks and no raw key material markers may be stored
        self.assertNotIn("-----BEGIN", dump)
        self.assertNotIn("PRIVATE KEY-----", dump.upper())


if __name__ == "__main__":
    unittest.main(verbosity=2)
