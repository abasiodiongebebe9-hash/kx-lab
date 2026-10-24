"""DatabaseService: all SQL lives here. Every query is parameterised (no string formatting of user input)."""
import json
import os
import sqlite3
import uuid
from contextlib import contextmanager

SCHEMA_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "schema.sql")


def new_id() -> str:
    return str(uuid.uuid4())


class Database:
    def __init__(self, path: str):
        self.path = path
        folder = os.path.dirname(os.path.abspath(path))
        os.makedirs(folder, exist_ok=True)

    @contextmanager
    def connect(self):
        conn = sqlite3.connect(self.path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def init(self):
        with open(SCHEMA_PATH, encoding="utf-8") as fh:
            script = fh.read()
        with self.connect() as c:
            c.executescript(script)

    # ---- users
    def count_users(self) -> int:
        with self.connect() as c:
            return c.execute("SELECT COUNT(*) FROM users").fetchone()[0]

    def create_user(self, username, email, password_hash, role="user") -> str:
        uid = new_id()
        with self.connect() as c:
            c.execute("INSERT INTO users (user_id, username, email, password_hash, role) VALUES (?,?,?,?,?)",
                      (uid, username, email, password_hash, role))
        return uid

    def get_user_by_username(self, username):
        with self.connect() as c:
            return c.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()

    def get_user(self, user_id):
        with self.connect() as c:
            return c.execute("SELECT * FROM users WHERE user_id = ?", (user_id,)).fetchone()

    def list_users(self):
        with self.connect() as c:
            rows = c.execute("""SELECT u.user_id, u.username, u.email, u.role, u.created_at,
                                       (SELECT COUNT(*) FROM exchange_sessions s WHERE s.user_id = u.user_id) AS sessions
                                FROM users u ORDER BY u.created_at""").fetchall()
        return [dict(r) for r in rows]

    # ---- sessions, benchmarks, attack logs
    def save_exchange(self, user_id, result) -> str:
        sid = new_id()
        m = result["metrics"]
        with self.connect() as c:
            c.execute("""INSERT INTO exchange_sessions
                (session_id, user_id, protocol, mitm_enabled, auth_enabled, keys_match, mallory_knows_key,
                 attack_outcome, message, steps_json) VALUES (?,?,?,?,?,?,?,?,?,?)""",
                      (sid, user_id, result["protocol"], int(result["mitm"]), int(result["signatures"]),
                       None if result["keys_match"] is None else int(result["keys_match"]),
                       int(result["mallory_knows_key"]), result["attack_outcome"], result["message"],
                       json.dumps({"steps": result["steps"], "fingerprints": result["fingerprints"],
                                   "bob_read": result["bob_read"], "mallory_read": result["mallory_read"]})))
            c.execute("""INSERT INTO benchmarks
                (benchmark_id, session_id, keygen_ms, secret_ms, total_ms, public_bytes, bytes_transmitted)
                VALUES (?,?,?,?,?,?,?)""",
                      (new_id(), sid, m.get("keygen_ms"), m.get("secret_ms"), m.get("total_ms"),
                       m.get("first_message_bytes"), m.get("bytes_transmitted")))
            for entry in result["attack_log"]:
                c.execute("""INSERT INTO attack_logs
                    (log_id, session_id, step_no, original_value, substituted_value, detected)
                    VALUES (?,?,?,?,?,?)""",
                          (new_id(), sid, entry["step_no"], entry["original_value"],
                           entry["substituted_value"], int(entry["detected"])))
        return sid

    def list_sessions(self, user_id=None, limit=50):
        sql = """SELECT s.session_id, s.protocol, s.mitm_enabled, s.auth_enabled, s.keys_match,
                        s.mallory_knows_key, s.attack_outcome, s.created_at, u.username,
                        b.keygen_ms, b.secret_ms, b.total_ms, b.bytes_transmitted
                 FROM exchange_sessions s
                 JOIN users u ON u.user_id = s.user_id
                 LEFT JOIN benchmarks b ON b.session_id = s.session_id"""
        args = []
        if user_id:
            sql += " WHERE s.user_id = ?"
            args.append(user_id)
        sql += " ORDER BY s.created_at DESC, s.rowid DESC LIMIT ?"
        args.append(limit)
        with self.connect() as c:
            return [dict(r) for r in c.execute(sql, args).fetchall()]

    def get_session(self, session_id, user_id=None):
        sql = "SELECT * FROM exchange_sessions WHERE session_id = ?"
        args = [session_id]
        if user_id:
            sql += " AND user_id = ?"
            args.append(user_id)
        with self.connect() as c:
            row = c.execute(sql, args).fetchone()
            if not row:
                return None
            bench = c.execute("SELECT * FROM benchmarks WHERE session_id = ?", (session_id,)).fetchone()
            logs = c.execute("SELECT * FROM attack_logs WHERE session_id = ? ORDER BY step_no",
                             (session_id,)).fetchall()
        out = dict(row)
        out.update(json.loads(out.pop("steps_json")))
        out["benchmark"] = dict(bench) if bench else None
        out["attack_log"] = [dict(r) for r in logs]
        return out

    def user_stats(self, user_id):
        with self.connect() as c:
            row = c.execute("""SELECT COUNT(*) AS total,
                       SUM(attack_outcome = 'succeeded') AS attacks_succeeded,
                       SUM(attack_outcome = 'detected')  AS attacks_detected
                FROM exchange_sessions WHERE user_id = ?""", (user_id,)).fetchone()
        return {k: (row[k] or 0) for k in ("total", "attacks_succeeded", "attacks_detected")}

    def session_summary(self, user_id):
        with self.connect() as c:
            rows = c.execute("""SELECT s.protocol, COUNT(*) AS runs,
                       ROUND(AVG(b.keygen_ms), 3) AS avg_keygen_ms,
                       ROUND(AVG(b.secret_ms), 3) AS avg_secret_ms,
                       ROUND(AVG(b.total_ms), 3) AS avg_total_ms
                FROM exchange_sessions s JOIN benchmarks b ON b.session_id = s.session_id
                WHERE s.user_id = ? GROUP BY s.protocol ORDER BY s.protocol""", (user_id,)).fetchall()
        return [dict(r) for r in rows]

    # ---- benchmark runs
    def save_benchmark_run(self, user_id, result, machine):
        with self.connect() as c:
            c.execute("""INSERT INTO benchmark_runs (run_id, user_id, protocol, runs, keygen_ms_median,
                    secret_ms_median, first_message_bytes, second_message_bytes, total_bytes, machine)
                    VALUES (?,?,?,?,?,?,?,?,?,?)""",
                      (new_id(), user_id, result["protocol"], result["runs"], result["keygen_ms_median"],
                       result["secret_ms_median"], result["first_message_bytes"],
                       result["second_message_bytes"], result["total_bytes"], machine))

    def latest_benchmark_runs(self):
        with self.connect() as c:
            rows = c.execute("""SELECT r.* FROM benchmark_runs r
                WHERE r.rowid = (SELECT r2.rowid FROM benchmark_runs r2 WHERE r2.protocol = r.protocol
                                 ORDER BY r2.created_at DESC, r2.rowid DESC LIMIT 1)
                ORDER BY r.protocol""").fetchall()
        return [dict(r) for r in rows]
