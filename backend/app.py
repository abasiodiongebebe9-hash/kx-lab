"""Key Exchange Lab: Flask application (REST API + static front end).

Run:   python app.py            (development, http://127.0.0.1:5000)
Host:  gunicorn app:app         (production-style)
"""
import os
import secrets
import sqlite3

from flask import Flask, g, jsonify, request, send_from_directory

from kx.auth import (EMAIL_RE, USERNAME_RE, RateLimiter, create_token, error, hash_password,
                     login_required, verify_password)
from kx.benchmark import benchmark_protocol, machine_description
from kx.db import Database
from kx.engine import DEFAULT_MESSAGE, run_exchange
from kx.protocols import PROTOCOLS

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
FRONTEND_DIR = os.path.join(os.path.dirname(BASE_DIR), "frontend")


def create_app(db_path=None, secret=None):
    app = Flask(__name__, static_folder=FRONTEND_DIR, static_url_path="/static-files")
    db = Database(db_path or os.environ.get("KX_DB", os.path.join(os.path.dirname(BASE_DIR), "data", "kx.db")))
    db.init()
    app.config["DB"] = db
    app.config["SECRET"] = secret or os.environ.get("KX_SECRET") or secrets.token_hex(32)
    limiter = RateLimiter()

    # ------------------------------------------------------------------ security headers
    @app.after_request
    def add_headers(resp):
        resp.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
            "connect-src 'self'; frame-ancestors 'none'")
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "no-referrer"
        return resp

    # ------------------------------------------------------------------ front end
    @app.route("/")
    def index():
        return send_from_directory(FRONTEND_DIR, "index.html")

    @app.route("/<path:name>")
    def assets(name):
        if name in ("style.css", "app.js"):
            return send_from_directory(FRONTEND_DIR, name)
        return error("Not found", 404)

    # ------------------------------------------------------------------ auth
    @app.post("/api/auth/register")
    def register():
        data = request.get_json(silent=True) or {}
        username = str(data.get("username", "")).strip()
        email = str(data.get("email", "")).strip()
        password = str(data.get("password", ""))
        if not USERNAME_RE.match(username):
            return error("Username must be 3 to 30 letters, digits or underscores", 400)
        if not EMAIL_RE.match(email) or len(email) > 120:
            return error("Please enter a valid email address", 400)
        if len(password) < 8 or len(password) > 128:
            return error("Password must be 8 to 128 characters", 400)
        role = "admin" if db.count_users() == 0 else "user"   # the first account becomes the administrator
        try:
            uid = db.create_user(username, email, hash_password(password), role)
        except sqlite3.IntegrityError:
            return error("That username or email is already registered", 409)
        return jsonify({"user_id": uid, "username": username, "role": role}), 201

    @app.post("/api/auth/login")
    def login():
        data = request.get_json(silent=True) or {}
        if not limiter.allow("login:" + (request.remote_addr or "?"), 20):
            return error("Too many attempts, please wait a minute", 429)
        user = db.get_user_by_username(str(data.get("username", "")))
        if not user or not verify_password(str(data.get("password", "")), user["password_hash"]):
            return error("Incorrect username or password", 401)
        token = create_token(user["user_id"], user["role"], app.config["SECRET"])
        return jsonify({"token": token, "user": {"username": user["username"], "role": user["role"]}})

    @app.get("/api/protocols")
    @login_required()
    def protocols():
        return jsonify([{"name": p.name, "description": p.description} for p in PROTOCOLS.values()])

    # ------------------------------------------------------------------ exchanges
    @app.post("/api/exchanges")
    @login_required()
    def start_exchange():
        data = request.get_json(silent=True) or {}
        protocol = data.get("protocol")
        mitm, signatures = data.get("mitm", False), data.get("signatures", False)
        message = data.get("message") or DEFAULT_MESSAGE
        if protocol not in PROTOCOLS:
            return error("Unknown protocol", 400)
        if not isinstance(mitm, bool) or not isinstance(signatures, bool):
            return error("'mitm' and 'signatures' must be true or false", 400)
        if not isinstance(message, str) or len(message) > 200:
            return error("Message must be text of at most 200 characters", 400)
        if not limiter.allow("exchange:" + g.user["user_id"], 30):
            return error("Too many exchanges, please wait a minute", 429)
        result = run_exchange(protocol, mitm=mitm, signatures=signatures, message=message)
        result["session_id"] = db.save_exchange(g.user["user_id"], result)
        return jsonify(result), 201

    @app.get("/api/exchanges")
    @login_required()
    def list_exchanges():
        return jsonify({"stats": db.user_stats(g.user["user_id"]),
                        "sessions": db.list_sessions(g.user["user_id"])})

    @app.get("/api/exchanges/<session_id>")
    @login_required()
    def get_exchange(session_id):
        uid = None if g.user["role"] == "admin" else g.user["user_id"]
        session = db.get_session(session_id, uid)
        return jsonify(session) if session else error("Session not found", 404)

    # ------------------------------------------------------------------ benchmarks
    @app.get("/api/benchmarks/summary")
    @login_required()
    def benchmark_summary():
        return jsonify(db.session_summary(g.user["user_id"]))

    @app.post("/api/benchmarks/run")
    @login_required()
    def benchmark_run():
        data = request.get_json(silent=True) or {}
        runs = data.get("runs", 30)
        if not isinstance(runs, int) or isinstance(runs, bool) or not (1 <= runs <= 200):
            return error("'runs' must be a whole number from 1 to 200", 400)
        if not limiter.allow("bench:" + g.user["user_id"], 3):
            return error("Please wait a minute before running another benchmark", 429)
        machine = machine_description()
        results = []
        for name in PROTOCOLS:
            r = benchmark_protocol(name, runs)
            db.save_benchmark_run(g.user["user_id"], r, machine)
            results.append(r)
        return jsonify({"machine": machine, "results": results}), 201

    @app.get("/api/benchmarks/latest")
    @login_required()
    def benchmark_latest():
        return jsonify(db.latest_benchmark_runs())

    # ------------------------------------------------------------------ admin
    @app.get("/api/admin/users")
    @login_required(role="admin")
    def admin_users():
        return jsonify(db.list_users())

    @app.get("/api/admin/sessions")
    @login_required(role="admin")
    def admin_sessions():
        return jsonify(db.list_sessions(None, 200))

    return app


app = create_app()

if __name__ == "__main__":
    app.run(host=os.environ.get("HOST", "127.0.0.1"), port=int(os.environ.get("PORT", "5000")), debug=False)
