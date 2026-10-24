"""AuthHandler: salted scrypt password hashing and short-lived signed tokens (JWT, HS256)."""
import datetime
import functools
import hashlib
import hmac
import os
import re
import time
from collections import defaultdict, deque

import jwt
from flask import current_app, g, jsonify, request

TOKEN_MINUTES = 30
USERNAME_RE = re.compile(r"^[A-Za-z0-9_]{3,30}$")
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def hash_password(password: str) -> str:
    salt = os.urandom(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, n=2 ** 14, r=8, p=1, dklen=32)
    return f"scrypt${salt.hex()}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        scheme, salt_hex, digest_hex = stored.split("$")
        if scheme != "scrypt":
            return False
        digest = hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt_hex), n=2 ** 14, r=8, p=1, dklen=32)
        return hmac.compare_digest(digest.hex(), digest_hex)
    except ValueError:
        return False


def create_token(user_id: str, role: str, secret: str) -> str:
    payload = {
        "sub": user_id,
        "role": role,
        "exp": datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=TOKEN_MINUTES),
    }
    return jwt.encode(payload, secret, algorithm="HS256")


def error(message, status):
    return jsonify({"error": message}), status


def login_required(role=None):
    """Decorator: requires a valid bearer token, and optionally a specific role."""
    def decorator(fn):
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            header = request.headers.get("Authorization", "")
            if not header.startswith("Bearer "):
                return error("Authentication required", 401)
            try:
                claims = jwt.decode(header[7:], current_app.config["SECRET"], algorithms=["HS256"])
            except jwt.PyJWTError:
                return error("Invalid or expired token", 401)
            user = current_app.config["DB"].get_user(claims["sub"])
            if not user:
                return error("Unknown user", 401)
            if role and user["role"] != role:
                return error("Forbidden", 403)
            g.user = user
            return fn(*args, **kwargs)
        return wrapper
    return decorator


class RateLimiter:
    """Very small in-memory limiter: at most `limit` calls per `window` seconds for each key."""

    def __init__(self):
        self._hits = defaultdict(deque)

    def allow(self, key, limit, window=60):
        now = time.monotonic()
        q = self._hits[key]
        while q and now - q[0] > window:
            q.popleft()
        if len(q) >= limit:
            return False
        q.append(now)
        return True
