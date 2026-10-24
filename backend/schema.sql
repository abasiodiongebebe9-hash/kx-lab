-- Key Exchange Lab: database schema (SQLite). See Chapter 4 for the specification of each column.
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS users (
    user_id        TEXT PRIMARY KEY,
    username       TEXT NOT NULL UNIQUE,
    email          TEXT NOT NULL UNIQUE,
    password_hash  TEXT NOT NULL,
    role           TEXT NOT NULL DEFAULT 'user' CHECK (role IN ('user', 'admin')),
    created_at     TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS exchange_sessions (
    session_id         TEXT PRIMARY KEY,
    user_id            TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    protocol           TEXT NOT NULL CHECK (protocol IN ('DH-2048', 'ECDH-P256', 'ECDH-X25519', 'RSA-2048')),
    mitm_enabled       INTEGER NOT NULL CHECK (mitm_enabled IN (0, 1)),
    auth_enabled       INTEGER NOT NULL CHECK (auth_enabled IN (0, 1)),
    keys_match         INTEGER CHECK (keys_match IN (0, 1)),
    mallory_knows_key  INTEGER NOT NULL DEFAULT 0 CHECK (mallory_knows_key IN (0, 1)),
    attack_outcome     TEXT NOT NULL DEFAULT 'none' CHECK (attack_outcome IN ('none', 'succeeded', 'detected')),
    message            TEXT,
    steps_json         TEXT NOT NULL,
    created_at         TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS benchmarks (
    benchmark_id       TEXT PRIMARY KEY,
    session_id         TEXT NOT NULL UNIQUE REFERENCES exchange_sessions(session_id) ON DELETE CASCADE,
    keygen_ms          REAL,
    secret_ms          REAL,
    total_ms           REAL,
    public_bytes       INTEGER,
    bytes_transmitted  INTEGER
);

CREATE TABLE IF NOT EXISTS attack_logs (
    log_id             TEXT PRIMARY KEY,
    session_id         TEXT NOT NULL REFERENCES exchange_sessions(session_id) ON DELETE CASCADE,
    step_no            INTEGER NOT NULL,
    original_value     TEXT NOT NULL,
    substituted_value  TEXT NOT NULL,
    detected           INTEGER NOT NULL CHECK (detected IN (0, 1)),
    logged_at          TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS benchmark_runs (
    run_id                 TEXT PRIMARY KEY,
    user_id                TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    protocol               TEXT NOT NULL,
    runs                   INTEGER NOT NULL,
    keygen_ms_median       REAL NOT NULL,
    secret_ms_median       REAL NOT NULL,
    first_message_bytes    INTEGER NOT NULL,
    second_message_bytes   INTEGER NOT NULL,
    total_bytes            INTEGER NOT NULL,
    machine                TEXT,
    created_at             TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_sessions_user    ON exchange_sessions(user_id, created_at);
CREATE INDEX IF NOT EXISTS idx_attacklogs_sess  ON attack_logs(session_id);
CREATE INDEX IF NOT EXISTS idx_benchruns_proto  ON benchmark_runs(protocol, created_at);
