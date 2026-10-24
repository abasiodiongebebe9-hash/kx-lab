# Key Exchange Lab

An interactive web application that compares **finite-field Diffie-Hellman (DH-2048)**, **ECDH (P-256 and X25519)** and
**RSA-2048 key transport**, and lets you switch on a **Man-in-the-Middle attacker (Mallory)** and a
**signature-based defence** to see an unauthenticated exchange fail and an authenticated one survive.
Final-year project (B.Sc.). Educational use only: it is not security audited and must not protect real data.

## Features
- Run DH, ECDH (P-256, X25519) and RSA key exchange between Alice and Bob, step by step in a live timeline
- Toggle Mallory (MITM) and Ed25519 signatures; see the verdict (attack succeeded / detected)
- AES-256-GCM sample message encrypted with a key derived by HKDF-SHA256
- Benchmarks: key generation time, shared-secret time, message sizes (stored in the database)
- Accounts (register / login), personal session history with replay, admin page
- SQLite database (schema in `backend/schema.sql`)

## Requirements
Python 3.10 or newer. Nothing else to install except the packages in `requirements.txt` (no database server needed).

## Quick start
```bash
git clone <your-repository-url> kx-lab
cd kx-lab
python -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate
pip install -r requirements.txt
cd backend
python app.py
```
Open http://127.0.0.1:5000 . Register an account: **the first account created becomes the administrator**.

## Run the tests
```bash
cd backend
python -m unittest discover -s tests -v      # 30 tests: unit + integration
```

## Run the benchmark from the command line
```bash
cd backend
python -m kx.benchmark --runs 100            # add --json for JSON output
```
The same benchmark is available in the browser on the Dashboard page.

## Configuration (environment variables)
| Variable    | Meaning                                   | Default                     |
|-------------|-------------------------------------------|-----------------------------|
| KX_SECRET   | Secret used to sign login tokens          | random at start-up          |
| KX_DB       | Path of the SQLite database file          | `data/kx.db`                |
| HOST / PORT | Address and port for `python app.py`      | `127.0.0.1` / `5000`        |

Set `KX_SECRET` to a long random value when hosting, otherwise everyone is logged out whenever the server restarts.

## Hosting (optional)
Any Python host works (Render, Railway, PythonAnywhere, a VPS). Start command: `gunicorn --chdir backend app:app`
(a `Procfile` is included). Set `KX_SECRET`, and keep `KX_DB` on a persistent disk.

## Project structure
```
backend/app.py              Flask application and REST API
backend/schema.sql          database schema
backend/kx/protocols.py     DH, ECDH (P-256, X25519), RSA transport modules
backend/kx/engine.py        exchange engine and Mallory (MITM) simulator
backend/kx/signatures.py    Ed25519 signature authenticator
backend/kx/crypto_utils.py  HKDF-SHA256 and AES-256-GCM
backend/kx/benchmark.py     performance benchmarker
backend/kx/db.py            database service (parameterised SQL only)
backend/kx/auth.py          password hashing (scrypt), tokens, rate limiter
backend/tests/              unit and integration tests
frontend/                   index.html, style.css, app.js (no libraries)
docs/                       screenshots, test output, benchmark output, video script
```

## REST API
| Method | Endpoint                | Purpose                                              | Access |
|--------|-------------------------|------------------------------------------------------|--------|
| POST   | /api/auth/register      | create an account                                    | public |
| POST   | /api/auth/login         | log in, returns a token                              | public |
| GET    | /api/protocols          | list the protocols                                   | user   |
| POST   | /api/exchanges          | run an exchange (protocol, mitm, signatures, message)| user   |
| GET    | /api/exchanges          | own history and statistics                           | user   |
| GET    | /api/exchanges/<id>     | one session with steps and attack log                | user   |
| POST   | /api/benchmarks/run     | run and store a benchmark (1 to 200 runs)            | user   |
| GET    | /api/benchmarks/latest  | latest stored benchmark per protocol                 | user   |
| GET    | /api/benchmarks/summary | average timings of your own sessions                 | user   |
| GET    | /api/admin/users        | all users                                            | admin  |
| GET    | /api/admin/sessions     | all sessions                                         | admin  |

## Upload to GitHub
```bash
git init
git add .
git commit -m "Key Exchange Lab: final year project"
git branch -M main
git remote add origin https://github.com/<your-username>/kx-lab.git
git push -u origin main
```
