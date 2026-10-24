"""PerformanceBenchmarker: repeated timing of key generation and shared-secret computation.

keygen_ms  = time to generate ONE key pair (DH family: Alice's pair; RSA: Bob's pair)
secret_ms  = time for Bob to obtain the shared secret (DH family: derive; RSA: decrypt)
Sizes are the bytes of the serialised values actually sent in one exchange. The median of many
runs is reported because it is less sensitive to occasional slow runs than the mean.
"""
import os
import platform
import statistics

from .crypto_utils import Timer
from .protocols import PROTOCOLS
from .signatures import SIGNATURE_BYTES

WARMUP = 3


def machine_description() -> str:
    return f"{platform.system()} {platform.machine()}, Python {platform.python_version()}"


def benchmark_protocol(name: str, runs: int = 100) -> dict:
    proto = PROTOCOLS[name]
    keygen, secret = [], []
    if proto.kind == "agreement":
        peer = proto.new_keypair()
        peer_pub = proto.public_bytes(peer)
        for i in range(runs + WARMUP):
            with Timer() as tk:
                mine = proto.new_keypair()
            with Timer() as ts:
                proto.derive(mine, peer_pub)
            if i >= WARMUP:
                keygen.append(tk.ms)
                secret.append(ts.ms)
        first = len(proto.public_bytes(proto.new_keypair()))
        second = first
    else:
        bob = None
        ct = None
        for i in range(runs + WARMUP):
            with Timer() as tk:
                bob = proto.new_keypair()
            ct = proto.encrypt(bob.public_key(), os.urandom(32))
            with Timer() as ts:
                proto.decrypt(bob, ct)
            if i >= WARMUP:
                keygen.append(tk.ms)
                secret.append(ts.ms)
        first = len(proto.public_bytes(bob))
        second = len(ct)
    return {
        "protocol": name,
        "runs": runs,
        "keygen_ms_median": round(statistics.median(keygen), 3),
        "secret_ms_median": round(statistics.median(secret), 3),
        "first_message_bytes": first,
        "second_message_bytes": second,
        "total_bytes": first + second,
        "total_bytes_with_signatures": first + second + 2 * SIGNATURE_BYTES,
    }


def benchmark_all(runs: int = 100) -> list:
    return [benchmark_protocol(name, runs) for name in PROTOCOLS]


if __name__ == "__main__":
    import argparse
    import json

    ap = argparse.ArgumentParser(description="Benchmark the key-exchange protocols.")
    ap.add_argument("--runs", type=int, default=100)
    ap.add_argument("--json", action="store_true", help="print JSON instead of a table")
    args = ap.parse_args()
    results = benchmark_all(args.runs)
    if args.json:
        print(json.dumps({"machine": machine_description(), "results": results}, indent=2))
    else:
        print(f"Machine: {machine_description()}   runs per protocol: {args.runs}")
        print(f"{'Protocol':<13}{'keygen ms':>11}{'secret ms':>11}{'msg 1 B':>9}{'msg 2 B':>9}{'total B':>9}{'+sigs B':>9}")
        for r in results:
            print(f"{r['protocol']:<13}{r['keygen_ms_median']:>11}{r['secret_ms_median']:>11}"
                  f"{r['first_message_bytes']:>9}{r['second_message_bytes']:>9}{r['total_bytes']:>9}"
                  f"{r['total_bytes_with_signatures']:>9}")
