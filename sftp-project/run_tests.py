"""
run_tests.py — Test harness for the Secure File Transfer Protocol

Tests performed:
  1. Small file   (1 KiB)  — baseline handshake + transfer
  2. Medium file  (1 MiB)  — throughput measurement
  3. Large file   (10 MiB) — throughput measurement
  4. Tamper test  — flip a byte in a chunk ciphertext → expect abort
  5. Drop test    — skip sending one chunk → expect sequence-mismatch abort
  6. Reorder test — swap chunk 0 and 1 → expect sequence-mismatch abort

All results are printed as a human-readable table.
"""

import os
import sys
import time
import threading
import tempfile
import random
import struct

# Ensure imports resolve from the same directory
sys.path.insert(0, os.path.dirname(__file__))

from server import SecureFileServer
from client import SecureFileClient


def make_test_file(size_bytes: int, suffix=".bin") -> str:
    """Create a temp file filled with pseudo-random bytes; return its path."""
    fd, path = tempfile.mkstemp(suffix=suffix, dir="test_files")
    # Use a seeded RNG for reproducibility
    rng = random.Random(42)
    with os.fdopen(fd, "wb") as f:
        remaining = size_bytes
        while remaining > 0:
            chunk = min(remaining, 65536)
            f.write(bytes([rng.randint(0, 255) for _ in range(chunk)]))
            remaining -= chunk
    return path


def run_scenario(label: str, file_path: str, **client_kwargs):
    """
    Spin up a server thread, then run the client in the main thread.
    Returns result dict from client.
    """
    PORT = 19876
    srv  = SecureFileServer(port=PORT, output_dir="received", log_dir="logs")

    server_result = {}

    def server_thread():
        r = srv.serve_one()
        server_result.update(r)

    t = threading.Thread(target=server_thread, daemon=True)
    t.start()
    time.sleep(0.15)   # give server time to bind

    client = SecureFileClient(port=PORT, log_dir="logs")
    client_result = client.send_file(file_path, **client_kwargs)

    t.join(timeout=5)
    return client_result, server_result


def fmt_result(label, client_res, server_res):
    if client_res.get("status") == "ok" and server_res.get("status") == "ok":
        mb        = client_res["bytes"] / 1024 / 1024
        elapsed   = client_res["elapsed_s"]
        tput      = client_res["throughput_mibps"]
        print(f"  {'✓':2} {label:<35} {mb:7.3f} MiB  {elapsed:6.3f}s  {tput:7.2f} MiB/s")
    elif client_res.get("status") == "error":
        reason = client_res.get("reason", "?")[:60]
        print(f"  {'✗':2} {label:<35} ERROR (client): {reason}")
    elif server_res.get("status") == "error":
        reason = server_res.get("reason", "?")[:60]
        print(f"  {'✗':2} {label:<35} ERROR (server): {reason}")
    else:
        print(f"  {'?':2} {label:<35} Unknown result")


def main():
    os.makedirs("test_files", exist_ok=True)
    os.makedirs("received",   exist_ok=True)
    os.makedirs("logs",       exist_ok=True)

    print()
    print("=" * 70)
    print("  SECURE FILE TRANSFER PROTOCOL — TEST SUITE")
    print("=" * 70)

    results = []

    # ── 1. Correct transfers of different sizes ────────────────────────────
    print()
    print("► Normal transfers (expect ✓)")
    print(f"  {'':2} {'Scenario':<35} {'Size':>9}  {'Time':>7}  {'Throughput':>10}")
    print("  " + "─" * 66)

    for label, size in [("1 KiB file",  1 * 1024),
                         ("64 KiB file", 64 * 1024),
                         ("1 MiB file",  1 * 1024 * 1024),
                         ("10 MiB file", 10 * 1024 * 1024)]:
        path = make_test_file(size)
        c, s = run_scenario(label, path)
        fmt_result(label, c, s)
        results.append((label, c, s))
        os.unlink(path)

    # ── 2. Security / attack tests (all should fail on server side) ────────
    print()
    print("► Attack tests (expect ✗ with informative error)")
    print("  " + "─" * 66)

    # Tamper: flip bit in chunk 0's ciphertext
    path = make_test_file(256 * 1024)   # 256 KiB — needs at least a few chunks
    c, s = run_scenario("Tamper: flip byte in chunk 0",
                         path, tamper_chunk=0)
    ok_for_attack = (c.get("status") == "error" or s.get("status") == "error")
    marker = "✓ (detected)" if ok_for_attack else "✗ NOT DETECTED"
    reason = (c.get("reason") or s.get("reason") or "")[:55]
    print(f"  {marker:15} {'Tamper: flip byte in chunk 0':<35}  {reason}")
    results.append(("Tamper chunk 0", c, s))

    # Drop: skip chunk 2 entirely (gap in sequence)
    c, s = run_scenario("Drop: skip chunk 2",
                         path, drop_chunk=2)
    ok_for_attack = (c.get("status") == "error" or s.get("status") == "error")
    marker = "✓ (detected)" if ok_for_attack else "✗ NOT DETECTED"
    reason = (c.get("reason") or s.get("reason") or "")[:55]
    print(f"  {marker:15} {'Drop: skip chunk 2':<35}  {reason}")
    results.append(("Drop chunk 2", c, s))

    # Reorder: swap chunk 0 and chunk 1
    c, s = run_scenario("Reorder: swap chunks 0↔1",
                         path, reorder_chunks=True)
    ok_for_attack = (c.get("status") == "error" or s.get("status") == "error")
    marker = "✓ (detected)" if ok_for_attack else "✗ NOT DETECTED"
    reason = (c.get("reason") or s.get("reason") or "")[:55]
    print(f"  {marker:15} {'Reorder: swap chunks 0↔1':<35}  {reason}")
    results.append(("Reorder chunks", c, s))

    os.unlink(path)

    # ── Summary ──────────────────────────────────────────────────────────
    print()
    print("=" * 70)
    print("  Transcript logs written to ./logs/")
    print("  Received files written to ./received/")
    print("=" * 70)
    print()


if __name__ == "__main__":
    main()
