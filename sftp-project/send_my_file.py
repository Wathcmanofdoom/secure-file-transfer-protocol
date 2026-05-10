"""
send_my_file.py — Easy way to send any file securely.
Just run: python send_my_file.py
"""

import os
import sys
import time
import threading

sys.path.insert(0, os.path.dirname(__file__))

from server import SecureFileServer
from client import SecureFileClient

os.makedirs("received", exist_ok=True)
os.makedirs("logs", exist_ok=True)


def send_one(file_path, port=19876):
    """Spin up server + client and send a single file. Returns result dict."""
    srv = SecureFileServer(port=port, output_dir="received", log_dir="logs")
    server_result = {}

    def run_server():
        r = srv.serve_one()
        server_result.update(r)

    t = threading.Thread(target=run_server, daemon=True)
    t.start()
    time.sleep(0.2)

    client = SecureFileClient(port=port, log_dir="logs")
    result = client.send_file(file_path)
    t.join(timeout=5)
    return result, server_result


def get_file_path(label=""):
    while True:
        prompt = f"  {label}Drag file here (or type path): " if label else "  Drag file here (or type path): "
        raw = input(prompt).strip().strip('"')
        if os.path.exists(raw):
            return raw
        print(f"  ! File not found, try again.\n")


def print_banner():
    print()
    print("=" * 55)
    print("  SECURE FILE SENDER")
    print("=" * 55)


def print_result(file_path, result, index=None):
    file_name = os.path.basename(file_path)
    label = f"  File {index}: " if index else "  File: "
    if result.get("status") == "ok":
        mb      = result["bytes"] / 1024 / 1024
        elapsed = result["elapsed_s"]
        speed   = result["throughput_mibps"]
        print(f"  {'✓'} {file_name}")
        print(f"    {mb:.3f} MiB  |  {elapsed:.3f}s  |  {speed:.2f} MiB/s")
        print(f"    Saved → received\\{file_name}")
    else:
        print(f"  ✗ {file_name}")
        print(f"    FAILED: {result.get('reason', 'Unknown error')}")


# ─────────────────────────────────────────────────────────
print_banner()
print()
print("  How do you want to test?")
print()
print("  [1] Send a single file")
print("  [2] Send multiple files (you choose how many)")
print("  [3] Stress test — send the same file many times")
print()

choice = input("  Enter 1, 2, or 3: ").strip()
print()

results_summary = []

# ── Option 1: Single file ─────────────────────────────────
if choice == "1":
    file_path = get_file_path()
    print(f"\n  Sending '{os.path.basename(file_path)}' securely...\n")
    result, _ = send_one(file_path)
    print()
    print("=" * 55)
    print_result(file_path, result)
    results_summary.append((file_path, result))

# ── Option 2: Multiple different files ───────────────────
elif choice == "2":
    while True:
        try:
            n = int(input("  How many files do you want to send? ").strip())
            if n >= 1:
                break
            print("  ! Enter a number of 1 or more.")
        except ValueError:
            print("  ! Please enter a valid number.")

    print()
    files = []
    for i in range(1, n + 1):
        files.append(get_file_path(label=f"File {i}/{n} — "))

    print(f"\n  Sending {n} file(s) securely...\n")
    print("=" * 55)

    for i, fp in enumerate(files, 1):
        print(f"\n  [{i}/{n}] {os.path.basename(fp)}")
        result, _ = send_one(fp)
        print()
        print_result(fp, result, index=i)
        results_summary.append((fp, result))

# ── Option 3: Stress test — same file N times ────────────
elif choice == "3":
    file_path = get_file_path()
    while True:
        try:
            n = int(input("  How many times to send it? ").strip())
            if n >= 1:
                break
            print("  ! Enter a number of 1 or more.")
        except ValueError:
            print("  ! Please enter a valid number.")

    print(f"\n  Stress testing: sending '{os.path.basename(file_path)}' x{n}...\n")
    print("=" * 55)

    for i in range(1, n + 1):
        print(f"\n  [{i}/{n}] {os.path.basename(file_path)}")
        result, _ = send_one(file_path)
        print()
        print_result(file_path, result, index=i)
        results_summary.append((file_path, result))

else:
    print("  ! Invalid choice. Run the script again and enter 1, 2, or 3.")
    input("\n  Press Enter to exit...")
    sys.exit(1)

# ── Final summary ─────────────────────────────────────────
print()
print("=" * 55)
print("  SUMMARY")
print("=" * 55)
ok    = sum(1 for _, r in results_summary if r.get("status") == "ok")
fail  = len(results_summary) - ok
total_bytes = sum(r.get("bytes", 0) for _, r in results_summary if r.get("status") == "ok")
print(f"  Sent     : {len(results_summary)} file(s)")
print(f"  Success  : {ok}")
print(f"  Failed   : {fail}")
print(f"  Total    : {total_bytes / 1024 / 1024:.3f} MiB transferred")
print(f"  Output   : received\\")
print(f"  Logs     : logs\\")
print("=" * 55)
print()
input("  Press Enter to exit...")
