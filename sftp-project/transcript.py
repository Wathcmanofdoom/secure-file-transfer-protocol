"""
transcript.py — Human-readable protocol transcript logger.

Every handshake event and data-transfer event is recorded with a timestamp
and role label.  A summary is printed at the end of each run.
"""

import time
import os
import hashlib


class Transcript:
    def __init__(self, role: str, log_dir: str = "."):
        self.role      = role.upper()
        self.events    = []
        self.log_dir   = log_dir
        self._t0       = time.perf_counter()
        os.makedirs(log_dir, exist_ok=True)

    def _ts(self) -> float:
        return time.perf_counter() - self._t0

    def log(self, event: str, detail: str = "", data: bytes = None):
        ts = self._ts()
        hex_snippet = ""
        if data:
            hex_snippet = data[:8].hex() + ("…" if len(data) > 8 else "")
        entry = {
            "ts":    ts,
            "role":  self.role,
            "event": event,
            "detail": detail,
            "hex":   hex_snippet,
        }
        self.events.append(entry)
        tag = f"[{ts:7.3f}s][{self.role:6}]"
        det = f" | {detail}" if detail else ""
        hx  = f" [{hex_snippet}]" if hex_snippet else ""
        print(f"{tag} {event}{det}{hx}")

    def save(self, filename: str = None):
        if filename is None:
            ts_str = time.strftime("%Y%m%d_%H%M%S")
            filename = f"transcript_{self.role.lower()}_{ts_str}.txt"
        path = os.path.join(self.log_dir, filename)
        with open(path, "w") as f:
            f.write(f"=== SECURE FILE TRANSFER PROTOCOL — TRANSCRIPT ===\n")
            f.write(f"Role: {self.role}\n")
            f.write(f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}\n\n")
            for e in self.events:
                line = (f"[{e['ts']:8.3f}s] [{e['role']:6}] {e['event']}")
                if e['detail']:
                    line += f"\n          detail: {e['detail']}"
                if e['hex']:
                    line += f"\n          bytes:  {e['hex']}"
                f.write(line + "\n")
        return path
