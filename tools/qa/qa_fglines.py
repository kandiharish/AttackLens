"""QA: tiny deterministic FortiGate key=value line sets with one embedded brute-force-then-success pattern.

Lines are formatted by tools/fortigate_gen.py's Fmt (loaded via importlib, never modified), so they are exactly the
format the ingest already parses. Used by tools/qa/qa_api_probe.py (upload -> run) and tools/qa/qa_live_feed.py.

Pattern (ground truth for the QA track, never read by detection code):
- noise: internal traffic / dns lines from 10.10.1.x clients
- attack: `n_fail` "Admin login failed" for user ATTACK_USER from ATTACK_IP (external), then one success
  -> expected rule fw_admin_bruteforce (T1110.001 Credential Access + secondary T1078 Initial Access).
"""

from __future__ import annotations

import importlib.util
import random
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
ATTACK_IP = "203.0.113.57"
ATTACK_USER = "admin"


def _fmt_mod():
    name = "qa_fortigate_gen"
    if name in sys.modules:
        return sys.modules[name]
    sys.path.insert(0, str(REPO / "tools"))
    spec = importlib.util.spec_from_file_location(name, REPO / "tools" / "fortigate_gen.py")
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


def formatter(seed: int = 7):
    return _fmt_mod().Fmt(random.Random(seed), 100_000)


def noise_line(f, ms: int, i: int) -> str:
    src = f"10.10.1.{10 + i % 40}"
    if i % 5 == 0:
        return f.dns(ms, src, "10.10.0.10", f"host{i % 17}.example.com")
    return f.traffic(ms, src, "93.184.216.34", "HTTPS")


def fail_line(f, ms: int) -> str:
    return f.admin_login(ms, ATTACK_USER, ATTACK_IP, ok=False, reason="passwd_invalid")


def success_line(f, ms: int) -> str:
    return f.admin_login(ms, ATTACK_USER, ATTACK_IP, ok=True)


def batch_file(start_ms: int, n_noise: int = 200, n_fail: int = 60, step_ms: int = 1000, seed: int = 7) -> list[str]:
    """All lines of a small upload file: noise, then n_fail failures 1 s apart, a success, more noise."""
    f = formatter(seed)
    out: list[str] = []
    ms = start_ms
    for i in range(n_noise // 2):
        out.append(noise_line(f, ms, i))
        ms += step_ms
    for _ in range(n_fail):
        out.append(fail_line(f, ms))
        ms += step_ms
    out.append(success_line(f, ms))
    ms += step_ms
    for i in range(n_noise // 2, n_noise):
        out.append(noise_line(f, ms, i))
        ms += step_ms
    return out
