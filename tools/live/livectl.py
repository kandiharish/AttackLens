"""Start / stop ONE real vendor container for the live connector tests (backend/tests/live, marker `live`).

    python tools/live/livectl.py gate  <vendor>          # docker up? free RAM / disk enough? (exit 1 if not)
    python tools/live/livectl.py up    <vendor> [--keep] # compose up + wait ready; prints URLs (never secrets)
    python tools/live/livectl.py down  <vendor>          # docker compose down -v (always -v: no volume survives)
    python tools/live/livectl.py clean                   # remove the vendor images pulled for these tests
vendors: splunk | elastic | syslog | localstack

Rules (reports/integrations/live.md): every port bound to 127.0.0.1 only, throwaway passwords generated per run and
passed as environment variables (never written to the repo), memory limits in each compose file, one vendor at a
time (`up` refuses while another al-live-* project is running), `down -v` after each.
Generated files (TLS certs, rsyslog.conf) go under data/live/<vendor>/ (git-ignored).
"""

from __future__ import annotations

import argparse
import json
import os
import secrets
import shutil
import socket
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
DATA = REPO / "data" / "live"
RESULTS = DATA / "results"
VENDORS = ("splunk", "elastic", "syslog", "localstack")
# free RAM needed before a container may start (container limit + headroom for the test process)
NEED_RAM_GB = {"splunk": 4.0, "elastic": 3.0, "syslog": 0.5, "localstack": 1.5}
NEED_DISK_GB = 10.0
MIN_FREE_RAM_GB = float(os.environ.get("AL_LIVE_MIN_FREE_GB", "6"))   # machine-wide floor before ANY start
WATCHDOG_RAM_GB = float(os.environ.get("AL_LIVE_WATCHDOG_GB", "2"))   # below this while running -> down -v
IMAGES = {"splunk": ("SPLUNK_IMAGE", "splunk/splunk:latest"),
          "elastic": ("ES_IMAGE", "docker.elastic.co/elasticsearch/elasticsearch:8.19.5"),
          "syslog": ("RSYSLOG_IMAGE", "rsyslog/syslog_appliance_alpine:latest"),
          "localstack": ("LOCALSTACK_IMAGE", "localstack/localstack:4.4")}


class GateError(RuntimeError):
    """The machine is not ready for this container (docker missing, too little RAM / disk, another vendor up)."""


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def password(n: int = 20) -> str:
    """Throwaway password meeting Splunk / Elastic policy (letters, digits, a symbol); never written to disk."""
    return "Al-" + secrets.token_urlsafe(n).replace("-", "x").replace("_", "y") + "7q"


def run(cmd: list[str], env: dict[str, str] | None = None, timeout: float = 900, check: bool = True,
        capture: bool = True) -> subprocess.CompletedProcess[str]:
    p = subprocess.run(cmd, env={**os.environ, **(env or {})}, timeout=timeout, text=True,
                       capture_output=capture, cwd=REPO)
    if check and p.returncode != 0:
        tail = ((p.stdout or "") + (p.stderr or ""))[-2000:]
        raise RuntimeError(f"{' '.join(cmd[:4])} ... exit {p.returncode}: {tail}")
    return p


def docker_ok() -> str | None:
    """None if the docker daemon answers, else the reason."""
    if not shutil.which("docker"):
        return "docker CLI not on PATH"
    try:
        p = run(["docker", "version", "--format", "{{.Server.Version}}"], timeout=30, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return f"docker not answering ({type(exc).__name__})"
    return None if p.returncode == 0 else "docker daemon not running"


def free_ram_gb() -> float:
    import psutil

    return psutil.virtual_memory().available / 2**30


def free_disk_gb() -> float:
    return shutil.disk_usage(REPO).free / 2**30


def running_projects() -> list[str]:
    p = run(["docker", "ps", "--format", "{{.Label \"com.docker.compose.project\"}}"], check=False, timeout=30)
    return sorted({ln.strip() for ln in (p.stdout or "").splitlines() if ln.strip().startswith("al-live-")})


def pipeline_procs() -> list[int]:
    """PIDs of python processes running `attacklens.run` or `attacklens.live` (benchmarks / live mode): a container
    must not start next to them (it would skew their RAM / time numbers)."""
    import psutil

    out = []
    for p in psutil.process_iter(["pid", "name", "cmdline"]):
        try:
            cmd = " ".join(p.info.get("cmdline") or [])
        except (psutil.Error, TypeError):
            continue
        if "python" in str(p.info.get("name") or "").lower() and ("attacklens.run" in cmd or "attacklens.live" in cmd):
            out.append(int(p.info["pid"]))
    return out


def gate(vendor: str) -> list[str]:
    """Reasons this vendor must not start now ([] = go). AL_LIVE_FORCE=1 skips the RAM checks only."""
    why = []
    d = docker_ok()
    if d:
        return [d]
    ram, disk = free_ram_gb(), free_disk_gb()
    need = max(NEED_RAM_GB[vendor], MIN_FREE_RAM_GB)
    if ram < need and os.environ.get("AL_LIVE_FORCE") != "1":
        why.append(f"free RAM {ram:.1f} GB < {need:g} GB needed before starting {vendor}")
    procs = pipeline_procs()
    if procs:
        why.append(f"attacklens.run / attacklens.live running (pids {procs[:5]}): containers would skew them")
    if disk < NEED_DISK_GB:
        why.append(f"free disk {disk:.1f} GB < {NEED_DISK_GB} GB")
    others = [p for p in running_projects() if p != f"al-live-{vendor}"]
    if others:
        why.append(f"another live vendor is running: {others} (one at a time; run livectl.py down)")
    return why


def image_info(image: str) -> dict[str, Any]:
    p = run(["docker", "image", "inspect", image, "--format",
             "{{json .RepoDigests}}|{{.Id}}|{{.Size}}|{{.Created}}"], check=False, timeout=60)
    if p.returncode != 0:
        return {"image": image, "digest": None}
    digests, iid, size, created = p.stdout.strip().split("|", 3)
    dl = json.loads(digests or "[]")
    return {"image": image, "digest": dl[0] if dl else None, "id": iid, "size_mb": round(int(size) / 2**20),
            "created": created}


def record(kind: str, row: dict[str, Any]) -> None:
    """Append one JSON row to data/live/results/<kind>.jsonl (vendors.jsonl, checks.jsonl): the source of live.md."""
    RESULTS.mkdir(parents=True, exist_ok=True)
    with (RESULTS / f"{kind}.jsonl").open("a", encoding="utf-8") as fh:
        fh.write(json.dumps({"at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), **row}) + "\n")


@dataclass
class Stack:
    """One running vendor: compose project, ports, generated secrets (memory only), timings."""
    vendor: str
    env: dict[str, str] = field(default_factory=dict)
    ports: dict[str, int] = field(default_factory=dict)
    timings: dict[str, float] = field(default_factory=dict)
    info: dict[str, Any] = field(default_factory=dict)

    @property
    def project(self) -> str:
        return f"al-live-{self.vendor}"

    @property
    def compose_file(self) -> Path:
        return HERE / self.vendor / "docker-compose.yml"

    @property
    def image(self) -> str:
        var, default = IMAGES[self.vendor]
        return os.environ.get(var) or default

    @property
    def dir(self) -> Path:
        d = DATA / self.vendor
        d.mkdir(parents=True, exist_ok=True)
        return d

    def compose(self, *args: str, timeout: float = 900, check: bool = True) -> subprocess.CompletedProcess[str]:
        return run(["docker", "compose", "-p", self.project, "-f", str(self.compose_file), *args],
                   env={**self.env, IMAGES[self.vendor][0]: self.image}, timeout=timeout, check=check)

    def up(self, wait_timeout: int = 600) -> None:
        why = gate(self.vendor)
        if why:
            raise GateError("; ".join(why))
        t0 = time.perf_counter()
        have = run(["docker", "image", "inspect", self.image], check=False, timeout=60).returncode == 0
        if not have:
            self.compose("pull", "--quiet", timeout=1800)
        self.timings["pull_s"] = round(time.perf_counter() - t0, 1)
        self.info["image_was_local"] = have
        t1 = time.perf_counter()
        self.compose("up", "-d", "--wait", "--wait-timeout", str(wait_timeout), timeout=wait_timeout + 120)
        self.timings["start_s"] = round(time.perf_counter() - t1, 1)
        self.info.update(image_info(self.image))

    def logs(self, tail: int = 80) -> str:
        p = self.compose("logs", "--no-color", "--tail", str(tail), check=False, timeout=60)
        return (p.stdout or "") + (p.stderr or "")

    def exec(self, service: str, *cmd: str, timeout: float = 120) -> str:
        return self.compose("exec", "-T", service, *cmd, timeout=timeout).stdout

    def cp_out(self, container: str, src: str, dst: Path) -> Path:
        run(["docker", "cp", f"{container}:{src}", str(dst)], timeout=60)
        return dst

    def down(self) -> None:
        self.compose("down", "-v", "--remove-orphans", timeout=300, check=False)


def clean() -> None:
    for var, default in IMAGES.values():
        img = os.environ.get(var) or default
        run(["docker", "image", "rm", img], check=False, timeout=300)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="livectl")
    ap.add_argument("cmd", choices=("gate", "up", "down", "clean"))
    ap.add_argument("vendor", nargs="?", choices=VENDORS)
    a = ap.parse_args(argv)
    if a.cmd == "clean":
        clean()
        return 0
    if not a.vendor:
        ap.error("vendor required")
    if a.cmd == "gate":
        why = gate(a.vendor)
        print("ok" if not why else "NOT READY: " + "; ".join(why))
        return 1 if why else 0
    if a.cmd == "down":
        Stack(a.vendor).down()
        return 0
    print("use pytest: .venv/Scripts/python -m pytest backend/tests/live -m live -k", a.vendor,
          "(the fixture brings the vendor up, seeds it, tests, and runs down -v)")
    return 2


if __name__ == "__main__":
    sys.exit(main())
