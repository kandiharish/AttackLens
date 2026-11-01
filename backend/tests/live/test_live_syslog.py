"""rsyslog (real relay in Docker) -> AttackLens syslog listener on the host, three transports, exact counts.

The listener (attacklens.connectors.syslog, events mode) binds 127.0.0.1:<P> for UDP and TCP. rsyslog receives
lines from the test on a loopback-published imtcp port and forwards them to host.docker.internal:<P> by program name:
UDP, TCP newline framing, TCP octet counting (RFC 6587). Per transport the test sends N lines and asserts the
listener's received == written == N and the spool holds seq 0..N-1 exactly once.

Run: .venv/Scripts/python -m pytest backend/tests/live -m live -k syslog -v
"""

from __future__ import annotations

import os
import socket
import time
import uuid
from pathlib import Path
from typing import Any, Iterator

import pytest
import yaml

from attacklens import config

from .conftest import vendor

import livectl  # noqa: E402  (tools/live, on sys.path via conftest)
import syslog_seed as sl  # noqa: E402

pytestmark = pytest.mark.live

N = 300


def _udp_tcp_free_port() -> int:
    for _ in range(50):
        p = livectl.free_port()
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as u:
            try:
                u.bind(("127.0.0.1", p))
                return p
            except OSError:
                continue
    raise RuntimeError("no port free for both UDP and TCP")


def _cfg(tmp: Path, port: int) -> dict[str, Any]:
    from ..test_integrations import cfg_dir

    ic = yaml.safe_load((config.CONFIG_DIR / "integrations.yaml").read_text(encoding="utf-8"))
    ic["spool"].update(events_dir=str(tmp / "spool" / "events"), alerts_dir=str(tmp / "spool" / "alerts"),
                       state_dir=str(tmp / "conn_state"), status_file=str(tmp / "conn_state" / "status.json"))
    ic["connectors"]["syslog"].update(enabled=True, bind=os.environ.get("AL_LIVE_SYSLOG_BIND", "127.0.0.1"),
                                      udp_port=port, tcp_port=port, flush_interval_s=1)
    return config.load_config(cfg_dir(tmp, ic))


@pytest.fixture(scope="module")
def relay(tmp_path_factory: pytest.TempPathFactory) -> Iterator[dict[str, Any]]:
    from attacklens import connectors

    tmp = tmp_path_factory.mktemp("syslog_live")
    port = _udp_tcp_free_port()
    conn = connectors.get("syslog", _cfg(tmp, port), "events")
    box: dict[str, Any] = {}

    def prepare(st: livectl.Stack) -> None:
        bound = conn.start()          # listener first: UDP has no retry
        box["bound"] = bound
        st.ports = {"listener": port, "relay_in": livectl.free_port()}
        conf = sl.write_conf(st.dir / "rsyslog.conf", "host.docker.internal", port)
        st.env = {"AL_RSYSLOG_CONF": conf.as_posix(), "AL_RSYSLOG_IN_PORT": str(st.ports["relay_in"])}

    try:
        with vendor("syslog", prepare) as st:
            sl.wait_tcp(st.ports["relay_in"])
            yield {"conn": conn, "tmp": tmp, "stack": st, "run": uuid.uuid4().hex[:10], **box}
    finally:
        conn.stop()


def _spool_seqs(tmp: Path, run: str, phase: str) -> list[int]:
    root = tmp / "spool" / "events" / "syslog"
    out = []
    for p in sorted(root.rglob("*")) if root.exists() else []:
        if p.is_file() and not p.name.startswith("."):
            for ln in p.read_text(encoding="utf-8", errors="replace").splitlines():
                if f"al-live {run} phase={phase} " in ln:
                    out.append(int(ln.rsplit("seq=", 1)[1][:5]))
    return out


@pytest.mark.parametrize("phase", ["udp", "tcp", "octet"])
def test_rsyslog_forwarding_counts(phase: str, relay, record_property) -> None:
    conn, run = relay["conn"], relay["run"]
    conn.flush()                                            # drain anything before this phase
    t0 = time.perf_counter()
    sl.send_to_relay(relay["stack"].ports["relay_in"], [sl.line(phase, i, run) for i in range(N)])
    received = written = failed = 0
    end = time.monotonic() + 60
    while time.monotonic() < end and written < N:
        time.sleep(1)
        st = conn.flush()
        received += int(st.get("received", 0))
        written += int(st["written"])
        failed += int(st["failed"])
    time.sleep(3)                                           # late extras / duplicates would show up here
    st = conn.flush()
    received += int(st.get("received", 0))
    written += int(st["written"])
    failed += int(st["failed"])
    got = _spool_seqs(relay["tmp"], run, phase)
    record_property("sent", N)
    record_property("received", received)
    record_property("written", written)
    record_property("failed", failed)
    record_property("spool_unique", len(set(got)))
    record_property("wall_s", round(time.perf_counter() - t0, 1))
    assert received == written == N and failed == 0, (received, written, failed)
    assert sorted(got) == list(range(N)), f"{phase}: {len(got)} lines, {len(set(got))} unique"
