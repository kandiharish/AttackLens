"""Fast self-checks of the live harness itself (NOT marked live: no Docker, no network).

A harness bug must not pass or fail a vendor check for the wrong reason: the throwaway CA really verifies 127.0.0.1
and really fails without the CA, the rsyslog relay config really uses the three framings, passwords are throwaway
and policy-compliant, and live tests are deselected from the default run.
"""

from __future__ import annotations

import socket
import ssl
import threading
from pathlib import Path

import pytest

from .conftest import LIVE_TOOLS  # noqa: F401  (puts tools/live on sys.path)

import certs  # noqa: E402
import livectl  # noqa: E402
import syslog_seed as sl  # noqa: E402


def _tls_server(paths: dict[str, Path]) -> tuple[int, threading.Thread]:
    sctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    sctx.load_cert_chain(paths["bundle"])          # cert + key (+ CA) in one PEM, the Splunk layout
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(2)

    def serve() -> None:
        for _ in range(2):
            c, _ = srv.accept()
            try:
                with sctx.wrap_socket(c, server_side=True) as t:
                    t.recv(1)
            except (ssl.SSLError, OSError):
                pass
        srv.close()

    th = threading.Thread(target=serve, daemon=True)
    th.start()
    return srv.getsockname()[1], th


def test_throwaway_ca_verifies_127_0_0_1_and_fails_without_it(tmp_path: Path) -> None:
    paths = certs.make(tmp_path / "tls")
    port, th = _tls_server(paths)
    ok = ssl.create_default_context(cafile=str(paths["ca"]))
    with socket.create_connection(("127.0.0.1", port)) as s, ok.wrap_socket(s, server_hostname="127.0.0.1") as t:
        assert t.version() is not None
    with pytest.raises(ssl.SSLCertVerificationError):
        with socket.create_connection(("127.0.0.1", port)) as s:
            ssl.create_default_context().wrap_socket(s, server_hostname="127.0.0.1")
    th.join(5)


def test_rsyslog_conf_has_three_transports() -> None:
    c = sl.conf("host.docker.internal", 15514)
    assert c.count('target="host.docker.internal" port="15514"') == 3
    assert 'protocol="udp"' in c and 'TCP_Framing="traditional"' in c and 'TCP_Framing="octet-counted"' in c
    assert 'input(type="imtcp" port="10514"' in c


def test_password_is_throwaway_and_policy_compliant() -> None:
    a, b = livectl.password(), livectl.password()
    assert a != b and len(a) >= 20 and any(ch.isdigit() for ch in a) and "-" in a


def test_compose_files_bind_loopback_only_and_limit_memory() -> None:
    import yaml

    for v in livectl.VENDORS:
        text = (livectl.HERE / v / "docker-compose.yml").read_text(encoding="utf-8")
        services = yaml.safe_load(text)["services"]
        for name, svc in services.items():
            ports = svc.get("ports") or []
            assert ports and all(str(p).startswith("127.0.0.1:") for p in ports), (v, name, ports)
            assert svc.get("mem_limit"), (v, name)
            for k, val in (svc.get("environment") or {}).items():
                if "PASSWORD" in k:
                    assert str(val).startswith("${"), f"{v}: literal password in {k}"
