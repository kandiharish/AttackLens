"""rsyslog relay config + line sender for the live syslog listener tests.

The test sends plain syslog lines into rsyslog (imtcp on a loopback-published port). rsyslog forwards each line to
the AttackLens listener on the host, choosing the transport by program name:
    al_udp   -> omfwd UDP
    al_tcp   -> omfwd TCP, TCP_Framing="traditional" (newline-delimited)
    al_octet -> omfwd TCP, TCP_Framing="octet-counted" (RFC 6587 `<len> <msg>`)
Action queues retry forever (resumeRetryCount -1), so a TCP line is delayed, not lost, while the listener starts.
"""

from __future__ import annotations

import socket
import time
from pathlib import Path

PHASES = {"udp": ("al_udp", "udp", None), "tcp": ("al_tcp", "tcp", "traditional"),
          "octet": ("al_octet", "tcp", "octet-counted")}

_ACTION = ('action(type="omfwd" target="{host}" port="{port}" protocol="{proto}"{framing} '
           'template="RSYSLOG_TraditionalForwardFormat" queue.type="LinkedList" queue.size="100000" '
           'action.resumeRetryCount="-1" action.resumeInterval="1")')


def conf(target_host: str, port: int) -> str:
    rules = []
    for prog, proto, framing in PHASES.values():
        fr = f' TCP_Framing="{framing}"' if framing else ""
        rules.append(f'  if $programname == "{prog}" then {{\n    '
                     + _ACTION.format(host=target_host, port=port, proto=proto, framing=fr) + "\n    stop\n  }")
    return ('global(workDirectory="/tmp" maxMessageSize="64k")\n'
            'module(load="imtcp")\n'
            'input(type="imtcp" port="10514" ruleset="al")\n'
            'ruleset(name="al") {\n' + "\n".join(rules) + "\n}\n")


def write_conf(dst: Path, target_host: str, port: int) -> Path:
    dst.parent.mkdir(parents=True, exist_ok=True)
    dst.write_text(conf(target_host, port), encoding="ascii", newline="\n")
    return dst


def line(phase: str, seq: int, run: str) -> str:
    prog = PHASES[phase][0]
    stamp = time.strftime("%b %d %H:%M:%S", time.gmtime())
    return f"<134>{stamp} al-live-host {prog}: al-live {run} phase={phase} seq={seq:05d}"


def send_to_relay(port: int, lines: list[str]) -> None:
    """Newline-framed TCP into rsyslog's imtcp input."""
    with socket.create_connection(("127.0.0.1", port), timeout=10) as s:
        s.sendall("".join(ln + "\n" for ln in lines).encode("utf-8"))


def wait_tcp(port: int, timeout: float = 60) -> None:
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1):
                return
        except OSError:
            time.sleep(0.5)
    raise TimeoutError(f"nothing listening on 127.0.0.1:{port}")
