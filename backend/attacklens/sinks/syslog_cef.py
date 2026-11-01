"""CEF over syslog sink: one CEF line per incident plus one per backbone step (UDP or TCP)."""

from __future__ import annotations

import re
import socket
from typing import Any

from attacklens import integrations as ig
from attacklens.connectors import catalog_fields as cf


CATALOG: dict[str, Any] = {
    "id": "syslog_cef", "kind": "sink", "name": "Syslog CEF",
    "docs_url": "https://www.microfocus.com/documentation/arcsight/arcsight-smartconnectors/pdfdoc/common-event-format-v25/common-event-format-v25.pdf",
    "help": "No credentials: the receiving syslog / SIEM collector must accept CEF on this host and port.",
    "fields": [
        cf.field("host", "Host", required=True, placeholder="siem.example"),
        cf.field("port", "Port", "number", True, default=5515, min=1, max=65535),
        cf.field("protocol", "Protocol", "select", options=["udp", "tcp"], default="udp"),
    ],
}

_SEV = (("critical", 90, 10), ("high", 70, 8), ("medium", 40, 5), ("low", 0, 3))


def _h(s: Any) -> str:
    """Escape a CEF header field."""
    return str(s if s is not None else "").replace("\\", "\\\\").replace("|", "\\|").replace("\n", " ")


def _e(s: Any) -> str:
    """Escape a CEF extension value."""
    return re.sub(r"[\r\n]+", " ", str(s if s is not None else "")).replace("\\", "\\\\").replace("=", "\\=")


FACILITIES = {"kern": 0, "user": 1, "daemon": 3, "auth": 4, "syslog": 5, "authpriv": 10, "local0": 16,
              "local1": 17, "local2": 18, "local3": 19, "local4": 20, "local5": 21, "local6": 22, "local7": 23}


def _cef_sev(risk: int) -> int:
    return next(v for _, lo, v in _SEV if risk >= lo)


def _syslog_sev(cef_sev: int) -> int:
    """CEF 0..10 -> syslog severity (2 critical, 3 error, 4 warning, 5 notice)."""
    return 2 if cef_sev >= 9 else 3 if cef_sev >= 7 else 4 if cef_sev >= 4 else 5


def syslog_header(cef_sev: int, scfg: dict[str, Any], ts_ms: int | None = None) -> str:
    """RFC 5424 header: <PRI>1 <ISO ts> <host> AttackLens - - - (facility from config, default local4)."""
    fac = scfg.get("facility", "local4")
    fac_n = int(fac) if str(fac).isdigit() else FACILITIES.get(str(fac).lower())
    if fac_n is None or not 0 <= fac_n <= 23:
        raise ValueError(f"syslog_cef: unknown facility {fac!r}")
    host = str(scfg.get("hostname") or socket.gethostname() or "-").replace(" ", "_")[:255]
    ts = ig.iso_ms(ts_ms if ts_ms is not None else ig.now_ms())
    return f"<{fac_n * 8 + _syslog_sev(cef_sev)}>1 {ts} {host} {scfg.get('app_name', 'AttackLens')} - - - "


def lines_for(inc: dict[str, Any], row: dict[str, Any], scfg: dict[str, Any]) -> list[str]:
    head = f"CEF:0|{_h(scfg.get('vendor', 'Mitigata'))}|{_h(scfg.get('product', 'AttackLens'))}|" \
           f"{_h(scfg.get('version', '0.1'))}"
    risk = int(inc.get("risk") or 0)
    rt = ig.to_ms(inc.get("first_ts")) or ig.now_ms()
    ext = (f"externalId={_e(inc.get('id'))} rt={rt} end={ig.to_ms(inc.get('last_ts')) or rt} "
           f"cs1Label=tactics cs1={_e(','.join(inc.get('tactics') or []))} "
           f"cs2Label=hosts cs2={_e(','.join(row.get('hosts') or []))} cn1Label=risk cn1={risk} "
           f"cn2Label=steps cn2={len(inc.get('backbone') or [])} msg={_e(row.get('entry_summary', ''))}")
    sev = _cef_sev(risk)
    out = [f"{syslog_header(sev, scfg)}{head}|incident|AttackLens incident {_h(inc.get('id'))}|{sev}|{ext}"]
    for s in inc.get("backbone") or []:
        tech = s.get("sub_technique_id") or s.get("technique_id")
        sext = (f"externalId={_e(inc.get('id'))}-{s.get('step')} rt={ig.to_ms(s.get('ts')) or rt} "
                f"cs1Label=incident cs1={_e(inc.get('id'))} cs2Label=technique cs2={_e(tech)} "
                f"cs3Label=tactic cs3={_e(s.get('tactic'))} cn1Label=step cn1={s.get('step')}")
        if s.get("host"):
            sext += f" dhost={_e(s['host'])}"
        if s.get("user"):
            sext += f" duser={_e(s['user'])}"
        if s.get("src_ip"):
            sext += f" src={_e(s['src_ip'])}"
        if s.get("dst_ip"):
            sext += f" dst={_e(s['dst_ip'])}"
        name = f"Step {s.get('step')}: {s.get('technique_name') or tech}"
        ssev = _cef_sev(int(s.get("severity") or 0))
        out.append(f"{syslog_header(ssev, scfg)}{head}|step:{_h(tech)}|{_h(name)}|{ssev}|{sext}")
    return out


def send(items: list[tuple[dict[str, Any], dict[str, Any]]], scfg: dict[str, Any], cfg: dict[str, Any]) -> int:
    from attacklens.connectors.syslog import send_lines

    lines: list[str] = []
    for inc, row in items:
        lines += lines_for(inc, row, scfg)
    send_lines(lines, str(scfg.get("host", "127.0.0.1")), int(scfg.get("port", 5515)),
               str(scfg.get("protocol", "udp")))
    return len(items)
