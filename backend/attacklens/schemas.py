"""Canonical event columns (DEVELOPMENT.md §3.1). Ingest writes exactly these; tests build fixtures from them."""

from __future__ import annotations

CANONICAL_COLUMNS: dict[str, str] = {
    "ts_ms": "BIGINT",
    "ts_ok": "BOOLEAN",
    "event_day": "DATE",
    "source_type": "VARCHAR",
    "source_seq": "UBIGINT",
    "action": "VARCHAR",
    "event_id": "INTEGER",
    "outcome": "VARCHAR",
    "logon_id": "VARCHAR",
    "logon_type": "INTEGER",
    "host": "VARCHAR",
    "host_ip": "VARCHAR",
    "src_user": "VARCHAR",
    "target_user": "VARCHAR",
    "is_machine": "BOOLEAN",
    "group_name": "VARCHAR",
    "src_ip": "VARCHAR",
    "src_port": "INTEGER",
    "dst_ip": "VARCHAR",
    "dst_port": "INTEGER",
    "dst_domain": "VARCHAR",
    "process_name": "VARCHAR",
    "process_path": "VARCHAR",
    "parent_process": "VARCHAR",
    "command_line": "VARCHAR",
    "file_path": "VARCHAR",
    "file_ext": "VARCHAR",
    "registry_path": "VARCHAR",
    "bytes_out": "BIGINT",
    "auth_package": "VARCHAR",       # NTLM / Kerberos / Negotiate (4624 AuthenticationPackageName, LmPackageName)
    "ticket_encryption": "VARCHAR",  # Kerberos ticket encryption type, lower hex, e.g. 0x17 (4769)
    "service_name": "VARCHAR",       # 7045 ServiceName / 4769 ServiceName / ECS service.name
    "signature": "VARCHAR",          # vendor detection name: FortiGate IPS attack / virus / webfilter catdesc
    "vendor_severity": "VARCHAR",    # vendor's own severity/level for that detection (raw field, not a label)
    "app": "VARCHAR",                # application name (FortiGate app / appcat)
    "src_zone": "VARCHAR",           # interface role of the source: wan / lan / dmz / undefined
    "dst_zone": "VARCHAR",           # interface role of the destination
    "bytes_in": "BIGINT",            # bytes received by the source (FortiGate rcvdbyte)
    "raw_line": "VARCHAR",
}

PARTITION_COLUMNS = ("source_type", "ts_ok", "event_day")

TACTICS_V20: list[str] = [
    "Reconnaissance", "Resource Development", "Initial Access", "Execution", "Persistence",
    "Privilege Escalation", "Stealth", "Defense Impairment", "Credential Access", "Discovery",
    "Lateral Movement", "Collection", "Command and Control", "Exfiltration", "Impact",
]
TACTIC_IDX: dict[str, int] = {t: i + 1 for i, t in enumerate(TACTICS_V20)}
