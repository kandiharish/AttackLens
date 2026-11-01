"""P1-3: Microsoft Sentinel / Defender alerts (Log Analytics SecurityAlert rows as the azure_monitor connector pulls
them) mapped to raw_alerts rows in alert-input mode (attacklens/siem_alerts.map_alert with the shipped
config/integrations.yaml azure_monitor alert fields). SecurityAlert writes Entities / ExtendedProperties / Techniques as
JSON STRINGS and Tactics as one comma-separated string. Alert-input is never part of the scored eval (run.py refuses
--siem-alerts with --ground-truth)."""

from __future__ import annotations

import json
from typing import Any

import pytest

from attacklens import integrations as ig
from attacklens import siem_alerts
from attacklens.config import load_config

TS = 1792807200000


@pytest.fixture(scope="module")
def cfg() -> dict[str, Any]:
    return load_config()


def fields(cfg: dict[str, Any]) -> dict[str, Any]:
    return ig.icfg(cfg)["connectors"]["azure_monitor"]["alerts"]["fields"]


def security_alert(name: str, *, techniques: list[str] | None = None, sub: list[str] | None = None,
                   tactics: str = "", severity: str = "High", entities: list[dict[str, Any]] | None = None,
                   compromised: str = "", provider: str = "Azure Security Center") -> dict[str, Any]:
    return {"TenantId": "4d5f1c2e-0000-4000-8000-0000000000a1", "TimeGenerated": "2026-10-24T02:00:00Z",
            "DisplayName": name, "AlertName": name, "AlertSeverity": severity, "ProviderName": provider,
            "VendorName": "Microsoft", "SystemAlertId": f"sa-{abs(hash(name)) % 10_000}",
            "Tactics": tactics, "Techniques": json.dumps(techniques) if techniques else "",
            "SubTechniques": json.dumps(sub) if sub else "", "CompromisedEntity": compromised,
            "Entities": json.dumps(entities or []), "ExtendedProperties": json.dumps({"Alert Id": "x"}),
            "Type": "SecurityAlert"}


def test_sentinel_analytics_alert_with_subtechnique(cfg) -> None:
    doc = security_alert("Password spray against Entra ID", techniques=["T1110"], sub=["T1110.003"],
                         tactics="CredentialAccess", severity="Medium", provider="ASI Scheduled Alerts",
                         entities=[{"$id": "2", "Name": "nbose", "UPNSuffix": "corp.example", "Type": "account"},
                                   {"$id": "3", "Address": "203.0.113.160", "Type": "ip"}])
    row, why = siem_alerts.map_alert(doc, "azure_monitor", fields(cfg), cfg, TS)
    assert why is None
    assert (row["rule_id"], row["technique_id"], row["sub_technique_id"], row["tactic"], row["severity"]) == \
        ("siem:azure_monitor:Password spray against Entra ID", "T1110", "T1110.003", "Credential Access", 60)
    assert (row["target_user"], row["src_ip"], row["ts_ms"]) == ("nbose", "203.0.113.160", TS)


def test_defender_alert_multi_tactic_string_and_host(cfg) -> None:
    # Tactics is ONE string "InitialAccess, Persistence": the vendor tactic that belongs to the technique is kept
    doc = security_alert("Suspicious sign-in followed by persistence", techniques=["T1078"], sub=["T1078.004"],
                         tactics="Persistence, InitialAccess", compromised="VM-WEB-01",
                         entities=[{"$id": "2", "HostName": "vm-web-01", "Type": "host"}])
    row, why = siem_alerts.map_alert(doc, "azure_monitor", fields(cfg), cfg, TS)
    assert why is None
    assert (row["technique_id"], row["sub_technique_id"], row["tactic"], row["host"], row["severity"]) == \
        ("T1078", "T1078.004", "Persistence", "vm-web-01", 80)


def test_defender_for_cloud_alert_without_mitre_uses_name_map(cfg) -> None:
    doc = security_alert("Access from a suspicious IP to a key vault", tactics="CredentialAccess",
                         compromised="KV-FINANCE", entities=[{"Address": "203.0.113.150", "Type": "ip"}])
    row, why = siem_alerts.map_alert(doc, "azure_monitor", fields(cfg), cfg, TS)
    assert why is None, why
    assert (row["technique_id"], row["sub_technique_id"], row["tactic"], row["src_ip"]) == \
        ("T1555", "T1555.006", "Credential Access", "203.0.113.150")


def test_alert_with_no_entity_or_no_technique_is_dropped_with_reason(cfg) -> None:
    assert siem_alerts.map_alert(security_alert("Something odd", tactics="Discovery"), "azure_monitor",
                                 fields(cfg), cfg, TS) == (None, "no_technique")
    assert siem_alerts.map_alert(security_alert("Brute force attack", techniques=["T1110"]), "azure_monitor",
                                 fields(cfg), cfg, TS) == (None, "no_entity")
