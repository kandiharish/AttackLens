"""AWS vendor findings -> alert-input rows (reports/cloud/log_coverage.md P0-6 GuardDuty, P1-3 Security Hub).

Reads GuardDuty findings (bare finding / API Findings[] / EventBridge `detail`), Security Hub ASFF findings (bare /
Findings[] / EventBridge detail.findings[]) and OCSF 2004 Detection Findings, maps each to one raw_alerts row through
siem_alerts.map_alert (rule_id "siem:<vendor>:<type or title>") and writes them as JSON lines into the alert spool.

Vendor verdicts are read ONLY here. A run picks the spool up only with --siem-alerts, which run.py refuses together
with --ground-truth (siem_alerts.union_into raises EvalGuardError): scored detection stays raw-events-only.
Mapping: config/aws_findings.yaml. Repeated deliveries of one finding (same id) keep the latest updatedAt.
Nothing is lost silently: every finding is counted as a row or under a drop reason.

    python -m attacklens.findings_aws --in data/raw/cloud_aws_findings [--out data/spool/siem_alerts/aws.jsonl]
"""

from __future__ import annotations

import argparse
import json
import logging
import re
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any, Iterator

from attacklens import integrations as ig
from attacklens.siem_alerts import TECH_RE, map_alert

log = logging.getLogger(__name__)

FIELDS = {"rule_name": "_al_name", "technique": "_al_technique", "tactic": "_al_tactic", "host": "_al_host",
          "src_user": "_al_user", "src_ip": "_al_src_ip", "dst_ip": "_al_dst_ip", "severity": "_al_sev",
          "id": "_al_id"}
INSTANCE_RX = re.compile(r"(?:^|instance/)(i-[0-9a-f]{8,17})$")
MAX_DOC_BYTES = 256 * 1024 * 1024


def ts_ms(v: Any) -> int | None:
    """ISO-8601 (Z or offset) or epoch s / ms -> epoch ms (UTC); None when unparseable."""
    if v is None or v == "":
        return None
    if isinstance(v, (int, float)) or (isinstance(v, str) and re.fullmatch(r"\d{9,13}(\.\d+)?", v)):
        n = float(v)
        return int(n if n > 1e11 else n * 1000)
    try:
        return int(datetime.fromisoformat(str(v).replace("Z", "+00:00")).timestamp() * 1000)
    except ValueError:
        return None


# ---- reading -------------------------------------------------------------------------------------------------------
def unwrap(doc: Any) -> Iterator[dict[str, Any]]:
    """One delivered JSON value -> the findings inside it."""
    if isinstance(doc, list):
        for x in doc:
            yield from unwrap(x)
        return
    if not isinstance(doc, dict):
        return
    if isinstance(doc.get("Findings"), list):
        yield from unwrap(doc["Findings"])
    elif isinstance(doc.get("detail"), dict):
        d = doc["detail"]
        yield from unwrap(d["findings"]) if isinstance(d.get("findings"), list) else unwrap(d)
    else:
        yield doc


def iter_findings(path: Path) -> Iterator[dict[str, Any] | None]:
    """Findings of one file: JSON lines, else one (pretty-printed) JSON document. None = an unparseable line."""
    with path.open(encoding="utf-8-sig") as fh:
        head = fh.read(1 << 16)
    one_doc = head.lstrip().startswith("[") or ("\n" in head.strip() and not _is_json(head.strip().splitlines()[0]))
    if one_doc and path.stat().st_size <= MAX_DOC_BYTES:
        try:
            yield from unwrap(json.loads(path.read_text(encoding="utf-8-sig")))
            return
        except ValueError:
            pass
    with path.open(encoding="utf-8-sig") as fh:
        for line in fh:
            if not line.strip():
                continue
            try:
                yield from unwrap(json.loads(line))
            except ValueError:
                yield None


def _is_json(s: str) -> bool:
    try:
        json.loads(s)
        return True
    except ValueError:
        return False


def kind(f: dict[str, Any]) -> str | None:
    svc = f.get("service") if isinstance(f.get("service"), dict) else {}
    if svc.get("serviceName") == "guardduty" or "detectorId" in svc:
        return "guardduty"
    if "ProductArn" in f:
        return "securityhub"
    if f.get("class_uid") in (2004, "2004"):
        return "ocsf"
    return None


# ---- per vendor ----------------------------------------------------------------------------------------------------
def _get(d: Any, *path: str) -> Any:
    for p in path:
        if not isinstance(d, dict):
            return None
        d = d.get(p)
    return d


def _gd_technique(ftype: str, f: dict[str, Any], gcfg: dict[str, Any], names: dict[str, str]) -> str | None:
    if ftype.startswith("AttackSequence:"):
        for ind in _get(f, "service", "detection", "sequence", "sequenceIndicators") or []:
            if str(ind.get("key", "")).upper() != "ATTACK_TECHNIQUE":
                continue
            for v in ind.get("values") or []:
                t = (TECH_RE.findall(str(v)) or [names.get(str(v).strip().lower())])[0]
                if t:
                    return t
        res = ftype.split(":", 1)[1].split("/", 1)[0]
        return (gcfg.get("attack_sequence_default") or {}).get(res)
    for rule in gcfg.get("types") or []:
        if re.search(str(rule["pattern"]), ftype):
            return str(rule["technique"])
    return (gcfg.get("purposes") or {}).get(ftype.split(":", 1)[0])


def guardduty(f: dict[str, Any], fc: dict[str, Any], names: dict[str, str]) -> dict[str, Any]:
    ftype = str(f.get("type") or "")
    act = _get(f, "service", "action") or {}
    net = act.get("networkConnectionAction") or {}
    remote = (_get(act, "awsApiCallAction", "remoteIpDetails", "ipAddressV4") or _get(net, "remoteIpDetails", "ipAddressV4")
              or _get((_get(act, "portProbeAction", "portProbeDetails") or [{}])[0], "remoteIpDetails", "ipAddressV4"))
    local = _get(net, "localIpDetails", "ipAddressV4")
    outbound = str(net.get("connectionDirection", "")).upper() == "OUTBOUND"
    inst = _get(f, "resource", "instanceDetails", "instanceId")
    return {"_al_name": ftype, "_al_technique": _gd_technique(ftype, f, fc.get("guardduty") or {}, names),
            "_al_tactic": ftype.split(":", 1)[0], "_al_host": inst or f.get("accountId"),
            "_al_user": _get(f, "resource", "accessKeyDetails", "userName"),
            "_al_src_ip": local if outbound else remote, "_al_dst_ip": remote if outbound else None,
            "_al_sev": f.get("severity"), "_al_id": f.get("id"),
            "_ts": ts_ms(_get(f, "service", "eventFirstSeen") or f.get("createdAt")), "_upd": f.get("updatedAt")}


def securityhub(f: dict[str, Any], fc: dict[str, Any], names: dict[str, str]) -> dict[str, Any] | str:
    sc = fc.get("securityhub") or {}
    if str(_get(f, "RecordState") or "").upper() in (sc.get("skip_record_states") or []) or \
            str(_get(f, "Workflow", "Status") or "").upper() in (sc.get("skip_workflow_status") or []):
        return "archived_or_suppressed"
    types = [str(t) for t in f.get("Types") or []]
    attack = [t for t in types if any(t.startswith(p) for p in sc.get("attack_type_prefixes") or [])]
    if not attack:
        return "posture_finding"
    blob = " ".join(types + [str(f.get("Title") or ""), json.dumps(f.get("ProductFields") or {})])
    tech = (TECH_RE.findall(blob) or [None])[0]
    if tech is None:
        gd = fc.get("guardduty") or {}
        tech = next((str(r["technique"]) for r in gd.get("types") or [] if re.search(str(r["pattern"]), blob)), None)
    parts = attack[0].split("/")
    tactic = parts[1] if parts[0] == "TTPs" and len(parts) > 1 else None
    if tech is None:
        tech = ((sc.get("tactic_default") or {}).get(tactic) if parts[0] == "TTPs"
                else (sc.get("effects") or {}).get(parts[1] if len(parts) > 1 else "") if parts[0] == "Effects"
                else sc.get("unusual_behavior_default"))
    res = f.get("Resources") or [{}]
    rid = str(res[0].get("Id") or "")
    m = INSTANCE_RX.search(rid)
    key = next((_get(r, "Details", "AwsIamAccessKey") for r in res if _get(r, "Details", "AwsIamAccessKey")), {}) or {}
    sev = _get(f, "Severity", "Label") or _get(f, "Severity", "Normalized")
    src = (_get(f, "Network", "SourceIpV4") or _get(f, "Action", "AwsApiCallAction", "RemoteIpDetails", "IpAddressV4")
           or _get(f, "Action", "NetworkConnectionAction", "RemoteIpDetails", "IpAddressV4"))
    return {"_al_name": str(f.get("Title") or f.get("GeneratorId") or attack[0]), "_al_technique": tech,
            "_al_tactic": tactic, "_al_host": m.group(1) if m else f.get("AwsAccountId"),
            "_al_user": key.get("PrincipalName") or key.get("UserName"), "_al_src_ip": src, "_al_dst_ip": None,
            "_al_sev": sev, "_al_id": f.get("Id"), "_ts": ts_ms(f.get("FirstObservedAt") or f.get("CreatedAt")),
            "_upd": f.get("UpdatedAt")}


def ocsf(f: dict[str, Any], fc: dict[str, Any], names: dict[str, str]) -> dict[str, Any]:
    fi = f.get("finding_info") or {}
    attacks = fi.get("attacks") or []
    techs = [_get(a, "sub_technique", "uid") or _get(a, "technique", "uid") for a in attacks]
    res = (f.get("resources") or [{}])[0]
    m = INSTANCE_RX.search(str(res.get("uid") or ""))
    sev = f.get("severity") or (fc.get("ocsf") or {}).get("severity_id", {}).get(f.get("severity_id"))
    return {"_al_name": str(fi.get("title") or f.get("message") or "finding"),
            "_al_technique": next((t for t in techs if t), None),
            "_al_tactic": next((_get(a, "tactic", "name") for a in attacks if _get(a, "tactic", "name")), None),
            "_al_host": m.group(1) if m else _get(f, "cloud", "account", "uid"),
            "_al_user": _get(f, "actor", "user", "name"), "_al_src_ip": _get(f, "src_endpoint", "ip"),
            "_al_dst_ip": _get(f, "dst_endpoint", "ip"), "_al_sev": sev, "_al_id": fi.get("uid"),
            "_ts": ts_ms(fi.get("first_seen_time") or f.get("time")), "_upd": fi.get("modified_time")}


VENDORS = {"guardduty": guardduty, "securityhub": securityhub, "ocsf": ocsf}


def map_finding(f: dict[str, Any], cfg: dict[str, Any]) -> tuple[dict[str, Any] | None, str | None, Any]:
    """-> (raw_alerts row, None, updated) or (None, drop reason, None)."""
    k = kind(f)
    if k is None:
        return None, "not_a_finding", None
    names = {str(v.get("name", "")).lower(): t for t, v in ((cfg.get("attack") or {}).get("techniques") or {}).items()}
    prep = VENDORS[k](f, cfg.get("aws_findings") or {}, names)
    if isinstance(prep, str):
        return None, prep, None
    row, why = map_alert(prep, f"aws_{k}", FIELDS, cfg, prep["_ts"])
    return row, why, prep.get("_upd")


def convert(paths: list[Path], cfg: dict[str, Any]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """All findings under `paths` (files or directories) -> (rows, stats). Latest update per finding id wins."""
    files = sorted(p for x in paths for p in ([x] if x.is_file() else x.rglob("*")) if p.is_file())
    best: dict[Any, tuple[str, dict[str, Any]]] = {}
    drops: Counter[str] = Counter()
    n = 0
    for p in files:
        for f in iter_findings(p):
            n += 1
            if f is None:
                drops["malformed_json"] += 1
                continue
            row, why, upd = map_finding(f, cfg)
            if row is None:
                drops[str(why)] += 1
                continue
            key = row["source_seq"]
            if key in best:
                drops["older_duplicate"] += 1
                if str(upd or "") < best[key][0]:
                    continue
            best[key] = (str(upd or ""), row)
    rows = sorted((r for _, r in best.values()), key=lambda r: (r["ts_ms"], r["source_seq"]))
    stats = {"files": len(files), "findings": n, "rows": len(rows), "dropped": dict(drops),
             "by_vendor": dict(Counter(r["rule_id"].split(":")[1] for r in rows))}
    if n != len(rows) + sum(drops.values()):                 # accounting: every finding is a row or a counted drop
        raise RuntimeError(f"findings accounting mismatch: {stats}")
    return rows, stats


def main(argv: list[str] | None = None) -> int:
    from attacklens.config import load_config

    ap = argparse.ArgumentParser(description="AWS findings -> alert spool (alert-input mode only)")
    ap.add_argument("--in", dest="inp", nargs="+", required=True, type=Path)
    ap.add_argument("--out", type=Path, help="JSONL file (default <integrations spool.alerts_dir>/aws_findings.jsonl)")
    a = ap.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    cfg = load_config()
    rows, stats = convert(list(a.inp), cfg)
    out = a.out or ig.alerts_spool_dir(cfg) / "aws_findings.jsonl"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")
    sys.stdout.write(json.dumps({**stats, "out": out.as_posix()}, indent=1) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
