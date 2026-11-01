"""Synthetic multi-cloud attack dataset with ground truth for AttackLens (stdlib only).

    python tools/cloud_attacks/gen.py --size small --out data/raw/cloud_small --seed 7
    python tools/cloud_attacks/gen.py --size 1G    --out data/raw/cloud1      --seed 7

Writes records exactly as the cloud connectors spool them (backend/attacklens/connectors/):
  aws_cloudtrail/cloudtrail/*.jsonl           one CloudTrail event record per line
  azure_monitor/azure_<table>/*.jsonl         Log Analytics rows (dynamic columns decoded, empty columns dropped)
  gcp_logging/gcp_audit/*.jsonl               Cloud Logging LogEntry (protoPayload AuditLog)
plus manifest.json and ground_truth/attacks.json (harness schema, backend/eval/harness.py).

Attack stories are modelled on Datadog Stratus Red Team techniques (https://github.com/DataDog/stratus-red-team,
Apache-2.0) and public incident write-ups; every name, key and IP is fake (IPs from RFC 5737 / RFC 1918).
"""
