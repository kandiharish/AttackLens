"""Splunk HTTP Event Collector sink: POST <base_url>/services/collector/event, one event per incident.

- Batches are cut by body size (`batch_bytes`, default 800 KB; Splunk's default max_content_length is 1 MB), never
  by count alone (`batch_size` is an extra upper bound).
- HTTP 413 (body too large for this HEC): the batch is split in half and each half retried; a single event that is
  still too large is reported as failed (PartialSend), the others are delivered.
- A single incident still too large on its own is sent as a compact summary (index row, `truncated: true`, a pointer
  to GET /api/incidents/<id>) and logged; only if even that is rejected is it reported as failed.
- Every request carries `X-Splunk-Request-Channel: <uuid4>`, one stable channel per sink kept in the sink state
  (required by HEC when indexer acknowledgement is on). Acks are not polled: a 200 counts as sent.
"""

from __future__ import annotations

import json
import logging
import uuid
from typing import Any

from attacklens import httpc
from attacklens import integrations as ig
from attacklens.connectors import catalog_fields as cf
from attacklens.live_tail import read_json, write_json
from attacklens.sinks import PartialSend

log = logging.getLogger(__name__)

DEFAULT_BATCH_BYTES = 800_000
_PROCESS_CHANNEL = str(uuid.uuid4())  # channel when none is kept on disk (constant for the process)

CATALOG: dict[str, Any] = {
    "id": "splunk_hec", "kind": "sink", "name": "Splunk HTTP Event Collector",
    "docs_url": "https://docs.splunk.com/Documentation/Splunk/latest/Data/UsetheHTTPEventCollector",
    "help": "Minimum permission: an HEC token allowed to write to the target index.",
    "fields": [
        cf.field("base_url", "HEC URL", "url", True, placeholder="https://splunk.example:8088"),
        cf.secret("token", "HEC token", required=True),
        cf.field("index", "Index (optional)", help="Empty = the token's default index."),
        cf.advanced("batch_bytes", "Max request body (bytes)", "number", default=DEFAULT_BATCH_BYTES, min=1024, max=100_000_000),
        *cf.tls_fields(),
    ],
}


def _event(inc: dict[str, Any], scfg: dict[str, Any]) -> str:
    ev: dict[str, Any] = {"time": (ig.to_ms(inc.get("first_ts")) or ig.now_ms()) / 1000,
                          "sourcetype": scfg.get("sourcetype", "attacklens:incident"),
                          "source": "attacklens", "event": inc}
    if scfg.get("index"):
        ev["index"] = scfg["index"]
    return json.dumps(ev, ensure_ascii=False, separators=(",", ":"))


def batches(lines: list[tuple[str, str]], max_bytes: int, max_count: int) -> list[list[tuple[str, str]]]:
    """(id, line) pairs -> batches whose newline-joined body stays <= max_bytes (a lone oversize line gets its own
    batch; the server decides) and <= max_count lines."""
    out: list[list[tuple[str, str]]] = []
    cur: list[tuple[str, str]] = []
    size = 0
    for item in lines:
        n = len(item[1].encode("utf-8")) + 1
        if cur and (size + n > max_bytes or len(cur) >= max_count):
            out.append(cur)
            cur, size = [], 0
        cur.append(item)
        size += n
    if cur:
        out.append(cur)
    return out


def channel(cfg: dict[str, Any], persist: bool = True) -> str:
    """The sink's HEC channel id: a uuid4 created once and kept in <state_dir>/sink_splunk_hec_channel.json, so
    indexer acknowledgement state on the Splunk side survives restarts. Nothing is written when spool.state_dir is
    not configured (a bare cfg would land in the repo default) or with persist=False (connection test): then the
    kept id if there is one, else this process's channel."""
    if not (ig.icfg(cfg).get("spool") or {}).get("state_dir"):
        return _PROCESS_CHANNEL
    path = ig.state_dir(cfg) / "sink_splunk_hec_channel.json"
    st = read_json(path, {})
    ch = st.get("channel") if isinstance(st, dict) else None
    try:
        return str(uuid.UUID(str(ch)))
    except (ValueError, TypeError):
        if not persist:
            return _PROCESS_CHANNEL
        ch = str(uuid.uuid4())
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            write_json(path, {"channel": ch, "created_at": ig.now_iso()})
        except OSError as exc:
            log.warning("sink splunk_hec: cannot keep the channel id (%s); using a per-run channel", exc)
        return ch


def _summary(inc: dict[str, Any], row: dict[str, Any], limit: int) -> dict[str, Any]:
    """Compact incident for an event the HEC body limit rejects: the index row plus a pointer back to AttackLens."""
    return {**row, "id": inc.get("id"), "first_ts": inc.get("first_ts"), "truncated": True,
            "truncated_reason": f"full incident exceeds the HEC body limit (> {limit} bytes); "
                                f"GET /api/incidents/{inc.get('id')} for the full JSON"}


def send(items: list[tuple[dict[str, Any], dict[str, Any]]], scfg: dict[str, Any], cfg: dict[str, Any]) -> int:
    tok = ig.secret(scfg.get("token_env"))
    headers = {"X-Splunk-Request-Channel": channel(cfg)}
    if tok:
        headers["Authorization"] = f"Splunk {tok}"
    url = httpc.join(str(scfg["base_url"]), "/services/collector/event")
    by_id = {str(inc.get("id")): (inc, row) for inc, row in items}
    lines = [(str(inc.get("id")), _event(inc, scfg)) for inc, _ in items]
    sent: list[str] = []
    errors: list[str] = []
    truncated: list[str] = []

    def post(batch: list[tuple[str, str]], shrunk: bool = False) -> None:
        body = "\n".join(ln for _, ln in batch).encode("utf-8")
        try:
            res = httpc.request_json("POST", url, headers=headers, raw_body=body,
                                     timeout=float(scfg.get("timeout_s", 10)),
                                     verify_tls=bool(scfg.get("verify_tls", True)),
                                     ca_file=scfg.get("ca_file") or None, retries=int(scfg.get("retries", 3)))
        except httpc.HttpError as exc:
            if exc.status == 413 and len(batch) > 1:
                half = len(batch) // 2
                post(batch[:half])
                post(batch[half:])
                return
            if exc.status == 413 and not shrunk:  # one event alone is too big: send its compact summary
                iid = batch[0][0]
                inc, row = by_id[iid]
                truncated.append(iid)
                post([(iid, _event(_summary(inc, row, len(body)), scfg))], shrunk=True)
                return
            if exc.status == 413:
                errors.append(f"{batch[0][0]}: even the summary exceeds the HEC body limit ({len(body)} bytes)")
                return
            raise
        if isinstance(res, dict) and res.get("code") not in (None, 0):
            raise httpc.HttpError(f"HEC error code {res.get('code')}: {res.get('text')}")
        sent.extend(i for i, _ in batch)

    max_bytes = max(1024, int(scfg.get("batch_bytes") or DEFAULT_BATCH_BYTES))
    for b in batches(lines, max_bytes, max(1, int(scfg.get("batch_size") or 10_000))):
        try:
            post(b)
        except httpc.HttpError:
            if not sent:
                raise
            raise PartialSend(f"HEC failed after {len(sent)} incident(s)", sent) from None
    if truncated:
        log.warning("sink splunk_hec: %d incident(s) over the HEC body limit sent as summaries: %s", len(truncated),
                    truncated[:5])
    if errors:
        raise PartialSend(f"HEC: {len(errors)} incident(s) not sent, first: {errors[0]}", sent)
    return len(sent)
