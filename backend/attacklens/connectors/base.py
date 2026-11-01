"""Connector base: checkpoint, atomic spool writer, per-cycle accounting, time window.

A connector only implements pull(): an iterator of Record(ts_ms, id, doc), streamed page by page (optionally a
PAGE_END marker after each page / chunk). The base class dedupes against the checkpoint, writes events (JSONL / raw
lines, by detected format) into the events spool, or maps alerts (siem_alerts.map_alert) into the alert spool, and
counts every row: pulled = written + skipped + failed, each with a named reason.

Atomicity: a cycle writes dot-prefixed `.part` files (the live tailer and the alert reader skip them) and renames
them only when the pull finished; then the checkpoint is saved. A failed cycle deletes its part files, keeps the old
checkpoint (the same rows are pulled again next cycle) and counts the rows as failed: cycle_aborted.
`commit_every_pages: N` (opt-in, default 0 = once per cycle) commits spool + checkpoint after every N pages; a later
failure then aborts only the rows since the last commit.

Time window (pull sources; push sources like syslog set PUSH = True and skip it):
- until = now - ingest_lag (default 5m): rows newer than that are not settled in the SIEM index yet. Connectors
  query up to `self.until_ms`; a row returned past it is skipped `after_lag` (pulled again next cycle) and a row
  dated after now is skipped `future_ts`. The checkpoint therefore never moves past now - lag.
- since = checkpoint - overlap (default 10m): the overlap is re-read every cycle so late-indexed rows are pulled;
  rows already written are recognised by id (Checkpoint.recent) and skipped `duplicate`.
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
import uuid
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Iterator

from attacklens import httpc
from attacklens import integrations as ig
from attacklens import profile, siem_alerts
from attacklens.connectors.spool import (MAX_IDS, PAGE_END, Checkpoint, CycleStats, Record,  # noqa: F401
                                         SpoolWriter)
from attacklens.live_tail import read_json, write_json

log = logging.getLogger("attacklens.connect")

MODES = ("events", "alerts")


class AuthError(httpc.HttpError):
    """Credentials rejected (HTTP 401/403) or a token could not be obtained. The message names keys / ids, never
    values. (Credentials that are not configured at all raise PermissionError, like check_auth.)"""

    def __init__(self, msg: str, status: int = 401) -> None:
        super().__init__(msg, status)


class MissingDependency(RuntimeError):
    """An optional library (pip extra) is not installed."""


class Connector(ABC):
    name = "base"
    PUSH = False             # push sources (syslog) have no query window: no lag / overlap / future checks

    def __init__(self, cfg: dict[str, Any], mode: str, since_ms: int | None = None, reset: bool = False) -> None:
        if mode not in MODES:
            raise ValueError(f"mode must be one of {MODES}")
        self.cfg, self.mode = cfg, mode
        self.ccfg: dict[str, Any] = (ig.icfg(cfg).get("connectors") or {}).get(self.name) or {}
        self.mcfg: dict[str, Any] = self.ccfg.get(mode) or {}
        self.key = f"{self.name}_{mode}"
        self.state_path = ig.state_dir(cfg) / f"{self.key}.json"
        if reset:
            self.state_path.unlink(missing_ok=True)
        st = read_json(self.state_path, {})
        self.checkpoint = Checkpoint.from_json(st.get("checkpoint"))
        self.totals: dict[str, int] = {k: int(v) for k, v in (st.get("totals") or {}).items()}
        self.default_since = since_ms if since_ms is not None else \
            ig.now_ms() - ig.parse_duration_ms(self.ccfg.get("default_since", "24h"))
        self.running = self.checkpoint.copy()
        sp = ig.icfg(cfg).get("spool") or {}
        self.max_file_bytes = int(sp.get("max_file_bytes", 256 * 2**20))
        self.strip = ig.label_strip_spec(cfg)
        push = self.PUSH
        self.lag_ms = 0 if push else ig.parse_duration_ms(self.ccfg.get("ingest_lag", "5m"))
        self.overlap_ms = 0 if push else ig.parse_duration_ms(self.ccfg.get("overlap", "10m"))
        self.commit_every = int(self.ccfg.get("commit_every_pages") or 0)
        self.until_ms: int | None = None

    # ---- implemented by vendors ----------------------------------------------------------------------------------
    @abstractmethod
    def pull(self, since_ms: int) -> Iterator[Record]:
        """Stream records with since_ms <= ts <= self.until_ms (order may be ascending or arbitrary). May yield
        PAGE_END after each page / chunk."""

    def event_line(self, rec: Record) -> str | dict[str, Any] | None:
        """Events mode: the raw line (str) or JSON doc (dict) to write. Default: the doc itself."""
        return rec.doc

    def alert_fields(self) -> dict[str, Any]:
        return self.mcfg.get("fields") or {}

    # ---- shared --------------------------------------------------------------------------------------------------
    @property
    def since_ms(self) -> int:
        if self.checkpoint.last_ts_ms is None:
            return self.default_since
        return max(0, self.checkpoint.last_ts_ms - self.overlap_ms)

    def headers(self) -> dict[str, str]:
        return {}

    AUTH_ENV_KEYS: tuple[str, ...] = ("token_env", "api_key_env", "user_env", "password_env")

    def has_credentials(self) -> bool:
        return bool(self.headers())

    def check_auth(self) -> None:
        """Auth configured (an *_env name set) but no credential resolved -> refuse; never call unauthenticated.
        Set the *_env keys to null for a SIEM without auth (e.g. the local mock)."""
        names = [str(self.ccfg[k]) for k in self.AUTH_ENV_KEYS if self.ccfg.get(k)]
        if names and not self.has_credentials():
            raise PermissionError(f"auth env var(s) {', '.join(names)} not set; not calling the SIEM "
                                  f"unauthenticated (set them, or set the *_env keys to null if no auth)")

    def http_json(self, method: str, url: str, payload: Any = None, headers: dict[str, str] | None = None,
                  **kw: Any) -> Any:
        """httpc.request_json with this connector's timeout_s, verify_tls, ca_file and retries (429/502/503/504)."""
        kw.setdefault("timeout", float(self.ccfg.get("timeout_s") or 30))
        return httpc.request_json(method, url, payload, headers, verify_tls=bool(self.ccfg.get("verify_tls", True)),
                                  ca_file=self.ccfg.get("ca_file") or None,
                                  retries=int(self.ccfg.get("retries", 3)), **kw)

    def tls(self) -> dict[str, Any]:
        return {"verify_tls": bool(self.ccfg.get("verify_tls", True)), "ca_file": self.ccfg.get("ca_file") or None}

    def _write_event(self, w: SpoolWriter, out: str | dict[str, Any], ts_ms: int | None,
                     bucket: str = "") -> str | None:
        """Write one event; returns a drop reason instead when there is nothing left to write. Raw lines in a
        format Stage 0 would not recognize are wrapped as {"@timestamp", "message"} so ingest still counts them."""
        if isinstance(out, dict):  # already label-stripped by handle()
            w.write(json.dumps(out, ensure_ascii=False, default=str), bucket or "json")
            return None
        line = str(out).strip()
        fmt = profile.sniff(line, self.cfg.get("sources") or {})
        kind = fmt.get("format", "unrecognized")
        if kind == "json":
            try:
                doc = json.loads(line)
            except ValueError:
                doc = None
            if isinstance(doc, dict):
                doc = ig.strip_labels(doc, *self.strip)
                if not doc:
                    return "empty_event"
                w.write(json.dumps(doc, ensure_ascii=False, default=str), bucket or "json")
                return None
        if kind in ("unrecognized", "csv"):  # a lone CSV line has no header: same treatment
            w.write(json.dumps({"@timestamp": ig.iso_ms(ts_ms), "message": line}, ensure_ascii=False), "json")
            return None
        b = str(fmt.get("source_type") or kind)
        w.write(line, b, "cef" if kind == "cef" else "log")
        return None

    def handle(self, rec: Record, st: CycleStats, w: SpoolWriter) -> None:
        if rec.fail:  # the connector could not decode this row (e.g. a truncated S3 object): counted, not written
            st.fail(rec.fail)
            return
        if self.mode == "events":
            out = self.event_line(rec)
            if isinstance(out, dict):
                out = ig.strip_labels(out, *self.strip)
            if not out:  # None, "" or {} (e.g. a document the SIEM could not parse)
                st.fail("empty_event")
                return
            reason = self._write_event(w, out, rec.ts_ms, rec.bucket)
            if reason:
                st.fail(reason)
                return
        else:
            doc = rec.doc if isinstance(rec.doc, dict) else {"raw": rec.doc}
            row, reason = siem_alerts.map_alert(doc, self.name, self.alert_fields(), self.cfg, rec.ts_ms)
            if row is None:
                st.fail(str(reason))
                return
            w.write(json.dumps(row, ensure_ascii=False))
        st.written += 1

    def spool_root(self) -> Path:
        return ig.events_spool_dir(self.cfg) if self.mode == "events" else ig.alerts_spool_dir(self.cfg)

    def _window_skip(self, ts: int | None, since: int, now: int) -> str | None:
        if ts is None:
            return None
        if ts < since:
            return "before_checkpoint"
        if self.PUSH:
            return None
        if ts > now:
            return "future_ts"
        if self.until_ms is not None and ts > self.until_ms:
            return "after_lag"  # not settled yet: pulled again next cycle
        return None

    def _save_state(self) -> None:
        write_json(self.state_path, {"checkpoint": self.checkpoint.to_json(), "totals": self.totals,
                                     "updated_at": ig.now_iso()})

    def _new_tag(self) -> str:
        # unique per cycle: ms stamp + random suffix (two cycles in one second must never share a file name)
        return time.strftime("%Y%m%dT%H%M%S", time.gmtime()) + f"{int(time.time() * 1000) % 1000:03d}-" \
            f"{uuid.uuid4().hex[:12]}"

    def cycle(self) -> dict[str, Any]:
        """One pull. Returns the cycle stats (also merged into connector_status.json)."""
        t0 = time.perf_counter()
        started = ig.now_iso()
        st = CycleStats()
        tag = self._new_tag()
        w = SpoolWriter(self.spool_root(), self.name, tag, self.max_file_bytes)
        start = self.checkpoint.copy()
        self.running = start.copy()
        now = ig.now_ms()
        self.until_ms = None if self.PUSH else now - self.lag_ms
        since = self.since_ms
        error = None
        files: list[Path] = []
        committed, pages = 0, 0
        try:
            self.check_auth()
            for rec in self.pull(since):
                if rec is PAGE_END:
                    pages += 1
                    if self.commit_every and pages % self.commit_every == 0:
                        files += w.commit()  # all-or-nothing for this chunk; then its checkpoint
                        committed = st.written
                        self.checkpoint = self.running.copy()
                        self._save_state()
                        w = SpoolWriter(self.spool_root(), self.name, f"{tag}-p{pages}", self.max_file_bytes)
                    continue
                st.pulled += 1
                if rec.rid is None:  # no vendor id: content hash is the tie-break id
                    rec.rid = "h:" + hashlib.sha1(json.dumps(rec.doc, sort_keys=True, default=str)
                                                  .encode("utf-8")).hexdigest()[:20]
                reason = self._window_skip(rec.ts_ms, since, now)
                if reason:
                    st.skip(reason)
                    continue
                if start.has(rec.ts_ms, rec.rid) or self.running.has(rec.ts_ms, rec.rid):
                    st.skip("duplicate")
                    continue
                self.handle(rec, st, w)
                self.running.advance(rec.ts_ms, rec.rid)
            files += w.commit()
            self.checkpoint = self.running
        except Exception as exc:  # noqa: BLE001 - recorded, the run loop keeps going
            w.abort()
            error = f"{type(exc).__name__}: {exc}"
            log.warning("connect %s: cycle failed: %s", self.key, error)
            st.fail("cycle_aborted (rows re-pulled next cycle)", st.written - committed)
            st.written = committed
            self.running = self.checkpoint.copy()
        self.checkpoint.prune(self.overlap_ms)
        stats = {**st.to_json(), "started_at": started, "wall_s": round(time.perf_counter() - t0, 3),
                 "ok": error is None, "error": error, "files": [p.name for p in files], "since": ig.iso_ms(since),
                 "until": ig.iso_ms(self.until_ms)}
        for k in ("pulled", "written", "skipped", "failed"):
            self.totals[k] = self.totals.get(k, 0) + int(stats[k])
        self._save_state()
        cp = self.checkpoint.to_json()
        cp.update(ids_at_last_ts=len(self.checkpoint.ids), recent_ids=len(self.checkpoint.recent))
        entry = {"source": self.name, "mode": self.mode, "last_cycle": stats, "totals": dict(self.totals),
                 "checkpoint": cp, "spool_dir": (self.spool_root() / self.name).as_posix()}
        entry["last_pull_at" if error is None else "last_error_at"] = ig.now_iso()
        entry["last_error"] = error
        ig.update_status(self.cfg, "connectors", self.key, entry)
        log.info("connect %s: pulled %d written %d skipped %d failed %d (%.2f s)%s", self.key, st.pulled,
                 stats["written"], stats["skipped"], stats["failed"], stats["wall_s"],
                 f" ERROR {error}" if error else "")
        return stats

    def run(self, once: bool) -> int:
        poll = float(self.ccfg.get("poll_interval_s", 10))
        if once:
            return 0 if self.cycle()["ok"] else 1
        try:
            while True:
                t = time.monotonic()
                self.cycle()
                time.sleep(max(0.1, poll - (time.monotonic() - t)))
        except KeyboardInterrupt:
            log.info("connect %s: stopped", self.key)
        return 0


def require(module: str, extra: str = "cloud") -> Any:
    """Import an optional dependency or raise MissingDependency with the pip command."""
    import importlib
    try:
        return importlib.import_module(module)
    except ImportError:
        raise MissingDependency(f"{module} is not installed; run: pip install \"attacklens[{extra}]\"") from None
