"""Set up and seed a real Splunk container for the live connector tests (no product code used here).

Setup over REST (admin basic auth, verified against the throwaway CA): indexes, token authentication on, one JWT
auth token for the connector, HEC on, two HEC tokens (indexer acknowledgement off / on).
Seed: ECS-JSON lines through HEC /services/collector/event with an explicit `time` (so _time is exact to the ms and
Splunk does no timestamp extraction). Counting uses its own export search, not the product connector.
"""

from __future__ import annotations

import json
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from vhttp import Resp, basic, req

INDEX = "attacklens"          # events the connector pulls
SINK_INDEX = "attacklens_sink"  # incidents the HEC sink writes
APP_SERVER_CONF = """[sslConfig]
serverCert = $SPLUNK_HOME/etc/apps/attacklens_tls/certs/server.pem
"""
APP_INPUTS_CONF = """[http]
serverCert = $SPLUNK_HOME/etc/apps/attacklens_tls/certs/server.pem
"""


def tls_app(dst: Path, bundle: Path) -> Path:
    """Splunk app `attacklens_tls` that points splunkd (8089) and HEC (8088) at our CA-signed cert (cert + key + CA
    in one PEM), packed as dst.tgz for the image's SPLUNK_APPS_URL installer. Returns the .tgz path."""
    import shutil
    import tarfile

    if dst.exists():
        shutil.rmtree(dst)
    (dst / "default").mkdir(parents=True, exist_ok=True)
    (dst / "certs").mkdir(parents=True, exist_ok=True)
    (dst / "default" / "server.conf").write_text(APP_SERVER_CONF, encoding="ascii")
    (dst / "default" / "inputs.conf").write_text(APP_INPUTS_CONF, encoding="ascii")
    (dst / "default" / "app.conf").write_text("[install]\nstate = enabled\n[ui]\nis_visible = false\n",
                                              encoding="ascii")
    (dst / "certs" / "server.pem").write_bytes(bundle.read_bytes())
    tgz = dst.with_suffix(".tgz")
    with tarfile.open(tgz, "w:gz") as tf:
        tf.add(dst, arcname="attacklens_tls")
    return tgz


def iso_ms(ms: int) -> str:
    return datetime.fromtimestamp(ms / 1000, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.") + f"{ms % 1000:03d}Z"


def ecs_line(seq: int, ts_ms: int, run: str) -> str:
    """One ECS JSON event (a failed logon) with a unique al_seq. Every 100th carries generator-style label keys that
    the connector must strip from the spool."""
    d: dict[str, Any] = {"@timestamp": iso_ms(ts_ms), "event": {"action": "user_logon", "outcome": "failure"},
                         "host": {"name": f"ws-live-{seq % 7:02d}"}, "user": {"name": f"user{seq % 11}"},
                         "source": {"ip": f"192.0.2.{seq % 250 + 1}"}, "winlog": {"event_id": 4625},
                         "al_seq": seq, "al_run": run, "message": f"al-live {run} seq={seq:05d}"}
    if seq % 100 == 0:
        d["labels_extra"] = {"planted": True}
        d["threat"] = {"technique": {"id": ["T1110"]}}
    return json.dumps(d, separators=(",", ":"))


def plan(n: int, now_ms: int, tie_at: int) -> list[int]:
    """Timestamps for seq 0..n-1: now-50 min, 5 s apart, seq tie_at shares seq tie_at-1's millisecond."""
    base = now_ms - 50 * 60_000
    ts = [base + i * 5_000 + 137 for i in range(n)]
    ts[tie_at] = ts[tie_at - 1]
    return ts


@dataclass
class Splunk:
    mgmt: str
    hec: str
    password: str
    ca_file: str | None
    verify: bool = True       # False until we know splunkd serves the test CA's cert (see served_test_ca)

    # ---- REST ----------------------------------------------------------------------------------------------------
    def rest(self, method: str, path: str, form: dict[str, Any] | None = None, timeout: float = 60) -> Resp:
        sep = "&" if "?" in path else "?"
        return req(method, f"{self.mgmt}{path}{sep}output_mode=json", headers=basic("admin", self.password),
                   form=form, ca_file=self.ca_file, verify=self.verify, timeout=timeout)

    def ok(self, r: Resp, what: str) -> dict[str, Any]:
        if r.status >= 300:
            raise RuntimeError(f"splunk {what}: HTTP {r.status} {r.text[:300]}")
        return r.json()

    def wait_ready(self, timeout: float = 600) -> None:
        end, last = time.monotonic() + timeout, ""
        while time.monotonic() < end:
            try:
                r = self.rest("GET", "/services/server/info")
                if r.status == 200:
                    return
                last = f"HTTP {r.status}"
            except OSError as exc:
                last = type(exc).__name__ + str(exc)[:120]
            time.sleep(3)
        raise TimeoutError(f"splunkd not ready after {timeout:g}s: {last}")

    def create_index(self, name: str) -> None:
        r = self.rest("POST", "/services/data/indexes", {"name": name})
        if r.status not in (200, 201, 409):
            self.ok(r, f"create index {name}")

    def enable_token_auth(self) -> None:
        self.ok(self.rest("POST", "/services/admin/token-auth/tokens_auth", {"disabled": "false"}), "token auth")

    def create_auth_token(self, audience: str = "attacklens-live") -> str:
        d = self.ok(self.rest("POST", "/services/authorization/tokens",
                              {"name": "admin", "audience": audience, "expires_on": "+3h"}), "create token")
        return str(d["entry"][0]["content"]["token"])

    def enable_hec(self) -> None:
        self.ok(self.rest("POST", "/servicesNS/nobody/splunk_httpinput/data/inputs/http/http",
                          {"disabled": "0", "enableSSL": "1"}), "enable HEC")

    def create_hec_token(self, name: str, ack: bool) -> str:
        d = self.ok(self.rest("POST", "/servicesNS/nobody/splunk_httpinput/data/inputs/http",
                              {"name": name, "index": INDEX, "indexes": f"{INDEX},{SINK_INDEX}",
                               "useACK": "1" if ack else "0"}), f"HEC token {name}")
        return str(d["entry"][0]["content"]["token"])

    def wait_hec(self, timeout: float = 120) -> None:
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            try:
                if req("GET", f"{self.hec}/services/collector/health", ca_file=self.ca_file,
                       verify=self.verify).status == 200:
                    return
            except OSError:
                pass
            time.sleep(2)
        raise TimeoutError("HEC not healthy")

    # ---- seed / count --------------------------------------------------------------------------------------------
    def hec_send(self, token: str, events: list[tuple[int, str]], index: str = INDEX, batch: int = 100) -> None:
        """events: (ts_ms, raw line). Uses the no-ack token; raises on any non-success answer."""
        for i in range(0, len(events), batch):
            body = "".join(json.dumps({"time": f"{ts / 1000:.3f}", "index": index, "host": "al-live-seed",
                                       "source": "al-live-seed", "sourcetype": "attacklens:ecs", "event": line})
                           for ts, line in events[i:i + batch])
            r = req("POST", f"{self.hec}/services/collector/event", raw=body.encode(),
                    headers={"Authorization": f"Splunk {token}",
                             "X-Splunk-Request-Channel": str(uuid.uuid4())},
                    content_type="application/json", ca_file=self.ca_file, verify=self.verify)
            if r.status != 200 or r.json().get("code") != 0:
                raise RuntimeError(f"HEC seed: HTTP {r.status} {r.text[:200]}")

    def count(self, search: str) -> int:
        r = req("POST", f"{self.mgmt}/services/search/jobs/export", headers=basic("admin", self.password),
                form={"search": f"search {search} | stats count", "output_mode": "json", "earliest_time": "0",
                      "latest_time": "+1d"}, ca_file=self.ca_file, verify=self.verify, timeout=120)
        if r.status != 200:
            raise RuntimeError(f"count: HTTP {r.status} {r.text[:200]}")
        n = 0
        for ln in r.text.splitlines():
            if ln.strip():
                obj = json.loads(ln)
                if not obj.get("preview") and isinstance(obj.get("result"), dict):
                    n = int(obj["result"].get("count", 0))
        return n

    def wait_count(self, search: str, n: int, timeout: float = 120) -> float:
        t0 = time.monotonic()
        got = -1
        while time.monotonic() - t0 < timeout:
            got = self.count(search)
            if got == n:
                return round(time.monotonic() - t0, 1)
            if got > n:
                break
            time.sleep(1.5)
        raise AssertionError(f"splunk count for `{search}` is {got}, expected {n}")


def served_test_ca(url: str) -> bool:
    from vhttp import peer_cert_issuer

    host, port = url.split("//", 1)[1].rsplit(":", 1)
    return "attacklens-live test CA" in peer_cert_issuer(host, int(port))


def setup(sp: Splunk) -> dict[str, str]:
    """Indexes, token auth + one auth token, HEC + two HEC tokens. -> {token, hec_noack, hec_ack, tls_app_applied}.
    Waits unverified first; verification is switched on only if BOTH ports serve the test CA's cert."""
    want_ca = sp.ca_file
    sp.verify = False
    sp.wait_ready()
    for ix in (INDEX, SINK_INDEX):
        sp.create_index(ix)
    sp.enable_token_auth()
    tok = sp.create_auth_token()
    sp.enable_hec()
    out = {"token": tok, "hec_noack": sp.create_hec_token("al_live_noack", False),
           "hec_ack": sp.create_hec_token("al_live_ack", True)}
    sp.wait_hec()
    ours = served_test_ca(sp.mgmt) and served_test_ca(sp.hec)
    sp.verify, sp.ca_file = (True, want_ca) if ours else (False, None)
    out["tls_app_applied"] = "yes" if ours else "no"
    return out
