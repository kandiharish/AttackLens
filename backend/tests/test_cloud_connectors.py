"""Cloud connectors (aws_cloudtrail, azure_monitor, gcp_logging), the shared cloud auth, and the connector base fixes
(time window, overlap, per-page commit, retries). No real network: httpc.open_url is replaced by an in-process fake
and boto3 by a stub module. Exact counts: pulled == written + skipped + failed, each with a named reason."""

from __future__ import annotations

import contextlib
import copy
import gzip
import io
import json
import socket
import sys
import time
import types
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterator

import pytest

from attacklens import config, httpc
from attacklens import integrations as ig

T0 = 1792807200000  # 2026-10-24T02:00:00Z
SECRET = "CLIENT-SECRET-9b1e77"
SA_PEM = "-----BEGIN PRIVATE KEY-----\nMIIfake\n-----END PRIVATE KEY-----\n"


def iso(ms: int) -> str:
    return ig.iso_ms(ms) or ""


# ----------------------------------------------------------------------------- fixtures
@pytest.fixture(scope="module")
def base_cfg() -> dict[str, Any]:
    return config.load_config()


def make_cfg(base: dict[str, Any], tmp: Path, source: str, **over: Any) -> dict[str, Any]:
    cfg = copy.deepcopy(base)
    ic = cfg["integrations"]
    ic["spool"].update(events_dir=str(tmp / "spool" / "events"), alerts_dir=str(tmp / "spool" / "alerts"),
                       state_dir=str(tmp / "state"), status_file=str(tmp / "state" / "status.json"))
    c = ic["connectors"][source]
    c.update(enabled=True, **over)
    return cfg


def spool_docs(tmp: Path) -> list[tuple[str, dict[str, Any]]]:
    root = tmp / "spool" / "events"
    out = []
    for p in sorted(root.rglob("*")) if root.exists() else []:
        if p.is_file() and not p.name.startswith("."):
            out += [(p.parent.name, json.loads(ln)) for ln in p.read_text(encoding="utf-8").splitlines() if ln]
    return out


def accounted(st: dict[str, Any]) -> None:
    assert st["pulled"] == st["written"] + st["skipped"] + st["failed"], st
    assert st["skipped"] == sum(st["skipped_reasons"].values()) and st["failed"] == sum(st["failed_reasons"].values())


class FakeHTTP:
    """Replaces httpc.open_url. routes: (url substring, handler(method, url, body, headers) -> (status, payload,
    headers)). Every request is recorded."""

    def __init__(self) -> None:
        self.routes: list[tuple[str, Callable[..., tuple[int, Any, dict[str, str]]]]] = []
        self.calls: list[dict[str, Any]] = []

    def route(self, part: str, fn: Callable[..., tuple[int, Any, dict[str, str]]]) -> None:
        self.routes.append((part, fn))

    @contextlib.contextmanager
    def __call__(self, method: str, url: str, body: bytes | None = None, headers: dict[str, str] | None = None,
                 timeout: float = 30.0, verify_tls: bool = True, ca_file: str | None = None) -> Iterator[Any]:
        self.calls.append({"method": method, "url": url, "body": body, "headers": dict(headers or {}),
                           "timeout": timeout})
        for part, fn in self.routes:
            if part in url:
                status, payload, hdrs = fn(method, url, body, headers or {})
                break
        else:
            status, payload, hdrs = 404, {"error": "no route"}, {}
        text = payload if isinstance(payload, str) else json.dumps(payload)
        if status >= 400:
            raise httpc.HttpError(f"{method} {httpc.safe_url(url)} -> HTTP {status}", status, text,
                                  httpc.parse_retry_after(hdrs.get("Retry-After")))
        yield io.BytesIO(text.encode("utf-8"))


@pytest.fixture
def http(monkeypatch: pytest.MonkeyPatch) -> FakeHTTP:
    fake = FakeHTTP()
    monkeypatch.setattr(httpc, "open_url", fake)
    sleeps: list[float] = []
    monkeypatch.setattr(httpc, "_sleep", sleeps.append)
    fake.sleeps = sleeps  # type: ignore[attr-defined]
    return fake


def get(source: str, cfg: dict[str, Any], mode: str = "events", since: int = T0 - 60_000):
    from attacklens import connectors
    return connectors.get(source, cfg, mode, since)


# ----------------------------------------------------------------------------- Azure (Log Analytics)
LA_COLS = ["TimeGenerated", "Type", "_ItemId", "AlId", "OperationName", "ResultType", "UserPrincipalName",
           "IPAddress", "ConditionalAccessStatus", "OperationNameValue", "ActivityStatusValue", "Caller",
           "InitiatedBy"]


def la_rows() -> list[list[Any]]:
    """3 rows at ONE timestamp (100 ns precision) + 1 later; mixed tables."""
    ts = "2026-10-24T02:00:00.1234567Z"
    def r(t, typ, iid, **kv):
        d = {c: None for c in LA_COLS}
        d.update(TimeGenerated=t, Type=typ, _ItemId=iid, AlId=iid, **kv)
        return [d[c] for c in LA_COLS]
    return [r(ts, "SigninLogs", "a1", OperationName="Sign-in activity", ResultType="0",
              UserPrincipalName="alice@contoso.com", IPAddress="198.51.100.7", ConditionalAccessStatus="notApplied"),
            r(ts, "SigninLogs", "a2", OperationName="Sign-in activity", ResultType="50126",
              UserPrincipalName="bob@contoso.com", IPAddress="198.51.100.66", ConditionalAccessStatus="notApplied"),
            r(ts, "AuditLogs", "a3", OperationName="Add user",
              InitiatedBy='{"user": {"userPrincipalName": "alice@contoso.com"}}'),
            r("2026-10-24T02:00:05Z", "AzureActivity", "a4", OperationNameValue="MICROSOFT.COMPUTE/VM/WRITE",
              ActivityStatusValue="Success", Caller="alice@contoso.com")]


class LAServer:
    """Fake token endpoint + Log Analytics query API with keyset paging on AlId."""

    def __init__(self, http: FakeHTTP, rows: list[list[Any]] | None = None, page: int = 2) -> None:
        self.rows, self.page, self.tokens, self.queries = rows or la_rows(), page, 0, []
        self.reject_token: str | None = None   # a token value the API answers 401 for
        self.fail_next: list[tuple[int, dict[str, str]]] = []
        self.token_status = 200
        http.route("login.microsoftonline.com", self.token)
        http.route("api.loganalytics", self.query)

    def token(self, method, url, body, headers):
        form = dict(p.split("=", 1) for p in body.decode().split("&"))
        if self.token_status != 200:
            return self.token_status, {"error": "invalid_client", "error_codes": [7000215],
                                       "error_description": f"Invalid client secret provided {form['client_secret']}"}, {}
        assert form["grant_type"] == "client_credentials" and "loganalytics" in form["scope"]
        self.tokens += 1
        return 200, {"access_token": f"tok-{self.tokens}", "expires_in": 3599, "token_type": "Bearer"}, {}

    def query(self, method, url, body, headers):
        if self.fail_next:
            st, h = self.fail_next.pop(0)
            return st, {"error": {"code": "TooManyRequests"}}, h
        if headers.get("Authorization") == f"Bearer {self.reject_token}":
            return 401, {"error": {"code": "InvalidTokenError"}}, {}
        q = json.loads(body)["query"]
        self.queries.append(q)
        rows = self.rows
        if "AlId > " in q:
            last = q.split('AlId > "', 1)[1].split('"', 1)[0]
            rows = [r for r in rows if r[3] > last]
        cols = [{"name": c, "type": "string"} for c in LA_COLS]
        return 200, {"tables": [{"name": "PrimaryResult", "columns": cols, "rows": rows[: self.page]}]}, {}


def azure_cfg(base, tmp, monkeypatch, **over):
    monkeypatch.setenv("AL_T_AZ_SECRET", SECRET)
    return make_cfg(base, tmp, "azure_monitor", workspace_id="ws-1", workspace_id_env=None, tenant_id="tid-1",
                    tenant_id_env=None, client_id="cid-1", client_id_env=None, client_secret_env="AL_T_AZ_SECRET",
                    page_size=2, **over)


def test_azure_keyset_paging_through_one_timestamp_buckets_per_table(base_cfg, tmp_path, http, monkeypatch) -> None:
    srv = LAServer(http, page=2)
    conn = get("azure_monitor", azure_cfg(base_cfg, tmp_path, monkeypatch))
    st = conn.cycle()
    assert st["ok"], st
    accounted(st)
    assert (st["pulled"], st["written"]) == (4, 4)
    assert len(srv.queries) == 3 and srv.tokens == 1                      # one sign-in for all pages
    assert "union isfuzzy=true AzureActivity, SigninLogs, AuditLogs" in srv.queries[0]
    assert "{after}" not in srv.queries[0] and "AlId >" not in srv.queries[0]
    # page 2 continues after (full-precision ts, last id): three rows at one timestamp never get stuck
    assert 'datetime(2026-10-24T02:00:00.1234567Z)' in srv.queries[1] and 'AlId > "a2"' in srv.queries[1]
    docs = spool_docs(tmp_path)
    assert {b for b, _ in docs} == {"azure_signinlogs", "azure_auditlogs", "azure_azureactivity"}
    audit = next(d for b, d in docs if b == "azure_auditlogs")
    assert audit["InitiatedBy"]["user"]["userPrincipalName"] == "alice@contoso.com"   # dynamic column decoded
    assert "AlId" not in audit and "ResultType" not in audit                           # helper + empty columns gone
    assert SECRET not in json.dumps(st) + "".join(json.dumps(d) for _, d in docs)


def test_azure_checkpoint_overlap_dedupes_and_late_row_is_written(base_cfg, tmp_path, http, monkeypatch) -> None:
    srv = LAServer(http, page=10)
    cfg = azure_cfg(base_cfg, tmp_path, monkeypatch)
    assert get("azure_monitor", cfg).cycle()["written"] == 4
    state = json.loads((tmp_path / "state" / "azure_monitor_events.json").read_text(encoding="utf-8"))
    assert state["checkpoint"]["last_ts_ms"] == T0 + 5000
    # a late-indexed row dated BEFORE the checkpoint (inside the overlap window) appears
    late = la_rows()[3][:]
    late[0], late[2], late[3] = "2026-10-24T02:00:03Z", "a35", "a35"
    srv.rows = sorted(srv.rows + [late], key=lambda r: (r[0], r[3]))
    st = get("azure_monitor", cfg).cycle()                                  # new instance: state from disk
    accounted(st)
    assert st["written"] == 1 and st["skipped_reasons"] == {"duplicate": 4}, st
    assert iso(T0 + 5000 - 600_000) in srv.queries[-1]                      # since = checkpoint - overlap (10m)


def test_azure_token_cached_then_refreshed_before_expiry(base_cfg, tmp_path, http, monkeypatch) -> None:
    from attacklens.connectors import cloud_auth
    srv = LAServer(http, page=10)
    now = [1_000_000.0]
    monkeypatch.setattr(cloud_auth, "_clock", lambda: now[0])
    conn = get("azure_monitor", azure_cfg(base_cfg, tmp_path, monkeypatch))
    conn.cycle()
    conn.cycle()
    assert srv.tokens == 1                                                   # cached across cycles
    now[0] += 3599 - 300 - 1
    conn.cycle()
    assert srv.tokens == 1                                                   # still > 5 min left
    now[0] += 2
    conn.cycle()
    assert srv.tokens == 2                                                   # refreshed 5 min before expiry


def test_azure_401_refreshes_token_once_then_succeeds(base_cfg, tmp_path, http, monkeypatch) -> None:
    srv = LAServer(http, page=10)
    srv.reject_token = "tok-1"                                               # first token revoked server-side
    st = get("azure_monitor", azure_cfg(base_cfg, tmp_path, monkeypatch)).cycle()
    assert st["ok"] and st["written"] == 4 and srv.tokens == 2, st


def test_azure_persistent_401_is_a_clear_counted_error(base_cfg, tmp_path, http, monkeypatch) -> None:
    srv = LAServer(http, page=10)
    srv.reject_token = "tok-1"
    http.routes.insert(0, ("api.loganalytics", lambda *a: (401, {"error": {"code": "InvalidTokenError"}}, {})))
    st = get("azure_monitor", azure_cfg(base_cfg, tmp_path, monkeypatch)).cycle()
    assert not st["ok"] and "HTTP 401" in st["error"] and "token refresh" in st["error"], st
    assert st["written"] == 0 and spool_docs(tmp_path) == [] and srv.tokens == 2


def test_azure_bad_client_secret_names_ids_not_secret(base_cfg, tmp_path, http, monkeypatch) -> None:
    srv = LAServer(http)
    srv.token_status = 401
    st = get("azure_monitor", azure_cfg(base_cfg, tmp_path, monkeypatch)).cycle()
    assert not st["ok"] and "sign-in rejected (HTTP 401 invalid_client AADSTS7000215)" in st["error"], st
    assert "tid-1" in st["error"] and "cid-1" in st["error"] and SECRET not in st["error"]
    status = (tmp_path / "state" / "status.json").read_text(encoding="utf-8")
    assert SECRET not in status


def test_azure_429_backs_off_with_retry_after(base_cfg, tmp_path, http, monkeypatch) -> None:
    srv = LAServer(http, page=10)
    srv.fail_next = [(429, {"Retry-After": "7"}), (503, {})]
    st = get("azure_monitor", azure_cfg(base_cfg, tmp_path, monkeypatch)).cycle()
    assert st["ok"] and st["written"] == 4, st
    assert http.sleeps[0] == 7.0 and len(http.sleeps) == 2                  # Retry-After honoured, then jitter


def test_azure_429_beyond_retries_fails_the_cycle(base_cfg, tmp_path, http, monkeypatch) -> None:
    srv = LAServer(http, page=10)
    srv.fail_next = [(429, {})] * 10
    st = get("azure_monitor", azure_cfg(base_cfg, tmp_path, monkeypatch, retries=2)).cycle()
    assert not st["ok"] and "HTTP 429" in st["error"] and len(http.sleeps) == 2


def test_azure_missing_secret_refuses_to_call(base_cfg, tmp_path, http, monkeypatch) -> None:
    srv = LAServer(http)
    cfg = azure_cfg(base_cfg, tmp_path, monkeypatch)
    monkeypatch.delenv("AL_T_AZ_SECRET")
    st = get("azure_monitor", cfg).cycle()
    assert not st["ok"] and "AL_T_AZ_SECRET" in st["error"] and http.calls == [] and srv.tokens == 0


def test_sentinel_signs_in_with_client_credentials(base_cfg, tmp_path, http, monkeypatch) -> None:
    srv = LAServer(http, page=10)
    monkeypatch.setenv("AL_T_AZ_SECRET", SECRET)
    monkeypatch.delenv("SENTINEL_TOKEN", raising=False)
    cfg = make_cfg(base_cfg, tmp_path, "sentinel", workspace_id="ws-1", workspace_id_env=None, tenant_id="tid-1",
                   tenant_id_env=None, client_id="cid-1", client_id_env=None, client_secret_env="AL_T_AZ_SECRET",
                   token_env="AL_T_UNSET_TOKEN", page_size=10)
    cfg["integrations"]["connectors"]["sentinel"]["events"]["raw_field"] = None
    st = get("sentinel", cfg).cycle()
    assert st["ok"] and srv.tokens == 1 and st["pulled"] == 4, st
    assert http.calls[-1]["headers"]["Authorization"] == "Bearer tok-1"
    assert "/v1/workspaces/ws-1/query" in http.calls[-1]["url"]


def test_sentinel_static_token_overrides_client_credentials(base_cfg, tmp_path, http, monkeypatch) -> None:
    srv = LAServer(http, page=10)
    monkeypatch.setenv("AL_T_STATIC", "static-tok-123")
    cfg = make_cfg(base_cfg, tmp_path, "sentinel", workspace_id="ws-1", workspace_id_env=None,
                   client_secret_env=None, token_env="AL_T_STATIC", page_size=10)
    st = get("sentinel", cfg).cycle()
    assert st["ok"] and srv.tokens == 0
    assert http.calls[-1]["headers"]["Authorization"] == "Bearer static-tok-123"


# ----------------------------------------------------------------------------- GCP
def sa_json() -> str:
    return json.dumps({"type": "service_account", "project_id": "acme-prod", "private_key_id": "k1",
                       "private_key": SA_PEM, "client_email": "reader@acme-prod.iam.gserviceaccount.com",
                       "token_uri": "https://oauth2.googleapis.com/token"})


def gcp_entries() -> list[dict[str, Any]]:
    return [{"insertId": f"g{i}", "logName": "projects/acme-prod/logs/cloudaudit.googleapis.com%2Factivity",
             "timestamp": iso(T0 + i * 1000), "protoPayload": {"methodName": "SetIamPolicy", "status": {}},
             "resource": {"labels": {"project_id": "acme-prod"}}, "labels": {"team": "x"}} for i in range(5)]


class GCPServer:
    def __init__(self, http: FakeHTTP, page: int = 2) -> None:
        self.entries, self.page, self.tokens, self.bodies = gcp_entries(), page, 0, []
        http.route("oauth2.googleapis.com/token", self.token)
        http.route("logging.googleapis.com/v2/entries:list", self.list)

    def token(self, method, url, body, headers):
        form = dict(p.split("=", 1) for p in body.decode().split("&"))
        assert form["grant_type"] == "urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer"
        header, claims, sig = form["assertion"].split(".")
        pad = lambda s: s + "=" * (-len(s) % 4)  # noqa: E731
        import base64
        c = json.loads(base64.urlsafe_b64decode(pad(claims)))
        assert c["iss"] == "reader@acme-prod.iam.gserviceaccount.com" and c["aud"].endswith("/token")
        assert c["scope"] == "https://www.googleapis.com/auth/logging.read" and c["exp"] - c["iat"] == 3600
        assert base64.urlsafe_b64decode(pad(sig)) == b"signed"
        self.tokens += 1
        return 200, {"access_token": f"g-tok-{self.tokens}", "expires_in": 3599}, {}

    def list(self, method, url, body, headers):
        b = json.loads(body)
        self.bodies.append(b)
        start = int(b.get("pageToken") or 0)
        out: dict[str, Any] = {"entries": self.entries[start:start + self.page]}
        if start + self.page < len(self.entries):
            out["nextPageToken"] = str(start + self.page)
        return 200, out, {}


def gcp_cfg(base, tmp, monkeypatch, **over):
    from attacklens.connectors import cloud_auth, gcp_logging
    monkeypatch.setenv("AL_T_GCP_SA", sa_json())
    monkeypatch.setattr(cloud_auth, "sign_rs256", lambda pem, data: b"signed")
    monkeypatch.setattr(gcp_logging, "_sleep", lambda s: None)
    return make_cfg(base, tmp, "gcp_logging", project_ids=["acme-prod"], service_account_json_env="AL_T_GCP_SA",
                    page_size=2, **over)


def test_gcp_pages_with_next_page_token_and_window_filter(base_cfg, tmp_path, http, monkeypatch) -> None:
    srv = GCPServer(http, page=2)
    conn = get("gcp_logging", gcp_cfg(base_cfg, tmp_path, monkeypatch))
    st = conn.cycle()
    assert st["ok"] and (st["pulled"], st["written"]) == (5, 5), st
    accounted(st)
    assert len(srv.bodies) == 3 and srv.tokens == 1
    b = srv.bodies[0]
    assert b["resourceNames"] == ["projects/acme-prod"] and b["orderBy"] == "timestamp asc" and b["pageSize"] == 2
    assert b["filter"].startswith('logName:"cloudaudit.googleapis.com" AND timestamp>="')
    assert f'timestamp<="{iso(conn.until_ms)}"' in b["filter"]               # bounded by now - ingest_lag
    assert [x.get("pageToken") for x in srv.bodies] == [None, "2", "4"]
    docs = spool_docs(tmp_path)
    assert {bk for bk, _ in docs} == {"gcp_audit"} and all("labels" not in d for _, d in docs)  # strip_keys
    assert get("gcp_logging", gcp_cfg(base_cfg, tmp_path, monkeypatch)).cycle()["written"] == 0  # checkpoint


def test_gcp_invalid_key_is_clear_and_never_echoed(base_cfg, tmp_path, http, monkeypatch) -> None:
    GCPServer(http)
    cfg = gcp_cfg(base_cfg, tmp_path, monkeypatch)
    monkeypatch.setenv("AL_T_GCP_SA", '{"type": "service_account", "private_key": "SUPERSECRETKEY"')
    st = get("gcp_logging", cfg).cycle()
    assert not st["ok"] and "not valid JSON" in st["error"] and "SUPERSECRET" not in st["error"]


def test_gcp_missing_cryptography_names_the_extra(monkeypatch) -> None:
    from attacklens.connectors import cloud_auth
    from attacklens.connectors.base import MissingDependency
    for mod in ("cryptography", "cryptography.hazmat", "cryptography.hazmat.primitives",
                "cryptography.hazmat.primitives.asymmetric"):
        monkeypatch.setitem(sys.modules, mod, None)   # also hides an installed [cloud] extra
    with pytest.raises(MissingDependency, match=r'pip install "attacklens\[cloud\]"'):
        cloud_auth.sign_rs256(SA_PEM, b"x")


# ----------------------------------------------------------------------------- AWS (boto3 stub)
class FakeClientError(Exception):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.response = {"Error": {"Code": code, "Message": "x"}}


def ct_event(i: int, ts_ms: int) -> dict[str, Any]:
    rec = {"eventVersion": "1.09", "eventTime": iso(ts_ms).replace(".000Z", "Z"), "eventSource": "iam.amazonaws.com",
           "eventName": "CreateUser", "eventID": f"e{i}", "recipientAccountId": "111122223333",
           "userIdentity": {"userName": "alice"}, "sourceIPAddress": "203.0.113.10"}
    return {"EventId": f"e{i}", "EventName": "CreateUser",
            "EventTime": datetime.fromtimestamp(ts_ms / 1000, tz=timezone.utc), "CloudTrailEvent": json.dumps(rec)}


class FakeAWS:
    def __init__(self) -> None:
        self.events = [ct_event(i, T0 + i * 1000) for i in range(5)]
        self.calls: list[dict[str, Any]] = []
        self.sessions: list[dict[str, Any]] = []
        self.clients: list[tuple[str, dict[str, Any]]] = []
        self.error: str | None = None
        self.objects: dict[str, tuple[datetime, bytes]] = {}

    def module(self) -> types.ModuleType:
        aws = self

        class Client:
            def __init__(self, service: str) -> None:
                self.service = service

            def lookup_events(self, **kw: Any) -> dict[str, Any]:
                aws.calls.append(kw)
                if aws.error:
                    raise FakeClientError(aws.error)
                lo, hi = kw["StartTime"], kw["EndTime"]
                hits = [e for e in aws.events if lo <= e["EventTime"] <= hi][::-1]   # newest first, like AWS
                start = int(kw.get("NextToken") or 0)
                out: dict[str, Any] = {"Events": hits[start:start + 2]}
                if start + 2 < len(hits):
                    out["NextToken"] = str(start + 2)
                return out

            def list_objects_v2(self, **kw: Any) -> dict[str, Any]:
                aws.calls.append(kw)
                return {"Contents": [{"Key": k, "LastModified": lm} for k, (lm, _) in aws.objects.items()
                                     if k.startswith(kw["Prefix"])], "IsTruncated": False}

            def get_object(self, Bucket: str, Key: str) -> dict[str, Any]:
                return {"Body": io.BytesIO(aws.objects[Key][1])}

        class Session:
            def __init__(self, **kw: Any) -> None:
                aws.sessions.append(kw)

            def client(self, service: str, config: Any = None, **kw: Any) -> Client:
                aws.clients.append((service, kw))
                return Client(service)

        boto3 = types.ModuleType("boto3")
        boto3.session = types.SimpleNamespace(Session=Session)  # type: ignore[attr-defined]
        return boto3


@pytest.fixture
def aws(monkeypatch: pytest.MonkeyPatch) -> FakeAWS:
    from attacklens.connectors import aws_cloudtrail
    fake = FakeAWS()
    bconf = types.ModuleType("botocore.config")
    bconf.Config = lambda **kw: kw  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "boto3", fake.module())
    monkeypatch.setitem(sys.modules, "botocore", types.ModuleType("botocore"))
    monkeypatch.setitem(sys.modules, "botocore.config", bconf)
    monkeypatch.setattr(aws_cloudtrail, "_sleep", lambda s: None)
    monkeypatch.setenv("AL_T_AK", "AKIAEXAMPLE")
    monkeypatch.setenv("AL_T_SK", "aws-secret-xyz")
    return fake


def aws_cfg(base, tmp, **over):
    cfg = make_cfg(base, tmp, "aws_cloudtrail", access_key_id_env="AL_T_AK", secret_access_key_env="AL_T_SK",
                   session_token_env=None, min_call_interval_s=0, **over)
    cfg["integrations"]["connectors"]["aws_cloudtrail"]["events"]["window"] = "30d"
    return cfg


def test_aws_lookup_pages_and_checkpoints(base_cfg, tmp_path, aws) -> None:
    st = get("aws_cloudtrail", aws_cfg(base_cfg, tmp_path)).cycle()
    assert st["ok"] and (st["pulled"], st["written"]) == (5, 5), st
    accounted(st)
    assert aws.sessions[0]["aws_access_key_id"] == "AKIAEXAMPLE" and aws.sessions[0]["region_name"] == "us-east-1"
    assert aws.clients[0] == ("cloudtrail", {})                              # no endpoint_url: boto3 regional default
    assert [c.get("NextToken") for c in aws.calls[:3]] == [None, "2", "4"]
    docs = spool_docs(tmp_path)
    assert {b for b, _ in docs} == {"cloudtrail"} and sorted(d["eventID"] for _, d in docs) == [f"e{i}" for i in range(5)]
    assert get("aws_cloudtrail", aws_cfg(base_cfg, tmp_path)).cycle()["written"] == 0


def test_aws_auth_error_is_clear(base_cfg, tmp_path, aws) -> None:
    aws.error = "UnrecognizedClientException"
    st = get("aws_cloudtrail", aws_cfg(base_cfg, tmp_path)).cycle()
    assert not st["ok"] and "authentication / authorization failed (UnrecognizedClientException)" in st["error"]
    assert "aws-secret-xyz" not in st["error"]


def test_aws_missing_boto3_names_the_extra(base_cfg, tmp_path, aws, monkeypatch) -> None:
    monkeypatch.setitem(sys.modules, "boto3", None)
    st = get("aws_cloudtrail", aws_cfg(base_cfg, tmp_path)).cycle()
    assert not st["ok"] and 'pip install "attacklens[cloud]"' in st["error"], st


def test_aws_s3_reads_gzip_records_in_last_modified_order(base_cfg, tmp_path, aws) -> None:
    def obj(i: int, lm_ms: int) -> tuple[datetime, bytes]:
        recs = [json.loads(ct_event(i * 10 + j, T0)["CloudTrailEvent"]) for j in range(2)]
        return datetime.fromtimestamp(lm_ms / 1000, tz=timezone.utc), gzip.compress(json.dumps({"Records": recs}).encode())
    aws.objects = {"AWSLogs/2026/10/24/b.json.gz": obj(1, T0 + 60_000), "AWSLogs/2026/10/24/a.json.gz": obj(2, T0 + 120_000),
                   "AWSLogs/2026/10/24/old.json.gz": obj(3, T0 - 3_600_000),
                   "AWSLogs/2026/10/24/CloudTrail-Digest/d.json.gz": obj(4, T0 + 90_000),
                   "AWSLogs/2026/10/24/again.json.gz": obj(1, T0 + 180_000)}       # e10/e11 delivered twice
    cfg = aws_cfg(base_cfg, tmp_path)
    cfg["integrations"]["connectors"]["aws_cloudtrail"]["events"].update(source="s3", s3_bucket="trail",
                                                                         s3_prefix="AWSLogs/{yyyy}/{mm}/{dd}/")
    st = get("aws_cloudtrail", cfg).cycle()
    accounted(st)
    assert st["ok"] and st["written"] == 4, st                               # old object is before the window
    assert st["skipped_reasons"] == {"duplicate": 2}, st                     # re-delivered eventIDs (no digest)
    assert [c["Prefix"] for c in aws.calls][0] == "AWSLogs/2026/10/24/"       # day prefixes of the window only
    assert [d["eventID"] for _, d in spool_docs(tmp_path)] == ["e10", "e11", "e20", "e21"]


def test_aws_s3_endpoint_from_the_form_endpoint_url(base_cfg, tmp_path, aws) -> None:
    """S3 mode: the form's endpoint_url reaches the S3 client (LocalStack / S3-compatible); s3_endpoint_url wins;
    neither set -> no endpoint_url kwarg (real AWS unchanged)."""
    from attacklens.connectors.aws_cloudtrail import AwsCloudTrailConnector
    ls = "http://127.0.0.1:4566"
    for over, want in (({}, {}), ({"endpoint_url": ls}, {"endpoint_url": ls}),
                       ({"endpoint_url": ls, "s3_endpoint_url": "http://s3.local:9000"},
                        {"endpoint_url": "http://s3.local:9000"})):
        aws.clients.clear()
        cfg = aws_cfg(base_cfg, tmp_path, endpoint_url=None, s3_endpoint_url=None)
        cfg["integrations"]["connectors"]["aws_cloudtrail"].update(over)
        cfg["integrations"]["connectors"]["aws_cloudtrail"]["events"].update(source="s3", s3_bucket="trail",
                                                                             s3_prefix="AWSLogs/{yyyy}/{mm}/{dd}/")
        st = AwsCloudTrailConnector(cfg, "events", T0 - 60_000).cycle()
        assert st["ok"], st
        assert aws.clients == [("s3", want)], (over, aws.clients)


# ----------------------------------------------------------------------------- base: window, overlap, commits
def fake_connector(rows: list[Any], fail_after_pages: int | None = None):
    from attacklens.connectors.base import PAGE_END, Connector, Record

    class Fake(Connector):
        name = "elastic"  # reuse a configured connector block

        def pull(self, since_ms: int) -> Iterator[Record]:
            for i, page in enumerate(rows):
                if fail_after_pages is not None and i >= fail_after_pages:
                    raise httpc.HttpError("boom", 500)
                for ts, rid in page:
                    yield Record(ts, rid, {"@timestamp": iso(ts), "id": rid})
                yield PAGE_END
    return Fake


def test_future_and_unsettled_rows_are_counted_and_never_move_checkpoint(base_cfg, tmp_path) -> None:
    now = ig.now_ms()
    C = fake_connector([[(T0, "a"), (now - 60_000, "b"), (now + 3_600_000, "c")]])
    conn = C(make_cfg(base_cfg, tmp_path, "elastic", api_key_env=None, user_env=None, password_env=None),
             "events", T0 - 1000)
    st = conn.cycle()
    accounted(st)
    assert st["written"] == 1 and st["skipped_reasons"] == {"after_lag": 1, "future_ts": 1}, st
    assert conn.checkpoint.last_ts_ms == T0 and conn.checkpoint.last_ts_ms <= conn.until_ms


def test_commit_every_page_keeps_committed_pages_after_a_failure(base_cfg, tmp_path) -> None:
    pages = [[(T0, "a"), (T0 + 1, "b")], [(T0 + 2, "c")], [(T0 + 3, "d")]]
    cfg = make_cfg(base_cfg, tmp_path, "elastic", api_key_env=None, user_env=None, password_env=None,
                   commit_every_pages=1)
    conn = fake_connector(pages, fail_after_pages=2)(cfg, "events", T0 - 1000)
    st = conn.cycle()
    accounted(st)
    assert not st["ok"] and st["written"] == 3 and conn.checkpoint.last_ts_ms == T0 + 2, st
    assert sorted(d["id"] for _, d in spool_docs(tmp_path)) == ["a", "b", "c"]
    st2 = fake_connector(pages)(cfg, "events", T0 - 1000).cycle()            # resume from the committed page
    assert st2["ok"] and st2["written"] == 1 and st2["skipped_reasons"] == {"duplicate": 3}, st2


def test_default_cycle_stays_all_or_nothing(base_cfg, tmp_path) -> None:
    cfg = make_cfg(base_cfg, tmp_path, "elastic", api_key_env=None, user_env=None, password_env=None,
                   commit_every_pages=0)
    conn = fake_connector([[(T0, "a")], [(T0 + 1, "b")]], fail_after_pages=1)(cfg, "events", T0 - 1000)
    st = conn.cycle()
    assert not st["ok"] and st["written"] == 0 and spool_docs(tmp_path) == []
    assert st["failed_reasons"] == {"cycle_aborted (rows re-pulled next cycle)": 1} and conn.checkpoint.last_ts_ms is None


# ----------------------------------------------------------------------------- httpc, splunk, elastic, syslog units
def test_httpc_scrub_and_retry_rules(monkeypatch) -> None:
    text = 'Bearer abcdef123456 {"client_secret": "s3cr3t-v4lue", "x": "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkw"}'
    out = httpc.scrub(text, ["mysecretvalue"])
    assert "abcdef123456" not in out and "s3cr3t" not in out and "eyJhbGci" not in out
    assert httpc.parse_retry_after("12") == 12.0 and httpc.parse_retry_after("soon") is None
    calls = []
    monkeypatch.setattr(httpc, "_sleep", calls.append)

    def boom(status: int):
        def f():
            calls.append(status)
            raise httpc.HttpError("x", status)
        return f
    with pytest.raises(httpc.HttpError):
        httpc.with_retries(boom(500), retries=3)
    assert calls == [500]                                                    # 500 is not retried
    calls.clear()
    with pytest.raises(httpc.HttpError):
        httpc.with_retries(boom(503), retries=2)
    assert [c for c in calls if c == 503] == [503, 503, 503] and len(calls) == 5


def test_splunk_chunks_and_auth_scheme(base_cfg, tmp_path, monkeypatch) -> None:
    from attacklens.connectors.splunk import SplunkConnector
    monkeypatch.setenv("AL_T_SPL", "spl-tok")
    cfg = make_cfg(base_cfg, tmp_path, "splunk", token_env="AL_T_SPL", auth_scheme="Splunk", chunk="15m",
                   max_chunks_per_cycle=4)
    c = SplunkConnector(cfg, "events", T0)
    assert c.headers() == {"Authorization": "Splunk spl-tok"}
    ch = c.chunks(T0, T0 + 30 * 60_000 - 1)
    assert ch == [(T0, T0 + 900_000), (T0 + 900_000, T0 + 1_800_000)]
    big = c.chunks(T0, T0 + 86_400_000)
    assert len(big) <= 4 and big[0][0] == T0 and big[-1][1] == T0 + 86_400_001
    assert all(a[1] == b[0] for a, b in zip(big, big[1:]))                  # contiguous, no gap
    assert c.rid({"_cd": "1:2", "index": "main", "splunk_server": "s1"}, "_cd") == "s1|main|1:2"


def test_elastic_api_key_and_cloud_id() -> None:
    import base64
    from attacklens.connectors.elastic import api_key_header, cloud_id_url
    encoded = base64.b64encode(b"test-id:not-a-real-key").decode()
    assert api_key_header(encoded) == "ApiKey " + encoded                    # already encoded: used as is
    assert api_key_header("id1:key1") == "ApiKey " + base64.b64encode(b"id1:key1").decode()
    cid = "dep:" + base64.b64encode(b"eu-west-1.aws.found.io:443$abc123$kib456").decode()
    assert cloud_id_url(cid) == "https://abc123.eu-west-1.aws.found.io"
    with pytest.raises(ValueError):
        cloud_id_url("garbage")


def test_syslog_tcp_octet_counting_and_udp_single_reader(base_cfg, tmp_path) -> None:
    from attacklens.connectors.syslog import SyslogConnector, cef_date_ms
    cfg = make_cfg(base_cfg, tmp_path, "syslog", udp_port=0, tcp_port=0)
    c = SyslogConnector(cfg, "events")
    bound = dict(c.start())
    try:
        msg1 = "<134>Oct 24 02:00:00 fw app: hello\nwith newline"
        msg2 = "<134>Oct 24 02:00:01 fw app: second"
        frame = "".join(f"{len(m.encode())} {m}" for m in (msg1, msg2)) + "<134>Oct 24 02:00:02 fw app: plain\n"
        with socket.create_connection(("127.0.0.1", bound["tcp"]), timeout=5) as s:
            s.sendall(frame.encode())
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as u:
            for i in range(20):
                u.sendto(f"<134>Oct 24 02:00:03 fw app: udp {i}".encode(), ("127.0.0.1", bound["udp"]))
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and len(c.buf.lines) < 23:
            time.sleep(0.05)
        lines = list(c.buf.lines)
    finally:
        c.stop()
    assert "<134>Oct 24 02:00:00 fw app: hello with newline" in lines         # one frame, one line
    assert "<134>Oct 24 02:00:01 fw app: second" in lines and "<134>Oct 24 02:00:02 fw app: plain" in lines
    assert sum(1 for ln in lines if " udp " in ln) == 20
    assert cef_date_ms("Oct 24 2026 02:00:00.250 UTC") == T0 + 250
    assert cef_date_ms("Oct 24 2026 07:30:00 +05:30") == T0
    assert cef_date_ms(str(T0)) == T0


def test_catalogs_are_complete_and_secret_typed() -> None:
    from attacklens import connectors
    from attacklens.integrations_status import catalog
    for sid in connectors.SOURCES:
        cat = connectors.catalog(sid)
        assert cat["id"] == sid and cat["docs_url"].startswith("https://") and cat["help"]
        keys = [f["key"] for f in cat["fields"]]
        assert len(keys) == len(set(keys))
        for f in cat["fields"]:
            secretish = any(w in f["key"] for w in ("secret", "token", "password", "api_key", "access_key", "json"))
            if secretish and not f["key"].endswith(("_uri", "_url")):
                assert f["type"] == "secret", (sid, f["key"])
            if f["key"] in ("base_url", "login_url", "token_uri", "endpoint_url") and sid in connectors.CLOUD_SOURCES:
                assert f.get("advanced") and not f.get("required") and not f.get("default"), (sid, f)
    by_id = {e["id"]: e for e in catalog()}
    assert {"aws_cloudtrail", "azure_monitor", "gcp_logging"} <= set(by_id)
    assert all(by_id[s]["kind"] == "cloud" for s in connectors.CLOUD_SOURCES)
    assert [f["key"] for f in by_id["azure_monitor"]["fields"] if f.get("required")] == \
        ["tenant_id", "client_id", "client_secret", "workspace_id"]


# ----------------------------------------------------------------------------- vendor-doc review fixes
def test_aws_s3_prefix_template_account_from_sts_and_no_full_listing(base_cfg, tmp_path, aws) -> None:
    from attacklens.connectors.aws_cloudtrail import AwsCloudTrailConnector
    cfg = aws_cfg(base_cfg, tmp_path)
    cfg["integrations"]["connectors"]["aws_cloudtrail"]["events"].update(source="s3", s3_bucket="trail")
    c = AwsCloudTrailConnector(cfg, "events", T0)
    c.client = lambda service: types.SimpleNamespace(get_caller_identity=lambda: {"Account": "999988887777"})
    pre = c._prefixes(T0, T0 + 86_400_000)
    assert pre == ["AWSLogs/999988887777/CloudTrail/us-east-1/2026/10/24/",
                   "AWSLogs/999988887777/CloudTrail/us-east-1/2026/10/25/"]
    assert c._skip_key("x/CloudTrail-Digest/a.json.gz") and c._skip_key("x/CloudTrail-Insight/a.json.gz")
    assert not c._skip_key("x/CloudTrail/a.json.gz")
    cfg["integrations"]["connectors"]["aws_cloudtrail"]["events"]["s3_prefix"] = "AWSLogs/"
    with pytest.raises(ValueError, match="never the whole bucket"):
        AwsCloudTrailConnector(cfg, "events", T0)._prefixes(T0, T0 + 1)
    from attacklens.connectors.aws_cloudtrail import CATALOG
    assert "kms:Decrypt" in CATALOG["help"]


def test_loganalytics_sends_prefer_wait_and_uses_the_azure_com_host(base_cfg, tmp_path, http, monkeypatch) -> None:
    LAServer(http, page=10)
    cfg = azure_cfg(base_cfg, tmp_path, monkeypatch)
    cfg["integrations"]["connectors"]["azure_monitor"]["timeout_s"] = None      # -> default 180
    get("azure_monitor", cfg).cycle()
    q = [c for c in http.calls if "/query" in c["url"]][-1]
    assert q["url"].startswith("https://api.loganalytics.azure.com/v1/workspaces/ws-1/query")
    assert q["headers"]["Prefer"] == "wait=175" and q["timeout"] == 180.0
    tok = [c for c in http.calls if "oauth2" in c["url"]][-1]
    assert b"scope=https%3A%2F%2Fapi.loganalytics.io%2F.default" in tok["body"]


def test_elastic_refuses_doc_tiebreak_without_pit(base_cfg, tmp_path, http, monkeypatch) -> None:
    cfg = make_cfg(base_cfg, tmp_path, "elastic", api_key_env=None, user_env=None, password_env=None,
                   use_pit=False, base_url="http://es.invalid:9200")
    cfg["integrations"]["connectors"]["elastic"]["events"]["tiebreak_field"] = "_doc"
    st = get("elastic", cfg).cycle()
    assert not st["ok"] and "tiebreak_field is _doc" in st["error"] and http.calls == []


def test_elastic_cloud_id_rpartition_and_es_port() -> None:
    import base64
    from attacklens.connectors.elastic import cloud_id_url
    enc = base64.b64encode(b"us-east-1.aws.found.io$es9:9243$kb1").decode()
    assert cloud_id_url(f"my:deploy:{enc}") == "https://es9.us-east-1.aws.found.io:9243"


def test_gcp_logview_names_cap_and_or_filter_grouped() -> None:
    from attacklens.connectors.gcp_logging import resource_names
    view = "projects/p1/locations/global/buckets/_Default/views/_AllLogs"
    assert resource_names({"resource_names": [view]}) == [view]
    with pytest.raises(ValueError, match="at most 100"):
        resource_names({"project_ids": [f"p{i}" for i in range(101)]})
    from attacklens.connectors.gcp_logging import GcpLoggingConnector
    c = GcpLoggingConnector.__new__(GcpLoggingConnector)
    c.mcfg, c.until_ms = {"filter": 'logName:"a" OR logName:"b"'}, T0
    assert c.query_filter(T0 - 1000).startswith('(logName:"a" OR logName:"b") AND timestamp>=')


def test_syslog_octet_detection_reads_digits_not_peek() -> None:
    from attacklens.connectors.syslog import _read_octet_count

    class Slow(io.BufferedReader):
        def peek(self, n: int = 0) -> bytes:   # a peek that returns 1 byte only (legal for BufferedReader)
            return super().peek(1)[:1]
    def rd(b: bytes):
        return Slow(io.BytesIO(b))
    assert _read_octet_count(rd(b"123 <134>x")) == (b"", 123)
    r = rd(b"2026-10-24T02:00:00Z host app: msg\n")
    pre, n = _read_octet_count(r)
    assert n is None and pre + r.readline() == b"2026-10-24T02:00:00Z host app: msg\n"   # nothing lost
    assert _read_octet_count(rd(b"12345678901 <x"))[1] is None                    # > 10 digits: not a length
    assert _read_octet_count(rd(b"5 hello\n"))[1] is None                          # no PRI after the space
    assert _read_octet_count(rd(b"")) == (None, None)


def test_syslog_cef_sink_rfc5424_header() -> None:
    import re as _re
    from attacklens.sinks.syslog_cef import lines_for
    inc = {"id": "inc-1", "risk": 95, "first_ts": iso(T0), "last_ts": iso(T0), "tactics": ["Impact"],
           "backbone": [{"step": 1, "technique_id": "T1486", "tactic": "Impact", "severity": 50, "ts": iso(T0)}]}
    lines = lines_for(inc, {"hosts": ["h1"]}, {"hostname": "al-host"})
    assert _re.match(r"^<162>1 \d{4}-\d\d-\d\dT[0-9:.]+Z al-host AttackLens - - - CEF:0\|Mitigata\|", lines[0])
    assert lines[1].startswith("<164>1 ")                                          # local4 warning (sev 5)
    assert lines_for(inc, {}, {"facility": "local7"})[0].startswith("<186>1 ")     # 23*8 + 2
    with pytest.raises(ValueError):
        lines_for(inc, {}, {"facility": "nope"})


def _hec_items(n: int, pad: int = 0) -> list[tuple[dict[str, Any], dict[str, Any]]]:
    return [({"id": f"inc-{i}", "risk": 50, "first_ts": iso(T0), "blob": "x" * pad}, {"id": f"inc-{i}", "risk": 50})
            for i in range(n)]


def test_hec_channel_stable_byte_batches_413_split_and_summary(base_cfg, tmp_path, http, monkeypatch) -> None:
    from attacklens.sinks import splunk_hec
    monkeypatch.setenv("AL_T_HEC", "hec-tok")
    cfg = make_cfg(base_cfg, tmp_path, "elastic")
    limit = {"n": 2500}
    bodies: list[tuple[str, int]] = []

    def hec(method, url, body, headers):
        bodies.append((headers["X-Splunk-Request-Channel"], len(body)))
        if len(body) > limit["n"]:
            return 413, {"text": "Content request too large", "code": 413}, {}
        return 200, {"text": "Success", "code": 0}, {}
    http.route("/services/collector/event", hec)
    scfg = {"base_url": "https://hec.example:8088", "token_env": "AL_T_HEC", "batch_bytes": 4000}
    assert splunk_hec.send(_hec_items(6, 400), scfg, cfg) == 6
    chans = {c for c, _ in bodies}
    assert len(chans) == 1 and all(n <= 4000 for _, n in bodies)                   # byte-cut batches, one channel
    assert any(n > 2500 for _, n in bodies)                                         # a 413 happened and was split
    assert splunk_hec.send(_hec_items(1), scfg, cfg) == 1
    assert {c for c, _ in bodies} == chans                                          # channel kept in sink state
    assert json.loads((tmp_path / "state" / "sink_splunk_hec_channel.json").read_text())["channel"] in chans
    bodies.clear()
    assert splunk_hec.send(_hec_items(1, 5000), scfg, cfg) == 1                     # alone > limit -> summary
    assert len(bodies) == 2 and bodies[-1][1] < 2500
    limit["n"] = 10                                                                 # even the summary is too big
    from attacklens.sinks import PartialSend
    with pytest.raises(PartialSend, match="even the summary"):
        splunk_hec.send(_hec_items(1), scfg, cfg)


def test_elastic_bulk_api_key_op_type_and_409(base_cfg, tmp_path, http, monkeypatch) -> None:
    import base64
    from attacklens.sinks import elastic_bulk
    monkeypatch.setenv("AL_T_ES", "kid:ksecret")
    seen: list[dict[str, Any]] = []

    def bulk(method, url, body, headers):
        lines = [json.loads(x) for x in body.decode().splitlines()]
        seen.append({"auth": headers["Authorization"], "ops": [next(iter(x)) for x in lines[::2]]})
        items = [{"create": {"_id": "inc-0", "status": 409, "error": {"type": "version_conflict_engine_exception"}}},
                 {"create": {"_id": "inc-1", "status": 201}}]
        return 200, {"errors": True, "items": items}, {}
    http.route("/_bulk", bulk)
    scfg = {"base_url": "https://es.example:9200", "api_key_env": "AL_T_ES", "index": "logs-attacklens-default",
            "op_type": "auto"}
    assert elastic_bulk.send(_hec_items(2), scfg, make_cfg(base_cfg, tmp_path, "elastic")) == 2   # 409 = stored
    assert seen[0]["auth"] == "ApiKey " + base64.b64encode(b"kid:ksecret").decode()
    assert seen[0]["ops"] == ["create", "create"]                                   # data stream -> create
    assert elastic_bulk.op_type({"op_type": "auto"}, "attacklens-incidents") == "index"
    assert elastic_bulk.op_type({"op_type": "create"}, "attacklens-incidents") == "create"
    with pytest.raises(ValueError):
        elastic_bulk.op_type({"op_type": "upsert"}, "x")
