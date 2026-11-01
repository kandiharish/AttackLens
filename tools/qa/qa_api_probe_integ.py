"""qa_api probe, part 2: the /api/integrations router (included by api.py) on a running server, harmless requests only.

Every request here is either a read or one the server must refuse BEFORE it touches the shared settings / secrets
(foreign Origin, foreign Host, unknown integration id). The only request that could pass every guard is
POST /api/integrations/qa-no-such-id/stop, which must end in 404 "unknown integration" and changes nothing.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import httpx

CheckFn = Callable[..., bool]
MUTATING = (("PUT", "/api/integrations/webhook"), ("DELETE", "/api/integrations/webhook"),
            ("POST", "/api/integrations/webhook/test"), ("POST", "/api/integrations/webhook/start"),
            ("POST", "/api/integrations/webhook/stop"))
NO_SUCH = "/api/integrations/qa-no-such-id/stop"


def probe_integrations(c: httpx.Client, port: int, check: CheckFn) -> None:
    r = c.get("/api/integrations/catalog")
    cat = r.json() if r.status_code == 200 else None
    check("I01", "GET /api/integrations/catalog 200 JSON", r.status_code == 200 and cat is not None, r.status_code)
    r = c.get("/api/integrations/status")
    check("I02", "GET /api/integrations/status is the status route, not shadowed by /{iid}",
          r.status_code == 200 and "connectors" in r.json(), sorted(r.json()) if r.status_code == 200 else r.status_code)
    r = c.get("/api/integrations/qa-no-such-id")
    check("I03", "GET unknown integration id -> 404 JSON",
          r.status_code == 404 and r.headers["content-type"].startswith("application/json"), r.status_code)
    for method, path in MUTATING:
        r = c.request(method, path, headers={"Origin": "http://evil.example"}, content=b"{}")
        check(f"I04 {method} {path}", f"{method} {path} with Origin evil.example -> 403", r.status_code == 403,
              r.status_code)
        r = c.request(method, path, headers={"Host": "evil.example"}, content=b"{}")
        check(f"I05 {method} {path}", f"{method} {path} with Host evil.example -> 400", r.status_code == 400,
              r.status_code)
    r = c.get("/api/integrations/catalog", headers={"Host": "evil.example"})
    check("I06", "GET catalog with Host evil.example -> 400", r.status_code == 400, r.status_code)
    # The API's own origin (the bundled UI served by this server) must pass the router's origin check, as it passes
    # OriginGuard on every other POST. Harmless: the id is unknown, so a passing guard gives 404 and changes nothing.
    own = f"http://127.0.0.1:{port}"
    r = c.post(NO_SUCH, headers={"Origin": own})
    check("I07", f"POST {NO_SUCH} with the API's own Origin ({own}) passes the guard -> 404 (QA-API-05)",
          r.status_code == 404, r.status_code, 404)
    r = c.post("/api/reload", headers={"Origin": own})
    check("I08", "control: POST /api/reload with the API's own Origin -> 200 (OriginGuard allows own origin)",
          r.status_code == 200, r.status_code)
    for method in ("PUT", "DELETE", "PATCH"):
        r = c.request(method, "/api/qa-nope")
        check(f"I09 {method}", f"{method} /api/qa-nope -> JSON 404 (catch-all)",
              r.status_code == 404 and r.headers["content-type"].startswith("application/json"), r.status_code)


def summary(results: list[dict[str, Any]]) -> dict[str, int]:
    mine = [r for r in results if str(r["id"]).startswith("I")]
    return {"checks": len(mine), "failed": sum(1 for r in mine if not r["ok"])}
