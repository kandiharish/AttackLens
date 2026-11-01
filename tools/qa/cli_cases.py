"""Black-box CLI robustness cases for `python -m attacklens.run` (QA track qa_cli_blackbox).

Each case builds a hostile raw directory with our own synthetic content (never organiser logs), runs the CLI as a
subprocess and summarises: rc, stderr verdict, which output files exist, accounting totals and drop reasons, and
the number of input lines that no accounting row covers (silent loss).

    python tools/qa/cli_cases.py [--base data/tmp/qa_cli] [--cases a,b] [--fast-config] [--jobs 1]

Writes <base>/results.json and prints one line per case. Used by backend/tests/qa/test_qa_cli.py.
Expected values come from what the case wrote (line counts we generated), never from the product.
"""

from __future__ import annotations

import argparse
import gzip
import json
import os
import random
import re
import shutil
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, Callable

REPO = Path(__file__).resolve().parents[2]
PY = REPO / ".venv" / "Scripts" / "python.exe"
if not PY.exists():
    PY = Path(sys.executable)

BASE_EPOCH = 1793354400  # 2026-10-30T10:00:00Z


# ---------------------------------------------------------------- synthetic lines (hand-written, deterministic)
def fgt(i: int, epoch: int | None = None, day: str | None = None, msg: str | None = None) -> str:
    """One FortiGate traffic line; tz +0000 so date/time == eventtime (UTC)."""
    e = BASE_EPOCH + i if epoch is None else epoch
    t = time.gmtime(e)
    d = day or time.strftime("%Y-%m-%d", t)
    m = f' msg="{msg}"' if msg is not None else ""
    return (f'date={d} time={time.strftime("%H:%M:%S", t)} devname="FGT-QA" devid="FGQA0000000001" '
            f'eventtime={e}000000000 tz="+0000" logid="0000000013" type="traffic" subtype="forward" '
            f'level="notice" vd="root" srcip=10.20.0.{i % 250 + 1} srcport={40000 + i} dstip=198.51.100.7 '
            f'dstport=443 action="accept" policyid=1 service="HTTPS" sentbyte=100 rcvdbyte=200{m}')


def ecs(i: int) -> str:
    ts = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(BASE_EPOCH + i)) + ".000Z"
    return json.dumps({"@timestamp": ts, "event": {"action": "process_created", "outcome": "success"},
                       "host": {"name": "WS-QA-01", "ip": ["10.30.0.5"]}, "user": {"name": "qa_user"},
                       "process": {"name": "cmd.exe", "executable": "C:\\Windows\\System32\\cmd.exe",
                                   "command_line": f"cmd.exe /c echo qa{i}"}}, separators=(",", ":"))


def cef(i: int) -> str:
    ts = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(BASE_EPOCH + i)) + ".000Z"
    return (f"CEF:0|QA|EDR|1.0|{100 + i}|Process start|3|rt={ts} dvchost=ws-qa-02 suser=qa_cef "
            f"act=process_created dproc=cmd.exe externalId={i}")


def syslog(i: int) -> str:
    t = time.gmtime(BASE_EPOCH + i)
    return (f'{time.strftime("%b %d %H:%M:%S", t)} lnx-qa-01 sshd[{1000 + i}]: Failed password for qa_ssh '
            f'from 203.0.113.9 port {50000 + i} ssh2')


def _write_lines(path: Path, lines: list[str], eol: str = "\n", encoding: str = "utf-8", bom: bool = False) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    text = eol.join(lines) + eol
    data = text.encode(encoding)
    if bom:
        data = (b"\xef\xbb\xbf" if encoding == "utf-8" else b"\xff\xfe") + data
    path.write_bytes(data)
    return len(lines)


def count_physical(data: bytes) -> int:
    """Independent count of non-empty physical lines (split on CRLF / LF / CR; space-only lines are blank)."""
    return sum(1 for s in re.split(rb"\r\n|\r|\n", data) if s.strip(b" "))


# ---------------------------------------------------------------- cases
# Builder(root) -> spec: raw, out, args (extra CLI args), lines_in (input lines that must be accounted, None if not
# meaningful e.g. random bytes), usable (bool), rows_ok (expected rows_ok, None = no exact expectation),
# sources ({source_type: rows_ok}), cleanup (optional callable).
Spec = dict[str, Any]


def _spec(root: Path, raw: Path, **kw: Any) -> Spec:
    s: Spec = {"raw": raw, "out": root / "out", "args": [], "usable": True, "lines_in": None, "rows_ok": None,
               "sources": None, "cleanup": None, "note": ""}
    s.update(kw)
    return s


def c_empty_file(root: Path) -> Spec:
    raw = root / "raw"
    raw.mkdir(parents=True)
    (raw / "empty.log").write_bytes(b"")
    return _spec(root, raw, usable=False, lines_in=0)


def c_empty_dir(root: Path) -> Spec:
    raw = root / "raw"
    raw.mkdir(parents=True)
    return _spec(root, raw, usable=False, lines_in=0)


def c_binary_only(root: Path) -> Spec:
    raw = root / "raw"
    raw.mkdir(parents=True)
    (raw / "blob.log").write_bytes(random.Random(7).randbytes(65536))
    return _spec(root, raw, usable=False, lines_in=None)


def _nul(root: Path, n: int) -> Spec:
    raw = root / "raw"
    lines = [fgt(i) for i in range(n)]
    p = raw / "fw.log"
    _write_lines(p, lines)
    with p.open("ab") as fh:
        fh.write(b"\x00" * 8192)  # preallocated tail left by a crash / power loss
    # the NUL run is one more non-empty physical line (it may be dropped, but it must be counted)
    return _spec(root, raw, lines_in=count_physical(p.read_bytes()), rows_ok=n, sources={"fortigate_kv": n},
                 note=f"{n} valid lines + 8 KiB NUL tail (no newline)")


def c_nul_padding_small(root: Path) -> Spec:
    return _nul(root, 10)


def c_nul_padding_large(root: Path) -> Spec:
    return _nul(root, 400)


def c_crlf(root: Path) -> Spec:
    raw = root / "raw"
    n = _write_lines(raw / "fw.log", [fgt(i) for i in range(20)], eol="\r\n")
    return _spec(root, raw, lines_in=n, rows_ok=n, sources={"fortigate_kv": n})


def c_utf16le_bom(root: Path) -> Spec:
    raw = root / "raw"
    n = _write_lines(raw / "fw.log", [fgt(i) for i in range(20)], eol="\r\n", encoding="utf-16-le", bom=True)
    return _spec(root, raw, lines_in=n, rows_ok=None, note="Windows-style UTF-16 LE export (BOM + CRLF)")


def c_utf16le_bom_lf(root: Path) -> Spec:
    raw = root / "raw"
    n = _write_lines(raw / "fw.log", [fgt(i) for i in range(20)], eol="\n", encoding="utf-16-le", bom=True)
    return _spec(root, raw, lines_in=n, rows_ok=None, note="UTF-16 LE, BOM, LF endings")


def c_utf8_bom(root: Path) -> Spec:
    raw = root / "raw"
    n = _write_lines(raw / "fw.log", [fgt(i) for i in range(20)], bom=True)
    return _spec(root, raw, lines_in=n, rows_ok=n, sources={"fortigate_kv": n})


def c_huge_line(root: Path) -> Spec:
    raw = root / "raw"
    lines = [fgt(i) for i in range(10)]
    lines.insert(5, fgt(99, msg="A" * (2 * 1024 * 1024)))
    n = _write_lines(raw / "fw.log", lines)
    return _spec(root, raw, lines_in=n, rows_ok=n, sources={"fortigate_kv": n}, note="one 2 MiB line among 10")


def c_same_ts(root: Path) -> Spec:
    raw = root / "raw"
    n = _write_lines(raw / "fw.log", [fgt(i, epoch=BASE_EPOCH) for i in range(50)])
    return _spec(root, raw, lines_in=n, rows_ok=n, sources={"fortigate_kv": n}, note="50 lines, one timestamp")


def c_future_ts(root: Path) -> Spec:
    raw = root / "raw"
    future = 4070908800  # 2099-01-01T00:00:00Z
    n = _write_lines(raw / "fw.log", [fgt(i, epoch=future + i) for i in range(20)])
    return _spec(root, raw, lines_in=n, rows_ok=None, note="all timestamps in 2099")


def c_mixed_formats(root: Path) -> Spec:
    raw = root / "raw"
    _write_lines(raw / "fw.log", [fgt(i) for i in range(10)])
    _write_lines(raw / "edr.jsonl", [ecs(i) for i in range(10)])
    _write_lines(raw / "feed.cef", [cef(i) for i in range(10)])
    _write_lines(raw / "auth.log", [syslog(i) for i in range(10)])
    return _spec(root, raw, lines_in=40, rows_ok=40,
                 sources={"fortigate_kv": 10, "ecs_json": 10, "cef": 10, "syslog": 10})


def c_unknown_format(root: Path) -> Spec:
    raw = root / "raw"
    n = _write_lines(raw / "notes.log", [f"the quick brown fox number {i} jumps" for i in range(15)])
    return _spec(root, raw, usable=False, lines_in=n)


def c_gzip(root: Path) -> Spec:
    raw = root / "raw"
    raw.mkdir(parents=True)
    body = ("\n".join(fgt(i) for i in range(20)) + "\n").encode()
    (raw / "fw.log.gz").write_bytes(gzip.compress(body, mtime=0))
    return _spec(root, raw, usable=False, lines_in=20, note="gzip of 20 valid FortiGate lines")


def c_hardlink(root: Path) -> Spec:
    raw = root / "raw"
    _write_lines(raw / "a.log", [fgt(i) for i in range(20)])
    os.link(raw / "a.log", raw / "b.log")
    return _spec(root, raw, lines_in=40, rows_ok=40, sources={"fortigate_kv": 40},
                 note="a.log + hard link b.log (documented: duplicates counted)")


def c_symlink(root: Path) -> Spec:
    raw = root / "raw"
    raw.mkdir(parents=True)
    tgt = root / "outside" / "fw.log"
    n = _write_lines(tgt, [fgt(i) for i in range(20)])
    try:
        os.symlink(tgt, raw / "fw.log")
    except OSError as exc:  # Windows without Developer Mode / SeCreateSymbolicLinkPrivilege
        return _spec(root, raw, skip=f"symlink not permitted: {exc}")
    return _spec(root, raw, lines_in=n, rows_ok=n, sources={"fortigate_kv": n})


def c_readonly_out(root: Path) -> Spec:
    raw = root / "raw"
    _write_lines(raw / "fw.log", [fgt(i) for i in range(20)])
    out = root / "out_ro"
    out.mkdir(parents=True)
    user = os.environ.get("USERNAME", "")
    # Windows ignores the read-only attribute on directories: deny add-file / add-subdir / write via ACL instead
    r = subprocess.run(["icacls", str(out), "/deny", f"{user}:(WD,AD,WA,WEA)"], capture_output=True, text=True)
    if r.returncode != 0:
        return _spec(root, raw, out=out, skip=f"icacls failed: {r.stdout.strip()} {r.stderr.strip()}")

    def cleanup() -> None:
        subprocess.run(["icacls", str(out), "/remove:d", user], capture_output=True)

    return _spec(root, raw, out=out, usable=False, lines_in=20, cleanup=cleanup, note="ACL denies writes")


def c_out_is_file(root: Path) -> Spec:
    raw = root / "raw"
    _write_lines(raw / "fw.log", [fgt(i) for i in range(20)])
    out = root / "out_file"
    out.write_text("not a directory\n", encoding="utf-8")
    return _spec(root, raw, out=out, usable=False, lines_in=20)


def c_missing_raw(root: Path) -> Spec:
    root.mkdir(parents=True, exist_ok=True)
    return _spec(root, root / "does_not_exist", usable=False, lines_in=0)


def c_raw_is_file(root: Path) -> Spec:
    p = root / "fw.log"
    n = _write_lines(p, [fgt(i) for i in range(20)])
    # either ingest the file (rows_ok 20) or refuse with a clear message; never rc 0 with the lines unaccounted
    return _spec(root, p, lines_in=n, rows_ok=n, sources={"fortigate_kv": n}, file_or_refuse=True)


def c_spaces_quotes(root: Path) -> Spec:
    # Windows forbids '"' in names; single quote, spaces, brackets, %, &, ; and $ are the hostile set here
    raw = root / "raw dir 'q' [x] %20 & ; $HOME"
    n = _write_lines(raw / "fw 'a'.log", [fgt(i) for i in range(20)])
    return _spec(root, raw, out=root / "out dir 'q' & ;", lines_in=n, rows_ok=n, sources={"fortigate_kv": n})


def c_invalid_utf8_kv(root: Path) -> Spec:
    raw = root / "raw"
    raw.mkdir(parents=True)
    lines = [fgt(i).encode() for i in range(10)]
    lines[4] = fgt(4, msg="bad\x01").encode().replace(b"\x01", b"\xff\xfe\xc3")
    (raw / "fw.log").write_bytes(b"\n".join(lines) + b"\n")
    return _spec(root, raw, lines_in=10, rows_ok=None, note="line 5 has invalid UTF-8 bytes")


def c_from_stage_no_prior(root: Path) -> Spec:
    raw = root / "raw"
    _write_lines(raw / "fw.log", [fgt(i) for i in range(20)])
    return _spec(root, raw, args=["--from-stage", "3"], usable=False, lines_in=None,
                 note="--from-stage 3 with no prior ingest (no events Parquet)")


CASES: dict[str, Callable[[Path], Spec]] = {
    "empty_file": c_empty_file, "empty_dir": c_empty_dir, "binary_only": c_binary_only,
    "nul_padding_small": c_nul_padding_small, "nul_padding_large": c_nul_padding_large, "crlf": c_crlf,
    "utf16le_bom": c_utf16le_bom, "utf16le_bom_lf": c_utf16le_bom_lf, "utf8_bom": c_utf8_bom,
    "huge_line": c_huge_line, "same_ts": c_same_ts, "future_ts": c_future_ts, "mixed_formats": c_mixed_formats,
    "unknown_format": c_unknown_format, "gzip": c_gzip, "hardlink": c_hardlink, "symlink": c_symlink,
    "readonly_out": c_readonly_out, "out_is_file": c_out_is_file, "missing_raw": c_missing_raw,
    "raw_is_file": c_raw_is_file, "spaces_quotes": c_spaces_quotes, "invalid_utf8_kv": c_invalid_utf8_kv,
    "from_stage_no_prior": c_from_stage_no_prior,
}


# ---------------------------------------------------------------- running
def fast_config(dst: Path) -> Path:
    """Copy of config/ with Sigma disabled (Sigma compile dominates tiny runs). Native rules unchanged."""
    import yaml

    dst.mkdir(parents=True, exist_ok=True)
    for p in (REPO / "config").glob("*.yaml"):
        shutil.copy2(p, dst / p.name)
    shutil.copy2(REPO / "config" / "attack_v20.json", dst / "attack_v20.json")
    pipe = yaml.safe_load((dst / "pipeline.yaml").read_text(encoding="utf-8"))
    pipe.setdefault("sigma", {})["enabled"] = False
    (dst / "pipeline.yaml").write_text(yaml.safe_dump(pipe, sort_keys=False), encoding="utf-8")
    return dst


_LOGLINE = re.compile(r"^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d,\d+ (WARNING|ERROR|CRITICAL) (\S+): (.*)$")


def stderr_verdict(stderr: str) -> dict[str, Any]:
    lines = stderr.splitlines()
    has_tb = any(ln.startswith("Traceback (most recent call last)") for ln in lines)
    msgs = [m.group(1) + " " + m.group(3)[:200] for ln in lines if (m := _LOGLINE.match(ln))]
    usage = [ln for ln in lines if ln.startswith("usage:") or ": error:" in ln]
    errs = [m for m in msgs if not m.startswith("WARNING")]
    return {"traceback": has_tb, "messages": (errs + [m for m in msgs if m.startswith("WARNING")])[:8],
            "error_messages": errs[:5], "argparse": usage[:2], "empty": not stderr.strip(),
            "traceback_only": has_tb and not msgs and not usage}


def summarise(spec: Spec, rc: int, stderr: str, wall: float) -> dict[str, Any]:
    out = Path(spec["out"])
    res: dict[str, Any] = {"rc": rc, "wall_s": round(wall, 1), "note": spec.get("note", "")}
    res["stderr"] = stderr_verdict(stderr)
    res["stderr_tail"] = [ln[:240] for ln in stderr.splitlines()[-6:]]
    files = {}
    for name in ("run_metrics.json", "ingest_accounting.json", "source_profile.json", "incidents_index.json"):
        try:
            files[name] = (out / name).is_file()
        except OSError:
            files[name] = False
    res["files"] = files
    acc = None
    if files["ingest_accounting.json"]:
        try:
            acc = json.loads((out / "ingest_accounting.json").read_text(encoding="utf-8"))
        except (OSError, ValueError):
            acc = None
    if acc is not None:
        res["accounting"] = [{k: a.get(k) for k in ("source_type", "rows_in", "rows_ok", "dropped", "drop_reasons")}
                             for a in acc]
        rin = sum(int(a.get("rows_in") or 0) for a in acc)
        rok = sum(int(a.get("rows_ok") or 0) for a in acc)
        res.update(rows_in=rin, rows_ok=rok, dropped=rin - rok,
                   reasons_ok=all(not a.get("dropped") or a.get("drop_reasons") for a in acc),
                   invariant_ok=all(int(a.get("rows_in") or 0) == int(a.get("rows_ok") or 0) + int(a.get("dropped")
                                                                                                    or 0) for a in acc))
    if files["run_metrics.json"]:
        try:
            m = json.loads((out / "run_metrics.json").read_text(encoding="utf-8"))
            res["metrics"] = {k: m.get(k) for k in ("error", "rows_in", "rows_ok", "incidents", "total_wall_s",
                                                    "peak_rss_mb")}
        except (OSError, ValueError):
            pass
    li = spec.get("lines_in")
    res["lines_in"] = li
    if li is not None:
        res["unaccounted"] = li - res.get("rows_in", 0)  # > 0: input lines no accounting row covers
    return res


def verdict(spec: Spec, res: dict[str, Any]) -> tuple[str, list[str]]:
    """pass / fail against the track's expectations; list of reasons for a fail."""
    why: list[str] = []
    sv = res["stderr"]
    if sv["traceback_only"]:
        why.append("traceback is the only stderr output")
    if res["rc"] != 0 and not (sv["error_messages"] or sv["argparse"]):
        why.append(f"rc {res['rc']} without an ERROR message")
    if spec.get("file_or_refuse"):
        if res["rc"] == 0 and res.get("rows_ok") != spec["rows_ok"]:
            why.append(f"rc 0 but rows_ok {res.get('rows_ok')} != {spec['rows_ok']} (file given as --raw ignored)")
    elif spec["usable"]:
        if res["rc"] != 0:
            why.append(f"usable input but rc {res['rc']}")
        if not res["files"]["ingest_accounting.json"] or not res["files"]["run_metrics.json"]:
            why.append("missing run_metrics.json / ingest_accounting.json")
        if spec.get("rows_ok") is not None and res.get("rows_ok") != spec["rows_ok"]:
            why.append(f"rows_ok {res.get('rows_ok')} != expected {spec['rows_ok']}")
        for st, n in (spec.get("sources") or {}).items():
            got = {a["source_type"]: a["rows_ok"] for a in res.get("accounting") or []}.get(st)
            if got != n:
                why.append(f"{st} rows_ok {got} != {n}")
    else:
        if res["rc"] == 0:
            why.append("unusable input but rc 0")
    if res.get("unaccounted") not in (None, 0) and (res["rc"] == 0 or res["files"]["ingest_accounting.json"]):
        why.append(f"accounting rows_in off by {-res['unaccounted']:+d} vs {res['lines_in']} input lines")
    if res.get("reasons_ok") is False:
        why.append("dropped rows without a reason")
    if res.get("invariant_ok") is False:
        why.append("rows_in != rows_ok + dropped")
    return ("fail" if why else "pass"), why


def run_case(name: str, base: Path, config_dir: Path | None = None, timeout: int = 900) -> dict[str, Any]:
    root = base / name
    if root.exists():
        subprocess.run(["icacls", str(root), "/reset", "/T", "/Q"], capture_output=True)
        shutil.rmtree(root, ignore_errors=True)
    root.mkdir(parents=True)
    spec = CASES[name](root)
    if spec.get("skip"):
        return {"case": name, "result": "not_run", "why": [spec["skip"]]}
    cmd = [str(PY), "-m", "attacklens.run", "--raw", str(spec["raw"]), "--out", str(spec["out"]),
           "--parquet", str(root / "pq"), *spec["args"]]
    if config_dir is not None:
        cmd += ["--config", str(config_dir)]
    env = {**os.environ, "PYTHONIOENCODING": "utf-8"}
    t0 = time.perf_counter()
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace",
                           cwd=str(REPO), timeout=timeout, env=env)
        rc, err = p.returncode, p.stderr + p.stdout
    except subprocess.TimeoutExpired as exc:
        rc, err = -999, f"TIMEOUT after {timeout}s\n{exc.stderr or ''}"
    wall = time.perf_counter() - t0
    try:
        res = summarise(spec, rc, err, wall)
        result, why = verdict(spec, res)
    finally:
        if spec.get("cleanup"):
            spec["cleanup"]()
    return {"case": name, "result": result, "why": why, "raw_dir": str(spec["raw"]), "out_dir": str(spec["out"]),
            "parquet_dir": str(root / "pq"), "extra_args": spec["args"], **res, "stderr_full": err[-20000:]}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default=str(REPO / "data" / "tmp" / "qa_cli"))
    ap.add_argument("--cases", default="")
    ap.add_argument("--fast-config", action="store_true", help="Sigma disabled config copy")
    ap.add_argument("--jobs", type=int, default=1)
    ap.add_argument("--results", default="")
    a = ap.parse_args(argv)
    base = Path(a.base).resolve()
    base.mkdir(parents=True, exist_ok=True)
    names = [c for c in a.cases.split(",") if c] or list(CASES)
    cfg = fast_config(base / "_config_fast") if a.fast_config else None
    with ThreadPoolExecutor(max_workers=max(1, a.jobs)) as pool:
        results = list(pool.map(lambda n: run_case(n, base, cfg), names))
    for r in results:
        print(f"{r['case']:22s} {r['result']:8s} rc={r.get('rc')} wall={r.get('wall_s')}s "
              f"in={r.get('rows_in')} ok={r.get('rows_ok')} unacc={r.get('unaccounted')} | {'; '.join(r['why'])}")
    dst = Path(a.results) if a.results else base / ("results_fast.json" if a.fast_config else "results.json")
    dst.write_text(json.dumps({"config": "sigma_off_copy" if cfg else "repo_config", "results": results},
                              indent=2, default=str), encoding="utf-8")
    print(f"results -> {dst}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
