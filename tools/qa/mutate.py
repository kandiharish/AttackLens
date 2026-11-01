"""White-box mutation smoke for AttackLens (qa_mutation track).

For every mutant in tools/qa/mutants.py: copy backend/attacklens (+ the tests, eval and pyproject.toml) into
data/tmp/qa_mut/<id>/backend/, apply ONE exact text replacement to one module, and run that module's test files
against the copy with a 60 s cap. Outcome:

  killed    pytest rc 1 (a test failed)          survived  pytest rc 0 (every test passed: no test sees it)
  timeout   wall > --timeout (process tree killed) error   invalid mutant (old text missing / syntax error),
                                                            collection/usage error (rc >= 2), or wrong package
A cap hit is triaged from pytest's -q progress line (triage_timeout): an F/E printed before the cap = killed (the
failure happened; the rest of the cap went on reporting / teardown), every test passed ([100%]) = survived (the
process hung at exit), otherwise it stays timeout. `--retriage` re-applies this to stored results.

Extra passes (separate result ids, merged by tools/qa/mutate_report.py):
  <id>+focus  --focus: only the existing suite tests in mutants.FOCUS that read the mutated decision. Used when the
              plain run hit the cap on a contended machine. A failure is a kill by the existing suite; a pass
              proves nothing and leaves the mutant unresolved.
  <id>+qa     --qa-only: only the backend/tests/qa/test_qa_mutants.py tests whose `# kills <ids>` comment names
              the mutant (--with-qa: the module's tests plus the whole QA file).
Re-running a mutant keeps its earlier classifications under "history".
Note: pytest does not honour the argument order of mutants.TESTS (ig10: the node id listed first never ran
inside the cap), so "most targeted first" is a hope, not a guarantee; it changes timings, never a class.

The product package is never touched. Which package the tests import is verified twice per mutant:
  1. conftest-free check: `python -c "import attacklens; print(attacklens.__file__)"` with PYTHONPATH = the copy,
     run from a neutral cwd (proves PYTHONPATH beats the editable install finder);
  2. in-run check: tests/test_000_qa_which.py (written into the COPY only) records attacklens.__file__ from inside
     the pytest process (pytest's rootdir sys.path insertion points at the copy's backend/ too).
A mutant whose run imported anything but its own copy is reported as error, never as killed.

config/, frontend/src/mock/ and tools/ are needed REPO_ROOT-relative (attacklens.config.REPO_ROOT = parents[2]);
they are copied ONCE into data/tmp/qa_mut/_shared/ and linked into each mutant root by directory junction (Windows)
or symlink, so no mutant can write into the real repo. data/cache/sigma is shared the same way (compiled-catalogue
cache). That is safe for the chosen tests: test_sigma*.py compile through sigma_fx.sigma_cfg / compile_docs with a
per-test cache_dir under tmp_path, and the one test_sigma3.py test used (burst) never loads the catalogue. It would
NOT be safe for a test that compiles through the default cache: the cache key ignores the compiler source
(QA-MUT-01), so a sigma_compile mutant would be served the unmutated compile and survive falsely.

Usage (from the repo root):
  .venv/Scripts/python tools/qa/mutate.py --check                 # validate the catalogue, no runs
  .venv/Scripts/python tools/qa/mutate.py --baseline              # unmutated copy per module (must pass)
  .venv/Scripts/python tools/qa/mutate.py [--module link] [--only lk01,lk02] [--timeout 60]
  .venv/Scripts/python tools/qa/mutate.py --retriage | --timeouts | --survivors | --focus | --qa-only
  .venv/Scripts/python tools/qa/mutate_report.py [--json]          # tables for reports/qa/qa_mutation.md
Results: data/tmp/qa_mut/results.json (merged across invocations), summary on stdout.
"""

from __future__ import annotations

import argparse
import ast
import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
sys.path.insert(0, str(HERE))
from mutants import FOCUS, MUTANTS, QA_TESTS, TESTS  # noqa: E402

BACKEND = REPO / "backend"
WORK = REPO / "data" / "tmp" / "qa_mut"
SHARED = WORK / "_shared"
RESULTS = WORK / "results.json"
IGNORE = shutil.ignore_patterns("__pycache__", "*.pyc", ".pytest_cache")
WHICH_TEST = '''"""qa_mutation: record which attacklens package this pytest process imported (copy only)."""
import os
from pathlib import Path

import attacklens


def test_000_qa_which():
    Path(os.environ["QA_WHICH_OUT"]).write_text(str(Path(attacklens.__file__).resolve()), encoding="utf-8")
'''


def python_exe() -> str:
    venv = REPO / ".venv" / "Scripts" / "python.exe"
    return str(venv) if venv.exists() else sys.executable


def _link_dir(link: Path, target: Path) -> None:
    link.parent.mkdir(parents=True, exist_ok=True)
    if os.name == "nt":
        import _winapi
        _winapi.CreateJunction(str(target), str(link))
    else:
        link.symlink_to(target, target_is_directory=True)


def _is_link(p: Path) -> bool:
    return p.is_symlink() or (hasattr(os.path, "isjunction") and os.path.isjunction(p))


def _rm_tree(root: Path) -> None:
    """Remove a mutant root: unlink junctions / symlinks FIRST (never follow them into _shared), then the copy."""
    if not root.exists():
        return
    for p in sorted(root.rglob("*"), key=lambda x: len(x.parts)):
        if _is_link(p):
            os.rmdir(p) if os.name == "nt" else p.unlink()
    shutil.rmtree(root, ignore_errors=True)


def ensure_shared(refresh: bool = False) -> None:
    """One read-only-by-convention copy of the REPO_ROOT-relative inputs the tests read."""
    items = {"config": REPO / "config", "frontend/src/mock": REPO / "frontend" / "src" / "mock",
             "tools": REPO / "tools", "data/cache/sigma": REPO / "data" / "cache" / "sigma"}
    for rel, src in items.items():
        dst = SHARED / rel
        if dst.exists() and not refresh:
            continue
        shutil.rmtree(dst, ignore_errors=True)
        if src.exists():
            ign = shutil.ignore_patterns("__pycache__", "*.pyc", "qa") if rel == "tools" else IGNORE
            shutil.copytree(src, dst, ignore=ign)
        else:
            dst.mkdir(parents=True)


def apply(src: str, m: dict[str, Any]) -> str:
    """Replace the nth occurrence of m['old'] by m['new']; ValueError if absent or (nth=1) ambiguous."""
    n, nth = src.count(m["old"]), int(m.get("nth", 1))
    if n < nth:
        raise ValueError(f"old text found {n}x, need occurrence {nth}")
    if nth == 1 and n > 1 and not m.get("allow_multi"):
        raise ValueError(f"old text ambiguous ({n} occurrences); set nth")
    pos = -1
    for _ in range(nth):
        pos = src.index(m["old"], pos + 1)
    out = src[:pos] + m["new"] + src[pos + len(m["old"]):]
    if out == src:
        raise ValueError("mutation is a no-op")
    ast.parse(out)
    return out


def build(root: Path, m: dict[str, Any] | None) -> Path:
    """Mutant root with backend/{attacklens,tests,eval,pyproject.toml} copies + shared junctions."""
    _rm_tree(root)
    be = root / "backend"
    shutil.copytree(BACKEND / "attacklens", be / "attacklens", ignore=IGNORE)
    shutil.copytree(BACKEND / "tests", be / "tests", ignore=IGNORE)
    shutil.copytree(BACKEND / "eval", be / "eval", ignore=IGNORE)
    shutil.copy2(BACKEND / "pyproject.toml", be / "pyproject.toml")
    (be / "tests" / "test_000_qa_which.py").write_text(WHICH_TEST, encoding="utf-8")
    for rel in ("config", "frontend/src/mock", "tools", "data/cache/sigma"):
        _link_dir(root / rel, SHARED / rel)
    if m is not None:
        f = be / "attacklens" / f"{m['module']}.py"
        f.write_text(apply(f.read_text(encoding="utf-8"), m), encoding="utf-8")
    return be


def _env(be: Path, which_out: Path) -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if not k.startswith(("COVERAGE_", "PYTEST_"))}
    env.update(PYTHONPATH=str(be), PYTHONDONTWRITEBYTECODE="1", QA_WHICH_OUT=str(which_out),
               PYTHONIOENCODING="utf-8", TMP=str(WORK / "_tmp"), TEMP=str(WORK / "_tmp"))
    (WORK / "_tmp").mkdir(parents=True, exist_ok=True)
    return env


def conftest_free_check(be: Path, env: dict[str, str]) -> str:
    out = subprocess.run([python_exe(), "-c", "import attacklens, pathlib; "
                          "print(pathlib.Path(attacklens.__file__).resolve())"],
                         cwd=str(WORK / "_tmp"), env=env, capture_output=True, text=True, timeout=60)
    return out.stdout.strip()


def _kill_tree(pid: int) -> None:
    if os.name == "nt":
        subprocess.run(["taskkill", "/F", "/T", "/PID", str(pid)], capture_output=True)
    else:
        os.killpg(pid, 9)


def run_tests(be: Path, tests: list[str], env: dict[str, str], timeout: float, log: Path) -> tuple[str, int, float]:
    cmd = [python_exe(), "-m", "pytest", "-q", "-x", "-rf", "--no-header", "-p", "no:cacheprovider",
           "-m", "not stress", "tests/test_000_qa_which.py", *tests]
    t0 = time.perf_counter()
    with open(log, "w", encoding="utf-8") as fh:
        p = subprocess.Popen(cmd, cwd=str(be), env=env, stdout=fh, stderr=subprocess.STDOUT,
                             start_new_session=os.name != "nt")
        try:
            rc = p.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            _kill_tree(p.pid)
            p.wait()
            return "timeout", -1, time.perf_counter() - t0
    return "", rc, time.perf_counter() - t0


def first_failure(log: Path) -> str:
    txt = log.read_text(encoding="utf-8", errors="replace") if log.exists() else ""
    m = re.search(r"^(?:FAILED|ERROR) (\S+)", txt, re.M)
    return m.group(1) if m else ""


_PROGRESS = re.compile(r"^([.FEsxX]+)\s*(\[\s*(\d+)%\])?\s*$")


def triage_timeout(log: Path, n_expected: int | None = None) -> tuple[str, str]:
    """A timed-out run is only a real timeout if its tests did not finish. From pytest's -q progress lines:
    an F/E before the cap = killed (a test failed; -x then spent the rest of the cap printing / tearing down);
    every test run and passed ([100%], no F/E) = survived (the process hung at exit under load);
    otherwise timeout. Returns (result, detail)."""
    txt = log.read_text(encoding="utf-8", errors="replace") if log.exists() else ""
    prog, done = "", False
    for line in txt.splitlines():
        if line.startswith("="):
            break
        mo = _PROGRESS.match(line.strip())
        if mo:
            prog += mo.group(1)
            done = done or mo.group(3) == "100"
    if "F" in prog or "E" in prog:
        k = min(i for i in (prog.find("F"), prog.find("E")) if i >= 0)
        hdr = re.search(r"^_{3,} (\S+) _{3,}$", txt, re.M)
        return "killed", (f"failure before the cap (test #{k + 1}"
                          + (f": {hdr.group(1)}" if hdr else "") + "); run then hit the cap")
    if done or (n_expected is not None and len(prog) >= n_expected):
        return "survived", f"all {len(prog)} tests passed before the cap; process hit the cap at exit"
    return "timeout", f"cap hit after {len(prog)} tests, no failure seen"


def tail(log: Path, n: int = 1) -> str:
    lines = [x for x in log.read_text(encoding="utf-8", errors="replace").splitlines() if x.strip()] \
        if log.exists() else []
    return " | ".join(lines[-n:])


QA_FILE = BACKEND / "tests" / "qa" / "test_qa_mutants.py"


def qa_kill_map() -> dict[str, list[str]]:
    """mutant id -> the test_qa_mutants.py tests whose `# kills <ids>` comment names it."""
    out: dict[str, list[str]] = {}
    src = QA_FILE.read_text(encoding="utf-8") if QA_FILE.exists() else ""
    for mo in re.finditer(r"^def (test_\w+)\(.*?# kills ([^\n(]+)", src, re.M):
        for mid in re.findall(r"\b[a-z]{2}\d{2}\b", mo.group(2)):
            out.setdefault(mid, []).append(f"tests/qa/test_qa_mutants.py::{mo.group(1)}")
    return out


def run_one(m: dict[str, Any] | None, module: str, timeout: float, keep: bool,
            with_qa: bool = False, qa_only: bool = False, focus: bool = False) -> dict[str, Any]:
    mid = (m["id"] if m else f"base_{module}") + ("+qa" if with_qa or qa_only else "") + ("+focus" if focus else "")
    root = WORK / mid
    if focus:     # only the existing suite tests that read the mutated decision (FOCUS in mutants.py)
        tests = FOCUS.get((m or {}).get("id", ""), [])
        if not tests:
            return {"id": mid, "module": module, "result": "error", "detail": "no FOCUS entry for this mutant"}
    elif qa_only:   # only the QA tests that claim this mutant (its module tests already passed in the plain run)
        tests = qa_kill_map().get((m or {}).get("id", ""), [])
        if not tests:
            return {"id": mid, "module": module, "result": "error", "detail": "no QA test claims this mutant"}
    else:
        tests = TESTS[module] + (QA_TESTS if with_qa else [])
    res: dict[str, Any] = {"id": mid, "module": module, "op": (m or {}).get("op", "none"),
                           "old": (m or {}).get("old", ""), "new": (m or {}).get("new", ""),
                           "why": (m or {}).get("why", "baseline (no mutation)"), "tests": tests}
    try:
        be = build(root, m)
    except (ValueError, SyntaxError) as exc:
        _rm_tree(root)
        return {**res, "result": "error", "detail": f"invalid mutant: {exc}"}
    which_out = root / "which.txt"
    env = _env(be, which_out)
    pkg = str((be / "attacklens").resolve())
    seen = conftest_free_check(be, env)
    res["conftest_free_file"] = seen
    if not seen.startswith(pkg):
        _rm_tree(root)
        return {**res, "result": "error", "detail": f"conftest-free import resolved to {seen!r}"}
    log = WORK / "logs" / f"{mid}.txt"
    log.parent.mkdir(parents=True, exist_ok=True)
    status, rc, secs = run_tests(be, tests, env, timeout, log)
    in_run = which_out.read_text(encoding="utf-8") if which_out.exists() else ""
    res.update(rc=rc, seconds=round(secs, 1), in_run_file=in_run, log=log.relative_to(REPO).as_posix())
    if status == "timeout":
        res["result"], res["detail"] = triage_timeout(log)
        res["timeout_cap_hit"] = True
        if res["result"] != "timeout" and not in_run.startswith(pkg):
            res["result"], res["detail"] = "error", f"in-run import resolved to {in_run!r} (timeout run)"
    elif not in_run.startswith(pkg):
        res["result"], res["detail"] = "error", f"in-run import resolved to {in_run!r}: {tail(log)}"
    elif rc == 0:
        res["result"], res["detail"] = "survived", tail(log)
    elif rc == 1:
        res["result"], res["detail"] = "killed", first_failure(log) or tail(log)
    else:
        res["result"], res["detail"] = "error", f"pytest rc {rc}: {tail(log, 3)}"
    if not keep:
        _rm_tree(root)
    return res


def load_results() -> dict[str, Any]:
    return json.loads(RESULTS.read_text(encoding="utf-8")) if RESULTS.exists() else {}


def save_results(res: dict[str, Any]) -> None:
    RESULTS.parent.mkdir(parents=True, exist_ok=True)
    RESULTS.write_text(json.dumps(res, indent=1), encoding="utf-8")


def score(results: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Per module: counts and score = killed / (killed + survived + timeout); errors excluded (not valid mutants)."""
    out: dict[str, dict[str, Any]] = {}
    for r in results.values():
        if r["id"].startswith("base_"):
            continue
        suf = "+focus" if r["id"].endswith("+focus") else "+qa" if r["id"].endswith("+qa") else ""
        s = out.setdefault(r["module"] + suf, {"killed": 0, "survived": 0, "timeout": 0, "error": 0})
        s[r["result"]] += 1
    for s in out.values():
        valid = s["killed"] + s["survived"] + s["timeout"]
        s["score_pct"] = round(100.0 * s["killed"] / valid, 1) if valid else None
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--module", action="append", help="limit to module(s)")
    ap.add_argument("--only", help="comma-separated mutant ids")
    ap.add_argument("--timeout", type=float, default=60.0)
    ap.add_argument("--baseline", action="store_true", help="run the unmutated copy per module")
    ap.add_argument("--check", action="store_true", help="validate the catalogue only")
    ap.add_argument("--keep", action="store_true", help="keep mutant dirs")
    ap.add_argument("--refresh-shared", action="store_true")
    ap.add_argument("--with-qa", action="store_true", help="also run backend/tests/qa/test_qa_mutants.py")
    ap.add_argument("--survivors", action="store_true", help="only mutants that survived a previous plain run")
    ap.add_argument("--qa-only", action="store_true",
                    help="run only the test_qa_mutants.py tests whose '# kills' comment names the mutant (+qa ids)")
    ap.add_argument("--retriage", action="store_true",
                    help="re-classify stored timeout results from their logs (no runs)")
    ap.add_argument("--timeouts", action="store_true", help="only mutants whose stored result is timeout")
    ap.add_argument("--focus", action="store_true",
                    help="run only the FOCUS tests of each mutant (+focus ids; a pass leaves it unresolved)")
    a = ap.parse_args(argv)
    if a.retriage:
        results = load_results()
        for r in results.values():
            if r["result"] == "timeout" and r.get("log"):
                r["result"], r["detail"] = triage_timeout(REPO / r["log"])
                r["timeout_cap_hit"] = True
                print(f"{r['id']:<22} {r['result']:<9} {r['detail'][:100]}")
        save_results(results)
        print(json.dumps(score(results), indent=1))
        return 0
    mods = a.module or list(TESTS)
    only = set(a.only.split(",")) if a.only else None
    sel = [m for m in MUTANTS if m["module"] in mods and (only is None or m["id"] in only)]
    if a.check:
        bad = 0
        for m in sel:
            try:
                apply((BACKEND / "attacklens" / f"{m['module']}.py").read_text(encoding="utf-8"), m)
            except (ValueError, SyntaxError) as exc:
                bad += 1
                print(f"BAD {m['id']}: {exc}")
        print(f"{len(sel) - bad}/{len(sel)} mutants valid")
        return 1 if bad else 0
    ensure_shared(a.refresh_shared)
    results = load_results()
    if a.survivors:
        sel = [m for m in sel if (results.get(m["id"]) or {}).get("result") == "survived"]
    if a.timeouts:
        sel = [m for m in sel if (results.get(m["id"]) or {}).get("result") == "timeout"]
    jobs: list[tuple[dict[str, Any] | None, str]] = ([(None, mod) for mod in mods] if a.baseline
                                                      else [(m, m["module"]) for m in sel])
    for m, mod in jobs:
        r = run_one(m, mod, a.timeout, a.keep, a.with_qa, a.qa_only, a.focus)
        r["finished_utc"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        r["timeout_cap_s"] = a.timeout
        prev = results.get(r["id"])
        if prev:   # keep every earlier classification of this mutant (e.g. a 60 s cap hit on a contended machine)
            r["history"] = prev.pop("history", []) + [{k: prev.get(k) for k in
                                                       ("result", "detail", "seconds", "finished_utc", "timeout_cap_s")}]
        results[r["id"]] = r
        save_results(results)
        print(f"{r['id']:<22} {r['result']:<9} {r.get('seconds', '-'):>6}s  {r.get('detail', '')[:110]}", flush=True)
    print(json.dumps(score(results), indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
