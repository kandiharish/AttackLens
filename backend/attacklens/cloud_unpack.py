"""Stage 0 pre-step: expand native cloud delivery envelopes into one-record-per-line JSON (gap P0-1).

    python -m attacklens.cloud_unpack --raw data/raw/<set> --out data/raw/<set>_unpacked [--link]

Containers are found by magic bytes (never by extension): gzip, bzip2, xz, zip, tar (also tar.gz), nested up to
`max_depth`. JSON content goes through cloud_unpack_env.Unwrapper (Records / records / arrays / pages /
EventBridge / CloudWatch subscription / Pub/Sub / LookupEvents); other text members are copied line by line.
Everything streams: memory is O(chunk + largest record); decompressed bytes per input file are capped
(`max_expand_ratio`, `max_expanded_bytes`: zip / gzip bombs fail with a reason, nothing crashes).

Output per unpacked input file: <out>/<rel>.unwrapped/[m0001-<member>/]<bucket>-0001.jsonl (JSON records) or
.log (text lines), one record per line. Files that need no unwrapping are passthrough: the pipeline profiles them in
place; the CLI copies (or with --link hard-links) them to the same relative path. The accounting
(`unwrap_accounting.json`; the CLI writes <out>/.unwrap/accounting.json, a hidden dir profile skips) lists per
file: records out, text lines out, envelopes, skipped (digest, CONTROL_MESSAGE) and failed with reasons.
No network, no third-party library.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import shutil
import sys
from pathlib import Path
from typing import Any, Callable, Iterator

from attacklens.cloud_unpack_env import Unwrapper
from attacklens.cloud_unpack_io import BZ2, GZIP, XZ, ZIP, ZIP_EMPTY, Unpacker, _is_binary, _is_tar

log = logging.getLogger(__name__)

ACCOUNTING_NAME = "unwrap_accounting.json"
CLI_META = Path(".unwrap") / "accounting.json"
# ---- classification ------------------------------------------------------------------------------------------
def classify(path: Path, ucfg: dict[str, Any], env: Unwrapper | None = None) -> str | None:
    """Why this file needs unwrapping (container, json_array, json_document, an envelope rule), None = passthrough."""
    with path.open("rb") as fh:
        head = fh.read(int(ucfg.get("sniff_bytes", 65536)))
    if head[:2] == GZIP or head[:3] == BZ2 or head[:6] == XZ:
        return "compressed"
    if head[:4] in (ZIP, ZIP_EMPTY):
        return "zip"
    if _is_tar(head):
        return "tar"
    if _is_binary(head):
        return None
    text = head.decode("utf-8", errors="replace").lstrip("\ufeff \t\r\n")
    if text[:1] == "[":
        return "json_array"
    if text[:1] != "{":
        return None
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    if lines and (lines[0] == "{" or lines[0].endswith(("{", "[", ",", ":"))):
        return "json_document"  # pretty-printed
    if len(head) == int(ucfg.get("sniff_bytes", 65536)) and b"\n" not in head.rstrip(b"\r\n"):
        with path.open("rb") as fh:  # one long first line (e.g. a 100-record Event Hub batch): read all of it
            lines = [fh.readline(int(ucfg.get("max_record_chars", 1 << 26))).decode("utf-8", "replace").strip()]
    env = env or Unwrapper(ucfg)
    for ln in lines[: int(ucfg.get("sniff_lines", 10))]:
        try:
            obj = json.loads(ln)
        except ValueError:
            continue
        name = env.envelope_name(obj)
        if name:
            return name
    return None


def unpack_file(path: Path, out_dir: Path, ucfg: dict[str, Any], reason: str = "") -> dict[str, Any]:
    out_dir.mkdir(parents=True, exist_ok=True)
    u = Unpacker(ucfg, out_dir, path.stat().st_size)
    u.run(path)
    res = {"why": reason, "bytes_in": path.stat().st_size, **u.acct.to_json(),
           "outputs": [p.as_posix() for p in u.outputs], "bytes_out": sum(p.stat().st_size for p in u.outputs)}
    if u.acct.failed:
        log.warning("unwrap %s: failed %s", path.name, dict(u.acct.failed))
    return res


def _totals(files: list[dict[str, Any]]) -> dict[str, Any]:
    t: dict[str, Any] = {"files_unpacked": len(files), "records_out": 0, "text_lines_out": 0, "skipped": 0,
                         "failed": 0, "unparsed_chars": 0, "skipped_reasons": {}, "failed_reasons": {}}
    for f in files:
        t["records_out"] += f["records_out"]
        t["text_lines_out"] += f["text_lines_out"]
        t["unparsed_chars"] += f["unparsed_chars"]
        for k, kk in (("skipped", "skipped_reasons"), ("failed", "failed_reasons")):
            for r, n in f[k].items():
                t[k] += n
                t[kk][r] = t[kk].get(r, 0) + n
    return t


def stage(root: Path, stage_dir: Path, ucfg: dict[str, Any],
          skip: Callable[[Path], str | None] | None = None) -> tuple[dict[Path, list[Path]], dict[str, Any]]:
    """Pipeline hook (Stage 0): unpack every envelope file under root into stage_dir.
    Returns ({original path: [unwrapped files]}, accounting); files not in the map are profiled in place."""
    root = Path(root)
    mapping: dict[Path, list[Path]] = {}
    files: list[dict[str, Any]] = []
    env = Unwrapper(ucfg)
    for path in sorted(p for p in root.rglob("*") if p.is_file()):
        if (skip and skip(path)) or path.stat().st_size == 0:
            continue
        try:
            why = classify(path, ucfg, env)
        except OSError as exc:  # unreadable: left to profile (it reports the file)
            log.warning("unwrap: cannot read %s: %s", path, exc)
            continue
        if not why:
            continue
        rel = path.relative_to(root).as_posix()
        try:
            res = unpack_file(path, stage_dir / f"{rel}.unwrapped", ucfg, why)
        except Exception as exc:  # noqa: BLE001 - never crash Stage 0 on a strange file; counted as failed
            log.warning("unwrap %s failed: %s", rel, exc)
            res = {"why": why, "bytes_in": path.stat().st_size, "records_out": 0, "text_lines_out": 0,
                   "envelopes": {}, "containers": {}, "skipped": {}, "notes": {}, "unparsed_chars": 0,
                   "failed": {f"unpack_error ({type(exc).__name__})": 1}, "outputs": [], "bytes_out": 0}
        files.append({"path": rel, **res})
        mapping[path] = [Path(p) for p in res["outputs"]]
    acc = {"raw_dir": root.resolve().as_posix(), "stage_dir": Path(stage_dir).resolve().as_posix(),
           "totals": _totals(files), "files": files}
    if files:
        log.info("unwrap: %s", acc["totals"])
    return mapping, acc


def raw_files(root: Path, stage_dir: Path, out_dir: Path, ucfg: dict[str, Any] | None,
              skip: Callable[[Path], str | None] | None = None) -> Iterator[tuple[Path, str]]:
    """Stage 0 hook: (path, rel) of every raw file in name order, an envelope file replaced by its unwrapped parts
    (rel `<file>!/<part>`). Writes <out_dir>/unwrap_accounting.json (read back by ingest's accounting)."""
    root, stage_dir = Path(root), Path(stage_dir)
    if stage_dir.exists():
        shutil.rmtree(stage_dir)
    staged: dict[Path, list[Path]] = {}
    if ucfg and ucfg.get("enabled", True):
        staged, acc = stage(root, stage_dir, ucfg, skip)
        Path(out_dir).mkdir(parents=True, exist_ok=True)
        (Path(out_dir) / ACCOUNTING_NAME).write_text(json.dumps(acc, indent=2), encoding="utf-8")
    for path in sorted(p for p in root.rglob("*") if p.is_file()):
        rel = path.relative_to(root).as_posix()
        if path not in staged:
            yield path, rel
            continue
        base = stage_dir / f"{rel}.unwrapped"
        for part in staged[path]:
            yield part, f"{rel}!/{part.relative_to(base).as_posix()}"


def unpack_tree(raw: Path, out: Path, ucfg: dict[str, Any], link: bool = False,
                skip: Callable[[Path], str | None] | None = None) -> dict[str, Any]:
    """CLI: mirror raw into out; envelope files become <rel>.unwrapped/..., the rest is copied (or hard-linked).
    Hidden dirs are not copied; `skip`ped files (ground truth, manifest) are copied as-is."""
    raw, out = Path(raw), Path(out)
    if out.resolve() == raw.resolve() or raw.resolve() in out.resolve().parents:
        raise ValueError("--out must not be the raw dir or inside it")
    hidden = lambda p: any(part.startswith(".") for part in p.relative_to(raw).parts[:-1])  # noqa: E731
    mapping, acc = stage(raw, out, ucfg, lambda p: hidden(p) or (skip(p) if skip else None))
    passthrough = 0
    for path in sorted(p for p in raw.rglob("*") if p.is_file()):
        if path in mapping or hidden(path):
            continue
        dst = out / path.relative_to(raw)
        dst.parent.mkdir(parents=True, exist_ok=True)
        if dst.exists():
            dst.unlink()
        if link:
            try:
                os.link(path, dst)
                passthrough += 1
                continue
            except OSError:
                pass
        shutil.copy2(path, dst)
        passthrough += 1
    acc["totals"]["files_passthrough"] = passthrough
    acc["out_dir"] = out.resolve().as_posix()
    meta = out / CLI_META
    meta.parent.mkdir(parents=True, exist_ok=True)
    meta.write_text(json.dumps(acc, indent=2), encoding="utf-8")
    return acc


def find_accounting(raw_dir: str | Path, out_dir: str | Path) -> dict[str, Any] | None:
    """The unwrap accounting of a run: <out>/unwrap_accounting.json (pipeline hook) or <raw>/.unwrap/accounting.json
    (raw dir made by the CLI)."""
    for p in (Path(out_dir) / ACCOUNTING_NAME, Path(raw_dir) / CLI_META):
        if p.exists():
            try:
                acc = json.loads(p.read_text(encoding="utf-8"))
            except ValueError:
                continue
            if p.name == ACCOUNTING_NAME and Path(acc.get("raw_dir", "")) != Path(raw_dir).resolve():
                continue
            return acc
    return None


def accounting_entry(acc: dict[str, Any] | None) -> dict[str, Any] | None:
    """ingest_accounting.json entry `envelope_unwrap`: what the unwrap could not turn into rows (dropped, with
    reasons) and what it skipped on purpose (notes). Unwrapped records are counted under their own source type."""
    t = (acc or {}).get("totals") or {}
    if not t.get("failed") and not t.get("skipped"):
        return None
    n = int(t.get("failed", 0))
    notes = {f"skipped_{r} (not an event record)": k for r, k in (t.get("skipped_reasons") or {}).items()}
    notes["records_out (unwrapped, counted under their source type)"] = int(t.get("records_out", 0))
    notes["text_lines_out"] = int(t.get("text_lines_out", 0))
    if t.get("unparsed_chars"):
        notes["unparsed_chars (after a failure, see drop_reasons)"] = int(t["unparsed_chars"])
    return {"source_type": "envelope_unwrap", "rows_in": n, "rows_ok": 0, "dropped": n,
            "drop_reasons": {f"{r} (envelope unwrap)": k for r, k in (t.get("failed_reasons") or {}).items()},
            "quarantined": 0, "notes": notes,
            "files": [f["path"] for f in acc.get("files", []) if f.get("failed") or f.get("skipped")]}


def main(argv: list[str] | None = None) -> int:
    from attacklens.config import load_config
    from attacklens.profile import _skip
    ap = argparse.ArgumentParser(prog="python -m attacklens.cloud_unpack", description=__doc__.split("\n\n")[0])
    ap.add_argument("--raw", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--link", action="store_true", help="hard-link passthrough files instead of copying them")
    ap.add_argument("--config", default=None)
    a = ap.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    cfg = load_config(Path(a.config) if a.config else None)
    pcfg = (cfg.get("pipeline") or {}).get("profile") or {}
    raw = Path(a.raw)
    acc = unpack_tree(raw, Path(a.out), cfg.get("unwrap") or {}, a.link, lambda p: _skip(p, raw, pcfg))
    log.info("unwrap totals: %s", json.dumps(acc["totals"]))
    return 1 if acc["totals"]["failed"] else 0


if __name__ == "__main__":
    sys.exit(main())
