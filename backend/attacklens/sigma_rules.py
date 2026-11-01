"""SigmaHQ rules -> AttackLens match rules (DEVELOPMENT.md §4 Stage 2). Mapping in config/sigma_map.yaml, switches
in pipeline.yaml `sigma`.

load(cfg) returns a SigmaSet: compiled rule dicts in the shape of `kind: match` rules (id `sigma_<uuid8>`, title,
where, technique, sub_technique, tactic, severity, source: sigma, plus gate / scan for the executor) and a coverage
report (files, parsed, compiled, skipped by reason, compiled by tactic / level). Compilation (~20 s for ~3800 files)
is cached on disk by a content hash of the rule files + map + ATT&CK data + compiler version; min_level and status
filter the cached output, so changing them never recompiles.

Warm path (sigma_cache.py; no rule file is opened): one directory walk (os.scandir: size + mtime come with the listing, no per-file
open, so on-access AV scanning is not triggered), a hash of that (path, size, mtime_ns) manifest + config, a lookup in
<cache_dir>/manifest.json (manifest hash -> content key) and ONE read of the compiled cache file. The content hash
(reads all ~3800 files, slow on a cold / contended disk) runs only when the manifest changed. Timings: log line
'sigma: load timings' and coverage['load_timing'].
"""

from __future__ import annotations

import functools
import hashlib
import json
import logging
import os
import re
import time
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import duckdb

from attacklens import sigma_cache
from attacklens.config import REPO_ROOT
from attacklens.schemas import CANONICAL_COLUMNS, TACTIC_IDX, TACTICS_V20
from attacklens.sigma_compile import Compiler, Unsupported, assume_true_spec, field_spec, lit, render  # noqa: F401
# re-exported: sigma_rules.LEVELS / RAW_LINE_EXCLUDE / keyword_column / coverage / level_overrides stay valid
from attacklens.sigma_options import (LEVELS, RAW_LINE_EXCLUDE, check_tactic, coverage, keyword_column,  # noqa: F401
                                      label_overrides, level_overrides)

log = logging.getLogger(__name__)

COMPILER_VERSION = "7"   # 7: label_override (6: per-logsource fields, cloud_logsources, technique_override, ...)
# sigma_map.yaml keys applied at load time (_filter), never compiled: changing them never recompiles
RUNTIME_KEYS = ("disable", "cloud_disable", "level_override")
NEVER_STATUS = ("deprecated", "unsupported")
DEFAULTS: dict[str, Any] = {"enabled": True, "dir": "config/sigma", "cache_dir": "data/cache/sigma",
                            "min_level": "low", "status": ["stable", "test", "experimental"],
                            "batch_size": 250, "check_batch": 400}
_TECH_TAG = re.compile(r"t\d{4}(\.\d{3})?")


@dataclass
class SigmaSet:
    rules: list[dict[str, Any]]          # filtered by min_level / status, ready to run
    exprs: list[str]                     # field expressions referenced by marker index in rule["scan"]
    coverage: dict[str, Any]


def settings(cfg: dict[str, Any]) -> dict[str, Any]:
    """pipeline.yaml `sigma` over DEFAULTS, plus sigma_map.yaml `disable` + `cloud_disable` (ids or SigmaHQ uuids,
    each with a reason) and `level_override` ({id, level}: the rule runs at that level / its severity)."""
    s = {**DEFAULTS, **((cfg.get("pipeline") or {}).get("sigma") or {})}
    if os.environ.get("ATTACKLENS_SIGMA", "").strip().lower() in ("0", "false", "off", "no"):
        s["enabled"] = False   # cheap global off switch (tests that do not concern Sigma)
    smap = cfg.get("sigma_map") or {}
    dis = list(smap.get("disable") or []) + list(smap.get("cloud_disable") or [])
    s["disable"] = [str(d["id"] if isinstance(d, dict) else d) for d in dis] + [str(x) for x in s.get("disable") or []]
    s["level_override"] = level_overrides(smap)
    s["level_severity"] = dict(smap.get("level_severity") or {})
    return s


def _resolve(p: str) -> Path:
    path = Path(p)
    return path if path.is_absolute() else REPO_ROOT / path


rule_files = sigma_cache.rule_files


def content_key(files: list[Path], root: Path, smap: dict[str, Any], attack: dict[str, Any]) -> str:
    return sigma_cache.content_key(files, root, smap, attack, COMPILER_VERSION)


def load(cfg: dict[str, Any]) -> SigmaSet:
    """Compiled + filtered Sigma rules. Raises nothing for bad rules (they are skipped); an absent dir -> empty."""
    t0 = time.perf_counter()
    s = settings(cfg)
    label_overrides(cfg.get("sigma_map") or {}, cfg.get("attack") or {})   # config error even on a warm cache
    root = _resolve(str(s["dir"]))
    cache_dir = _resolve(str(s["cache_dir"]))
    smap = {k: v for k, v in (cfg.get("sigma_map") or {}).items() if k not in RUNTIME_KEYS}   # runtime, not compiled
    smap_json, attack_json = json.dumps(smap, sort_keys=True, default=str), json.dumps(cfg.get("attack") or {})
    walk = sigma_cache.walk(root) if root.is_dir() else []
    t_walk = time.perf_counter()
    mh = sigma_cache.manifest_hash(root, walk, smap_json, attack_json, COMPILER_VERSION) if walk else ""
    key, how = (sigma_cache.key_for(mh, str(root), str(cache_dir), smap_json, attack_json, COMPILER_VERSION)
                if walk else ("empty", "empty"))
    t_key = time.perf_counter()
    hits0 = _compiled.cache_info().hits
    full = _compiled(key, str(root), str(cache_dir), smap_json, attack_json, int(s["check_batch"]))
    t_cache = time.perf_counter()
    out = _filter(full, s)
    t_end = time.perf_counter()
    timing = {"files": len(walk), "walk_s": round(t_walk - t0, 3), "key_s": round(t_key - t_walk, 3), "key_via": how,
              "cache_s": round(t_cache - t_key, 3),
              "cache_via": "memory" if _compiled.cache_info().hits > hits0 else full.get("_via"),
              "filter_s": round(t_end - t_cache, 3), "total_s": round(t_end - t0, 3)}
    out.coverage["load_timing"] = timing
    log.info("sigma: load timings %s", timing)
    return out


@functools.lru_cache(maxsize=4)
def _compiled(key: str, root: str, cache_dir: str, smap_json: str, attack_json: str, check_batch: int
              ) -> dict[str, Any]:
    cache = Path(cache_dir) / f"sigma_{key[:16]}.json"
    if cache.exists():
        try:
            data = json.loads(cache.read_bytes())
            if data.get("key") == key:
                log.info("sigma: %d compiled rules from cache %s", len(data["rules"]), cache.name)
                data["_via"] = "disk"
                return data
        except (OSError, ValueError) as exc:
            log.warning("sigma: unreadable cache %s (%s); recompiling", cache, exc)
    t0 = time.perf_counter()
    data = compile_dir(Path(root), json.loads(smap_json), json.loads(attack_json), check_batch)
    data["key"] = key
    data["compile_s"] = round(time.perf_counter() - t0, 2)
    try:
        cache.parent.mkdir(parents=True, exist_ok=True)
        tmp = cache.with_name(f"{cache.stem}.{os.getpid()}.tmp")
        tmp.write_text(json.dumps(data), encoding="utf-8")
        tmp.replace(cache)
    except OSError as exc:
        log.warning("sigma: cannot write cache %s: %s", cache, exc)
    log.info("sigma: compiled %d of %d rules in %.1f s", len(data["rules"]), data["parsed"], data["compile_s"])
    data["_via"] = "compiled"
    return data


def compile_dir(root: Path, smap: dict[str, Any], attack: dict[str, Any], check_batch: int = 400
                ) -> dict[str, Any]:
    """Parse and compile every *.yml under root. Returns {rules, exprs, skipped, files, parsed}."""
    from sigma.collection import SigmaCollection
    from sigma.rule import SigmaRule

    files = rule_files(root) if root.exists() else []
    entries = list(smap.get("logsources") or []) + list(smap.get("cloud_logsources") or [])
    specs = {k: field_spec(v, CANONICAL_COLUMNS) for k, v in (smap.get("fields") or {}).items()}
    relabel = label_overrides(smap, attack)   # ValueError (config error) propagates: never skipped silently
    exprs: list[str] = []
    rules: list[dict[str, Any]] = []
    skipped: list[dict[str, str]] = []
    parsed = 0
    ids: set[str] = set()
    for f in files:
        rel = f.relative_to(root).as_posix()
        try:
            col = SigmaCollection.from_yaml(f.read_text(encoding="utf-8"), collect_errors=True)
        except Exception as exc:  # noqa: BLE001 - malformed third-party YAML must never stop the run
            skipped.append({"path": rel, "reason": f"parse_error:{type(exc).__name__}"})
            continue
        if not col.rules and col.errors:
            skipped.append({"path": rel, "reason": f"parse_error:{type(col.errors[0]).__name__}"})
        for r in col.rules:
            parsed += 1
            if not isinstance(r, SigmaRule):
                skipped.append({"path": rel, "reason": f"not_detection_rule:{type(r).__name__}"})
                continue
            try:
                rules.append(_compile_one(r, rel, entries, specs, exprs, smap, attack, ids, relabel))
            except Unsupported as exc:
                skipped.append({"path": rel, "reason": str(exc), "level": _level(r) or "", "status": _status(r)})
    rules, bad = _sql_check(rules, exprs, check_batch)
    skipped += bad
    return {"rules": rules, "exprs": exprs, "skipped": skipped, "files": len(files), "parsed": parsed}


def _status(r: Any) -> str:
    return r.status.name.lower() if getattr(r, "status", None) is not None else "none"


def _level(r: Any) -> str | None:
    return r.level.name.lower() if getattr(r, "level", None) is not None else None


def _entry_for(r: Any, entries: list[dict[str, Any]]) -> dict[str, Any] | None:
    ls = r.logsource
    have = {"product": ls.product, "category": ls.category, "service": ls.service}
    for e in entries:
        ok = True
        for k, v in have.items():
            want = e.get(k, None) if k in e else None
            allowed = want if isinstance(want, list) else [want]
            if v not in allowed:
                ok = False
                break
        if ok:
            return e
    return None


def _compile_one(r: Any, rel: str, entries: list[dict[str, Any]], specs: dict[str, Any], exprs: list[str],
                 smap: dict[str, Any], attack: dict[str, Any], ids: set[str],
                 relabel: dict[str, dict[str, str]] | None = None) -> dict[str, Any]:
    if r.errors:
        raise Unsupported(f"parse_error:{type(r.errors[0]).__name__}")
    status = _status(r)
    if status in NEVER_STATUS:
        raise Unsupported(f"status:{status}")
    entry = _entry_for(r, entries)
    if entry is None:
        ls = r.logsource
        raise Unsupported(f"unmapped_logsource:{ls.product}/{ls.category}/{ls.service}")
    if entry.get("fields"):   # a logsource with its own fields uses ONLY those: no global name leaks in or out
        specs = {k: field_spec(v, CANONICAL_COLUMNS) for k, v in entry["fields"].items()}
    kw_expr, kw_guard = keyword_column(entry.get("keywords"))
    comp = Compiler(specs, exprs, assume_true_spec(entry.get("assume_true")), kw_expr, keyword_guard=kw_guard,
                    policy=str(smap.get("unmapped_field_policy", "skip")))
    try:
        scan = comp.compile_rule(r.detection.parsed_condition)
    except Unsupported:
        raise
    except Exception as exc:  # noqa: BLE001 - pySigma value/modifier errors surface lazily here
        raise Unsupported(f"compile_error:{type(exc).__name__}") from exc
    gate = str(entry["gate"])
    pgate = (smap.get("product_gates") or {}).get(r.logsource.product)
    if pgate:
        gate = f"({gate}) AND ({str(pgate).strip()})"
    level = _level(r)
    sev_map = smap.get("level_severity") or {}
    if level not in sev_map:
        raise Unsupported(f"level:{level}")
    fallback = {str(d["id"]).lower(): str(d["technique"]) for d in smap.get("technique_override") or []}
    ov = (relabel or {}).get(str(r.id).lower()) or (relabel or {}).get(f"sigma_{_base(r, rel)[:8]}") or {}
    tech, sub, tactic, de = labels(r, attack, smap.get("tactic_aliases") or {}, fallback.get(str(r.id).lower()), ov)
    rid = _rule_id(r, rel, ids)
    out = {"id": rid, "kind": "match", "source": "sigma", "title": str(r.title or "")[:200],
           "sigma_id": str(r.id) if r.id else None, "path": rel, "logsource": entry.get("name"),
           "level": level, "status": status, "technique": tech, "tactic": tactic,
           "severity": int(sev_map[level]), "gate": gate, "scan": scan,
           "fields": sorted(comp.used), "defense_evasion_to": de, "keyword_search": comp.keyword_used}
    if sub:
        out["sub_technique"] = sub
    if ov:
        out["label_override"] = ov["reason"]
    out["where"] = f"({out['gate']}) AND {render(scan, exprs)}"
    return out


def _base(r: Any, rel: str) -> str:
    base = str(r.id).replace("-", "").lower() if r.id else hashlib.sha1(rel.encode()).hexdigest()
    return re.sub(r"[^0-9a-f]", "", base) or hashlib.sha1(rel.encode()).hexdigest()


def _rule_id(r: Any, rel: str, ids: set[str]) -> str:
    base = _base(r, rel)
    for n in (8, 12, 32):
        rid = f"sigma_{base[:n]}"
        if rid not in ids:
            ids.add(rid)
            return rid
    rid = f"sigma_{hashlib.sha1(rel.encode()).hexdigest()[:12]}"
    ids.add(rid)
    return rid


def _tactic_names(tag: str, aliases: dict[str, Any]) -> list[str]:
    norm = re.sub(r"[-_]+", " ", tag).strip().lower()
    if norm in aliases:
        return [str(x) for x in aliases[norm]]
    return [t for t in TACTICS_V20 if t.lower() == norm]


def labels(r: Any, attack: dict[str, Any], aliases: dict[str, Any], fallback: str | None = None,
           override: dict[str, str] | None = None) -> tuple[str, str | None, str, str | None]:
    """(technique, sub_technique, tactic, defense_evasion_to) from the rule's attack.* tags, mapped through
    attack_v20.json. Technique: the first tagged sub-technique known to v20, else the first known technique.
    Tactic (deterministic): among the rule's tagged tactics that the technique belongs to in v20, the EARLIEST in
    kill-chain order (TACTIC_IDX); a tag that names a pre-v20 tactic is translated by sigma_map tactic_aliases
    (Defense Evasion -> Stealth / Defense Impairment, decided by the technique's own v20 tactics). No usable tag ->
    the technique's default v20 tactic. defense_evasion_to = the v20 tactic a defense-evasion tag resolved to.
    fallback: sigma_map technique_override for a rule that carries tactic tags only (used only when it has none).
    override: sigma_map label_override ({technique?, tactic?}): technique REPLACES the tagged ones (tactic then from
    the tags as above), tactic replaces the result and must be one of the chosen technique's v20 tactics (ValueError)."""
    techniques = attack.get("techniques") or {}
    ov = override or {}
    tags = [t.name.lower() for t in (r.tags or []) if str(t.namespace).lower() == "attack"]
    techs = ([ov["technique"].upper()] if ov.get("technique") else
             [t.upper() for t in tags if _TECH_TAG.fullmatch(t)] or ([fallback.upper()] if fallback else []))
    if not techs:
        raise Unsupported("no_attack_technique_tag")
    known = [t for t in techs if t in techniques and t.split(".")[0] in techniques]
    if not known:
        raise Unsupported("technique_not_in_v20")
    chosen = next((t for t in known if "." in t), known[0])
    parent = chosen.split(".")[0]
    allowed = techniques[chosen].get("tactics") or [techniques[chosen].get("tactic")]
    cands: set[str] = set()
    de_to: str | None = None
    for tag in tags:
        names = [n for n in _tactic_names(tag, aliases) if n in allowed]
        cands.update(names)
        if re.sub(r"[-_]+", " ", tag).strip() == "defense evasion" and names:
            de_to = min(names, key=lambda n: TACTIC_IDX[n])
    tactic = min(cands, key=lambda n: TACTIC_IDX[n]) if cands else techniques[chosen].get("tactic")
    if ov.get("tactic"):
        check_tactic(chosen, ov["tactic"], techniques, r.id)
        tactic = ov["tactic"]
        de_to = de_to if de_to == tactic else None
    if tactic not in TACTIC_IDX:
        raise Unsupported("tactic_not_v20")
    return parent, (chosen if "." in chosen else None), tactic, de_to


def referenced_columns(rule: dict[str, Any], exprs: list[str]) -> set[str]:
    """Every identifier a compiled rule's SQL reads (gate + scan field expressions), string literals removed:
    canonical columns plus anything else that looks like a column. A test can assert this never contains a
    generator label field (threat, rule, labels, labels_extra, event.kind, event.severity, event_kind, ...)."""
    from attacklens.sigma_compile import marker_indices
    text = " ".join([str(rule.get("gate") or "")] + [exprs[i] for i in sorted(marker_indices(str(rule["scan"])))])
    text = re.sub(r"'(?:[^']|'')*'", " ", text)
    idents = set(re.findall(r"[A-Za-z_][A-Za-z0-9_.]*", text))
    return {i for i in idents if i.lower() not in _SQL_WORDS}


_SQL_WORDS = frozenset("""and or not in is null case when then else end as cast coalesce lower upper like escape
    contains starts_with ends_with regexp_matches regexp_extract nullif try_cast true false varchar integer bigint
    double ubigint between distinct al_is_internal_ip""".split())


def _sql_check(rules: list[dict[str, Any]], exprs: list[str], batch: int
               ) -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
    """EXPLAIN each batch against an empty typed events view; a failing batch is bisected to the bad rules."""
    from attacklens.detect_sql import create_empty_events, register_macros

    con = duckdb.connect()
    good: list[dict[str, Any]] = []
    bad: list[dict[str, str]] = []
    try:
        con.execute("SET TimeZone='UTC'")
        con.execute("SET threads=1")
        create_empty_events(con)
        register_macros(con)   # gates may use al_is_internal_ip etc., exactly as at run time

        def ok(chunk: list[dict[str, Any]]) -> bool:
            pred = " OR ".join(f"({r['where']})" for r in chunk)
            try:
                con.execute(f"EXPLAIN SELECT 1 FROM events WHERE {pred}")
                return True
            except duckdb.Error:
                return False

        def walk(chunk: list[dict[str, Any]]) -> None:
            if ok(chunk):
                good.extend(chunk)
            elif len(chunk) == 1:
                bad.append({"path": chunk[0]["path"], "reason": "sql_compile_error", "level": chunk[0]["level"],
                            "status": chunk[0]["status"]})
            else:
                mid = len(chunk) // 2
                walk(chunk[:mid])
                walk(chunk[mid:])

        for i in range(0, len(rules), max(1, batch)):
            walk(rules[i:i + batch])
    finally:
        con.close()
    return good, bad


def _filter(full: dict[str, Any], s: dict[str, Any]) -> SigmaSet:
    min_level = str(s.get("min_level") or "low").lower()
    lo = LEVELS.index(min_level) if min_level in LEVELS else 1
    status = {str(x).lower() for x in s.get("status") or []} - set(NEVER_STATUS)
    run, filtered = [], Counter()
    disabled = {str(x).lower() for x in s.get("disable") or []}
    over, sev = s.get("level_override") or {}, s.get("level_severity") or {}
    n_over = 0
    for r in full["rules"]:
        lv = over.get(r["id"]) or over.get(str(r.get("sigma_id") or "").lower())
        if lv and lv != r["level"]:   # context / raised rules: level and severity as configured, original kept
            r = {**r, "level": lv, "severity": int(sev[lv]), "level_from": r["level"]}
            n_over += 1
        if r["id"] in disabled or str(r.get("sigma_id") or "").lower() in disabled:
            filtered["disabled"] += 1
        elif r["status"] not in status:
            filtered[f"status:{r['status']}"] += 1
        elif LEVELS.index(r["level"]) < lo:
            filtered[f"below_min_level:{r['level']}"] += 1
        else:
            run.append(r)
    cov = coverage(full, run, filtered, s)
    cov["level_overridden"] = n_over
    return SigmaSet(run, list(full["exprs"]), cov)
