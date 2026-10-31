"""L0 config tests (TESTING.md §4.1): rules reference known techniques/tactics, thresholds exist, every `where`
compiles against an empty canonical `events` table."""

from __future__ import annotations

import re
from collections import Counter

import duckdb
import pytest

from attacklens import config
from attacklens.schemas import CANONICAL_COLUMNS, TACTICS_V20

RULES_YAML = config.CONFIG_DIR / "rules.yaml"
pytestmark = pytest.mark.skipif(not RULES_YAML.exists(), reason="config/rules.yaml not written yet (BB-detect)")

# DEVELOPMENT.md §5.1 thresholds block
REQUIRED_THRESHOLDS = {
    "bf_min_failures", "bf_gap_ms", "bf_success_window_ms", "emit_t1078_on_bruteforce", "spray_min_users",
    "exfil_min_bytes", "exfil_window_ms", "exfil_baseline_mult", "mass_rename_min", "beacon_min_conns",
    "hub_min_median_daily_peers", "seed_confidence", "critical_confidence", "raw_ref_score",
}
LABEL_FIELDS = ("threat", "labels", "labels_extra", "event_kind", "event_severity", "event.kind", "event.severity")
PLACEHOLDER = re.compile(r"\{([a-z_]+)\.([a-z_]+)\}")


@pytest.fixture(scope="module")
def cfg() -> dict:
    return config.load_config()


@pytest.fixture(scope="module")
def rules(cfg: dict) -> list[dict]:
    r = cfg["rules"].get("rules")
    assert isinstance(r, list) and r, "rules.yaml must have a non-empty `rules` list"
    return r


@pytest.fixture(scope="module")
def techniques(cfg: dict) -> dict:
    att = cfg["attack"]
    assert att, "config/attack_v20.json missing or empty"
    t = att.get("techniques", att)
    assert isinstance(t, dict) and t
    return t


def _labels(rule: dict) -> list[tuple[str, str | None, str]]:
    """(technique, sub_technique, tactic) for the primary and the optional secondary label."""
    out = [(rule.get("technique"), rule.get("sub_technique"), rule.get("tactic"))]
    if rule.get("secondary"):
        s = rule["secondary"]
        out.append((s.get("technique"), s.get("sub_technique"), s.get("tactic")))
    return out


def test_rule_ids_unique_and_nonempty(rules: list[dict]) -> None:
    ids = [r.get("id") for r in rules]
    assert all(isinstance(i, str) and re.fullmatch(r"[a-z0-9_]+", i) for i in ids), ids
    dup = [i for i, n in Counter(ids).items() if n > 1]
    assert not dup, f"duplicate rule ids: {dup}"


def test_rule_kinds_and_required_fields(rules: list[dict]) -> None:
    for r in rules:
        assert r.get("kind") in {"match", "template", "sigma"}, r["id"]
        assert isinstance(r.get("severity"), int) and 0 < r["severity"] <= 100, r["id"]
        if r["kind"] == "match":
            assert isinstance(r.get("where"), str) and r["where"].strip(), r["id"]
        if r["kind"] == "template":
            assert isinstance(r.get("template"), str) and r["template"], r["id"]
        if r.get("secondary"):
            assert isinstance(r["secondary"].get("severity"), int) and 0 < r["secondary"]["severity"] <= 100


def test_every_technique_in_attack_v20(rules: list[dict], techniques: dict) -> None:
    for r in rules:
        for tech, sub, _ in _labels(r):
            assert tech in techniques, f"{r['id']}: technique {tech} not in attack_v20.json"
            if sub:
                assert sub in techniques, f"{r['id']}: sub_technique {sub} not in attack_v20.json"
                assert sub.split(".")[0] == tech, f"{r['id']}: {sub} is not a sub-technique of {tech}"


def test_every_tactic_is_v20_and_belongs_to_technique(rules: list[dict], techniques: dict) -> None:
    for r in rules:
        for tech, sub, tactic in _labels(r):
            assert tactic in TACTICS_V20, f"{r['id']}: tactic {tactic!r} is not a v20 tactic"
            allowed = techniques[tech].get("tactics")
            if allowed:
                assert tactic in allowed, f"{r['id']}: {tech} does not belong to {tactic} (has {allowed})"


def test_attack_v20_tactics_and_techniques(cfg: dict, techniques: dict) -> None:
    att = cfg["attack"]
    assert att.get("version") == "v20"
    if "tactics" in att:
        names = [t["name"] for t in sorted(att["tactics"], key=lambda t: t["idx"])]
        assert names == TACTICS_V20
        assert [t["idx"] for t in sorted(att["tactics"], key=lambda t: t["idx"])] == list(range(1, 16))
    for tid, t in techniques.items():
        assert re.fullmatch(r"T\d{4}(\.\d{3})?", tid), tid
        assert t.get("name"), tid
        assert t.get("tactic") in TACTICS_V20, f"{tid}: {t.get('tactic')!r}"
        for x in t.get("tactics", []):
            assert x in TACTICS_V20, f"{tid}: {x!r}"


def test_thresholds_present(cfg: dict) -> None:
    th = cfg["rules"].get("thresholds") or {}
    missing = REQUIRED_THRESHOLDS - set(th)
    assert not missing, f"thresholds missing: {sorted(missing)}"
    for k in REQUIRED_THRESHOLDS - {"emit_t1078_on_bruteforce"}:
        assert isinstance(th[k], (int, float)) and not isinstance(th[k], bool) and th[k] > 0, k
    assert isinstance(th["emit_t1078_on_bruteforce"], bool)
    assert th["seed_confidence"] < th["critical_confidence"] <= 100


def _expand(rule: dict, cfg: dict) -> str:
    """The product's own {ioc.<list>} expansion (detect.expand_where), so test and pipeline cannot drift."""
    from attacklens import detect
    for m in PLACEHOLDER.finditer(rule["where"]):
        vals = cfg[m.group(1)][m.group(2)]
        assert isinstance(vals, list) and vals, f"{rule['id']}: placeholder {m.group(0)} must name a non-empty list"
    return detect.expand_where(rule, cfg.get("ioc") or {})


def test_detect_validate_accepts_shipped_config(cfg: dict) -> None:
    from attacklens import detect
    detect.validate(cfg)  # raises detect.RuleError naming the rule


@pytest.mark.parametrize("bad,needle", [
    ({"where": "action = 'x' AND nope_column = 1"}, "does not compile"),
    ({"where": "dst_ip IN {ioc.no_such_list}"}, "unknown placeholder"),
    ({"technique": "T9999"}, "not in attack_v20"),
    ({"tactic": "Defense Evasion"}, "not a v20 tactic"),
])
def test_detect_validate_rejects_bad_rule(cfg: dict, bad: dict, needle: str) -> None:
    from attacklens import detect
    rule = {"id": "zz_probe", "kind": "match", "where": "action = 'log_cleared'", "technique": "T1070",
            "tactic": "Defense Impairment", "severity": 10, **bad}
    broken = {**cfg, "rules": {**cfg["rules"], "rules": [*cfg["rules"]["rules"], rule]}}
    with pytest.raises(detect.RuleError, match=rf"^zz_probe: .*{needle}"):
        detect.validate(broken)


def test_every_match_where_compiles(rules: list[dict], cfg: dict) -> None:
    con = duckdb.connect()
    con.execute("SET TimeZone='UTC'")
    con.execute("CREATE TABLE events (" + ", ".join(f'"{c}" {t}' for c, t in CANONICAL_COLUMNS.items()) + ")")
    failures = []
    for r in rules:
        if r["kind"] != "match":
            continue
        where = _expand(r, cfg)
        assert "{" not in where, f"{r['id']}: unexpanded placeholder in {where!r}"
        try:
            con.execute(f"EXPLAIN SELECT * FROM events WHERE {where}").fetchall()
        except duckdb.Error as e:
            failures.append(f"{r['id']}: {e}")
    con.close()
    assert not failures, "\n".join(failures)


def test_no_rule_reads_label_fields(rules: list[dict]) -> None:
    for r in rules:
        text = " ".join(str(v) for v in r.values()).lower()
        for f in LABEL_FIELDS:
            assert not re.search(rf"\b{re.escape(f)}\b", r.get("where", "").lower()), (r["id"], f)
        assert "labels_extra" not in text and "threat." not in text, r["id"]
