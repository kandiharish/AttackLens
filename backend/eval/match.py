"""Matching primitives for the evaluation harness (TESTING.md §5.1). Frozen once the probes pass.

Everything here is deliberately strict: when in doubt, a prediction does NOT match.
- Step match iff |dt| <= 10 min AND host equal AND (user equal OR an IP in common), after normalization.
- Greedy one-to-one assignment ordered by (label match, entity overlap, closeness).
- Label correct iff technique correct AND tactic correct (Defense Evasion mapping only when GT uses it).
"""

from __future__ import annotations

import bisect
import re
import unicodedata
from dataclasses import dataclass, field
from datetime import datetime
from typing import Iterable

TOLERANCE_MS = 10 * 60 * 1000  # inclusive

_PREFIX = re.compile(r"^(host|user|ip|domain):", re.IGNORECASE)
_DEFENSE_EVASION_SPLIT = {"stealth", "defense impairment", "defense evasion"}


# ---------------------------------------------------------------- normalization
def _base(v: object) -> str | None:
    if v is None:
        return None
    s = unicodedata.normalize("NFC", str(v)).strip().lower()
    s = _PREFIX.sub("", s).strip()
    return s if s and s != "-" else None


def norm_host(v: object) -> str | None:
    return _base(v)


def norm_user(v: object) -> str | None:
    s = _base(v)
    if s is None:
        return None
    if "\\" in s:  # DOMAIN\user
        s = s.rsplit("\\", 1)[1]
    if "@" in s:  # user@domain
        s = s.split("@", 1)[0]
    s = s.strip()
    return s or None


def norm_ip(v: object) -> str | None:
    return _base(v)


def norm_technique(v: object) -> str | None:
    if v is None:
        return None
    s = str(v).strip().upper()
    return s or None


def parent_technique(t: str | None) -> str | None:
    return t.split(".", 1)[0] if t else None


def norm_tactic(v: object) -> str | None:
    if v is None:
        return None
    s = " ".join(str(v).split()).lower()
    return s or None


def parse_ts_ms(ts: str) -> int:
    """ISO-8601 with explicit UTC offset -> epoch ms. Naive timestamps are a contract violation."""
    dt = datetime.fromisoformat(ts)
    if dt.tzinfo is None:
        raise ValueError(f"timestamp without time zone violates the contract (needs 'Z'): {ts!r}")
    return int(round(dt.timestamp() * 1000))


# ---------------------------------------------------------------- items
@dataclass(frozen=True)
class GTStep:
    attack_id: str
    step: int
    ts_ms: int
    technique: str | None
    tactic: str | None
    host: str | None
    user: str | None
    ips: frozenset[str]

    @property
    def key(self) -> tuple[str, int]:
        return (self.attack_id, self.step)


@dataclass(frozen=True)
class PredStep:
    """One predicted step (an episode). `order` = position in its incident (backbone first, then branches)."""
    incident_id: str
    episode_id: str
    order: int
    ts_ms: int
    technique: str | None
    sub_technique: str | None
    tactic: str | None
    host: str | None
    user: str | None
    ips: frozenset[str]
    alt_users: frozenset[str] = frozenset()  # raw alerts carry src_user AND target_user
    extra: dict = field(default_factory=dict, compare=False, hash=False)

    @property
    def users(self) -> tuple[str | None, ...]:
        return (self.user, *sorted(self.alt_users))


def make_gt_step(attack_id: str, d: dict) -> GTStep:
    return GTStep(
        attack_id=str(attack_id), step=int(d["step"]), ts_ms=int(d["ts_ms"]),
        technique=norm_technique(d.get("technique_id")), tactic=norm_tactic(d.get("tactic")),
        host=norm_host(d.get("host")), user=norm_user(d.get("user")),
        ips=frozenset(x for x in (norm_ip(d.get("src_ip")), norm_ip(d.get("dst_ip"))) if x),
    )


# ---------------------------------------------------------------- predicates
def entity_match(gt_host: str | None, gt_user: str | None, gt_ips: frozenset[str],
                 host: str | None, users: Iterable[str | None], ips: frozenset[str]) -> tuple[bool, int]:
    """(matches, overlap). Host must be equal (both non-null) and user or IP must match."""
    if gt_host is None or host is None or gt_host != host:
        return False, 0
    user_ok = gt_user is not None and any(u is not None and u == gt_user for u in users)
    ip_ok = bool(gt_ips & ips)
    if not (user_ok or ip_ok):
        return False, 0
    return True, 1 + int(user_ok) + int(ip_ok)


def technique_ok(gt_technique: str | None, technique: str | None, sub_technique: str | None) -> bool:
    """Parent technique match, or exact sub-technique. A conflicting sub-technique is wrong.

    GT T1110      vs pred T1110 / T1110.001        -> ok (parent match)
    GT T1110.003  vs pred T1110 (no sub)           -> ok (parent match, GT more specific)
    GT T1110.003  vs pred sub T1110.003            -> ok (exact)
    GT T1110.003  vs pred sub T1110.001            -> WRONG (conflicting sub-technique)
    """
    if not gt_technique:
        return False
    pred_ids = [t for t in (technique, sub_technique) if t]
    if not pred_ids:
        return False
    if gt_technique in pred_ids and "." in gt_technique:
        return True
    gt_parent = parent_technique(gt_technique)
    if gt_parent not in {parent_technique(t) for t in pred_ids}:
        return False
    pred_subs = {t for t in pred_ids if "." in t}
    gt_sub = gt_technique if "." in gt_technique else None
    if gt_sub and pred_subs and gt_sub not in pred_subs:
        return False
    return True


def tactic_ok(gt_tactic: str | None, tactic: str | None) -> bool:
    if gt_tactic is None or tactic is None:
        return False
    if gt_tactic == "defense evasion":  # GT on pre-v20 naming: accept either v20 half
        return tactic in _DEFENSE_EVASION_SPLIT
    return gt_tactic == tactic


def label_ok(gt: GTStep, p: PredStep) -> bool:
    return technique_ok(gt.technique, p.technique, p.sub_technique) and tactic_ok(gt.tactic, p.tactic)


@dataclass(frozen=True)
class Candidate:
    gt: GTStep
    pred: PredStep
    label: bool
    overlap: int
    dt_ms: int

    def sort_key(self) -> tuple:
        return (not self.label, -self.overlap, self.dt_ms, self.gt.attack_id, self.gt.step,
                self.pred.incident_id, self.pred.order, self.pred.episode_id)


def candidates(gts: list[GTStep], preds: list[PredStep]) -> list[Candidate]:
    """All (gt, pred) pairs satisfying the step-match rule. Per-host time index + bisect (noise sets are large)."""
    by_host: dict[str, list[PredStep]] = {}
    for p in preds:
        if p.host is not None:
            by_host.setdefault(p.host, []).append(p)
    index: dict[str, tuple[list[int], list[PredStep]]] = {}
    for h, ps in by_host.items():
        ps.sort(key=lambda x: (x.ts_ms, x.incident_id, x.order, x.episode_id))
        index[h] = ([x.ts_ms for x in ps], ps)
    out: list[Candidate] = []
    for g in gts:
        if g.host is None or g.host not in index:
            continue
        times, ps = index[g.host]
        lo = bisect.bisect_left(times, g.ts_ms - TOLERANCE_MS)
        hi = bisect.bisect_right(times, g.ts_ms + TOLERANCE_MS)
        for p in ps[lo:hi]:
            ok, overlap = entity_match(g.host, g.user, g.ips, p.host, p.users, p.ips)
            if ok:
                out.append(Candidate(g, p, label_ok(g, p), overlap, abs(p.ts_ms - g.ts_ms)))
    return out


def greedy_assign(cands: list[Candidate]) -> list[Candidate]:
    """One-to-one: each GT step and each predicted episode is used at most once."""
    used_gt: set[tuple[str, int]] = set()
    used_pred: set[str] = set()
    chosen: list[Candidate] = []
    for c in sorted(cands, key=Candidate.sort_key):
        if c.gt.key in used_gt or c.pred.episode_id in used_pred:
            continue
        used_gt.add(c.gt.key)
        used_pred.add(c.pred.episode_id)
        chosen.append(c)
    return chosen


def lcs_len(a: list, b: list) -> int:
    if not a or not b:
        return 0
    prev = [0] * (len(b) + 1)
    for x in a:
        cur = [0] * (len(b) + 1)
        for j, y in enumerate(b, 1):
            cur[j] = prev[j - 1] + 1 if x == y else max(prev[j], cur[j - 1])
        prev = cur
    return prev[-1]
