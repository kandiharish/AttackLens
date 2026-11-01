"""QA black-box attack injection into real FortiGate backgrounds (track qa_injection).

    python tools/qa/inject.py --keys n10,n30,n50                      # data/raw/<key>_inj/ (hard link + attacks)
    python tools/qa/inject.py --slice-of n10 --slice-mb 300 --name n10slice   # data/raw/n10slice_inj/ (head copy)

(1) inject_scan.scan(): one bounded DuckDB pass over the background (aggregates only, nothing printed).
(2) F1, F2, F3 + decoy F4 + context from tools/fortigate_scenarios.scenario_lines (days=7, as f1) are re-timed
    into the busiest 12 h window: F4 once (day 0, the f1 gap of 7 h 45 m after F1, outside the 2 h
    config-after-login window), the 7 daily context instances spread over the window (one instance alone is a
    rare internal SMB pair = a lateral alert that f1 never sees; 7 keep it routine as in f1), and re-headed in the background's convention (key order, quoting, eventtime unit, local-vs-UTC, tz,
    line ending) with a synthetic devname/devid and an RFC 5737 WAN address. --entities isolated (default) also
    remaps the scenario's internal 10.x addresses to a /16 and its users to made-up names that the scan found
    absent from the background, so ground truth cannot collide with real hosts; --entities generator keeps the
    generator's values (collision counts are in manifest.json either way). Every line is re-parsed with the
    product's convention and must give its intended ms.
    Internal nets: an unused /16 per generator /16 if the background leaves one (n10); otherwise (n30, n50 use every
    10.x and 172.16-31 /16) a used /16 in which none of the remapped /24s occurs (scan probe private_24).
    External RFC 5737 IPs that occur in the background are swapped for unused stand-ins (EXT_POOL).
(3) <name>_inj/: HARD LINK to the real log (os.link, never a copy; failure aborts), attack_inject.log,
    ground_truth/attacks.json (backend/eval/harness.py format), manifest.json (ingest skips both).
"""
from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import re
import shutil
import sys
import time
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "tools"))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import fortigate_gen as fg  # noqa: E402
import fortigate_scenarios as fs  # noqa: E402
import inject_scan as isc  # noqa: E402
from attacklens.config import load_config  # noqa: E402

log = logging.getLogger("qa.inject")

MIN, HOUR, DAY = isc.MIN, isc.HOUR, isc.DAY
KEYS = ("n10", "n30", "n50")
IDS = ["F1", "F2", "F3", "F4"]
GEN_START = 1_792_800_000_000           # day-aligned generator clock; every group is re-timed from it
WINDOW_MS, SPAN_MS = 12 * HOUR, 11 * HOUR + 1
SYNTH_WAN = "198.51.100.1"              # RFC 5737 stand-in for fortigate_gen.WAN_IP (which is not RFC 5737)
# group -> (generator offset range [lo, hi) from GEN_START, new offset from the window start w0)
GEN_DAYS = 7
CTX_OFFSETS = (10 * HOUR, 30 * MIN, 2 * HOUR, 4 * HOUR, 6 * HOUR, 8 * HOUR, 9 * HOUR)   # ctx of generator day d
GROUPS = {"F1": (90 * MIN, 3 * HOUR, 20 * MIN), "F2": (DAY + 19 * HOUR, DAY + 21 * HOUR, 3 * HOUR),
          "F3": (2 * DAY + 6 * HOUR, 2 * DAY + 8 * HOUR, 5 * HOUR + 30 * MIN),
          "F4@0": (9 * HOUR, 11 * HOUR, 7 * HOUR + 50 * MIN),
          **{f"ctx@{d}": (d * DAY + 11 * HOUR, d * DAY + 12 * HOUR + 1, o) for d, o in enumerate(CTX_OFFSETS)},
          **{f"F4@{d}": (d * DAY + 9 * HOUR, d * DAY + 11 * HOUR, None) for d in range(1, GEN_DAYS)}}  # None: dropped
GEN_RX = re.compile(r'^date=(\S+) time=(\S+) devname="([^"]*)" devid="([^"]*)" eventtime=(\d+) tz="([^"]*)" '
                    r'logid="([^"]*)" type="([^"]*)" subtype="([^"]*)" level="([^"]*)" vd="([^"]*)" (.*)$')
IP_RX = re.compile(r"(?<![\d.])(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?![\d.])")
RFC5737 = ("192.0.2.", "198.51.100.", "203.0.113.")
GEN_USERS = ("admin", "vpnuser")
QA_USERS = {"admin": "qa_fwadm", "vpnuser": "qa_vpnusr"}
OCTET_CANDIDATES = (77, 78, 79, 83, 87, 91, 93, 97, 101, 103, 107, 109, 113, 119, 127, 131, 137, 139)
EXT_POOL = tuple(f"{p}{o}" for p in RFC5737 for o in (11, 23, 37, 59, 71, 89))   # stand-ins for busy RFC 5737 IPs
RFC1918 = ("10.", "192.168.", *(f"172.{o}." for o in range(16, 32)))


def scenario_entities() -> tuple[list[str], list[str]]:
    """(internal 10.x IPs, external IPs) used by the scenario lines (constants of fortigate_scenarios/_gen)."""
    lines, _ = fs.scenario_lines(GEN_START, IDS, 0, days=1)
    ips = sorted({ip for _, ln in lines for ip in IP_RX.findall(ln.replace(fg.WAN_IP, SYNTH_WAN))})
    return [i for i in ips if i.startswith("10.")], [i for i in ips if not i.startswith("10.")]


def thirds_of(internal: list[str]) -> list[int]:
    return sorted({int(ip.split(".")[2]) for ip in internal})


def probes(internal: list[str], external: list[str]) -> dict[str, Any]:
    return {"ips": internal + external + [x for x in EXT_POOL if x not in external],
            "users": list(GEN_USERS) + list(QA_USERS.values()), "private_nets": True,
            "private_24": thirds_of(internal), "substr": {"devname:qainj": ["QAINJ", "qainj"]}}


def prefix_order() -> list[str]:
    """Private /16 prefixes in preference order: candidate 10.x, other 10.x, 172.16-31, 192.168 (never 10.10 or
    10.212, the generator's own nets)."""
    order = [f"10.{o}" for o in OCTET_CANDIDATES] + [f"10.{o}" for o in range(2, 255) if o not in OCTET_CANDIDATES]
    return [p for p in order + [f"172.{o}" for o in range(16, 32)] + ["192.168"] if p not in ("10.10", "10.212")]


def free_prefixes(seen: list[str]) -> list[str]:
    """Unused private /16 prefixes in preference order."""
    return [p for p in prefix_order() if p not in set(seen)]


def map_nets(internal: list[str], seen16: list[str], seen24: list[str] | None,
             nets: str = "auto") -> tuple[dict[str, str], dict[str, str]]:
    """Generator /16 (second octet) -> target prefix.
    Level 16: a /16 the background never uses, one per generator /16.
    Level 24 (fallback when no unused /16 is left, or nets='busy24'): a /16 the background uses, but none of the exact
    /24s the remap writes (<prefix>.<third>) occurs in it; two generator /16s may share a target when their /24s
    differ. seen24 None = the /24 probe was not run -> level 24 is not available."""
    need: dict[str, set[int]] = {}
    for ip in internal:
        need.setdefault(ip.split(".")[1], set()).add(int(ip.split(".")[2]))
    s16, taken = set(seen16), set()
    o_map: dict[str, str] = {}
    level: dict[str, str] = {}
    order = prefix_order()
    if nets == "busy24":
        order = [p for p in order if p in s16] + [p for p in order if p not in s16]
    for sec in sorted(need, key=int):
        th = sorted(need[sec])
        pick, lv = None, "16"
        if nets == "auto":
            used = {q for q, _ in taken}
            pick = next((p for p in order if p not in s16 and p not in used), None)
        if pick is None and seen24 is not None:
            s24 = set(seen24)
            pick = next((p for p in order if all(f"{p}.{t}" not in s24 and (p, t) not in taken for t in th)), None)
            lv = "24"
        if pick is None:
            raise SystemExit(f"no private /16 left for 10.{sec}.x (nets={nets}, /24 probe "
                             f"{'off' if seen24 is None else 'on'})")
        o_map[sec], level[f"10.{sec}"] = pick, lv
        taken |= {(pick, t) for t in th}
    return {ip: f"{o_map[ip.split('.')[1]]}.{ip.split('.', 2)[2]}" for ip in internal}, level


def map_external(external: list[str], col: dict[str, int]) -> dict[str, str]:
    """External RFC 5737 IPs that the background already contains -> an unused stand-in from EXT_POOL."""
    free = [x for x in EXT_POOL if x not in external and col.get(f"ip:{x}", 1) == 0]
    out = {}
    for ip in external:
        if col.get(f"ip:{ip}", 1):
            if not free:
                raise SystemExit(f"external {ip} occurs in the background and no unused stand-in is left")
            out[ip] = free.pop(0)
    return out


def entity_map(style: dict[str, Any], internal: list[str], mode: str, external: list[str] | None = None,
               nets: str = "auto") -> tuple[dict[str, str], dict[str, str]]:
    if mode == "generator":
        return {}, {}
    col = style["collisions"]
    ips, level = map_nets(internal, style["private_nets_seen"], style.get("private_24_seen"), nets)
    style["_net_level"] = level
    ips.update(map_external(external or [], col))
    busy = [u for u in QA_USERS.values() if col.get(f"user:{u}", 1)]
    if busy or col.get("devname:qainj", 1):
        raise SystemExit(f"synthetic names present in the background: users {busy}")
    return ips, dict(QA_USERS)


def synth_names(style: dict[str, Any], name: str) -> tuple[str, str]:
    dev, did = f"FGT-QAINJ-{name.upper()}", "FGTQAINJ00000001"
    return (dev.lower(), did.lower()) if style.get("devname_lowercase") else (dev, did)


def _group(ts: int) -> str:
    off = ts - GEN_START
    hit = [g for g, (lo, hi, _) in GROUPS.items() if lo <= off < hi]
    if len(hit) != 1:
        raise ValueError(f"scenario record at offset {off} ms is in {len(hit)} groups")
    return hit[0]


def _majority(d: dict[str, int], ok: Any = None) -> str:
    c = {k: v for k, v in d.items() if k and (ok is None or ok(k))}
    return max(sorted(c), key=lambda k: c[k]) if c else ""


def _remap(text: str, ips: dict[str, str], users: dict[str, str]) -> str:
    text = IP_RX.sub(lambda m: ips.get(m.group(1), m.group(1)), text.replace(fg.WAN_IP, SYNTH_WAN))
    for u, q in users.items():
        text = text.replace(f'user="{u}"', f'user="{q}"').replace(f"Administrator {u} ", f"Administrator {q} ")
    return text


def build_attack(style: dict[str, Any], window: dict[str, Any], seed: int, ids: list[str], name: str,
                 ips: dict[str, str], users: dict[str, str]) -> tuple[list[tuple[int, str]], dict, dict[str, int]]:
    lines, attacks = fs.scenario_lines(GEN_START, ids, seed, days=GEN_DAYS)
    dev, did = synth_names(style, name)
    conv = style.get("conventions") or {}
    local = conv.get("local", 0) >= conv.get("utc", 0)
    tz = _majority(style.get("tz_values") or {}, lambda k: isc.tz_offset_ms(k) is not None)
    off = isc.tz_offset_ms(tz) or 0
    dg = _majority(style.get("eventtime_digits") or {}, lambda k: k.isdigit() and int(k) in isc.NS_DIGITS)
    digits = int(dg) if dg else 0
    hk = list(style.get("header_keys") or isc.GEN_HEAD)
    order = [k for k in hk + [k for k in isc.GEN_HEAD if k not in hk]
             if (k != "eventtime" or digits) and (k != "tz" or tz)]
    quoted = style.get("header_quoted") or {}
    et_local = bool(style.get("eventtime_is_local_cfg", True))
    w0 = window["w0_ms"]
    delta = {g: w0 + new - (GEN_START + lo) for g, (lo, _, new) in GROUPS.items() if new is not None}
    out: list[tuple[int, str]] = []
    per_group: dict[str, int] = {}
    for ts, ln in lines:
        m = GEN_RX.match(ln)
        if not m:
            raise ValueError("scenario line does not match the fortigate_gen header")
        g = _group(ts)
        per_group[g] = per_group.get(g, 0) + 1
        if g not in delta:
            continue
        t = ts + delta[g]
        sub = int(m.group(5)) % 1_000_000
        base, loc = (t + off if (local and tz) else t), t + off
        et = {19: base * 1_000_000 + sub, 16: base * 1000 + sub // 1000, 13: base, 10: base // 1000}.get(digits)
        vals = {"date": time.strftime("%Y-%m-%d", time.gmtime(loc // 1000)),
                "time": time.strftime("%H:%M:%S", time.gmtime(loc // 1000)), "devname": dev, "devid": did,
                "eventtime": str(et), "tz": tz, "logid": m.group(7), "type": m.group(8), "subtype": m.group(9),
                "level": m.group(10), "vd": m.group(11)}
        head = " ".join(f'{k}="{vals[k]}"' if quoted.get(k) else f"{k}={vals[k]}" for k in order)
        new = f"{head} {_remap(m.group(12), ips, users)}"
        want = t if digits != 10 else t // 1000 * 1000
        if isc.line_ts(new, et_local) != want:
            raise ValueError(f"re-parsed ts {isc.line_ts(new, et_local)} != intended {want} ({g})")
        out.append((want, new))
    bad = [x for _, x in out if fg.DEVNAME in x or fg.WAN_IP in x
           or any(not ip.startswith((*RFC1918, *RFC5737)) for ip in IP_RX.findall(x))
           or (users and any(f'user="{u}"' in x for u in users))]
    if bad:
        raise ValueError(f"{len(bad)} injected lines carry generator devname/WAN/user or a non-RFC 1918/5737 IP")
    for a in attacks["attacks"]:
        for s in a["steps"]:
            s["ts_ms"] = s["ts_ms"] + delta[_group(s["ts_ms"])]
            s["host"] = dev if s["host"] == fg.DEVNAME else _remap(s["host"], ips, {})
            for k in ("src_ip", "dst_ip"):
                s[k] = _remap(s[k], ips, {}) if s[k] else s[k]
            s["user"] = users.get(s["user"], s["user"]) if s["user"] else s["user"]
    out.sort(key=lambda x: x[0])
    return out, attacks, per_group


# ---------------------------------------------------------------- the set directory
def _sha(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for b in iter(lambda: f.read(1 << 22), b""):
            h.update(b)
    return h.hexdigest()


def _prepare(out: Path, force: bool) -> None:
    if not out.name.endswith("_inj"):
        raise SystemExit(f"refusing {out}: not an *_inj directory")
    if out.exists():
        if not force:
            raise SystemExit(f"{out} exists (use --force)")
        shutil.rmtree(out)                       # removes only the hard link, never the real file's data
    (out / "ground_truth").mkdir(parents=True)


def link_background(src: Path, out: Path) -> dict[str, Any]:
    dst = out / src.name
    os.link(src, dst)                            # never a copy: a failure aborts the build
    st = os.stat(dst)
    if not os.path.samefile(src, dst) or st.st_nlink < 2:
        raise SystemExit(f"{dst} is not a hard link of {src}")
    return {"mode": "hardlink", "src": src.as_posix(), "dst": dst.name, "bytes": st.st_size, "st_nlink": st.st_nlink}


def copy_head(src: Path, out: Path, nbytes: int, name: str) -> dict[str, Any]:
    dst = out / name
    with open(src, "rb") as fi, open(dst, "wb") as fo:
        buf = fi.read(nbytes)
        cut = buf.rfind(b"\n")
        fo.write(buf[:cut + 1] if cut >= 0 else buf)
    return {"mode": "head_copy", "src": src.as_posix(), "dst": dst.name, "bytes": dst.stat().st_size,
            "requested_bytes": nbytes}


def make_set(name: str, background: Path, out_root: Path, seed: int = 7, ids: list[str] | None = None,
             max_rows: int | None = None, slice_bytes: int | None = None, force: bool = False,
             tmp: Path | None = None, entities: str = "isolated", nets: str = "auto") -> dict[str, Any]:
    ids = list(ids or IDS)
    out = out_root / f"{name}_inj"
    _prepare(out, force)
    bg = (copy_head(background, out, slice_bytes, f"{name}_head{slice_bytes >> 20}m.log") if slice_bytes
          else link_background(background, out))
    internal, external = scenario_entities()
    kcfg = load_config()["sources"]["kv_sources"]["fortigate_kv"]
    tmp = tmp or REPO / "data" / "tmp" / "qa_inj"
    pr = probes(internal, external)
    key = hashlib.sha256(json.dumps([bg["src"], bg["mode"], bg["bytes"], bg.get("requested_bytes"),
                                     os.stat(bg["src"]).st_mtime_ns, max_rows, pr, kcfg, _sha(Path(isc.__file__))],
                                    sort_keys=True, default=str).encode()).hexdigest()[:20]
    cache = tmp / "scan_cache" / f"{key}.json"          # a rerun after a failed build does not rescan 30 GB
    if cache.exists() and not slice_bytes:
        style = json.loads(cache.read_text(encoding="utf-8"))
        style["hist_hours"] = [tuple(x) for x in style["hist_hours"]]
    else:
        style = isc.scan(out / bg["dst"], kcfg, tmp, max_rows, pr)
        cache.parent.mkdir(parents=True, exist_ok=True)
        cache.write_text(json.dumps(style), encoding="utf-8")
    window = isc.choose_window(style["hist_hours"], style["ts_min_ms"], style["ts_max_ms"], WINDOW_MS, SPAN_MS)
    ips, users = entity_map(style, internal, entities, external, nets)
    lines, attacks, per_group = build_attack(style, window, seed, ids, name, ips, users)
    nl = "\r\n" if style["line_ending"] == "crlf" else "\n"
    atk = out / "attack_inject.log"
    with open(atk, "w", encoding="utf-8", newline="") as f:
        f.write("".join(x + nl for _, x in lines))
    with open(out / "ground_truth" / "attacks.json", "w", encoding="utf-8", newline="\n") as f:
        json.dump(attacks, f, indent=1)
    lo, hi = lines[0][0], lines[-1][0]
    gt_ts = [s["ts_ms"] for a in attacks["attacks"] for s in a["steps"]]
    manifest = {
        "format": "fortigate_kv_injected", "name": out.name, "seed": seed, "scenario_ids": ids,
        "ground_truth_ids": [a["id"] for a in attacks["attacks"]], "decoy_ids": [i for i in ids if i == "F4"],
        "entities_mode": entities, "nets_mode": nets, "net_level": style.pop("_net_level", {}), "ip_map": ips,
        "user_map": users, "background": bg, "window": window,
        "window_ms": WINDOW_MS, "schedule_offsets_ms": {g: v[2] for g, v in GROUPS.items() if v[2] is not None},
        "dropped_groups": sorted(g for g in per_group if GROUPS[g][2] is None),
        "attack_ts_range_ms": [lo, hi], "gt_ts_range_ms": [min(gt_ts), max(gt_ts)],
        "attack_inside_background_span": bool(style["ts_min_ms"] <= lo and hi <= style["ts_max_ms"]),
        "counts": {"attack_lines": len(lines), "generator_lines_per_group": per_group, "attack_bytes": atk.stat().st_size,
                   "gt_attacks": len(attacks["attacks"]), "gt_steps": len(gt_ts)},
        "synthetic": {"devname": synth_names(style, name)[0], "wan_ip": ips.get(SYNTH_WAN, SYNTH_WAN)},
        "scan": {k: v for k, v in style.items() if k != "hist_hours"},
        "sha256": {"attack_inject.log": _sha(atk), "fortigate_scenarios.py": _sha(Path(fs.__file__)),
                   "fortigate_gen.py": _sha(Path(fg.__file__)), "inject.py": _sha(Path(__file__)),
                   "inject_scan.py": _sha(Path(isc.__file__))},
        "created_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    with open(out / "manifest.json", "w", encoding="utf-8", newline="\n") as f:
        json.dump(manifest, f, indent=1)
    log.info("%s: %d attack lines, fits=%s, scan %.1fs", out.name, len(lines), window["fits"], style["scan_s"])
    return manifest


def _single_log(d: Path) -> Path:
    files = [p for p in d.iterdir() if p.is_file() and p.suffix.lower() not in (".md", ".json")]
    if len(files) != 1:
        raise SystemExit(f"{d}: expected exactly one log file, found {len(files)}")
    return files[0]


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--keys", default=",".join(KEYS), help="real log keys under --raw-root")
    ap.add_argument("--raw-root", type=Path, default=REPO / "data" / "raw")
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--scenarios", default=",".join(IDS))
    ap.add_argument("--entities", choices=["isolated", "generator"], default="isolated")
    ap.add_argument("--nets", choices=["auto", "busy24"], default="auto",
                    help="busy24: map into /16s the background uses (exact /24s free); validates the n30/n50 fallback")
    ap.add_argument("--max-rows", type=int, default=None, help="cap rows scanned per background")
    ap.add_argument("--slice-of", default=None, help="copy the head of this key instead of hard-linking")
    ap.add_argument("--slice-mb", type=int, default=300)
    ap.add_argument("--name", default=None, help="set name (default <key>, or <key>slice with --slice-of)")
    ap.add_argument("--force", action="store_true")
    a = ap.parse_args(argv)
    ids = [x.strip().upper() for x in a.scenarios.split(",") if x.strip()]
    if a.slice_of:
        jobs = [(a.name or f"{a.slice_of}slice", a.slice_of, a.slice_mb << 20)]
    else:
        jobs = [(a.name or k, k, None) for k in a.keys.split(",") if k]
    for name, key, sb in jobs:
        m = make_set(name, _single_log(a.raw_root / key), a.raw_root, a.seed, ids, a.max_rows, sb, a.force,
                     entities=a.entities, nets=a.nets)
        log.info("%s", json.dumps({"name": m["name"], "window_fits": m["window"]["fits"], "counts": m["counts"],
                                   "conventions": m["scan"]["conventions"], "rows_read": m["scan"]["rows_read"],
                                   "scan_s": m["scan"]["scan_s"]}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
