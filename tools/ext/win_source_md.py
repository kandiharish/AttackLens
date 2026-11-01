"""Write data/raw/ext_win_<name>/SOURCE.md: URLs, licence, fetch date, sha256 / size / rows of every file.
    python -I tools/ext/win_source_md.py NAME
"""
from __future__ import annotations

import hashlib
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SD = "https://raw.githubusercontent.com/OTRF/Security-Datasets/master/datasets"
SD_COMMIT = "d9d40ef123d2c87d5d3df28c96bcab4f0faccc87"
THP = ("https://github.com/OTRF/ThreatHunter-Playbook/tree/f7a58156dbfc9b019f17f638b8c62d22e557d350/"
       "docs/evals/apt29/steps")
LIC = ("Security-Datasets: MIT License (github.com/OTRF/Security-Datasets/blob/master/LICENSE). "
       "ThreatHunter-Playbook step docs: MIT License.")
META = f"{SD}/atomic/_metadata"
SETS = {
    "apt29d1": ("OTRF Security-Datasets compound/apt29 day 1 (APT29 ATT&CK Evaluations round 2 emulation, "
                "manual replay by R. Rodriguez)",
                [f"{SD}/compound/apt29/day1/apt29_evals_day1_manual.zip", f"{SD}/compound/apt29/emulationplans/apt29.xlsx",
                 THP + " (79 step YAMLs, list in .dl/otrf_steps_urls.txt)"]),
    "lsass_comsvcs": ("OTRF SDWIN-201018195009 Lsass Memory Dump via Comsvcs.dll",
                      [f"{SD}/atomic/windows/credential_access/host/psh_lsass_memory_dump_comsvcs.zip",
                       f"{META}/SDWIN-201018195009.yaml"]),
    "vbs_launcher": ("OTRF SDWIN-190518182022 Empire VBS Execution",
                     [f"{SD}/atomic/windows/execution/host/empire_launcher_vbs.zip", f"{META}/SDWIN-190518182022.yaml"]),
    "runkeys": ("OTRF SDWIN-190319023812 Empire Userland Registry Run Keys",
                [f"{SD}/atomic/windows/persistence/host/empire_persistence_registry_modification_run_keys_standard_user.zip",
                 f"{META}/SDWIN-190319023812.yaml"]),
    "psexec": ("OTRF SDWIN-190518210652 Empire Invoke PsExec",
               [f"{SD}/atomic/windows/lateral_movement/host/empire_psexec_dcerpc_tcp_svcctl.zip",
                f"{META}/SDWIN-190518210652.yaml"]),
    "sharpwmi": ("OTRF SDWIN-200806035621 Covenant SharpWMI Exec",
                 [f"{SD}/atomic/windows/lateral_movement/host/covenant_sharpwmi_create_dcerpc_wmi.zip",
                  f"{META}/SDWIN-200806035621.yaml"]),
    "overpth": ("OTRF SDWIN-190319131123 Empire Over-Pass-The-Hash",
                [f"{SD}/atomic/windows/credential_access/host/empire_over_pth_patch_lsass.zip",
                 f"{META}/SDWIN-190319131123.yaml"]),
    "evtlog_disable": ("OTRF SDWIN-220708104215 Stopping Event Log Service via Modification of Start Up Type",
                       [f"{SD}/atomic/windows/defense_evasion/host/psh_disable_eventlog_service_startuptype_modification.zip",
                        f"{META}/SDWIN-220708104215.yaml"]),
}


def sha(p: Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as f:
        while b := f.read(1 << 20):
            h.update(b)
    return h.hexdigest()


def rows(p: Path) -> str:
    if p.suffix.lower() != ".json":
        return "-"
    n = 0
    with p.open("rb") as f:
        while b := f.read(1 << 20):
            n += b.count(b"\n")
    return str(n)


def main() -> int:
    name = sys.argv[1]
    title, urls = SETS[name]
    base = ROOT / "data" / "raw" / f"ext_win_{name}"
    lines = [f"# ext_win_{name}", "", f"**Dataset:** {title}", "", "**Fetched:** 2026-11-01 (UTC), with curl from "
             f"raw.githubusercontent.com (Security-Datasets master = {SD_COMMIT}).", "", f"**Licence:** {LIC}", "",
             "**URLs:**", *[f"- {u}" for u in urls], "",
             "Layout: `.dl/` = downloads as fetched (hidden dir, not ingested), `src/` = the archive's JSON-lines "
             "file extracted as-is (zip members listed and checked for path traversal first, "
             "tools/ext/win_ziplist.py), `ground_truth/` = attacks.json built from the docs only "
             "(tools/ext/win_build_gt.py).", "", "| file | bytes | rows (lines) | sha256 |", "|---|---:|---:|---|"]
    for p in sorted(x for x in base.rglob("*") if x.is_file() and ".logs" not in x.parts and x.name != "SOURCE.md"):
        lines.append(f"| {p.relative_to(base).as_posix()} | {p.stat().st_size} | {rows(p)} | {sha(p)} |")
    (base / "SOURCE.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print((base / "SOURCE.md").as_posix())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
