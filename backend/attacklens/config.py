"""Load config/*.yaml into one dict: {"sources": ..., "rules": ..., "pipeline": ..., "ioc": ..., "allowlist": ...}."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import yaml

# ATTACKLENS_HOME (set by the desktop launcher, attacklens/desktop.py) replaces the repo root for frozen installs:
# <home>/config, <home>/data, <home>/frontend/dist. Unset -> the repo checkout (editable install), unchanged.
_HOME = os.environ.get("ATTACKLENS_HOME", "").strip()
REPO_ROOT = Path(_HOME).resolve() if _HOME else Path(__file__).resolve().parents[2]
CONFIG_DIR = REPO_ROOT / "config"


def load_config(config_dir: Path | None = None) -> dict[str, Any]:
    d = Path(config_dir or CONFIG_DIR)
    cfg: dict[str, Any] = {}
    for p in sorted(d.glob("*.yaml")):
        cfg[p.stem] = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    attack = d / "attack_v20.json"
    cfg["attack"] = json.loads(attack.read_text(encoding="utf-8")) if attack.exists() else {}
    return cfg
