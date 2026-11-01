"""Shared constants, the seeded RNG and the event tuple for the cloud attack generator.

Address plan (never mixed): 203.0.113.0/24 = attacker infrastructure ONLY; 192.0.2.0/24 = corp egress + VPN;
198.51.100.0/24 = home ISPs, CI runners, Azure automation, the real traveller; 10.0.0.0/8 = in-cloud workloads.
Company: Bengaluru (IST = UTC+5:30), business hours 09:00-19:00 IST = 03:30-13:30 UTC.
"""

from __future__ import annotations

import random
import uuid
from datetime import datetime, timezone
from typing import Any, NamedTuple

START_MS = 1792368000000           # 2026-10-19T00:00:00Z, a Monday
DAY = 86_400_000
HOUR = 3_600_000
MIN = 60_000
SEC = 1000

# ---- AWS
ACCT_PROD, ACCT_DEV = "111122223333", "444455556666"
ACCT_EXTERNAL = "999988887777"     # attacker-controlled account (snapshot share target)
REGIONS = ("ap-south-1", "us-east-1", "eu-west-1")
# ---- Azure
TENANT = "4d5f1c2e-0000-4000-8000-0000000000a1"
SUB = "9b0e6a51-0000-4000-8000-0000000000b2"
AAD_RESOURCE = f"/tenants/{TENANT}/providers/Microsoft.aadiam"
DOMAIN = "corp.example"
OWNER_ROLE = "8e3af657-a8ff-443c-a75c-2fe8c4bcb635"      # built-in role definition ids (public constants)
READER_ROLE = "acdd72a7-3385-48ef-bd42-f606fba81ae7"
# ---- GCP
PROJ_PROD, PROJ_DATA = "corp-prod-1234", "corp-data-5678"

# ---- IP plan
CORP_IPS = ("192.0.2.10", "192.0.2.11")
VPN_IPS = tuple(f"192.0.2.{i}" for i in range(20, 30))
CI_IPS = tuple(f"198.51.100.{i}" for i in range(40, 46))
AZ_AUTOMATION_IP = "198.51.100.60"
TRAVEL_IP = "198.51.100.200"       # vreddy, Singapore hotel (real traveller, near-miss)
BACKUP_IP = "10.20.0.5"

# Named employees: (id, display name, role). Every one exists in Entra ID; AWS / GCP subsets below.
EMPLOYEES = (("asharma", "Aarti Sharma", "admin"), ("pmehta", "Priya Mehta", "dev"),
             ("vreddy", "Vikram Reddy", "dev"), ("kiyer", "Kavya Iyer", "finance"), ("rnair", "Rohan Nair", "ops"),
             ("dsingh", "Deepak Singh", "data"), ("mjoshi", "Meera Joshi", "marketing"),
             ("tgupta", "Tarun Gupta", "dev"), ("lfernandes", "Lena Fernandes", "data"),
             ("skapoor", "Sana Kapoor", "hr"), ("akumar", "Arjun Kumar", "ops"), ("nbose", "Nikhil Bose", "finance"))
_FIRST = ("anita", "bharat", "chitra", "dev", "esha", "farhan", "gita", "hari", "isha", "jay", "kiran", "leela")
_LAST = ("rao", "pillai", "menon")
EXTRA_STAFF = tuple((f"{f}.{l}", f"{f.title()} {l.title()}", "staff") for f in _FIRST for l in _LAST)  # 36
ALL_STAFF = EMPLOYEES + EXTRA_STAFF
AWS_HUMANS = ("asharma", "pmehta", "vreddy", "tgupta", "lfernandes", "rnair", "dsingh", "akumar")
GCP_HUMANS = ("asharma", "dsingh", "mjoshi", "pmehta", "lfernandes", "vreddy")


def home_ip(i: int) -> str:
    return f"198.51.100.{100 + i}"


def staff_index(user: str) -> int:
    return [u for u, _, _ in ALL_STAFF].index(user)


def iso_s(ms: int) -> str:
    return datetime.fromtimestamp(ms // 1000, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def iso_7(ms: int) -> str:
    """Log Analytics style: 7 fractional digits (ms precision, rest zero)."""
    return iso_s(ms)[:-1] + f".{ms % 1000:03d}0000Z"


def iso_9(ms: int, ns_tail: int) -> str:
    """Cloud Logging style: 9 fractional digits (ms + 6 sub-ms digits)."""
    return iso_s(ms)[:-1] + f".{ms % 1000:03d}{ns_tail % 1_000_000:06d}Z"


class Ev(NamedTuple):
    ts: int          # epoch ms exactly as written in the record (CloudTrail: whole seconds)
    feed: str        # cloudtrail | signin | audit | activity | blob | gcp
    rid: str         # stable record id (eventID / _ItemId / insertId) for deterministic ordering
    doc: dict[str, Any]


class Rand(random.Random):
    """Seeded RNG with id helpers. Same seed -> same bytes."""

    def guid(self) -> str:
        return str(uuid.UUID(int=self.getrandbits(128), version=4))

    def hexs(self, n: int) -> str:
        return "".join(self.choice("0123456789abcdef") for _ in range(n))

    def b32(self, n: int) -> str:
        return "".join(self.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567") for _ in range(n))

    def akid(self, prefix: str = "AKIA") -> str:
        return prefix + self.b32(16)

    def jitter(self, ms: int) -> int:
        return self.randint(-ms, ms)


def sub_rng(seed: int, *parts: object) -> Rand:
    """Independent deterministic stream per (seed, parts): chunking never changes the bytes."""
    key = "|".join(str(p) for p in (seed, *parts))
    h = 0
    for ch in key.encode():
        h = (h * 1_000_003 + ch) % (1 << 61)
    return Rand(h)
