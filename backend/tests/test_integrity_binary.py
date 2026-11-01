"""Binary files next to the logs (pcap, etl, legacy evt, ...) are hashed and sealed but never NUL-scanned:
NUL bytes are normal there, and ingest does not read them (profile.first_lines -> None). A text log whose head was
wiped with long NUL runs must still be NUL-scanned (and flagged)."""

from __future__ import annotations

import struct
from pathlib import Path

from attacklens import integrity
from attacklens.profile import first_lines

LOG = b"".join(b"Oct 24 02:%02d:00 ws-fin-010 sshd[%d]: Accepted password for alice from 10.0.0.%d port 22\n"
               % (i, 1000 + i, i) for i in range(40))


def _pcap(n_packets: int = 3) -> bytes:
    """Little-endian pcap: global header + packets whose payload is zero-padded (long NUL runs)."""
    out = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    for i in range(n_packets):
        payload = b"\x45\x00\x00\x54" + b"\x00" * 80
        out += struct.pack("<IIII", 1792807200 + i, 0, len(payload), len(payload)) + payload
    return out


def _zeroed(rep: dict, name: str) -> int:
    return next(f["zeroed_bytes"] for f in rep["files"] if f["file"].endswith(name))


def test_pcap_without_listed_suffix_is_not_nul_scanned(tmp_path: Path) -> None:
    raw = tmp_path / "raw"
    raw.mkdir()
    (raw / "auth.log").write_bytes(LOG)
    (raw / "capture.bin").write_bytes(_pcap())  # suffix not in binary_suffixes, magic not in the short list
    assert first_lines(raw / "capture.bin") is None  # ingest treats it as binary
    rep = integrity.check(raw, tmp_path / "out")
    assert [f for f in rep["findings"] if f["check"] == "zeroed_regions"] == []
    assert _zeroed(rep, "capture.bin") == 0
    row = next(f for f in rep["files"] if f["file"].endswith("capture.bin"))
    assert row["sha256"] and row["size"] == len(_pcap())  # still hashed
    assert rep["verdict"] != "tampered"


def test_text_log_with_wiped_head_is_still_flagged(tmp_path: Path) -> None:
    raw = tmp_path / "raw"
    raw.mkdir()
    (raw / "auth.log").write_bytes(b"\x00" * 600 + LOG[600:])  # > 5 % NUL in the head, but one long run
    rep = integrity.check(raw, tmp_path / "out")
    assert _zeroed(rep, "auth.log") == 600
    assert rep["verdict"] == "tampered"
