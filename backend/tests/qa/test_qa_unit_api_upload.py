"""QA unit / white-box tests for attacklens.api_upload (track qa_coverage_unit), UploadManager used directly (no API).

Baseline coverage left these branches unexecuted: a name that sanitizes to empty ('.', 'dir/'), a Content-Disposition
without filename=, register_local outside upload.local_roots (403) and over max_bytes (413), the cleanup when the
copy fallback fails, GET /api/uploads on a missing root and on an upload dir whose .meta file is gone, and _rel for a
root outside the repo. Exact status codes, messages and on-disk state.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from attacklens import api_upload as au
from attacklens.api_upload import UploadConfig, UploadError, UploadManager


def mgr(tmp: Path, **kw) -> UploadManager:
    return UploadManager(UploadConfig(root=tmp / "up", **kw), repo_root=tmp / "repo", disk_free=lambda p: 10**15)


def src_file(tmp: Path, name: str = "fw.log", body: bytes = b"a\nb\n") -> Path:
    d = tmp / "src"
    d.mkdir(exist_ok=True)
    p = d / name
    p.write_bytes(body)
    return p


@pytest.mark.parametrize("raw", [".", "dir/", "dir\\\\", "./"])
def test_sanitize_to_empty_rejected(raw: str) -> None:
    with pytest.raises(UploadError) as ei:
        au.sanitize_name(raw, au.DEFAULT_EXT)
    assert (ei.value.status, ei.value.detail) == (400, "empty file name")


def test_sanitize_near_miss_kept() -> None:
    assert au.sanitize_name("..hidden.log"[1:], au.DEFAULT_EXT) == "hidden.log"   # '.hidden.log': dot stripped


@pytest.mark.parametrize("disp, expected", [
    (b'form-data; name="files"; filename="a b.log"', "a b.log"),
    (b"form-data; name=files; filename=C:\\x\\y.log", "C:\\x\\y.log"),           # raw, IE-style path kept
    (b'form-data; name="files"; FILENAME="UP.LOG"', "UP.LOG"),
    (b'form-data; name="files"', None),                                          # not a file part
    (b'form-data; name="files"; filename=""', ""),
])
def test_raw_filename(disp: bytes, expected: str | None) -> None:
    assert au._raw_filename(disp) == expected


def test_register_local_outside_local_roots_403(tmp_path: Path) -> None:
    f = src_file(tmp_path)
    m = mgr(tmp_path, local_roots=[(tmp_path / "allowed").resolve()])
    with pytest.raises(UploadError) as ei:
        m.register_local(str(f))
    assert (ei.value.status, ei.value.detail) == (403, "path is outside upload.local_roots")
    ok = mgr(tmp_path, local_roots=[(tmp_path / "src").resolve()]).register_local(str(f))   # near miss: inside
    assert ok["files"] == [{"name": "fw.log", "bytes": 4}] and ok["mode"] in ("link", "copy")


def test_register_local_over_max_bytes_413(tmp_path: Path) -> None:
    f = src_file(tmp_path, body=b"x" * 11)
    with pytest.raises(UploadError) as ei:
        mgr(tmp_path, max_bytes=10).register_local(str(f))
    assert (ei.value.status, ei.value.detail) == (413, "file exceeds max_bytes (10)")
    assert mgr(tmp_path, max_bytes=11).register_local(str(f))["total_bytes"] == 11      # exactly the cap: ok


def test_register_local_copy_failure_leaves_nothing(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    f = src_file(tmp_path)
    m = UploadManager(UploadConfig(root=tmp_path / "up", min_free_bytes=100), repo_root=tmp_path,
                      disk_free=lambda p: 50)                                  # link fails -> copy -> 507

    def no_link(a, b):
        raise OSError("cross-device")
    monkeypatch.setattr(os, "link", no_link)
    with pytest.raises(UploadError) as ei:
        m.register_local(str(f))
    assert ei.value.status == 507
    incoming = tmp_path / "up" / au.INCOMING_DIR
    assert not incoming.exists() or list(incoming.iterdir()) == []             # partial dir removed
    assert m.list() == []


def test_list_missing_root_and_missing_meta(tmp_path: Path) -> None:
    m = mgr(tmp_path)
    assert m.list() == []                                                      # root does not exist yet
    info = m.register_local(str(src_file(tmp_path, body=b"12345")))
    (tmp_path / "up" / au.META_DIR / f"{info['upload_id']}.json").unlink()    # metadata lost
    (tmp_path / "up" / "not-an-upload").mkdir()                                # ignored: not an upload id
    (tmp_path / "up" / "up-20261101-000000-zzzzzz").mkdir()                    # ignored: id regex (hex only)
    got = m.list()
    assert [g["upload_id"] for g in got] == [info["upload_id"]]
    g = got[0]
    assert (g["mode"], g["files"], g["total_bytes"]) == ("unknown", [{"name": "fw.log", "bytes": 5}], 5)
    assert g["created_at"].endswith("Z") and len(g["created_at"]) == 20


def test_list_corrupt_meta_falls_back(tmp_path: Path) -> None:
    m = mgr(tmp_path)
    info = m.register_local(str(src_file(tmp_path)))
    (tmp_path / "up" / au.META_DIR / f"{info['upload_id']}.json").write_text("{not json", encoding="utf-8")
    assert m.list()[0]["mode"] == "unknown"


def test_rel_outside_repo_is_absolute(tmp_path: Path) -> None:
    m = mgr(tmp_path)                                                          # repo_root = tmp/repo, root = tmp/up
    info = m.register_local(str(src_file(tmp_path)))
    assert info["raw_dir"] == (tmp_path / "up" / info["upload_id"]).resolve().as_posix()
    inside = UploadManager(UploadConfig(root=tmp_path / "up"), repo_root=tmp_path, disk_free=lambda p: 10**15)
    assert inside._rel(tmp_path / "up" / "x") == "up/x"                        # near miss: repo-relative


def test_meta_file_content_exact(tmp_path: Path) -> None:
    m = mgr(tmp_path)
    info = m.register_local(str(src_file(tmp_path, name="A.CSV", body=b"h\n1\n")))
    meta = json.loads((tmp_path / "up" / au.META_DIR / f"{info['upload_id']}.json").read_text("utf-8"))
    assert meta == info
    assert set(meta) == {"upload_id", "raw_dir", "files", "total_bytes", "mode", "created_at"}
    assert meta["files"] == [{"name": "A.CSV", "bytes": 4}]
    assert au._ID_RE.match(meta["upload_id"])


def test_from_pipeline_resolves_relative_and_lowercases_ext(tmp_path: Path) -> None:
    cfg = UploadConfig.from_pipeline({"upload": {"root": "data/up", "allowed_extensions": [".LOG", ".Csv"],
                                                 "local_roots": ["logs", str(tmp_path)], "max_bytes": 5}},
                                     repo_root=tmp_path / "repo")
    assert cfg.root == (tmp_path / "repo" / "data" / "up").resolve()
    assert cfg.allowed == (".log", ".csv") and cfg.max_bytes == 5
    assert cfg.local_roots == [(tmp_path / "repo" / "logs").resolve(), tmp_path.resolve()]
    d = UploadConfig.from_pipeline({}, repo_root=tmp_path)
    assert d.local_roots is None and d.allowed == au.DEFAULT_EXT and d.max_bytes == 64 * 2**30
