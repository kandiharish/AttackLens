"""QA unit / white-box tests for attacklens.api_runs (track qa_coverage_unit): log-tail stage progress, run failure
reason extraction (pipeline line > traceback line > generic note, stage suffix, 300-char cap), and the raw_dir /
out_dir confinement rules (every rejection branch has a positive and a near miss). No subprocess is spawned."""

from __future__ import annotations

from pathlib import Path

import pytest

from attacklens import api_runs as ar


def _log(tmp: Path, text: str, name: str = "run.log") -> Path:
    p = tmp / name
    p.write_text(text, encoding="utf-8")
    return p


# ---- _furthest_stage -------------------------------------------------------------------------------------------
def test_furthest_stage_is_monotonic_max(tmp_path: Path) -> None:
    p = _log(tmp_path, "stage ingest start\nstage detect start\nstage episodes start\nstage ingest start\n")
    assert ar._furthest_stage(p) == "episodes"          # furthest by STAGE_PERCENT, not last mentioned
    assert ar._furthest_stage(_log(tmp_path, "nothing here\n", "b.log")) is None
    assert ar._furthest_stage(tmp_path / "missing.log") is None   # OSError branch


def test_furthest_stage_word_boundary_near_miss(tmp_path: Path) -> None:
    # 'ingested' / 'relink' / 'publisher' are not the stage words; only 'profile' counts
    p = _log(tmp_path, "stage profile start\nprofile done; ingested 10 rows; relink; publisher\n")
    assert ar._furthest_stage(p) == "profile"


def test_furthest_stage_reads_only_tail(tmp_path: Path) -> None:
    # a stage word older than the last 64 KiB is not seen
    p = _log(tmp_path, "stage publish start\n" + "x" * (ar._TAIL_BYTES + 10) + "\nstage detect start\n")
    assert ar._furthest_stage(p) == "detect"


# ---- run_error ---------------------------------------------------------------------------------------------------
def test_run_error_prefers_pipeline_failed_line(tmp_path: Path) -> None:
    p = _log(tmp_path, "2026-10-31 10:00:00,123 INFO attacklens.run: stage ingest start\n"
                       "2026-10-31 10:00:01,000 INFO attacklens.run: stage detect start\n"
                       "Traceback (most recent call last):\n"
                       "duckdb.IOException: IO Error: tb line 'secret-a'\n"
                       "2026-10-31 10:00:02,000 ERROR attacklens.run: pipeline failed: "
                       "IOException: IO Error: No files found \"C:/secret/x\"\n")
    assert ar.run_error(p) == "IOException: IO Error: No files found <redacted> (stage detect)"


def test_run_error_falls_back_to_traceback_line(tmp_path: Path) -> None:
    p = _log(tmp_path, "stage link start\nTraceback (most recent call last):\n  File \"x.py\", line 3\n"
                       "KeyError: 'episode_id'\n")
    assert ar.run_error(p) == "KeyError: <redacted> (stage link)"


def test_run_error_generic_and_unknown_stage(tmp_path: Path) -> None:
    # 'stage warmup start' is not a pipeline stage -> no suffix; no exception text -> generic note
    p = _log(tmp_path, "stage warmup start\nsomething odd happened\n")
    assert ar.run_error(p) == "run failed (no exception message in the log)"
    assert ar.run_error(tmp_path / "nope.log") == "run failed (log unreadable)"


def test_run_error_cap_includes_suffix(tmp_path: Path) -> None:
    p = _log(tmp_path, "stage incidents start\npipeline failed: ValueError: " + "w " * 400 + "\n")
    e = ar.run_error(p)
    assert len(e) == ar._ERR_MAX and e.endswith("... (stage incidents)") and e.startswith("ValueError: w w")
    short = ar.run_error(_log(tmp_path, "pipeline failed: ValueError: short\n", "s.log"))
    assert short == "ValueError: short"                   # near miss: under the cap, no stage started


@pytest.mark.parametrize("msg, expected", [
    ("", ""),
    ("Error 42: plain", "Error 42: plain"),               # head is not an identifier -> whole message is the body
    ("KeyError: ", "KeyError:"),                         # stripped, no separator left
    ("X: a\x00b\tc", "X: a b c"),                        # control chars -> spaces, collapsed
    ("X: bad 'it\\'s secret' value", "X: bad <redacted> value"),
    ("X: before\nLINE 1: SELECT 'secret'", "X: before <redacted>"),
    ("X: a `tick` b", "X: a <redacted> b"),
])
def test_sanitize_error_branches(msg: str, expected: str) -> None:
    assert ar.sanitize_error(msg) == expected


def test_cap_exact() -> None:
    assert ar._cap("abcdef", 6) == "abcdef"
    assert ar._cap("abcdefg", 6) == "abc..."


# ---- confined / confined_raw ----------------------------------------------------------------------------------
@pytest.fixture
def roots(tmp_path: Path) -> tuple[Path, Path, Path]:
    raw, out = tmp_path / "raw", tmp_path / "out"
    up = raw / "uploads"
    for d in (raw / "set1" / "sub", up / "up-1", up / ".incoming" / "up-2", out):
        d.mkdir(parents=True, exist_ok=True)
    return raw, up, out


def test_confined_depth_and_names(roots) -> None:
    raw, _, out = roots
    assert ar.confined(str(out / "run_a"), out, "out_dir", depth=1) == (out / "run_a").resolve()
    with pytest.raises(ValueError, match="exactly"):
        ar.confined(str(out / "a" / "b"), out, "out_dir", depth=1)        # nested out dir
    with pytest.raises(ValueError, match=r"names of \[A-Za-z0-9._-\]"):
        ar.confined(str(out / "bad name"), out, "out_dir")
    with pytest.raises(ValueError, match="sub-directory"):
        ar.confined(str(out), out, "out_dir")                            # the root itself
    with pytest.raises(ValueError, match="must be under"):
        ar.confined(str(raw / "set1"), out, "out_dir")                   # outside root
    with pytest.raises(ValueError, match="must be under"):
        ar.confined(str(out / ".." / "raw" / "set1"), out, "out_dir")    # '..' resolved, then outside


def test_confined_error_never_echoes_path(roots) -> None:
    _, _, out = roots
    with pytest.raises(ValueError) as ei:
        ar.confined("C:/Users/secret-name/x", out, "out_dir")
    assert "secret-name" not in str(ei.value)


def test_confined_raw_accepts_set_and_upload(roots) -> None:
    raw, up, _ = roots
    assert ar.confined_raw(str(raw / "set1"), raw, up) == (raw / "set1").resolve()
    assert ar.confined_raw(str(up / "up-1"), raw, up) == (up / "up-1").resolve()


@pytest.mark.parametrize("rel, match", [
    ("uploads", "not a directory that holds uploads"),        # the upload root itself
    ("uploads/.incoming/up-2", "no hidden directories"),     # partial upload
    ("set1/sub", "raw_dir must be"),                         # deeper than data/raw/<set>
    ("uploads/up-1/x", "raw_dir must be"),                   # deeper than <upload root>/<id>
    (".hidden", "no hidden directories"),
])
def test_confined_raw_rejections(roots, rel: str, match: str) -> None:
    raw, up, _ = roots
    with pytest.raises(ValueError, match=match):
        ar.confined_raw(str(raw / rel), raw, up)


def test_confined_raw_rejects_folder_holding_uploads(tmp_path: Path) -> None:
    raw = tmp_path / "raw"
    up = raw / "nested" / "uploads"                         # upload root two levels down
    up.mkdir(parents=True)
    with pytest.raises(ValueError, match="not a directory that holds uploads"):
        ar.confined_raw(str(raw / "nested"), raw, up)
    other = raw / "plain"
    other.mkdir()
    assert ar.confined_raw(str(other), raw, up) == other.resolve()   # near miss: a sibling set is fine


def test_stage_percent_monotonic_in_pipeline_order() -> None:
    order = ["profile", "ingest", "lookups", "detect", "episodes", "link", "incidents", "publish", "integrity", "eval"]
    assert list(ar.STAGE_PERCENT) == order
    vals = [ar.STAGE_PERCENT[s] for s in order]
    assert vals == sorted(vals) and len(set(vals)) == len(vals) and vals[-1] < 100


# ---- RunManager.start rejections (no pipeline is spawned; the positive case runs a no-op stub) -------------------
@pytest.fixture
def rm(tmp_path: Path):
    import sys
    raw, out = tmp_path / "raw", tmp_path / "out"
    (raw / "set1").mkdir(parents=True)
    (raw / "set1" / "ground_truth").mkdir()
    (raw / "set1" / "ground_truth" / "attacks.json").write_text("[]", encoding="utf-8")
    out.mkdir()
    m = ar.RunManager(runs_dir=tmp_path / "runs", raw_root=raw, out_root=out,
                      runner=[sys.executable, "-c", "import sys; sys.exit(0)"], parquet_root=tmp_path / "pq")
    yield m, raw, out
    for j in m.jobs():
        j.proc.wait(timeout=30)


def test_start_raw_dir_missing(rm) -> None:
    m, raw, _ = rm
    with pytest.raises(ValueError, match="^raw_dir is not an existing directory$"):
        m.start(str(raw / "nope"), None, None)
    assert m.jobs() == []


def test_start_ground_truth_missing_or_outside(rm, tmp_path: Path) -> None:
    m, raw, _ = rm
    with pytest.raises(ValueError, match="^ground_truth is not an existing file$"):
        m.start(str(raw / "set1"), None, str(raw / "set1" / "ground_truth" / "missing.json"))
    with pytest.raises(ValueError, match="^ground_truth is not an existing file$"):
        m.start(str(raw / "set1"), None, str(raw / "set1" / "ground_truth"))          # a directory
    outside = tmp_path / "gt.json"
    outside.write_text("[]", encoding="utf-8")
    with pytest.raises(ValueError, match="^ground_truth must be under"):
        m.start(str(raw / "set1"), None, str(outside))
    assert m.jobs() == []


def test_start_with_ground_truth_builds_exact_cmd(rm) -> None:
    m, raw, out = rm
    gt = raw / "set1" / "ground_truth" / "attacks.json"
    job = m.start(str(raw / "set1"), None, str(gt))
    assert job.cmd[-6:] == ["--raw", str((raw / "set1").resolve()), "--out", str((out / "set1").resolve()),
                            "--ground-truth", str(gt.resolve())]
    job.proc.wait(timeout=30)
    st = m.status(job)
    assert (st["status"], st["stage"], st["percent"], st["error"], st["returncode"]) == ("succeeded", "done", 100,
                                                                                       None, 0)


def test_start_protected_out_dir(rm) -> None:
    m, raw, out = rm
    served = out / "set1"
    with pytest.raises(ValueError, match="^out_dir is the output the API is serving now"):
        m.start(str(raw / "set1"), str(served), None, protect=[served])
    job = m.start(str(raw / "set1"), None, None, protect=[served, None])     # default out -> fresh <set>-<run_id>
    assert job.out_dir == (out / f"set1-{job.run_id}").resolve()
    assert job.cmd[-2:] == ["--parquet", str(m.parquet_root / "set1")]


# ---- product bug QA-COV-03 ---------------------------------------------------------------------------------------
PROFILE_TAIL = ("2026-11-01 00:57:49,450 INFO attacklens.run: stage profile start\n"
                "2026-11-01 00:57:49,583 WARNING attacklens.profile: unrecognized file eval-notes.txt: no text line "
                "found (empty or binary)\n"
                "2026-11-01 00:57:54,999 INFO attacklens.run: stage ingest start\n")


# QA-COV-03 fixed: _furthest_stage only reads run.py's "stage <name> start|done" lines
def test_furthest_stage_ignores_stage_words_in_file_names(tmp_path: Path) -> None:
    assert ar._furthest_stage(_log(tmp_path, PROFILE_TAIL)) == "ingest"


def test_furthest_stage_ignores_integrity_log_file_name(tmp_path: Path) -> None:
    # a raw file named integrity.log (logged by profile) must not jump the shown stage to 'integrity' (93 %)
    tail = PROFILE_TAIL.replace("eval-notes.txt", "integrity.log")
    assert ar._furthest_stage(_log(tmp_path, tail)) == "ingest"
    done = tail + "2026-11-01 01:10:00,000 INFO attacklens.run: stage integrity start\n"
    assert ar._furthest_stage(_log(tmp_path, done, "b.log")) == "integrity"   # the real stage line still counts


def test_furthest_stage_near_miss_neutral_file_name(tmp_path: Path) -> None:
    assert ar._furthest_stage(_log(tmp_path, PROFILE_TAIL.replace("eval-notes", "readme"))) == "ingest"
