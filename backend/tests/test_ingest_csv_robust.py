"""CSV ingest robustness (reports/robust/SUMMARY.md item 1): a header column named like DuckDB's `filename`
pseudo-column, RFC 4180 doubled quotes (Purview AuditData JSON, Excel), field-count mismatches counted with a reason,
BOM + CRLF exports. Fixtures are made up and written inline; routing is by content, never by file name."""

from __future__ import annotations

import json
from pathlib import Path

from attacklens import db, ingest, profile

from .conftest import _new_ctx, query, run_ingest

T0 = 1793355480000  # 2026-10-30T10:18:00Z
MISMATCH_DROP = "field_count_mismatch (fewer fields than the header, row not readable)"
MISMATCH_NOTE = "field_count_mismatch (more fields than the header: extras dropped, row kept)"


def _raw(tmp: Path, name: str, body: bytes) -> Path:
    raw = tmp / "raw"
    raw.mkdir(parents=True, exist_ok=True)
    (raw / name).write_bytes(body)
    return raw


def _acc(tmp: Path) -> dict[str, dict]:
    return {a["source_type"]: a for a in json.loads((tmp / "out" / "ingest_accounting.json").read_text("utf-8"))}


def test_filename_header_column_ingests_with_accounting(tmp_path: Path) -> None:
    body = ("timestamp,device,src,sport,dst,dport,action,user,FileName\r\n"
            "2026-10-30T10:18:00Z,fw01,192.0.2.10,50112,203.0.113.57,443,accept,alice,invoice.pdf\r\n"
            "2026-10-30T10:18:07Z,fw01,192.0.2.10,50113,203.0.113.58,8443,deny,alice,payload.exe\r\n"
            "2026-10-30T10:19:12Z,fw01,198.51.100.77,61002,192.0.2.22,445,deny,,report.xlsx\r\n").encode()
    ctx = run_ingest(_raw(tmp_path, "proxy_export.csv", body), tmp_path)
    try:
        rows = query(ctx, "SELECT ts_ms, src_ip, dst_port, raw_line FROM events ORDER BY ts_ms")
    finally:
        ctx.con.close()
    fw = _acc(tmp_path)["firewall_csv"]
    assert (fw["rows_in"], fw["rows_ok"], fw["dropped"], fw["drop_reasons"]) == (3, 3, 0, {})
    assert [(r["ts_ms"], r["src_ip"], r["dst_port"]) for r in rows] == \
        [(T0, "192.0.2.10", 443), (T0 + 7000, "192.0.2.10", 8443), (T0 + 72000, "198.51.100.77", 445)]
    assert rows[1]["raw_line"].endswith(",payload.exe")                        # the FileName value is data


def _audit(i: int, op: str, status: str, ip: str, extra: str = "") -> str:
    doc = {"CreationTime": f"2026-10-30T13:0{i}:00", "Id": f"u-{i}", "Operation": op,
           "OrganizationId": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", "RecordType": 15, "ResultStatus": status,
           "UserId": "ivan@contoso.example.com", "ClientIP": ip, "ObjectId": f"Doc {i}, final.xlsx{extra}"}
    return '"' + json.dumps(doc, separators=(",", ":")).replace('"', '""') + '"'


PURVIEW = ("\ufeffRecordId,CreationDate,RecordType,Operation,UserId,AuditData,AssociatedAdminUnits,"
           "AssociatedAdminUnitsNames\r\n"
           + "".join(f"u-{i},2026-10-30T13:0{i}:00.0000000Z,AzureActiveDirectoryStsLogon,{op},"
                     f"ivan@contoso.example.com,{_audit(i, op, st, ip, ex)},,\r\n"
                     for i, (op, st, ip, ex) in enumerate([
                         ("UserLoginFailed", "Failed", "203.0.113.57", ""),
                         ("UserLoggedIn", "Success", "203.0.113.57", ' "quoted"'),
                         ("FileDownloaded", "", "[2001:db8::25]:51544", ""),
                         ("UserLoggedIn", "Success", "203.0.113.57:4431", "")])))


def test_purview_auditdata_json_intact(tmp_path: Path) -> None:
    raw = _raw(tmp_path, "Audit_Search_2026-10-31.csv", PURVIEW.encode("utf-8"))
    ctx = run_ingest(raw, tmp_path)
    try:
        rows = query(ctx, "SELECT ts_ms, action, outcome, src_ip, host, src_user, target_user, raw_line, "
                          "json_valid(nullif(regexp_extract(raw_line, '(\\{.*\\})', 1), '')) AS ok "
                          "FROM events WHERE source_type = 'm365_purview_csv' ORDER BY ts_ms")
        # the CSV reader itself: AuditData parses as JSON on every row (doubled quotes unescaped, commas kept)
        from attacklens import ingest_csv
        src = ingest_csv.csv_reader([str(p) for p in raw.glob("*.csv")], ",", ingest_csv.dialect(
            ctx.cfg["sources"], ctx.cfg["sources"]["csv_sources"]["m365_purview_csv"]))
        n_valid = ctx.con.execute(f"SELECT count(*) FILTER (WHERE json_valid(AuditData)), count(*) FROM {src}").fetchone()
    finally:
        ctx.con.close()
    acc = _acc(tmp_path)["m365_purview_csv"]
    assert (acc["rows_in"], acc["rows_ok"], acc["dropped"]) == (4, 4, 0) and "notes" not in acc
    assert n_valid == (4, 4)
    assert [r["ok"] for r in rows] == [True, True, True, True]
    assert [r["src_ip"] for r in rows] == ["203.0.113.57", "203.0.113.57", "2001:db8::25", "203.0.113.57"]
    assert [r["action"] for r in rows] == ["login_failed", "login_success", "other", "login_success"]
    assert [r["outcome"] for r in rows] == ["failure", "success", None, "success"]
    assert {r["host"] for r in rows} == {"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"}
    assert rows[0]["ts_ms"] == 1793365200000                                   # 2026-10-30T13:00:00Z
    assert 'Doc 1, final.xlsx \\"quoted\\""}' in rows[1]["raw_line"]          # JSON escapes and commas intact


FW = "timestamp,device,src,sport,dst,dport,action,user,comment\n"


def test_field_count_mismatch_counted_with_reason(tmp_path: Path) -> None:
    body = (FW
            + "2026-10-30T10:18:00Z,fw01,192.0.2.10,50112,203.0.113.57,443,accept,alice,ok\n"
            + '2026-10-30T10:18:07Z,fw01,192.0.2.10,50113,203.0.113.58,8443,deny,alice,"has, quote",EXTRA\n'
            + "2026-10-30T10:18:09Z,fw01,192.0.2.11,50114,203.0.113.59,22,deny,bob,plain,EXTRA,MORE\n"
            + "2026-10-30T10:19:12Z,fw01,198.51.100.77\n").encode()
    ctx = run_ingest(_raw(tmp_path, "fw.csv", body), tmp_path)
    try:
        n = ctx.con.execute("SELECT count(*) FROM events").fetchone()[0]
    finally:
        ctx.con.close()
    fw = _acc(tmp_path)["firewall_csv"]
    assert (fw["rows_in"], fw["rows_ok"], fw["dropped"]) == (4, 3, 1) and n == 3
    assert fw["drop_reasons"] == {MISMATCH_DROP: 1}
    assert fw["notes"] == {MISMATCH_NOTE: 2}                                   # the quoted row is no longer skipped


def test_field_count_check_can_be_disabled(tmp_path: Path) -> None:
    body = (FW + '2026-10-30T10:18:07Z,fw01,192.0.2.10,50113,203.0.113.58,8443,deny,alice,"q",EXTRA\n').encode()
    raw = _raw(tmp_path, "fw.csv", body)
    ctx = _new_ctx(tmp_path, raw_dir=raw)
    ctx.cfg["sources"].setdefault("ingest_checks", {})["csv_field_count"] = False
    try:
        profile.run(ctx)
        ingest.run(ctx)
    finally:
        ctx.con.close()
    fw = _acc(tmp_path)["firewall_csv"]
    assert (fw["rows_in"], fw["rows_ok"]) == (1, 1) and MISMATCH_NOTE not in (fw.get("notes") or {})


def test_excel_bom_crlf_quoted_fields(tmp_path: Path) -> None:
    body = ("\ufefftimestamp,device,src,sport,dst,dport,action,user,comment\r\n"
            '2026-10-30T10:18:00Z,fw01,192.0.2.10,50112,203.0.113.57,443,accept,alice,"egress, ""allow-web"" policy"\r\n'
            '2026-10-30T10:18:07Z,fw01,192.0.2.10,50113,203.0.113.58,8443,deny,alice,"geo-block, matched rule 17"\r\n'
            '2026-10-30T10:19:12Z,fw01,198.51.100.77,61002,192.0.2.22,445,deny,,"inbound ""smb"", dropped"\r\n'
            ).encode("utf-8")
    ctx = run_ingest(_raw(tmp_path, "firewall_export.csv", body), tmp_path)
    try:
        rows = query(ctx, "SELECT ts_ms, host, src_ip, src_port, dst_ip, dst_port, src_user, raw_line "
                          "FROM events ORDER BY ts_ms")
    finally:
        ctx.con.close()
    fw = _acc(tmp_path)["firewall_csv"]
    assert (fw["rows_in"], fw["rows_ok"], fw["dropped"], fw["drop_reasons"]) == (3, 3, 0, {}) and "notes" not in fw
    assert [(r["ts_ms"], r["host"], r["src_ip"], r["src_port"], r["dst_ip"], r["dst_port"], r["src_user"])
            for r in rows] == [(T0, "fw01", "192.0.2.10", 50112, "203.0.113.57", 443, "alice"),
                               (T0 + 7000, "fw01", "192.0.2.10", 50113, "203.0.113.58", 8443, "alice"),
                               (T0 + 72000, "fw01", "198.51.100.77", 61002, "192.0.2.22", 445, None)]
    assert rows[0]["raw_line"].endswith('egress, "allow-web" policy')
    assert rows[2]["raw_line"].endswith('inbound "smb", dropped')              # was cut at the doubled quote


def test_csv_reader_and_rel_use_reserved_column() -> None:
    from attacklens import ingest_csv, ingest_sql
    assert db.SRC_FILE_COL == "__al_src_file"
    assert f"filename={db.sql_str(db.SRC_FILE_COL)}" in ingest_csv.csv_reader(["x.csv"], ",", ingest_csv.RFC4180)
    assert db.SRC_FILE_COL in ingest_sql._rel("C:/raw", db.SRC_FILE_COL)


# ---- sweep item 2 (Stage 0 owns decompression): line_reader never gunzips, binary / arrays never sniffed as text ----
def _gz_text(n: int = 2000) -> bytes:
    import gzip
    import random
    rnd = random.Random(7)
    return gzip.compress("".join(f"2026-10-30T10:18:00Z,fw01,192.0.2.{rnd.randint(1, 254)},{rnd.random()}\n"
                                 for _ in range(n)).encode())


def test_line_reader_never_gunzips(tmp_path: Path) -> None:
    body = _gz_text()
    for name in ("app.log.gz", "app.log"):
        (tmp_path / name).write_bytes(body)
    sql = db.line_reader([str(tmp_path / "app.log.gz"), str(tmp_path / "app.log")], filename=False)
    assert "compression='none'" in sql
    con = db.connect(memory_limit="512MB", threads=1, temp_directory=tmp_path / "spill")
    try:
        n_plain = con.execute(f"SELECT count(*) FROM {sql} WHERE contains(line, '2026-10-30T')").fetchone()[0]
    finally:
        con.close()
    assert n_plain == 0                                                        # raw bytes, never decompressed


def test_compressed_bytes_never_sniffed_as_text(tmp_path: Path) -> None:
    import bz2
    import lzma
    import zipfile
    from attacklens.config import load_config
    src = load_config()["sources"]
    plain = b"".join(b"timestamp,device,src,dst,dport\n2026-10-30T10:18:00Z,fw01,192.0.2.%d,1.2.3.4,443\n" % i
                     for i in range(300))
    (tmp_path / "a.log").write_bytes(_gz_text())
    (tmp_path / "b.log").write_bytes(bz2.compress(plain + _gz_text()))
    (tmp_path / "c.log").write_bytes(lzma.compress(plain + _gz_text()))
    with zipfile.ZipFile(tmp_path / "d.log", "w", compression=zipfile.ZIP_DEFLATED) as z:
        z.writestr("x.csv", plain + _gz_text())
    got = {n: profile.sniff_lines(profile.first_lines(tmp_path / n), src) for n in ("a.log", "b.log", "c.log", "d.log")}
    assert {n: g["format"] for n, g in got.items()} == dict.fromkeys(got, "unrecognized")
    assert [g["reason"].split()[0] for g in got.values()] == ["gzip", "bzip2", "xz", "zip"]
    assert all("final" not in g for g in got.values())


def test_json_array_not_routed_to_csv() -> None:
    from attacklens.config import load_config
    src = load_config()["sources"]
    one = ['[{"@timestamp":"2026-10-30T10:18:00Z","src":"192.0.2.1","dst":"1.2.3.4","dport":443,"device":"fw01"}]']
    pretty = ["[", '  {"@timestamp": "2026-10-30T10:18:00Z", "event": {"action": "x"}},', "  {", "  }", "]"]
    for lines in (one, pretty):
        info = profile.sniff_lines(lines, src)
        assert (info["format"], info["reason"]) == ("unrecognized", "json_array (unwrap failed)")
    assert profile.sniff("[Thu Oct 30 10:18:00 2026] [error] [client 192.0.2.1] denied", src)["reason"] != \
        "json_array (unwrap failed)"                                           # bracketed text logs are not arrays
