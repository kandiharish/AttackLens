"""Offline IP enrichment for cloud detection (config/cloud.yaml `geo`). Nothing is downloaded at runtime.

Builds temp table `cl_ip_geo(ip, asn, as_desc, geo_cc, provider, corp_ip, prefix)` over the DISTINCT caller IPs of
the cloud rows (thousands, never the events):
- asn / as_desc / geo_cc: from an iptoasn TSV (range_start, range_end, AS_number, country_code, AS_description;
  ip2asn-v4 or ip2asn-combined, optionally .gz) when `geo.asn_db_path` exists. IPv4 ranges only (ASOF join).
- provider: 'aws' / 'gcp' / 'azure' when the IPv4 is inside a CIDR of `geo.provider_ranges.<name>` (any file that
  lists CIDRs: AWS ip-ranges.json, Google cloud.json, Azure ServiceTags JSON, or plain text).
- corp_ip: inside params.corp_egress_cidrs.
- prefix: the network key without an ASN: IPv4 /ipv4_prefix_bits (default 16), IPv6 first ipv6_prefix_hextets (3 = /48).
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import duckdb

from attacklens.db import sql_path
from attacklens.detect_sql import q

log = logging.getLogger(__name__)

IP4_RX = r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"
CIDR_RX = r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2})"


def _macros(con: duckdb.DuckDBPyConnection) -> None:
    con.execute(f"""CREATE OR REPLACE TEMP MACRO al_cl_ip4(ip) AS (
        CASE WHEN regexp_matches(ip, {q(IP4_RX)}) THEN
            TRY_CAST(split_part(ip, '.', 1) AS BIGINT) * 16777216 + TRY_CAST(split_part(ip, '.', 2) AS BIGINT) * 65536
            + TRY_CAST(split_part(ip, '.', 3) AS BIGINT) * 256 + TRY_CAST(split_part(ip, '.', 4) AS BIGINT) END)""")


def _cidr_table(con: duckdb.DuckDBPyConnection, name: str, cidrs_sql: str) -> None:
    """cidrs_sql: a SELECT of one VARCHAR column `c` (a.b.c.d/n) -> rows (name, lo, hi)."""
    con.execute(f"""INSERT INTO cl_cidr
        SELECT {q(name)}, (al_cl_ip4(split_part(c, '/', 1)) // p) * p, (al_cl_ip4(split_part(c, '/', 1)) // p) * p + p - 1
        FROM (SELECT c, CAST(pow(2, 32 - least(32, TRY_CAST(split_part(c, '/', 2) AS INTEGER))) AS BIGINT) AS p
              FROM ({cidrs_sql})) WHERE al_cl_ip4(split_part(c, '/', 1)) IS NOT NULL AND p IS NOT NULL""")


def _load_ranges(con: duckdb.DuckDBPyConnection, gcfg: dict[str, Any], params: dict[str, Any]) -> dict[str, int]:
    con.execute("CREATE OR REPLACE TEMP TABLE cl_cidr(name VARCHAR, lo BIGINT, hi BIGINT)")
    loaded: dict[str, int] = {}
    corp = [str(c) for c in params.get("corp_egress_cidrs") or []]
    if corp:
        _cidr_table(con, "corp", "SELECT unnest(" + "[" + ", ".join(q(c) for c in corp) + "]::VARCHAR[]) AS c")
    for prov, path in (gcfg.get("provider_ranges") or {}).items():
        if not path or not Path(path).exists():
            continue
        _cidr_table(con, str(prov), f"SELECT unnest(regexp_extract_all(content, {q(CIDR_RX)}, 1)) AS c "
                                    f"FROM read_text({sql_path(Path(path))})")
        loaded[str(prov)] = int(con.execute("SELECT count(*) FROM cl_cidr WHERE name = ?", [str(prov)]).fetchone()[0])
    return loaded


def _load_asn(con: duckdb.DuckDBPyConnection, path: str | None) -> bool:
    con.execute("CREATE OR REPLACE TEMP TABLE cl_asn(lo BIGINT, hi BIGINT, asn VARCHAR, cc VARCHAR, descr VARCHAR)")
    if not path or not Path(path).exists():
        return False
    con.execute(f"""INSERT INTO cl_asn
        SELECT al_cl_ip4(s), al_cl_ip4(e), a, nullif(upper(c), 'NONE'), d FROM read_csv({sql_path(Path(path))},
            delim='\\t', header=false, quote='', all_varchar=true, ignore_errors=true,
            columns={{'s': 'VARCHAR', 'e': 'VARCHAR', 'a': 'VARCHAR', 'c': 'VARCHAR', 'd': 'VARCHAR'}})
        WHERE al_cl_ip4(s) IS NOT NULL AND al_cl_ip4(e) IS NOT NULL AND a IS NOT NULL AND a <> '0'""")
    return True


def _prefix_sql(gcfg: dict[str, Any], ip: str = "ip") -> str:
    bits = max(1, min(32, int(gcfg.get("ipv4_prefix_bits", 16))))
    hx = max(1, min(8, int(gcfg.get("ipv6_prefix_hextets", 3))))
    step = 2 ** (32 - bits)
    v6_groups = (f"list_transform(CASE WHEN {ip} LIKE '%::%' THEN list_concat(string_split(split_part({ip}, '::', 1), "
                 f"':'), ['0', '0', '0', '0', '0', '0', '0', '0']) ELSE string_split({ip}, ':') END, "
                 "lambda g: coalesce(nullif(ltrim(lower(g), '0'), ''), '0'))")
    return (f"CASE WHEN al_cl_ip4({ip}) IS NOT NULL THEN 'v4:' || CAST(al_cl_ip4({ip}) // {step} AS VARCHAR) || '/{bits}' "
            f"WHEN {ip} LIKE '%:%' THEN 'v6:' || array_to_string(list_slice({v6_groups}, 1, {hx}), ':') "
            f"|| '/{hx * 16}' END")


def build_ip_geo(con: duckdb.DuckDBPyConnection, gcfg: dict[str, Any], params: dict[str, Any],
                 src: str = "cl_base") -> dict[str, Any]:
    """cl_ip_geo over the distinct src_ip of table `src`. Returns stats (what was loaded)."""
    _macros(con)
    has_asn = _load_asn(con, gcfg.get("asn_db_path"))
    ranges = _load_ranges(con, gcfg, params)
    cent = gcfg.get("country_centroids_path")
    con.execute("CREATE OR REPLACE TEMP TABLE cl_centroid(cc VARCHAR, lat DOUBLE, lon DOUBLE)")
    if cent and Path(cent).exists():
        con.execute(f"INSERT INTO cl_centroid SELECT upper(cc), TRY_CAST(lat AS DOUBLE), TRY_CAST(lon AS DOUBLE) "
                    f"FROM read_csv({sql_path(Path(cent))}, header=true, all_varchar=true)")
    con.execute(f"""CREATE OR REPLACE TEMP TABLE cl_ip_geo AS
        WITH ips AS (SELECT DISTINCT src_ip AS ip, al_cl_ip4(src_ip) AS n FROM {src} WHERE src_ip IS NOT NULL),
        a AS (SELECT ips.ip, ips.n, CASE WHEN ips.n <= x.hi THEN x.asn END AS asn,
                     CASE WHEN ips.n <= x.hi THEN x.descr END AS as_desc, CASE WHEN ips.n <= x.hi THEN x.cc END AS geo_cc
              FROM ips ASOF LEFT JOIN cl_asn x ON ips.n >= x.lo),
        r AS (SELECT a.ip, min(c.name) FILTER (WHERE c.name <> 'corp') AS provider,
                     coalesce(bool_or(c.name = 'corp'), false) AS corp_ip
              FROM a LEFT JOIN cl_cidr c ON a.n BETWEEN c.lo AND c.hi GROUP BY a.ip)
        SELECT a.ip, a.asn, a.as_desc, a.geo_cc, r.provider, r.corp_ip, {_prefix_sql(gcfg, 'a.ip')} AS prefix
        FROM a JOIN r USING (ip)""")
    n = con.execute("SELECT count(*), count(asn), count(provider) FROM cl_ip_geo").fetchone()
    return {"ips": int(n[0]), "ips_with_asn": int(n[1]), "ips_in_provider_ranges": int(n[2]),
            "asn_db": has_asn, "provider_ranges": ranges, "centroids": bool(cent and Path(cent).exists()),
            "network_key": "asn" if has_asn else "prefix"}
