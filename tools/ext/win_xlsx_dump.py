"""Dump every sheet of an .xlsx (stdlib only: zipfile + ElementTree) as tab-separated rows. Untrusted input:
read-only, no macros or formulas evaluated.
    python -I tools/ext/win_xlsx_dump.py BOOK.xlsx
"""
from __future__ import annotations

import re
import sys
import zipfile
import xml.etree.ElementTree as ET

NS = {"m": "http://schemas.openxmlformats.org/spreadsheetml/2006/main",
      "r": "http://schemas.openxmlformats.org/officeDocument/2006/relationships"}


def col_index(ref: str) -> int:
    letters = re.match(r"[A-Z]+", ref).group(0)
    n = 0
    for ch in letters:
        n = n * 26 + ord(ch) - 64
    return n - 1


def main() -> int:
    with zipfile.ZipFile(sys.argv[1]) as z:
        shared: list[str] = []
        if "xl/sharedStrings.xml" in z.namelist():
            for si in ET.fromstring(z.read("xl/sharedStrings.xml")).findall("m:si", NS):
                shared.append("".join(t.text or "" for t in si.iter(f"{{{NS['m']}}}t")))
        wb = ET.fromstring(z.read("xl/workbook.xml"))
        rels = ET.fromstring(z.read("xl/_rels/workbook.xml.rels"))
        target = {r.get("Id"): r.get("Target") for r in rels}
        for sh in wb.find("m:sheets", NS):
            rid = sh.get(f"{{{NS['r']}}}id")
            path = "xl/" + target[rid].lstrip("/").removeprefix("xl/")
            print(f"=== sheet {sh.get('name')}")
            root = ET.fromstring(z.read(path))
            for row in root.iter(f"{{{NS['m']}}}row"):
                cells: dict[int, str] = {}
                for c in row.findall("m:c", NS):
                    v = c.find("m:v", NS)
                    txt = v.text if v is not None else "".join(t.text or "" for t in c.iter(f"{{{NS['m']}}}t"))
                    if c.get("t") == "s" and txt is not None:
                        txt = shared[int(txt)]
                    cells[col_index(c.get("r"))] = (txt or "").replace("\n", " | ").replace("\t", " ")
                if cells:
                    print("\t".join(cells.get(i, "") for i in range(max(cells) + 1)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
