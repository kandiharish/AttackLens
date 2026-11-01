"""List a zip archive and flag unsafe members (absolute paths, '..', drive letters). Optionally extract safe
members into an empty directory. Reads untrusted data only; never executes anything.
    python -I tools/ext/win_ziplist.py ARCHIVE [--extract DEST]
"""
from __future__ import annotations

import argparse
import sys
import zipfile
from pathlib import Path, PurePosixPath


def unsafe(name: str) -> bool:
    p = PurePosixPath(name.replace("\\", "/"))
    return p.is_absolute() or ".." in p.parts or (len(name) > 1 and name[1] == ":")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("archive")
    ap.add_argument("--extract")
    a = ap.parse_args()
    with zipfile.ZipFile(a.archive) as z:
        bad = 0
        for i in z.infolist():
            flag = "UNSAFE" if unsafe(i.filename) else "ok"
            bad += flag != "ok"
            print(f"{flag}\t{i.file_size}\t{i.compress_size}\t{i.filename}")
        if a.extract:
            if bad:
                print("refusing to extract: unsafe members", file=sys.stderr)
                return 2
            dest = Path(a.extract).resolve()
            dest.mkdir(parents=True, exist_ok=True)
            for i in z.infolist():
                if i.is_dir():
                    continue
                target = (dest / PurePosixPath(i.filename).name).resolve()  # flatten: basename only
                if target.parent != dest or target.exists():
                    print(f"refusing {i.filename}", file=sys.stderr)
                    return 3
                with z.open(i) as src, open(target, "wb") as out:
                    while chunk := src.read(1 << 20):
                        out.write(chunk)
                print(f"extracted {target}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
