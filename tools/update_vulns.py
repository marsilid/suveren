"""Refresh the built-in copy of the retire.js vulnerability database.

Suveren reads the vulnerable versions of jQuery, Bootstrap, lodash and the rest from
retire.js (https://github.com/RetireJS/retire.js, jsrepository-v4.json, Apache-2.0).
A scan downloads the database itself once a day; this copy in
src/suveren/data/retire.json is what it falls back on offline or where GitHub is not
reachable. The script keeps only the libraries Suveren detects, and only their
vulnerabilities, and writes the date of the download.

    python tools/update_vulns.py            # what would change
    python tools/update_vulns.py --write    # write the new copy
    python tools/update_vulns.py --file jsrepository-v4.json --write   # from a file
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import sys
from pathlib import Path
from typing import Any

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from suveren.vulns import RETIRE_NAMES, RETIRE_URL

DATA = Path(__file__).resolve().parent.parent / "src" / "suveren" / "data" / "retire.json"


def snapshot(repository: dict[str, Any], day: dt.date) -> dict[str, Any]:
    """The part of the retire.js database Suveren uses, with where and when it came from."""
    keys = sorted({k for names in RETIRE_NAMES.values() for k in names})
    missing = [k for k in keys if k not in repository]
    if missing:
        raise SystemExit(f"в базе retire.js нет {', '.join(missing)}: формат изменился?")
    out: dict[str, Any] = {
        "_suveren": {
            "about": "Копия базы retire.js для работы без сети: только библиотеки, которые "
            "находит Suveren, и только их уязвимости. Обновляется tools/update_vulns.py.",
            "url": RETIRE_URL,
            "license": "Apache-2.0",
            "fetched": day.isoformat(),
        }
    }
    for key in keys:
        out[key] = {"vulnerabilities": repository[key].get("vulnerabilities", [])}
    return out


def ids(data: dict[str, Any]) -> set[tuple[str, str, str]]:
    """(library, first identifier, below) of every entry, to show what changed."""
    found = set()
    for key, entry in data.items():
        if key.startswith("_"):
            continue
        for v in entry.get("vulnerabilities", []):
            ident = v.get("identifiers", {})
            first = (ident.get("CVE") or [ident.get("githubID") or ident.get("summary", "?")])[0]
            found.add((key, str(first), str(v.get("below"))))
    return found


def diff(old: dict[str, Any], new: dict[str, Any]) -> list[str]:
    before, after = ids(old), ids(new)
    lines = [f"+ {k} {i} (ниже {b})" for k, i, b in sorted(after - before)]
    lines += [f"- {k} {i} (ниже {b})" for k, i, b in sorted(before - after)]
    return lines


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--write", action="store_true", help="записать новую копию")
    parser.add_argument("--file", type=Path, help="взять базу из файла, а не из сети")
    args = parser.parse_args(argv)
    if args.file:
        repository = json.loads(args.file.read_text("utf-8"))
    else:
        resp = httpx.get(RETIRE_URL, timeout=60, follow_redirects=True)
        resp.raise_for_status()
        repository = resp.json()
    new = snapshot(repository, dt.date.today())
    old = json.loads(DATA.read_text("utf-8")) if DATA.exists() else {}
    changes = diff(old, new)
    print("\n".join(changes) if changes else "изменений в уязвимостях нет")
    if args.write:
        DATA.write_text(json.dumps(new, ensure_ascii=False, indent=1) + "\n", "utf-8")
        print(f"записано: {DATA}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
