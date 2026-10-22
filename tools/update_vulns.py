"""Check src/suveren/data/vulns.json against NVD and, with --write, update it.

For every CVE in the file the script asks the NVD API 2.0 for the record and
compares the affected version ranges of the library with the ones in the file. It
reports what changed, and CVEs that NVD has rejected (as happened to Bootstrap's
CVE-2024-6484 and CVE-2024-6531). With --write it puts NVD's ranges into the file
and moves the "checked" date to today; a rejected CVE is reported, never removed
silently.

    python tools/update_vulns.py            # report only
    python tools/update_vulns.py --write    # update ranges and the date

New CVEs are not searched for: adding one stays a decision with a source.
"""

from __future__ import annotations

import datetime as dt
import json
import sys
import time
from pathlib import Path
from typing import Any

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from suveren.vulns import in_range

DATA = Path(__file__).resolve().parent.parent / "src" / "suveren" / "data" / "vulns.json"
API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
# NVD asks clients without an API key to keep to about one request every 6 seconds.
DELAY = 6.5

# Library name in vulns.json -> CPE vendor:product in NVD.
CPE = {
    "jquery": "jquery:jquery",
    "jquery-ui": "jqueryui:jquery_ui",
    "bootstrap": "getbootstrap:bootstrap",
    "lodash": "lodash:lodash",
    "moment": "momentjs:moment",
}

Range = list[str | None]


def nvd_ranges(cve: dict[str, Any], library: str) -> tuple[list[Range], list[str]]:
    """Affected [from, to) ranges of the library in an NVD record, and what could not be
    expressed that way (an inclusive upper bound, a single exact version)."""
    product = CPE[library]
    ranges: list[Range] = []
    odd: list[str] = []
    exact: list[str] = []
    for config in cve.get("configurations", []):
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                parts = match.get("criteria", "").split(":")
                if len(parts) < 6 or f"{parts[3]}:{parts[4]}" != product:
                    continue
                if not match.get("vulnerable", True):
                    continue
                start = match.get("versionStartIncluding")
                end = match.get("versionEndExcluding")
                if match.get("versionStartExcluding") or match.get("versionEndIncluding"):
                    odd.append(json.dumps({k: v for k, v in match.items() if "version" in k}))
                    continue
                if not start and not end and parts[5] not in ("*", "-"):
                    exact.append(parts[5])
                    continue
                if [start, end] not in ranges:
                    ranges.append([start, end])
    # A single version inside a range is already covered (Bootstrap's 4.0.0 betas).
    odd += [f"только версия {v}" for v in dict.fromkeys(exact) if not _covered(v, ranges)]
    return sorted(ranges, key=lambda r: (r[0] or "", r[1] or "")), odd


def _covered(version: str, ranges: list[Range]) -> bool:
    try:
        return in_range(version, ranges)
    except ValueError:  # "4.0.0-beta" and the like
        return False


def compare(entry: dict[str, Any], cve: dict[str, Any] | None) -> tuple[str, list[Range] | None]:
    """A line for the report and the ranges to write (None: leave the entry as it is)."""
    name = f"{entry['library']} {entry['id']}"
    if cve is None:
        return f"{name}: в NVD не найдена", None
    if cve.get("vulnStatus") == "Rejected":
        return f"{name}: ОТОЗВАНА в NVD, уберите запись вручную", None
    ranges, odd = nvd_ranges(cve, entry["library"])
    note = f" (не учтено: {'; '.join(odd)})" if odd else ""
    if not ranges:
        return f"{name}: в NVD нет диапазонов для этой библиотеки{note}", None
    mine = sorted(entry["ranges"], key=lambda r: (r[0] or "", r[1] or ""))
    if mine == ranges:
        return f"{name}: совпадает{note}", None
    return f"{name}: было {mine}, в NVD {ranges}{note}", ranges


def fetch(client: httpx.Client, cve_id: str) -> dict[str, Any] | None:
    resp = client.get(API, params={"cveId": cve_id})
    resp.raise_for_status()
    found = resp.json().get("vulnerabilities", [])
    return found[0]["cve"] if found else None


def main(argv: list[str]) -> int:
    write = "--write" in argv
    data = json.loads(DATA.read_text(encoding="utf-8"))
    changed = 0
    with httpx.Client(timeout=60) as client:
        for i, entry in enumerate(data["vulns"]):
            if i:
                time.sleep(DELAY)
            line, ranges = compare(entry, fetch(client, entry["id"]))
            print(line)
            if ranges is not None:
                changed += 1
                if write:
                    entry["ranges"] = ranges
    if write:
        today = dt.date.today().isoformat()
        text = DATA.read_text(encoding="utf-8")
        old = data["checked"]
        # Rewrite only what changed, keeping the hand-made one-entry-per-line layout.
        for entry in data["vulns"]:
            start = text.index(f'"id": "{entry["id"]}"')
            r_start = text.index('"ranges": ', start) + len('"ranges": ')
            r_end = text.index("]],", r_start) + 2
            text = text[:r_start] + json.dumps(entry["ranges"]) + text[r_end:]
        text = text.replace(f'"checked": "{old}"', f'"checked": "{today}"')
        text = text.replace(f"проверено {old}", f"проверено {today}")
        DATA.write_text(text, encoding="utf-8")
        print(f"Записано: изменено записей {changed}, дата сверки {today}.")
    else:
        print(f"Расхождений: {changed}. Запустите с --write, чтобы обновить.")
    return 1 if changed and not write else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
