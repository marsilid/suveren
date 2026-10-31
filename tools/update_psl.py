"""Refresh src/suveren/data/public_suffix_list.dat from publicsuffix.org.

    python tools/update_psl.py

The list is MPL-2.0 (https://publicsuffix.org). GitHub's copy is used when
publicsuffix.org does not answer.
"""

from __future__ import annotations

import sys
from pathlib import Path

import httpx

DATA = Path(__file__).resolve().parent.parent / "src" / "suveren" / "data"
URLS = (
    "https://publicsuffix.org/list/public_suffix_list.dat",
    "https://raw.githubusercontent.com/publicsuffix/list/main/public_suffix_list.dat",
)


def main() -> int:
    for url in URLS:
        try:
            resp = httpx.get(url, timeout=60, follow_redirects=True)
            resp.raise_for_status()
        except httpx.HTTPError as exc:
            print(f"{url}: {exc}")
            continue
        if "===BEGIN PRIVATE DOMAINS===" not in resp.text:
            print(f"{url}: это не Public Suffix List")
            continue
        (DATA / "public_suffix_list.dat").write_text(resp.text, "utf-8")
        print(f"записано из {url}")
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
