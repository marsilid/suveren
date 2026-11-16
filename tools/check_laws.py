"""Weekly: has the text of a law Suveren relies on changed? (roadmap 1.3, item 2)

For every law in src/suveren/data/laws.json the script downloads its text, takes the
fingerprint (laws.fingerprint: sha256 of the text without markup) and compares it with
the recorded one. A change means: reread the provisions listed for the law, fix the
checks if needed, then record the new fingerprint with --write.

    python tools/check_laws.py            # exit 1 when a text changed or did not load
    python tools/check_laws.py --write    # record today's fingerprints and the date

consultant.ru answers Russian addresses best; from abroad a law may not load, which is
reported, not taken for a change.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import sys
import time
from pathlib import Path

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from suveren.laws import fingerprint

DATA = Path(__file__).resolve().parent.parent / "src" / "suveren" / "data" / "laws.json"
UA = "Mozilla/5.0 (Suveren law watch; +https://github.com/marsilid/suveren)"


def _transient(exc: httpx.HTTPError) -> bool:
    """A timeout, a broken connection or a 429/5xx may pass on its own; a 404 will not."""
    if isinstance(exc, httpx.HTTPStatusError):
        return exc.response.status_code == 429 or exc.response.status_code >= 500
    return True


def fetch(client: httpx.Client, url: str, *, attempts: int, pause: float) -> httpx.Response:
    """GET with a few tries: the runners are abroad and consultant.ru is slow for them, so a
    single timeout must not turn the weekly run red."""
    for attempt in range(1, attempts + 1):
        try:
            resp = client.get(url)
            resp.raise_for_status()
            return resp
        except httpx.HTTPError as exc:
            if attempt == attempts or not _transient(exc):
                raise
            time.sleep(pause * attempt)
    raise AssertionError("unreachable")  # pragma: no cover


def check(
    client: httpx.Client, data: dict, *, write: bool, attempts: int = 3, pause: float = 20.0
) -> tuple[list[str], int]:
    """Lines for the report and the exit code."""
    lines, code = [], 0
    today = dt.date.today().isoformat()
    for law in data["laws"]:
        try:
            resp = fetch(client, law["url"], attempts=attempts, pause=pause)
        except httpx.HTTPError as exc:
            lines.append(f"{law['id']}: не загрузился ({exc})")
            code = 1
            continue
        new = fingerprint(resp.text)
        old = law.get("text_sha256")
        if old is None:
            lines.append(f"{law['id']}: отпечаток снят впервые")
        elif old != new:
            what = "; ".join(p["article"] for p in law.get("provisions", []))
            lines.append(f"{law['id']}: ТЕКСТ ИЗМЕНИЛСЯ — перечитайте {what}")
            code = 1
        else:
            lines.append(f"{law['id']}: без изменений")
        if write:
            law["text_sha256"], law["checked"] = new, today
    return lines, code


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Не изменились ли тексты законов.")
    parser.add_argument("--write", action="store_true", help="записать новые отпечатки")
    args = parser.parse_args(argv)
    data = json.loads(DATA.read_text("utf-8"))
    with httpx.Client(timeout=60, follow_redirects=True, headers={"User-Agent": UA}) as client:
        lines, code = check(client, data, write=args.write)
    print("\n".join(lines))
    if args.write:
        DATA.write_text(json.dumps(data, ensure_ascii=False, indent=1) + "\n", "utf-8")
        return 0
    return code


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
