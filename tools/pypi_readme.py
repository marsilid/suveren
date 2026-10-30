"""Make the README's relative links absolute, for the package page on PyPI.

On GitHub `docs/demo.svg` and `docs/guide.md` resolve against the repository; on
PyPI they lead nowhere. The release job runs this before building the package, so
the page on PyPI points at the files of that very tag and never drifts:

    python tools/pypi_readme.py README.md --ref v1.1.0

Images go to raw.githubusercontent.com (served as files), other files to their
page on github.com. Web links and anchors within the page are left alone.
"""

from __future__ import annotations

import argparse
import re
from pathlib import Path

REPO = "marsilid/suveren"
IMAGES = (".png", ".svg", ".jpg", ".jpeg", ".gif", ".webp")
# A markdown link target `](path)` or an HTML `src="path"` / `srcset="path"`.
LINK = re.compile(r'(\]\(|\b(?:src|srcset)=")([^)"\s]+)')


def absolute(text: str, ref: str, repo: str = REPO) -> str:
    def fix(m: re.Match[str]) -> str:
        opener, target = m.groups()
        if re.match(r"[a-z][a-z0-9+.-]*:|#|/", target, re.I):
            return m.group(0)
        path = target.removeprefix("./")
        if path.split("#", 1)[0].lower().endswith(IMAGES):
            url = f"https://raw.githubusercontent.com/{repo}/{ref}/{path}"
        else:
            url = f"https://github.com/{repo}/blob/{ref}/{path}"
        return opener + url

    return LINK.sub(fix, text)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("readme", type=Path)
    parser.add_argument("--ref", required=True, help="tag or branch the links point at")
    args = parser.parse_args(argv)
    text = args.readme.read_text(encoding="utf-8")
    args.readme.write_text(absolute(text, args.ref), encoding="utf-8", newline="\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
