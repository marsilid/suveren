"""MkDocs hook for the site on GitHub Pages (mkdocs.yml, workflow pages.yml).

The pages in docs/ are written for GitHub, where `../README.md` and `../src/...` open
files in the repository. On the site those files don't exist, so such links go to
the repository on GitHub instead.
"""

from __future__ import annotations

import re

REPO = "https://github.com/marsilid/suveren/blob/main/"
_UP = re.compile(r"\]\(\.\./")


def on_page_markdown(markdown: str, **_: object) -> str:
    return _UP.sub("](" + REPO, markdown)
