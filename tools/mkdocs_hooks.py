"""MkDocs hook for the site on GitHub Pages (mkdocs.yml, workflow pages.yml).

The pages in docs/ are written for GitHub, where `../README.md` and `../src/...` open
files in the repository. On the site those files don't exist, so such links go to
the repository on GitHub instead. Working notes left out of the site (exclude_docs in
mkdocs.yml) are linked on GitHub too.
"""

from __future__ import annotations

import re

REPO = "https://github.com/marsilid/suveren/blob/main/"
_UP = re.compile(r"\]\(\.\./")
_NOTES = re.compile(r"\]\((accuracy-sample|standards-review|roadmap)\.md")


def on_page_markdown(markdown: str, **_: object) -> str:
    markdown = _UP.sub("](" + REPO, markdown)
    return _NOTES.sub(r"](" + REPO + r"docs/\1.md", markdown)
