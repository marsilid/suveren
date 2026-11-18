"""Lint the wording of finished reports: the mistakes `suveren audit` cannot see.

    python tools/report_lint.py <folder or file> [...]

`suveren audit` checks the logic of a report (a problem with a calm text, a grade that
does not add up). The words themselves went unchecked, and real reports said "ailaba.ru и
1 поддоменов", "auth-portal.sberbank.ru…." and "оценка не выше b" (2026-11-18). This
reads what a person reads (the JSON texts, the HTML pages, the DOCX and a saved terminal
output) and reports such slips. Text quoted from a site («…» or "…") is skipped: its
typos are the site's, not ours. Exit code 1 when anything is found.
"""

from __future__ import annotations

import json
import re
import sys
import zipfile
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from suveren.utils import visible_text  # noqa: E402


@dataclass(frozen=True, slots=True)
class Slip:
    where: str  # file, and the check ID for a JSON text
    rule: str
    text: str  # the words around the slip


# "1 поддоменов": a number ending in 1 (not 11) takes the singular, never "-ов/-ев/-ей".
_ONE = re.compile(r"(?<![\d.,])(\d+)\s+([а-яё]+(?:ов|ев|ей))\b", re.IGNORECASE)
_RULES = (
    ("ellipsis-dot", re.compile(r"…\.|(?<!\.)\.\.(?!\.)")),
    # A grade letter is a capital: "не выше b" came from a filter that lowered the line.
    ("lowercase-grade", re.compile(r"\b(?:оценк[аиеу]|выше|ниже)\s+[a-f]\b(?!-)")),
    ("leftover", re.compile(r"\bNone\b|\{\{|\}\}|\{[a-z_]+\}|\bnan\b|\[\]|\bTrue\b|\bFalse\b")),
    # "camera=()" is the syntax of Permissions-Policy, not an empty aside.
    ("empty-brackets", re.compile(r"(?<!=)\(\s*\)")),
    ("doubled-word", re.compile(r"\b([а-яё]{2,})\s+\1\b", re.IGNORECASE)),
)
# Only in our own short texts (JSON): rendered pages collapse spaces anyway.
_TEXT_RULES = (
    ("space-before-punctuation", re.compile(r"[^\s]\s+[,;:!?](?=\s|$)|[а-яё]\s+\.(?=\s|$)")),
    ("double-space", re.compile(r"\S  +\S")),
)
_QUOTED = (
    re.compile(r"«[^«»]*»"),
    re.compile(r'"[^"\n]*"'),
    re.compile(r"`[^`\n]*`"),
    # A DNS record shown as it is: netology.ru's SPF has spaces of its own (2026-11-18).
    re.compile(r"\bv=(?:spf1|DMARC1|STSv1|TLSRPTv1|BIMI1|DKIM1)\b.*?(?=\.\s|\.$|$)", re.I),
)


def _unquoted(text: str) -> str:
    for pattern in _QUOTED:
        text = pattern.sub("«»", text)
    return text


def _around(text: str, start: int, end: int) -> str:
    return " ".join(text[max(0, start - 40) : end + 40].split())


def lint_text(text: str, where: str, *, own: bool = False) -> list[Slip]:
    """Slips in ``text``; ``own`` adds the rules for our short texts (spacing)."""
    text = _unquoted(text)
    slips = []
    for m in _ONE.finditer(text):
        n = int(m.group(1))
        if n % 10 == 1 and n % 100 != 11:
            slips.append(Slip(where, "one-with-plural", _around(text, m.start(), m.end())))
    for rule, pattern in _RULES + (_TEXT_RULES if own else ()):
        slips += [
            Slip(where, rule, _around(text, m.start(), m.end())) for m in pattern.finditer(text)
        ]
    return slips


def _json_texts(data: dict) -> list[tuple[str, str]]:
    fields = ("title", "details", "recommendation")
    texts = [
        (c.get("id") or c.get("title", "?"), c.get(k) or "")
        for c in data.get("checks", [])
        for k in fields
    ]
    texts += [("заметка", n) for n in data.get("notes", [])]
    texts += [("overall_incomplete", n) for n in data.get("overall_incomplete", []) or []]
    return [(w, t) for w, t in texts if isinstance(t, str) and t]


def lint_file(path: Path) -> list[Slip]:
    name = path.name
    if path.suffix == ".json":
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict) or "checks" not in data:
            return []
        return [s for w, t in _json_texts(data) for s in lint_text(t, f"{name} {w}", own=True)]
    if path.suffix == ".html":
        return lint_text(visible_text(path.read_text(encoding="utf-8")), name)
    if path.suffix == ".docx":
        with zipfile.ZipFile(path) as z:
            xml = z.read("word/document.xml").decode("utf-8")
        return lint_text(visible_text(xml.replace("</w:p>", "</w:p>\n")), name)
    if path.suffix == ".txt":
        return lint_text(path.read_text(encoding="utf-8"), name)
    return []


def lint(paths: list[Path]) -> list[Slip]:
    files = []
    for p in paths:
        files += sorted(f for f in p.rglob("*") if f.is_file()) if p.is_dir() else [p]
    return [s for f in files for s in lint_file(f)]


def main(argv: list[str]) -> int:
    slips = lint([Path(a) for a in argv] or [Path(".")])
    for s in slips:
        print(f"{s.where}: {s.rule}: {s.text}")
    print(f"найдено: {len(slips)}")
    return 1 if slips else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
