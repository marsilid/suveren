"""Accepted findings: the .suveren-ignore file.

A finding someone looked at and decided to live with (a false alarm, a risk taken on
purpose, a fix planned for later) should not fail CI or lead the priorities every run.
But an exception nobody remembers is a hole: so every entry names who accepted it, why,
and until when, and after that day it stops working and the report says so.

One entry per line, columns separated by spaces; the reason is the rest of the line:

    # ID          сайт         до          автор    причина
    SUV-MAIL-005  example.ru   2027-01-31  ivanov   MTA-STS настроим после переезда почты
    SUV-WEB-004   *            2026-12-31  petrova  CSP готовим в задаче WEB-123

The site is a domain (its subdomains match too) or ``*`` for any. Lines starting with
``#`` and empty lines are skipped. A file with a broken line is refused as a whole: a
half-read file would silently drop exceptions.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Any

from suveren.checks import Check, Status
from suveren.errors import SuverenError

DEFAULT_FILE = ".suveren-ignore"
_ID = re.compile(r"[A-Z][A-Z0-9]{1,15}-[A-Z0-9]{1,15}-[0-9]{3}")
_AUTHOR = re.compile(r"\S{1,64}")


class IgnoreFileError(SuverenError):
    pass


@dataclass(frozen=True, slots=True)
class IgnoreEntry:
    check_id: str
    site: str  # a domain, or "*"
    until: date  # the last day the exception works
    author: str
    reason: str
    line: int

    def covers(self, host: str) -> bool:
        if self.site == "*":
            return True
        return host == self.site or host.endswith("." + self.site)

    def to_dict(self) -> dict[str, Any]:
        return {"reason": self.reason, "author": self.author, "until": self.until.isoformat()}


def parse(text: str, name: str = DEFAULT_FILE) -> list[IgnoreEntry]:
    entries = []
    for number, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 4)
        where = f"{name}, строка {number}"
        if len(parts) < 5:
            raise IgnoreFileError(
                f"{where}: нужно пять полей — ID, сайт, срок, автор и причина: «{line}»"
            )
        check_id, site, until, author, reason = parts
        if not _ID.fullmatch(check_id):
            raise IgnoreFileError(f"{where}: «{check_id}» не похоже на ID проверки (SUV-MAIL-005)")
        if check_id.startswith("SUV-"):
            from suveren.catalog import BY_ID  # the catalogue imports the checks' modules

            if check_id not in BY_ID:
                raise IgnoreFileError(f"{where}: проверки {check_id} нет, см. suveren checks")
        site = site.lower().rstrip(".")
        if site != "*" and ("." not in site or "/" in site):
            raise IgnoreFileError(f"{where}: сайт пишется доменом (example.ru) или *: «{site}»")
        try:
            day = date.fromisoformat(until)
        except ValueError:
            raise IgnoreFileError(
                f"{where}: срок пишется датой ГГГГ-ММ-ДД, например 2027-01-31: «{until}»"
            ) from None
        if not _AUTHOR.fullmatch(author):
            raise IgnoreFileError(f"{where}: автор — одно слово без пробелов: «{author}»")
        entries.append(IgnoreEntry(check_id, site, day, author, reason.strip(), number))
    return entries


def load(path: Path | None) -> list[IgnoreEntry]:
    """Entries of ``path``, or of ./.suveren-ignore when no path is given and it exists."""
    if path is None:
        path = Path(DEFAULT_FILE)
        if not path.is_file():
            return []
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise IgnoreFileError(f"не удалось прочитать {path}: {exc.strerror or exc}") from exc
    except UnicodeDecodeError as exc:
        raise IgnoreFileError(f"{path}: файл должен быть в UTF-8") from exc
    return parse(text, str(path))


def apply(checks: list[Check], entries: list[IgnoreEntry], host: str, today: date) -> list[str]:
    """Mark the accepted problems; return notes for the report: exceptions that expired
    and exceptions no longer needed. "Not checked" is never accepted: it hides nothing."""
    notes: list[str] = []
    for entry in entries:
        if not entry.covers(host):
            continue
        matched = [c for c in checks if c.id == entry.check_id]
        if today > entry.until:
            if any(c.status in (Status.FAIL, Status.WARN) for c in matched):
                notes.append(
                    f"Исключение для {entry.check_id} (строка {entry.line}, {entry.author}) "
                    f"истекло {entry.until:%d.%m.%Y}: проверка снова учитывается."
                )
            continue
        for check in matched:
            if check.status in (Status.FAIL, Status.WARN):
                check.accepted = entry.to_dict()
        if matched and all(c.status is Status.OK for c in matched):
            notes.append(
                f"Исключение для {entry.check_id} (строка {entry.line}) больше не нужно: "
                "проверка в порядке. Его можно удалить."
            )
    return notes
