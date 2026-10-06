"""Pass/fail checklist items (152-ФЗ compliance, block lists)."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any


class Status(str, Enum):
    OK = "ok"
    WARN = "warn"
    FAIL = "fail"
    UNKNOWN = "unknown"

    @property
    def ru(self) -> str:
        return {"ok": "в порядке", "warn": "внимание", "fail": "проблема", "unknown": "не ясно"}[
            self.value
        ]

    @property
    def icon(self) -> str:
        return {"ok": "✓", "warn": "!", "fail": "✗", "unknown": "?"}[self.value]


GROUP_152 = "Персональные данные (152-ФЗ)"
GROUP_BLOCK = "Блокировки в России"

# Official consolidated texts, so every conclusion can be checked against the law.
LAW_URLS = {
    "152-ФЗ": "https://www.consultant.ru/document/cons_doc_LAW_61801/",
    "ЗоЗПП": "https://www.consultant.ru/document/cons_doc_LAW_305/",
}


def law_url(law: str | None) -> str | None:
    if not law:
        return None
    return LAW_URLS.get(law.split(",", 1)[0].strip())


@dataclass(slots=True)
class Check:
    group: str
    title: str
    status: Status
    details: str = ""
    recommendation: str = ""
    link: str | None = None
    law: str | None = None  # e.g. "152-ФЗ, ст. 9"

    @property
    def law_url(self) -> str | None:
        return law_url(self.law)

    def to_dict(self) -> dict[str, Any]:
        return {
            "group": self.group,
            "title": self.title,
            "status": self.status.value,
            "details": self.details,
            "recommendation": self.recommendation,
            "link": self.link,
            "law": self.law,
            "law_url": self.law_url,
        }
