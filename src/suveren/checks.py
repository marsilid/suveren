"""Pass/fail checklist items (152-ФЗ compliance, block lists)."""

from __future__ import annotations

import os
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
# Requirements to Russian sites outside 152-ФЗ (sign-in, labelling...).
GROUP_LAWS = "Другие требования законов"

# Official consolidated texts, so every conclusion can be checked against the law.
LAW_URLS = {
    "152-ФЗ": "https://www.consultant.ru/document/cons_doc_LAW_61801/",
    "149-ФЗ": "https://www.consultant.ru/document/cons_doc_LAW_61798/",
    "ЗоЗПП": "https://www.consultant.ru/document/cons_doc_LAW_305/",
}


def law_url(law: str | None) -> str | None:
    if not law:
        return None
    return LAW_URLS.get(law.split(",", 1)[0].strip())


# Tests set this so that a check missing from the catalogue fails loudly; in use an
# unknown check just has no ID.
STRICT_IDS = os.environ.get("SUVEREN_STRICT_CHECK_IDS") == "1"


@dataclass(slots=True)
class Check:
    group: str
    title: str
    status: Status
    details: str = ""
    recommendation: str = ""
    link: str | None = None
    law: str | None = None  # e.g. "152-ФЗ, ст. 9"
    id: str = ""  # stable ID from catalog.py, e.g. "SUV-MAIL-003"; filled in by title

    def __post_init__(self) -> None:
        if not self.id:
            from suveren.catalog import spec_for

            spec = spec_for(self.group, self.title)
            if spec is not None:
                self.id = spec.id
            elif STRICT_IDS:
                raise ValueError(f"check missing from catalog.py: {self.group} / {self.title}")

    @property
    def law_url(self) -> str | None:
        return law_url(self.law)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "group": self.group,
            "title": self.title,
            "status": self.status.value,
            "details": self.details,
            "recommendation": self.recommendation,
            "link": self.link,
            "law": self.law,
            "law_url": self.law_url,
        }
