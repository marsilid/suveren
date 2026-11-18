"""Laws as data: where each law's text is, which edition was checked, from which day
the provisions the checks rest on are in force (data/laws.json). The weekly
tools/check_laws.py compares the text's fingerprint to the recorded one."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import date
from functools import cache
from importlib.resources import files
from typing import Any

from suveren.utils import visible_text


@dataclass(frozen=True, slots=True)
class Provision:
    article: str
    effective_from: date | None
    what: str
    checks: tuple[str, ...]

    def in_force(self, on: date) -> bool:
        return self.effective_from is None or on >= self.effective_from


@dataclass(frozen=True, slots=True)
class Law:
    id: str
    title: str
    url: str
    edition: str
    provisions: tuple[Provision, ...]
    text_sha256: str | None
    checked: str | None


def _law(raw: dict[str, Any]) -> Law:
    return Law(
        raw["id"],
        raw["title"],
        raw["url"],
        raw.get("edition", ""),
        tuple(
            Provision(
                p["article"],
                date.fromisoformat(p["effective_from"]) if p.get("effective_from") else None,
                p["what"],
                tuple(p.get("checks", [])),
            )
            for p in raw.get("provisions", [])
        ),
        raw.get("text_sha256"),
        raw.get("checked"),
    )


@cache
def laws() -> tuple[Law, ...]:
    raw = json.loads(files("suveren").joinpath("data/laws.json").read_text("utf-8"))
    return tuple(_law(r) for r in raw["laws"])


def law_urls() -> dict[str, str]:
    return {law.id: law.url for law in laws()}


def fingerprint(page: str) -> str:
    """sha256 of the law's text without markup, scripts and spacing: a new banner or a
    reordered menu should not count as a change of the law, a changed word should."""
    return hashlib.sha256(visible_text(page).encode("utf-8")).hexdigest()
