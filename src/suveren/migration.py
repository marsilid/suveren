"""The way out of each foreign dependency: steps, Russian alternatives, how hard and
roughly what it costs, and one plan for the whole site ordered by what to do first.

Data lives in data/migration.json. Costs are deliberately not prices: prices change and
a wrong number would discredit the report; "free", "a free tier" or "the provider's
rate" is what can be said honestly.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from functools import cache
from importlib.resources import files
from typing import Any

from suveren.models import Category, Finding, Severity

DIFFICULTY = {"easy": "легко", "medium": "средне", "hard": "сложно"}
_EFFORT = {"easy": 0, "medium": 1, "hard": 2}


@dataclass(frozen=True, slots=True)
class Move:
    category: Category
    services: list[str]
    severity: Severity
    difficulty: str  # easy, medium, hard
    cost: str
    alternatives: list[str]
    steps: list[str]

    @property
    def difficulty_ru(self) -> str:
        return DIFFICULTY[self.difficulty]

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.category.rule_id,
            "category": self.category.value,
            "services": self.services,
            "severity": self.severity.label,
            "difficulty": self.difficulty,
            "cost": self.cost,
            "alternatives": self.alternatives,
            "steps": self.steps,
        }


@cache
def _data() -> dict[str, Any]:
    return json.loads(files("suveren").joinpath("data/migration.json").read_text("utf-8"))


def move_for(finding: Finding) -> Move | None:
    entry = _data()["categories"].get(finding.category.value)
    if entry is None:
        return None
    return Move(
        finding.category,
        finding.services,
        finding.severity,
        entry["difficulty"],
        entry["cost"],
        entry["alternatives"],
        entry["steps"],
    )


def plan(findings: list[Finding]) -> list[Move]:
    """All moves, the most useful first: higher risk, then less effort."""
    moves = [m for m in (move_for(f) for f in findings) if m is not None]
    return sorted(moves, key=lambda m: (-m.severity, _EFFORT[m.difficulty], m.category.title))
