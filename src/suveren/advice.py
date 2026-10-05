"""The to-do list: findings and failed checks merged and ranked by urgency."""

from __future__ import annotations

import re
from dataclasses import dataclass

from suveren.checks import Status
from suveren.models import Report, Severity


def first_sentence(text: str) -> str:
    """Up to the first full stop that is followed by a capital letter (or the end), so
    abbreviations like «ст. 18.1 ч. 2» don't cut the sentence short."""
    match = re.match(r"(.+?[.!?])(?=\s+[А-ЯЁA-Z]|\s*$)", text, re.S)
    return match.group(1) if match else text


@dataclass(slots=True)
class Action:
    weight: int
    severity: Severity
    action: str
    reason: str


def priorities(report: Report) -> list[Action]:
    """Most urgent first: high findings and failed checks, then the rest."""
    actions = [
        Action(f.severity * 10 + 1, f.severity, first_sentence(f.recommendation), f.title)
        for f in report.findings
    ]
    for c in report.checks:
        if c.status in (Status.FAIL, Status.WARN) and c.recommendation:
            severity = Severity.HIGH if c.status is Status.FAIL else Severity.MEDIUM
            actions.append(
                Action(severity * 10, severity, first_sentence(c.recommendation), c.title)
            )
    return sorted(actions, key=lambda a: -a.weight)
