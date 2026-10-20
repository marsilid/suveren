"""The to-do list: findings and failed checks merged and ranked by urgency."""

from __future__ import annotations

import re
from dataclasses import dataclass

from suveren.checks import Status
from suveren.models import Report, Severity, grade_for


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
    anchor: str = ""  # the report section the reason links to


def priorities(report: Report) -> list[Action]:
    """Most urgent first: high findings and failed checks, then the rest."""
    # (action, topic, is a scenario): one action per topic, a concrete check before the
    # scenario that cites it.
    ranked: list[tuple[Action, str, bool]] = [
        (
            Action(
                f.severity * 10 + 1,
                f.severity,
                first_sentence(f.recommendation),
                f.title,
                f"risk-{f.category.value}",
            ),
            f"dep:{f.category.value}",
            False,
        )
        for f in report.findings
    ]
    for c in report.checks:
        if c.status in (Status.FAIL, Status.WARN) and c.recommendation:
            severity = Severity.HIGH if c.status is Status.FAIL else Severity.MEDIUM
            if c.id in SECOND_ORDER:
                severity = Severity.LOW
            action = Action(
                severity * 10, severity, first_sentence(c.recommendation), c.title, c.id
            )
            topic = TOPICS.get(c.id) or (c.id[:-1] if c.id.startswith("SUV-MAIL-") else "")
            ranked.append((action, topic or action.action, c.id.startswith("SUV-ATK-")))
    # Several checks say the same thing in different words (the mail verdict, SPF, DMARC
    # and the phishing scenario all mean "fix the mail records"): keep the most urgent.
    unique: dict[str, Action] = {}
    for action, topic, _ in sorted(ranked, key=lambda r: (-r[0].weight, r[2])):
        unique.setdefault(topic, action)
    return list(unique.values())


# Warnings the checks themselves call second-order ("редкая атака"): low urgency.
SECOND_ORDER = frozenset({"SUV-MAIL-005"})

# Checks that give the same advice as another one, by topic.
TOPICS = {
    "SUV-ATK-001": "SUV-MAIL-00",
    "SUV-ATK-002": "scripts",
    # Encrypted inbound mail is its own topic, not "fix the mail records" (SPF, DMARC).
    "SUV-MAIL-005": "mta-sts",
    "SUV-WEB-001": "scripts",
    "SUV-WEB-002": "scripts",
    "SUV-WEB-003": "scripts",
    "SUV-ATK-003": "takeover",
    "SUV-SUB-002": "takeover",
    "SUV-ATK-004": "hsts",
    "SUV-WEB-005": "hsts",
    "SUV-ATK-005": "secrets",
    "SUV-WEB-009": "secrets",
    "SUV-ATK-006": "dep:dns",
    "SUV-CUT-001": "dep:dns",
    # The data-flow map is the evidence for cross-border transfer: one problem.
    "SUV-PD-006": "xborder",
    "SUV-PD-010": "xborder",
}


# The overall grade: every distinct problem costs points once, however many checks
# report it (the mail verdict, SPF and DMARC are one problem).
OVERALL_PENALTY = {Severity.HIGH: 10, Severity.MEDIUM: 3, Severity.LOW: 1, Severity.INFO: 0}


def overall_score(report: Report) -> int:
    """All sections together: laws, security, mail, blocks and foreign dependencies."""
    return max(0, 100 - sum(OVERALL_PENALTY[a.severity] for a in priorities(report)))


def overall_grade(report: Report) -> str:
    return grade_for(overall_score(report))


# Section words for what the overall grade covered, by the start of the group name.
SCOPE = (
    ("Персональные", "законы"),
    ("Другие требования", "законы"),
    ("Блокировки", "блокировки"),
    ("Защита почты", "почта"),
    ("Безопасность", "безопасность"),
    ("Поддомены", "поддомены"),
    ("Отключение", "отключение"),
)


def overall_scope(report: Report) -> str:
    """What the overall grade rests on: only sections that ran (--quick runs none)."""
    # A section counts only if something in it was actually checked: a section whose
    # page did not load holds a single "не проверено" line (gosuslugi.ru, PD-000).
    checked = [c for c in report.checks if c.status is not Status.UNKNOWN]
    ran = [word for prefix, word in SCOPE if any(c.group.startswith(prefix) for c in checked)]
    gap = unchecked(report)
    note = f"; не удалось проверить {gap[0]} из {gap[1]}, оценка может быть завышена" if gap else ""
    if not ran:
        return "проверены только иностранные зависимости" + note
    return "проверено: " + ", ".join(dict.fromkeys([*ran, "зависимости"])) + note


def unchecked(report: Report) -> tuple[int, int] | None:
    """(not checked, all) when a quarter or more of the checks could not run: a bot wall
    or a script-built page hides what was not seen, and the grade looks better than it is.
    A section that did not run at all ("SUV-WEB-000") stands for every check in it."""
    from suveren.catalog import CATALOG  # the catalogue imports the checks' modules

    n = total = 0
    for c in report.checks:
        if c.id.startswith("SUV-ATK-"):
            continue
        weight = 1
        if c.id.endswith("-000") and c.status is Status.UNKNOWN:
            prefix = c.id[:-3]
            weight = sum(1 for s in CATALOG if s.id.startswith(prefix) and s.id != c.id) or 1
        total += weight
        n += weight if c.status is Status.UNKNOWN else 0
    return (n, total) if n >= 3 and n * 4 >= total else None
