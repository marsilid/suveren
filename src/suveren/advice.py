"""The to-do list: findings and failed checks merged and ranked by urgency."""

from __future__ import annotations

import re
from dataclasses import dataclass

from suveren.checks import Check, Status
from suveren.collect import DNS_SECTIONS
from suveren.models import UNSEEN_CAP, Report, Severity, grade_for


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
    status = {c.id: c.status for c in report.checks}
    for c in report.checks:
        # An accepted problem (.suveren-ignore) is a decision taken: no action, no points.
        if c.status in (Status.FAIL, Status.WARN) and c.recommendation and not c.accepted:
            severity = Severity.HIGH if c.status is Status.FAIL else Severity.MEDIUM
            if (
                c.id in SECOND_ORDER
                or (c.id in LOW_WHEN_WARN and c.status is Status.WARN)
                or _spf_behind_reject(c, status)
            ):
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
# Their warnings are advice of a standard ("SHOULD"), not a weakness anyone uses today:
# a 1024-bit DKIM key, a zone signed with an old algorithm. Their failures stay urgent.
LOW_WHEN_WARN = frozenset({"SUV-MAIL-006", "SUV-WEB-013"})


def _spf_behind_reject(check: Check, status: dict[str, Status]) -> bool:
    """An SPF warning when DMARC already rejects forged mail (SUV-MAIL-001 is OK): what is
    left is deliverability of the real mail, which DKIM also covers, not forgery. A broken
    SPF (FAIL) stays urgent: under p=reject real mail without DKIM is then rejected."""
    return (
        check.id == "SUV-MAIL-002"
        and check.status is Status.WARN
        and status.get("SUV-MAIL-001") is Status.OK
    )


# Checks that give the same advice as another one, by topic.
TOPICS = {
    "SUV-ATK-001": "SUV-MAIL-00",
    "SUV-ATK-002": "scripts",
    # Encrypted inbound mail is its own topic, not "fix the mail records" (SPF, DMARC).
    "SUV-MAIL-005": "mta-sts",
    # A new key under a new selector, not "fix the mail records".
    "SUV-MAIL-006": "dkim-key",
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


# A means "checked and clean". On 98 sites (nightly run, 2026-10-21) 19 of 22 A grades
# came from sites whose bot wall hid a quarter of the checks: unseen is not clean.
UNCHECKED_CAP = UNSEEN_CAP  # the top of B


def overall_score(report: Report) -> int:
    """All sections together: laws, security, mail, blocks and foreign dependencies."""
    score = max(0, 100 - sum(OVERALL_PENALTY[a.severity] for a in priorities(report)))
    # An unreachable site got A 100/100 in --quick: no page, so no checks to count.
    capped = unchecked(report) or report.page_unseen or report.dns_unanswered
    return min(score, UNCHECKED_CAP) if capped else score


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
    note = f"; не удалось проверить {gap[0]} из {gap[1]}, поэтому оценка не выше B" if gap else ""
    missed = missed_sections(report)
    if missed:
        note += "; оценка неполная, не проверены: " + ", ".join(missed)
    if not ran:
        return "проверены только иностранные зависимости" + note
    return "проверено: " + ", ".join(dict.fromkeys([*ran, "зависимости"])) + note


# What could not run, by the ID that stands for it. Often only the page-based part of a
# section (TLS runs when the headers do not), so the names are narrower than SCOPE's. Its
# problems are missing, so the grade goes up: economy.gov.ru timed out and rose from B 77
# to B 89 in the nightly run of 2026-10-23, amocrm.ru lost its mail checks to a SERVFAIL.
PAGE_SECTION = "скрипты и виджеты на странице"
MISSED_SECTION = {
    "SUV-PD-000": "152-ФЗ на страницах сайта",
    "SUV-WEB-000": "заголовки безопасности",
    "SUV-MAIL-001": "почта",
    "SUV-BLK-000": "реестр блокировок",
    "SUV-SUB-000": "поддомены",
}


def missed_sections(report: Report) -> list[str]:
    """Sections that did not run at all: a grade without them is not comparable with
    one that had them, whichever way it moved."""
    missed = [
        MISSED_SECTION[c.id]
        for c in report.checks
        if c.id in MISSED_SECTION and c.status is Status.UNKNOWN
    ]
    # The page and the site's DNS feed the dependency scan in every profile, --quick too.
    dns = [DNS_SECTIONS[k] for k in report.dns_unanswered if k in DNS_SECTIONS]
    return ([PAGE_SECTION] if report.page_unseen else []) + dns + missed


def incomplete(report: Report) -> list[str]:
    """Why the overall grade is incomplete (empty when it is not)."""
    gap = unchecked(report)
    reasons = [f"не проверены: {', '.join(missed)}"] if (missed := missed_sections(report)) else []
    return reasons + ([f"не удалось проверить {gap[0]} из {gap[1]}"] if gap else [])


def unchecked(report: Report) -> tuple[int, int] | None:
    """(not checked, all) when a quarter or more of the checks could not run: a bot wall
    or a script-built page hides what was not seen, and the grade looks better than it is.
    A section that did not run at all ("SUV-WEB-000") stands for every check in it."""
    from suveren.catalog import BY_ID, CATALOG  # the catalogue imports the checks' modules

    n = total = 0
    for c in report.checks:
        if c.id.startswith("SUV-ATK-"):
            continue
        weight = 1
        # A plugin's "PLUGIN-ERROR-000" is one check of its own, not a section of ours:
        # looking it up in the catalogue crashed the report of any scan with a failed plugin.
        if c.id.endswith("-000") and c.status is Status.UNKNOWN and c.id in BY_ID:
            # Only the checks of that module: SUV-PD-012 is a separate experiment.
            prefix, module = c.id[:-3], BY_ID[c.id].module
            weight = (
                sum(
                    1
                    for s in CATALOG
                    if s.id.startswith(prefix) and s.id != c.id and s.module == module
                )
                or 1
            )
        total += weight
        n += weight if c.status is Status.UNKNOWN else 0
    return (n, total) if n >= 3 and n * 4 >= total else None
