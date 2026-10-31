"""Self-audit of a report: does it contradict itself?

Every rule here is a mistake a reader once caught in a real report: a check filed under
"в порядке" with alarming text, a section that vanished, two checks saying opposite
things about the same data. Run over JSON reports (``scan --json``, a batch folder), so
the tests, the nightly run and anyone with old reports can use it.
"""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass
from typing import Any

# Words that mean "do something" or "this is dangerous": out of place in an OK check.
_ALARM = re.compile(
    r"\b(?:уберите|опасн|может (?:выполнить|украсть|перехват)|исправьте|замените|перенесите)",
    re.I,
)
# Names quoted from registers: "БЕЗОПАСНАЯ ИНФОРМАЦИОННАЯ ЗОНА" is bi.zone's legal name.
_QUOTED = re.compile(r'"[^"]*"|«[^»]*»')
# A whole text that reassures: out of place in a problem or a warning.
_CALM = re.compile(
    r"^(?:таких \w+ не найдено|замечаний нет|всё в порядке|противоречий[^.]* нет)|"
    r"не заблокирован\w*\.$",
    re.I,
)


# A note of collect.py saying a DNS lookup of the site itself got no answer.
_DNS_GAP = re.compile(r"Не удалось получить (?:DNS-серверы|почтовые серверы|IP-адреса сайта):")


@dataclass(frozen=True, slots=True)
class Issue:
    rule: str  # short slug, stable for tests and the nightly diff
    check: str  # the check ID it is about, or "" for the report as a whole
    text: str


def audit(report: dict[str, Any]) -> list[Issue]:
    """Contradictions in one report, as ``Report.to_dict()`` gives it."""
    issues: list[Issue] = []
    checks = report.get("checks", [])
    by_id = {c.get("id"): c for c in checks if c.get("id")}

    for c in checks:
        cid, status = c.get("id") or "", c.get("status")
        details = (c.get("details") or "").strip()
        if not cid:
            issues.append(Issue("no-id", "", f"проверка без ID: {c.get('title')}"))
        if not details:
            issues.append(Issue("empty-text", cid, "пустой текст"))
        words = _QUOTED.sub("", details)
        if status == "ok" and _ALARM.search(words):
            issues.append(Issue("ok-but-alarming", cid, details[:140]))
        if status in ("warn", "fail") and _CALM.search(details) and not _ALARM.search(words):
            issues.append(Issue("problem-but-calm", cid, details[:140]))
        if status in ("warn", "fail") and not (c.get("recommendation") or "").strip():
            issues.append(Issue("problem-without-advice", cid, "нет совета, что делать"))

    for cid, n in Counter(c.get("id") for c in checks if c.get("id")).items():
        if n > 1:
            issues.append(Issue("duplicate-id", cid, f"встречается {n} раза"))

    pd6, pd10 = by_id.get("SUV-PD-006"), by_id.get("SUV-PD-010")
    if pd6 and pd10 and pd6["status"] in ("warn", "fail") and pd10["status"] == "ok":
        issues.append(
            Issue(
                "xborder-disagree", "SUV-PD-010", "PD-006 видит иностранные сервисы, PD-010 — нет"
            )
        )
    web1 = by_id.get("SUV-WEB-001")
    scripts = "Страницы загружают скрипты" in ((web1 or {}).get("details") or "")
    if scripts and pd10 and pd10["details"].startswith("Сторонних сервисов"):
        issues.append(Issue("scripts-disagree", "SUV-PD-010", "WEB-001 нашёл сторонние скрипты"))
    blk3 = by_id.get("SUV-BLK-003")
    if scripts and blk3 and blk3["details"].startswith("Сторонних доменов"):
        issues.append(Issue("scripts-disagree", "SUV-BLK-003", "WEB-001 нашёл сторонние скрипты"))
    if pd10 and pd10["status"] == "warn" and not report.get("facts", {}).get("dataflow"):
        issues.append(Issue("flow-missing", "SUV-PD-010", "внимание, а таблицы стран нет"))

    sections = {cid.rsplit("-", 1)[0] for cid in by_id}
    if "SUV-MAIL" in sections and "SUV-WEB" not in sections and "SUV-PD" in sections:
        issues.append(Issue("section-vanished", "", "раздел безопасности сайта пропал целиком"))
    # profi.ru, 2026-10-23: one handshake timed out and the TLS check left the report.
    https = str(report.get("facts", {}).get("final_url") or "").startswith("https://")
    if https and {"SUV-WEB-001", "SUV-WEB-005"} <= by_id.keys() and "SUV-WEB-008" not in by_id:
        issues.append(Issue("check-vanished", "SUV-WEB-008", "сайт на HTTPS, а проверки TLS нет"))

    # sravni.ru, 2026-10-25: A, NS and MX timed out, yet the grade was not "неполная".
    silent = [n for n in report.get("notes", []) if _DNS_GAP.match(n)]
    if silent and "overall_incomplete" in report and not report["overall_incomplete"]:
        issues.append(Issue("dns-gap-complete", "", silent[0][:140]))

    issues += _grade_rules(report)
    return issues


def _grade_rules(report: dict[str, Any]) -> list[Issue]:
    """The rules of the two grades (advice.py, models.py), checked on the JSON: a grade
    that breaks them is a bug in the scoring, not in a check."""
    from suveren import __version__
    from suveren.advice import OVERALL_PENALTY, SECOND_ORDER
    from suveren.models import PENALTIES, UNSEEN_CAP, Severity, grade_for

    issues: list[Issue] = []
    facts = report.get("facts") or {}
    unseen = bool(facts.get("page_unseen") or facts.get("dns_unanswered"))
    incomplete_reasons = report.get("overall_incomplete") or []
    for key, name in (("overall", "общая"), ("", "независимость")):
        score = report.get(f"{key}_score" if key else "score")
        grade = report.get(f"{key}_grade" if key else "grade")
        if score is None:
            continue
        label = f"{name}: {grade} при {score} баллах"
        if not 0 <= score <= 100:
            issues.append(Issue("score-range", "", label))
        if grade is not None and grade_for(score) != grade:
            issues.append(Issue("grade-mismatch", "", f"оценка {label}"))
        # A means "checked and clean": an unseen page or DNS keeps both grades at B at
        # most, and so does a quarter of the checks not run for the overall one.
        gap = any(str(r).startswith("не удалось проверить") for r in incomplete_reasons)
        if (unseen or (key and gap)) and score > UNSEEN_CAP:
            issues.append(Issue("incomplete-top", "", f"оценка неполная, а {label}"))

    # The overall grade counts a failed check with advice as a high problem (advice.py).
    overall = report.get("overall_score")
    worst = {
        c.get("status")
        for c in report.get("checks", [])
        if c.get("recommendation") and c.get("id") not in SECOND_ORDER
    }
    if overall is not None and "fail" in worst and overall > 100 - OVERALL_PENALTY[Severity.HIGH]:
        issues.append(Issue("fail-top", "", f"есть проблема, а общая оценка {overall}"))
    # Every finding costs its penalty once: the independence score is their sum.
    severities = [str(f.get("severity", "")).upper() for f in report.get("findings", [])]
    score = report.get("score")
    if score is not None and all(s in Severity.__members__ for s in severities):
        penalty = sum(PENALTIES[Severity[s]] for s in severities)
        expected = max(0, 100 - penalty)
        expected = min(expected, UNSEEN_CAP) if unseen else expected
        if score != expected:
            issues.append(
                Issue("score-mismatch", "", f"независимость {score}, по находкам {expected}")
            )
    # The overall score is recounted in full only for reports of this very version: the
    # weights of older versions were different.
    if overall is not None and report.get("tool_version") == __version__:
        expected = _recount_overall(report)
        if expected is not None and expected != overall:
            issues.append(Issue("score-mismatch", "", f"общая {overall}, по проверкам {expected}"))
    return issues


def _recount_overall(data: dict[str, Any]) -> int | None:
    """The overall score of a JSON report, counted again from its checks and findings."""
    from suveren.advice import overall_score
    from suveren.checks import Check, Status
    from suveren.models import Category, Finding, Report, Severity

    try:
        report = Report(target=str(data.get("target") or ""))
        report.facts = dict(data.get("facts") or {})
        report.findings = [
            Finding(
                Category(f["category"]),
                f["title"],
                Severity[f["severity"].upper()],
                f.get("description", ""),
                f.get("recommendation", ""),
            )
            for f in data.get("findings", [])
        ]
        report.checks = [
            Check(
                group=c.get("group", ""),
                title=c.get("title", ""),
                status=Status(c["status"]),
                recommendation=c.get("recommendation", ""),
                id=c.get("id") or "SUV-NOID",
            )
            for c in data.get("checks", [])
        ]
        return overall_score(report)
    except (KeyError, ValueError, TypeError, AttributeError):
        return None
