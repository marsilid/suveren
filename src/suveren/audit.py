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
    scripts = bool(web1) and "Страницы загружают скрипты" in (web1.get("details") or "")
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

    score, grade = report.get("overall_score"), report.get("overall_grade")
    if score is not None and grade is not None:
        from suveren.models import grade_for

        if grade_for(score) != grade:
            issues.append(Issue("grade-mismatch", "", f"оценка {grade} при {score} баллах"))
    return issues
