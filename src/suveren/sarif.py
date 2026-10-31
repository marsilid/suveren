"""SARIF 2.1.0 output: the format security tools exchange results in.

GitHub and GitLab code scanning, DefectDojo and most aggregators read it, so
``suveren scan --sarif`` drops into a pipeline next to other scanners. A result is
a problem, a warning or "not checked" (as a note); passed checks are left out.
Foreign dependencies are results too, one rule per category (SUV-DEP-HOSTING...).
Spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from suveren import __version__
from suveren.catalog import BY_ID
from suveren.checks import Check, Status
from suveren.models import Finding, Report, Severity, grade_for

SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
HOME = "https://github.com/marsilid/suveren"

LEVEL = {Status.FAIL: "error", Status.WARN: "warning", Status.UNKNOWN: "note"}
SEVERITY_LEVEL = {Severity.HIGH: "error", Severity.MEDIUM: "warning"}  # else "note"


def _check_rule(check: Check) -> dict[str, Any]:
    spec = BY_ID.get(check.id)
    rule: dict[str, Any] = {
        "id": check.id,
        "name": check.title,
        "shortDescription": {"text": spec.summary if spec else check.title},
        "properties": {"tags": list(spec.tags) if spec else [], "group": check.group},
    }
    if spec:
        # What the check does to the site and what it costs the one who runs it.
        rule["properties"] |= {"siteAction": spec.site, "runnerRisk": spec.runner}
    if check.law_url:
        rule["helpUri"] = check.law_url
    return rule


def _finding_rule(f: Finding) -> dict[str, Any]:
    return {
        "id": f.category.rule_id,
        "name": f"Иностранный сервис: {f.category.title}",
        "shortDescription": {"text": f.category.info.risk},
        "help": {"text": f.recommendation},
        "properties": {"tags": ["foreign", f.category.value]},
    }


def to_sarif(report: Report) -> dict[str, Any]:
    from suveren.advice import incomplete, overall_score  # advice reads the report

    url = report.facts.get("final_url") or f"https://{report.target}/"
    location = [{"physicalLocation": {"artifactLocation": {"uri": url}}}]
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []
    overall = overall_score(report)

    for f in report.sorted_findings():
        rules.setdefault(f.category.rule_id, _finding_rule(f))
        results.append(
            {
                "ruleId": f.category.rule_id,
                "level": SEVERITY_LEVEL.get(f.severity, "note"),
                # The title already names the services: "DNS-серверы: Cloudflare (США)".
                "message": {"text": f"{f.title}. {f.recommendation}"},
                "locations": location,
                "properties": {"severity": f.severity.label, "services": f.services},
            }
        )
    for c in report.checks:
        if c.status is Status.OK or not c.id:
            continue
        rules.setdefault(c.id, _check_rule(c))
        text = f"{c.title}. {c.details}".strip()
        if c.recommendation:
            text += f" Что делать: {c.recommendation}"
        results.append(
            {
                "ruleId": c.id,
                "level": LEVEL[c.status],
                "message": {"text": text},
                "locations": location,
                "properties": {
                    "status": c.status.value,
                    "law": c.law,
                    "evidence": [e.to_dict() for e in c.evidence],
                },
            }
        )

    order = list(rules)
    for r in results:
        r["ruleIndex"] = order.index(r["ruleId"])
    return {
        "$schema": SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Suveren",
                        "version": __version__,
                        "informationUri": HOME,
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
                # "grade" and "score" are the independence from foreign services; the
                # overall grade covers every section, as in the HTML and JSON reports.
                "properties": {
                    "target": report.target,
                    "grade": report.grade,
                    "score": report.score,
                    "overallGrade": grade_for(overall),
                    "overallScore": overall,
                    "overallIncomplete": incomplete(report),
                    **({"plugins": report.plugins} if report.plugins else {}),
                },
            }
        ],
    }


def sarif_text(report: Report) -> str:
    return json.dumps(to_sarif(report), ensure_ascii=False, indent=1)


def write_sarif(report: Report, path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(sarif_text(report), encoding="utf-8")
    return path
