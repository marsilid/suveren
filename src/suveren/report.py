"""HTML and JSON report writers."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from jinja2 import Environment, PackageLoader, select_autoescape

from suveren import __version__
from suveren.checks import GROUP_BLOCK, Status
from suveren.company import CompanyReport
from suveren.models import Category, Report
from suveren.sanctions import SOURCE_TITLES
from suveren.utils import country_name

# Bar colours for the country breakdown; Russia is always green.
_PALETTE = ("#3b5bdb", "#e8590c", "#ae3ec9", "#1098ad", "#f59f00", "#d6336c", "#5c7cfa")


def country_bars(report: Report) -> list[dict[str, object]]:
    bars = []
    others = iter(_PALETTE * 4)
    for code, share in report.countries:
        color = "var(--grade-a)" if code == "RU" else next(others)
        bars.append({"code": code, "name": country_name(code), "share": share, "color": color})
    return bars


def _environment() -> Environment:
    return Environment(
        loader=PackageLoader("suveren", "templates"),
        autoescape=select_autoescape(["html", "j2"]),
        trim_blocks=True,
        lstrip_blocks=True,
    )


def render_html(report: Report) -> str:
    template = _environment().get_template("report.html.j2")
    groups = [
        (category, [d for d in report.dependencies if d.category is category])
        for category in Category
    ]
    return template.render(
        report=report,
        version=__version__,
        bars=country_bars(report),
        groups=[(c, deps) for c, deps in groups if deps],
    )


def write_html(report: Report, path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_html(report), encoding="utf-8")
    return path


def write_json(report: Report, path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(report.to_dict(), indent=2, ensure_ascii=False, default=str), encoding="utf-8"
    )
    return path


def render_company_html(report: CompanyReport) -> str:
    template = _environment().get_template("company.html.j2")
    return template.render(report=report, version=__version__, sources=SOURCE_TITLES)


def write_company(report: CompanyReport, html_path: Path | None, json_path: Path | None) -> None:
    if html_path is not None:
        html_path.parent.mkdir(parents=True, exist_ok=True)
        html_path.write_text(render_company_html(report), encoding="utf-8")
    if json_path is not None:
        json_path.parent.mkdir(parents=True, exist_ok=True)
        json_path.write_text(
            json.dumps(report.to_dict(), indent=2, ensure_ascii=False, default=str),
            encoding="utf-8",
        )


def write_batch_html(
    reports: list[Report], failed: list[tuple[str, str | None]], path: Path
) -> Path:
    """Summary page for `batch`: one row per site, linking to its own report."""
    rows = []
    for r in sorted(reports, key=lambda r: (r.score, r.target)):
        checks = {status: 0 for status in Status}
        for c in r.checks:
            checks[c.status] += 1
        rows.append(
            {
                "report": r,
                "fails": checks[Status.FAIL],
                "warns": checks[Status.WARN],
                "blocked": any(
                    c.group == GROUP_BLOCK and c.status is Status.FAIL for c in r.checks
                ),
                "top": r.sorted_findings()[:2],
            }
        )
    template = _environment().get_template("batch.html.j2")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        template.render(rows=rows, failed=failed, version=__version__, generated=datetime.now()),
        encoding="utf-8",
    )
    return path
