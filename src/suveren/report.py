"""HTML and JSON report writers."""

from __future__ import annotations

import json
from pathlib import Path

from jinja2 import Environment, PackageLoader, select_autoescape

from suveren import __version__
from suveren.models import Category, Report
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
