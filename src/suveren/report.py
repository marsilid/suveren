"""HTML and JSON report writers."""

from __future__ import annotations

import base64
import json
import re
from datetime import datetime
from pathlib import Path
from urllib.parse import urlsplit

from jinja2 import Environment, PackageLoader, select_autoescape
from markupsafe import Markup, escape

from suveren import __version__
from suveren.advice import overall_grade, overall_scope, overall_score, priorities, unchecked
from suveren.brand import Brand
from suveren.checks import GROUP_BLOCK, Status
from suveren.company import CompanyReport
from suveren.fines import DISCLAIMER, rub, span
from suveren.migration import plan as migration_plan
from suveren.models import Category, Report
from suveren.sanctions import SOURCE_TITLES
from suveren.utils import country_name

# Bar colours for the country breakdown; Russia is always green.
# The terminal's palette (view.py): Russia green, the rest in its warm and cool tones.
_PALETTE = ("var(--medium)", "var(--accent)", "#b48ead", "#81a1c1", "#d9822b", "var(--high)")


def country_bars(report: Report) -> list[dict[str, object]]:
    bars = []
    others = iter(_PALETTE * 4)
    for code, share in report.countries:
        color = "var(--grade-a)" if code == "RU" else next(others)
        bars.append({"code": code, "name": country_name(code), "share": share, "color": color})
    return bars


# A web address in check texts: a host with a dot, no brackets or quotes, so a link
# written in parentheses keeps its closing bracket out ("…(см. https://x.ru/doc/).").
_URL = re.compile(r"https?://[\w-]+(?:\.[\w-]+)+[^\s<>()\"']*")


# Report sections that check texts refer to by name.
_SECTIONS = {"«Иностранные зависимости»": "#risks"}


def _sections(text: str) -> Markup:
    out = escape(text)
    for name, href in _SECTIONS.items():
        out = Markup(out.replace(name, Markup('<a href="{}">{}</a>').format(href, name)))
    return out


def web_url(url: str | None) -> str | None:
    """The address if it is http(s), else None. A check's link can come from the
    scanned page (the policy link): a "javascript:" href there would run in the
    reader's browser on click, and escaping does not stop that."""
    if url and urlsplit(url.strip()).scheme.lower() in ("http", "https"):
        return url.strip()
    return None


def linkify(text: str | None) -> Markup:
    """Escaped text with its web addresses turned into short links: the site's name
    instead of a long address nobody reads. Section names link to their sections."""
    out, last = [], 0
    text = text or ""
    for match in _URL.finditer(text):
        url = match.group(0).rstrip(".,;:!?")
        end = match.start() + len(url)
        host = urlsplit(url).hostname or url
        label = host.removeprefix("www.")
        out.append(_sections(text[last : match.start()]))
        out.append(Markup('<a href="{}" target="_blank" rel="noopener">{}</a>').format(url, label))
        last = end
    out.append(_sections(text[last:]))
    return Markup("").join(out)


def _environment() -> Environment:
    env = Environment(
        loader=PackageLoader("suveren", "templates"),
        autoescape=select_autoescape(["html", "j2"]),
        trim_blocks=True,
        lstrip_blocks=True,
    )
    env.filters["rub"] = rub
    env.filters["span"] = span
    env.filters["linkify"] = linkify
    env.filters["web_url"] = web_url
    env.globals["fines_disclaimer"] = DISCLAIMER
    return env


def render_html(report: Report, brand: Brand | None = None) -> str:
    template = _environment().get_template("report.html.j2")
    groups = [
        (category, [d for d in report.dependencies if d.category is category])
        for category in Category
    ]
    moves = migration_plan(report.findings)
    shots = {
        k: "data:image/jpeg;base64," + base64.b64encode(v).decode("ascii")
        for k, v in report.media.items()
        if k.startswith("cutoff_")
    }
    graph_svg = report.media.get("script_graph_svg", b"").decode("utf-8")
    return template.render(
        report=report,
        brand=brand,
        version=__version__,
        bars=country_bars(report),
        actions=priorities(report)[:5],
        overall={
            "score": overall_score(report),
            "grade": overall_grade(report),
            "scope": overall_scope(report),
        },
        groups=[(c, deps) for c, deps in groups if deps],
        shots=shots,
        graph_svg=Markup(graph_svg),
        plan=moves,
        moves={m.category: m for m in moves},
        risk={f.category: f.severity for f in report.findings},
        tiles=summary_tiles(report),
        nav=navigation(report, bool(moves)),
    )


def _group_anchors(report: Report) -> dict[str, str]:
    """Anchors as the template numbers the sections: scenarios 0, the rest from 1."""
    anchors, n = {}, 0
    for group, _ in report.check_groups:
        if group.startswith("Сценарии"):
            anchors[group] = "#checks-0"
        else:
            n += 1
            anchors[group] = f"#checks-{n}"
    return anchors


def summary_tiles(report: Report) -> list[dict[str, str]]:
    """The five numbers a client looks for first, each linking to its section."""
    anchors = _group_anchors(report)
    by_status = {s: sum(1 for c in report.checks if c.status is s) for s in Status}
    tiles = [
        {
            "label": "Проблемы",
            "value": str(by_status[Status.FAIL]),
            "tone": "fail" if by_status[Status.FAIL] else "ok",
            "href": "#todo",
        },
        {
            "label": "Внимание",
            "value": str(by_status[Status.WARN]),
            "tone": "warn" if by_status[Status.WARN] else "ok",
            "href": "#todo",
        },
    ]
    fines = report.fines
    pd = next((a for g, a in anchors.items() if g.startswith("Персональные")), "#todo")
    tiles.append(
        {
            "label": "Штрафы по КоАП",
            "value": f"до {rub(fines.total('legal'))}" if fines and fines.counted else "нет",
            "tone": "fail" if fines and fines.counted else "ok",
            "href": pd,
        }
    )
    attacks = [c for c in report.checks if c.id.startswith("SUV-ATK-")]
    tiles.append(
        {
            "label": "Сценарии атак",
            "value": str(len(attacks)),
            "tone": "fail"
            if any(c.status is Status.FAIL for c in attacks)
            else "warn"
            if attacks
            else "ok",
            "href": "#checks-0" if attacks else "#todo",
        }
    )
    cut = next((c for c in report.checks if c.id == "SUV-CUT-002"), None)
    whole = next((c for c in report.checks if c.id == "SUV-CUT-001"), None)
    cut_anchor = next((a for g, a in anchors.items() if g.startswith("Отключение")), "#todo")
    if whole is not None and whole.status is Status.FAIL:
        # Foreign DNS, hosting or CDN: the whole site goes, whatever the page needs.
        value, tone = "сайт не откроется", "fail"
    elif cut is not None:
        value, tone = {
            Status.FAIL: ("сломается важное", "fail"),
            Status.WARN: ("сломается часть", "warn"),
            Status.OK: ("всё работает", "ok"),
            Status.UNKNOWN: ("не проверено", "muted"),
        }[cut.status]
    else:
        value, tone = "не проверялось", "muted"
    tiles.append(
        {"label": "Без иностранных сервисов", "value": value, "tone": tone, "href": cut_anchor}
    )
    return tiles


def navigation(report: Report, has_plan: bool) -> list[dict[str, object]]:
    """Sections for the sticky table of contents, with problem and warning counts."""
    anchors = _group_anchors(report)
    groups = dict(report.check_groups)

    def counts(group: str) -> tuple[int, int]:
        items = groups.get(group, [])
        return (
            sum(1 for c in items if c.status is Status.FAIL),
            sum(1 for c in items if c.status is Status.WARN),
        )

    nav: list[dict[str, object]] = [{"href": "#todo", "title": "Что сделать", "fail": 0, "warn": 0}]
    scenarios = next((g for g in groups if g.startswith("Сценарии")), None)
    if scenarios:
        f, w = counts(scenarios)
        nav.append({"href": "#checks-0", "title": "Сценарии атак", "fail": f, "warn": w})
    nav.append({"href": "#risks", "title": "Зависимости", "fail": 0, "warn": len(report.findings)})
    for group, _ in report.check_groups:
        if group == scenarios:
            continue
        f, w = counts(group)
        title = group.split(" (")[0]
        nav.append({"href": anchors[group], "title": title, "fail": f, "warn": w})
    if has_plan:
        nav.append({"href": "#plan", "title": "План переезда", "fail": 0, "warn": 0})
    nav.append({"href": "#services", "title": "Сервисы", "fail": 0, "warn": 0})
    if report.notes:
        nav.append({"href": "#notes", "title": "Замечания", "fail": 0, "warn": 0})
    return nav


def write_html(report: Report, path: Path, brand: Brand | None = None) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_html(report, brand), encoding="utf-8")
    return path


def write_json(report: Report, path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(report.to_dict(), indent=2, ensure_ascii=False, default=str), encoding="utf-8"
    )
    return path


def render_company_html(report: CompanyReport, brand: Brand | None = None) -> str:
    template = _environment().get_template("company.html.j2")
    return template.render(report=report, version=__version__, sources=SOURCE_TITLES, brand=brand)


def write_company(
    report: CompanyReport,
    html_path: Path | None,
    json_path: Path | None,
    brand: Brand | None = None,
) -> None:
    if html_path is not None:
        html_path.parent.mkdir(parents=True, exist_ok=True)
        html_path.write_text(render_company_html(report, brand), encoding="utf-8")
    if json_path is not None:
        json_path.parent.mkdir(parents=True, exist_ok=True)
        json_path.write_text(
            json.dumps(report.to_dict(), indent=2, ensure_ascii=False, default=str),
            encoding="utf-8",
        )


def write_batch_html(
    reports: list[Report],
    failed: list[tuple[str, str | None]],
    path: Path,
    brand: Brand | None = None,
) -> Path:
    """Summary page for `batch`: one row per site, linking to its own report."""
    rows = []
    for r in sorted(reports, key=lambda r: (overall_score(r), r.target)):
        checks = {status: 0 for status in Status}
        for c in r.checks:
            checks[c.status] += 1
        rows.append(
            {
                "report": r,
                "grade": overall_grade(r),
                "score": overall_score(r),
                "unchecked": unchecked(r),
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
        template.render(
            rows=rows, failed=failed, version=__version__, generated=datetime.now(), brand=brand
        ),
        encoding="utf-8",
    )
    return path
