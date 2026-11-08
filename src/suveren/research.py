"""`suveren research`: many sites, then only the totals (for a study or an article).

Each site is scanned once (the standard, passive checks) and its raw JSON report kept in
<out>/raw/; a run that broke off goes on from where it stopped, skipping the sites whose
report is already there. Then the totals: for every finding, the share of sites that
have it, overall and by the type of site when the list gives one. Output: summary.csv
and summary.html with bar charts drawn in inline SVG (no outside scripts).

Only aggregates: the HTML names no site unless --show-domains, which is for the one who
ran it, not for publishing (a list of sites with a weakness is a list of targets).

The list: one site a line, optionally a type after a comma, a semicolon or a tab:

    shop.ru, магазин
    clinic.ru; медицина
"""

from __future__ import annotations

import asyncio
import csv
import html
import io
import json
import re
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from suveren.errors import SuverenError
from suveren.models import Report
from suveren.utils import normalize_domain

PROBLEM = {"warn", "fail"}
ScanFn = Callable[[str], Awaitable[Report]]


@dataclass(slots=True)
class Site:
    domain: str
    label: str = ""


def read_sites(text: str) -> tuple[list[Site], list[str]]:
    """Sites and their types; lines that are not a site come back as skipped."""
    sites, skipped, seen = [], [], set()
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        parts = [p.strip() for p in re.split(r"[,;\t]", line, maxsplit=1)]
        try:
            domain = normalize_domain(parts[0])
        except SuverenError:
            skipped.append(line)
            continue
        if domain not in seen:
            seen.add(domain)
            sites.append(Site(domain, parts[1] if len(parts) > 1 else ""))
    return sites, skipped


def _raw_path(out: Path, domain: str) -> Path:
    return out / "raw" / f"{domain}.json"


def _done(out: Path, domain: str) -> bool:
    try:
        data = json.loads(_raw_path(out, domain).read_text("utf-8"))
    except (OSError, ValueError):
        return False
    return isinstance(data, dict) and "checks" in data


async def run_research(
    sites: list[Site], out: Path, scan: ScanFn, *, jobs: int = 4
) -> tuple[int, int, list[tuple[str, str]]]:
    """(scanned now, already there, failures as (domain, why)). Resumable."""
    (out / "raw").mkdir(parents=True, exist_ok=True)
    todo = [s for s in sites if not _done(out, s.domain)]
    semaphore = asyncio.Semaphore(jobs)
    failures: list[tuple[str, str]] = []

    async def one(site: Site) -> bool:
        async with semaphore:
            try:
                report = await scan(site.domain)
            except SuverenError as exc:
                failures.append((site.domain, str(exc)))
                return False
            path = _raw_path(out, site.domain)
            tmp = path.with_suffix(".part")
            data = report.to_dict()
            tmp.write_text(json.dumps(data, ensure_ascii=False, default=str), "utf-8")
            tmp.replace(path)  # a half-written report never counts as done
            return True

    done = await asyncio.gather(*(one(s) for s in todo))
    return sum(done), len(sites) - len(todo), failures


# --- Totals ---------------------------------------------------------------------------


@dataclass(slots=True)
class Row:
    key: str  # check ID or SUV-DEP-...
    title: str
    sites: list[str] = field(default_factory=list)  # with the finding
    checked: int = 0  # sites where it could be seen at all
    by_label: dict[str, tuple[int, int]] = field(default_factory=dict)  # label -> (with, of)

    @property
    def share(self) -> float:
        return len(self.sites) / self.checked if self.checked else 0.0


def _findings(report: dict[str, Any]) -> tuple[dict[str, str], set[str]]:
    """(key -> title of what the site has, keys that could be seen on it)."""
    has: dict[str, str] = {}
    seen: set[str] = set()
    for c in report.get("checks", []):
        cid = c.get("id") or ""
        if not cid or c.get("status") == "unknown":
            continue  # "not checked" says nothing either way
        seen.add(cid)
        if c.get("status") in PROBLEM:
            has[cid] = c.get("title", cid)
    for f in report.get("findings", []):
        fid = f.get("id") or ""
        if fid:
            has[fid] = "Иностранная зависимость: " + str(f.get("title", fid))
    return has, seen


def aggregate(reports: dict[str, dict[str, Any]], labels: dict[str, str]) -> list[Row]:
    rows: dict[str, Row] = {}
    total_by_label: dict[str, int] = {}
    per_site = {d: _findings(r) for d, r in reports.items()}
    for domain in reports:
        label = labels.get(domain, "")
        if label:
            total_by_label[label] = total_by_label.get(label, 0) + 1
    for domain, (has, seen) in per_site.items():
        for key, title in has.items():
            rows.setdefault(key, Row(key, title)).sites.append(domain)
        for key in seen:
            rows.setdefault(key, Row(key, key))
    for row in rows.values():
        if row.key.startswith("SUV-DEP-"):
            row.checked = len(reports)  # a dependency is looked for on every site
        else:
            row.checked = sum(1 for has, seen in per_site.values() if row.key in seen)
        for label in total_by_label:
            of = [d for d in reports if labels.get(d) == label]
            looked = (
                of
                if row.key.startswith("SUV-DEP-")
                else [d for d in of if row.key in per_site[d][1]]
            )
            row.by_label[label] = (sum(1 for d in looked if d in row.sites), len(looked))
    found = [r for r in rows.values() if r.sites]
    return sorted(found, key=lambda r: (-r.share, r.key))


def summary_csv(rows: list[Row], labels: list[str]) -> str:
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(
        ["Находка", "Название", "Сайтов с находкой", "Проверено сайтов", "Доля, %"]
        + [f"{label}, %" for label in labels]
    )
    for r in rows:
        writer.writerow(
            [r.key, r.title, len(r.sites), r.checked, f"{100 * r.share:.1f}"]
            + [
                f"{100 * w / of:.1f}" if of else ""
                for w, of in (r.by_label.get(lb, (0, 0)) for lb in labels)
            ]
        )
    return out.getvalue()


def _bar(share: float, width: int = 260) -> str:
    filled = round(share * width)
    return (
        f'<svg width="{width}" height="14" role="img" aria-label="{100 * share:.0f}%">'
        f'<rect width="{width}" height="14" rx="3" fill="#e1e4e8"/>'
        f'<rect width="{filled}" height="14" rx="3" fill="#2b8a8a"/></svg>'
    )


def summary_html(rows: list[Row], total: int, labels: list[str], *, show_domains: bool) -> str:
    esc = html.escape
    lines = [
        '<!DOCTYPE html><html lang="ru"><head><meta charset="utf-8">',
        '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; '
        "style-src 'unsafe-inline'\">",
        "<title>Suveren — сводка исследования</title><style>"
        "body{font:15px/1.5 -apple-system,'Segoe UI',Roboto,Arial,sans-serif;max-width:1000px;"
        "margin:0 auto;padding:24px 16px;color:#1c2024}table{border-collapse:collapse;width:100%}"
        "td,th{padding:6px 8px;border-bottom:1px solid #e1e4e8;text-align:left;vertical-align:top}"
        "th{font-weight:600}.n{text-align:right;white-space:nowrap}small{color:#5f6873}</style>",
        "</head><body>",
        "<h1>Сводка исследования</h1>",
        f"<p>Сайтов в выборке: <b>{total}</b>. Доля считается от сайтов, где находку можно было "
        "увидеть («не проверено» не входит).</p>",
    ]
    if not show_domains:
        lines.append("<p><small>Названия сайтов скрыты: показываются только доли.</small></p>")
    head = "<tr><th>Находка</th><th class=n>Сайтов</th><th>Доля</th>"
    head += "".join(f"<th class=n>{esc(lb)}</th>" for lb in labels)
    if show_domains:
        head += "<th>Сайты</th>"
    lines += ["<table>", head + "</tr>"]
    for r in rows:
        cells = (
            f"<td>{esc(r.title)}<br><small>{esc(r.key)}</small></td>"
            f"<td class=n>{len(r.sites)} из {r.checked}</td>"
            f"<td>{_bar(r.share)} {100 * r.share:.0f}%</td>"
        )
        for lb in labels:
            w, of = r.by_label.get(lb, (0, 0))
            cells += f"<td class=n>{f'{100 * w / of:.0f}%' if of else '—'}</td>"
        if show_domains:
            cells += f"<td><small>{esc(', '.join(sorted(r.sites)))}</small></td>"
        lines.append(f"<tr>{cells}</tr>")
    lines += ["</table>", "<p><small>Suveren research</small></p></body></html>"]
    return "\n".join(lines)


def load_raw(out: Path) -> dict[str, dict[str, Any]]:
    reports = {}
    for path in sorted((out / "raw").glob("*.json")):
        try:
            data = json.loads(path.read_text("utf-8"))
        except (OSError, ValueError):
            continue
        if isinstance(data, dict) and "checks" in data:
            reports[str(data.get("target") or path.stem)] = data
    return reports


def write_summary(out: Path, sites: list[Site], *, show_domains: bool) -> tuple[Path, Path, int]:
    labels = {s.domain: s.label for s in sites if s.label}
    wanted = {s.domain for s in sites}
    reports = {d: r for d, r in load_raw(out).items() if d in wanted}
    rows = aggregate(reports, labels)
    label_names = sorted(set(labels.values()))
    csv_path, html_path = out / "summary.csv", out / "summary.html"
    csv_path.write_text(summary_csv(rows, label_names), "utf-8-sig")  # Excel reads it right
    html_path.write_text(
        summary_html(rows, len(reports), label_names, show_domains=show_domains), "utf-8"
    )
    return csv_path, html_path, len(reports)
