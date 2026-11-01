"""suveren research: resumable runs and only aggregates (offline, lab reports)."""

import asyncio
import csv
import io
import json
import sys
from pathlib import Path

import pytest
from typer.testing import CliRunner

from suveren.cli import app
from suveren.errors import SuverenError
from suveren.models import Report
from suveren.research import (
    Site,
    aggregate,
    load_raw,
    read_sites,
    run_research,
    summary_csv,
    summary_html,
    write_summary,
)

sys.path.insert(0, str(Path(__file__).parent))
import lab

CASES = {"lab-good": "магазин", "lab-no-hsts": "магазин", "lab-hosting-abroad": "блог"}


def lab_report(name: str) -> Report:
    case = next(c for c in lab.CASES if c.name == name)
    checks = asyncio.run(lab.run_case(case))
    return Report(case.host, checks=list(checks.values()))


@pytest.fixture(scope="module")
def recorded():
    return {f"{n}.ru": lab_report(n) for n in CASES}


def test_read_sites_with_types():
    sites, skipped = read_sites(
        "a.ru, магазин\nb.ru;блог\nhttps://c.ru/\tмедицина\n\nне сайт\na.ru\n"
    )
    assert [(s.domain, s.label) for s in sites] == [
        ("a.ru", "магазин"), ("b.ru", "блог"), ("c.ru", "медицина"),
    ]  # fmt: skip
    assert skipped == ["не сайт"]


def test_run_is_resumable_and_keeps_raw_reports(tmp_path, recorded):
    calls = []

    async def scan(host):
        calls.append(host)
        if host == "bad.ru":
            raise SuverenError("сайт не ответил")
        return recorded[host]

    sites = [Site(d) for d in recorded] + [Site("bad.ru")]
    scanned, before, failed = asyncio.run(run_research(sites, tmp_path, scan, jobs=2))
    assert (scanned, before) == (3, 0) and failed == [("bad.ru", "сайт не ответил")]
    calls.clear()
    scanned, before, _ = asyncio.run(run_research(sites, tmp_path, scan))
    assert (scanned, before) == (0, 3) and calls == ["bad.ru"]  # only what was missing
    (tmp_path / "raw" / "lab-good.ru.json").write_text("{broken", "utf-8")
    asyncio.run(run_research(sites, tmp_path, scan))
    assert "lab-good.ru" in calls and set(load_raw(tmp_path)) == set(recorded)


def test_aggregate_shares_and_types(recorded):
    reports = {d: r.to_dict() for d, r in recorded.items()}
    labels = {f"{n}.ru": t for n, t in CASES.items()}
    rows = {r.key: r for r in aggregate(reports, labels)}
    hsts = rows["SUV-WEB-005"]
    assert hsts.sites == ["lab-no-hsts.ru"] and hsts.checked == 3
    assert hsts.by_label == {"магазин": (1, 2), "блог": (0, 1)}
    abroad = rows["SUV-PD-007"]
    assert abroad.sites == ["lab-hosting-abroad.ru"] and abroad.by_label["блог"] == (1, 1)
    assert all(r.sites for r in rows.values())  # nothing found is not listed


def test_unknown_is_not_counted_as_seen():
    reports = {
        "a.ru": {"checks": [{"id": "SUV-WEB-005", "status": "warn", "title": "HSTS"}]},
        "b.ru": {"checks": [{"id": "SUV-WEB-005", "status": "unknown", "title": "HSTS"}]},
    }
    [row] = aggregate(reports, {})
    assert (len(row.sites), row.checked, row.share) == (1, 1, 1.0)


def test_outputs_hide_domains_by_default(recorded, tmp_path):
    reports = {d: r.to_dict() for d, r in recorded.items()}
    rows = aggregate(reports, {f"{n}.ru": t for n, t in CASES.items()})
    table = list(csv.reader(io.StringIO(summary_csv(rows, ["блог", "магазин"]))))
    assert table[0][-2:] == ["блог, %", "магазин, %"]
    hsts = next(r for r in table if r[0] == "SUV-WEB-005")
    assert hsts[2:5] == ["1", "3", "33.3"] and hsts[-1] == "50.0"
    page = summary_html(rows, 3, ["блог", "магазин"], show_domains=False)
    assert "lab-no-hsts.ru" not in page and "Названия сайтов скрыты" in page
    assert "<svg" in page and "<script" not in page and "Content-Security-Policy" in page
    shown = summary_html(rows, 3, [], show_domains=True)
    assert "lab-no-hsts.ru" in shown


def test_summary_counts_only_the_listed_sites(tmp_path, recorded):
    (tmp_path / "raw").mkdir()
    for d, r in recorded.items():
        (tmp_path / "raw" / f"{d}.json").write_text(json.dumps(r.to_dict(), default=str))
    csv_path, html_path, total = write_summary(
        tmp_path, [Site("lab-good.ru"), Site("lab-no-hsts.ru")], show_domains=False
    )
    assert total == 2 and csv_path.read_text("utf-8-sig").startswith("Находка")
    assert html_path.exists()


def test_research_command(tmp_path, monkeypatch, recorded):
    sites = tmp_path / "sites.txt"
    sites.write_text("lab-good.ru, магазин\nlab-no-hsts.ru, магазин\nплохо\n", "utf-8")

    async def fake_run_scan(host, **kwargs):
        return recorded[host]

    monkeypatch.setattr("suveren.cli.run_scan", fake_run_scan)
    out = tmp_path / "r"
    result = CliRunner().invoke(app, ["research", str(sites), "--out", str(out)])
    assert result.exit_code == 0, result.output
    assert "Сводка по 2 сайтам" in result.output and "пропущена" in result.output
    again = CliRunner().invoke(app, ["research", str(sites), "--out", str(out), "--summary-only"])
    assert again.exit_code == 0 and "проверено сейчас" not in again.output
