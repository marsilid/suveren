"""suveren watch: the same sites again, and what changed (offline)."""

import asyncio
import json

import pytest
from typer.testing import CliRunner

from suveren.checks import Check, Status
from suveren.cli import app
from suveren.errors import SuverenError
from suveren.models import Category, Dependency, Report
from suveren.watch import KEEP_REPORTS, describe, parse_interval, watch_round

TITLE = "Принудительный HTTPS (HSTS)"
GROUP = "Безопасность сайта"


def report(host, hsts=Status.OK, ga=False):
    r = Report(host, checks=[Check(GROUP, TITLE, hsts, "")])
    if ga:
        r.dependencies = [Dependency(Category.ANALYTICS, "Google Analytics", "US", "gtag.js")]
    return r


def test_interval():
    assert parse_interval("24h") == 86400 and parse_interval("2d") == 172800
    assert parse_interval("90m") == 5400
    for bad in ("30m", "x", "", "5"):
        with pytest.raises(SuverenError):
            parse_interval(bad)


def test_rounds_compare_with_the_last_report_and_log_changes(tmp_path):
    answers = iter([report("a.ru"), report("a.ru", Status.WARN, ga=True)])

    async def scan(host):
        return next(answers)

    first = asyncio.run(watch_round(["a.ru"], tmp_path, scan))
    assert first[0].changes is None and first[0].report.exists()
    import time

    time.sleep(1.1)  # the next report gets a later file name
    second = asyncio.run(watch_round(["a.ru"], tmp_path, scan))
    lines = describe(second[0].changes)
    assert "+ Аналитика: Google Analytics" in lines[0] or any(
        "Google Analytics" in x for x in lines
    )
    assert any(TITLE in x and "✗" in x for x in lines)
    log = (tmp_path / "changes.log").read_text("utf-8")
    assert "a.ru" in log and "Google Analytics" in log


def test_a_failed_site_is_logged_and_old_reports_are_pruned(tmp_path):
    folder = tmp_path / "a.ru"
    folder.mkdir()
    for i in range(KEEP_REPORTS + 5):
        (folder / f"2026010{i:03d}.json").write_text(json.dumps(report("a.ru").to_dict()))

    async def scan(host):
        if host == "b.ru":
            raise SuverenError("сайт не ответил")
        return report(host)

    results = asyncio.run(watch_round(["a.ru", "b.ru"], tmp_path, scan))
    assert results[0].changes is not None and results[0].changes.empty
    assert results[1].error == "сайт не ответил"
    assert len(list(folder.glob("*.json"))) == KEEP_REPORTS
    assert "b.ru: не проверен" in (tmp_path / "changes.log").read_text("utf-8")


def test_watch_command_once(tmp_path, monkeypatch):
    sites = tmp_path / "sites.txt"
    sites.write_text("a.ru\nне домен\n", "utf-8")

    async def fake_run_scan(host, **kwargs):
        return report(host)

    monkeypatch.setattr("suveren.cli.run_scan", fake_run_scan)
    result = CliRunner().invoke(
        app, ["watch", str(sites), "--once", "--state", str(tmp_path / "w")]
    )
    assert result.exit_code == 0, result.output
    assert "первая проверка" in result.output and "пропущена" in result.output
    bad = CliRunner().invoke(app, ["watch", str(sites), "--every", "5m"])
    assert bad.exit_code == 2 and "раза в час" in bad.output
