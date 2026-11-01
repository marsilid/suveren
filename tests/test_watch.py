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


# --- Telegram -------------------------------------------------------------------------

TOKEN = "123456:SECRET-token-value"


def _changed():
    from suveren.watch import WatchResult

    old = report("a.ru").to_dict()
    new = report("a.ru", Status.WARN, ga=True).to_dict()
    from suveren.history import compare

    return [WatchResult("a.ru", compare(old, new)), WatchResult("b.ru", None)]


def test_message_only_when_something_changed():
    from datetime import datetime

    from suveren.watch import changes_message

    text = changes_message(_changed(), datetime(2026, 11, 1, 9, 0))
    assert text.startswith("Suveren: изменения на сайтах (01.11.2026 09:00)")
    assert "a.ru:" in text and "Google Analytics" in text and "b.ru" not in text
    assert changes_message([]) is None
    first = _changed()[1:]  # a first round has nothing to compare
    assert changes_message(first) is None


def test_long_message_is_cut(monkeypatch):
    from suveren import watch as watch_module

    monkeypatch.setattr(watch_module, "TELEGRAM_LIMIT", 120)
    text = watch_module.changes_message(_changed())
    assert len(text) <= 120 and text.endswith("changes.log)")


def _send(handler):
    import httpx

    from suveren.watch import send_telegram

    async def go():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as c:
            await send_telegram(c, TOKEN, "@chan", "текст")

    asyncio.run(go())


def test_send_telegram_posts_the_message():
    import httpx

    seen = {}

    def handler(request):
        seen["url"] = str(request.url)
        seen["body"] = json.loads(request.content)
        return httpx.Response(200, json={"ok": True})

    _send(handler)
    assert seen["url"] == f"https://api.telegram.org/bot{TOKEN}/sendMessage"
    assert seen["body"]["chat_id"] == "@chan" and seen["body"]["text"] == "текст"


def test_telegram_errors_never_show_the_token():
    import httpx

    with pytest.raises(SuverenError) as refused:
        _send(lambda r: httpx.Response(401, json={"ok": False}))
    assert "401" in str(refused.value) and TOKEN not in str(refused.value)

    def down(request):
        raise httpx.ConnectError(f"cannot reach {request.url}", request=request)

    with pytest.raises(SuverenError) as failed:
        _send(down)
    assert TOKEN not in str(failed.value) and "SECRET" not in str(failed.value)


def test_watch_command_sends_changes_and_keeps_the_token_out_of_files(tmp_path, monkeypatch):
    sites = tmp_path / "sites.txt"
    sites.write_text("a.ru\n", "utf-8")
    answers = iter([report("a.ru"), report("a.ru", Status.WARN, ga=True)])
    sent = []

    async def fake_run_scan(host, **kwargs):
        return next(answers)

    async def fake_send(client, token, chat, text):
        sent.append((token, chat, text))

    monkeypatch.setattr("suveren.cli.run_scan", fake_run_scan)
    monkeypatch.setattr("suveren.watch.send_telegram", fake_send)
    monkeypatch.setenv("SUVEREN_TELEGRAM_TOKEN", TOKEN)
    monkeypatch.setenv("SUVEREN_TELEGRAM_CHAT", "42")
    state = tmp_path / "w"
    args = ["watch", str(sites), "--once", "--state", str(state)]
    first = CliRunner().invoke(app, args)
    assert first.exit_code == 0 and sent == []  # nothing to compare: silence
    import time

    time.sleep(1.1)
    second = CliRunner().invoke(app, args)
    assert second.exit_code == 0, second.output
    assert len(sent) == 1 and sent[0][1] == "42" and "Google Analytics" in sent[0][2]
    assert "отправлены в Telegram" in second.output and TOKEN not in second.output
    for path in state.rglob("*"):
        if path.is_file():
            assert TOKEN not in path.read_text("utf-8")


def test_telegram_needs_both_options(tmp_path, monkeypatch):
    monkeypatch.delenv("SUVEREN_TELEGRAM_CHAT", raising=False)
    monkeypatch.delenv("SUVEREN_TELEGRAM_TOKEN", raising=False)
    sites = tmp_path / "sites.txt"
    sites.write_text("a.ru\n", "utf-8")
    result = CliRunner().invoke(app, ["watch", str(sites), "--once", "--telegram-token", "x"])
    assert result.exit_code == 2 and "оба" in result.output
