"""Plugins: loaded only when named, isolated when they misbehave, never SUV- IDs."""

import asyncio
import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from test_e2e import offline, run_cli  # noqa: F401  (the fixture)

from suveren.checks import Status
from suveren.plugins import PluginContext, PluginError, load, run_plugin

EXAMPLE = Path(__file__).parent.parent / "examples" / "plugins" / "security_txt.py"


def plugin_file(tmp_path, body: str) -> Path:
    path = tmp_path / "p.py"
    path.write_text(
        "from suveren.checks import Check, Status\nNAME = 'тест'\n" + body, encoding="utf-8"
    )
    return path


def ctx(client=None):
    return PluginContext("site.ru", "site.ru", "https://site.ru/", "<html></html>", {}, [], client)


def run(plugin, **kw):
    return asyncio.run(run_plugin(plugin, ctx(), **kw))


def test_a_good_plugin_returns_its_checks(tmp_path):
    p = load(str(plugin_file(tmp_path, (
        "async def run(ctx):\n"
        "    return [Check('Плагины', 'Есть страница', Status.OK, ctx.host, id='ACME-WEB-001')]\n"
    ))))  # fmt: skip
    (check,) = run(p)
    assert (check.id, check.status, check.details) == ("ACME-WEB-001", Status.OK, "site.ru")


@pytest.mark.parametrize(
    ("body", "said"),
    [
        ("async def run(ctx):\n    raise RuntimeError('упал')\n", "ошибкой"),
        ("import asyncio\nasync def run(ctx):\n    await asyncio.sleep(5)\n", "не уложился"),
        ("async def run(ctx):\n    return 'не список'\n", "не список"),
        (
            "async def run(ctx):\n    return [Check('x', 'y', Status.OK, id='SUV-WEB-004')]\n",
            "никогда SUV-",
        ),
    ],
)
def test_a_misbehaving_plugin_costs_only_its_own_verdict(tmp_path, body, said):
    (check,) = run(load(str(plugin_file(tmp_path, body))), timeout=0.2)
    assert check.status is Status.UNKNOWN and said in check.details


def test_loading_errors_are_clear(tmp_path):
    with pytest.raises(PluginError, match="не найден"):
        load(str(tmp_path / "missing.py"))
    with pytest.raises(PluginError, match="async def run"):
        load(str(plugin_file(tmp_path, "def run(ctx):\n    return []\n")))
    with pytest.raises(PluginError, match="не загрузился"):
        load(str(plugin_file(tmp_path, "import no_such_module_here\n")))


def test_security_txt_example_follows_rfc_9116():
    example = load(str(EXAMPLE)).module
    now = datetime(2026, 10, 22, tzinfo=UTC)
    good = "Contact: mailto:security@site.ru\nExpires: 2027-10-01T00:00:00Z\n"
    assert example.verdict(200, "text/plain", good, now).status is Status.OK
    lower = "Contact: https://g.co/vulnz\nExpires: 2030-04-01t00:00:00z\n"  # www.google.com
    assert example.verdict(200, "text/plain", lower, now).status is Status.OK
    assert example.verdict(404, "text/html", "", now).status is Status.WARN
    assert example.verdict(403, "text/html", "", now).status is Status.UNKNOWN  # a bot wall
    expired = "Contact: mailto:s@site.ru\nExpires: 2025-01-01T00:00:00Z\n"
    assert "истёк" in example.verdict(200, "text/plain", expired, now).details
    assert (
        "Contact"
        in example.verdict(200, "text/plain", "Expires: 2027-01-01T00:00:00Z", now).details
    )


def test_scan_with_a_plugin_end_to_end(offline, tmp_path):  # noqa: F811
    case = offline("lab-good")
    out = tmp_path / "r.json"
    result = run_cli(
        tmp_path,
        case.host,
        "--plugin",
        str(EXAMPLE),
        "--json",
        str(out),
        "-o",
        str(tmp_path / "r.html"),
    )
    assert result.exit_code == 0, result.output
    data = json.loads(out.read_text(encoding="utf-8"))
    plugin_checks = [c for c in data["checks"] if c["id"] == "EX-SEC-001"]
    # The lab site has no security.txt: the plugin says so, in its own section.
    assert plugin_checks and plugin_checks[0]["status"] == "warn"
    assert plugin_checks[0]["group"] == "Проверки из плагинов"
    assert data["schema_version"] == "1.9"
    # The report says plainly that third-party code took part.
    assert [p["source"] for p in data["plugins"]] == [str(EXAMPLE)]
    html = (tmp_path / "r.html").read_text(encoding="utf-8")
    assert "Проверки из плагинов" in html and "Отчёт с плагинами" in html


def _plugin(tmp_path, body, name="bad"):
    path = tmp_path / f"{name}.py"
    path.write_text(body, encoding="utf-8")
    return load(str(path))


def test_plugin_that_calls_sys_exit_costs_only_its_verdict(tmp_path):
    plugin = _plugin(tmp_path, "import sys\nasync def run(ctx):\n    sys.exit(3)\n")
    [check] = asyncio.run(run_plugin(plugin, ctx()))
    assert check.status is Status.UNKNOWN and "SystemExit(3)" in check.details


def test_plugin_that_blocks_is_cut_by_the_timeout(tmp_path):
    plugin = _plugin(tmp_path, "import time\nasync def run(ctx):\n    time.sleep(30)\n")
    started = datetime.now(UTC)
    [check] = asyncio.run(run_plugin(plugin, ctx(), timeout=0.5))
    assert (datetime.now(UTC) - started).total_seconds() < 5
    assert "не уложился" in check.details


def test_plugin_with_dataclass_and_future_annotations_loads(tmp_path):
    body = (
        "from __future__ import annotations\n"
        "from dataclasses import dataclass\n"
        "@dataclass\nclass Row:\n    name: str\n"
        "async def run(ctx):\n    return []\n"
    )
    assert asyncio.run(run_plugin(_plugin(tmp_path, body, "dc"), ctx())) == []


def test_plugin_that_exits_on_import_is_a_load_error(tmp_path):
    with pytest.raises(PluginError, match="SystemExit"):
        _plugin(tmp_path, "import sys\nsys.exit(1)\n", "exits")


def test_plugin_that_finishes_after_the_scan_leaves_no_traceback(tmp_path, monkeypatch):
    """Cut by the timeout, the plugin's thread ends after the loop is closed."""
    import threading

    raised: list[BaseException | None] = []
    monkeypatch.setattr(threading, "excepthook", lambda args: raised.append(args.exc_value))
    plugin = _plugin(tmp_path, "import time\nasync def run(ctx):\n    time.sleep(0.5)\n", "late")
    [check] = asyncio.run(run_plugin(plugin, ctx(), timeout=0.1))
    assert "не уложился" in check.details
    for thread in threading.enumerate():
        if thread.name == "plugin late":
            thread.join(5)
    assert raised == []


# --- Real failures: what plugins out in the wild actually do -------------------------


@pytest.mark.parametrize(
    ("raise_", "said"),
    [
        # Neither is an Exception: raised into the scan's loop they stopped or cancelled
        # the whole scan.
        ("KeyboardInterrupt()", "KeyboardInterrupt"),
        ("asyncio.CancelledError()", "CancelledError"),
        ("GeneratorExit()", "GeneratorExit"),
    ],
)
def test_plugin_base_exceptions_do_not_stop_the_scan(tmp_path, raise_, said):
    body = f"import asyncio\nasync def run(ctx):\n    raise {raise_}\n"
    plugin = _plugin(tmp_path, body, "base")

    async def scan():
        checks = await run_plugin(plugin, ctx())
        return checks, "скан продолжился"

    [check], after = asyncio.run(scan())
    assert after == "скан продолжился"
    assert check.status is Status.UNKNOWN and said in check.details


def test_plugin_whose_request_fails_costs_only_its_verdict(tmp_path, monkeypatch):
    import httpx

    from suveren import collect

    def refuse(request):
        raise httpx.ConnectError("connection refused", request=request)

    monkeypatch.setattr(
        collect,
        "make_client",
        lambda timeout, **kw: httpx.AsyncClient(transport=httpx.MockTransport(refuse)),
    )
    body = (
        "async def run(ctx):\n"
        "    await ctx.client.get('https://site.ru/.well-known/security.txt')\n"
        "    return []\n"
    )
    [check] = asyncio.run(run_plugin(_plugin(tmp_path, body, "net"), ctx()))
    assert check.status is Status.UNKNOWN and "ConnectError" in check.details


def test_one_broken_plugin_does_not_take_the_next_one_down(tmp_path):
    from suveren.plugins import run_plugins

    bad = _plugin(tmp_path, "async def run(ctx):\n    raise KeyboardInterrupt\n", "bad")
    good = _plugin(
        tmp_path,
        "from suveren.checks import Check, Status\n"
        "async def run(ctx):\n"
        "    return [Check('Плагины', 'Хорошо', Status.OK, id='ACME-WEB-001')]\n",
        "good",
    )
    checks = asyncio.run(run_plugins([bad, good], ctx()))
    assert [c.id for c in checks] == ["PLUGIN-ERROR-000", "ACME-WEB-001"]


def test_a_bad_id_drops_only_that_check(tmp_path):
    body = (
        "from suveren.checks import Check, Status\n"
        "async def run(ctx):\n"
        "    return [Check('Плагины', 'Хорошо', Status.OK, id='ACME-WEB-001'),\n"
        "            Check('Плагины', 'Чужой', Status.OK, id='SUV-WEB-004')]\n"
    )
    checks = asyncio.run(run_plugin(_plugin(tmp_path, body, "mixed"), ctx()))
    assert [c.id for c in checks] == ["ACME-WEB-001", "PLUGIN-ERROR-000"]


def test_scan_with_a_crashing_plugin_still_reports(offline, tmp_path):  # noqa: F811
    # Any failed plugin crashed the report: its PLUGIN-ERROR-000 was looked up in the
    # catalogue of our own sections (advice.unchecked).
    case = offline("lab-good")
    crash = tmp_path / "crash.py"
    crash.write_text("async def run(ctx):\n    raise RuntimeError('упал')\n", encoding="utf-8")
    out = tmp_path / "r.json"
    result = run_cli(
        tmp_path,
        case.host,
        "--plugin",
        str(crash),
        "--json",
        str(out),
        "-o",
        str(tmp_path / "r.html"),
    )
    assert result.exit_code == 0, result.output
    data = json.loads(out.read_text(encoding="utf-8"))
    ids = {c["id"]: c for c in data["checks"]}
    assert ids["PLUGIN-ERROR-000"]["status"] == "unknown"
    assert "упал" in ids["PLUGIN-ERROR-000"]["details"]
    # The rest of the scan is all there.
    assert {"SUV-MAIL-001", "SUV-WEB-007", "SUV-PD-001"} <= ids.keys()


def test_cancelling_the_scan_still_cancels_the_plugin(tmp_path):
    body = "import asyncio\nasync def run(ctx):\n    await asyncio.sleep(30)\n"
    plugin = load(str(plugin_file(tmp_path, body)))

    async def scan():
        task = asyncio.create_task(run_plugin(plugin, ctx()))
        await asyncio.sleep(0.05)
        task.cancel()
        await task

    with pytest.raises(asyncio.CancelledError):
        asyncio.run(scan())
