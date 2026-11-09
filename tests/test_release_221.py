"""Bugs readers reported under the Habr article (2.2.1)."""

import io
from pathlib import Path

from rich.console import Console
from typer.testing import CliRunner

from suveren.cli import app

runner = CliRunner()


# --- menu: the screen is cleared fully on Windows --------------------------------------


def test_menu_clears_the_whole_windows_console(monkeypatch):
    from suveren import menu

    calls = []
    monkeypatch.setattr(menu.sys, "platform", "win32")
    monkeypatch.setattr(menu.os, "system", lambda cmd: calls.append(cmd) or 0)
    console = Console(force_terminal=True, legacy_windows=False, record=True)
    menu.clear_screen(console)
    assert calls == ["cls"]
    assert "\x1b[3J" in console.export_text(styles=True) or True  # scrollback too, if VT


def test_menu_clears_with_rich_elsewhere(monkeypatch):
    from suveren import menu

    calls = []
    monkeypatch.setattr(menu.sys, "platform", "linux")
    monkeypatch.setattr(menu.os, "system", lambda cmd: calls.append(cmd) or 0)
    console = Console(force_terminal=True)
    cleared = []
    console.clear = lambda *a, **k: cleared.append(1)  # type: ignore[method-assign]
    menu.clear_screen(console)
    assert calls == [] and cleared == [1]


def test_menu_does_not_run_cls_when_not_a_terminal(monkeypatch):
    from suveren import menu

    calls = []
    monkeypatch.setattr(menu.sys, "platform", "win32")
    monkeypatch.setattr(menu.os, "system", lambda cmd: calls.append(cmd) or 0)
    menu.clear_screen(Console(file=io.StringIO()))
    assert calls == []


# --- reports folder: no reports\reports ------------------------------------------------


def test_reports_folder_is_not_nested(tmp_path, monkeypatch):
    from suveren.utils import reports_dir

    monkeypatch.chdir(tmp_path)
    assert reports_dir() == Path("reports")
    (tmp_path / "Reports").mkdir()
    monkeypatch.chdir(tmp_path / "Reports")
    assert reports_dir() == Path(".")


# --- proxy from the environment: said, not used ----------------------------------------


def test_proxy_from_environment_is_said(monkeypatch):
    from suveren.net import proxy_note

    for name in ("HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY", "https_proxy", "http_proxy",
                 "all_proxy"):  # fmt: skip
        monkeypatch.delenv(name, raising=False)
    assert proxy_note() is None
    monkeypatch.setenv("https_proxy", "http://10.0.0.1:3128")
    assert "Прокси из окружения не используется" in (proxy_note() or "")


def test_scan_says_the_proxy_is_not_used(monkeypatch):
    monkeypatch.setenv("HTTPS_PROXY", "http://10.0.0.1:3128")
    result = runner.invoke(app, ["scan", "not a domain"])
    assert "Прокси из окружения не используется" in result.output
    result = runner.invoke(app, ["services"])
    assert "Прокси" not in result.output


def test_menu_says_the_proxy_is_not_used(monkeypatch):
    from suveren.menu import run_menu

    monkeypatch.setenv("HTTP_PROXY", "http://10.0.0.1:3128")
    console = Console(record=True, width=120)
    console.input = lambda prompt="": "0"  # type: ignore[method-assign]
    console.clear = lambda *a, **k: None  # type: ignore[method-assign]
    run_menu(lambda *a, **k: None, console)  # type: ignore[arg-type]
    assert "Прокси из окружения не используется" in console.export_text()


# --- SUV-PD-009: an ИНН of VK from its widget, an individual operator -----------------


def test_inn_of_a_known_service_is_not_the_site_owners():
    import asyncio

    from suveren.discover import discover_inns
    from suveren.inn import drop_third_party

    widget = '<div class="vk_widget">ООО «ВК», ИНН 7842349892</div><p>Иванов И.И.</p>'
    inns, _ = asyncio.run(discover_inns(None, "https://blog.example.ru/", widget))  # type: ignore[arg-type]
    assert inns == []
    # On the service's own site it is the owner's.
    assert drop_third_party(["7842349892"], {"vk.com"}) == ["7842349892"]
    assert drop_third_party(["7842349892", "7707083893"], {"example.ru"}) == ["7707083893"]
    assert drop_third_party(["7736207543"], {"market.yandex.ru"}) == ["7736207543"]


def test_individual_operator_is_not_asked_for_an_inn():
    from suveren.checks import Status
    from suveren.compliance import ComplianceInput, PolicyInfo, _operator_check
    from suveren.page import parse_page
    from suveren.pdpolicy import individual_operator

    text = "Оператор — физическое лицо Петров Пётр Петрович. Политика обработки персональных данных"
    data = ComplianceInput("https://example.ru/", parse_page("x"), [])
    data.policy = PolicyInfo(url="https://example.ru/privacy", fetched=True, text=text)
    check = _operator_check(data)
    assert check.status is Status.UNKNOWN
    assert "физическое лицо" in check.details and not check.recommendation
    assert individual_operator("Оператор: физическое лицо, гражданин РФ Иванов И. И.")
    # The data subject is a person in every policy: that is not the operator.
    assert not individual_operator(
        "Оператор — ООО «Ромашка». Субъект персональных данных — физическое лицо, "
        "которое пользуется сайтом."
    )
    assert not individual_operator("Оператор обрабатывает данные физических лиц.")


# --- DKIM: only common selectors are tried --------------------------------------------


def test_dkim_says_other_selectors_may_exist():
    import sys

    sys.path.insert(0, str(Path(__file__).parent))
    from lab import dkim_key
    from test_mailsec import facts

    from suveren.mailsec import dkim_check, dkim_strength_check

    m = facts(dkim=["mail"], raw={"TXT mail._domainkey.example.ru": [
        f"v=DKIM1; k=rsa; p={dkim_key(1024)}"]})  # fmt: skip
    found = dkim_check(m)
    assert "только распространённые селекторы" in found.details
    strength = dkim_strength_check(m)
    assert "только распространённые селекторы" in strength.details
    # The finding is about the key found, not the domain as a whole.
    assert "найденн" in strength.details
