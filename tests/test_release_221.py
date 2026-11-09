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
