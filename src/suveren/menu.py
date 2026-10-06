"""Interactive menu for people who don't use the command line.

`suveren menu`, or the Windows .exe started with a double click, shows this
menu; every item simply runs the matching command.
"""

from __future__ import annotations

import contextlib
import os
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path

import typer
from rich.console import Console

REPORTS = Path("reports")
SITES_TEMPLATE = (
    "# Впишите сайты, по одному в строке, сохраните файл и выберите пункт 2 снова.\nexample.ru\n"
)

ITEMS = (
    ("1", "Проверить сайт (сервисы, 152-ФЗ, блокировки)"),
    ("2", "Проверить список сайтов"),
    ("3", "Проверить компанию (ИНН, ОГРН или сайт)"),
    ("4", "Сравнить два отчёта (JSON)"),
    ("5", "Показать базу сервисов"),
    ("6", "Обновить санкционные списки и реестр блокировок"),
    ("7", "Проверить источники данных"),
    ("8", "Открыть папку с отчётами"),
    ("0", "Выход"),
)


def open_path(path: Path) -> None:
    """Open a file or folder in the system's default application."""
    with contextlib.suppress(Exception):
        if sys.platform == "win32":
            os.startfile(path)  # type: ignore[attr-defined]
        elif sys.platform == "darwin":
            subprocess.run(["open", str(path)], check=False)
        else:
            subprocess.run(["xdg-open", str(path)], check=False)


def run_menu(app: typer.Typer, console: Console) -> None:
    def call(*args: str) -> None:
        with contextlib.suppress(SystemExit, typer.Exit, typer.Abort):
            app(list(args), standalone_mode=False)

    def ask(prompt: str) -> str:
        try:
            return console.input(f"  {prompt}: ").strip().strip('"')
        except (EOFError, KeyboardInterrupt):
            return ""

    def pause() -> None:
        ask("\n[dim]Нажмите Enter, чтобы вернуться в меню[/]")

    def scan() -> None:
        target = ask("Домен или ссылка")
        if target:
            REPORTS.mkdir(exist_ok=True)
            call("scan", target, "--browser")

    def batch() -> None:
        console.print("  Нужен текстовый файл: по одному сайту в строке.")
        path = ask("Файл со списком (Enter — создать шаблон)")
        if not path:
            REPORTS.mkdir(exist_ok=True)
            template = REPORTS / "sites.txt"
            if not template.exists():
                template.write_text(SITES_TEMPLATE, encoding="utf-8")
            open_path(template)
            console.print(f"  Открыл {template}. Заполните, сохраните и выберите пункт 2 снова.")
            return
        call("batch", path, "--browser")

    def company() -> None:
        console.print("  [dim]Первая проверка скачивает санкционные списки (около 100 МБ).[/]")
        target = ask("ИНН, ОГРН или сайт компании")
        if target:
            call("company", target)

    def diff() -> None:
        old = ask("Старый отчёт (JSON)")
        new = ask("Новый отчёт (JSON)") if old else ""
        if old and new:
            call("diff", old, new)

    def reports() -> None:
        REPORTS.mkdir(exist_ok=True)
        open_path(REPORTS.resolve())

    actions: dict[str, tuple[Callable[[], None], bool]] = {
        "1": (scan, True),
        "2": (batch, True),
        "3": (company, True),
        "4": (diff, True),
        "5": (lambda: call("services"), True),
        "6": (lambda: call("update"), True),
        "7": (lambda: call("doctor"), True),
        "8": (reports, False),
    }

    empty = 0
    while True:
        console.clear()
        console.print("\n  [bold green]S u v e r e n[/]   [dim]аудит сайта и компании для РФ[/]\n")
        for key, title in ITEMS:
            console.print(f"  [bold]{key}[/]  {title}")
        choice = ask("\nВыберите пункт и нажмите Enter")
        if choice == "0":
            return
        if choice not in actions:
            empty += not choice
            if empty >= 5:  # input is closed: don't spin forever
                return
            continue
        empty = 0
        action, wait = actions[choice]
        console.print()
        action()
        if wait:
            pause()
