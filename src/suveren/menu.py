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

from suveren import __version__

REPORTS = Path("reports")
SITES_TEMPLATE = (
    "# Впишите сайты, по одному в строке, сохраните файл и выберите пункт 2 снова.\nexample.ru\n"
)
ACCENT, DIM = "#5fb3b3", "grey50"

# (group, ((key, title, hint), ...))
GROUPS = (
    ("Проверка", (
        ("1", "Сайт", "сервисы, 152-ФЗ, безопасность, сценарии атак"),
        ("2", "Список сайтов", "сводная таблица и отчёт по каждому"),
        ("3", "Компания", "ЕГРЮЛ, санкции, реестр операторов — по ИНН, ОГРН или сайту"),
    )),
    ("Данные", (
        ("4", "Сравнить два отчёта", "что изменилось после переезда (JSON)"),
        ("5", "База сервисов", "какие сервисы распознаёт Suveren"),
        ("6", "Обновить списки", "санкции и реестр блокировок"),
    )),
    ("Сервис", (
        ("7", "Проверить источники", "доступны ли реестры и списки"),
        ("8", "Папка с отчётами", ""),
        ("0", "Выход", ""),
    )),
)  # fmt: skip
ITEMS = tuple((key, title) for _, items in GROUPS for key, title, _ in items)


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
            return console.input(f"  [{DIM}]{prompt}[/]  ").strip().strip('"')
        except (EOFError, KeyboardInterrupt):
            return ""

    def pause() -> None:
        console.print()
        ask("Enter — вернуться в меню")

    def yes(prompt: str) -> bool:
        answer = ask(f"{prompt}  [{ACCENT}]д[/]/[bold]Н[/]")
        return answer.lower() in ("д", "да", "y", "yes")

    def scan() -> None:
        target = ask("Адрес сайта")
        if not target:
            return
        REPORTS.mkdir(exist_ok=True)
        args = ["scan", target, "--browser"]
        if yes("Глубокая проверка (браузер, отключение сервисов, ~1 мин)"):
            args = ["scan", target, "--profile", "deep"]
        if yes("Сохранить ещё и PDF"):
            name = "".join(c if c.isalnum() or c in ".-" else "_" for c in target)
            args += ["--pdf", str(REPORTS / f"{name}.pdf")]
        console.print()
        call(*args)

    def batch() -> None:
        console.print(f"  [{DIM}]Нужен текстовый файл: по одному сайту в строке.[/]")
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
        console.print(f"  [{DIM}]Первая проверка скачивает санкционные списки (около 100 МБ).[/]")
        target = ask("ИНН, ОГРН или сайт компании")
        if target:
            call("company", target, "--browser")

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
        console.print()
        console.print(
            f"[bold {ACCENT}]suveren[/] [{DIM}]{__version__}   аудит сайта и компании для России[/]"
        )
        for group, items in GROUPS:
            console.print()
            console.print(f"  [bold {DIM}]{group}[/]")
            for key, title, hint in items:
                console.print(f"    [bold {ACCENT}]{key}[/]   {title:<22}[{DIM}]{hint}[/]")
        console.print()
        try:
            choice = console.input(f"  [bold {ACCENT}]›[/] ").strip()
        except (EOFError, KeyboardInterrupt):
            choice = ""
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
