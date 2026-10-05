"""Command-line interface."""

from __future__ import annotations

import asyncio
import contextlib
import json
import sys
import webbrowser
from collections import Counter
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from suveren import __version__
from suveren.blocklist import DOMAINS, IP_LISTS
from suveren.blocklist import SOURCE as BLOCK_SOURCE
from suveren.cache import cache_dir, fetch_cached
from suveren.checks import Check, Status
from suveren.collect import make_client
from suveren.company import run_company
from suveren.errors import SuverenError
from suveren.models import Report, Severity
from suveren.report import write_company, write_html, write_json
from suveren.sanctions import SOURCE_TITLES, load_index
from suveren.sanctions import SOURCES as SANCTION_SOURCES
from suveren.scan import run_scan
from suveren.services import ALL_SERVICES
from suveren.utils import country_name, normalize_domain

# The output uses box-drawing and Cyrillic. A legacy Windows console (cp1251/cp866)
# can't encode some of it and would crash, so force UTF-8 output.
for _stream in (sys.stdout, sys.stderr):
    with contextlib.suppress(Exception):
        _stream.reconfigure(encoding="utf-8")

app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    rich_markup_mode="rich",
    help="[bold]Suveren[/] — аудит сайта и компании: иностранные сервисы, 152-ФЗ, "
    "блокировки, ЕГРЮЛ, санкции.",
)
console = Console(record=True)

BANNER = r"""[bold green]
  ___
 / __|_  ___ _____ _ _ ___ _ _
 \__ \ || \ V / -_) '_/ -_) ' \
 |___/\_,_|\_/\___|_| \___|_||_|[/]  [dim]v{version} · независимость инфраструктуры[/]
"""

SEVERITY_STYLE = {
    Severity.HIGH: "bold red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}
GRADE_STYLE = {"A": "bold green", "B": "green", "C": "yellow", "D": "red", "F": "bold red"}
GRADE_ORDER = ("A", "B", "C", "D", "F")


class DnsChoice(str, Enum):
    auto = "auto"
    system = "system"
    doh = "doh"


def _version_callback(value: bool) -> None:
    if value:
        console.print(f"Suveren {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: Annotated[
        bool,
        typer.Option("--version", callback=_version_callback, is_eager=True, help="Версия."),
    ] = False,
) -> None:
    """Подробнее о команде: `suveren КОМАНДА --help`."""


def _fail(message: str, code: int = 2) -> typer.Exit:
    console.print(f"[bold red]✗[/] {message}")
    return typer.Exit(code)


def _print_summary(report: Report) -> None:
    style = GRADE_STYLE[report.grade]
    countries = " · ".join(f"{country_name(c)} {share}%" for c, share in report.countries)
    console.print(
        Panel(
            f"Независимость [{style}]{report.grade}[/]   [bold]{report.score}[/]/100\n"
            f"Иностранных сервисов: [bold]{report.foreign_count}[/] · "
            f"российских: [bold]{report.domestic_count}[/]\n"
            f"[dim]{countries or 'страны не определены'}[/]",
            title=f"[bold]{report.target}[/]",
            expand=False,
            padding=(0, 2),
        )
    )

    findings = report.sorted_findings()
    if not findings:
        console.print("[green]Иностранных зависимостей не найдено.[/]")
    else:
        risks = Table(
            title="\nРиски", title_justify="left", box=None, show_header=False, padding=(0, 1)
        )
        risks.add_column(no_wrap=True)
        risks.add_column()
        for f in findings:
            text = Text(f.title)
            text.append(f"\n→ {f.recommendation}", style="dim")
            risks.add_row(Text(f.severity.ru.upper(), style=SEVERITY_STYLE[f.severity]), text)
        console.print(risks)

    table = Table(
        title="\nВсе найденные сервисы",
        title_justify="left",
        box=None,
        header_style="bold",
        padding=(0, 2),
    )
    table.add_column("Категория", style="dim")
    table.add_column("Сервис")
    table.add_column("Страна")
    table.add_column("")
    for d in report.dependencies:
        if d.foreign:
            mark = Text("!", style=SEVERITY_STYLE[d.severity or Severity.LOW])
        elif d.foreign is False:
            mark = Text("✓", style="green")
        else:
            mark = Text("?", style="dim")
        table.add_row(d.category.title, d.service, d.country_ru, mark)
    console.print(table)


STATUS_STYLE = {
    Status.OK: "green",
    Status.WARN: "yellow",
    Status.FAIL: "bold red",
    Status.UNKNOWN: "dim",
}


def _print_checks(checks: list[Check]) -> None:
    groups: dict[str, list[Check]] = {}
    for check in checks:
        groups.setdefault(check.group, []).append(check)
    for group, items in groups.items():
        table = Table(
            title=f"\n{group}", title_justify="left", box=None, show_header=False, padding=(0, 1)
        )
        table.add_column(no_wrap=True)
        table.add_column()
        for c in items:
            text = Text(c.title, style="bold")
            if c.details:
                text.append(f"\n{c.details}")
            if c.recommendation and c.status is not Status.OK:
                text.append(f"\n→ {c.recommendation}", style="dim")
            table.add_row(Text(c.status.icon, style=STATUS_STYLE[c.status]), text)
        console.print(table)


def _validate_grade(value: str | None) -> str | None:
    if value is None:
        return None
    grade = value.strip().upper()
    if grade not in GRADE_ORDER:
        raise SuverenError(f"--fail-under принимает одну из оценок {', '.join(GRADE_ORDER)}")
    return grade


@app.command()
def scan(
    target: Annotated[str, typer.Argument(help="Домен или ссылка, например example.ru")],
    output: Annotated[
        Path | None,
        typer.Option("--output", "-o", help="Путь к HTML-отчёту (по умолчанию reports/...)."),
    ] = None,
    json_path: Annotated[
        Path | None, typer.Option("--json", help="Сохранить результат в JSON (нужно для diff).")
    ] = None,
    no_report: Annotated[
        bool, typer.Option("--no-report", help="Не создавать HTML-отчёт.")
    ] = False,
    open_report: Annotated[
        bool, typer.Option("--open/--no-open", help="Открыть отчёт в браузере.")
    ] = True,
    timeout: Annotated[
        float, typer.Option("--timeout", "-t", min=1.0, help="Сетевой таймаут, секунды.")
    ] = 10.0,
    dns_mode: Annotated[
        DnsChoice,
        typer.Option("--dns", help="DNS: auto (системный, при сбое DoH), system или doh."),
    ] = DnsChoice.auto,
    fail_under: Annotated[
        str | None,
        typer.Option("--fail-under", help="Код выхода 3, если оценка хуже указанной (для CI)."),
    ] = None,
    export_svg: Annotated[
        Path | None, typer.Option("--export-svg", help="Сохранить вывод терминала в SVG.")
    ] = None,
    no_152fz: Annotated[
        bool, typer.Option("--no-152fz", help="Пропустить проверку по 152-ФЗ.")
    ] = False,
    no_blocklist: Annotated[
        bool,
        typer.Option("--no-blocklist", help="Пропустить проверку по реестру блокировок РКН."),
    ] = False,
    quick: Annotated[
        bool,
        typer.Option(
            "--quick", help="Только иностранные сервисы: без 152-ФЗ и блокировок (для CI)."
        ),
    ] = False,
    refresh: Annotated[
        bool, typer.Option("--refresh", help="Обновить скачанные списки, не дожидаясь суток.")
    ] = False,
) -> None:
    """Проверить сайт: иностранные сервисы, 152-ФЗ и блокировки РКН."""
    try:
        host = normalize_domain(target)
        threshold = _validate_grade(fail_under)
    except SuverenError as exc:
        raise _fail(str(exc)) from exc

    console.print(BANNER.format(version=__version__))
    try:
        with console.status(f"Проверяю {host}…", spinner="dots"):
            report = asyncio.run(
                run_scan(
                    host,
                    timeout=timeout,
                    dns_mode=dns_mode.value,
                    compliance=not (no_152fz or quick),
                    blocklist=not (no_blocklist or quick),
                    refresh=refresh,
                )
            )
    except SuverenError as exc:
        raise _fail(str(exc), code=1) from exc

    for note in report.notes:
        console.print(f"[yellow]![/] [dim]{note}[/]")
    console.print()
    _print_summary(report)
    _print_checks(report.checks)

    if not no_report:
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        html_path = output or Path("reports") / f"{host}-{stamp}.html"
        write_html(report, html_path)
        console.print(f"\n[bold]HTML-отчёт:[/] {html_path}")
        if open_report:
            webbrowser.open(html_path.resolve().as_uri())
    if json_path is not None:
        write_json(report, json_path)
        console.print(f"[bold]JSON:[/] {json_path}")
    if export_svg is not None:
        export_svg.parent.mkdir(parents=True, exist_ok=True)
        console.save_svg(str(export_svg), title=f"suveren scan {host}")

    if threshold is not None and GRADE_ORDER.index(report.grade) > GRADE_ORDER.index(threshold):
        console.print(f"\n[bold red]✗ Оценка {report.grade} хуже требуемой {threshold}.[/]")
        raise typer.Exit(3)


def _dep_key(dep: dict) -> tuple[str, str]:
    return dep.get("category_title", dep.get("category", "?")), dep.get("service", "?")


@app.command()
def diff(
    old: Annotated[Path, typer.Argument(help="Ранний JSON-отчёт (из scan --json).")],
    new: Annotated[Path, typer.Argument(help="Поздний JSON-отчёт того же сайта.")],
) -> None:
    """Сравнить два отчёта: что удалось заменить, а что добавилось."""
    try:
        a = json.loads(old.read_text(encoding="utf-8"))
        b = json.loads(new.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise _fail(f"не удалось прочитать отчёты: {exc}") from exc

    a_deps = {_dep_key(d): d for d in a.get("dependencies", [])}
    b_deps = {_dep_key(d): d for d in b.get("dependencies", [])}
    console.print(
        f"\n[bold]{b.get('target', '?')}[/]: независимость {a.get('grade')} → {b.get('grade')}, "
        f"{a.get('score')} → {b.get('score')} из 100\n"
    )
    changed = False
    for key in sorted(a_deps.keys() - b_deps.keys()):
        changed = True
        style = "green" if a_deps[key].get("foreign") else "yellow"
        console.print(f"  [{style}]− убран   [/] {key[0]}: {key[1]}")
    for key in sorted(b_deps.keys() - a_deps.keys()):
        changed = True
        foreign = b_deps[key].get("foreign")
        style = "red" if foreign else "green"
        console.print(f"  [{style}]+ добавлен[/] {key[0]}: {key[1]}")
    if not changed:
        console.print("  [dim]Набор сервисов не изменился.[/]")


@app.command()
def services() -> None:
    """Показать базу сервисов, которые умеет распознавать Suveren."""
    foreign = Counter(s.country for s in ALL_SERVICES if s.foreign)
    domestic = sum(1 for s in ALL_SERVICES if not s.foreign)
    table = Table(box=None, header_style="bold", padding=(0, 2))
    table.add_column("Сервис")
    table.add_column("Страна")
    table.add_column("Как распознаётся", style="dim")
    for s in sorted(ALL_SERVICES, key=lambda s: (not s.foreign, s.name.lower())):
        ways = [
            label
            for label, present in (
                ("NS", s.ns),
                ("MX", s.mx),
                ("ASN", s.asn or s.as_names),
                ("регистратор", s.registrar),
                ("сертификат", s.issuer),
                ("код страницы", s.page),
            )
            if present
        ]
        country = Text(country_name(s.country), style="green" if not s.foreign else "")
        table.add_row(s.name, country, ", ".join(ways))
    console.print(table)
    console.print(
        f"\nВсего: [bold]{len(ALL_SERVICES)}[/] · иностранных {sum(foreign.values())} · "
        f"российских {domestic}"
    )


@app.command()
def company(
    target: Annotated[
        str, typer.Argument(help="ИНН, ОГРН или домен сайта (ИНН будет найден на сайте).")
    ],
    output: Annotated[
        Path | None,
        typer.Option("--output", "-o", help="Путь к HTML-отчёту (по умолчанию reports/...)."),
    ] = None,
    json_path: Annotated[Path | None, typer.Option("--json", help="Сохранить в JSON.")] = None,
    no_report: Annotated[
        bool, typer.Option("--no-report", help="Не создавать HTML-отчёт.")
    ] = False,
    open_report: Annotated[
        bool, typer.Option("--open/--no-open", help="Открыть отчёт в браузере.")
    ] = True,
    no_sanctions: Annotated[
        bool, typer.Option("--no-sanctions", help="Не проверять санкционные списки.")
    ] = False,
    refresh: Annotated[
        bool, typer.Option("--refresh", help="Обновить санкционные списки сейчас.")
    ] = False,
    timeout: Annotated[
        float, typer.Option("--timeout", "-t", min=1.0, help="Сетевой таймаут, секунды.")
    ] = 15.0,
) -> None:
    """Проверить компанию: ЕГРЮЛ, санкционные списки, реестр операторов ПДн."""
    console.print(BANNER.format(version=__version__))
    try:
        with console.status("Проверяю компанию… (первый раз скачиваются санкционные списки)"):
            report = asyncio.run(
                run_company(target, timeout=timeout, sanctions=not no_sanctions, refresh=refresh)
            )
    except SuverenError as exc:
        raise _fail(str(exc)) from exc

    for note in report.notes:
        console.print(f"[yellow]![/] [dim]{note}[/]")
    rec = report.egrul
    lines = []
    if rec:
        lines.append(rec.name_full)
        lines.append(f"ИНН {rec.inn or '—'} · ОГРН {rec.ogrn or '—'}")
        if rec.head:
            lines.append(f"[dim]{rec.head}[/]")
    elif report.domain:
        lines.append(f"Сайт {report.domain}, ИНН {report.inn or 'не найден'}")
    console.print()
    console.print(
        Panel("\n".join(lines) or report.query, title=f"[bold]{report.title}[/]", expand=False)
    )
    _print_checks(report.checks)

    if report.hits:
        table = Table(
            title="\nСовпадения в санкционных списках",
            title_justify="left",
            box=None,
            header_style="bold",
            padding=(0, 2),
        )
        table.add_column("Список")
        table.add_column("Запись")
        table.add_column("Как найдено", style="dim")
        for h in report.hits:
            table.add_row(SOURCE_TITLES[h.entry.source], h.entry.names[0], h.how_ru)
        console.print(table)

    html_path = None
    if not no_report:
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        slug = report.inn or report.ogrn or report.domain or "company"
        html_path = output or Path("reports") / f"company-{slug}-{stamp}.html"
    write_company(report, html_path, json_path)
    if html_path is not None:
        console.print(f"\n[bold]HTML-отчёт:[/] {html_path}")
        if open_report:
            webbrowser.open(html_path.resolve().as_uri())
    if json_path is not None:
        console.print(f"[bold]JSON:[/] {json_path}")


@app.command()
def update() -> None:
    """Скачать свежие санкционные списки и реестр блокировок (обычно раз в сутки сам)."""

    async def run() -> None:
        async with make_client(30.0) as client:
            with console.status("Санкционные списки…"):
                index = await load_index(client, refresh=True)
            for note in index.notes:
                console.print(f"[yellow]![/] {note}")
            for source in SANCTION_SOURCES:
                count = sum(1 for e in index.entries if e.source == source.key)
                console.print(f"[green]✓[/] {source.title}: {count} записей")
            for name in (DOMAINS, *IP_LISTS):
                with console.status(f"Реестр блокировок: {name}…"):
                    path, note = await fetch_cached(
                        client, BLOCK_SOURCE + name, f"blocklist-{name}", refresh=True
                    )
                mark = "[yellow]![/]" if note else "[green]✓[/]"
                size = path.stat().st_size / 1_048_576
                console.print(f"{mark} Реестр блокировок {name}: {size:.1f} МБ")
        console.print(f"\n[dim]Кэш: {cache_dir()}[/]")

    try:
        asyncio.run(run())
    except SuverenError as exc:
        raise _fail(str(exc), code=1) from exc
