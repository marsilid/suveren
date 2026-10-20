"""Command-line interface."""

from __future__ import annotations

import asyncio
import contextlib
import csv
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

from suveren import __version__, unknown
from suveren.blocklist import ensure_lists
from suveren.brand import Brand, brand_from
from suveren.cache import cache_dir
from suveren.catalog import BY_ID, CATALOG, SelectionError, all_tags, select
from suveren.checks import GROUP_152, GROUP_BLOCK, Check, Status
from suveren.collect import make_client
from suveren.company import run_company
from suveren.crawl import DEFAULT_PAGES
from suveren.doctor import run_doctor
from suveren.errors import TIMEOUTS, SuverenError
from suveren.menu import run_menu
from suveren.models import Report
from suveren.plan import PROFILE_HELP, Profile, make_plan
from suveren.render import print_pdf
from suveren.report import write_batch_html, write_company, write_html, write_json
from suveren.sanctions import SOURCE_TITLES, load_index
from suveren.sanctions import SOURCES as SANCTION_SOURCES
from suveren.sarif import write_sarif
from suveren.scan import gather_limited, run_scan
from suveren.services import ALL_SERVICES
from suveren.utils import country_name, normalize_domain
from suveren.view import (
    BANNER,
    GRADE_STYLE,
    print_checks,
    print_scan,
    score_bar,
    section,
)

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
GRADE_ORDER = ("A", "B", "C", "D", "F")
SITE_DEADLINE = 300  # seconds per site in batch


class DnsChoice(str, Enum):
    auto = "auto"
    system = "system"
    ru = "ru"
    doh = "doh"


BrandName = Annotated[
    str | None,
    typer.Option(
        "--brand-name",
        help="Название студии в шапке отчёта вместо Suveren (или SUVEREN_BRAND_NAME).",
    ),
]
BrandLogo = Annotated[
    Path | None,
    typer.Option("--brand-logo", help="Логотип студии: PNG, JPEG или SVG до 512 КБ."),
]
BrandUrl = Annotated[str | None, typer.Option("--brand-url", help="Сайт студии в подвале.")]
PdfPath = Annotated[
    Path | None,
    typer.Option("--pdf", help="Сохранить отчёт в PDF (нужен playwright, как для --browser)."),
]


def _brand(name: str | None, logo: Path | None, url: str | None) -> Brand | None:
    try:
        return brand_from(name, logo, url)
    except SuverenError as exc:
        raise _fail(str(exc)) from exc


def _pdf(html_path: Path, pdf_path: Path) -> None:
    try:
        with _spinner("[dim]Печатаю PDF…[/]"):
            asyncio.run(print_pdf(html_path, pdf_path))
    except SuverenError as exc:
        console.print(f"[yellow]![/] PDF не создан: {exc}")
        return
    console.print(f"[bold]PDF:[/]   {pdf_path}")


class FailOn(str, Enum):
    fail = "fail"
    warn = "warn"

    @property
    def ru(self) -> str:
        return Status(self.value).ru


def failing_checks(report: Report, fail_on: FailOn | None) -> list[Check]:
    """Checks that make ``--fail-on`` exit with code 4; "not checked" never does."""
    if fail_on is None:
        return []
    bad = {Status.FAIL} if fail_on is FailOn.fail else {Status.FAIL, Status.WARN}
    return [c for c in report.checks if c.status in bad]


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


def _validate_grade(value: str | None) -> str | None:
    if value is None:
        return None
    grade = value.strip().upper()
    if grade not in GRADE_ORDER:
        raise SuverenError(f"--fail-under принимает одну из оценок {', '.join(GRADE_ORDER)}")
    return grade


def _stamp() -> str:
    return datetime.now().strftime("%Y%m%d-%H%M%S")


def _open(path: Path) -> None:
    with contextlib.suppress(Exception):
        webbrowser.open(path.resolve().as_uri())


def _spinner(text: str) -> contextlib.AbstractContextManager[object]:
    """A live spinner in a real terminal; nothing when output is redirected, so logs and
    --export-svg don't fill up with animation frames."""
    if console.is_terminal:
        return console.status(text, spinner="dots")
    return contextlib.nullcontext()


class StageLog:
    """Prints each finished scan stage with its duration under a live spinner."""

    def __init__(self) -> None:
        self.status = console.status("", spinner="dots") if console.is_terminal else None

    def __enter__(self) -> StageLog:
        if self.status is not None:
            self.status.__enter__()
        return self

    def __exit__(self, *exc: object) -> None:
        if self.status is not None:
            self.status.__exit__(*exc)  # type: ignore[arg-type]

    def __call__(self, stage: str, seconds: float | None) -> None:
        if seconds is None:
            if self.status is not None:
                self.status.update(f"[dim]{stage}…[/]")
        else:
            console.print(f"  [green]✓[/] {stage:<44} [dim]{seconds:5.1f} с[/]")


# --- scan -----------------------------------------------------------------------------


@app.command()
def scan(
    target: Annotated[str, typer.Argument(help="Домен или ссылка, например example.ru")],
    browser: Annotated[
        bool,
        typer.Option(
            "--browser",
            "-b",
            help="Открыть сайт в браузере (Edge/Chrome): находит скрипты, подгружаемые "
            "динамически, и проходит часть защит от ботов. Нужен пакет playwright.",
        ),
    ] = False,
    details: Annotated[
        bool, typer.Option("--details", "-d", help="Показать все найденные сервисы.")
    ] = False,
    pages: Annotated[
        int,
        typer.Option(
            "--pages",
            "-p",
            min=0,
            max=30,
            help="Сколько внутренних страниц проверить помимо главной (0 — только главную).",
        ),
    ] = DEFAULT_PAGES,
    quick: Annotated[
        bool,
        typer.Option(
            "--quick",
            help="Только иностранные сервисы, без 152-ФЗ, блокировок, почты, поддоменов и "
            "проверок безопасности (то же, что --profile quick).",
        ),
    ] = False,
    profile: Annotated[
        Profile, typer.Option("--profile", "-P", help=PROFILE_HELP)
    ] = Profile.standard,
    checks: Annotated[
        str | None,
        typer.Option(
            "--checks",
            "-c",
            help="Только эти проверки: ID (SUV-MAIL-003), префиксы (SUV-WEB), теги (mail, "
            "headers, law) через запятую. Список: suveren checks.",
        ),
    ] = None,
    cutoff: Annotated[
        bool,
        typer.Option(
            "--cutoff",
            help="Эксперимент: открыть сайт в браузере без иностранных сервисов и показать, "
            "что сломается (ещё 3 загрузки, нужен playwright).",
        ),
    ] = False,
    no_152fz: Annotated[
        bool, typer.Option("--no-152fz", help="Пропустить проверку по 152-ФЗ.")
    ] = False,
    no_blocklist: Annotated[
        bool, typer.Option("--no-blocklist", help="Пропустить реестр блокировок РКН.")
    ] = False,
    no_mail: Annotated[
        bool, typer.Option("--no-mail", help="Пропустить проверку защиты почты от подделки.")
    ] = False,
    no_security: Annotated[
        bool,
        typer.Option(
            "--no-security",
            help="Пропустить проверку безопасности сайта: сторонние скрипты, CSP, HSTS, TLS.",
        ),
    ] = False,
    no_subdomains: Annotated[
        bool,
        typer.Option(
            "--no-subdomains",
            help="Пропустить поддомены из журналов сертификатов (crt.sh) и поиск их захвата.",
        ),
    ] = False,
    output: Annotated[
        Path | None,
        typer.Option("--output", "-o", help="Путь к HTML-отчёту (по умолчанию reports/...)."),
    ] = None,
    json_path: Annotated[
        Path | None, typer.Option("--json", help="Сохранить результат в JSON (нужно для diff).")
    ] = None,
    sarif_path: Annotated[
        Path | None,
        typer.Option(
            "--sarif",
            help="Сохранить результат в SARIF 2.1.0 (GitHub/GitLab code scanning, DefectDojo).",
        ),
    ] = None,
    no_report: Annotated[
        bool, typer.Option("--no-report", help="Не создавать HTML-отчёт.")
    ] = False,
    open_report: Annotated[
        bool, typer.Option("--open/--no-open", help="Открыть отчёт в браузере.")
    ] = True,
    fail_under: Annotated[
        str | None,
        typer.Option("--fail-under", help="Код выхода 3, если оценка хуже указанной (для CI)."),
    ] = None,
    fail_on: Annotated[
        FailOn | None,
        typer.Option(
            "--fail-on",
            help="Код выхода 4, если есть проверки с этим статусом или хуже: fail — "
            "только «проблема», warn — ещё и «внимание» (для CI).",
        ),
    ] = None,
    timeout: Annotated[
        float, typer.Option("--timeout", "-t", min=1.0, help="Сетевой таймаут, секунды.")
    ] = 10.0,
    dns_mode: Annotated[
        DnsChoice,
        typer.Option(
            "--dns",
            help="DNS: auto (системный, при сбое Яндекс DNS, затем Google), system, "
            "ru (только Яндекс DNS, запросы не уходят за рубеж) или doh (Google/Cloudflare).",
        ),
    ] = DnsChoice.auto,
    refresh: Annotated[
        bool, typer.Option("--refresh", help="Обновить скачанные списки, не дожидаясь суток.")
    ] = False,
    export_svg: Annotated[
        Path | None, typer.Option("--export-svg", help="Сохранить вывод терминала в SVG.")
    ] = None,
    pdf: PdfPath = None,
    brand_name: BrandName = None,
    brand_logo: BrandLogo = None,
    brand_url: BrandUrl = None,
) -> None:
    """Проверить сайт: иностранные сервисы, 152-ФЗ и блокировки РКН."""
    brand = _brand(brand_name, brand_logo, brand_url)
    try:
        host = normalize_domain(target)
        threshold = _validate_grade(fail_under)
        plan = make_plan(
            Profile.quick if quick else profile,
            checks,
            browser=browser,
            pages=pages,
            cutoff=cutoff,
            skip={
                name
                for name, off in (
                    ("compliance", no_152fz),
                    ("blocklist", no_blocklist),
                    ("mail", no_mail),
                    ("security", no_security),
                    ("subdomains", no_subdomains),
                )
                if off
            },
        )
    except (SuverenError, SelectionError) as exc:
        raise _fail(str(exc)) from exc

    console.print(BANNER.format(version=__version__))
    console.print(f"  Проверяю [bold]{host}[/]\n")
    try:
        with StageLog() as log:
            report = asyncio.run(
                run_scan(
                    host,
                    timeout=timeout,
                    dns_mode=dns_mode.value,
                    refresh=refresh,
                    progress=log,
                    **plan.kwargs(),  # type: ignore[arg-type]
                )
            )
    except SuverenError as exc:
        raise _fail(str(exc), code=1) from exc

    console.print()
    print_scan(console, report, details=details)

    console.print()
    if not no_report or pdf is not None:
        html_path = output or Path("reports") / f"{host}-{_stamp()}.html"
        write_html(report, html_path, brand)
        if not no_report:
            console.print(f"[bold]Отчёт:[/] {html_path}")
        if pdf is not None:
            _pdf(html_path, pdf)
        if no_report:
            html_path.unlink(missing_ok=True)  # only needed to print the PDF
        elif open_report:
            _open(html_path)
    if json_path is not None:
        write_json(report, json_path)
        console.print(f"[bold]JSON:[/]  {json_path}")
    if sarif_path is not None:
        write_sarif(report, sarif_path)
        console.print(f"[bold]SARIF:[/] {sarif_path}")
    if export_svg is not None:
        export_svg.parent.mkdir(parents=True, exist_ok=True)
        console.save_svg(str(export_svg), title=f"suveren scan {host}")

    if threshold is not None and GRADE_ORDER.index(report.grade) > GRADE_ORDER.index(threshold):
        console.print(f"\n[bold red]✗ Оценка {report.grade} хуже требуемой {threshold}.[/]")
        raise typer.Exit(3)
    failing = failing_checks(report, fail_on)
    if failing:
        ids = ", ".join(dict.fromkeys(c.id for c in failing))
        console.print(f"\n[bold red]✗ Проверки со статусом «{fail_on.ru}» и хуже: {ids}.[/]")
        raise typer.Exit(4)


# --- batch ----------------------------------------------------------------------------


def read_targets(path: Path) -> list[str]:
    """Domains from a text file: one per line, '#' comments and blanks ignored."""
    hosts: list[str] = []
    for line in path.read_text(encoding="utf-8-sig").splitlines():
        value = line.split("#", 1)[0].strip()
        if value:
            host = normalize_domain(value)
            if host not in hosts:
                hosts.append(host)
    return hosts


def batch_row(report: Report) -> dict[str, object]:
    def count(group: str, status: Status) -> int:
        return sum(1 for c in report.checks if c.group == group and c.status is status)

    return {
        "domain": report.target,
        "grade": report.grade,
        "score": report.score,
        "foreign": report.foreign_count,
        "domestic": report.domestic_count,
        "pd_fail": count(GROUP_152, Status.FAIL),
        "pd_warn": count(GROUP_152, Status.WARN),
        "blocked": count(GROUP_BLOCK, Status.FAIL) > 0,
        "top_risks": "; ".join(f.title for f in report.sorted_findings()[:3]),
        # New columns go last: summary.csv may be read by position.
        "fines_max": report.fines.total(),
    }


@app.command()
def batch(
    file: Annotated[Path, typer.Argument(help="Текстовый файл: по одному домену в строке.")],
    quick: Annotated[
        bool, typer.Option("--quick", help="Только иностранные сервисы (быстрее).")
    ] = False,
    profile: Annotated[
        Profile, typer.Option("--profile", "-P", help=PROFILE_HELP)
    ] = Profile.standard,
    checks: Annotated[
        str | None,
        typer.Option("--checks", "-c", help="Только эти проверки: ID, префиксы или теги."),
    ] = None,
    jobs: Annotated[
        int, typer.Option("--jobs", "-j", min=1, max=10, help="Сколько сайтов проверять сразу.")
    ] = 4,
    out_dir: Annotated[
        Path | None, typer.Option("--out", help="Папка для отчётов (по умолчанию reports/...).")
    ] = None,
    open_report: Annotated[
        bool, typer.Option("--open/--no-open", help="Открыть сводный отчёт в браузере.")
    ] = True,
    browser: Annotated[
        bool,
        typer.Option("--browser", "-b", help="Открывать сайты в браузере (точнее, но дольше)."),
    ] = False,
    pages: Annotated[
        int,
        typer.Option(
            "--pages",
            "-p",
            min=0,
            max=30,
            help="Сколько внутренних страниц проверить помимо главной (0 — только главную).",
        ),
    ] = DEFAULT_PAGES,
    timeout: Annotated[float, typer.Option("--timeout", "-t", min=1.0)] = 10.0,
    refresh: Annotated[bool, typer.Option("--refresh", help="Обновить списки.")] = False,
    brand_name: BrandName = None,
    brand_logo: BrandLogo = None,
    brand_url: BrandUrl = None,
) -> None:
    """Проверить список сайтов: сводная таблица, CSV и отчёт по каждому сайту."""
    brand = _brand(brand_name, brand_logo, brand_url)
    try:
        hosts = read_targets(file)
    except (OSError, SuverenError) as exc:
        raise _fail(f"не удалось прочитать список: {exc}") from exc
    if not hosts:
        raise _fail("в файле нет доменов")
    try:
        plan = make_plan(Profile.quick if quick else profile, checks, browser=browser, pages=pages)
    except SelectionError as exc:
        raise _fail(str(exc)) from exc

    folder = out_dir or Path("reports") / f"batch-{_stamp()}"
    folder.mkdir(parents=True, exist_ok=True)
    console.print(BANNER.format(version=__version__))
    console.print(f"  Проверяю сайтов: [bold]{len(hosts)}[/] · одновременно {jobs}\n")

    results: list[tuple[str, Report | None, str | None]] = []

    async def run_all() -> list[tuple[str, Report | None, str | None]]:
        if "blocklist" in plan.modules:
            async with make_client(30.0) as client:
                await ensure_lists(client, refresh=refresh)

        async def one(host: str) -> tuple[str, Report | None, str | None]:
            try:
                # One stuck site must not hold up the whole list.
                report = await asyncio.wait_for(
                    run_scan(host, timeout=timeout, **plan.kwargs()),  # type: ignore[arg-type]
                    SITE_DEADLINE,
                )
            except (SuverenError, *TIMEOUTS) as exc:
                reason = str(exc) or f"не уложилась в {SITE_DEADLINE // 60} мин"
                console.print(f"  [red]✗[/] {host:<32} [dim]{reason}[/]")
                return host, None, reason
            write_html(report, folder / f"{host}.html", brand)
            write_json(report, folder / f"{host}.json")
            line = Text("  ")
            line.append(f" {report.grade} ", style=GRADE_STYLE[report.grade])
            line.append(f" {host:<32} ")
            line.append_text(score_bar(report.score, report.grade))
            line.append(f" {report.score:>3}", style="bold")
            console.print(line)
            return host, report, None

        return await gather_limited([lambda h=h: one(h) for h in hosts], jobs)

    with _spinner("[dim]Проверка…[/]"):
        results = asyncio.run(run_all())

    reports = [r for _, r, _ in results if r is not None]
    failed = [(h, err) for h, r, err in results if r is None]

    csv_path = folder / "summary.csv"
    with csv_path.open("w", encoding="utf-8-sig", newline="") as fh:
        writer = csv.DictWriter(
            fh, fieldnames=list(batch_row(reports[0]).keys()) if reports else ["domain"]
        )
        writer.writeheader()
        for r in sorted(reports, key=lambda r: r.score):
            writer.writerow(batch_row(r))
    index_path = write_batch_html(reports, failed, folder / "index.html", brand)

    grades = Counter(r.grade for r in reports)
    section(console, "Итого")
    line = Text("  ")
    for g in GRADE_ORDER:
        if grades[g]:
            line.append(f" {g} ", style=GRADE_STYLE[g])
            line.append(f" {grades[g]}   ")
    console.print(line)
    if failed:
        console.print(f"  [red]Не проверены: {len(failed)}[/]")
    console.print(f"\n[bold]Сводка:[/] {index_path}\n[bold]CSV:[/]    {csv_path}")
    if open_report:
        _open(index_path)


# --- diff -----------------------------------------------------------------------------


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
        style = "red" if b_deps[key].get("foreign") else "green"
        console.print(f"  [{style}]+ добавлен[/] {key[0]}: {key[1]}")

    a_checks = {c["title"]: c["status"] for c in a.get("checks", [])}
    for c in b.get("checks", []):
        before = a_checks.get(c["title"])
        if before and before != c["status"]:
            changed = True
            good = c["status"] == "ok"
            style = "green" if good else "red"
            console.print(
                f"  [{style}]{'✓' if good else '✗'} {c['title']}[/]: {before} → {c['status']}"
            )
    if not changed:
        console.print("  [dim]Ничего не изменилось.[/]")


# --- services -------------------------------------------------------------------------


@app.command()
def services(
    search: Annotated[
        str | None, typer.Argument(help="Фильтр по названию, например google.")
    ] = None,
) -> None:
    """Показать базу сервисов, которые умеет распознавать Suveren."""
    items = [s for s in ALL_SERVICES if not search or search.lower() in s.name.lower()]
    foreign = sum(1 for s in items if s.foreign)
    table = Table(box=None, header_style="bold", padding=(0, 2))
    table.add_column("Сервис")
    table.add_column("Страна")
    table.add_column("Как распознаётся", style="dim")
    for s in sorted(items, key=lambda s: (not s.foreign, s.name.lower())):
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
    domestic = len(items) - foreign
    console.print(f"\nВсего: [bold]{len(items)}[/] · иностранных {foreign} · российских {domestic}")


@app.command("checks")
def list_checks(
    query: Annotated[
        str | None,
        typer.Argument(help="ID (SUV-MAIL-003), префикс (SUV-WEB) или тег (mail, law)."),
    ] = None,
) -> None:
    """Показать все проверки: ID, раздел, теги. Их можно выбрать в scan --checks."""
    try:
        ids = select(query) if query else set(BY_ID)
    except SelectionError as exc:
        raise _fail(str(exc)) from exc
    specs = [s for s in CATALOG if s.id in ids]
    if len(specs) == 1:
        s = specs[0]
        console.print(f"[bold]{s.id}[/]  {s.title}")
        console.print(f"Раздел:  {s.group}")
        console.print(f"Модуль:  {s.module}")
        console.print(f"Теги:    {', '.join(s.tags)}")
        console.print(f"\n{s.summary}")
        return
    table = Table(box=None, header_style="bold", padding=(0, 2))
    table.add_column("ID", no_wrap=True)
    table.add_column("Проверка")
    table.add_column("Теги", style="dim")
    group = None
    for s in specs:
        if s.group != group:
            group = s.group
            table.add_row("", Text(group, style="bold"), "")
        table.add_row(s.id, s.title if not s.pattern else s.summary, ", ".join(s.tags))
    console.print(table)
    console.print(
        f"\nВсего: [bold]{len(specs)}[/]. Теги: {', '.join(all_tags())}.\n"
        "Выбрать: [bold]suveren scan сайт.ru --checks mail,SUV-WEB-004[/]"
    )


# --- company --------------------------------------------------------------------------


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
    browser: Annotated[
        bool,
        typer.Option("--browser", "-b", help="Открыть сайт в браузере, если он закрыт от роботов."),
    ] = False,
    refresh: Annotated[
        bool, typer.Option("--refresh", help="Обновить санкционные списки сейчас.")
    ] = False,
    timeout: Annotated[
        float, typer.Option("--timeout", "-t", min=1.0, help="Сетевой таймаут, секунды.")
    ] = 15.0,
    pdf: PdfPath = None,
    brand_name: BrandName = None,
    brand_logo: BrandLogo = None,
    brand_url: BrandUrl = None,
) -> None:
    """Проверить компанию: ЕГРЮЛ, санкционные списки, реестр операторов ПДн."""
    brand = _brand(brand_name, brand_logo, brand_url)
    console.print(BANNER.format(version=__version__))
    console.print(f"  Проверяю [bold]{target}[/]\n")
    try:
        with _spinner(
            "[dim]ЕГРЮЛ, реестры, санкционные списки… "
            "(в первый раз списки скачиваются около минуты)[/]"
        ):
            report = asyncio.run(
                run_company(
                    target,
                    timeout=timeout,
                    sanctions=not no_sanctions,
                    refresh=refresh,
                    browser=browser,
                )
            )
    except SuverenError as exc:
        raise _fail(str(exc)) from exc

    rec = report.egrul
    rows = []
    if rec:
        rows.append(Text(rec.name_full, style="bold"))
        rows.append(Text(f"ИНН {rec.inn or '—'} · ОГРН {rec.ogrn or '—'}", style="dim"))
        if rec.registered:
            rows.append(Text(f"Зарегистрирована {rec.registered:%d.%m.%Y}", style="dim"))
        if rec.head:
            rows.append(Text(rec.head, style="dim"))
    elif report.domain:
        rows.append(Text(f"Сайт {report.domain}, ИНН {report.inn or 'не найден'}"))
    worst = min((c.status for c in report.checks), key=_status_rank, default=Status.UNKNOWN)
    verdict = {
        Status.FAIL: ("ЕСТЬ ПРОБЛЕМЫ", "bold white on red"),
        Status.WARN: ("ЕСТЬ ВОПРОСЫ", "bold black on yellow"),
        Status.OK: ("ВСЁ В ПОРЯДКЕ", "bold black on green"),
        Status.UNKNOWN: ("НЕДОСТАТОЧНО ДАННЫХ", "bold white on grey35"),
    }[worst]
    rows.insert(0, Text(f" {verdict[0]} ", style=verdict[1]))
    rows.insert(1, Text(""))
    console.print(
        Panel(
            Text("\n").join(rows) if rows else Text(report.query),
            title=f"[bold]{report.title}[/]",
            title_align="left",
            padding=(1, 2),
            expand=False,
        )
    )
    section(console, "Результаты")
    print_checks(console, report.checks, verbose=True)

    if report.hits:
        section(console, "Совпадения в санкционных списках")
        table = Table(box=None, header_style="dim", padding=(0, 2), pad_edge=False)
        table.add_column(" Список")
        table.add_column("Запись")
        table.add_column("Как найдено", style="dim")
        for h in report.hits:
            table.add_row(f" {SOURCE_TITLES[h.entry.source]}", h.entry.names[0], h.how_ru)
        console.print(table)
    if report.notes:
        section(console, "Замечания")
        for note in report.notes:
            console.print(Text(f" ! {note}", style="dim"))

    console.print()
    html_path = None
    if not no_report or pdf is not None:
        slug = report.inn or report.ogrn or report.domain or "company"
        html_path = output or Path("reports") / f"company-{slug}-{_stamp()}.html"
    write_company(report, html_path, json_path, brand)
    if html_path is not None:
        if pdf is not None:
            _pdf(html_path, pdf)
        if no_report:
            html_path.unlink(missing_ok=True)  # only needed to print the PDF
        else:
            console.print(f"[bold]Отчёт:[/] {html_path}")
            if open_report:
                _open(html_path)
    if json_path is not None:
        console.print(f"[bold]JSON:[/]  {json_path}")


def _status_rank(status: Status) -> int:
    return {Status.FAIL: 0, Status.WARN: 1, Status.OK: 2, Status.UNKNOWN: 3}[status]


# --- update ---------------------------------------------------------------------------


@app.command()
def update() -> None:
    """Скачать свежие санкционные списки и реестр блокировок (обычно раз в сутки сам)."""

    async def run() -> None:
        async with make_client(30.0) as client:
            with _spinner("[dim]Санкционные списки…[/]"):
                index = await load_index(client, refresh=True)
            for note in index.notes:
                console.print(f"  [yellow]![/] {note}")
            for source in SANCTION_SOURCES:
                count = sum(1 for e in index.entries if e.source == source.key)
                console.print(f"  [green]✓[/] {source.title}: {count} записей")
            with _spinner("[dim]Реестр блокировок…[/]"):
                sizes, notes = await ensure_lists(client, refresh=True)
            for note in notes:
                console.print(f"  [yellow]![/] {note}")
            total = sum(sizes.values()) / 1_048_576
            console.print(f"  [green]✓[/] Реестр блокировок РКН: {total:.1f} МБ")
        console.print(f"\n[dim]Кэш: {cache_dir()}[/]")

    try:
        asyncio.run(run())
    except SuverenError as exc:
        raise _fail(str(exc), code=1) from exc


# --- unknown --------------------------------------------------------------------------


@app.command("unknown")
def unknown_cmd(
    limit: Annotated[int, typer.Option("--limit", "-n", min=1, help="Сколько показать.")] = 30,
    reset: Annotated[bool, typer.Option("--clear", help="Очистить накопленный список.")] = False,
) -> None:
    """Внешние домены, которых нет в базе: с чего начать её пополнение."""
    if reset:
        unknown.clear()
        console.print("[green]✓[/] Список очищен.")
        return
    data = unknown.load()
    if not data:
        console.print(
            "[dim]Пока пусто. Домены копятся при каждой проверке сайтов (только на этом "
            "компьютере, никуда не отправляются).[/]"
        )
        return
    rows = sorted(data.items(), key=lambda item: (-item[1]["count"], item[0]))[:limit]
    table = Table(box=None, header_style="bold", padding=(0, 2))
    table.add_column("Домен")
    table.add_column("Сайтов", justify="right")
    table.add_column("Где встречался", style="dim")
    for domain, entry in rows:
        table.add_row(domain, str(entry["count"]), ", ".join(entry["sites"]))
    console.print(table)
    console.print(
        f"\n[dim]Всего неизвестных доменов: {len(data)}. Чтобы добавить сервис в базу, "
        "откройте issue «Добавить сервис» на GitHub или допишите запись в services.py.[/]"
    )


# --- doctor ---------------------------------------------------------------------------


@app.command()
def doctor(
    timeout: Annotated[float, typer.Option("--timeout", "-t", min=1.0)] = 20.0,
    abroad: Annotated[
        bool,
        typer.Option(
            "--abroad",
            help="Запуск не из России: если ЕГРЮЛ или реестр РКН не отвечают, это не ошибка.",
        ),
    ] = False,
) -> None:
    """Проверить, что все источники данных доступны и отвечают как ожидается."""
    with _spinner("[dim]Проверяю источники данных…[/]"):
        probes = asyncio.run(run_doctor(timeout, abroad=abroad))
    table = Table(box=None, show_header=False, padding=(0, 1))
    table.add_column(no_wrap=True)
    table.add_column(no_wrap=True)
    table.add_column(style="dim")
    table.add_column(justify="right", style="dim")
    for p in probes:
        icon = {True: "[green]✓[/]", False: "[bold red]✗[/]", None: "[yellow]–[/]"}[p.ok]
        table.add_row(f" {icon}", p.name, p.details, f"{p.seconds:.1f} с")
    console.print(table)
    broken = [p for p in probes if p.ok is False]
    if broken:
        console.print(f"\n[bold red]Не работает источников: {len(broken)}.[/]")
        raise typer.Exit(1)
    console.print("\n[green]Все источники работают.[/]")


# --- menu -----------------------------------------------------------------------------


@app.command()
def menu() -> None:
    """Меню для работы без командной строки."""
    run_menu(app, console)


def main_exe() -> None:
    """Entry point of the Windows .exe: a double click opens the menu."""
    if len(sys.argv) == 1:
        run_menu(app, console)
    else:
        app()
