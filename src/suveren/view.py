"""Terminal presentation of scan and company reports (rich)."""

from __future__ import annotations

from rich.console import Console, Group
from rich.padding import Padding
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from suveren.advice import priorities
from suveren.checks import Check, Status
from suveren.models import Report, Severity
from suveren.utils import country_name

BANNER = r"""[bold green]
  ___
 / __|_  ___ _____ _ _ ___ _ _
 \__ \ || \ V / -_) '_/ -_) ' \
 |___/\_,_|\_/\___|_| \___|_||_|[/]  [dim]v{version} · аудит сайта и компании для РФ[/]
"""

SEVERITY_STYLE = {
    Severity.HIGH: "bold red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}
STATUS_STYLE = {
    Status.OK: "green",
    Status.WARN: "yellow",
    Status.FAIL: "bold red",
    Status.UNKNOWN: "dim",
}
# Explicit colours: named ones like "black" follow the terminal theme and can vanish.
GRADE_STYLE = {
    "A": "bold #102a12 on #40c057",
    "B": "bold #1f2d05 on #94d82d",
    "C": "bold #2b2100 on #fab005",
    "D": "bold #ffffff on #e8590c",
    "F": "bold #ffffff on #e03131",
}
BAR_STYLE = {"A": "green", "B": "bright_green", "C": "yellow", "D": "dark_orange3", "F": "red"}
COUNTRY_COLORS = ("blue", "magenta", "dark_orange3", "cyan", "yellow", "bright_magenta")
BAR_WIDTH = 30
TOP_ACTIONS = 3


def score_bar(score: int, grade: str) -> Text:
    filled = round(BAR_WIDTH * score / 100)
    bar = Text("█" * filled, style=BAR_STYLE[grade])
    bar.append("░" * (BAR_WIDTH - filled), style="grey30")
    return bar


def country_line(report: Report, limit: int = 5) -> Text:
    line = Text()
    countries = report.countries
    colors = iter(COUNTRY_COLORS)
    shown = countries[:limit]
    for code, share in shown:
        style = "green" if code == "RU" else next(colors, "white")
        line.append("■ ", style=style)
        line.append(f"{country_name(code)} {share}%   ")
    rest = sum(share for _, share in countries[limit:])
    if rest:
        line.append("■ ", style="grey50")
        line.append(f"другие {rest}%")
    return line if countries else Text("страны не определены", style="dim")


def check_counts(checks: list[Check]) -> Text:
    text = Text()
    for status in (Status.FAIL, Status.WARN, Status.OK, Status.UNKNOWN):
        n = sum(1 for c in checks if c.status is status)
        if n:
            text.append(f"{status.icon} {n}  ", style=STATUS_STYLE[status])
    return text


def summary_panel(report: Report) -> Panel:
    grade = Text(f"  {report.grade}  ", style=GRADE_STYLE[report.grade])
    head = Text.assemble(
        grade,
        "   ",
        ("Независимость ", "bold"),
        (f"{report.score}", "bold"),
        ("/100   ", "dim"),
        score_bar(report.score, report.grade),
    )
    rows: list[Text] = [
        head,
        Text(""),
        Text.assemble(
            ("Иностранных сервисов ", "dim"),
            (str(report.foreign_count), "bold"),
            ("   российских ", "dim"),
            (str(report.domestic_count), "bold"),
        ),
        country_line(report),
    ]
    by_group: dict[str, list[Check]] = {}
    for c in report.checks:
        by_group.setdefault(c.group, []).append(c)
    if by_group:
        rows.append(Text(""))
        for group, items in by_group.items():
            rows.append(Text.assemble((f"{group:<30}", "dim"), check_counts(items)))
    return Panel(
        Group(*rows),
        title=f"[bold]{report.target}[/]",
        title_align="left",
        subtitle=f"[dim]{report.duration:.1f} с[/]",
        subtitle_align="right",
        padding=(1, 2),
        expand=False,
    )


def section(console: Console, title: str) -> None:
    console.print()
    console.print(Text(title.upper(), style="bold"))


def print_scan(console: Console, report: Report, *, details: bool = False) -> None:
    console.print(summary_panel(report))

    actions = priorities(report)
    if actions:
        section(console, "Что сделать в первую очередь")
        table = Table(box=None, show_header=False, padding=(0, 1), pad_edge=False)
        table.add_column(justify="right", no_wrap=True)
        table.add_column()
        for i, a in enumerate(actions[:TOP_ACTIONS], 1):
            text = Text(a.action)
            text.append(f"\n{a.reason}", style="dim")
            table.add_row(Text(f" {i}", style=SEVERITY_STYLE[a.severity]), text)
        console.print(table)
        if len(actions) > TOP_ACTIONS:
            console.print(
                Text(f"   и ещё {len(actions) - TOP_ACTIONS} в отчёте", style="dim italic")
            )

    findings = report.sorted_findings()
    section(console, "Иностранные зависимости")
    if not findings:
        console.print(Text(" ✓ не найдены", style="green"))
    else:
        table = Table(box=None, show_header=False, padding=(0, 1), pad_edge=False)
        table.add_column(no_wrap=True)
        table.add_column(no_wrap=True, style="dim")
        table.add_column()
        for f in findings:
            names = ", ".join(
                f"{d.service} ({d.country_ru})"
                for d in report.dependencies
                if d.category is f.category and d.foreign
            )
            table.add_row(
                Text(f" ● {f.severity.ru}", style=SEVERITY_STYLE[f.severity]),
                f.category.title,
                names,
            )
        console.print(table)

    for group, items in report.check_groups:
        section(console, group)
        print_checks(console, items)

    if details:
        section(console, "Все найденные сервисы")
        table = Table(box=None, header_style="dim", padding=(0, 1), pad_edge=False)
        table.add_column(" ")
        table.add_column("Категория", style="dim")
        table.add_column("Сервис")
        table.add_column("Страна")
        table.add_column("Где найдено", style="dim")
        for d in report.dependencies:
            if d.foreign:
                mark = Text(" !", style=SEVERITY_STYLE[d.severity or Severity.LOW])
            elif d.foreign is False:
                mark = Text(" ✓", style="green")
            else:
                mark = Text(" ?", style="dim")
            table.add_row(mark, d.category.title, d.service, d.country_ru, d.evidence)
        console.print(table)
    else:
        console.print()
        console.print(
            Text("Полный список сервисов — в HTML-отчёте или с параметром --details.", "dim")
        )

    if report.notes:
        section(console, "Замечания")
        for note in report.notes:
            console.print(Padding(Text(f"! {note}", style="dim"), (0, 0, 0, 1)))


def print_checks(console: Console, checks: list[Check], *, verbose: bool = False) -> None:
    table = Table(box=None, show_header=False, padding=(0, 1), pad_edge=False)
    table.add_column(no_wrap=True)
    table.add_column()
    for c in checks:
        text = Text()
        if c.status is Status.OK:
            # Passed checks take one quiet line.
            text.append(c.title)
            if c.details:
                text.append(f" — {c.details}", style="dim")
        else:
            text.append(c.title, style="bold" if c.status is not Status.UNKNOWN else "")
            if c.details:
                text.append(f"\n{c.details}", style="dim" if c.status is Status.UNKNOWN else "")
            if c.recommendation and c.status in (Status.FAIL, Status.WARN) and verbose:
                text.append(f"\n→ {c.recommendation}", style="dim")
        table.add_row(Text(f" {c.status.icon}", style=STATUS_STYLE[c.status]), text)
    console.print(table)
