"""Terminal presentation of scan and company reports (rich).

One quiet palette: colour only where it means something (problem, warning, passed,
not checked); everything secondary — timings, paths, check IDs — is dim. No ASCII art.
The console must be created with ``highlight=False``: rich's automatic highlighting
colours every number ("152-ФЗ", dates in paths) and makes the output look random.
"""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path

from rich import box
from rich.console import Console, Group
from rich.padding import Padding
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table
from rich.text import Text

from suveren.advice import overall_grade, overall_score, priorities
from suveren.checks import Check, Status
from suveren.fines import FineEstimate, rub
from suveren.models import Report, Severity
from suveren.utils import country_name

ACCENT = "#5fb3b3"
DIM = "grey50"
OK, WARN, FAIL, UNKNOWN = "#7fb069", "#e6b450", "#e5534b", "grey58"

SEVERITY_STYLE = {
    Severity.HIGH: f"bold {FAIL}",
    Severity.MEDIUM: WARN,
    Severity.LOW: ACCENT,
    Severity.INFO: DIM,
}
STATUS_STYLE = {
    Status.OK: OK,
    Status.WARN: WARN,
    Status.FAIL: f"bold {FAIL}",
    Status.UNKNOWN: UNKNOWN,
}
STATUS_WORDS = {
    Status.FAIL: ("проблема", "проблемы", "проблем"),
    Status.WARN: ("внимание", "внимание", "внимание"),
    Status.OK: ("в порядке", "в порядке", "в порядке"),
    Status.UNKNOWN: ("не проверено", "не проверено", "не проверено"),
}
# Explicit colours: named ones like "black" follow the terminal theme and can vanish.
GRADE_STYLE = {
    "A": "bold #102a12 on #7fb069",
    "B": "bold #1f2d05 on #a9c46a",
    "C": "bold #2b2100 on #e6b450",
    "D": "bold #ffffff on #d9822b",
    "F": "bold #ffffff on #e5534b",
}
BAR_STYLE = {"A": OK, "B": "#a9c46a", "C": WARN, "D": "#d9822b", "F": FAIL}
COUNTRY_COLORS = (WARN, "#d9822b", ACCENT, "#b48ead", "#81a1c1", FAIL)
BAR_WIDTH = 30
COUNTRY_BAR = 60
TOP_ACTIONS = 3


def header(version: str, target: str | None = None, meta: str = "") -> Text:
    """`suveren 1.1.0   site.ru   profile · browser` — the whole banner."""
    line = Text("suveren", style=f"bold {ACCENT}")
    line.append(f" {version}", style=DIM)
    if target:
        line.append(f"   {target}", style="bold")
    if meta:
        line.append(f"   {meta}", style=DIM)
    return line


def _plural(n: int, forms: tuple[str, str, str]) -> str:
    if n % 10 == 1 and n % 100 != 11:
        return forms[0]
    if 2 <= n % 10 <= 4 and not 12 <= n % 100 <= 14:
        return forms[1]
    return forms[2]


def score_bar(score: int, grade: str) -> Text:
    filled = round(BAR_WIDTH * score / 100)
    bar = Text("━" * filled, style=BAR_STYLE[grade])
    bar.append("━" * (BAR_WIDTH - filled), style="grey23")
    return bar


def country_bar(report: Report, width: int = COUNTRY_BAR, limit: int = 5) -> Group | Text:
    countries = report.countries
    if not countries:
        return Text("страны не определены", style=DIM)
    colors = iter(COUNTRY_COLORS)
    bar, legend = Text(), Text()
    rest = sum(share for _, share in countries[limit:])
    for code, share in countries[:limit]:
        style = OK if code == "RU" else next(colors, DIM)
        bar.append("━" * max(1, round(width * share / 100)), style=style)
        legend.append(f"{country_name(code)} {share}%   ", style=style)
    if rest:
        bar.append("━" * max(1, round(width * rest / 100)), style=DIM)
        legend.append(f"другие {rest}%", style=DIM)
    return Group(bar, legend)


def country_line(report: Report, limit: int = 5) -> Text:
    """Countries in one line (used where a bar does not fit)."""
    line = Text()
    colors = iter(COUNTRY_COLORS)
    for code, share in report.countries[:limit]:
        style = OK if code == "RU" else next(colors, DIM)
        line.append(f"{country_name(code)} {share}%   ", style=style)
    return line if report.countries else Text("страны не определены", style=DIM)


def check_counts(checks: Iterable[Check], *, words: bool = False) -> Text:
    checks = list(checks)
    text = Text()
    for status in (Status.FAIL, Status.WARN, Status.OK, Status.UNKNOWN):
        n = sum(1 for c in checks if c.status is status)
        if n:
            label = f" {_plural(n, STATUS_WORDS[status])}" if words else ""
            text.append(f"{status.icon} {n}{label}   ", style=STATUS_STYLE[status])
    return text


def summary_panel(report: Report) -> Panel:
    grade, score = overall_grade(report), overall_score(report)
    top = Text.assemble(
        (f" {grade} ", GRADE_STYLE[grade]),
        ("  Общая оценка ", "bold"),
        (f"{score}", "bold"),
        ("/100", DIM),
        ("     ", ""),
        (f" {report.grade} ", GRADE_STYLE[report.grade]),
        ("  Независимость ", "bold"),
        (f"{report.score}", "bold"),
        ("/100", DIM),
    )
    deps = Text.assemble(
        ("иностранных сервисов ", DIM),
        (str(report.foreign_count), "bold"),
        (" · российских ", DIM),
        (str(report.domestic_count), "bold"),
    )
    rows: list[object] = [top, Text(""), deps, country_bar(report)]
    if report.checks:
        rows += [Text(""), check_counts(report.checks, words=True)]
    extra = Text()
    fines = report.fines
    if fines and fines.counted:
        extra.append("штрафы ", style=DIM)
        extra.append(f"до {rub(fines.total('legal'))}", style="bold")
        extra.append("    ")
    attacks = [c for c in report.checks if c.id.startswith("SUV-ATK-")]
    if attacks:
        extra.append("сценарии атак ", style=DIM)
        extra.append(str(len(attacks)), style="bold")
        extra.append("    ")
    cut = next((c for c in report.checks if c.id == "SUV-CUT-002"), None)
    if cut is not None and cut.status in (Status.FAIL, Status.WARN):
        extra.append("без иностранных сервисов ", style=DIM)
        extra.append("сломается часть страницы", style="bold")
    if extra:
        rows.append(extra)
    return Panel(Group(*rows), box=box.ROUNDED, border_style="grey35", padding=(1, 2))


def fines_line(fines: FineEstimate) -> Text:
    """One line with the total; details are in the HTML report."""
    text = Text("₽  ", style=f"bold {FAIL}" if fines.counted else DIM)
    if fines.counted:
        text.append(f"Потенциальные штрафы: до {rub(fines.total('legal'))} для юрлица", "bold")
        text.append(f" (статей: {len(fines.counted)}", DIM)
        if fines.listed:
            text.append(f"; ещё {len(fines.listed)} по предупреждениям не в сумме", DIM)
        text.append(")", DIM)
    else:
        text.append(
            f"Штраф возможен по {len(fines.listed)} предупреждениям, проблем со штрафом нет"
        )
    text.append(". Оценка максимального риска, не юридическое заключение.", DIM)
    return text


def section(console: Console, title: str, counts: Text | None = None) -> None:
    """A thin rule with the section's name and, if given, its status counts."""
    console.print()
    label = Text(f" {title} ", style="bold")
    if counts is not None and counts.plain:
        label.append(" ")
        label.append_text(counts)
    console.print(Rule(label, align="left", style="grey35", characters="─"))


def print_scan(console: Console, report: Report, *, details: bool = False) -> None:
    console.print(summary_panel(report))

    findings = report.sorted_findings()
    section(console, "Иностранные зависимости")
    if not findings:
        console.print(Text("  ✓ не найдены", style=OK))
    else:
        table = Table(box=None, show_header=False, padding=(0, 1), pad_edge=False)
        table.add_column(no_wrap=True, width=3)
        table.add_column(no_wrap=True, style=DIM)
        table.add_column()
        for f in findings:
            names = ", ".join(
                f"{d.service} ({d.country_ru})"
                for d in report.dependencies
                if d.category is f.category and d.foreign
            )
            table.add_row(Text("  ●", style=SEVERITY_STYLE[f.severity]), f.category.title, names)
        console.print(table)

    fines = report.fines
    for group, items in report.check_groups:
        section(console, group, check_counts(items))
        print_checks(console, items)
        if fines and group.startswith("Персональные"):
            console.print(Padding(fines_line(fines), (0, 0, 0, 2)))

    if details:
        section(console, "Все найденные сервисы")
        table = Table(box=None, header_style=DIM, padding=(0, 1), pad_edge=False)
        table.add_column(" ")
        table.add_column("Категория", style=DIM)
        table.add_column("Сервис")
        table.add_column("Страна")
        table.add_column("Где найдено", style=DIM)
        for d in report.dependencies:
            if d.foreign:
                mark = Text("  !", style=SEVERITY_STYLE[d.severity or Severity.LOW])
            elif d.foreign is False:
                mark = Text("  ✓", style=OK)
            else:
                mark = Text("  ?", style=DIM)
            table.add_row(mark, d.category.title, d.service, d.country_ru, d.evidence)
        console.print(table)

    if report.notes:
        section(console, "Замечания")
        for note in report.notes:
            console.print(Padding(Text(note, style=DIM), (0, 2, 0, 2)))


def print_checks(console: Console, checks: list[Check], *, verbose: bool = False) -> None:
    table = Table(box=None, show_header=False, padding=(0, 1), pad_edge=False, expand=True)
    table.add_column(no_wrap=True, width=3)
    table.add_column(ratio=1)
    table.add_column(justify="right", no_wrap=True, style="grey39")
    for c in checks:
        text = Text()
        if c.status is Status.OK:
            text.append(c.title)
            if c.details:
                text.append(f"\n{c.details}", style=DIM)
        else:
            text.append(c.title, style="bold" if c.status is not Status.UNKNOWN else "")
            if c.details:
                text.append(f"\n{c.details}", style=DIM if c.status is Status.UNKNOWN else "")
            if c.recommendation and c.status in (Status.FAIL, Status.WARN) and verbose:
                text.append(f"\n→ {c.recommendation}", style=DIM)
        table.add_row(Text(f"  {c.status.icon}", style=STATUS_STYLE[c.status]), text, c.id)
    console.print(table)


def print_footer(
    console: Console, report: Report | None, files: list[tuple[str, Path | str]]
) -> None:
    """Where the files are and what to do first: the last thing the eye lands on."""
    console.print()
    console.print(Rule(style="grey35", characters="─"))
    table = Table(box=None, show_header=False, padding=(0, 1), pad_edge=False)
    table.add_column(style=DIM, width=7)
    table.add_column()
    for label, path in files:
        table.add_row(label, str(path))
    if files:
        console.print(Padding(table, (0, 0, 0, 2)))
    actions = priorities(report)[:TOP_ACTIONS] if report is not None else []
    if actions:
        console.print()
        console.print(Text("  Что сделать первым", style="bold"))
        todo = Table(box=None, show_header=False, padding=(0, 1), pad_edge=False)
        todo.add_column(width=4, justify="right", no_wrap=True)
        todo.add_column(ratio=1)
        for i, a in enumerate(actions, 1):
            body = Text(a.action)
            body.append(f"\n{a.reason}", style=DIM)
            todo.add_row(Text(f"{i}", style=SEVERITY_STYLE[a.severity]), body)
        console.print(todo)
