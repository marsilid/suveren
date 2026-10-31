"""Text from a site never reaches the terminal with control sequences or Rich markup."""

import io

from rich.console import Console

from suveren.checks import Check, Evidence, Status
from suveren.models import Category, Dependency, Report
from suveren.utils import clean_text
from suveren.view import esc, print_checks, print_scan

OSC52 = "\x1b]52;c;cm0gLXJmIH4=\x07"  # "put `rm -rf ~` on the clipboard"
BIDI = "‮ur.live‬"


def test_clean_text_drops_c0_c1_and_bidi_but_keeps_lines_and_tabs():
    dirty = f"Согласие{OSC52} на\x00 обработку\x9b31m\r\n\tданных {BIDI} ⁦x⁩\x7f"
    assert clean_text(dirty) == "Согласие]52;c;cm0gLXJmIH4= на обработку31m\n\tданных ur.live x"
    assert clean_text("обычный текст «как есть» — 152-ФЗ") == "обычный текст «как есть» — 152-ФЗ"


def test_check_and_evidence_are_cleaned_on_creation():
    check = Check(
        "Персональные данные (152-ФЗ)",
        "Политика обработки персональных данных",
        Status.WARN,
        f"Цитата из политики: «{OSC52}текст»",
        f"Сделайте{BIDI}",
    )
    assert "\x1b" not in check.details and "\x07" not in check.details
    assert "‮" not in check.recommendation
    ev = Evidence("html", f"страница{OSC52}", f"<p>{OSC52}</p>")
    assert "\x1b" not in ev.what and "\x1b" not in ev.value


def _render(fn, *args) -> str:
    out = io.StringIO()
    console = Console(file=out, force_terminal=True, width=200, color_system=None)
    fn(console, *args)
    return out.getvalue()


def test_terminal_shows_markup_from_the_site_as_text():
    check = Check(
        "Персональные данные (152-ФЗ)",
        "Политика обработки персональных данных",
        Status.OK,
        "Найдена: [link=https://evil.example]политика[/link] [bold red]x[/]",
    )
    text = _render(print_checks, [check])
    assert "[link=https://evil.example]" in text and "[bold red]x[/]" in text
    assert "\x1b]8;" not in text  # no hyperlink escape was made from it


def test_dependency_evidence_and_notes_are_safe():
    report = Report(target="example.ru")
    report.dependencies = [
        Dependency(
            Category.ANALYTICS, "Google Analytics", "US", f"https://x.ru/[red]a[/]{OSC52}.js"
        )
    ]
    report.notes = [f"заметка {OSC52}"]
    out = io.StringIO()
    print_scan(Console(file=out, force_terminal=True, width=200), report, details=True)
    text = out.getvalue()
    assert "[red]a[/]" in text and "\x1b]52" not in text


def test_esc_for_markup_strings():
    assert esc("[bold]x[/] \x1b[31m") == "\\[bold]x\\[/] [31m"
