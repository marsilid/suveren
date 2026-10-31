"""Typer's English messages, said in Russian."""

import pytest
from typer.testing import CliRunner

from suveren.cli import app
from suveren.clirus import translate


@pytest.mark.parametrize(
    ("english", "russian"),
    [
        ("No such option: --bogus", "Нет такого параметра: --bogus."),
        ("No such option: --jsno Did you mean --json?",
         "Нет такого параметра: --jsno. Может быть, --json?"),
        ("Missing argument 'TARGET'.", "Не указан аргумент TARGET."),
        ("Option '--json' requires an argument.", "Параметру --json нужно значение."),
        ("Got unexpected extra argument (b.ru)", "Лишние аргументы: b.ru."),
        ("Invalid value for '--pages': 'x' is not a valid integer.",
         "Недопустимое значение для '--pages': «x» — не целое число."),
        ("Invalid value for '--dns': 'zz' is not one of 'auto', 'ru'.",
         "Недопустимое значение для '--dns': «zz» — не из списка: 'auto', 'ru'."),
        ("Something new and unknown", "Something new and unknown"),
    ],
)  # fmt: skip
def test_translate(english, russian):
    assert translate(english) == russian


def test_cli_errors_and_help_are_russian():
    runner = CliRunner()
    bad = runner.invoke(app, ["scan", "example.ru", "--bogus"])
    assert bad.exit_code != 0 and "Нет такого параметра" in bad.output
    helped = runner.invoke(app, ["scan", "--help"])
    assert "Что проверять" in helped.output and "Отчёты" in helped.output
    assert "Параметры" in helped.output
