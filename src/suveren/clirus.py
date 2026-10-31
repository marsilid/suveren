"""Command-line messages in Russian: the panel titles of `--help` and the errors that
Typer (its built-in Click) writes in English ("No such option", "Missing argument").

Typer has no translation hook, so the English text is translated by patterns where it
is shown. A message without a pattern stays in English rather than being lost.
"""

from __future__ import annotations

import re
from typing import Any

PANEL_TITLES = {
    "ERRORS_PANEL_TITLE": "Ошибка",
    "OPTIONS_PANEL_TITLE": "Параметры",
    "ARGUMENTS_PANEL_TITLE": "Аргументы",
    "COMMANDS_PANEL_TITLE": "Команды",
    "ABORTED_TEXT": "Прервано.",
    "DEFAULT_STRING": "[по умолчанию: {}]",
    "REQUIRED_LONG_STRING": "[обязательно]",
    "ENVVAR_STRING": "[переменная окружения: {}]",
    "DEPRECATED_STRING": "(устарело) ",
    "RICH_HELP": "Справка: [blue]'{command_path} {help_option}'[/]",
}

# (English pattern, Russian replacement); applied in turn to the whole message.
MESSAGES: tuple[tuple[re.Pattern[str], str], ...] = tuple(
    (re.compile(p), r)
    for p, r in (
        (r"No such option: (\S+)", r"Нет такого параметра: \1."),
        (r"\(Possible options: ([^)]*)\)", r"(Подходящие: \1)"),
        (r"Did you mean (\S+?)\?", r"Может быть, \1?"),
        (r"No such command '([^']*)'\.", r"Нет такой команды: \1."),
        (r"Missing argument '([^']*)'\.", r"Не указан аргумент \1."),
        (r"Missing option '([^']*)'\.", r"Не указан параметр \1."),
        (r"Missing parameter: (\S+)", r"Не указан параметр \1."),
        (r"Option '([^']*)' requires an argument\.", r"Параметру \1 нужно значение."),
        (r"Option '([^']*)' requires (\d+) arguments\.", r"Параметру \1 нужно значений: \2."),
        (r"Got unexpected extra arguments? \(([^)]*)\)", r"Лишние аргументы: \1."),
        (r"Invalid value for ([^:]+): ", r"Недопустимое значение для \1: "),
        (r"Invalid value: ", r"Недопустимое значение: "),
        (r"'([^']*)' is not one of (.+)\.", r"«\1» — не из списка: \2."),
        (r"'([^']*)' is not a valid integer( range)?\.", r"«\1» — не целое число."),
        (r"'([^']*)' is not a valid float( range)?\.", r"«\1» — не число."),
        (r"'([^']*)' is not a valid boolean\.?", r"«\1» — не «да» или «нет»."),
        (r"File '([^']*)' does not exist\.", r"Файла «\1» нет."),
        (r"Path '([^']*)' does not exist\.", r"Пути «\1» нет."),
        (r"Could not open file '([^']*)': ", r"Не удалось открыть файл «\1»: "),
    )
)


def translate(text: str) -> str:
    for pattern, russian in MESSAGES:
        text = pattern.sub(russian, text)
    return text


def apply() -> None:
    """Patch Typer's help titles and error output; quiet when its internals moved."""
    try:
        from typer import rich_utils
    except ImportError:  # pragma: no cover - typer is a dependency
        return
    for name, value in PANEL_TITLES.items():
        if hasattr(rich_utils, name):
            setattr(rich_utils, name, value)
    original = getattr(rich_utils, "rich_format_error", None)
    if original is None or getattr(original, "suveren_ru", False):
        return

    def rich_format_error(self: Any) -> None:
        english = self.format_message

        def russian() -> str:
            return translate(english())

        self.format_message = russian
        original(self)

    rich_format_error.suveren_ru = True  # type: ignore[attr-defined]
    rich_utils.rich_format_error = rich_format_error
