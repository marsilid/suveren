"""tools/report_lint.py: the wording slips real reports had, and what must not be flagged."""

import importlib.util
import json
import sys
import zipfile
from pathlib import Path

TOOLS = Path(__file__).parent.parent / "tools"
spec = importlib.util.spec_from_file_location("report_lint", TOOLS / "report_lint.py")
report_lint = importlib.util.module_from_spec(spec)
sys.modules["report_lint"] = report_lint
spec.loader.exec_module(report_lint)
lint_text = report_lint.lint_text


def rules(text, *, own=False):
    return [s.rule for s in lint_text(text, "t", own=own)]


def test_the_slips_of_2026_11_18_are_found():
    assert rules("Делегирований нет (ailaba.ru и 1 поддоменов).") == ["one-with-plural"]
    assert rules("не ответил: a.ru, b.ru, auth-portal.sberbank.ru….") == ["ellipsis-dot"]
    assert rules("не удалось проверить 26 из 44, поэтому оценка не выше b;") == ["lowercase-grade"]


def test_right_russian_is_not_flagged():
    for text in (
        "ailaba.ru и 1 поддомен. Среди 21 поддомена. Из 11 сайтов, 111 доменов, 2 сайтов.",
        "Проверены первые 300 по алфавиту… Ещё 110 не успели проверить.",
        "Оценка не выше B. Общая оценка C, независимость A-.",
        "Permissions-Policy: camera=(), microphone=(), geolocation=().",
        "Многоточие... тоже бывает.",
        # Site data from the 1000-site run: field names, a cookie attribute, a path.
        "Поля: filter[sex][] (checkbox), phone[] (tel).",
        "Нужно Secure (обязателен при SameSite=None).",
        "Скрипт https://tube.example.com/js/lib/../..//js/lib/x.js подгружен.",
    ):
        assert rules(text, own=True) == [], text


def test_leftovers_and_spacing_in_our_own_texts():
    assert rules("Сервис: None.") == ["leftover"]
    assert rules("Найдено {count} форм.") == ["leftover"]
    assert rules("Сайт не не ответил.") == ["doubled-word"]
    assert rules("Пусто ( ) здесь.") == ["empty-brackets"]
    assert rules("Сайт ответил , но поздно.", own=True) == ["space-before-punctuation"]
    assert rules("Сайт  ответил.", own=True) == ["double-space"]
    # Rendered pages collapse spacing, so only our short texts get those two rules.
    assert rules("Сайт  ответил , но поздно.") == []


def test_quotes_from_a_site_are_its_own_business():
    assert rules("В политике: «согласие  на на обработку , None».", own=True) == []
    assert rules('Кнопка "Отправить  ( )" без согласия.', own=True) == []
    # netology.ru's own SPF record has extra spaces; the report shows it as it is.
    spf = "Запись: v=spf1 include:_spf.yandex.net   include:x.ru  ~all. DNS-запросов: 10."
    assert rules(spf, own=True) == []
    assert rules("Запись есть.  А тут  наш пробел.", own=True) == ["double-space"] * 2


def test_every_format_is_read(tmp_path):
    slip = "ailaba.ru и 1 поддоменов"
    (tmp_path / "a.json").write_text(
        json.dumps({"checks": [{"id": "SUV-SUB-004", "details": slip}], "notes": []}),
        encoding="utf-8",
    )
    (tmp_path / "a.html").write_text(f"<p>{slip}</p><script>1 поддоменов</script>", "utf-8")
    (tmp_path / "t.txt").write_text(slip, encoding="utf-8")
    with zipfile.ZipFile(tmp_path / "a.docx", "w") as z:
        z.writestr("word/document.xml", f"<w:p><w:r><w:t>{slip}</w:t></w:r></w:p>")
    (tmp_path / "summary.json").write_text("[1, 2]", encoding="utf-8")  # not a report
    slips = report_lint.lint([tmp_path])
    assert sorted(s.where for s in slips) == ["a.docx", "a.html", "a.json SUV-SUB-004", "t.txt"]
    assert report_lint.main([str(tmp_path)]) == 1
    assert report_lint.main([str(tmp_path / "summary.json")]) == 0
