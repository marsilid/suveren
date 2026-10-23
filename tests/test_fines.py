from rich.console import Console

from suveren.checks import GROUP_152, GROUP_LAWS, Check, Status
from suveren.fines import DISCLAIMER, estimate, rub, span
from suveren.models import Report
from suveren.report import render_html
from suveren.view import fines_line


def check(title, status, group=GROUP_152):
    return Check(group, title, status, "details")


VIOLATIONS = [
    check("Политика обработки персональных данных", Status.FAIL),  # ч. 3: до 60 тыс.
    check("Хранение данных в России", Status.FAIL),  # ч. 8: до 6 млн
    check("Вход через иностранные сервисы", Status.FAIL, GROUP_LAWS),  # 13.55: до 700 тыс.
    check("Согласие на обработку в формах", Status.WARN),  # possible, ч. 1: not counted
    check("Реестр операторов персональных данных", Status.WARN),  # possible, ч. 10
]


def test_total_counts_problems_and_lists_warnings():
    fines = estimate(VIOLATIONS)
    assert [i.fine.article for i in fines.counted] == [
        "КоАП, ст. 13.11 ч. 3",
        "КоАП, ст. 13.11 ч. 8",
        "КоАП, ст. 13.55",
    ]
    # Missing consent may be lawful (a request to sign a contract): listed, not counted.
    assert [i.fine.article for i in fines.listed] == [
        "КоАП, ст. 13.11 ч. 1",
        "КоАП, ст. 13.11 ч. 10",
    ]
    assert fines.total("legal") == 60_000 + 6_000_000 + 700_000
    # A sole trader: named in ч. 3, as a legal entity in ч. 8 and ч. 10 (note 1 to
    # ст. 13.11), otherwise as an official (note to ст. 2.4).
    assert fines.total("sole_trader") == 20_000 + 6_000_000 + 50_000
    assert fines.listed[1].fine.sole_trader == (100_000, 300_000)
    by_title = {i.title: i for i in fines.items}
    assert (
        by_title["Согласие на обработку в формах"].note == "если для этой обработки нужно согласие"
    )
    assert by_title["Политика обработки персональных данных"].note is None


def test_ok_unknown_and_warnings_without_a_rule_add_nothing():
    checks = [
        check("Политика обработки персональных данных", Status.UNKNOWN),
        check("Хранение данных в России", Status.WARN),
        check("Уведомление о cookies", Status.WARN),
        check("Вход через иностранные сервисы", Status.OK, GROUP_LAWS),
    ]
    fines = estimate(checks)
    assert not fines
    assert fines.total() == 0


def test_one_article_is_counted_once():
    twice = [check("Хранение данных в России", Status.FAIL)] * 2
    assert estimate(twice).total() == 6_000_000


def test_repeat_offence_is_shown_where_the_article_has_it():
    fines = estimate(VIOLATIONS)
    by_article = {i.fine.article: i.fine for i in fines.items}
    assert by_article["КоАП, ст. 13.11 ч. 8"].repeat_legal == (6_000_000, 18_000_000)
    assert by_article["КоАП, ст. 13.55"].repeat_legal is None


def test_rub_format():
    assert rub(60_000) == "60 тыс. ₽"
    assert rub(1_500_000) == "1,5 млн ₽"
    assert rub(6_000_000) == "6 млн ₽"
    assert rub(1_500) == "1,5 тыс. ₽"
    assert span((30_000, 60_000)) == "30 тыс. – 60 тыс. ₽"


def test_json_has_total_items_and_disclaimer():
    report = Report("example.ru", checks=list(VIOLATIONS))
    data = report.to_dict()["fines"]
    assert data["total_max_legal_entity"] == 6_760_000
    assert data["items"][-1]["counted"] is False
    assert len(data["items"]) == 5
    assert data["items"][0]["url"].startswith("https://www.consultant.ru/")
    assert data["disclaimer"] == DISCLAIMER
    assert Report("example.ru").to_dict()["fines"] is None


def test_html_block_above_personal_data_section():
    html = render_html(Report("example.ru", checks=list(VIOLATIONS)))
    assert "Потенциальные штрафы: до 6,76 млн ₽ для юрлица" in html
    assert "«внимание»: не входит в сумму" in html
    assert "если для этой обработки нужно согласие" in html
    assert "не юридическое заключение" in html
    assert html.index("Потенциальные штрафы") > html.index("Персональные данные (152-ФЗ)")


def test_terminal_line():
    console = Console(record=True, width=200)
    console.print(fines_line(estimate(VIOLATIONS)))
    out = console.export_text()
    assert "до 6,76 млн ₽ для юрлица" in out
    assert "статей: 3; ещё 2 по предупреждениям не в сумме" in out
    assert "не юридическое заключение" in out
