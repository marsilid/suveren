from rich.console import Console

from suveren.checks import GROUP_152, GROUP_LAWS, Check, Status
from suveren.fines import DISCLAIMER, estimate, rub, span
from suveren.models import Report
from suveren.report import render_html
from suveren.view import fines_line


def check(title, status, group=GROUP_152, details="details"):
    return Check(group, title, status, details)


VIOLATIONS = [
    check("Политика обработки персональных данных", Status.FAIL),  # ч. 3: до 60 тыс.
    check("Хранение данных в России", Status.FAIL),  # ч. 8: до 6 млн
    check("Вход через иностранные сервисы", Status.FAIL, GROUP_LAWS),  # 13.55: до 700 тыс.
    # possible, ч. 1: not counted
    check("Согласие на обработку в формах", Status.WARN, details="не найдено согласия на …"),
    check("Реестр операторов персональных данных", Status.WARN),  # possible, ч. 10
]


def test_total_counts_problems_and_lists_warnings():
    fines = estimate(VIOLATIONS)
    assert [i.fine.article for i in fines.counted] == ["КоАП, ст. 13.11 ч. 3"]
    # Missing consent may be lawful (a request to sign a contract): listed, not counted.
    # A foreign server fines only if the leads are stored there, foreign sign-in only a
    # Russian owner: conditional, listed, not counted (review of 1.1.2).
    assert [i.fine.article for i in fines.listed] == [
        "КоАП, ст. 13.11 ч. 8",
        "КоАП, ст. 13.55",
        "КоАП, ст. 13.11 ч. 1",
        "КоАП, ст. 13.11 ч. 10",
    ]
    assert fines.total("legal") == 60_000
    # A sole trader: named in ч. 3 (ст. 13.11); as a legal entity in ч. 8 and ч. 10
    # (note 1 to ст. 13.11).
    assert fines.total("sole_trader") == 20_000
    assert fines.listed[0].fine.sole_trader == (1_000_000, 6_000_000)
    assert fines.listed[3].fine.sole_trader == (100_000, 300_000)
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
    twice = [check("Политика обработки персональных данных", Status.FAIL)] * 2
    assert estimate(twice).total() == 60_000
    assert len(estimate([check("Хранение данных в России", Status.FAIL)] * 2).items) == 1


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
    assert data["total_max_legal_entity"] == 60_000
    assert data["items"][-1]["counted"] is False
    assert len(data["items"]) == 5
    assert data["items"][0]["url"].startswith("https://www.consultant.ru/")
    assert data["disclaimer"] == DISCLAIMER
    assert Report("example.ru").to_dict()["fines"] is None


def test_html_block_above_personal_data_section():
    html = render_html(Report("example.ru", checks=list(VIOLATIONS)))
    assert "Потенциальные штрафы: до 60 тыс. ₽ для юрлица" in html
    assert "условный: не входит в сумму" in html
    assert "если заявки с сайта хранятся на этом сервере" in html
    assert "если для этой обработки нужно согласие" in html
    assert "не юридическое заключение" in html
    assert html.index("Потенциальные штрафы") > html.index("Персональные данные (152-ФЗ)")


def test_terminal_line():
    console = Console(record=True, width=200)
    console.print(fines_line(estimate(VIOLATIONS)))
    out = console.export_text()
    assert "до 60 тыс. ₽ для юрлица" in out
    assert "статей: 1; ещё 4 условных, не в сумме" in out
    assert "не юридическое заключение" in out


def test_consent_that_is_there_has_no_fine_line():
    # Consent on a later step, outside the form or pre-ticked: it exists, ч. 1 is not about it.
    for details in (
        "Согласия не видно в первом шаге формы (главная).",
        "Чекбокс согласия отмечен заранее.",
        "Согласие упоминается на странице, но не внутри формы (главная).",
    ):
        consent = check("Согласие на обработку в формах", Status.WARN, details=details)
        assert estimate([consent]).items == ()


def test_recommendation_rules_fine_is_listed_not_counted():
    # КоАП ст. 13.56 ч. 3 (199-ФЗ, с 07.07.2026): 500–700 тыс. ₽ for an organisation.
    feed = check("Рекомендательные технологии", Status.WARN, GROUP_LAWS)
    fines = estimate([feed])
    assert [i.fine.article for i in fines.listed] == ["КоАП, ст. 13.56 ч. 3"]
    assert fines.listed[0].fine.legal == (500_000, 700_000) and fines.total() == 0


def test_one_page_summary_for_a_director():
    from suveren.report import render_summary_html

    report = Report("example.ru", checks=list(VIOLATIONS))
    html = render_summary_html(report)
    assert "сводка для руководителя" in html
    assert "Общая оценка:" in html and "Главные риски и что сделать" in html
    assert "До 60 тыс. ₽" in html and "при условиях" in html
    assert html.count("<li") <= 5
    assert "Content-Security-Policy" in html
    clean = render_summary_html(Report("example.ru"))
    assert "Серьёзных рисков не найдено" in clean and "Штрафы" not in clean
