"""Recommendation technologies (149-ФЗ, ст. 10.2-2): a warning at most, never a violation."""

from suveren.checks import Status
from suveren.recommend import recommendation_check


def check(*htmls):
    return recommendation_check(list(htmls))


def test_personal_recommendations_without_rules_warn():
    result = check("<h2>Персональные рекомендации</h2><p>Для вас подборка</p>")
    assert "Персональные рекомендации" in result.details
    assert result.status is Status.WARN
    assert "13.56" in result.recommendation and result.law == "149-ФЗ, ст. 10.2-2"


def test_rules_on_any_page_are_enough():
    home = "<h2>Вы недавно смотрели</h2>"
    assert check(home).status is Status.WARN
    footer = '<a href="/docs/recs">Правила применения рекомендательных технологий</a>'
    result = check(home, footer)
    assert result.status is Status.OK and "Правила применения" in result.details
    assert check('<a href="/legal/recommendation-rules">Правила</a>').status is Status.OK


def test_the_same_list_for_everyone_is_not_a_case():
    assert check("<h2>Популярные товары</h2><h2>Похожие товары</h2><p>Хиты</p>") is None
    # In running text these are not feeds (netology.ru, skillbox.ru in the corpus).
    assert check("<p>Вы получите взгляд со стороны и персональные рекомендации.</p>") is None
    assert check("<p>Мы рекомендуем вам проверить, что ваш браузер безопасен.</p>") is None
    assert check('<a href="/recommendations/alfa">Выбор Альфа-Банка</a>') is None
    assert check("") is None


def test_never_a_violation():
    result = check("<h3>Вам может понравиться</h3>")
    assert result.status is not Status.FAIL
