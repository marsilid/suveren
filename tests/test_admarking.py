"""Advertising labels (38-ФЗ, ст. 18.1, ч. 16–17): facts only, never a violation."""

from suveren.admarking import ad_marking_check, erids
from suveren.checks import Status


def test_erids_from_links_text_and_markup():
    pages = [
        '<a href="https://x.ru/?utm=1&erid=2SDnjcVm4Kd">Реклама</a>',
        "<p>Реклама. ООО «А». erid: LjN8KBzLs</p>",
        '<a href="https://y.ru/#erid=2SDnjcVm4Kd">дубль</a>',
        '<div class="banner" data-erid="Kra23f4Xy">',
        '<script>window.ad = {"erid":"F7Lm9Qw2zA"}</script>',
        "<div data-erid='Pq8sT4uVw'>",
    ]
    assert erids(pages) == ["2SDnjcVm4Kd", "LjN8KBzLs", "Kra23f4Xy", "F7Lm9Qw2zA", "Pq8sT4uVw"]
    assert erids(["<p>error id=12</p>", "?erid=abc", "<p>period: 2026</p>"]) == []


def test_check_only_reports_what_it_sees():
    check = ad_marking_check([("главная", '<a href="/?erid=2SDnjcVm4Kd">Реклама</a>')])
    assert check is not None and check.id == "SUV-LAW-003"
    # A label seen is not a check of all ads: "not clear", never "в порядке" (2.1).
    assert check.status is Status.UNKNOWN and check.law == "38-ФЗ, ст. 18.1"
    assert "Не проверялось" in check.details and "ЕРИР" in check.details
    assert "ч. 16–17" in check.details and "слово «реклама»" not in check.details
    assert check.law_url and "consultant.ru" in check.law_url
    assert ad_marking_check([("главная", "<p>ничего</p>")]) is None
    many = ad_marking_check([("главная", f"?erid=AAAAAA{i:02d}") for i in range(8)])
    assert many is not None and "и ещё 3" in many.details


def test_token_without_the_word_is_named_but_still_unknown():
    pages = [
        ("главная", "<p>Рекламодатель: ООО «А»</p><a href='/?erid=2SDnjcVm4Kd'>Купить</a>"),
        ("/news", '<div data-erid="Kra23f4Xy"><img src="b.png"></div>'),
        ("/about", "<p>Реклама. ООО «Б». erid: LjN8KBzLs</p>"),
    ]
    check = ad_marking_check(pages)
    assert check is not None and check.status is Status.UNKNOWN
    # "Рекламодатель" is not the mark; a script-only word is not seen either.
    assert "На страницах (главная, /news) токен есть" in check.details
    one = ad_marking_check(
        [("/news", '<div data-erid="Kra23f4Xy"></div><script>"реклама"</script>')]
    )
    assert one is not None and "На странице (/news)" in one.details
