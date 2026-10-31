"""Advertising labels: facts only, never a violation (38-ФЗ not checked yet)."""

from suveren.admarking import ad_marking_check, erids
from suveren.checks import Status


def test_erids_from_links_and_text():
    pages = [
        '<a href="https://x.ru/?utm=1&erid=2SDnjcVm4Kd">Реклама</a>',
        "<p>Реклама. ООО «А». erid: LjN8KBzLs</p>",
        '<a href="https://y.ru/#erid=2SDnjcVm4Kd">дубль</a>',
    ]
    assert erids(pages) == ["2SDnjcVm4Kd", "LjN8KBzLs"]
    assert erids(["<p>error id=12</p>", "?erid=abc"]) == []


def test_check_only_reports_what_it_sees():
    check = ad_marking_check(['<a href="/?erid=2SDnjcVm4Kd">Реклама</a>'])
    assert check is not None and check.id == "SUV-LAW-003"
    assert check.status is Status.OK and check.law == "38-ФЗ, ст. 18.1"
    assert check.law_url and "consultant.ru" in check.law_url
    assert ad_marking_check(["<p>ничего</p>"]) is None
    many = ad_marking_check([f"?erid=AAAAAA{i:02d}" for i in range(8)])
    assert many is not None and "и ещё 3" in many.details
