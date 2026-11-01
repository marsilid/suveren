"""Instagram and Facebook links without the Meta note: a warning at most."""

import time

import pytest

from suveren.checks import Status
from suveren.metanote import has_note, meta_links, meta_note_check


def test_links_are_found_by_address_not_by_word():
    page = (
        '<a href="https://www.instagram.com/x">i</a> <a href=//m.facebook.com/x>f</a>'
        '<a href="https://fb.me/x">f</a> <p>Мы есть в Instagram и Facebook</p>'
    )
    assert meta_links(page) == ["facebook.com", "fb.me", "instagram.com"]
    assert meta_links('<a href="https://notinstagram.company/">x</a>') == []
    assert meta_links("<p>instagram.com/lab</p>") == []


@pytest.mark.parametrize(
    ("text", "noted"),
    [
        ("Instagram принадлежит компании Meta, признанной экстремистской организацией", True),
        ("* Meta Platforms Inc. признана экстремистской и запрещена в РФ", True),
        ("Деятельность компании Meta запрещена на территории России", True),
        ("Facebook и Instagram запрещены в России.", True),
        ("Соцсеть Инстаграм запрещена в РФ", True),
        ("Копирование материалов запрещено. Мы в Facebook", False),
        ("Подписывайтесь на наш Instagram", False),
        ("metadata extremist", False),
    ],
)
def test_note_wordings(text, noted):
    assert has_note(f"<footer><p>{text}</p></footer>") is noted


def test_check_statuses_per_page():
    linked = '<a href="https://instagram.com/x">i</a>'
    note = "<p>Meta признана экстремистской организацией и запрещена в РФ</p>"
    assert meta_note_check([("главная", "<p>нет ссылок</p>")]) is None
    ok = meta_note_check([("главная", linked + note)])
    assert ok is not None and ok.id == "SUV-LAW-004" and ok.status is Status.OK
    # The note on another page does not cover a page without it.
    warn = meta_note_check([("главная", linked + note), ("/contacts", linked)])
    assert warn is not None and warn.status is Status.WARN
    assert "/contacts" in warn.details and "главная" not in warn.details.split("есть ссылки")[0]
    assert "штраф" not in warn.details.lower() and "пометку" in warn.recommendation


def test_long_pages_stay_fast():
    page = '<a href="https://instagram.com/x">i</a>' + "Instagram facebook meta " * 20000
    started = time.perf_counter()
    has_note(page)
    assert time.perf_counter() - started < 2.0


def test_warning_shows_the_link_it_rests_on():
    warn = meta_note_check([("/about", '<a href="https://www.facebook.com/x">f</a>')])
    assert warn is not None and warn.evidence[0].what == "Ссылка без пометки (страница /about)"
    assert "facebook.com" in warn.evidence[0].value
