"""Russian lists: Росфинмониторинг's list by the text of its page (synthetic pages: the
real one answers only Russian addresses, so these are not recordings)."""

import asyncio

import httpx

from suveren.checks import Status
from suveren.ruregistries import (
    FEDSFM_URL,
    RuScreening,
    find,
    list_check,
    normalize,
    not_connected_note,
    screen,
)

PAGE = """<h1>Перечень террористов и экстремистов</h1>
<p>Организации</p><ol><li>1. ООО «ПРИМЕР», ИНН: 7707083893, ОГРН: 1027700132195</li></ol>
<p>Физические лица</p><ol><li>12. ИВАНОВ ИВАН ИВАНОВИЧ*, 02.03.1980 г.р., г. МОСКВА</li>
<li>13. СЁМИН ПЁТР АЛЕКСЕЕВИЧ, 04.05.1990 г.р.</li></ol>"""


def test_normalize():
    assert normalize("<b>Сёмин</b>  &laquo;x&raquo;*") == "СЕМИН «X»"


def test_find_by_ids_and_full_name():
    text = normalize(PAGE)
    hits = find(text, {"ИНН": "7707083893", "ОГРН": ""}, None)
    assert [(h.by, h.value) for h in hits] == [("ИНН", "7707083893")] and hits[0].strong
    # The ИНН as part of a longer number is not a match.
    assert find(normalize("12377070838934"), {"ИНН": "7707083893"}, None) == []
    person = find(text, {}, "Сёмин Пётр Алексеевич")
    assert person[0].by == "ФИО" and not person[0].strong
    # A surname and a first name only match too many people.
    assert find(text, {}, "Иванов Иван") == []


def test_list_check_statuses():
    text = normalize(PAGE)
    fail = list_check(RuScreening(find(text, {"ИНН": "7707083893"}, None), "s"), asked=True)
    assert (
        fail.id == "SUV-CO-008" and fail.status is Status.FAIL and "115-ФЗ" in (fail.recommendation)
    )
    warn = list_check(RuScreening(find(text, {}, "Иванов Иван Иванович"), "s"), asked=True)
    assert warn.status is Status.WARN and "тёзка" in warn.details
    assert list_check(RuScreening([], "s"), asked=True).status is Status.OK
    down = list_check(RuScreening(error="нет связи"), asked=True)
    assert down.status is Status.UNKNOWN and "российского IP" in down.recommendation
    assert list_check(RuScreening(), asked=False).status is Status.UNKNOWN
    assert "Минюст" in not_connected_note() and "ЕФРСБ" in not_connected_note()


def _screen(handler, tmp_path, monkeypatch):
    monkeypatch.setenv("SUVEREN_CACHE", str(tmp_path))

    async def go():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as c:
            return await screen(c, {"ИНН": "7707083893"}, None)

    return asyncio.run(go())


def test_screen_downloads_the_list_and_dates_it(tmp_path, monkeypatch):
    def handler(request):
        assert str(request.url) == FEDSFM_URL
        return httpx.Response(200, text=PAGE)

    result = _screen(handler, tmp_path, monkeypatch)
    assert result.error is None and result.matches[0].by == "ИНН"
    assert result.source and "fedsfm.ru" in result.source and "выгрузка от" in result.source


def test_a_page_that_is_not_the_list_is_not_checked(tmp_path, monkeypatch):
    stub = _screen(lambda r: httpx.Response(200, text="Доступ ограничен"), tmp_path, monkeypatch)
    assert stub.error and not stub.matches
    down = _screen(lambda r: httpx.Response(403), tmp_path / "2", monkeypatch)
    assert down.error
