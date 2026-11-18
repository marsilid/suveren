"""The cookie banner experiment (SUV-PD-013): what counts as a counter's hit, the verdicts,
and, in a real browser against local pages, what is pressed and what is never touched."""

import asyncio
import re

import pytest

from suveren import render
from suveren.checks import Status
from suveren.consent import (
    REJECT_RE,
    ConsentProbe,
    Request,
    consent_check,
    counter_hits,
)
from suveren.net import ALLOW_PRIVATE_ENV
from suveren.scan import consent_walls

HIT = Request("https://mc.yandex.ru/watch/1?page-url=x", "ping", 1500)
TAG = Request("https://mc.yandex.ru/metrika/tag.js", "script", 300)
ADS = Request("https://an.yandex.ru/meta/1?imp-id=2", "xhr", 2000)
PIXEL = Request("https://vk.com/rtrg?p=VK-1", "image", 900)


@pytest.mark.parametrize(
    ("text", "pressed"),
    [
        ("Отклонить", True),
        ("Отклонить все", True),
        ("Только необходимые", True),
        ("Принять только необходимые", True),
        ("Reject all", True),
        ("Use necessary cookies only", True),
        ("Decline all", True),
        ("Принять", False),
        ("Принять все", False),
        ("Хорошо", False),
        ("Отказаться от рассылки", False),
        ("Настроить", False),
    ],
)
def test_only_refusing_buttons_are_pressed(text, pressed):
    assert bool(re.search(REJECT_RE, text, re.IGNORECASE)) is pressed


def test_hits_are_counters_data_not_their_scripts_nor_the_site_nor_the_banner():
    own = Request("https://mc.shop.ru/watch/1", "ping", 10)  # matches nothing: own host
    cmp_ = Request("https://cdn.cookielaw.org/consent/receipt", "xhr", 10)  # OneTrust
    hits = counter_hits([TAG, HIT, own, cmp_, PIXEL], "www.shop.ru")
    assert list(hits) == ["Яндекс Метрика", "Пиксель VK"]
    assert hits["Яндекс Метрика"] == [HIT]


def test_reject_that_works_after_data_sent_at_once_is_a_warning():
    probe = ConsentProbe("https://shop.ru/", before=[TAG, HIT], button="Отклонить", after=[TAG])
    check = consent_check(probe, "shop.ru")
    assert check.id == "SUV-PD-013" and check.status is Status.WARN
    assert "Яндекс Метрика (через 1,5 с)" in check.details and "отказ работает" in check.details
    assert check.evidence[0].what == "до действия: Яндекс Метрика"
    assert probe.to_dict()["before"] == [TAG.url, HIT.url]


def test_reject_that_does_not_work_fails():
    probe = ConsentProbe("https://shop.ru/", before=[HIT], button="Reject all", after=[HIT, ADS])
    check = consent_check(probe, "shop.ru")
    assert check.status is Status.FAIL and "«Reject all»" in check.details
    assert "рекламные сервисы (Рекламная сеть Яндекса)" in check.details
    assert [e.what for e in check.evidence][1] == "после отказа: Яндекс Метрика"


def test_counters_that_wait_for_consent_are_fine():
    check = consent_check(ConsentProbe("u", before=[TAG], button="Отклонить", after=[]), "a.ru")
    assert check.status is Status.OK and "— тоже" in check.details
    nothing = consent_check(ConsentProbe("u", before=[TAG]), "a.ru")
    assert nothing.status is Status.OK and "данных не получали" in nothing.details
    empty = consent_check(ConsentProbe("u"), "a.ru")
    assert empty.status is Status.OK and "ни одного запроса" in empty.details


def test_ads_after_a_refusal_may_be_plain_ads():
    probe = ConsentProbe("u", before=[TAG], button="Отклонить", after=[ADS])
    check = consent_check(probe, "a.ru")
    assert check.status is Status.WARN and "без персонализации" in check.details


def test_google_consent_mode_pings_are_named_not_failed():
    ping = Request("https://region1.google-analytics.com/g/collect?v=2&gcs=G100", "ping", 5)
    granted = Request("https://region1.google-analytics.com/g/collect?v=2&gcs=G111", "ping", 5)
    check = consent_check(ConsentProbe("u", before=[], button="Reject", after=[ping]), "a.ru")
    assert check.status is Status.OK and "gcs=G100" in check.details
    both = consent_check(
        ConsentProbe("u", before=[HIT, ping], button="Reject", after=[ping]), "a.ru"
    )
    assert both.status is Status.WARN and "gcs=G100" in both.details
    bad = consent_check(ConsentProbe("u", before=[], button="Reject", after=[granted]), "a.ru")
    assert bad.status is Status.FAIL


def test_no_reject_button_is_said_plainly():
    check = consent_check(ConsentProbe("u", before=[HIT]), "a.ru")
    assert check.status is Status.WARN and "не проверено" in check.details


def test_a_wall_or_a_failure_leaves_it_unchecked():
    failed = consent_check(ConsentProbe("u", problem="браузер не открыл u (Timeout)"), "a.ru")
    assert failed.status is Status.UNKNOWN and failed.details.startswith("Не проверено")
    wall = consent_walls(ConsentProbe("u", loads=[(403, "<html><title>Antibot</title></html>")]))
    assert wall.problem and "403" in wall.problem
    fine = consent_walls(ConsentProbe("u", loads=[(200, "<html>" + "<p>текст</p>" * 400)]))
    assert fine.problem is None


# --- in a real browser ------------------------------------------------------------------

BANNER = """<!doctype html><html><head><meta charset="utf-8"></head><body>
<p>{filler}</p>
<form><input type="email" name="email"><button type="button">Отказаться</button></form>
<div id="banner"></div>
<script>
  const denied = localStorage.getItem('consent') === 'no';
  if (!denied) fetch('/hit?' + Math.random());
  const host = document.getElementById('banner');
  const root = {shadow} ? host.attachShadow({{mode: 'open'}}) : host;
  setTimeout(() => {{
    root.innerHTML = '<button id="yes">Принять</button><button id="no">Отклонить все</button>';
    root.querySelector('#yes').onclick = () => fetch('/accepted');
    root.querySelector('#no').onclick = () => localStorage.setItem('consent', 'no');
  }}, 700);
</script></body></html>"""


@pytest.mark.parametrize("shadow", [False, True])
def test_probe_presses_reject_and_watches_the_page_again(monkeypatch, shadow):
    pytest.importorskip("playwright")
    from test_formleaks_browser import Server

    monkeypatch.setenv(ALLOW_PRIVATE_ENV, "1")
    page = BANNER.format(filler="Текст " * 200, shadow="true" if shadow else "false")
    server = Server(page)

    async def go():
        try:
            async with render.BrowserSession(timeout=20) as session:
                return await session.consent(f"http://127.0.0.1:{server.port}/", settle_ms=1500)
        except Exception as exc:  # no browser on this machine
            pytest.skip(f"browser unavailable: {exc}")

    try:
        probe = asyncio.run(go())
    finally:
        server.httpd.shutdown()
    assert probe.problem is None and probe.button == "Отклонить все"
    assert any("/hit?" in r.url and r.kind == "fetch" for r in probe.before)
    assert not any("/hit?" in r.url for r in probe.after)
    paths = [p for _, p, _ in server.hits]
    assert "/accepted" not in paths  # "Принять" never pressed
    assert [s for s, _ in probe.loads] == [200, 200]
