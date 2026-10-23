from pathlib import Path

from suveren.checks import Status
from suveren.compliance import (
    ComplianceInput,
    PolicyInfo,
    evaluate,
    find_policy_link,
    has_cookie_notice,
    pd_forms,
)
from suveren.discover import contact_links, is_requisites_path
from suveren.models import Category, Dependency, Severity
from suveren.page import parse_page
from suveren.registries import RknOperator

BASE = "https://example.ru/"


def status(checks, title):
    return next(c for c in checks if c.title == title).status


def run(html, deps=(), policy=None, inns=(), operator=None, final_url=BASE):
    data = ComplianceInput(
        final_url=final_url,
        page=parse_page(html),
        deps=list(deps),
        policy=policy or PolicyInfo(),
        inns=list(inns),
        operator=operator,
    )
    return evaluate(data, html)


def test_policy_link_found_by_text_and_href():
    page = parse_page(
        '<a href="/about">О нас</a>'
        '<a href="/docs/politika.pdf">Политика обработки персональных данных</a>'
    )
    assert find_policy_link(page.links, BASE) == "https://example.ru/docs/politika.pdf"


def test_policy_link_absent():
    page = parse_page('<a href="/news">Новости</a><a href="/privacy-news">Блог</a>')
    assert find_policy_link(page.links, BASE) is None


def test_pd_form_detection_skips_search_and_login():
    html = """
    <form action="/search"><input type="search" name="q"></form>
    <form action="/login"><input name="login"><input type="password" name="pass"></form>
    <form action="/lead"><input name="name"><input type="tel" name="phone"></form>
    """
    forms = pd_forms(parse_page(html))
    assert [f.action for f in forms] == ["/lead"]


def test_form_without_consent_warns():
    html = (
        '<form action="/lead"><input type="tel" name="phone"><button>Позвоните мне</button></form>'
    )
    assert status(run(html), "Согласие на обработку в формах") is Status.WARN


def test_form_with_consent_checkbox_ok():
    html = """<form action="/lead"><input type="email" name="email">
      <label><input type="checkbox" name="agree"> Я даю согласие на обработку
      <a href="/consent">персональных данных</a></label></form>"""
    assert status(run(html), "Согласие на обработку в формах") is Status.OK


def test_prechecked_consent_warns():
    html = """<form><input type="email" name="email">
      <input type="checkbox" checked> Согласен на обработку персональных данных</form>"""
    assert status(run(html), "Согласие на обработку в формах") is Status.WARN


def test_cookie_notice_detection():
    assert has_cookie_notice('<div class="cookie-banner">Мы используем cookies</div>')
    assert has_cookie_notice("<p>Продолжая работу с сайтом, вы соглашаетесь на cookie</p>")
    assert not has_cookie_notice("<p>Рецепт печенья (cookie) с шоколадом</p>")


def test_tracking_without_cookie_notice_warns():
    metrika = Dependency(Category.ANALYTICS, "Яндекс Метрика", "RU", "mc.yandex.ru")
    checks = run("<p>Привет</p>", deps=[metrika])
    assert status(checks, "Уведомление о cookies") is Status.WARN


def test_foreign_tracking_is_cross_border():
    ga = Dependency(Category.ANALYTICS, "Google Analytics", "US", "gtm", severity=Severity.LOW)
    checks = run("<p>Привет</p>", deps=[ga])
    assert status(checks, "Трансграничная передача данных") is Status.WARN


def test_foreign_hosting_with_forms_fails_localisation():
    hetzner = Dependency(Category.HOSTING, "Hetzner", "DE", "IP", severity=Severity.HIGH)
    html = '<form><input type="tel" name="phone"> согласие на обработку персональных данных</form>'
    checks = run(html, deps=[hetzner])
    assert status(checks, "Хранение данных в России") is Status.FAIL


def test_http_site_fails_encryption():
    form = '<form><input type="tel" name="phone"><button>Позвоните мне</button></form>'
    checks = run(form, final_url="http://example.ru/")
    assert status(checks, "Защищённое соединение") is Status.FAIL
    # No form to send in the clear: a warning, and no false "data from forms" sentence.
    checks = run("<p>x</p>", final_url="http://example.ru/")
    check = next(c for c in checks if c.title == "Защищённое соединение")
    assert check.status is Status.WARN and "форм на проверенных страницах нет" in check.details


def test_policy_content_missing_sections():
    partial = Path(__file__).parent / "fixtures" / "policies" / "partial.txt"
    policy = PolicyInfo(
        url=BASE + "privacy", fetched=True, text=partial.read_text(encoding="utf-8")
    )
    checks = run("<p>x</p>", policy=policy)
    assert status(checks, "Политика обработки персональных данных") is Status.OK
    assert status(checks, "Содержание политики") is Status.WARN


def test_policy_content_complete():
    text = (Path(__file__).parent / "fixtures" / "policies" / "full.txt").read_text(
        encoding="utf-8"
    )
    policy = PolicyInfo(url=BASE + "privacy", fetched=True, text=text)
    assert status(run("<p>x</p>", policy=policy), "Содержание политики") is Status.OK


def test_operator_register_states():
    title = "Реестр операторов персональных данных"
    assert status(run("x"), title) is Status.UNKNOWN
    assert status(run("x", inns=["7707083893"]), title) is Status.WARN
    op = RknOperator("77-123", "ООО Ромашка", "7707083893", "Приказ", None, None)
    assert status(run("x", inns=["7707083893"], operator=op), title) is Status.OK


def test_an_inn_from_the_sites_own_ad_says_where_it_came_from():
    from suveren.compliance import _operator_check

    data = ComplianceInput(BASE, parse_page("x"), [], inns=["7704218694"])
    data.inn_from_ad = "МЕТРО Кэш энд Керри"
    check = _operator_check(data)
    assert check.status is Status.WARN
    assert "из маркировки рекламы" in check.details and "«МЕТРО Кэш энд Керри»" in check.details


def test_contact_links_same_site_only():
    page = parse_page(
        '<a href="/contacts">Контакты</a><a href="https://other.ru/rekvizity">Реквизиты</a>'
        '<a href="/rekvizity">Реквизиты</a><a href="/blog">Блог</a>'
    )
    assert contact_links(page, BASE) == [
        "https://example.ru/rekvizity",
        "https://example.ru/contacts",
    ]


def test_consent_text_next_to_form_is_a_warning():
    html = """<form action="/lead"><input type="tel" name="phone"><button>Отправить</button></form>
      <p>Нажимая кнопку, вы даёте согласие на обработку персональных данных.</p>"""
    assert status(run(html), "Согласие на обработку в формах") is Status.WARN


def test_checks_cite_the_law():
    checks = {c.title: c for c in run("<p>x</p>")}
    policy = checks["Политика обработки персональных данных"]
    assert policy.law == "152-ФЗ, ст. 18.1"
    assert policy.law_url.startswith("https://www.consultant.ru/")
    assert policy.to_dict()["law"] == "152-ФЗ, ст. 18.1"


def test_policy_link_ignores_personal_products_and_prefers_own_site():
    page = parse_page(
        '<a href="/features/#personal">Персональный ассистент</a>'
        '<a href="/premium/">Персональные занятия</a>'
        '<a href="https://yandex.ru/legal/confidential/">Политика конфиденциальности Яндекса</a>'
        '<a href="/privacy">Политика конфиденциальности</a>'
    )
    assert find_policy_link(page.links, BASE) == "https://example.ru/privacy"


def test_policy_link_none_for_unrelated_personal_links():
    page = parse_page('<a href="/personal/">Персональный менеджер</a>')
    assert find_policy_link(page.links, BASE) is None


def test_owner_inn_only_from_the_sites_own_pages():
    # habr.com: a company blog post carries that company's ИНН, not the site owner's.
    assert not is_requisites_path("/ru/companies/haulmont/news/123456/")
    assert not is_requisites_path("/catalog/item-42/reviews")
    for path in ("/contacts", "/rekvizity/", "/about", "/o-kompanii", "/oferta", "/privacy"):
        assert is_requisites_path(path)
    page = parse_page('<a href="/ru/companies/">Компании</a><a href="/ru/about/">О сайте</a>')
    assert contact_links(page, BASE) == ["https://example.ru/ru/about/"]


def test_policy_found_on_a_documents_page():
    """beget.com: no policy link in the footer, only "Правила и лицензии"; there the
    table of contents links to its own section, and the section links to a PDF."""
    import asyncio

    import httpx

    from suveren.checks import GROUP_152
    from suveren.compliance import hub_links, run_compliance

    home = (
        '<html><body><a href="/ru/oferta">Публичная оферта</a>'
        '<a href="/ru/rules">Правила и лицензии</a><a href="https://other.ru/docs">Документы</a>'
        + "<p>текст</p>" * 200
        + "</body></html>"
    )
    hub = (
        '<a href="/ru/rules#pd">Политика обработки персональных данных</a>'
        '<h2 id="pd">Политика обработки персональных данных</h2>'
        '<a href="/files/personal-data.pdf">Политика обработки персональных данных</a>'
    )
    assert hub_links([(BASE, parse_page(home))], BASE) == ["https://example.ru/ru/rules"]

    def handler(request):
        if request.url.path == "/ru/rules":
            return httpx.Response(200, html=hub + "<p>текст</p>" * 100)
        return httpx.Response(404)

    async def go():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            return await run_compliance(client, BASE, home, [])

    checks = asyncio.run(go())
    policy = next(c for c in checks if c.group == GROUP_152 and c.id == "SUV-PD-001")
    assert policy.status is Status.OK
    assert "PDF" in policy.details


def test_gift_card_field_is_not_personal_data_but_css_classes_do_not_hide_a_phone():
    card = '<form><input type="tel" name="GIFT_CARD"><button>Добавить</button></form>'
    assert status(run(card), "Согласие на обработку в формах") is Status.UNKNOWN
    phone = (
        '<form><input type="tel" name="phone" class="js--SignInBySms__input">'
        "<button>Позвоните мне</button></form>"
    )
    assert status(run(phone), "Согласие на обработку в формах") is Status.WARN


def test_first_step_of_a_form_without_consent_is_a_warning():
    step = (
        '<form><p>Отправим СМС с кодом подтверждения.</p><input type="tel" name="phone">'
        "<button>Продолжить</button></form>"
    )
    checks = run(step)
    check = next(c for c in checks if c.title == "Согласие на обработку в формах")
    assert check.status is Status.WARN
    assert "первом шаге" in check.details


def test_a_policy_page_that_timed_out_is_not_a_finding():
    title = "Политика обработки персональных данных"
    page = '<a href="/privacy">Политика обработки персональных данных</a>'
    slow = PolicyInfo(url=BASE + "privacy", error="сайт не ответил вовремя (ReadTimeout)")
    assert status(run(page, policy=slow), title) is Status.UNKNOWN
    gone = PolicyInfo(url=BASE + "privacy", error="такой страницы нет (код 404)")
    assert status(run(page, policy=gone), title) is Status.WARN


def test_get_once_more_retries_a_timeout_only():
    import asyncio

    import httpx

    from suveren.crawl import get_once_more

    calls = []

    def handler(request):
        calls.append(request.url.path)
        if len(calls) == 1:
            raise httpx.ReadTimeout("slow", request=request)
        return httpx.Response(200, text="ok")

    async def go():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            return await get_once_more(client, "https://example.ru/privacy")

    assert asyncio.run(go()).text == "ok" and len(calls) == 2


def test_a_policy_404_is_asked_twice_before_it_counts():
    import asyncio

    import httpx

    from suveren.compliance import fetch_policy

    answers = [404, 200]

    def handler(request):
        return httpx.Response(answers.pop(0), text="<p>Политика обработки персональных данных</p>")

    async def go():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            return await fetch_policy(client, "https://example.ru/privacy")

    info = asyncio.run(go())
    assert info.fetched and info.error is None and not answers
