from suveren.checks import Status
from suveren.compliance import (
    ComplianceInput,
    PolicyInfo,
    evaluate,
    find_policy_link,
    has_cookie_notice,
    pd_forms,
)
from suveren.discover import contact_links
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


def test_form_without_consent_fails():
    html = (
        '<form action="/lead"><input type="tel" name="phone"><button>Позвоните мне</button></form>'
    )
    assert status(run(html), "Согласие на обработку в формах") is Status.FAIL


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
    checks = run("<p>x</p>", final_url="http://example.ru/")
    assert status(checks, "Защищённое соединение") is Status.FAIL


def test_policy_content_missing_sections():
    policy = PolicyInfo(url=BASE + "privacy", fetched=True, text="Мы бережём ваши данные.")
    checks = run("<p>x</p>", policy=policy)
    assert status(checks, "Политика обработки персональных данных") is Status.OK
    assert status(checks, "Содержание политики") is Status.WARN


def test_policy_content_complete():
    text = (
        "Политика в соответствии с 152-ФЗ. Оператор ООО Ромашка. Цели обработки: связь. "
        "Субъект может направить отзыв согласия."
    )
    policy = PolicyInfo(url=BASE + "privacy", fetched=True, text=text)
    assert status(run("<p>x</p>", policy=policy), "Содержание политики") is Status.OK


def test_operator_register_states():
    title = "Реестр операторов персональных данных"
    assert status(run("x"), title) is Status.UNKNOWN
    assert status(run("x", inns=["7707083893"]), title) is Status.WARN
    op = RknOperator("77-123", "ООО Ромашка", "7707083893", "Приказ", None, None)
    assert status(run("x", inns=["7707083893"], operator=op), title) is Status.OK


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
