from suveren.analyze import analyze
from suveren.checks import Status
from suveren.collect import Facts
from suveren.compliance import ComplianceInput, evaluate
from suveren.crawl import FetchedPage, pick_links
from suveren.page import parse_page

BASE = "https://example.ru/"


def test_pick_links_prioritises_forms_and_contacts():
    page = parse_page(
        """
        <a href="/news">Новости</a>
        <a href="/blog/post-1">Статья</a>
        <a href="/contacts/">Контакты</a>
        <a href="/order">Оформить заказ</a>
        <a href="https://www.example.ru/about">О компании</a>
        """
    )
    assert pick_links(page, BASE, 3) == [
        "https://example.ru/contacts",
        "https://example.ru/order",
        "https://www.example.ru/about",
    ]


def test_pick_links_skips_other_sites_files_and_duplicates():
    page = parse_page(
        """
        <a href="/">Главная</a>
        <a href="https://other.ru/contacts">Чужие контакты</a>
        <a href="https://kids.example.ru/">Детский сайт</a>
        <a href="/price.pdf">Прайс</a>
        <a href="/login">Войти</a>
        <a href="mailto:a@example.ru">Почта</a>
        <a href="/catalog?page=2">Каталог</a>
        <a href="/catalog/">Каталог</a>
        """
    )
    assert pick_links(page, BASE, 10) == ["https://example.ru/catalog"]


def test_pick_links_zero_limit():
    assert pick_links(parse_page('<a href="/a">a</a>'), BASE, 0) == []


def test_services_on_inner_pages_note_the_path():
    facts = Facts(
        host="example.ru",
        domain="example.ru",
        html="<p>home</p>",
        extra_pages=[
            FetchedPage(
                "https://example.ru/contacts",
                200,
                '<script src="https://code.jivo.ru/widget/x"></script>'
                '<script src="https://www.googletagmanager.com/gtag/js"></script>',
            )
        ],
    )
    deps = {d.service: d for d in analyze(facts).dependencies}
    assert deps["Jivo"].evidence.endswith("· /contacts")
    assert "Google Analytics / Tag Manager" in deps


def test_forms_on_inner_pages_are_checked():
    form = '<form action="/send"><input type="tel" name="phone"></form>'
    data = ComplianceInput(
        final_url=BASE,
        page=parse_page("<p>home</p>"),
        deps=[],
        extra=[("/contacts", form, parse_page(form))],
    )
    checks = {c.title: c for c in evaluate(data, "<p>home</p>")}
    consent = checks["Согласие на обработку в формах"]
    assert consent.status is Status.FAIL
    assert "/contacts" in consent.details


def test_repeated_header_form_counted_once():
    form = '<form action="/auth/sms"><input type="tel" name="phone"></form>'
    pages = [(f"/p{i}", form, parse_page(form)) for i in range(5)]
    data = ComplianceInput(final_url=BASE, page=parse_page(form), deps=[], extra=pages)
    consent = {c.title: c for c in evaluate(data, form)}["Согласие на обработку в формах"]
    assert "Форм с персональными данными: 1" in consent.details
    assert "(главная)" in consent.details
