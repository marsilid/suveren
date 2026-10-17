import asyncio
from pathlib import Path

import httpx

from suveren.checks import GROUP_LAWS, Status
from suveren.compliance import run_compliance
from suveren.logins import (
    BUTTON,
    OAUTH,
    PATH,
    SDK,
    WIDGET,
    LoginEvidence,
    find_evidence,
    find_login_page,
    login_check,
    short_path,
)
from suveren.page import parse_page

FIXTURES = Path(__file__).parent / "fixtures" / "logins"
BASE = "https://example.ru/"


def evidence(name, url=BASE, loaded=()):
    html = (FIXTURES / name).read_text(encoding="utf-8")
    return find_evidence(html, parse_page(html), url, "/login", loaded)


def kinds(found, provider):
    return {e.kind for e in found if e.provider == provider}


def test_google_oauth_link_and_apple_button_fail():
    found = evidence("google_apple.html")
    assert kinds(found, "Google") == {OAUTH, BUTTON}
    assert kinds(found, "Apple") == {WIDGET, SDK, BUTTON}
    check = login_check(found, ["главная", "/login"])
    assert check.status is Status.FAIL
    assert check.group == GROUP_LAWS
    assert check.law == "149-ФЗ, ст. 8 ч. 10"
    assert "Google" in check.details and "Apple" in check.details
    assert "accounts.google.com/o/oauth2" in check.details
    assert "13.55 КоАП" in check.recommendation and "500–700" in check.recommendation


def test_russian_sign_in_and_plain_links_pass():
    """VK ID, Yandex ID, Gosuslugi are allowed; maps, stores, channels and share links
    to foreign companies are not sign-in."""
    found = evidence("russian_only.html")
    assert not [e for e in found if e.foreign]
    assert {e.provider for e in found} == {"VK ID", "Яндекс ID", "Госуслуги"}
    check = login_check(found, ["главная"])
    assert check.status is Status.OK
    assert "VK ID" in check.details and "разрешён" in check.details


def test_article_text_and_shop_links_are_not_sign_in():
    # A headline and a paragraph mention sign-in with Google: that's not a button.
    assert evidence("blog.html") == []
    label = (
        '<a href="#">Как войти через Google в почту, если забыл пароль: подробная инструкция</a>'
    )
    assert find_evidence(label, parse_page(label), BASE, "главная") == []
    plain = find_evidence(
        '<a href="/remont/?service=apple">Ремонт</a><a href="/catalog/apple/x">iPhone</a>'
        '<a href="/social/instagram">Соцсети</a>',
        parse_page(
            '<a href="/remont/?service=apple">Ремонт</a><a href="/catalog/apple/x">iPhone</a>'
            '<a href="/social/instagram">Соцсети</a>'
        ),
        BASE,
        "главная",
    )
    assert plain == []


def test_own_routes_foreign_fail_and_russian_allowed():
    found = evidence("own_routes.html")
    foreign = {e.provider for e in found if e.kind == PATH and e.foreign}
    assert foreign == {"GitHub", "Facebook", "Steam"}
    assert {e.provider for e in found if not e.foreign} == {"VK ID"}
    check = login_check(found, ["главная"])
    assert check.status is Status.FAIL
    assert "Вход через VK ID разрешён" in check.details


def test_habr_style_post_forms_with_icon_buttons():
    """Habr Account: a POST form to /extidp/<network>/prompt and an icon button."""
    found = evidence("extidp_forms.html", "https://account.example.ru/ru/ident/abc")
    assert {e.provider for e in found if e.kind == PATH and e.foreign} == {"GitHub", "X (Twitter)"}
    assert {e.provider for e in found if not e.foreign} == {"VK ID", "Яндекс ID"}
    check = login_check(found, ["главная"])
    assert check.status is Status.FAIL
    assert "скрыты от пользователей из России" in check.recommendation


def test_drom_style_sign_route_and_long_svg_button():
    found = evidence("sign_route.html")
    assert kinds(found, "Telegram") == {PATH, BUTTON}
    assert kinds(found, "GitHub") == {BUTTON}  # the label sits after a long SVG icon


def test_same_evidence_on_many_pages_is_listed_once():
    found = [LoginEvidence("Google", SDK, p, "accounts.google.com/gsi/client") for p in "abcde"]
    details = login_check(found, ["главная"]).details
    assert details.count("gsi/client") == 1
    assert "страницы a, b и ещё 3" in details


def test_short_path_hides_tokens():
    assert short_path("/ru/ident/" + "x" * 80) == "/ru/ident/…"


def test_ulogin_widget_lists_foreign_networks():
    found = evidence("ulogin.html")
    assert {e.provider for e in found} == {"Google", "X (Twitter)"}
    assert all(e.kind == WIDGET for e in found)


def test_google_script_alone_is_a_warning():
    found = evidence("gsi_only.html")
    assert kinds(found, "Google") == {SDK}
    check = login_check(found, ["главная"])
    assert check.status is Status.WARN
    assert "возможное нарушение" in check.recommendation
    assert "13.55" not in check.recommendation


def test_script_seen_only_in_browser_requests():
    found = find_evidence(
        "<html><body>Вход</body></html>",
        parse_page("<html><body>Вход</body></html>"),
        BASE,
        "главная",
        ["https://accounts.google.com/gsi/client"],
    )
    assert kinds(found, "Google") == {SDK}


def test_telegram_login_widget_but_not_post_embed():
    assert kinds(evidence("telegram_login.html"), "Telegram") == {WIDGET}
    assert kinds(evidence("russian_only.html"), "Telegram") == set()


def test_endpoint_needs_host_boundary():
    html = '<a href="https://netflix.com/oauth/authorize">x</a>'
    assert find_evidence(html, parse_page(html), BASE, "главная") == []


def test_find_login_page_prefers_link_text_on_same_site():
    html = (FIXTURES / "home_with_login_link.html").read_text(encoding="utf-8")
    assert find_login_page(parse_page(html), BASE) == "https://lk.example.ru/"
    by_href = parse_page('<a href="/about">О нас</a><a href="/personal/">👤</a>')
    assert find_login_page(by_href, BASE) == "https://example.ru/personal/"
    assert find_login_page(parse_page('<a href="/news">Новости</a>'), BASE) is None


def test_bot_wall_is_unknown():
    check = login_check([], [], "сайт показал страницу проверки «вы не робот»")
    assert check.status is Status.UNKNOWN


def test_details_are_capped():
    many = [LoginEvidence(f"P{i}", OAUTH, "/login", f"x{i}") for i in range(8)]
    assert "и ещё 3" in login_check(many, ["главная"]).details


def test_run_compliance_opens_the_sign_in_page():
    home = (
        '<html><body><a href="/">Главная</a><a href="/user/login">Войти</a>'
        + "<p>текст</p>" * 200
        + "</body></html>"
    )
    login = (FIXTURES / "google_apple.html").read_text(encoding="utf-8")
    asked = []

    def handler(request):
        asked.append(request.url.path)
        if request.url.path == "/user/login":
            return httpx.Response(200, html=login)  # short, with a captcha-free form
        return httpx.Response(404)

    async def go():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            return await run_compliance(client, BASE, home, [])

    checks = asyncio.run(go())
    check = next(c for c in checks if c.group == GROUP_LAWS)
    assert "/user/login" in asked
    assert check.status is Status.FAIL
    assert "страница /user/login" in check.details


def test_button_text_alone_warns_and_with_script_fails():
    button = '<button class="btn"><img alt=""> Войти через Google</button>'
    found = find_evidence(button, parse_page(button), BASE, "главная")
    assert kinds(found, "Google") == {BUTTON}
    assert login_check(found, ["главная"]).status is Status.WARN
    with_sdk = find_evidence(
        button, parse_page(button), BASE, "главная", ["https://accounts.google.com/gsi/client"]
    )
    assert login_check(with_sdk, ["главная"]).status is Status.FAIL


def test_sign_in_page_drawn_by_scripts_is_named():
    check = login_check([], ["главная", "/login"], shell="/login")
    assert check.status is Status.OK
    assert "/login собирается скриптами" in check.details and "--browser" in check.details
