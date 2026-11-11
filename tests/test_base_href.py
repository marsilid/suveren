"""<base href> is honoured wherever relative links are resolved (redfox0, 2.2.3).

The site had <base href="/ru/"> and relative links; Suveren resolved them against the
page address and got 404 for the policy, contacts and inner pages."""

from suveren import crawl, discover, unknown, websec
from suveren.compliance import find_policy_link
from suveren.page import document_base, parse_page, with_base

HOME = "https://shop.ru/"
HTML = """<html><head><base href="/ru/">
<script src="js/app.js"></script><link rel="stylesheet" href="css/site.css">
</head><body>
<a href="contacts">Контакты</a>
<a href="about/company">О компании</a>
<a href="privacy">Политика обработки персональных данных</a>
<a href="#top">Наверх</a>
<a href="mailto:info@shop.ru">Почта</a>
<a href="/en/">English</a>
<form action="send.php"><input name="phone"></form>
</body></html>"""


def test_links_and_form_actions_follow_the_base():
    page = parse_page(HTML)
    assert page.base == "/ru/"
    hrefs = [link.href for link in page.links]
    assert hrefs[:3] == ["/ru/contacts", "/ru/about/company", "/ru/privacy"]
    # A jump within the page, mail and an absolute path are left as written.
    assert hrefs[3:] == ["#top", "mailto:info@shop.ru", "/en/"]
    assert page.forms[0].action == "/ru/send.php"


def test_policy_contacts_and_inner_pages_are_found_under_the_base():
    page = parse_page(HTML)
    assert find_policy_link(page.links, HOME) == "https://shop.ru/ru/privacy"
    assert "https://shop.ru/ru/contacts" in discover.contact_links(page, HOME)
    picked = crawl.pick_links(page, HOME, 10)
    assert "https://shop.ru/ru/about/company" in picked
    assert not any(u in ("https://shop.ru/contacts", "https://shop.ru/privacy") for u in picked)


def test_scripts_and_styles_follow_the_base():
    resources, _ = websec.page_resources(HTML, HOME)
    assert {r.url for r in resources} == {
        "https://shop.ru/ru/js/app.js",
        "https://shop.ru/ru/css/site.css",
    }
    assert "https://shop.ru/ru/js/app.js" in unknown.resource_urls(HTML, HOME)


def test_relative_and_foreign_bases():
    page_url = "https://shop.ru/a/b/index.html"
    assert document_base(page_url, "<BASE HREF=/ru/ >") == "https://shop.ru/ru/"
    assert document_base(page_url, "<base href='https://cdn.ru/x/'>") == "https://cdn.ru/x/"
    # No href, or a script in it: the page address stays the base.
    assert document_base(page_url, "<base target=_blank>") == page_url
    assert document_base(page_url, '<base href="javascript:alert(1)">') == page_url
    # A relative base is resolved against the page address by the usual join.
    from urllib.parse import urljoin

    assert urljoin(page_url, with_base("ru/", "../x")) == "https://shop.ru/a/b/x"


def test_a_page_without_base_is_unchanged():
    page = parse_page('<a href="contacts">Контакты</a>')
    assert page.base == "" and page.links[0].href == "contacts"
