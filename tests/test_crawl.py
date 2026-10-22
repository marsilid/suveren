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


def test_sitemap_from_robots_with_an_index_and_form_pages_only():
    import asyncio

    import httpx

    from suveren.crawl import pick_from_sitemap, sitemap_urls

    site = "https://shop.example"
    pages = {
        "/robots.txt": f"User-agent: *\nSitemap: {site}/sitemap-index.xml\n",
        "/sitemap-index.xml": "<sitemapindex>"
        f"<sitemap><loc>{site}/sitemap-pages.xml</loc></sitemap>"
        f"<sitemap><loc>{site}/sitemap-old.xml.gz</loc></sitemap></sitemapindex>",
        "/sitemap-pages.xml": "<urlset>"
        f"<url><loc>{site}/blog/2019/kontakty-partnerov</loc></url>"
        f"<url><loc>{site}/kontakty</loc></url>"
        f"<url><loc>{site}/catalog/item-1</loc></url>"
        f"<url><loc>{site}/course/vkontakte-promotion</loc></url>"
        f"<url><loc>{site}/courses/vzaimodeistvie-s-zakazchikom</loc></url>"
        f"<url><loc>{site}/cart?step=1&amp;x=2</loc></url>"
        f"<url><loc>https://other.example/contacts</loc></url>"
        f"<url><loc>{site}/price.pdf</loc></url></urlset>",
    }
    seen = []

    def handler(request):
        seen.append(request.url.path)
        body = pages.get(request.url.path)
        return httpx.Response(200, text=body) if body else httpx.Response(404)

    async def go():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            return await sitemap_urls(client, f"{site}/")

    urls = asyncio.run(go())
    assert "/sitemap-old.xml.gz" not in seen  # compressed: skipped
    assert f"{site}/cart?step=1&x=2" in urls
    picked = pick_from_sitemap(urls, f"{site}/", skip={f"{site}/about"})
    # Contacts and cart, shallow paths first; not the blog post, the catalog, the PDF
    # or another site.
    assert picked == [f"{site}/kontakty", f"{site}/cart"]


def test_sitemap_falls_back_to_sitemap_xml():
    import asyncio

    import httpx

    from suveren.crawl import sitemap_urls

    def handler(request):
        if request.url.path == "/sitemap.xml":
            return httpx.Response(
                200, text="<urlset><url><loc>https://a.example/x</loc></url></urlset>"
            )
        return httpx.Response(404)

    async def go():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            return await sitemap_urls(client, "https://a.example/page")

    assert asyncio.run(go()) == ["https://a.example/x"]
