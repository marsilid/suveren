"""Code an antivirus on the operator's computer puts into pages is not the site's (2.2.3)."""

from suveren import localsoft
from suveren.collect import Facts
from suveren.crawl import FetchedPage
from suveren.scriptgraph import build, graph_check

KIS = "https://gc.kis.v2.scr.kaspersky-labs.com/FD126C42-EBFA-4E12-B309-BB3FDD723AC1/main.js"
KIS_CSS = (
    "https://gc.kis.v2.scr.kaspersky-labs.com/E3E8934C-235A-4B0E-825A-35A08381A191/abn/main.css"
)
PAGE = (
    '<html><head><script src="/app.js"></script>'
    f'<script type="text/javascript" src="{KIS}?attr=abc" charset="UTF-8"></script>'
    f'<link rel="stylesheet" crossorigin="anonymous" href="{KIS_CSS}"/>'
    '<script src="https://mc.yandex.ru/metrika/tag.js"></script></head><body></body></html>'
)


def facts() -> Facts:
    f = Facts(host="example.ru", domain="example.ru")
    f.html = PAGE
    f.loaded_urls = [
        "https://example.ru/app.js",
        KIS,
        KIS_CSS,
        "https://mc.yandex.ru/metrika/tag.js",
    ]
    f.initiators = {
        "https://example.ru/app.js": "",
        KIS: "",
        "https://mc.yandex.ru/metrika/tag.js": "",
        # something the antivirus script itself fetched
        "https://cdn.example.net/kis-helper.js": KIS,
    }
    f.extra_pages = [FetchedPage("https://example.ru/about", 200, PAGE, [KIS])]
    return f


def test_program_of_knows_only_listed_hosts():
    assert localsoft.program_of(KIS) == "Kaspersky"
    assert localsoft.program_of("https://local.adguard.org/?ts=1&type=content-script") == "AdGuard"
    assert localsoft.program_of("https://adguard.com/ru/welcome.html") is None
    assert localsoft.program_of("https://kaspersky.ru/") is None  # the vendor's own site
    assert localsoft.program_of("https://evil-kaspersky-labs.com/x.js") is None


def test_injected_script_is_not_counted_as_the_sites_code():
    f = facts()
    localsoft.clean(f)
    assert "kaspersky-labs" not in f.html and "/app.js" in f.html and "tag.js" in f.html
    assert not any("kaspersky" in u for u in f.loaded_urls)
    assert "kaspersky-labs" not in f.extra_pages[0].html and not f.extra_pages[0].loaded_urls
    graph = build(f.initiators, "example.ru")
    assert "kaspersky-labs.com" not in graph.nodes
    assert "example.net" not in graph.nodes  # loaded by the antivirus, not by the site
    assert "kaspersky" not in graph_check(graph).details.lower()
    # One line in the report about the machine, not about the site.
    said = [n for n in f.notes if "Kaspersky" in n]
    assert len(said) == 1 and "на компьютере" in said[0].lower()


def test_clean_page_gets_no_note():
    f = Facts(host="example.ru", domain="example.ru")
    f.html = "<html><script src='/a.js'></script></html>"
    f.loaded_urls = ["https://example.ru/a.js"]
    localsoft.clean(f)
    assert f.notes == [] and f.html.count("<script") == 1
