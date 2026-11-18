"""What other services load inside their own frames, and what a script only names, is not
the site's (DVORYAN's report on Habr, 2.2.2: a Google map made the site "use Google Ads")."""

import asyncio

from suveren import services as db
from suveren.analyze import analyze
from suveren.collect import Facts, NetInfo
from suveren.page import page_code
from suveren.render import foreign_frame, frame_chain

SITE = "https://shop.ru/"
MAP = "https://www.google.com/maps/embed?pb=!1m18"


def test_requests_from_the_page_and_its_own_frames_are_the_sites():
    assert foreign_frame((), SITE) == ""
    assert foreign_frame(("about:blank",), SITE) == ""
    assert foreign_frame(("https://widget.shop.ru/form",), SITE) == ""
    assert foreign_frame(("https://www.shop.ru/",), "https://shop.ru/") == ""


def test_requests_from_a_foreign_frame_are_not():
    assert foreign_frame((MAP,), SITE) == MAP
    # An empty frame inside the map is still the map's.
    assert foreign_frame(("about:blank", MAP), SITE) == MAP
    assert foreign_frame(("https://shop.ru/inner", MAP), SITE) == MAP


class _Frame:
    def __init__(self, url: str, parent: "_Frame | None" = None) -> None:
        self.url, self.parent_frame = url, parent


class _Request:
    def __init__(self, frame: _Frame, navigation: bool = False) -> None:
        self.frame, self._nav = frame, navigation

    def is_navigation_request(self) -> bool:
        return self._nav


def test_frame_chain_starts_at_the_parent_for_a_frames_own_navigation():
    top = _Frame(SITE)
    child = _Frame(MAP, top)
    inner = _Frame("about:blank", child)
    assert frame_chain(_Request(top)) == ()
    assert frame_chain(_Request(child, navigation=True)) == ()  # the site loads the map
    assert frame_chain(_Request(child)) == (MAP,)
    assert frame_chain(_Request(inner)) == ("about:blank", MAP)


def test_a_request_without_a_frame_counts_as_the_pages():
    class Worker:
        @property
        def frame(self):
            raise RuntimeError("Service Worker requests do not have an associated frame")

    assert frame_chain(Worker()) == ()


def _names(html: str) -> set[str]:
    return {s.name for s, _ in db.scan_page(page_code(html, links=False))}


def test_a_host_named_in_a_scripts_list_is_not_a_load():
    html = (
        "<script>cfg={block:['googleadservices.com',\"doubleclick.net\"]}</script>"
        '<meta name="google-site-verification" content="abc">'
    )
    assert _names(html) == set()


def test_a_host_a_script_loads_from_still_counts():
    for code in (
        "s.src='//www.googleadservices.com/pagead/conversion_async.js'",
        's.src="https://www.googleadservices.com/pagead/conversion.js"',
        "load('googleadservices.com/pagead/conversion.js')",
    ):
        assert "Google Ads / AdSense" in _names(f"<script>{code}</script>"), code


def test_google_ads_from_inside_a_map_is_not_a_dependency():
    facts = Facts(
        "shop.ru",
        "shop.ru",
        web=[NetInfo("192.0.2.10", 64500, "Selectel", "RU")],
        final_url=SITE,
        page_status=200,
        html=f'<html><head><meta name="google-site-verification" content="x"></head>'
        f'<body><iframe src="{MAP}"></iframe></body></html>',
    )
    seen = [
        (MAP, ()),
        ("https://www.googleadservices.com/pagead/conversion_async.js", (MAP,)),
    ]
    facts.loaded_urls = [u for u, chain in seen if not foreign_frame(chain, SITE)]
    names = {d.service for d in analyze(facts).dependencies}
    assert "Google Maps" in names
    assert "Google Ads / AdSense" not in names


def test_open_keeps_only_the_sites_requests():
    """BrowserSession.open records what the page and its own frames ask for."""
    from suveren.render import BrowserSession

    top = _Frame(SITE)
    child = _Frame(MAP, top)
    handlers: dict = {}

    class Page:
        url = SITE

        def on(self, event, fn):
            handlers[event] = fn

        async def goto(self, url, **_):
            handlers["request"](_Named(SITE, top, True))
            handlers["request"](_Named(MAP, child, True))
            handlers["request"](_Named("https://www.googleadservices.com/x.js", child))
            handlers["request"](_Named("https://shop.ru/app.js", top))
            return None

        async def wait_for_load_state(self, *a, **k):
            return None

        async def evaluate(self, *a, **k):
            return None

        async def content(self):
            return "<html></html>"

        async def close(self):
            return None

    class Context:
        async def new_page(self):
            return Page()

    session = BrowserSession()
    session._context = Context()
    rendered = asyncio.run(session.open(SITE))
    assert rendered.requests == [SITE, MAP, "https://shop.ru/app.js"]


class _Named(_Request):
    def __init__(self, url: str, frame: _Frame, navigation: bool = False) -> None:
        super().__init__(frame, navigation)
        self.url = url
