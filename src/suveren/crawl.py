"""Pick and fetch a few internal pages besides the home page.

Forms, chats and maps usually live on "Contacts", "Order" or "Cart" pages rather
than on the home page, so those are fetched first; the rest of the budget goes
to the main navigation links in page order.
"""

from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlsplit, urlunsplit

import httpx

from suveren.page import Page

DEFAULT_PAGES = 6
MAX_HTML_CHARS = 2_000_000

# (pattern over link text + URL, weight)
_PRIORITY = (
    (re.compile(r"контакт|contact|kontakt", re.I), 10),
    (re.compile(r"заявк|оформ|заказ|order|checkout|zakaz|zayavk", re.I), 9),
    (re.compile(r"корзин|cart|basket|korzin", re.I), 8),
    (re.compile(r"обратн\w* связ|callback|feedback|запис|записаться|booking|zapis", re.I), 8),
    (re.compile(r"регистрац|signup|sign-up|register", re.I), 6),
    (re.compile(r"доставк|оплат|delivery|payment|dostavk|oplat", re.I), 5),
    (re.compile(r"услуг|services|uslug|прайс|price|цены|тариф", re.I), 4),
    (re.compile(r"о компании|о нас|about|o-nas|o-kompanii", re.I), 3),
)
_SKIP_EXT = re.compile(
    r"\.(?:pdf|jpe?g|png|gif|webp|svg|ico|zip|rar|7z|docx?|xlsx?|pptx?|mp4|mp3|avi|mov|xml|json|"
    r"txt|css|js)$",
    re.I,
)
_SKIP_PATH = re.compile(
    r"/(?:login|logout|signin|auth|admin|wp-admin|account|lk|search)(?:/|$)", re.I
)


@dataclass(slots=True)
class FetchedPage:
    url: str
    status: int | None
    html: str
    loaded_urls: list[str] = field(default_factory=list)

    @property
    def path(self) -> str:
        parts = urlsplit(self.url)
        return parts.path or "/"


def _bare(host: str) -> str:
    host = host.lower().rstrip(".")
    return host[4:] if host.startswith("www.") else host


def _normalize(url: str) -> str:
    parts = urlsplit(url)
    path = parts.path or "/"
    if path != "/" and path.endswith("/"):
        path = path[:-1]
    return urlunsplit((parts.scheme, parts.netloc.lower(), path, "", ""))


def pick_links(page: Page, base: str, limit: int, skip: set[str] | None = None) -> list[str]:
    """Up to ``limit`` same-site page URLs, most useful first."""
    if limit <= 0:
        return []
    # Subdomains are often separate sites (kids.example.ru, shop.example.ru): stay on
    # the same host, treating www. as the same.
    site = _bare(urlsplit(base).hostname or "")
    seen = {_normalize(base), *(_normalize(u) for u in (skip or set()))}
    scored: list[tuple[int, int, str]] = []
    for order, link in enumerate(page.links):
        href = link.href.strip()
        if not href or href.startswith(("#", "javascript:", "mailto:", "tel:", "data:")):
            continue
        url = urljoin(base, href)
        parts = urlsplit(url)
        if parts.scheme not in ("http", "https") or not parts.hostname:
            continue
        if _bare(parts.hostname) != site:
            continue
        if _SKIP_EXT.search(parts.path) or _SKIP_PATH.search(parts.path):
            continue
        key = _normalize(url)
        if key in seen:
            continue
        seen.add(key)
        haystack = f"{link.text} {parts.path}"
        weight = max((w for rx, w in _PRIORITY if rx.search(haystack)), default=0)
        scored.append((-weight, order, key))
    scored.sort()
    # One page of each kind first: fl.ru's home page shows freelancers' cards that change
    # on every visit (their text says "заказ", so they rank as order pages), and five
    # /users/<name>/portfolio pages took the whole budget: the policy link was found one
    # night and not the next. News sites do the same with today's articles. Pages of a
    # kind already taken fill what budget is left, still by weight.
    first, rest, kinds = [], [], set()
    for _, _, url in scored:
        kind = _kind(url)
        if kind not in kinds:
            first.append(url)
            kinds.add(kind)
        else:
            rest.append(url)
    return (first + rest)[:limit]


def _kind(url: str) -> tuple[str, int]:
    """/users/maxiseo/portfolio and /users/me2w/portfolio are one kind of page."""
    segments = urlsplit(url).path.strip("/").split("/")
    return segments[0], len(segments)


async def get_once_more(client: httpx.AsyncClient, url: str) -> httpx.Response:
    """GET, tried once more after a timeout: under a batch's load one page in many times
    out and comes on the second try (kp.ru's policy, 2026-10-23)."""
    try:
        return await client.get(url)
    except httpx.TimeoutException:
        return await client.get(url)


async def fetch_pages(
    client: httpx.AsyncClient, urls: list[str], *, concurrency: int = 4
) -> list[FetchedPage]:
    """Fetch pages over plain HTTP; failures and non-HTML responses are dropped."""
    semaphore = asyncio.Semaphore(concurrency)

    async def one(url: str) -> FetchedPage | None:
        async with semaphore:
            try:
                resp = await get_once_more(client, url)
            except httpx.HTTPError:
                return None
        if "html" not in resp.headers.get("content-type", "html"):
            return None
        return FetchedPage(str(resp.url), resp.status_code, resp.text[:MAX_HTML_CHARS])

    results = await asyncio.gather(*(one(u) for u in urls))
    return [r for r in results if r is not None]


# --- sitemap ---------------------------------------------------------------------------

SITEMAP_PAGES = 2  # pages added from the sitemap on top of the links
_MAX_SITEMAPS = 4
_MAX_SITEMAP_BYTES = 5_000_000
_LOC = re.compile(r"<loc>\s*([^<\s]+)\s*</loc>", re.I)
_ROBOTS_SITEMAP = re.compile(r"(?im)^\s*sitemap\s*:\s*(\S+)")
# Pages where forms with personal data live (contacts, orders, cart, callback).
_FORM_PAGE_WEIGHT = 8
# In a bare path the keyword must open a short last segment (/kontakty, /cart,
# /contact-us): skillbox.ru's /course/vkontakte-promotion-specialist and
# /courses/vzaimodeistvie-s-zakazchikom are courses, not a contacts or order page.
_PATH_PRIORITY = tuple(
    (re.compile(rf"(?:{rx.pattern})[\w-]{{0,12}}$", re.I), w) for rx, w in _PRIORITY
)


def _absolute(origin: str, url: str) -> str | None:
    """A sitemap address from robots.txt or an index as an absolute http(s) URL, or None.
    Sites write relative paths ("Sitemap: /sitemap.xml") and broken ones ("http://[::1",
    lone surrogates): fuzzing found that one such line in robots.txt crashed the scan."""
    try:
        url.encode("utf-8")
        full = urljoin(origin + "/", url)
        parts = urlsplit(full)
        parts.hostname  # noqa: B018  (validates the brackets of an IPv6 host)
    except (ValueError, UnicodeError):
        return None
    return full if parts.scheme in ("http", "https") and parts.netloc else None


def _host(url: str) -> str:
    try:
        return _bare(urlsplit(url).hostname or "")
    except ValueError:
        return ""


async def sitemap_urls(client: httpx.AsyncClient, base: str) -> list[str]:
    """Page URLs from the site's sitemap: the one robots.txt names, else /sitemap.xml;
    an index is followed one level. Compressed (.gz) sitemaps are skipped."""
    parts = urlsplit(base)
    origin = f"{parts.scheme}://{parts.netloc}"
    queue: list[str] = []
    try:
        robots = await client.get(f"{origin}/robots.txt")
        if robots.status_code == 200:
            queue = _ROBOTS_SITEMAP.findall(robots.text[:200_000])
    except httpx.HTTPError:
        pass
    queue = queue or [f"{origin}/sitemap.xml"]
    pages: list[str] = []
    fetched = 0
    site = _bare(parts.hostname or "")
    while queue and fetched < _MAX_SITEMAPS:
        url = _absolute(origin, queue.pop(0))
        # robots.txt and a sitemap index are the site's words: they may not send the
        # scanner to another host.
        if url is None or url.lower().endswith(".gz") or _host(url) != site:
            continue
        fetched += 1
        try:
            resp = await client.get(url)
        except (httpx.HTTPError, httpx.InvalidURL):
            continue
        if resp.status_code != 200:
            continue
        text = resp.text[:_MAX_SITEMAP_BYTES]
        locs = [loc.replace("&amp;", "&") for loc in _LOC.findall(text)]
        if "<sitemapindex" in text[:2000].lower():
            queue += locs
        else:
            pages += locs
    return pages


def pick_from_sitemap(
    urls: list[str], base: str, skip: set[str], limit: int = SITEMAP_PAGES
) -> list[str]:
    """Form pages (contacts, order, cart, callback) the home page doesn't link to."""
    site = _bare(urlsplit(base).hostname or "")
    seen = {_normalize(base), *(_normalize(u) for u in skip)}
    scored: list[tuple[int, int, str]] = []
    for url in urls:
        try:
            parts = urlsplit(url)
        except ValueError:  # "http://[::1" in a sitemap: not a page
            continue
        if parts.scheme not in ("http", "https") or _bare(parts.hostname or "") != site:
            continue
        if _SKIP_EXT.search(parts.path) or _SKIP_PATH.search(parts.path):
            continue
        key = _normalize(url)
        last = parts.path.rstrip("/").rsplit("/", 1)[-1]
        weight = max((w for rx, w in _PATH_PRIORITY if rx.match(last)), default=0)
        if key in seen or weight < _FORM_PAGE_WEIGHT:
            continue
        seen.add(key)
        # Shallow paths first: /contacts rather than /blog/2019/contacts-of-our-partners.
        scored.append((parts.path.count("/"), -weight, key))
    scored.sort()
    return [url for _, _, url in scored[:limit]]
