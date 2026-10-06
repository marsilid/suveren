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
    return [url for _, _, url in scored[:limit]]


async def fetch_pages(
    client: httpx.AsyncClient, urls: list[str], *, concurrency: int = 4
) -> list[FetchedPage]:
    """Fetch pages over plain HTTP; failures and non-HTML responses are dropped."""
    semaphore = asyncio.Semaphore(concurrency)

    async def one(url: str) -> FetchedPage | None:
        async with semaphore:
            try:
                resp = await client.get(url)
            except httpx.HTTPError:
                return None
        if "html" not in resp.headers.get("content-type", "html"):
            return None
        return FetchedPage(str(resp.url), resp.status_code, resp.text[:MAX_HTML_CHARS])

    results = await asyncio.gather(*(one(u) for u in urls))
    return [r for r in results if r is not None]
