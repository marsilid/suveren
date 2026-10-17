"""Find the company's ИНН on its website: home page, then contacts/requisites pages."""

from __future__ import annotations

import re
from urllib.parse import urljoin, urlsplit

import httpx

from suveren.inn import find_inns
from suveren.page import Page, parse_page
from suveren.utils import registrable_domain

_CONTACT_TEXT = re.compile(
    r"реквизит|контакт|о компании|о нас|юридическ|правов|requisites|contacts?|about", re.I
)
# The site's own details live on these pages; an ИНН in an article, a company blog
# (/companies/haulmont/news/...), a product card or a review belongs to someone else.
_REQUISITES_PATH = re.compile(
    r"/(?:rekvizit\w*|requisites?|contacts?|kontakt\w*|about(?:-us)?|o-nas|o-kompanii|company"
    r"|oferta|offer|legal|privacy(?:-policy)?|policy|politika\w*)(?:\.\w{2,4})?/?$",
    re.I,
)
MAX_EXTRA_PAGES = 3


def contact_links(page: Page, base: str) -> list[str]:
    """Same-site links that usually carry company details, best first."""
    site = registrable_domain(urlsplit(base).hostname or "")
    scored: dict[str, int] = {}
    for link in page.links:
        href = link.href.strip()
        if not href or href.startswith(("#", "javascript:", "mailto:", "tel:")):
            continue
        url = urljoin(base, href).split("#", 1)[0]
        host = urlsplit(url).hostname or ""
        if registrable_domain(host) != site or url.rstrip("/") == base.rstrip("/"):
            continue
        score = 0
        if "реквизит" in link.text.lower() or "rekvizit" in href or "requisites" in href:
            score += 3
        if _CONTACT_TEXT.search(link.text):
            score += 2
        if is_requisites_path(urlsplit(url).path):
            score += 1
        if score:
            scored[url] = max(score, scored.get(url, 0))
    return [url for url, _ in sorted(scored.items(), key=lambda item: -item[1])]


def is_requisites_path(path: str) -> bool:
    """Whether the page at ``path`` is where a site states its own company details."""
    return bool(_REQUISITES_PATH.search(path))


async def discover_inns(
    client: httpx.AsyncClient, base: str, html: str, extra_text: str = ""
) -> tuple[list[str], str | None]:
    """Return (ИНН list, URL where they were found). ``extra_text`` must come only from
    the site's own documents (policy, contacts, requisites), not from any inner page."""
    inns = find_inns(html + " " + extra_text)
    if inns:
        return inns, base
    for url in contact_links(parse_page(html), base)[:MAX_EXTRA_PAGES]:
        try:
            resp = await client.get(url)
        except httpx.HTTPError:
            continue
        if resp.status_code != 200:
            continue
        inns = find_inns(resp.text[:3_000_000])
        if inns:
            return inns, str(resp.url)
    return [], None
