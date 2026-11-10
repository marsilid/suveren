"""Code that programs on the operator's own computer put into every page.

An antivirus that checks web traffic (Kaspersky) or a system-wide ad blocker
(AdGuard for Windows and macOS) adds its own script to each page the browser opens.
In --browser mode that script came out as code the site loads: "Кто подключает
сторонний код" showed kaspersky-labs.com (DVORYAN, 2.2.2). It says something about
the machine the check ran on, not about the site, so it is taken out of what the
browser saw, and the report says in one line that such a program is at work.

Only hosts known for certain to be injected locally are listed. ESET and Dr.Web filter
traffic too, but no address of a script they add to pages is confirmed; one goes here
when a report shows it.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING
from urllib.parse import urlsplit

from suveren.crawl import FetchedPage

if TYPE_CHECKING:
    from suveren.collect import Facts

# host suffix -> program
HOSTS: dict[str, str] = {
    # gc.kis.v2.scr.kaspersky-labs.com/<id>/main.js and the like: Kaspersky Internet
    # Security, Total Security, Standard/Plus/Premium.
    "kaspersky-labs.com": "Kaspersky",
    # https://local.adguard.org/?ts=…&type=content-script: AdGuard's own local address.
    "local.adguard.org": "AdGuard",
}

# <script src=…>, <link href=…> (the injected styles), with the closing tag if any.
_TAG = re.compile(
    r"<(script|link)\b[^>]*?\b(?:src|href)\s*=\s*[\"']?([^\"'\s>]+)[^>]*>(?:\s*</\1\s*>)?",
    re.IGNORECASE,
)


def program_of(url: str) -> str | None:
    """The local program that injected ``url``, or None for anything else."""
    host = (urlsplit(url).hostname or "").lower().rstrip(".")
    for suffix, name in HOSTS.items():
        if host == suffix or host.endswith("." + suffix):
            return name
    return None


def scrub_html(html: str, found: set[str]) -> str:
    """``html`` without the tags that load a local program's code; names go to ``found``."""

    def drop(m: re.Match[str]) -> str:
        name = program_of(m.group(2))
        if name is None:
            return m.group(0)
        found.add(name)
        return ""

    return _TAG.sub(drop, html)


def scrub_urls(urls: list[str], found: set[str]) -> list[str]:
    kept = []
    for url in urls:
        name = program_of(url)
        if name:
            found.add(name)
        else:
            kept.append(url)
    return kept


def _scrub_page(page: FetchedPage, found: set[str]) -> FetchedPage:
    return FetchedPage(
        page.url, page.status, scrub_html(page.html, found), scrub_urls(page.loaded_urls, found)
    )


def clean(facts: Facts) -> None:
    """Take the local programs' code out of what the browser saw, and say so once."""
    found: set[str] = set()
    facts.html = scrub_html(facts.html, found)
    facts.loaded_urls = scrub_urls(facts.loaded_urls, found)
    initiators = {}
    for script, loader in facts.initiators.items():
        # What the program's script loads is the program's doing too.
        name = program_of(script) or (program_of(loader) if loader else None)
        if name:
            found.add(name)
            continue
        initiators[script] = loader
    facts.initiators = initiators
    facts.extra_pages = [_scrub_page(p, found) for p in facts.extra_pages]
    facts.prefetched = {u: _scrub_page(p, found) for u, p in facts.prefetched.items()}
    if found:
        facts.notes.append(
            f"На компьютере, с которого шла проверка, работает программа, которая вставляет "
            f"свой код в страницы ({', '.join(sorted(found))}). Этот код не учтён как код сайта."
        )
