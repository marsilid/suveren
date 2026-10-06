"""External domains that pages load but the service database doesn't know yet.

Every scan records them locally (nothing is sent anywhere); `suveren unknown`
lists the most frequent ones, which is the quickest way to grow the database.
"""

from __future__ import annotations

import contextlib
import json
import re
from collections.abc import Iterable
from datetime import date
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlsplit

from suveren.cache import cache_dir
from suveren.services import ALL_SERVICES
from suveren.utils import registrable_domain

_RESOURCE = re.compile(
    r"<(?:script|iframe|link|img|source|embed|video|audio)\b[^>]*?\s(?:src|href)\s*=\s*[\"']([^\"']+)",
    re.I,
)
_PATTERNS = tuple(rx for s in ALL_SERVICES for rx in s._page_re)
MAX_EXAMPLES = 5


def resource_urls(html: str, base: str) -> list[str]:
    """Absolute URLs of resources a page embeds (scripts, styles, frames, media)."""
    urls = []
    for raw in _RESOURCE.findall(html):
        if raw.startswith(("data:", "javascript:", "#", "mailto:")):
            continue
        urls.append(urljoin(base, raw))
    return urls


def _known(url: str) -> bool:
    text = url.lower()
    return any(rx.search(text) for rx in _PATTERNS)


def unknown_domains(urls: Iterable[str], site: str) -> set[str]:
    """Registrable domains of third-party URLs no service pattern recognises."""
    own = registrable_domain(site)
    found: set[str] = set()
    for url in urls:
        host = (urlsplit(url).hostname or "").lower()
        if not host or "." not in host or host.replace(".", "").isdigit():
            continue
        domain = registrable_domain(host)
        if domain == own or _known(url):
            continue
        found.add(domain)
    return found


def _store() -> Path:
    return cache_dir() / "unknown-hosts.json"


def load() -> dict[str, dict[str, Any]]:
    try:
        return json.loads(_store().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def record(domains: Iterable[str], site: str) -> None:
    """Add one scan's unknown domains to the local tally (best effort)."""
    domains = sorted(set(domains))
    if not domains:
        return
    data = load()
    today = date.today().isoformat()
    for domain in domains:
        entry = data.setdefault(domain, {"count": 0, "sites": [], "last": today})
        if site not in entry["sites"]:
            entry["count"] += 1
            if len(entry["sites"]) < MAX_EXAMPLES:
                entry["sites"].append(site)
        entry["last"] = today
    with contextlib.suppress(OSError):
        _store().parent.mkdir(parents=True, exist_ok=True)
        _store().write_text(json.dumps(data, ensure_ascii=False, indent=1), encoding="utf-8")


def clear() -> None:
    with contextlib.suppress(OSError):
        _store().unlink()
