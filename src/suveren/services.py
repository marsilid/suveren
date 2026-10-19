"""The service database: how to recognise a provider and where it is based.

Each :class:`Service` lists every trace it can leave:

* ``ns`` / ``mx`` — host suffixes of name servers and mail exchangers
  (``*`` is a wildcard: ``*awsdns-*`` matches ``ns-12.awsdns-34.com``);
* ``asn`` / ``as_names`` — the network an IP address belongs to (hosting, CDN);
* ``registrar`` / ``issuer`` — substrings of the registrar or TLS issuer name;
* ``page`` — regular expressions searched in the page HTML (lowercased),
  for scripts, fonts and widgets. Such services also set ``category``.

``country`` is the provider's jurisdiction, not the location of a data centre:
sanctions follow the company. The entries live in ``data/services.json``, data apart
from code: to add a service, add an entry there (with its country and how it is
recognised) and a test. ``tests/test_services.py`` checks every entry.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from importlib.resources import files
from typing import Any

from suveren.models import Category, Severity
from suveren.utils import host_matches


@dataclass(frozen=True)
class Service:
    name: str
    country: str
    category: Category | None = None
    ns: tuple[str, ...] = ()
    mx: tuple[str, ...] = ()
    asn: tuple[int, ...] = ()
    as_names: tuple[str, ...] = ()
    cdn: bool = False
    registrar: tuple[str, ...] = ()
    issuer: tuple[str, ...] = ()
    page: tuple[str, ...] = ()
    severity: Severity | None = None
    note: str = ""
    alternative: str = ""
    _page_re: tuple[re.Pattern[str], ...] = field(default=(), init=False, repr=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "_page_re", tuple(re.compile(p) for p in self.page))

    @property
    def foreign(self) -> bool:
        return self.country != "RU"


def _service(d: dict[str, Any]) -> Service:
    severity = d.get("severity")
    return Service(
        d["name"],
        d["country"],
        Category(d["category"]) if "category" in d else None,
        ns=tuple(d.get("ns", ())),
        mx=tuple(d.get("mx", ())),
        asn=tuple(d.get("asn", ())),
        as_names=tuple(d.get("as_names", ())),
        cdn=d.get("cdn", False),
        registrar=tuple(d.get("registrar", ())),
        issuer=tuple(d.get("issuer", ())),
        page=tuple(d.get("page", ())),
        severity=Severity[severity.upper()] if severity else None,
        note=d.get("note", ""),
        alternative=d.get("alternative", ""),
    )


def _load() -> dict[str, list[Service]]:
    raw = json.loads(files("suveren").joinpath("data/services.json").read_text("utf-8"))
    return {group: [_service(d) for d in raw[group]] for group in ("infra", "tls", "page")}


_DATA = _load()

INFRA_SERVICES: tuple[Service, ...] = tuple(_DATA["infra"])
TLS_SERVICES: tuple[Service, ...] = tuple(_DATA["tls"])
PAGE_SERVICES: tuple[Service, ...] = tuple(_DATA["page"])
ALL_SERVICES: tuple[Service, ...] = INFRA_SERVICES + TLS_SERVICES + PAGE_SERVICES
_WITH_PAGE_PATTERNS = tuple(s for s in ALL_SERVICES if s.page)

# Top-level domains run by Russian registries.
RU_ZONES = frozenset(
    {"ru", "su", "xn--p1ai", "xn--p1acf", "moscow", "xn--80adxhks", "tatar", "xn--d1acj3b"}
)
# Common generic zones: (registry, country of the registry operator).
GENERIC_ZONES: dict[str, tuple[str, str]] = {
    "com": ("Verisign", "US"),
    "net": ("Verisign", "US"),
    "org": ("Public Interest Registry", "US"),
    "info": ("Identity Digital", "US"),
    "biz": ("GoDaddy Registry", "US"),
    "io": ("Identity Digital", "US"),
    "app": ("Google Registry", "US"),
    "dev": ("Google Registry", "US"),
    "xyz": ("XYZ.com", "US"),
    "online": ("Radix", "AE"),
    "site": ("Radix", "AE"),
    "store": ("Radix", "AE"),
    "tech": ("Radix", "AE"),
    "space": ("Radix", "AE"),
    "website": ("Radix", "AE"),
    "pro": ("Identity Digital", "US"),
    "shop": ("GMO Registry", "JP"),
    "co": (".CO Internet", "CO"),
    "me": ("doMEn", "ME"),
    "ai": ("Government of Anguilla", "AI"),
}
_CCTLD_COUNTRY_FIX = {"uk": "GB", "eu": "EU"}


def zone_info(domain: str) -> tuple[str, str | None]:
    """Return (zone description, registry country or None if unknown)."""
    tld = domain.rsplit(".", 1)[-1].lower()
    shown = "." + (tld.encode("ascii").decode("idna") if tld.startswith("xn--") else tld)
    if tld in RU_ZONES:
        return f"{shown} — Координационный центр доменов .RU/.РФ", "RU"
    if tld in GENERIC_ZONES:
        registry, country = GENERIC_ZONES[tld]
        return f"{shown} — {registry}", country
    if len(tld) == 2 and tld.isalpha():
        return shown, _CCTLD_COUNTRY_FIX.get(tld, tld.upper())
    return shown, None


def by_ns(host: str) -> Service | None:
    return next((s for s in INFRA_SERVICES if any(host_matches(host, p) for p in s.ns)), None)


def by_mx(host: str) -> Service | None:
    return next((s for s in INFRA_SERVICES if any(host_matches(host, p) for p in s.mx)), None)


def by_network(asn: int | None, as_name: str | None) -> Service | None:
    if asn is not None:
        for s in INFRA_SERVICES:
            if asn in s.asn:
                return s
    name = (as_name or "").lower()
    if name:
        for s in INFRA_SERVICES:
            if any(marker in name for marker in s.as_names):
                return s
    return None


def by_registrar(registrar: str | None) -> Service | None:
    name = (registrar or "").lower()
    if not name:
        return None
    return next((s for s in INFRA_SERVICES if any(m in name for m in s.registrar)), None)


def by_issuer(issuer: str | None) -> Service | None:
    name = (issuer or "").lower()
    if not name:
        return None
    return next((s for s in TLS_SERVICES if any(m in name for m in s.issuer)), None)


MAX_MATCHES_CHECKED = 50


def scan_page(html: str, own_domain: str | None = None) -> list[tuple[Service, str]]:
    """Find page-level services in the HTML; returns (service, matched text) pairs.

    Matches that mention ``own_domain`` are the site's own hosts (beeline.ru linking
    to www.beeline.ru), not a dependency, and are skipped.
    """
    text = html.lower()
    own = (own_domain or "").lower()
    found: list[tuple[Service, str]] = []
    for service in _WITH_PAGE_PATTERNS:
        hit = _first_foreign_match(service, text, own)
        if hit is not None:
            found.append((service, hit))
    return found


def _first_foreign_match(service: Service, text: str, own: str) -> str | None:
    for regex in service._page_re:
        for n, match in enumerate(regex.finditer(text)):
            if n >= MAX_MATCHES_CHECKED:
                break
            matched = match.group(0)
            if not own or own not in matched:
                return matched
    return None
