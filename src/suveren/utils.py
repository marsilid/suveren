"""Small helpers: domain normalisation and country names."""

from __future__ import annotations

import re
from urllib.parse import urlsplit

from suveren.errors import InvalidTargetError

_LABEL_RE = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")

# Public suffixes with two labels that are common enough to matter. A full
# Public Suffix List would be more accurate; this keeps the tool dependency-free.
_TWO_LABEL_SUFFIXES = frozenset(
    {
        "co.uk",
        "org.uk",
        "com.au",
        "co.jp",
        "com.br",
        "com.tr",
        "com.cn",
        "co.il",
        "com.ua",
        "com.kz",
        "org.kz",
        "com.ru",
        "net.ru",
        "org.ru",
        "pp.ru",
        "msk.ru",
        "spb.ru",
        "com.by",
    }
)

COUNTRY_NAMES = {
    "RU": "Россия",
    "US": "США",
    "DE": "Германия",
    "NL": "Нидерланды",
    "FR": "Франция",
    "GB": "Великобритания",
    "IE": "Ирландия",
    "FI": "Финляндия",
    "SE": "Швеция",
    "LU": "Люксембург",
    "BE": "Бельгия",
    "AT": "Австрия",
    "CH": "Швейцария",
    "PL": "Польша",
    "CZ": "Чехия",
    "LT": "Литва",
    "LV": "Латвия",
    "EE": "Эстония",
    "SI": "Словения",
    "MT": "Мальта",
    "CY": "Кипр",
    "IL": "Израиль",
    "IN": "Индия",
    "CN": "Китай",
    "HK": "Гонконг",
    "SG": "Сингапур",
    "JP": "Япония",
    "CA": "Канада",
    "AU": "Австралия",
    "KZ": "Казахстан",
    "BY": "Беларусь",
    "AM": "Армения",
    "TR": "Турция",
    "AE": "ОАЭ",
    "BS": "Багамы",
    "CO": "Колумбия",
    "ME": "Черногория",
    "AI": "Ангилья",
    "KR": "Южная Корея",
    "UA": "Украина",
    "NO": "Норвегия",
    "DK": "Дания",
    "IT": "Италия",
    "ES": "Испания",
    "PT": "Португалия",
    "RO": "Румыния",
    "BG": "Болгария",
    "HU": "Венгрия",
    "MD": "Молдова",
    "GE": "Грузия",
    "UZ": "Узбекистан",
    "KG": "Киргизия",
    "RS": "Сербия",
    "EU": "ЕС",
}


def country_name(code: str | None) -> str:
    if not code:
        return "неизвестно"
    return COUNTRY_NAMES.get(code.upper(), code.upper())


def normalize_domain(raw: str) -> str:
    """Accept a domain or URL (IDN allowed) and return a lowercase ASCII hostname."""
    value = raw.strip().lower()
    if "://" in value:
        value = urlsplit(value).hostname or ""
    else:
        value = value.split("/", 1)[0].split(":", 1)[0]
    value = value.rstrip(".")

    try:
        value = value.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise InvalidTargetError(f"«{raw}» — это не доменное имя") from exc

    labels = value.split(".")
    if (
        len(labels) < 2
        or not all(_LABEL_RE.match(label) for label in labels)
        or labels[-1].isdigit()
    ):
        raise InvalidTargetError(f"«{raw}» — это не доменное имя")
    return value


def registrable_domain(domain: str) -> str:
    """Best-effort 'example.co.uk' from 'www.shop.example.co.uk'."""
    labels = domain.split(".")
    size = 3 if ".".join(labels[-2:]) in _TWO_LABEL_SUFFIXES else 2
    return ".".join(labels[-size:])


def host_matches(host: str, pattern: str) -> bool:
    """True if ``host`` is ``pattern`` or a subdomain of it. ``*`` is a wildcard."""
    host = host.lower().rstrip(".")
    if "*" in pattern:
        regex = re.escape(pattern).replace(r"\*", "[a-z0-9.-]*")
        return re.fullmatch(regex, host) is not None
    return host == pattern or host.endswith("." + pattern)
