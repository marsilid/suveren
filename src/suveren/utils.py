"""Small helpers: domain normalisation and country names."""

from __future__ import annotations

import re
from urllib.parse import urlsplit

from suveren.errors import InvalidTargetError

_LABEL_RE = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")

COUNTRY_NAMES = {
    "RU": "Россия",
    "US": "США",
    "DE": "Германия",
    "NL": "Нидерланды",
    "FR": "Франция",
    "GB": "Великобритания",
    "IE": "Ирландия",
    "FI": "Финляндия",
    # Offshore zones where foreign services often register (Telegram: VG).
    "VG": "Британские Виргинские острова",
    "KY": "Каймановы острова",
    "BZ": "Белиз",
    "PA": "Панама",
    "SC": "Сейшелы",
    "AZ": "Азербайджан",
    "TW": "Тайвань",
    "BR": "Бразилия",
    "MX": "Мексика",
    "ZA": "ЮАР",
    "GR": "Греция",
    "IS": "Исландия",
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
    """'example.co.uk' from 'www.shop.example.co.uk', by the Public Suffix List with its
    private section: 'mysite.github.io', not 'github.io' (psl.py)."""
    from suveren.psl import registrable

    return registrable(domain)


def host_matches(host: str, pattern: str) -> bool:
    """True if ``host`` is ``pattern`` or a subdomain of it. ``*`` is a wildcard."""
    host = host.lower().rstrip(".")
    if "*" in pattern:
        regex = re.escape(pattern).replace(r"\*", "[a-z0-9.-]*")
        return re.fullmatch(regex, host) is not None
    return host == pattern or host.endswith("." + pattern)


def plural(n: int, one: str, few: str, many: str) -> str:
    """Russian plural form: 1 домен, 2 домена, 5 доменов, 21 домен."""
    if n % 10 == 1 and n % 100 != 11:
        return one
    if 2 <= n % 10 <= 4 and not 12 <= n % 100 <= 14:
        return few
    return many


# C0 controls except tab and newline, DEL, C1 controls, and the bidi embeddings and
# isolates. A site's text (a quote from its policy, a consent label) with ESC sequences
# would otherwise reach the terminal: OSC 52 rewrites the clipboard, others the screen;
# bidi controls make "evil.ru" read as "ur.live".
_CONTROL = re.compile("[\x00-\x08\x0b-\x1f\x7f-\x9f\u202a-\u202e\u2066-\u2069]")


def clean_text(text: str) -> str:
    """Text from a site, safe to show: control characters and bidi controls removed."""
    return _CONTROL.sub("", text)
