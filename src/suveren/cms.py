"""Which CMS the site runs on (WordPress, 1C-Bitrix) and its version, when the pages
already loaded show it: the generator tag, the paths of the CMS's own files. No extra
requests to the site.

The version is shown, never judged: there is no open vulnerability database of WordPress
and 1C-Bitrix versions that works without an API key, so the answer is "не ясно" with
what to check by hand, not "уязвимо" or "в порядке".
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urljoin, urlsplit

from suveren.checks import Check, Evidence, Status
from suveren.utils import registrable_domain

TITLE = "Версия CMS"
GROUP_WEB = "Безопасность сайта"

_V = r"(\d+\.\d+(?:\.\d+)?)"
_META = re.compile(r"(?is)<meta\b[^>]*>")
_ATTR = re.compile(r"""(?is)\b(name|content)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))""")
_LINK = re.compile(r"""(?is)\b(?:src|href)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>"']+))""")
# WordPress stamps its own version on a few core files; others in wp-includes carry the
# version of a bundled library (jquery.min.js?ver=3.7.1), so only these count.
_WP_FILE = re.compile(
    r"/wp-includes/(?:js/wp-emoji-release\.min\.js|js/wp-embed(?:\.min)?\.js"
    rf"|css/dist/block-library/style(?:\.min)?\.css)\?ver={_V}(?:[&#]|$)"
)
_WP_PATH = re.compile(r"/wp-(?:content|includes)/")
_BITRIX_PATH = re.compile(r"/bitrix/(?:js|templates|cache|css|components|tools)/")

NAMES = {"wordpress": "WordPress", "bitrix": "1С-Битрикс"}
ADVICE = {
    "wordpress": "Сверьте версию со списком выпусков на wordpress.org/download/releases: "
    "если она не последняя в своей ветке, обновите WordPress, темы и плагины. Номер версии в "
    "теге generator лучше убрать: он подсказывает, какие уязвимости пробовать.",
    "bitrix": "Проверьте в панели управления («Marketplace» → «Обновление платформы»), что "
    "установлены все обновления: исправления уязвимостей 1С-Битрикс приходят через них.",
}


@dataclass(slots=True)
class Cms:
    name: str  # key in NAMES
    version: str | None = None
    signs: list[Evidence] | None = None


def _generators(html: str) -> list[str]:
    found = []
    for tag in _META.findall(html):
        attrs: dict[str, str] = {}
        for m in _ATTR.finditer(tag):
            attrs[m.group(1).lower()] = next(g for g in m.groups()[1:] if g is not None)
        if attrs.get("name", "").strip().lower() == "generator" and attrs.get("content"):
            found.append(attrs["content"].strip())
    return found


def _own_links(html: str, base: str, domain: str) -> list[str]:
    """Addresses in src and href that lead to the site itself: a picture from another
    site's /wp-content/ says nothing about this one."""
    out = []
    for m in _LINK.finditer(html):
        raw = next(g for g in m.groups() if g is not None).replace("&amp;", "&")
        url = urljoin(base, raw.strip())
        host = urlsplit(url).hostname or ""
        if host and registrable_domain(host) == domain:
            out.append(url)
    return out


def detect_cms(pages: list[tuple[str, str]], base: str, domain: str) -> list[Cms]:
    """CMSes seen on the pages (where, html), each with its version if a page shows it."""
    found: dict[str, Cms] = {}

    def add(name: str, version: str | None, sign: Evidence) -> None:
        cms = found.setdefault(name, Cms(name, None, []))
        assert cms.signs is not None
        if sign.value in {s.value for s in cms.signs}:
            return
        if version and not cms.version:
            cms.version = version
            cms.signs.insert(0, sign)  # the sign the version was read from comes first
        elif len(cms.signs) < 3:
            cms.signs.append(sign)

    for where, html in pages:
        for content in _generators(html):
            # WordPress.com is a hosted service, updated by its owner, not the site's CMS.
            if re.match(r"(?i)wordpress(?!\.com)\b", content):
                m = re.match(rf"(?i)wordpress\s+{_V}", content)
                add(
                    "wordpress",
                    m.group(1) if m else None,
                    Evidence("html", f"Тег generator (страница {where})", content),
                )
            elif re.search(r"(?i)1c-bitrix|bitrix site manager|битрикс", content):
                m = re.search(_V, content)
                add(
                    "bitrix",
                    m.group(1) if m else None,
                    Evidence("html", f"Тег generator (страница {where})", content),
                )
        for url in _own_links(html, base, domain):
            parts = urlsplit(url)
            path = parts.path
            if m := _WP_FILE.search(f"{path}?{parts.query}"):
                add(
                    "wordpress",
                    m.group(1),
                    Evidence("url", f"Файл WordPress (страница {where})", url),
                )
            elif _WP_PATH.search(path):
                add("wordpress", None, Evidence("url", f"Путь WordPress (страница {where})", url))
            elif _BITRIX_PATH.search(path):
                add("bitrix", None, Evidence("url", f"Путь 1С-Битрикс (страница {where})", url))
    return list(found.values())


def cms_check(found: list[Cms]) -> Check | None:
    """ "Не ясно" with the version, or no check when no CMS is seen."""
    if not found:
        return None
    parts = []
    for cms in found:
        name = NAMES[cms.name]
        parts.append(
            f"{name} {cms.version}" if cms.version else f"{name} (версия снаружи не видна)"
        )
    shown = [c for c in found if c.version]
    details = f"Сайт работает на {', '.join(parts)}. "
    if shown:
        details += (
            "Есть ли у этой версии известные уязвимости, Suveren не проверяет: открытой базы "
            "уязвимостей по версиям WordPress и 1С-Битрикс без ключа API нет, а гадать он не "
            "будет."
        )
    else:
        details += (
            "Номер версии на страницах не указан, поэтому об уязвимостях ничего сказать нельзя."
        )
    check = Check(
        GROUP_WEB,
        TITLE,
        Status.UNKNOWN,
        details,
        " ".join(ADVICE[c.name] for c in found),
    )
    check.evidence = [s for c in found for s in (c.signs or [])][:6]
    return check
