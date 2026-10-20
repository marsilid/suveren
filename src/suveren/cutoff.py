"""What breaks if foreign services are cut off: an experiment, not a guess.

Two levels:

* infrastructure, from what the scan found: foreign DNS, hosting, CDN or site builder
  take the whole site down; foreign mail takes the mail;
* the page, measured in a real browser: the page is opened twice as usual and once
  with every request to a foreign service refused, as when a provider cuts Russia off
  or Russia blocks it. Only what is the same in both normal loads counts, so
  carousels, rotating banners and A/B tests are not reported as "broken".

Which hosts are foreign: the service database first (by the request URL), then the
network the host's address belongs to (Team Cymru). The site's own domain is never
blocked: losing it is the infrastructure level. Hosts whose country is unknown are not
blocked and are listed. Everything stays passive: the page is only opened.
"""

from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

from suveren.checks import Check, Status
from suveren.models import Category, Dependency
from suveren.services import by_network, scan_page
from suveren.utils import country_name, registrable_domain

GROUP_CUT = "Отключение иностранных сервисов"
INFRA_TITLE = "Отключение: сайт и почта целиком"
PAGE_TITLE = "Отключение: что перестанет работать на странице"

WHOLE_SITE = (Category.DNS, Category.HOSTING, Category.CDN, Category.BUILDER)
MAX_HOSTS = 40
SHOWN = 8

# Thresholds of a "problem": what a visitor clearly notices.
CONTROLS_GONE = 3  # buttons and links that vanished
TEXT_DROP = 0.3  # share of the page text that vanished
VISUAL_CHANGE = 0.25  # share of the first screen that changed, beyond normal noise


@dataclass(frozen=True, slots=True)
class HostInfo:
    host: str
    service: str | None
    country: str | None
    via_network: bool = False  # the owner is the network the host is in (Cloudflare...)

    @property
    def foreign(self) -> bool | None:
        return None if not self.country else self.country.upper() != "RU"

    def label(self) -> str:
        country = country_name(self.country) if self.country else ""
        if self.via_network or not self.service:
            via = f"через {self.service}, " if self.service else ""
            return f"{self.host} ({via}{country})" if country else self.host
        return f"{self.service} ({country})" if country else self.service


def third_party_hosts(urls: list[str], site: str) -> list[str]:
    own = registrable_domain(site)
    hosts: list[str] = []
    for url in urls:
        parts = urlsplit(url)
        host = (parts.hostname or "").lower()
        if parts.scheme not in ("http", "https") or not host or host in hosts:
            continue
        if registrable_domain(host) != own:
            hosts.append(host)
    return hosts[:MAX_HOSTS]


def known_service(url: str) -> HostInfo | None:
    """The host's owner from the service database, if a page pattern matches the URL."""
    found = scan_page(url)
    if not found:
        return None
    service = found[0][0]
    return HostInfo((urlsplit(url).hostname or "").lower(), service.name, service.country)


async def classify(urls: list[str], site: str, collector: Any) -> dict[str, HostInfo]:
    """host -> owner and country, for every third-party host the page loaded."""
    first_url: dict[str, str] = {}
    for url in urls:
        host = (urlsplit(url).hostname or "").lower()
        first_url.setdefault(host, url)
    result: dict[str, HostInfo] = {}
    unknown: list[str] = []
    for host in third_party_hosts(urls, site):
        info = known_service(first_url[host]) or known_service(f"https://{host}/")
        if info:
            result[host] = HostInfo(host, info.service, info.country)
        else:
            unknown.append(host)

    async def by_net(host: str) -> HostInfo:
        try:
            infos = await collector._host_infos(host)
        except Exception:  # a lookup failure only leaves the host unclassified
            return HostInfo(host, None, None)
        nets = [i.net for i in infos if i.net is not None]
        if not nets:
            return HostInfo(host, None, None)
        net = nets[0]
        service = by_network(net.asn, net.as_name)
        if service is not None:
            return HostInfo(host, service.name, service.country, via_network=True)
        return HostInfo(host, net.as_name, net.country, via_network=True)

    for info in await asyncio.gather(*(by_net(h) for h in unknown)):
        result[info.host] = info
    return result


# --- infrastructure ---------------------------------------------------------------------


def infra_check(deps: list[Dependency]) -> Check:
    whole = [d for d in deps if d.foreign and d.category in WHOLE_SITE]
    mail = [d for d in deps if d.foreign and d.category is Category.MAIL]
    parts = []
    if whole:
        by_category: dict[str, list[str]] = {}
        for d in whole:
            by_category.setdefault(d.category.title, [])
            if d.service not in by_category[d.category.title]:
                by_category[d.category.title].append(d.service)
        names = "; ".join(f"{c} ({', '.join(s)})" for c, s in by_category.items())
        parts.append(f"Сайт перестанет открываться целиком: {names}.")
    if mail:
        names = ", ".join(dict.fromkeys(d.service for d in mail))
        parts.append(f"Перестанет работать почта домена ({names}).")
    if not parts:
        return Check(
            GROUP_CUT,
            INFRA_TITLE,
            Status.OK,
            "DNS, хостинг и почта у российских провайдеров: отключение иностранных сервисов "
            "не выключит сайт и почту целиком.",
        )
    return Check(
        GROUP_CUT,
        INFRA_TITLE,
        Status.FAIL if whole else Status.WARN,
        " ".join(parts),
        "Перенесите то, без чего сайт не откроется, к российским провайдерам: DNS, хостинг "
        "и CDN в первую очередь. Варианты — в разделе «Иностранные зависимости».",
    )


# --- the page ---------------------------------------------------------------------------


@dataclass(slots=True)
class PageCutoff:
    """The page experiment, comparable without a browser (see compare())."""

    blocked: list[HostInfo] = field(default_factory=list)
    unknown: list[str] = field(default_factory=list)
    new_errors: list[str] = field(default_factory=list)
    gone_controls: list[str] = field(default_factory=list)
    gone_frames: list[HostInfo | str] = field(default_factory=list)
    new_broken_images: int = 0
    lost_fonts: list[str] = field(default_factory=list)
    captcha_forms: int = 0
    text_drop: float = 0.0
    visual_change: float | None = None
    render_blocking: list[str] = field(default_factory=list)
    slower_ms: int = 0

    @property
    def visible(self) -> bool:
        return bool(
            self.gone_controls
            or self.gone_frames
            or self.new_broken_images
            or self.lost_fonts
            or self.captcha_forms
            or self.text_drop >= 0.1
            or (self.visual_change or 0) >= 0.05
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "blocked": [{"host": h.host, "service": h.service, "country": h.country}
                        for h in self.blocked],
            "unknown_hosts": self.unknown,
            "new_js_errors": self.new_errors,
            "gone_controls": self.gone_controls,
            "gone_frames": [f.label() if isinstance(f, HostInfo) else f for f in self.gone_frames],
            "new_broken_images": self.new_broken_images,
            "lost_fonts": self.lost_fonts,
            "captcha_forms": self.captcha_forms,
            "text_drop": round(self.text_drop, 3),
            "visual_change": None if self.visual_change is None else round(self.visual_change, 3),
            "render_blocking": self.render_blocking,
        }  # fmt: skip


# Labels that change by themselves: relative times and counters ("+14", "1 234").
_NUMERIC = re.compile(r"^[\d\s+\-–.,:%×xк]+$", re.I)
_VOLATILE = re.compile(
    r"\d+\s*(?:сек|мин|час|дн|недел|месяц)\w*\.?\s+назад|^(?:вчера|сегодня|только что)\b|"
    r"\b\d+\s*(?:ago|min|hours?)\b",
    re.I,
)


def compare(
    base1: dict[str, Any],
    base2: dict[str, Any],
    cut: dict[str, Any],
    *,
    errors1: list[str],
    errors2: list[str],
    errors_cut: list[str],
    hosts: dict[str, HostInfo],
    blocked_hosts: set[str],
    noise: float | None = None,
    change: float | None = None,
) -> PageCutoff:
    """What is stable in both normal loads (``base1``, ``base2``: DOM features from
    render._DOM_FEATURES) and gone when foreign hosts are blocked (``cut``)."""
    result = PageCutoff(
        blocked=[hosts[h] for h in sorted(blocked_hosts) if h in hosts],
        unknown=sorted(h for h, i in hosts.items() if i.foreign is None),
    )
    normal_errors = set(errors1) | set(errors2)
    result.new_errors = list(dict.fromkeys(e for e in errors_cut if e not in normal_errors))

    stable = set(base1.get("controls", [])) & set(base2.get("controls", []))
    after = set(cut.get("controls", []))
    # Labels with words first: "Оплатить" says more than "Beget 1129.39".
    result.gone_controls = sorted(
        (c for c in stable - after if not _VOLATILE.search(c) and not _NUMERIC.match(c)),
        key=lambda c: (bool(re.search(r"\d", c)), c.lower()),
    )

    frames_after = list(cut.get("frames", []))
    for host in base1.get("frames", []):
        if host in base2.get("frames", []) and host not in frames_after:
            result.gone_frames.append(hosts.get(host) or host or "встроенный блок")
        elif host in frames_after:
            frames_after.remove(host)

    broken_before = max(base1.get("broken", 0), base2.get("broken", 0))
    result.new_broken_images = max(0, cut.get("broken", 0) - broken_before)
    fonts_stable = set(base1.get("fonts", [])) & set(base2.get("fonts", []))
    result.lost_fonts = sorted(fonts_stable - set(cut.get("fonts", [])))

    captcha_before = sum(1 for f in base1.get("forms", []) if f.get("captcha"))
    captcha_after = sum(1 for f in cut.get("forms", []) if f.get("captcha"))
    captcha_blocked = any(
        re.search(r"recaptcha|google|hcaptcha|cloudflare|turnstile", h) for h in blocked_hosts
    )
    if captcha_blocked:
        result.captcha_forms = max(captcha_before, captcha_after)

    text = min(base1.get("text", 0), base2.get("text", 0))
    if text > 200:
        result.text_drop = max(0.0, (text - cut.get("text", 0)) / text)
    if change is not None:
        result.visual_change = max(0.0, change - (noise or 0.0))
    return result


_HEAD = re.compile(r"<head\b.*?</head>", re.I | re.S)
_STYLESHEET = re.compile(r"<link\b[^>]*rel=[\"']?stylesheet[^>]*>", re.I)
_SCRIPT = re.compile(r"<script\b[^>]*\bsrc=[^>]*>", re.I)
_HREF = re.compile(r"\b(?:href|src)=[\"']?([^\"'\s>]+)", re.I)


def render_blocking(html: str, base_url: str, foreign: set[str]) -> list[str]:
    """Foreign stylesheets and synchronous scripts in <head>: if such a resource hangs
    (a block often drops packets rather than refusing), the page stays blank until the
    browser gives up."""
    head = _HEAD.search(html)
    if not head:
        return []
    found: list[str] = []
    tags = _STYLESHEET.findall(head.group(0)) + [
        t for t in _SCRIPT.findall(head.group(0))
        if not re.search(r"\b(?:async|defer)\b|type=[\"']?module", t, re.I)
    ]  # fmt: skip
    for tag in tags:
        m = _HREF.search(tag)
        if not m:
            continue
        url = m.group(1)
        url = "https:" + url if url.startswith("//") else url
        host = (urlsplit(url).hostname or "").lower()
        if host in foreign and host not in found:
            found.append(host)
    return found


def _list(items: list[str]) -> str:
    shown = ", ".join(f"«{i}»" for i in items[:SHOWN])
    return shown + (f" и ещё {len(items) - SHOWN}" if len(items) > SHOWN else "")


def page_check(r: PageCutoff, hosts: dict[str, HostInfo]) -> Check:
    if not r.blocked:
        return Check(
            GROUP_CUT,
            PAGE_TITLE,
            Status.OK,
            "Страница не загружает ничего с иностранных сервисов: отключать нечего.",
        )
    names = ", ".join(dict.fromkeys(h.label() for h in r.blocked[:SHOWN]))
    more = f" и ещё {len(r.blocked) - SHOWN}" if len(r.blocked) > SHOWN else ""
    lines = [f"Страницу открыли без иностранных сервисов ({names}{more})."]
    if r.new_errors:
        lines.append(
            f"Код сайта падает с ошибками JavaScript ({len(r.new_errors)}): "
            f"{r.new_errors[0]}. Из-за этого может не работать то, что выглядит целым."
        )
    if r.captcha_forms:
        lines.append(
            f"Формы с капчей ({r.captcha_forms}) не отправятся: капча грузится с "
            "иностранного сервиса."
        )
    if r.gone_controls:
        lines.append(f"Пропали кнопки и ссылки: {_list(r.gone_controls)}.")
    if r.gone_frames:
        frames = [f.label() if isinstance(f, HostInfo) else f for f in r.gone_frames]
        lines.append(f"Пропали встроенные блоки (карты, видео, виджеты): {', '.join(frames)}.")
    if r.new_broken_images:
        lines.append(f"Не загрузились картинки: {r.new_broken_images}.")
    if r.lost_fonts:
        lines.append(f"Шрифты заменятся системными: {', '.join(r.lost_fonts[:SHOWN])}.")
    if r.text_drop >= 0.1:
        lines.append(f"Пропало {round(r.text_drop * 100)}% текста страницы.")
    if r.visual_change is not None and r.visual_change >= 0.05:
        lines.append(f"Первый экран изменился на {round(r.visual_change * 100)}%.")
    if r.render_blocking:
        lines.append(
            "Если эти сервисы не откажут, а зависнут, страница останется белой, пока браузер "
            f"их ждёт: в <head> они грузятся до показа страницы ({', '.join(r.render_blocking)})."
        )
    severe = bool(
        r.captcha_forms
        or (r.new_errors and (len(r.gone_controls) >= CONTROLS_GONE or r.text_drop >= TEXT_DROP))
        or r.text_drop >= TEXT_DROP
        or (r.visual_change or 0) >= VISUAL_CHANGE
    )
    if not r.visible and not r.new_errors:
        lines.append("Заметных изменений нет: страница работает и без них.")
        status = Status.WARN if r.render_blocking else Status.OK
    else:
        status = Status.FAIL if severe else Status.WARN
    if r.unknown:
        lines.append(
            f"Не удалось определить страну: {', '.join(r.unknown[:SHOWN])} — их не отключали."
        )
    return Check(
        GROUP_CUT,
        PAGE_TITLE,
        status,
        " ".join(lines),
        _advice(r) if status is not Status.OK else "",
    )


def _advice(r: PageCutoff) -> str:
    """Only the fixes for what actually broke."""
    steps = []
    if r.new_errors or r.lost_fonts:
        steps.append("библиотеки и шрифты — соберите в сам сайт, а не грузите с чужих CDN")
    if r.new_broken_images:
        steps.append("картинки — на свой сервер или российский CDN")
    if r.captcha_forms:
        steps.append("капчу — замените на Yandex SmartCaptcha")
    if r.gone_frames:
        steps.append("карты и видео — Яндекс Карты, 2ГИС, VK Видео или Rutube")
    if r.gone_controls and not steps:
        steps.append("кнопки и блоки, которые пропали, — перенесите на свой сервер")
    text = "Перенесите то, без чего страница ломается: " + "; ".join(steps) + "." if steps else ""
    if r.render_blocking:
        text += " Скрипты и стили из <head> подключайте с async/defer или со своего сервера."
    return text.strip() or "Перенесите эти сервисы на свой сервер или к российским провайдерам."


async def run_cutoff(
    url: str, site: str, collector: Any, *, timeout: float = 25.0
) -> tuple[Check, PageCutoff, dict[str, bytes]]:
    """Open ``url`` three times (twice as usual, once with foreign hosts refused) and
    compare. Returns the check, the details and two screenshots (before, after)."""
    from suveren.render import BrowserSession

    async with BrowserSession(timeout=timeout) as session:
        base1 = await session.probe(url)
        hosts = await classify(base1.requests, site, collector)
        foreign = {h for h, i in hosts.items() if i.foreign}

        def block(request_url: str) -> bool:
            return (urlsplit(request_url).hostname or "").lower() in foreign

        # Normal, cut off, normal again: what changed on its own during the experiment
        # (a news feed, "5 минут назад") differs between the two normal loads.
        cut = await session.probe(url, block=block)
        base2 = await session.probe(url)
        noise = change = None
        if base1.screenshot and base2.screenshot and cut.screenshot:
            noise = await session.image_diff(base1.screenshot, base2.screenshot)
            change = await session.image_diff(base1.screenshot, cut.screenshot)
    blocked = {(urlsplit(u).hostname or "").lower() for u in cut.blocked}
    result = compare(
        base1.dom,
        base2.dom,
        cut.dom,
        errors1=base1.errors,
        errors2=base2.errors,
        errors_cut=cut.errors,
        hosts=hosts,
        blocked_hosts=blocked,
        noise=noise,
        change=change,
    )
    result.render_blocking = render_blocking(base1.html, base1.final_url, foreign)
    result.slower_ms = max(0, cut.ready_ms - max(base1.ready_ms, base2.ready_ms))
    shots = {"before": base1.screenshot, "after": cut.screenshot}
    return page_check(result, hosts), result, shots
