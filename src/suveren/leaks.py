"""Keys and secrets in the site's own JavaScript: what every visitor's browser receives.

Passive: only the scripts the page itself loads from the site's domain, and the
scripts written into its HTML, are read; nothing is guessed or probed. Libraries from
other companies' CDNs are not the site's secrets and are skipped.

Two kinds of findings:

* a secret that must never reach a browser (a private key, a bot token, a server API
  key): a problem — whoever opens the site can use it;
* a key that is public by design but must be restricted (a Google API key): a warning.

Values are masked everywhere (AKIA…7Q): the report must not leak them further.
Signatures follow the providers' documented key formats (AWS, GitHub, Stripe, Slack,
Telegram, OpenAI, Anthropic, SendGrid, Yandex), as in gitleaks and GitHub secret
scanning; placeholders ("your-key", "xxxx") are ignored.
"""

from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass
from typing import Any

import httpx

from suveren.checks import Check, Status

TITLE = "Ключи и секреты в коде сайта"
GROUP_WEB = "Безопасность сайта"
MAX_SCRIPTS = 15
MAX_BYTES = 3_000_000
HEAD_CHARS = 6000  # where a library's banner and version are
SHOWN = 6


@dataclass(frozen=True, slots=True)
class Signature:
    name: str
    regex: re.Pattern[str]
    secret: bool  # True: must never be public; False: public but must be restricted


def _sig(name: str, pattern: str, secret: bool = True) -> Signature:
    return Signature(name, re.compile(pattern), secret)


SIGNATURES = (
    _sig("приватный ключ", r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----"),
    _sig("ключ доступа AWS", r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    _sig("секретный ключ Stripe", r"\b[sr]k_live_[0-9a-zA-Z]{24,}\b"),
    _sig("токен GitHub", r"\b(?:gh[pousr]_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{60,})\b"),
    _sig("токен Slack", r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b"),
    _sig("вебхук Slack", r"hooks\.slack\.com/services/T[0-9A-Z]{6,}/B[0-9A-Z]{6,}/[0-9A-Za-z]{20,}"),  # noqa: E501
    # In code it sits in a URL, ".../bot123:AA...": no word boundary before the digits.
    _sig("токен Telegram-бота", r"(?<!\d)\d{8,10}:AA[0-9A-Za-z_-]{33}(?![0-9A-Za-z_-])"),
    _sig("ключ OpenAI", r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}T3BlbkFJ[A-Za-z0-9_-]{20,}"),
    _sig("ключ Anthropic", r"\bsk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_-]{80,}"),
    _sig("ключ SendGrid", r"\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b"),
    _sig("OAuth-токен Яндекса", r"\by0_[A-Za-z0-9_-]{55,}"),
    _sig("API-ключ Yandex Cloud", r"\bAQVN[A-Za-z0-9_-]{35,}"),
    _sig("ключ Google API", r"\bAIza[0-9A-Za-z_-]{35}\b", secret=False),
)  # fmt: skip

_PLACEHOLDER = re.compile(r"x{5,}|X{5,}|example|your|dummy|placeholder|sample|0{10,}", re.I)
_INLINE = re.compile(r"<script\b(?![^>]*\bsrc=)[^>]*>(.*?)</script\s*>", re.I | re.S)


@dataclass(frozen=True, slots=True)
class Leak:
    kind: str
    masked: str
    where: str
    secret: bool

    def to_dict(self) -> dict[str, Any]:
        return {"kind": self.kind, "value": self.masked, "where": self.where, "secret": self.secret}


def mask(value: str) -> str:
    """Enough to find the key in the code, not enough to use it."""
    if value.startswith("-----BEGIN"):
        return value
    return f"{value[:4]}…{value[-2:]}" if len(value) > 10 else "…"


def find_leaks(text: str, where: str) -> list[Leak]:
    found: list[Leak] = []
    seen: set[str] = set()
    for sig in SIGNATURES:
        for m in sig.regex.finditer(text):
            value = m.group(0)
            if value in seen or _PLACEHOLDER.search(value):
                continue
            seen.add(value)
            found.append(Leak(sig.name, mask(value), where, sig.secret))
    return found


def inline_scripts(html: str) -> str:
    return "\n".join(m.group(1) for m in _INLINE.finditer(html))


async def scan_scripts(
    client: httpx.AsyncClient,
    urls: list[str],
    pages: list[tuple[str, str]],
    heads: dict[str, str] | None = None,
) -> tuple[list[Leak], int]:
    """Leaks in the site's own script files (``urls``) and in the scripts written into
    its pages (``pages``: (where, html)). Returns the leaks and how many sources were
    read. ``heads``, if given, receives the start of each file (for vulns.py: library
    banners), so the files are downloaded once."""
    leaks: list[Leak] = []
    for where, html in pages:
        leaks += find_leaks(inline_scripts(html), f"код страницы {where}")

    async def one(url: str) -> list[Leak]:
        try:
            resp = await client.get(url)
        except httpx.HTTPError:
            return []
        if resp.status_code != 200:
            return []
        short = re.sub(r"^https?://", "", url).split("?")[0]
        text = resp.text[:MAX_BYTES]
        if heads is not None:
            heads[url] = text[:HEAD_CHARS]
        return find_leaks(text, short[:80])

    for found in await asyncio.gather(*(one(u) for u in urls[:MAX_SCRIPTS])):
        leaks += found
    unique: dict[tuple[str, str], Leak] = {}
    for leak in leaks:
        unique.setdefault((leak.kind, leak.masked), leak)
    return list(unique.values()), len(pages) + min(len(urls), MAX_SCRIPTS)


def leak_check(leaks: list[Leak], sources: int) -> Check:
    secrets = [x for x in leaks if x.secret]
    public = [x for x in leaks if not x.secret]

    def listed(items: list[Leak]) -> str:
        text = "; ".join(f"{x.kind} {x.masked} ({x.where})" for x in items[:SHOWN])
        return text + (f" и ещё {len(items) - SHOWN}" if len(items) > SHOWN else "")

    if secrets:
        return Check(
            GROUP_WEB,
            TITLE,
            Status.FAIL,
            f"В коде, который получает браузер каждого посетителя, есть секреты: "
            f"{listed(secrets)}. Любой, кто откроет сайт, может их взять и использовать."
            + (f" Ещё публичные ключи: {listed(public)}." if public else ""),
            "Немедленно отзовите эти ключи у провайдера и выпустите новые. Секреты храните "
            "только на сервере: браузер должен обращаться к вашему API, а не к сервису напрямую.",
        )
    if public:
        return Check(
            GROUP_WEB,
            TITLE,
            Status.WARN,
            f"В коде сайта есть ключи, которые видит любой посетитель: {listed(public)}. "
            "Такие ключи бывают публичными по задумке, но без ограничений их можно "
            "использовать с чужих сайтов за ваш счёт.",
            "Ограничьте ключ в консоли провайдера: только ваши домены (HTTP referrer) и "
            "только нужные API.",
        )
    return Check(
        GROUP_WEB,
        TITLE,
        Status.OK,
        f"Секретов и ключей не найдено (проверено источников кода: {sources}).",
    )
