"""`suveren doctor`: are all external data sources still working?

Run by hand when something looks wrong, and daily in CI so that a change on a
government site is noticed before users hit it. Each probe uses a well-known
target whose answer is stable (Сбербанк's ИНН, google.com, 8.8.8.8).

Russian government sites often drop connections from abroad, and the CI runners
are abroad: with ``abroad=True`` a network failure of those sources is reported
as "not checked" instead of "broken". A wrong answer still counts as broken.
"""

from __future__ import annotations

import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass

import httpx

from suveren.blocklist import DOMAINS
from suveren.blocklist import SOURCE as BLOCK_SOURCE
from suveren.cloud import SOURCES as CLOUD_SOURCES
from suveren.collect import (
    Collector,
    make_client,
    parse_whois_registrar,
    whois_query,
)
from suveren.dnsutil import create_resolver
from suveren.errors import TIMEOUTS, ModuleError, describe
from suveren.registries import egrul_search, rkn_operator
from suveren.ruregistries import FEDSFM_URL
from suveren.sanctions import SOURCES
from suveren.subdomains import CRTSH_URL, clean_names, parse_crtsh
from suveren.vulns import RETIRE_URL

PROBE_INN = "7707083893"  # ПАО Сбербанк: present in every registry and sanctions list
# Sources that may not answer outside Russia at all.
RU_ONLY = frozenset(
    {"ЕГРЮЛ (ФНС)", "Реестр операторов ПДн (РКН)", "Перечень Росфинмониторинга (fedsfm.ru)"}
)


@dataclass(slots=True)
class Probe:
    name: str
    ok: bool | None  # None = optional component missing
    details: str
    seconds: float = 0.0


class _Optional(Exception):
    """An optional component (the browser mode) is not installed."""


def _network_failure(exc: BaseException) -> bool:
    """The source did not answer at all, as opposed to answering something unexpected."""
    cause = exc.__cause__ if isinstance(exc, ModuleError) else exc
    return isinstance(cause, (httpx.TransportError, OSError, *TIMEOUTS))


async def _timed(name: str, fn: Callable[[], Awaitable[str]], *, abroad: bool = False) -> Probe:
    started = time.perf_counter()
    try:
        details = await fn()
        return Probe(name, True, details, time.perf_counter() - started)
    except _Optional as exc:
        return Probe(name, None, str(exc), time.perf_counter() - started)
    except (ModuleError, httpx.HTTPError, OSError, *TIMEOUTS, ValueError, KeyError) as exc:
        message = describe(exc)
        if abroad and name in RU_ONLY and _network_failure(exc):
            message = f"не проверен: из-за границы не отвечает ({message})"
            return Probe(name, None, message, time.perf_counter() - started)
        return Probe(name, False, message, time.perf_counter() - started)


async def _reachable(client: httpx.AsyncClient, url: str) -> str:
    async with client.stream("GET", url, headers={"Range": "bytes=0-1023"}) as resp:
        if resp.status_code not in (200, 206):
            raise ModuleError(f"HTTP {resp.status_code}")
        async for _ in resp.aiter_bytes():  # the first chunk is enough; skip the rest
            break
    return "доступен"


async def run_doctor(timeout: float = 20.0, *, abroad: bool = False) -> list[Probe]:
    async with make_client(timeout) as client:
        resolver, note = await create_resolver("auto", timeout, client)
        collector = Collector(resolver, client, timeout)

        async def dns() -> str:
            mx = await resolver.resolve("google.com", "MX")
            if not mx:
                raise ModuleError("пустой ответ на MX google.com")
            return f"{resolver.kind}" + (" (системный DNS отвечает неполно)" if note else "")

        async def cymru() -> str:
            info = await collector.net_info("8.8.8.8")
            if info.asn != 15169:
                raise ModuleError(f"ожидался AS15169, получено {info.asn}")
            return f"AS{info.asn} {info.as_name}"

        async def rdap() -> str:
            name = await collector.registrar("google.com")
            if not name:
                raise ModuleError("регистратор не определён")
            return name

        async def whois_ru() -> str:
            text = await whois_query("whois.tcinet.ru", "yandex.ru", timeout)
            name = parse_whois_registrar(text)
            if not name:
                raise ModuleError("в ответе нет поля registrar")
            return name

        async def egrul() -> str:
            rows = await egrul_search(client, PROBE_INN)
            if not rows or rows[0].inn != PROBE_INN:
                raise ModuleError("Сбербанк не найден по ИНН")
            return rows[0].name_short or rows[0].name_full

        async def rkn() -> str:
            op = await rkn_operator(client, PROBE_INN)
            if op is None:
                raise ModuleError("Сбербанк не найден в реестре: изменилась вёрстка?")
            return f"№ {op.reg_number}"

        async def crtsh() -> str:
            resp = await client.get(
                CRTSH_URL,
                params={"q": "%.example.com", "output": "json"},
                timeout=httpx.Timeout(timeout, read=60.0),
            )
            resp.raise_for_status()
            names = clean_names(parse_crtsh(resp.json()), "example.com")
            if not names:
                raise ModuleError("пустой ответ для example.com")
            return f"поддоменов example.com: {len(names)}"

        async def blocklist() -> str:
            return await _reachable(client, BLOCK_SOURCE + DOMAINS)

        def sanctions(url: str) -> Callable[[], Awaitable[str]]:
            return lambda: _reachable(client, url)

        async def browser() -> str:
            try:
                from suveren.render import BrowserSession
            except ImportError as exc:  # pragma: no cover - render has no hard deps
                raise _Optional(str(exc)) from exc
            try:
                async with BrowserSession(timeout=timeout) as session:
                    return session.browser_name
            except ModuleError as exc:
                raise _Optional(f"не настроен: {exc}") from exc

        probes = [
            ("DNS", dns),
            ("Team Cymru (сети IP-адресов)", cymru),
            ("RDAP", rdap),
            ("WHOIS .ru", whois_ru),
            ("ЕГРЮЛ (ФНС)", egrul),
            ("Реестр операторов ПДн (РКН)", rkn),
            ("Реестр блокировок", blocklist),
            ("Журналы сертификатов (crt.sh)", crtsh),
            *((f"Санкции: {s.title}", sanctions(s.url)) for s in SOURCES),
            *((f"Адреса облака: {c.name}", sanctions(c.url)) for c in CLOUD_SOURCES),
            ("База уязвимостей (retire.js)", sanctions(RETIRE_URL)),
            ("Перечень Росфинмониторинга (fedsfm.ru)", sanctions(FEDSFM_URL)),
            ("Браузер для --browser", browser),
        ]
        return [await _timed(name, fn, abroad=abroad) for name, fn in probes]
