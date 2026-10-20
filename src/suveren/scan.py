"""One full scan: collect facts, analyse dependencies, run the extra checks."""

from __future__ import annotations

import asyncio
import contextlib
import time
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import TypeVar
from urllib.parse import urljoin

import httpx

from suveren import unknown
from suveren.analyze import analyze
from suveren.blocklist import run_blocklist
from suveren.catalog import BY_ID
from suveren.checks import GROUP_152, Check, Status
from suveren.collect import Collector, Facts, collect, make_client, page_problem
from suveren.compliance import policy_target, run_compliance
from suveren.crawl import DEFAULT_PAGES, FetchedPage, fetch_pages, pick_links
from suveren.cutoff import GROUP_CUT, PAGE_TITLE, infra_check, run_cutoff
from suveren.dnsutil import ResolverMode, create_resolver
from suveren.errors import ModuleError
from suveren.logins import find_login_page
from suveren.mailsec import run_mail_checks
from suveren.models import Report
from suveren.page import parse_page
from suveren.render import EXTRA_SETTLE_MS, BrowserSession
from suveren.subdomains import run_subdomain_checks
from suveren.websec import run_web_checks

# progress(stage, seconds): seconds is None when the stage starts, then its duration.
Progress = Callable[[str, float | None], None]
T = TypeVar("T")


def _quiet(stage: str, seconds: float | None) -> None:
    pass


@asynccontextmanager
async def _stage(progress: Progress, name: str) -> AsyncIterator[None]:
    progress(name, None)
    started = time.perf_counter()
    try:
        yield
    finally:
        progress(name, time.perf_counter() - started)


async def run_scan(
    host: str,
    *,
    timeout: float = 10.0,
    dns_mode: ResolverMode = "auto",
    compliance: bool = True,
    blocklist: bool = True,
    mail: bool = True,
    subdomains: bool = True,
    security: bool = True,
    refresh: bool = False,
    browser: bool = False,
    pages: int = DEFAULT_PAGES,
    progress: Progress | None = None,
    only: frozenset[str] | set[str] | None = None,
    cutoff: bool = False,
) -> Report:
    """``only``: IDs of the checks to report (from ``--checks``); None reports all."""
    progress = progress or _quiet
    started = datetime.now(timezone.utc)
    async with _stage(progress, "DNS, почта, хостинг, сертификат, страница"):
        facts = await collect(host, timeout=timeout, dns_mode=dns_mode)
    if browser:
        async with _stage(
            progress, "Сайт в браузере" + (f" (до {pages + 1} стр.)" if pages else "")
        ):
            try:
                await _render_site(facts, host, timeout=max(timeout, 25.0), pages=pages)
            except ModuleError as exc:
                facts.notes.append(f"Режим --browser не сработал: {exc}. Использован обычный HTML.")
    if pages and not facts.rendered and facts.html and not facts.page_problem:
        async with (
            _stage(progress, f"Внутренние страницы (до {pages})"),
            make_client(timeout) as client,
        ):
            links = pick_links(parse_page(facts.html), facts.final_url or "", pages)
            facts.extra_pages = _usable(await fetch_pages(client, links))
    report = analyze(facts, started_at=started)
    unseen = _unknown_domains(facts, host)
    report.facts["unknown_domains"] = sorted(unseen)
    unknown.record(unseen, host)

    if compliance or blocklist:
        async with make_client(timeout) as client:
            if compliance:
                async with _stage(progress, "Персональные данные (152-ФЗ)"):
                    report.checks += await _compliance(client, facts, report)
            if blocklist:
                async with _stage(progress, "Реестр блокировок"):
                    checks, notes = await run_blocklist(
                        client, host, [n.ip for n in facts.web], refresh=refresh
                    )
                report.checks += checks
                report.notes += notes

    if mail:
        async with _stage(progress, "Защита почты от подделки"), make_client(timeout) as client:
            resolver, _ = await create_resolver(dns_mode, timeout, client)
            report.checks += await run_mail_checks(resolver, client, facts.domain)

    if security and (facts.html or facts.headers):
        async with _stage(progress, "Безопасность сайта"), make_client(timeout) as client:
            resolver, _ = await create_resolver(dns_mode, timeout, client)
            checks, data = await run_web_checks(facts, resolver, client, timeout)
            report.checks += checks
            report.facts["web_security"] = data

    if subdomains:
        async with (
            _stage(progress, "Поддомены и их захват"),
            make_client(timeout) as client,
            make_client(timeout, verify=False) as page_client,
        ):
            # Forgotten subdomains often have broken certificates; the page is only read.
            resolver, _ = await create_resolver(dns_mode, timeout, client)
            checks, data = await run_subdomain_checks(
                resolver, client, page_client, facts.domain, refresh=refresh
            )
            report.checks += checks
            report.facts["subdomains"] = data

    if cutoff:
        async with (
            _stage(progress, "Отключение иностранных сервисов (3 загрузки)"),
            make_client(timeout) as client,
        ):
            report.checks += await _cutoff(client, facts, report, host, dns_mode, timeout)

    if only is not None:
        report.checks = narrow(report.checks, only)
    report.finished_at = datetime.now(timezone.utc)
    return report


async def _cutoff(
    client: httpx.AsyncClient,
    facts: Facts,
    report: Report,
    host: str,
    dns_mode: ResolverMode,
    timeout: float,
) -> list[Check]:
    checks = [infra_check(report.dependencies)]
    if not facts.html or facts.page_problem:
        checks.append(
            Check(
                GROUP_CUT,
                PAGE_TITLE,
                Status.UNKNOWN,
                f"Не проверено: {facts.page_problem or 'главная не загрузилась'}.",
            )
        )
        return checks
    resolver, _ = await create_resolver(dns_mode, timeout, client)
    try:
        check, result, shots = await run_cutoff(
            facts.final_url or f"https://{host}/",
            host,
            Collector(resolver, client, timeout),
            timeout=max(timeout, 25.0),
        )
    except ModuleError as exc:
        checks.append(Check(GROUP_CUT, PAGE_TITLE, Status.UNKNOWN, f"Не проверено: {exc}."))
        return checks
    report.facts["cutoff"] = result.to_dict()
    report.media.update({f"cutoff_{k}": v for k, v in shots.items() if v})
    return [*checks, check]


def narrow(checks: list[Check], only: frozenset[str] | set[str]) -> list[Check]:
    """The chosen checks. When a module returned none of them (DNS did not answer and
    the mail module gave one "not checked" verdict), its "not checked" stays: it says
    why the chosen check is missing."""

    def module(c: Check) -> str | None:
        spec = BY_ID.get(c.id)
        return spec.module if spec else None

    answered = {module(c) for c in checks if c.id in only}
    wanted = {BY_ID[i].module for i in only if i in BY_ID}
    return [
        c
        for c in checks
        if c.id in only
        or (c.status is Status.UNKNOWN and module(c) in wanted and module(c) not in answered)
    ]


async def _compliance(client: httpx.AsyncClient, facts: Facts, report: Report) -> list[Check]:
    if not facts.html:
        return [
            Check(
                GROUP_152,
                "Проверка 152-ФЗ",
                Status.UNKNOWN,
                "Главная страница не загрузилась, проверять нечего.",
            )
        ]
    return await run_compliance(
        client,
        facts.final_url,
        facts.html,
        report.dependencies,
        page_problem=facts.page_problem,
        extra_pages=facts.extra_pages,
        prefetched=facts.prefetched,
        loaded_urls=facts.loaded_urls,
    )


def _unknown_domains(facts: Facts, host: str) -> set[str]:
    urls: list[str] = []
    if facts.html and not facts.page_problem:
        urls += unknown.resource_urls(facts.html, facts.final_url or f"https://{host}/")
        urls += facts.loaded_urls
    for page in facts.extra_pages:
        urls += unknown.resource_urls(page.html, page.url) + page.loaded_urls
    return unknown.unknown_domains(urls, host)


def _usable(pages: list[FetchedPage]) -> list[FetchedPage]:
    """Drop inner pages that are bot walls or empty shells."""
    return [p for p in pages if not page_problem(p.status, p.html, rendered=bool(p.loaded_urls))]


async def _render_site(facts: Facts, host: str, *, timeout: float, pages: int) -> None:
    async with BrowserSession(timeout=timeout) as session:
        home = await session.open(facts.final_url or f"https://{host}/")
        facts.final_url, facts.page_status, facts.html = home.final_url, home.status, home.html
        facts.loaded_urls, facts.rendered = home.requests, True
        if facts.page_problem:
            return
        home_page = parse_page(home.html)
        if pages:
            links = pick_links(home_page, home.final_url, pages)
            rendered = await session.open_many(links)
            facts.extra_pages = _usable(
                [FetchedPage(r.final_url, r.status, r.html, r.requests) for r in rendered]
            )
        # Open the privacy policy here too: over plain HTTP it is often a bot wall.
        extras = [(urljoin(home.final_url, p.path), parse_page(p.html)) for p in facts.extra_pages]
        target = policy_target(home_page, extras, home.final_url)
        urls = [target[0]] if target and not target[0].lower().endswith(".pdf") else []
        # And the sign-in page: its buttons are usually drawn by a script.
        login = find_login_page(home_page, home.final_url)
        if login and login not in urls:
            urls.append(login)
        for url in urls:
            with contextlib.suppress(ModuleError):
                doc = await session.open(url, settle_ms=EXTRA_SETTLE_MS)
                facts.prefetched[url] = FetchedPage(
                    doc.final_url, doc.status, doc.html, doc.requests
                )


async def gather_limited(jobs: list[Callable[[], Awaitable[T]]], limit: int) -> list[T]:
    """Run coroutine factories with at most ``limit`` in flight, keeping order."""
    semaphore = asyncio.Semaphore(limit)

    async def run(job: Callable[[], Awaitable[T]]) -> T:
        async with semaphore:
            return await job()

    return list(await asyncio.gather(*(run(j) for j in jobs)))
