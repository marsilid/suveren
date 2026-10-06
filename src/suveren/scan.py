"""One full scan: collect facts, analyse dependencies, run the extra checks."""

from __future__ import annotations

import asyncio
import time
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import TypeVar

import httpx

from suveren.analyze import analyze
from suveren.blocklist import run_blocklist
from suveren.checks import GROUP_152, Check, Status
from suveren.collect import Facts, collect, make_client, page_problem
from suveren.compliance import run_compliance
from suveren.crawl import DEFAULT_PAGES, FetchedPage, fetch_pages, pick_links
from suveren.dnsutil import ResolverMode
from suveren.errors import ModuleError
from suveren.models import Report
from suveren.page import parse_page
from suveren.render import BrowserSession

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
    refresh: bool = False,
    browser: bool = False,
    pages: int = DEFAULT_PAGES,
    progress: Progress | None = None,
) -> Report:
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

    report.finished_at = datetime.now(timezone.utc)
    return report


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
    )


def _usable(pages: list[FetchedPage]) -> list[FetchedPage]:
    """Drop inner pages that are bot walls or empty shells."""
    return [p for p in pages if not page_problem(p.status, p.html, rendered=bool(p.loaded_urls))]


async def _render_site(facts: Facts, host: str, *, timeout: float, pages: int) -> None:
    async with BrowserSession(timeout=timeout) as session:
        home = await session.open(facts.final_url or f"https://{host}/")
        facts.final_url, facts.page_status, facts.html = home.final_url, home.status, home.html
        facts.loaded_urls, facts.rendered = home.requests, True
        if pages and not facts.page_problem:
            links = pick_links(parse_page(home.html), home.final_url, pages)
            rendered = await session.open_many(links)
            facts.extra_pages = _usable(
                [FetchedPage(r.final_url, r.status, r.html, r.requests) for r in rendered]
            )


async def gather_limited(jobs: list[Callable[[], Awaitable[T]]], limit: int) -> list[T]:
    """Run coroutine factories with at most ``limit`` in flight, keeping order."""
    semaphore = asyncio.Semaphore(limit)

    async def run(job: Callable[[], Awaitable[T]]) -> T:
        async with semaphore:
            return await job()

    return list(await asyncio.gather(*(run(j) for j in jobs)))
