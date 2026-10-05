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
from suveren.collect import Facts, collect, make_client
from suveren.compliance import run_compliance
from suveren.dnsutil import ResolverMode
from suveren.errors import ModuleError
from suveren.models import Report
from suveren.render import render

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
    progress: Progress | None = None,
) -> Report:
    progress = progress or _quiet
    started = datetime.now(timezone.utc)
    async with _stage(progress, "DNS, почта, хостинг, сертификат, страница"):
        facts = await collect(host, timeout=timeout, dns_mode=dns_mode)
    if browser:
        async with _stage(progress, "Загрузка сайта в браузере"):
            try:
                page = await render(
                    facts.final_url or f"https://{host}/", timeout=max(timeout, 25.0)
                )
            except ModuleError as exc:
                facts.notes.append(f"Режим --browser не сработал: {exc}. Использован обычный HTML.")
            else:
                facts.final_url, facts.page_status, facts.html = (
                    page.final_url,
                    page.status,
                    page.html,
                )
                facts.loaded_urls, facts.rendered = page.requests, True
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
        client, facts.final_url, facts.html, report.dependencies, page_problem=facts.page_problem
    )


async def gather_limited(jobs: list[Callable[[], Awaitable[T]]], limit: int) -> list[T]:
    """Run coroutine factories with at most ``limit`` in flight, keeping order."""
    semaphore = asyncio.Semaphore(limit)

    async def run(job: Callable[[], Awaitable[T]]) -> T:
        async with semaphore:
            return await job()

    return list(await asyncio.gather(*(run(j) for j in jobs)))
