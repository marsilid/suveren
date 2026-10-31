"""One full scan: collect facts, analyse dependencies, run the extra checks."""

from __future__ import annotations

import asyncio
import contextlib
import time
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from typing import TypeVar
from urllib.parse import urljoin, urlsplit

import httpx

from suveren import unknown
from suveren.analyze import TLS_UNTRUSTED_NOTE, analyze
from suveren.blocklist import run_blocklist
from suveren.catalog import BY_ID
from suveren.checks import GROUP_152, Check, Status
from suveren.collect import Collector, Facts, collect, make_client, page_problem
from suveren.compliance import policy_target, run_compliance
from suveren.crawl import (
    DEFAULT_PAGES,
    FetchedPage,
    fetch_pages,
    pick_from_sitemap,
    pick_links,
    sitemap_urls,
)
from suveren.cutoff import GROUP_CUT, PAGE_TITLE, infra_check, run_cutoff
from suveren.dataflow import run_dataflow
from suveren.dnsutil import ResolverMode, create_resolver
from suveren.dnszone import run_zone_checks
from suveren.errors import ModuleError
from suveren.formleaks import TITLE as FORM_TITLE
from suveren.formleaks import pages_with_fields, run_form_leaks
from suveren.logins import find_login_page
from suveren.mailsec import run_mail_checks
from suveren.models import Report
from suveren.page import parse_page
from suveren.plugins import Plugin, PluginContext, run_plugins
from suveren.render import EXTRA_SETTLE_MS, BrowserSession
from suveren.scenarios import build as build_scenarios
from suveren.subdomains import run_subdomain_checks
from suveren.websec import GROUP_WEB, run_web_checks

# progress(stage, seconds): seconds is None when the stage starts, then its duration.
Progress = Callable[[str, float | None], None]
T = TypeVar("T")


def _quiet(stage: str, seconds: float | None) -> None:
    pass


@asynccontextmanager
async def _stage(progress: Progress, name: str) -> AsyncIterator[None]:
    progress(name, None)
    started = time.perf_counter()
    yield
    # Only a stage that finished gets its tick; a failed one is told by the error.
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
    formleaks: bool = False,
    form_phone: str | None = None,
    plugins: list[Plugin] | None = None,
) -> Report:
    """``only``: IDs of the checks to report (from ``--checks``); None reports all.
    ``form_phone``: the owner's own number for the form experiment (ten digits)."""
    progress = progress or _quiet
    started = datetime.now(UTC)
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
            # Form pages the home page doesn't link to (a contacts page only in the
            # footer menu drawn by a script) are often in the sitemap.
            links += pick_from_sitemap(
                await sitemap_urls(client, facts.final_url or ""),
                facts.final_url or "",
                set(links),
            )
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
                    report.checks.append(
                        await _dataflow(client, facts, report, host, dns_mode, timeout)
                    )
            if blocklist:
                async with _stage(progress, "Реестр блокировок"):
                    readable = bool(facts.html) and not facts.page_problem
                    checks, notes = await run_blocklist(
                        client,
                        host,
                        None if "web" in facts.dns_unanswered else [n.ip for n in facts.web],
                        refresh=refresh,
                        third_party=unknown.third_party_hosts(_page_urls(facts, host), host)
                        if readable
                        else None,
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
            if any(c.id == "SUV-WEB-008" for c in checks):  # TLS: says it better
                report.notes = [n for n in report.notes if n != TLS_UNTRUSTED_NOTE]
            svg = data.pop("script_graph_svg", "")
            if svg:
                report.media["script_graph_svg"] = svg.encode("utf-8")
            report.facts["web_security"] = data
    elif security:
        # No page and no headers: say so, or the section silently vanishes (gosuslugi.ru).
        report.checks.append(
            Check(
                GROUP_WEB,
                "Заголовки безопасности (CSP, HSTS и другие)",
                Status.UNKNOWN,
                "Не проверено: главная страница не загрузилась.",
            )
        )
    if security:
        # DNS only, so it runs even when the page did not load.
        async with _stage(progress, "CAA и DNSSEC"), make_client(timeout) as client:
            resolver, _ = await create_resolver(dns_mode, timeout, client)
            https = not facts.final_url or facts.final_url.startswith("https://")
            report.checks += await run_zone_checks(resolver, facts.host, https=https)

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

    if formleaks:
        async with (
            _stage(progress, "Данные из форм до отправки (браузер)"),
            make_client(timeout) as client,
        ):
            report.checks.append(
                await _form_leaks(client, facts, report, host, dns_mode, timeout, form_phone)
            )

    if plugins:
        report.plugins = [{"name": p.name, "source": p.source} for p in plugins]
        async with _stage(progress, "Плагины"), make_client(timeout) as client:
            ctx = PluginContext(
                host,
                facts.domain,
                facts.final_url,
                "" if facts.page_problem else facts.html,
                dict(facts.headers),
                [d.to_dict() for d in report.dependencies],
                client,
            )
            report.checks += await run_plugins(plugins, ctx)

    # Scenarios join what the modules found; they open the report.
    report.checks = build_scenarios(report.checks, report.dependencies, facts.domain) + (
        report.checks
    )
    if only is not None:
        report.checks = narrow(report.checks, only)
    report.finished_at = datetime.now(UTC)
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
            # The HTML as the server sent it; in --browser mode it is already rendered.
            raw_html=None if facts.rendered else facts.html,
        )
    except Exception as exc:  # the experiment must never take the whole scan down
        reason = str(exc) if isinstance(exc, ModuleError) else f"ошибка браузера ({exc!r:.120})"
        checks.append(Check(GROUP_CUT, PAGE_TITLE, Status.UNKNOWN, f"Не проверено: {reason}."))
        return checks
    report.facts["cutoff"] = result.to_dict()
    report.media.update({f"cutoff_{k}": v for k, v in shots.items() if v})
    return [*checks, check]


async def _form_leaks(
    client: httpx.AsyncClient,
    facts: Facts,
    report: Report,
    host: str,
    dns_mode: ResolverMode,
    timeout: float,
    phone: str | None = None,
) -> Check:
    # A bot wall over plain HTTP is no reason to skip: the experiment runs in a browser,
    # which often gets through. Only a site that did not answer at all is skipped.
    if not facts.html and not facts.final_url:
        reason = facts.page_problem or "главная не загрузилась"
        return Check(GROUP_152, FORM_TITLE, Status.UNKNOWN, f"Не проверено: {reason}.")
    home = facts.final_url or f"https://{host}/"
    login = find_login_page(parse_page(facts.html), home)
    urls = pages_with_fields(home, [(p.url, p.html) for p in facts.extra_pages], login)
    resolver, _ = await create_resolver(dns_mode, timeout, client)
    try:
        check, _result, data = await run_form_leaks(
            urls,
            host,
            Collector(resolver, client, timeout),
            timeout=max(timeout, 25.0),
            phone=phone,
        )
    except Exception as exc:  # the experiment must never take the whole scan down
        reason = str(exc) if isinstance(exc, ModuleError) else f"ошибка браузера ({exc!r:.120})"
        return Check(GROUP_152, FORM_TITLE, Status.UNKNOWN, f"Не проверено: {reason}.")
    report.facts["form_leaks"] = data
    return check


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
        rendered=facts.rendered,
        https_unanswered=facts.https_unanswered,
    )


async def _dataflow(
    client: httpx.AsyncClient,
    facts: Facts,
    report: Report,
    host: str,
    dns_mode: ResolverMode,
    timeout: float,
) -> Check:
    """SUV-PD-010: the countries the visitor's data goes to (report.facts["dataflow"])."""
    # What a browser requested did reach those servers even if the page looks empty
    # (2gis.ru); without a browser a bot wall's resources are the wall's, not the site's.
    urls = _page_urls(facts, host)
    if facts.rendered and facts.page_problem:
        base = facts.final_url or f"https://{host}/"
        urls += unknown.resource_urls(facts.html, base) + facts.loaded_urls
    if not facts.html or (facts.page_problem and (not facts.rendered or not urls)):
        return Check(
            GROUP_152,
            "Куда уходят данные посетителя",
            Status.UNKNOWN,
            f"Не проверено: {facts.page_problem or 'главная страница не загрузилась'}.",
        )
    resolver, _ = await create_resolver(dns_mode, timeout, client)
    landed = urlsplit(facts.final_url or "").hostname
    check, rows = await run_dataflow(
        urls, host, Collector(resolver, client, timeout), landed, report.dependencies
    )
    report.facts["dataflow"] = rows
    return check


def _unknown_domains(facts: Facts, host: str) -> set[str]:
    return unknown.unknown_domains(_page_urls(facts, host), host)


def _page_urls(facts: Facts, host: str) -> list[str]:
    """Everything the pages embed or (in the browser) requested."""
    urls: list[str] = []
    if facts.html and not facts.page_problem:
        urls += unknown.resource_urls(facts.html, facts.final_url or f"https://{host}/")
        urls += facts.loaded_urls
    for page in facts.extra_pages:
        urls += unknown.resource_urls(page.html, page.url) + page.loaded_urls
    return urls


def _usable(pages: list[FetchedPage]) -> list[FetchedPage]:
    """Drop inner pages that are bot walls or empty shells."""
    return [p for p in pages if not page_problem(p.status, p.html, rendered=bool(p.loaded_urls))]


async def _render_site(facts: Facts, host: str, *, timeout: float, pages: int) -> None:
    async with BrowserSession(timeout=timeout) as session:
        home = await session.open(facts.final_url or f"https://{host}/", initiators=True)
        facts.final_url, facts.page_status, facts.html = home.final_url, home.status, home.html
        facts.loaded_urls, facts.rendered = home.requests, True
        facts.initiators = home.initiators
        facts.browser_headers = home.headers
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
