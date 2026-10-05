"""One full scan: collect facts, analyse dependencies, run optional checks."""

from __future__ import annotations

from datetime import datetime, timezone

from suveren.analyze import analyze
from suveren.blocklist import run_blocklist
from suveren.checks import GROUP_152, Check, Status
from suveren.collect import collect, make_client
from suveren.compliance import run_compliance
from suveren.dnsutil import ResolverMode
from suveren.models import Report


async def run_scan(
    host: str,
    *,
    timeout: float = 10.0,
    dns_mode: ResolverMode = "auto",
    compliance: bool = True,
    blocklist: bool = True,
    refresh: bool = False,
) -> Report:
    started = datetime.now(timezone.utc)
    facts = await collect(host, timeout=timeout, dns_mode=dns_mode)
    report = analyze(facts, started_at=started)

    if compliance or blocklist:
        async with make_client(timeout) as client:
            if compliance:
                if facts.html:
                    report.checks += await run_compliance(
                        client, facts.final_url, facts.html, report.dependencies
                    )
                else:
                    report.checks.append(
                        Check(
                            GROUP_152,
                            "Проверка 152-ФЗ",
                            Status.UNKNOWN,
                            "Главная страница не загрузилась, проверять нечего.",
                        )
                    )
            if blocklist:
                checks, notes = await run_blocklist(
                    client, host, [n.ip for n in facts.web], refresh=refresh
                )
                report.checks += checks
                report.notes += notes

    report.finished_at = datetime.now(timezone.utc)
    return report
