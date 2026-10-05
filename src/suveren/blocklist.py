"""Is the site blocked in Russia? Checked against the public РКН register dump
republished by antifilter.download (domains, single IPs and aggregated subnets).
"""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable
from pathlib import Path

import httpx

from suveren.cache import fetch_cached
from suveren.checks import GROUP_BLOCK, Check, Status
from suveren.errors import ModuleError

SOURCE = "https://antifilter.download/list/"
DOMAINS = "domains.lst"
# ipsum.lst is deliberately not used: it widens single blocked IPs to whole /24
# networks and would flag innocent neighbours on shared hosting.
IP_LISTS = ("ip.lst", "subnet.lst")


def domain_candidates(host: str) -> list[str]:
    """'a.b.example.ru' -> ['a.b.example.ru', 'b.example.ru', 'example.ru']."""
    labels = host.lower().strip(".").split(".")
    return [".".join(labels[i:]) for i in range(len(labels) - 1)]


def _normalize(line: str) -> str:
    return line.strip().strip('"').strip().lower().removeprefix("*.").rstrip(".")


def find_blocked_domains(lines: Iterable[str], candidates: Iterable[str]) -> set[str]:
    wanted = set(candidates)
    return {entry for line in lines if (entry := _normalize(line)) in wanted}


def find_blocked_ips(lines: Iterable[str], ips: Iterable[str]) -> dict[str, str]:
    """Map of IP -> list entry (IP or subnet) that covers it."""
    addresses = []
    for ip in ips:
        try:
            addresses.append(ipaddress.ip_address(ip))
        except ValueError:
            continue
    hits: dict[str, str] = {}
    for line in lines:
        entry = line.strip()
        if not entry or entry.startswith("#"):
            continue
        try:
            network = ipaddress.ip_network(entry, strict=False)
        except ValueError:
            continue
        for addr in addresses:
            if addr.version == network.version and addr in network and str(addr) not in hits:
                hits[str(addr)] = entry
    return hits


def _lines(path: Path) -> Iterable[str]:
    with path.open(encoding="utf-8", errors="replace") as fh:
        yield from fh


async def run_blocklist(
    client: httpx.AsyncClient, host: str, ips: list[str], *, refresh: bool = False
) -> tuple[list[Check], list[str]]:
    notes: list[str] = []
    try:
        domains_path, note = await fetch_cached(
            client, SOURCE + DOMAINS, f"blocklist-{DOMAINS}", refresh=refresh
        )
        if note:
            notes.append(note)
        ip_paths = []
        for name in IP_LISTS:
            path, note = await fetch_cached(
                client, SOURCE + name, f"blocklist-{name}", refresh=refresh
            )
            ip_paths.append(path)
            if note:
                notes.append(note)
    except ModuleError as exc:
        return [
            Check(GROUP_BLOCK, "Реестр блокировок Роскомнадзора", Status.UNKNOWN, str(exc))
        ], notes

    checks: list[Check] = []
    blocked = find_blocked_domains(_lines(domains_path), domain_candidates(host))
    if blocked:
        checks.append(
            Check(
                GROUP_BLOCK,
                "Домен в реестре блокировок",
                Status.FAIL,
                f"В реестре: {', '.join(sorted(blocked))}. Пользователи из России без VPN "
                "сайт не откроют.",
                "Выясните причину блокировки на blocklist.rkn.gov.ru и обратитесь в "
                "Роскомнадзор, если блокировка ошибочна.",
                link="https://blocklist.rkn.gov.ru/",
            )
        )
    else:
        checks.append(
            Check(GROUP_BLOCK, "Домен в реестре блокировок", Status.OK, "Домен не заблокирован.")
        )

    hits: dict[str, str] = {}
    for path in ip_paths:
        for ip, entry in find_blocked_ips(_lines(path), ips).items():
            hits.setdefault(ip, entry)
    if hits:
        shown = ", ".join(f"{ip} (в списке {entry})" for ip, entry in sorted(hits.items()))
        checks.append(
            Check(
                GROUP_BLOCK,
                "IP-адреса сайта",
                Status.WARN,
                f"IP сайта попадают под блокировку: {shown}. Обычно это общий IP хостинга или "
                "CDN, заблокированный из-за другого сайта: часть посетителей сайт не откроет.",
                "Попросите у хостинга выделенный IP или переезжайте к провайдеру, чьи адреса "
                "не блокируются.",
            )
        )
    elif ips:
        checks.append(
            Check(GROUP_BLOCK, "IP-адреса сайта", Status.OK, "IP сайта не заблокированы.")
        )
    return checks, notes
