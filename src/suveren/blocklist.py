"""Is the site blocked in Russia? Checked against the public РКН register dump
republished by antifilter.download (domains, single IPs and aggregated subnets).
"""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable
from pathlib import Path

import httpx

from suveren.cache import cache_dir, fetch_cached
from suveren.checks import GROUP_BLOCK, Check, Evidence, Status
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


async def ensure_lists(
    client: httpx.AsyncClient, *, refresh: bool = False
) -> tuple[dict[str, int], list[str]]:
    """Download the lists if missing or stale; returns sizes in bytes and notes."""
    sizes: dict[str, int] = {}
    notes: list[str] = []
    for name in (DOMAINS, *IP_LISTS):
        path, note = await fetch_cached(client, SOURCE + name, f"blocklist-{name}", refresh=refresh)
        sizes[name] = path.stat().st_size
        if note:
            notes.append(note)
    return sizes, notes


def blocked_hosts(lines: Iterable[str], hosts: Iterable[str]) -> dict[str, str]:
    """Map of host -> register entry that blocks it (the host or a parent domain)."""
    candidates = {h: domain_candidates(h) for h in hosts}
    entries = find_blocked_domains(lines, {c for cs in candidates.values() for c in cs})
    return {
        h: next(c for c in cs if c in entries)
        for h, cs in candidates.items()
        if any(c in entries for c in cs)
    }


def third_party_check(hits: dict[str, str], checked: int) -> Check:
    """Third-party hosts the page loads that are in the register: for visitors in
    Russia without a VPN they do not load today, whatever the site does."""
    title = "Сторонние сервисы в реестре блокировок"
    if not checked:
        return Check(
            GROUP_BLOCK, title, Status.OK, "Сторонних доменов на проверенных страницах нет."
        )
    if not hits:
        return Check(
            GROUP_BLOCK,
            title,
            Status.OK,
            f"Ни один из сторонних доменов, с которых грузится сайт ({checked}), не заблокирован.",
        )
    by_entry: dict[str, list[str]] = {}
    for host, entry in sorted(hits.items()):
        by_entry.setdefault(entry, []).append(host)
    shown = "; ".join(
        entry if hosts == [entry] else f"{entry} ({', '.join(hosts[:3])})"
        for entry, hosts in by_entry.items()
    )
    return Check(
        GROUP_BLOCK,
        title,
        Status.WARN,
        f"Сайт подключает заблокированные в России домены: {shown}. У посетителей из России "
        "без VPN эти скрипты, виджеты и картинки уже сейчас не загружаются, а страница может "
        "ждать их и открываться медленнее.",
        "Уберите эти подключения или замените сервисы на доступные в России.",
        link="https://blocklist.rkn.gov.ru/",
        evidence=[
            Evidence("registry", f"{host}: запись в выгрузке реестра", entry)
            for host, entry in sorted(hits.items())[:10]
        ],
    )


async def run_blocklist(
    client: httpx.AsyncClient,
    host: str,
    ips: list[str],
    *,
    refresh: bool = False,
    third_party: Iterable[str] | None = None,
) -> tuple[list[Check], list[str]]:
    """``third_party``: hosts the page loads from; None when the page was not read."""
    try:
        _, notes = await ensure_lists(client, refresh=refresh)
    except ModuleError as exc:
        return [Check(GROUP_BLOCK, "Реестр блокировок Роскомнадзора", Status.UNKNOWN, str(exc))], []
    domains_path = cache_dir() / f"blocklist-{DOMAINS}"
    ip_paths = [cache_dir() / f"blocklist-{name}" for name in IP_LISTS]

    checks: list[Check] = []
    others = sorted(set(third_party or ()))
    # One pass over the register for the site and every third-party host.
    found = blocked_hosts(_lines(domains_path), [host, *others])
    blocked = {found[host]} if host in found else set()
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
                evidence=[Evidence("registry", "Запись в выгрузке реестра", e) for e in blocked],
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
                evidence=[
                    Evidence("registry", f"IP {ip} в списке", entry)
                    for ip, entry in sorted(hits.items())
                ],
            )
        )
    elif ips:
        checks.append(
            Check(GROUP_BLOCK, "IP-адреса сайта", Status.OK, "IP сайта не заблокированы.")
        )
    if third_party is not None:
        checks.append(third_party_check({h: found[h] for h in others if h in found}, len(others)))
    return checks, notes
