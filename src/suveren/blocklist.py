"""Is the site blocked in Russia? Checked against the public РКН register dump
republished by antifilter.download (domains, single IPs and aggregated subnets).
"""

from __future__ import annotations

import contextlib
import ipaddress
from collections.abc import Iterable
from datetime import datetime
from pathlib import Path

import httpx

from suveren.cache import cache_dir, fetch_cached, stale_days
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
    entry = line.strip().strip('"').strip().lower().removeprefix("*.").rstrip(".")
    # About 7 000 entries are Cyrillic ("01инвест.рф") while the host we look up is
    # punycode, as normalize_domain makes it: a blocked .рф site came out "not blocked".
    if not entry.isascii():
        with contextlib.suppress(UnicodeError):  # not a valid name: kept, matches nothing
            entry = entry.encode("idna").decode("ascii")
    return entry


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


def source_note(path: Path) -> str:
    """Where the answer comes from: not the register itself (it has no open download)
    but antifilter's copy of it, as of the day the copy was taken."""
    day = datetime.fromtimestamp(path.stat().st_mtime).strftime("%d.%m.%Y")
    return f"antifilter.download, выгрузка реестра РКН от {day}"


def _outdated(old: int | None) -> str:
    if not old:
        return ""
    return (
        f" Но это по копии реестра {old}-дневной давности: обновить её не удалось, "
        "повторите проверку с --refresh."
    )


def blocked_hosts(lines: Iterable[str], hosts: Iterable[str]) -> dict[str, str]:
    """Map of host -> register entry that blocks it (the host or a parent domain)."""
    candidates = {h: domain_candidates(h) for h in hosts}
    entries = find_blocked_domains(lines, {c for cs in candidates.values() for c in cs})
    return {
        h: next(c for c in cs if c in entries)
        for h, cs in candidates.items()
        if any(c in entries for c in cs)
    }


def third_party_check(hits: dict[str, str], checked: int, old: int | None = None) -> Check:
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
            Status.UNKNOWN if old else Status.OK,
            f"Ни один из сторонних доменов, с которых грузится сайт ({checked}), не заблокирован."
            + _outdated(old),
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
        evidence=[
            Evidence("registry", f"{host}: запись в выгрузке реестра", entry)
            for host, entry in sorted(hits.items())[:10]
        ],
    )


async def run_blocklist(
    client: httpx.AsyncClient,
    host: str,
    ips: list[str] | None,
    *,
    refresh: bool = False,
    third_party: Iterable[str] | None = None,
) -> tuple[list[Check], list[str]]:
    """``ips``: None when DNS did not answer for them (an empty list: the site has none).
    ``third_party``: hosts the page loads from; None when the page was not read."""
    try:
        _, notes = await ensure_lists(client, refresh=refresh)
    except ModuleError as exc:
        return [Check(GROUP_BLOCK, "Реестр блокировок Роскомнадзора", Status.UNKNOWN, str(exc))], []
    domains_path = cache_dir() / f"blocklist-{DOMAINS}"
    ip_paths = [cache_dir() / f"blocklist-{name}" for name in IP_LISTS]
    # A copy kept because the refresh failed: "not blocked" by it is not a clean answer.
    old = stale_days(domains_path)
    clean = Status.UNKNOWN if old else Status.OK

    checks: list[Check] = []
    no_ips: Check | None = None  # the IP check that had nothing to look up
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
                evidence=[Evidence("registry", "Запись в выгрузке реестра", e) for e in blocked],
            )
        )
    else:
        checks.append(
            Check(
                GROUP_BLOCK,
                "Домен в реестре блокировок",
                clean,
                "Домен не заблокирован." + _outdated(old),
            )
        )

    hits: dict[str, str] = {}
    for path in ip_paths:
        for ip, entry in find_blocked_ips(_lines(path), ips or ()).items():
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
            Check(
                GROUP_BLOCK, "IP-адреса сайта", clean, "IP сайта не заблокированы." + _outdated(old)
            )
        )
    elif ips is None:
        checks.append(
            no_ips := Check(
                GROUP_BLOCK,
                "IP-адреса сайта",
                Status.UNKNOWN,
                "DNS не ответил на запрос IP-адресов сайта, поэтому блокировку по IP "
                "проверить не удалось. Повторите проверку позже.",
            )
        )
    if third_party is not None:
        hits3 = {h: found[h] for h in others if h in found}
        checks.append(third_party_check(hits3, len(others), old))
    source = source_note(domains_path)
    for check in checks:
        if check is not no_ips:
            check.link = SOURCE
            check.evidence.append(Evidence("registry", "Источник", source))
    return checks, notes
