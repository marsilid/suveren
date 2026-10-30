"""Check src/suveren/data/services.json against DNS: is the base still true?

Passive, DNS only, like the scans themselves:
- every AS number: Team Cymru must name an owner that one of the entry's as_names
  matches (an AS sold or renumbered shows up here);
- every domain in the NS and MX suffixes and in the page patterns: it must still
  exist (a dead domain is a stale entry, and a dead script domain that someone
  re-registers is a supply-chain risk worth knowing about).

It never edits the file: each finding needs a person and a source.

    python tools/check_services.py          # report; exit code 1 if anything is off
"""

from __future__ import annotations

import asyncio
import json
import re
import sys
from pathlib import Path
from typing import Any

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from suveren.collect import parse_cymru_asname
from suveren.dnsutil import DnsLookupError, DnsResolver, create_resolver
from suveren.utils import registrable_domain

DATA = Path(__file__).resolve().parent.parent / "src" / "suveren" / "data" / "services.json"
CONCURRENCY = 8

# A literal domain inside a page pattern: "googletagmanager\\.com", "mc\\.yandex\\.ru".
_DOMAIN_IN_PATTERN = re.compile(r"((?:[a-z0-9-]+\\\.)+[a-z]{2,})(?![a-z0-9\\])")


# "embed\\.js", "ext\\.php": file names in a URL pattern, not domains.
_FILE_EXTENSIONS = frozenset({"js", "php", "css", "html", "htm", "json", "svg", "png", "gif"})
# AS owners that differ from as_names on purpose: Linode is Akamai's now, and its AS
# number is listed, so the name never decides.
EXPECTED_OWNERS = {63949: "akamai connected cloud"}


def pattern_domains(pattern: str) -> list[str]:
    """Registrable domains written out in a regex, skipping file names."""
    out = []
    for m in _DOMAIN_IN_PATTERN.finditer(pattern):
        domain = m.group(1).replace("\\.", ".")
        if domain.rsplit(".", 1)[-1] not in _FILE_EXTENSIONS:
            out.append(registrable_domain(domain))
    return out


def suffix_domain(suffix: str) -> str | None:
    """ "*awsdns-*" has no fixed domain; "ns.cloudflare.com" gives cloudflare.com."""
    if "*" in suffix or "." not in suffix:
        return None
    return registrable_domain(suffix.strip("."))


def targets(data: dict[str, Any]) -> tuple[dict[str, set[str]], dict[int, tuple[str, list[str]]]]:
    """Domains to check (domain -> services using it) and AS numbers (asn -> service, names)."""
    domains: dict[str, set[str]] = {}
    asns: dict[int, tuple[str, list[str]]] = {}
    for section in ("infra", "page"):
        for entry in data[section]:
            names = [suffix_domain(s) for s in entry.get("ns", []) + entry.get("mx", [])]
            for pattern in entry.get("page", []):
                names += pattern_domains(pattern)
            for name in filter(None, names):
                domains.setdefault(name, set()).add(entry["name"])
            for asn in entry.get("asn", []):
                asns[asn] = (entry["name"], entry.get("as_names", []))
    return domains, asns


async def check(resolver: DnsResolver, data: dict[str, Any]) -> list[str]:
    domains, asns = targets(data)
    problems: list[str] = []
    gate = asyncio.Semaphore(CONCURRENCY)

    async def domain(name: str) -> None:
        async with gate:
            try:
                alive = await resolver.exists(name)
            except DnsLookupError:
                return  # no answer is not proof of anything
        if not alive:
            users = ", ".join(sorted(domains[name]))
            problems.append(f"домен {name} не существует (NXDOMAIN); используют: {users}")

    async def asn(number: int) -> None:
        service, expected = asns[number]
        async with gate:
            try:
                txt = await resolver.resolve(f"AS{number}.asn.cymru.com", "TXT")
            except DnsLookupError:
                return
        if not txt:
            problems.append(f"AS{number} ({service}): Team Cymru не знает такой AS")
            return
        _, owner = parse_cymru_asname(txt[0])
        known = EXPECTED_OWNERS.get(number)
        if known and known in (owner or "").lower():
            return
        if expected and not any(e.lower() in (owner or "").lower() for e in expected):
            problems.append(
                f"AS{number} ({service}): владелец «{owner}», а в базе ожидается "
                f"{' / '.join(expected)}"
            )

    await asyncio.gather(*(domain(d) for d in domains), *(asn(a) for a in asns))
    return sorted(problems)


def main() -> int:
    data = json.loads(DATA.read_text(encoding="utf-8"))

    async def run() -> list[str]:
        async with httpx.AsyncClient(timeout=10) as client:
            resolver, note = await create_resolver("auto", 10, client)
            if note:
                print(note)
            return await check(resolver, data)

    domains, asns = targets(data)
    problems = asyncio.run(run())
    print(f"Проверено доменов: {len(domains)}, номеров AS: {len(asns)}.")
    for line in problems:
        print(f"  ! {line}")
    print("Расхождений нет." if not problems else f"Расхождений: {len(problems)}.")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
