"""DNS resolution with two interchangeable backends.

* ``SystemResolver`` — the OS-configured resolver via dnspython.
* ``DohResolver`` — DNS-over-HTTPS JSON APIs (Google, then Cloudflare).

Some networks (corporate proxies, captive portals, sandboxes, a few home routers)
answer only A queries and return empty answers for TXT/MX/NS. For a security
tool that is dangerous: "no SPF record" would be a false HIGH finding. In
``auto`` mode we therefore probe the system resolver with a record that is known
to exist and fall back to DoH if the answer is missing.

Contract for ``resolve``: an empty list means the name has no records of that
type (NOERROR/NODATA or NXDOMAIN). Anything that prevents a trustworthy answer
(timeout, SERVFAIL, HTTP failure) raises :class:`DnsLookupError` instead.
"""

from __future__ import annotations

import asyncio
from abc import ABC, abstractmethod
from typing import Literal

import dns.asyncresolver
import dns.exception
import dns.resolver
import httpx

from suveren.errors import ModuleError

ResolverMode = Literal["auto", "system", "doh"]

_FALLBACK_NAMESERVERS = ["1.1.1.1", "8.8.8.8"]
# (name, type) pairs that must always have records; used to detect filtering resolvers.
_CANARIES = (("google.com", "MX"), ("cloudflare.com", "TXT"))

RR_TYPES = {
    "A": 1,
    "NS": 2,
    "CNAME": 5,
    "SOA": 6,
    "MX": 15,
    "TXT": 16,
    "AAAA": 28,
    "DNSKEY": 48,
    "CAA": 257,
}
HEALTH_TIMEOUT = 3.0
_system_healthy: bool | None = None

DOH_ENDPOINTS = ("https://dns.google/resolve", "https://cloudflare-dns.com/dns-query")


class DnsLookupError(ModuleError):
    """The resolver could not give a trustworthy answer."""


class DnsResolver(ABC):
    kind: str

    @abstractmethod
    async def resolve(self, name: str, rtype: str) -> list[str]: ...

    @abstractmethod
    async def exists(self, domain: str) -> bool:
        """False only on a definitive NXDOMAIN."""

    async def is_healthy(self) -> bool:
        async def probe(name: str, rtype: str) -> bool:
            try:
                return bool(await self.resolve(name, rtype))
            except DnsLookupError:
                return False

        results = await asyncio.gather(*(probe(n, t) for n, t in _CANARIES))
        return all(results)


class SystemResolver(DnsResolver):
    kind = "system"

    def __init__(self, timeout: float) -> None:
        try:
            resolver = dns.asyncresolver.Resolver()
        except dns.resolver.NoResolverConfiguration:
            resolver = dns.asyncresolver.Resolver(configure=False)
        if not resolver.nameservers:
            resolver.nameservers = list(_FALLBACK_NAMESERVERS)
        resolver.lifetime = timeout
        resolver.timeout = max(1.0, timeout / 2)
        self._resolver = resolver

    async def resolve(self, name: str, rtype: str) -> list[str]:
        try:
            answer = await self._resolver.resolve(name, rtype)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return []
        except (dns.resolver.NoNameservers, dns.exception.Timeout) as exc:
            raise DnsLookupError(f"DNS lookup {name} {rtype} failed: {type(exc).__name__}") from exc
        if rtype == "TXT":
            # TXT records may be split into several 255-byte strings; join them back.
            return [b"".join(r.strings).decode("utf-8", "replace") for r in answer]
        return [r.to_text() for r in answer]

    async def exists(self, domain: str) -> bool:
        try:
            await self._resolver.resolve(domain, "SOA")
        except dns.resolver.NXDOMAIN:
            return False
        except (dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.Timeout):
            return True
        return True


def _clean_doh_data(rtype: str, data: str) -> str:
    if rtype != "TXT":
        return data
    # Cloudflare returns '"part1" "part2"', Google returns the joined text.
    if data.startswith('"') and data.endswith('"'):
        return "".join(part for part in data[1:-1].split('" "'))
    return data


def parse_doh_answer(payload: dict, rtype: str) -> list[str]:
    """Extract records of ``rtype`` from a DoH JSON response (skips CNAME hops)."""
    status = payload.get("Status")
    if status == 3:  # NXDOMAIN
        return []
    if status != 0:
        raise DnsLookupError(f"DNS server returned rcode {status}")
    wanted = RR_TYPES[rtype]
    return [
        _clean_doh_data(rtype, str(rr.get("data", "")))
        for rr in payload.get("Answer", [])
        if rr.get("type") == wanted
    ]


class DohResolver(DnsResolver):
    kind = "doh"

    def __init__(self, client: httpx.AsyncClient) -> None:
        self._client = client

    async def _query(self, name: str, rtype: str) -> dict:
        last_error: Exception | None = None
        for endpoint in DOH_ENDPOINTS:
            try:
                resp = await self._client.get(
                    endpoint,
                    params={"name": name, "type": rtype},
                    headers={"Accept": "application/dns-json"},
                )
                resp.raise_for_status()
                return resp.json()
            except (httpx.HTTPError, ValueError) as exc:
                last_error = exc
        raise DnsLookupError(f"DoH lookup {name} {rtype} failed: {type(last_error).__name__}")

    async def resolve(self, name: str, rtype: str) -> list[str]:
        return parse_doh_answer(await self._query(name, rtype), rtype)

    async def exists(self, domain: str) -> bool:
        try:
            payload = await self._query(domain, "SOA")
        except DnsLookupError:
            return True
        return payload.get("Status") != 3


async def create_resolver(
    mode: ResolverMode, timeout: float, client: httpx.AsyncClient
) -> tuple[DnsResolver, str | None]:
    """Return the resolver to use and, if we had to switch, a note explaining why."""
    if mode == "doh":
        return DohResolver(client), None
    system = SystemResolver(timeout)
    if mode == "system":
        return system, None
    # The health probe can wait for a timeout on a filtering network, so its answer
    # is remembered for the rest of the process (batch scans many sites in a row).
    global _system_healthy
    if _system_healthy is None:
        _system_healthy = await SystemResolver(min(timeout, HEALTH_TIMEOUT)).is_healthy()
    if _system_healthy:
        return system, None
    return DohResolver(client), (
        "The system DNS resolver returned incomplete answers (it looks filtered), "
        "so DNS-over-HTTPS was used instead."
    )
