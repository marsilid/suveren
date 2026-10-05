"""Collects raw facts about a domain from public sources.

Everything here is passive or equivalent to a normal browser visit: DNS
queries, one WHOIS/RDAP lookup, one TLS handshake and one GET of the home page.
Network ownership (ASN) comes from Team Cymru's free IP-to-ASN service over DNS.
"""

from __future__ import annotations

import asyncio
import contextlib
import ipaddress
import re
import socket
import ssl
from dataclasses import dataclass, field
from typing import Any

import httpx

from suveren import __version__
from suveren.dnsutil import DnsLookupError, DnsResolver, ResolverMode, create_resolver
from suveren.errors import ModuleError, TargetNotFoundError
from suveren.utils import registrable_domain

USER_AGENT = (
    f"Mozilla/5.0 (compatible; Suveren/{__version__}; +https://github.com/marsilid/suveren)"
)
RDAP_URL = "https://rdap.org/domain/{}"
IANA_WHOIS = "whois.iana.org"
MAX_HTML_CHARS = 2_000_000
MAX_HOSTS = 6


@dataclass(slots=True)
class NetInfo:
    """Who owns the network an IP address lives in."""

    ip: str
    asn: int | None = None
    as_name: str | None = None
    country: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "ip": self.ip,
            "asn": f"AS{self.asn}" if self.asn else None,
            "as_name": self.as_name,
            "country": self.country,
        }


@dataclass(slots=True)
class HostInfo:
    host: str
    net: NetInfo | None = None

    def to_dict(self) -> dict[str, Any]:
        return {"host": self.host, **(self.net.to_dict() if self.net else {"ip": None})}


@dataclass(slots=True)
class Facts:
    host: str
    domain: str
    ns: list[HostInfo] = field(default_factory=list)
    mx: list[HostInfo] = field(default_factory=list)
    web: list[NetInfo] = field(default_factory=list)
    registrar: str | None = None
    tls_issuer: str | None = None
    final_url: str | None = None
    html: str = ""
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "host": self.host,
            "domain": self.domain,
            "ns": [h.to_dict() for h in self.ns],
            "mx": [h.to_dict() for h in self.mx],
            "web": [n.to_dict() for n in self.web],
            "registrar": self.registrar,
            "tls_issuer": self.tls_issuer,
            "final_url": self.final_url,
        }


# --- Parsers (pure functions, unit-tested) -------------------------------------------


def parse_cymru_origin(txt: str) -> tuple[int | None, str | None]:
    """'13335 | 1.1.1.0/24 | US | arin | 2010-07-14' -> (13335, 'US')."""
    parts = [p.strip() for p in txt.strip('"').split("|")]
    if len(parts) < 3:
        return None, None
    asn_field = parts[0].split()
    asn = int(asn_field[0]) if asn_field and asn_field[0].isdigit() else None
    return asn, (parts[2] or None)


def parse_cymru_asname(txt: str) -> tuple[str | None, str | None]:
    """'13335 | US | arin | 2010-07-14 | CLOUDFLARENET, US' -> ('US', 'CLOUDFLARENET').

    The country here is where the network owner is registered, which matters more
    for sanctions than where a particular prefix happens to be announced.
    """
    parts = [p.strip() for p in txt.strip('"').split("|")]
    if len(parts) < 5:
        return None, None
    return (parts[1] or None), clean_as_name(parts[-1])


def clean_as_name(raw: str) -> str | None:
    """'PAGM-AS - CLOUD.DOG OU, EE' -> 'CLOUD.DOG OU'; 'CLOUDFLARENET, US' -> 'CLOUDFLARENET'."""
    name = re.sub(r",\s*[A-Z]{2}$", "", raw.strip())
    _, sep, org = name.partition(" - ")
    if sep and org.strip():
        name = org
    return name.strip() or None


def parse_mx(records: list[str]) -> list[str]:
    """'10 mx.yandex.net.' -> 'mx.yandex.net'; skips a null MX ('0 .')."""
    hosts: list[tuple[int, str]] = []
    for record in records:
        parts = record.split()
        if len(parts) != 2 or parts[1] in (".", ""):
            continue
        try:
            priority = int(parts[0])
        except ValueError:
            continue
        hosts.append((priority, parts[1].rstrip(".").lower()))
    return [h for _, h in sorted(hosts)]


def parse_rdap_registrar(doc: dict[str, Any]) -> str | None:
    for entity in doc.get("entities", []):
        if "registrar" not in entity.get("roles", []):
            continue
        vcard = entity.get("vcardArray")
        if isinstance(vcard, list) and len(vcard) == 2:
            for item in vcard[1]:
                if item and item[0] == "fn" and item[3]:
                    return str(item[3])
        return entity.get("handle")
    return None


def parse_whois_registrar(text: str) -> str | None:
    keys = ("registrar", "sponsoring registrar", "registrar name")
    for line in text.splitlines():
        key, sep, value = line.strip().partition(":")
        if sep and key.strip().lower() in keys and value.strip():
            return value.strip()
    return None


def issuer_org(cert: dict[str, Any]) -> str | None:
    """Organisation (or common name) of the issuer from ``SSLSocket.getpeercert()``."""
    fields = {k: v for rdn in cert.get("issuer", ()) for k, v in rdn}
    return fields.get("organizationName") or fields.get("commonName")


# --- Network -----------------------------------------------------------------------


class Collector:
    def __init__(self, resolver: DnsResolver, client: httpx.AsyncClient, timeout: float) -> None:
        self.resolver = resolver
        self.client = client
        self.timeout = timeout
        self._net_cache: dict[str, NetInfo] = {}

    async def net_info(self, ip: str) -> NetInfo:
        if ip not in self._net_cache:
            self._net_cache[ip] = await self._lookup_net(ip)
        return self._net_cache[ip]

    async def _lookup_net(self, ip: str) -> NetInfo:
        info = NetInfo(ip)
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return info
        if addr.version != 4:
            return info
        arpa = ".".join(reversed(ip.split(".")))
        with contextlib.suppress(DnsLookupError):
            origin = await self.resolver.resolve(f"{arpa}.origin.asn.cymru.com", "TXT")
            if origin:
                info.asn, info.country = parse_cymru_origin(origin[0])
        if info.asn:
            with contextlib.suppress(DnsLookupError):
                names = await self.resolver.resolve(f"AS{info.asn}.asn.cymru.com", "TXT")
                if names:
                    as_country, info.as_name = parse_cymru_asname(names[0])
                    info.country = as_country or info.country
        return info

    async def _host_info(self, host: str) -> HostInfo:
        try:
            ips = await self.resolver.resolve(host, "A")
        except DnsLookupError:
            ips = []
        return HostInfo(host, await self.net_info(ips[0]) if ips else None)

    async def ns(self, domain: str) -> list[HostInfo]:
        records = await self.resolver.resolve(domain, "NS")
        hosts = sorted({r.rstrip(".").lower() for r in records})[:MAX_HOSTS]
        return list(await asyncio.gather(*(self._host_info(h) for h in hosts)))

    async def mx(self, domain: str) -> list[HostInfo]:
        hosts = parse_mx(await self.resolver.resolve(domain, "MX"))[:MAX_HOSTS]
        return list(await asyncio.gather(*(self._host_info(h) for h in hosts)))

    async def web(self, host: str) -> list[NetInfo]:
        ips = await self.resolver.resolve(host, "A")
        if not ips and not host.startswith("www."):
            ips = await self.resolver.resolve(f"www.{host}", "A")
        unique = sorted(set(ips))[:MAX_HOSTS]
        return list(await asyncio.gather(*(self.net_info(ip) for ip in unique)))

    async def homepage(self, host: str) -> tuple[str, str]:
        last_error: Exception | None = None
        for url in (f"https://{host}/", f"http://{host}/"):
            try:
                resp = await self.client.get(url)
            except httpx.HTTPError as exc:
                last_error = exc
                continue
            return str(resp.url), resp.text[:MAX_HTML_CHARS]
        raise ModuleError(f"сайт не открылся ({type(last_error).__name__})")

    async def registrar(self, domain: str) -> str | None:
        with contextlib.suppress(httpx.HTTPError, ValueError):
            resp = await self.client.get(RDAP_URL.format(domain))
            if resp.status_code == 200:
                name = parse_rdap_registrar(resp.json())
                if name:
                    return name
        tld = domain.rsplit(".", 1)[-1]
        try:
            iana = await whois_query(IANA_WHOIS, tld, self.timeout)
            server = next(
                (
                    line.split(":", 1)[1].strip()
                    for line in iana.splitlines()
                    if line.lower().startswith(("refer:", "whois:"))
                ),
                None,
            )
            if not server:
                return None
            return parse_whois_registrar(await whois_query(server, domain, self.timeout))
        except (OSError, TimeoutError) as exc:
            raise ModuleError(f"WHOIS недоступен ({type(exc).__name__})") from exc

    async def tls_issuer(self, host: str) -> str | None:
        context = ssl.create_default_context()
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(host, 443, ssl=context, server_hostname=host),
                self.timeout,
            )
        except (OSError, TimeoutError, ssl.SSLError, socket.gaierror):
            return None
        try:
            sslobj = writer.get_extra_info("ssl_object")
            cert = sslobj.getpeercert() if sslobj else None
            return issuer_org(cert) if cert else None
        finally:
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()


async def whois_query(server: str, query: str, timeout: float) -> str:
    reader, writer = await asyncio.wait_for(asyncio.open_connection(server, 43), timeout)
    try:
        writer.write(f"{query}\r\n".encode())
        await writer.drain()
        data = await asyncio.wait_for(reader.read(), timeout)
    finally:
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()
    return data.decode("utf-8", errors="replace")


def make_client(timeout: float) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        timeout=timeout,
        follow_redirects=True,
        headers={"User-Agent": USER_AGENT, "Accept": "text/html,*/*"},
        limits=httpx.Limits(max_connections=20),
    )


async def collect(host: str, *, timeout: float = 10.0, dns_mode: ResolverMode = "auto") -> Facts:
    domain = registrable_domain(host)
    facts = Facts(host=host, domain=domain)

    async with make_client(timeout) as client:
        resolver, note = await create_resolver(dns_mode, timeout, client)
        if note:
            facts.notes.append(
                "Системный DNS отвечал неполно, поэтому использовался DNS-over-HTTPS."
            )
        if not await resolver.exists(domain):
            raise TargetNotFoundError(f"домен {domain} не существует (NXDOMAIN)")

        c = Collector(resolver, client, timeout)
        tasks = {
            "ns": c.ns(domain),
            "mx": c.mx(domain),
            "web": c.web(host),
            "homepage": c.homepage(host),
            "registrar": c.registrar(domain),
            "tls": c.tls_issuer(host),
        }
        labels = {
            "ns": "DNS-серверы",
            "mx": "почтовые серверы",
            "web": "IP-адреса сайта",
            "homepage": "главную страницу",
            "registrar": "регистратора",
            "tls": "SSL-сертификат",
        }
        results = await asyncio.gather(*tasks.values(), return_exceptions=True)

    for key, value in zip(tasks, results, strict=True):
        if isinstance(value, BaseException):
            if not isinstance(value, (ModuleError, httpx.HTTPError, OSError, TimeoutError)):
                raise value
            facts.notes.append(f"Не удалось получить {labels[key]}: {value}")
            continue
        if key == "ns":
            facts.ns = value
        elif key == "mx":
            facts.mx = value
        elif key == "web":
            facts.web = value
        elif key == "homepage":
            facts.final_url, facts.html = value
        elif key == "registrar":
            facts.registrar = value
        elif key == "tls":
            facts.tls_issuer = value
    return facts
