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
import ssl
from dataclasses import dataclass, field
from typing import Any

import certifi
import httpx

from suveren import __version__
from suveren.crawl import FetchedPage
from suveren.dnsutil import DnsLookupError, DnsResolver, ResolverMode, create_resolver
from suveren.errors import TIMEOUTS, ModuleError, TargetNotFoundError
from suveren.page import parse_page
from suveren.utils import registrable_domain

USER_AGENT = (
    f"Mozilla/5.0 (compatible; Suveren/{__version__}; +https://github.com/marsilid/suveren)"
)
RDAP_URL = "https://rdap.org/domain/{}"
IANA_WHOIS = "whois.iana.org"
NO_RDAP_ZONES = frozenset({"ru", "su", "xn--p1ai"})
MAX_HTML_CHARS = 2_000_000
MAX_HOSTS = 6
MAX_IPS_PER_HOST = 4


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
    tls_trusted: bool | None = None
    final_url: str | None = None
    page_status: int | None = None
    html: str = ""
    # Home page response headers (lower-case names) and raw Set-Cookie lines; the
    # cookies are only read for their flags and never written to reports.
    headers: dict[str, str] = field(default_factory=dict)
    set_cookies: list[str] = field(default_factory=list)
    # Why that HTTP response is not the real site (a bot wall), if it isn't. Kept apart
    # from page_problem: --browser may get past the wall while the headers did not.
    http_problem: str | None = None
    # Extra hosts the page loaded at runtime (filled by the --browser mode).
    loaded_urls: list[str] = field(default_factory=list)
    # Who started each script request on the home page (--browser): script URL ->
    # the URL of the script that loaded it, or "" when the page's own HTML did.
    initiators: dict[str, str] = field(default_factory=dict)
    # The home page's response headers as the browser got them (--browser): used when
    # plain HTTP met a bot wall but the browser got through to the site.
    browser_headers: dict[str, str] = field(default_factory=dict)
    rendered: bool = False
    # Internal pages fetched besides the home page (contacts, order forms, ...).
    extra_pages: list[FetchedPage] = field(default_factory=list)
    # Pages opened in the browser for later checks (the privacy policy), keyed by URL.
    prefetched: dict[str, FetchedPage] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)

    @property
    def page_problem(self) -> str | None:
        """Why the home page can't be analysed, or None if it can."""
        if not self.html:
            return "главная страница не загрузилась"
        return page_problem(self.page_status, self.html, rendered=self.rendered)

    def to_dict(self) -> dict[str, Any]:
        return {
            "host": self.host,
            "domain": self.domain,
            "ns": [h.to_dict() for h in self.ns],
            "mx": [h.to_dict() for h in self.mx],
            "web": [n.to_dict() for n in self.web],
            "registrar": self.registrar,
            "tls_issuer": self.tls_issuer,
            "tls_trusted": self.tls_trusted,
            "final_url": self.final_url,
            "page_status": self.page_status,
            "rendered": self.rendered,
            "page_problem": self.page_problem,
            "extra_pages": [p.url for p in self.extra_pages],
        }


_CHALLENGE = re.compile(
    r"captcha|challenge|доступ ограничен|доступ запрещ|проверка безопасности|"
    r"запрос отклонен|пройдите проверку|подтвердите, что вы|checking your browser|"
    r"ddos-guard|servicepipe|qrator|antibot|are you a robot|не робот|access denied|"
    r"enable javascript|включите javascript|user_blocked",
    re.I,
)


def page_problem(status: int | None, html: str, *, rendered: bool = False) -> str | None:
    """Detect anti-bot pages and empty JavaScript shells that can't be analysed."""
    page = parse_page(html)
    # Stub pages are short; they may still carry a phone number or a few links.
    short = len(page.text) < 1500
    # A small page with no scripts at all is simply small, not built by scripts.
    scripted = "<script" in html.lower()
    thin = len(page.links) < 10 and len(page.text) < 600 and (scripted or rendered)
    challenge = short and bool(_CHALLENGE.search(html[:30000]))
    # A browser may pass a challenge that first answered 403/503: judge the content then.
    if status is not None and status >= 400 and (thin or challenge or not rendered):
        return f"сайт ответил кодом {status}, вероятно, это защита от ботов"
    if challenge:
        return "сайт показал страницу проверки «вы не робот»"
    if thin:
        if rendered:
            return "страница почти пустая даже после загрузки в браузере"
        return "страница собирается скриптами в браузере, в исходном HTML её содержимого нет"
    return None


def bot_wall(status: int | None, html: str) -> str | None:
    """A bot wall or an error answered instead of the site.

    Unlike page_problem, an empty JavaScript shell is not one: a single-page app's
    HTML is tiny, but its headers are the site's real headers.
    """
    if status is not None and status >= 400:
        return f"сайт ответил кодом {status}, вероятно, это защита от ботов"
    if len(parse_page(html).text) < 1500 and _CHALLENGE.search(html[:30000]):
        return "сайт показал страницу защиты от ботов"
    return None


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
    # Cymru replaces quotes with underscores: 'JSC _ER-Telecom Holding_'.
    name = re.sub(r"_([^_]+)_", r"«\1»", name)
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
        self._insecure: httpx.AsyncClient | None = None

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
        origin = await self._txt_twice(f"{arpa}.origin.asn.cymru.com")
        if origin:
            info.asn, info.country = parse_cymru_origin(origin[0])
        if info.asn:
            names = await self._txt_twice(f"AS{info.asn}.asn.cymru.com")
            if names:
                as_country, info.as_name = parse_cymru_asname(names[0])
                info.country = as_country or info.country
        return info

    async def _txt_twice(self, name: str) -> list[str]:
        """One retry: a lost answer at night left gosuslugi.ru with no owner for its IPs."""
        for attempt in range(2):
            try:
                return await self.resolver.resolve(name, "TXT")
            except DnsLookupError:
                if attempt:
                    return []
        return []

    async def _host_infos(self, host: str) -> list[HostInfo]:
        """One entry per network the host's addresses live in.

        A server name often has several A records in different networks (ns1 in the US
        and in Russia), returned in rotating order: looking only at the first one made
        the result change from run to run.
        """
        try:
            ips = sorted(set(await self.resolver.resolve(host, "A")))[:MAX_IPS_PER_HOST]
        except DnsLookupError:
            ips = []
        if not ips:
            return [HostInfo(host)]
        nets = await asyncio.gather(*(self.net_info(ip) for ip in ips))
        unique: dict[object, NetInfo] = {}
        for net in nets:
            unique.setdefault(net.asn or net.ip, net)
        return [HostInfo(host, net) for net in unique.values()]

    async def _hosts(self, hosts: list[str]) -> list[HostInfo]:
        found = await asyncio.gather(*(self._host_infos(h) for h in hosts))
        return [info for infos in found for info in infos]

    async def ns(self, domain: str) -> list[HostInfo]:
        records = await self.resolver.resolve(domain, "NS")
        return await self._hosts(sorted({r.rstrip(".").lower() for r in records})[:MAX_HOSTS])

    async def mx(self, domain: str) -> list[HostInfo]:
        return await self._hosts(parse_mx(await self.resolver.resolve(domain, "MX"))[:MAX_HOSTS])

    async def web(self, host: str) -> list[NetInfo]:
        ips = await self.resolver.resolve(host, "A")
        if not ips and not host.startswith("www."):
            ips = await self.resolver.resolve(f"www.{host}", "A")
        unique = sorted(set(ips))[:MAX_HOSTS]
        return list(await asyncio.gather(*(self.net_info(ip) for ip in unique)))

    async def homepage(self, host: str) -> tuple[str, int, str, httpx.Headers]:
        """(final URL, HTTP status, HTML, headers). Tolerates certificates Python doesn't
        trust, such as the Russian НУЦ Минцифры root, before falling back to plain HTTP."""
        last_error: Exception | None = None
        attempts = ((self.client, f"https://{host}/"), (None, f"https://{host}/"))
        for client, url in (*attempts, (self.client, f"http://{host}/")):
            if client is None:
                if not _is_tls_error(last_error):
                    continue
                client = self.insecure_client
            try:
                resp = await client.get(url)
            except httpx.HTTPError as exc:
                last_error = exc
                continue
            return str(resp.url), resp.status_code, resp.text[:MAX_HTML_CHARS], resp.headers
        raise ModuleError(f"сайт не открылся ({type(last_error).__name__})")

    @property
    def insecure_client(self) -> httpx.AsyncClient:
        if self._insecure is None:
            self._insecure = make_client(self.timeout, verify=False)
        return self._insecure

    async def aclose(self) -> None:
        if self._insecure is not None:
            await self._insecure.aclose()

    async def registrar(self, domain: str) -> str | None:
        tld = domain.rsplit(".", 1)[-1]
        # The .ru/.рф/.su registry has no RDAP: asking costs seconds for a 404.
        if tld not in NO_RDAP_ZONES:
            with contextlib.suppress(httpx.HTTPError, ValueError):
                resp = await self.client.get(RDAP_URL.format(domain))
                if resp.status_code == 200:
                    name = parse_rdap_registrar(resp.json())
                    if name:
                        return name
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
        except (OSError, *TIMEOUTS) as exc:
            raise ModuleError(f"WHOIS недоступен ({type(exc).__name__})") from exc

    async def tls_issuer(self, host: str) -> tuple[str | None, bool | None]:
        """(issuer organisation, trusted by the standard CA bundle)."""
        try:
            return await self._issuer(host, verify=True), True
        except ssl.SSLCertVerificationError:
            pass
        except (OSError, *TIMEOUTS, ssl.SSLError):
            return None, None
        try:
            return await self._issuer(host, verify=False), False
        except (OSError, *TIMEOUTS, ssl.SSLError):
            return None, None

    async def _issuer(self, host: str, *, verify: bool) -> str | None:
        context = browser_trust()
        if not verify:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(host, 443, ssl=context, server_hostname=host),
            self.timeout,
        )
        try:
            sslobj = writer.get_extra_info("ssl_object")
            if sslobj is None:
                return None
            if verify:
                cert = sslobj.getpeercert()
                return issuer_org(cert) if cert else None
            der = sslobj.getpeercert(binary_form=True)
            return issuer_from_der(der) if der else None
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


def parse_whois_org(text: str) -> str | None:
    keys = ("org", "registrant organization", "registrant organisation", "organization")
    for line in text.splitlines():
        key, sep, value = line.strip().partition(":")
        if sep and key.strip().lower() in keys and value.strip():
            return value.strip()
    return None


async def whois_raw(domain: str, timeout: float) -> str | None:
    """Raw WHOIS text from the registry's server (found via IANA)."""
    tld = domain.rsplit(".", 1)[-1]
    try:
        iana = await whois_query(IANA_WHOIS, tld, timeout)
        server = next(
            (
                line.split(":", 1)[1].strip()
                for line in iana.splitlines()
                if line.lower().startswith(("refer:", "whois:"))
            ),
            None,
        )
        return await whois_query(server, domain, timeout) if server else None
    except (OSError, *TIMEOUTS):
        return None


def browser_trust() -> ssl.SSLContext:
    """Verify against Mozilla's root list, as httpx does, not the Windows store.

    Windows adds a root only when something first needs it, so the store often lacks
    newer roots (vk.com's SSL.com 2022, dzen.ru's HARICA 2021) and real chains fail.
    """
    return ssl.create_default_context(cafile=certifi.where())


def make_client(timeout: float, *, verify: bool = True) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        timeout=timeout,
        follow_redirects=True,
        verify=verify,
        headers={
            "User-Agent": USER_AGENT,
            "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
            "Accept-Language": "ru-RU,ru;q=0.9,en;q=0.5",
        },
        limits=httpx.Limits(max_connections=20),
    )


def _is_tls_error(exc: BaseException | None) -> bool:
    """httpx wraps certificate failures in ConnectError; walk the chain."""
    while exc is not None:
        if isinstance(exc, ssl.SSLError):
            return True
        exc = exc.__cause__ or exc.__context__
    return False


def issuer_from_der(der: bytes) -> str | None:
    """Issuer organisation from a raw certificate (used when it isn't trusted)."""
    from cryptography import x509
    from cryptography.x509.oid import NameOID

    try:
        cert = x509.load_der_x509_certificate(der)
    except ValueError:
        return None
    for oid in (NameOID.ORGANIZATION_NAME, NameOID.COMMON_NAME):
        attrs = cert.issuer.get_attributes_for_oid(oid)
        if attrs:
            return str(attrs[0].value)
    return None


async def collect(host: str, *, timeout: float = 10.0, dns_mode: ResolverMode = "auto") -> Facts:
    domain = registrable_domain(host)
    facts = Facts(host=host, domain=domain)

    async with make_client(timeout) as client:
        resolver, note = await create_resolver(dns_mode, timeout, client)
        if note:
            facts.notes.append(note)
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
        await c.aclose()

    for key, value in zip(tasks, results, strict=True):
        if isinstance(value, BaseException):
            if not isinstance(value, (ModuleError, httpx.HTTPError, OSError, *TIMEOUTS)):
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
            facts.final_url, facts.page_status, facts.html, headers = value
            facts.headers = {k.lower(): v for k, v in headers.items()}
            facts.set_cookies = headers.get_list("set-cookie")
            facts.http_problem = bot_wall(facts.page_status, facts.html)
        elif key == "registrar":
            facts.registrar = value
        elif key == "tls":
            facts.tls_issuer, facts.tls_trusted = value
    return facts
