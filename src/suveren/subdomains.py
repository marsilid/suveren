"""Subdomains from Certificate Transparency logs and possible subdomain takeovers.

Every publicly trusted TLS certificate is logged, so CT logs list the names a company
has ever got certificates for, including forgotten promo sites. A forgotten name whose
CNAME still points at a service where the project was deleted can be claimed by
anyone who opens an account there, and then serves their page (phishing, cookie
theft) on the company's own domain.

Passive only: one CT query, DNS lookups, and for names pointing at a known service
one GET of the page it serves, as a browser would.
"""

from __future__ import annotations

import asyncio
import html
import json
import re
from dataclasses import dataclass, field
from typing import Any

import httpx

from suveren.cache import age_text, cache_dir, is_fresh
from suveren.checks import Check, Evidence, Status, asked, copy_of
from suveren.checks import source as source_evidence
from suveren.collect import NO_RDAP_ZONES, RDAP_URL, whois_query
from suveren.dnsutil import DnsLookupError, DnsResolver
from suveren.errors import TIMEOUTS, ModuleError, describe
from suveren.takeover_signatures import SOURCE_URL, Signature, database_source, find_signature
from suveren.utils import registrable_domain

GROUP_SUB = "Поддомены"

CRTSH_URL = "https://crt.sh/"
CERTSPOTTER_URL = "https://api.certspotter.com/v1/issuances"
CRTSH_ATTEMPTS = 2
CRTSH_RETRY_DELAY = 3.0
CERTSPOTTER_PAGES = 5
# The whole stage: certificate logs can take a minute per attempt, and in a batch the
# stage once pushed alfabank.ru and sovcombank.ru past the per-site deadline, losing
# the whole report for want of one section.
STAGE_BUDGET = 120.0
STALE_TTL = 14 * 24 * 3600  # an old list, used only when both logs are down
MAX_SUBDOMAINS = 300
MAX_CNAME_HOPS = 4
DNS_CONCURRENCY = 20
PAGE_BYTES = 200_000
RU_WHOIS = "whois.tcinet.ru"  # .ru, .su and .рф
WHOIS_TIMEOUT = 10.0
_LABEL = r"[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?"
_NAME = re.compile(rf"^{_LABEL}(?:\.{_LABEL})+$")


# --- CT logs --------------------------------------------------------------------------


def clean_names(raw: list[str], domain: str) -> list[str]:
    """Unique subdomains of ``domain`` without wildcards, the apex or junk."""
    suffix = "." + domain
    names = set()
    for item in raw:
        for name in item.lower().split():
            name = name.strip().rstrip(".").removeprefix("*.")
            if name.endswith(suffix) and name != domain and _NAME.match(name):
                names.add(name)
    return sorted(names)


def parse_crtsh(rows: list[dict[str, Any]]) -> list[str]:
    return [str(r.get("name_value", "")) for r in rows]


def parse_certspotter(rows: list[dict[str, Any]]) -> list[str]:
    return [str(n) for r in rows for n in r.get("dns_names", [])]


async def _crtsh(client: httpx.AsyncClient, domain: str) -> list[str]:
    timeout = httpx.Timeout(15.0, read=60.0)
    params = {"q": f"%.{domain}", "output": "json"}
    for attempt in range(CRTSH_ATTEMPTS):
        try:
            resp = await client.get(CRTSH_URL, params=params, timeout=timeout)
            resp.raise_for_status()
            return parse_crtsh(resp.json())
        except (httpx.HTTPError, ValueError, AttributeError, *TIMEOUTS):
            # crt.sh is often overloaded for a moment; one retry usually helps.
            if attempt + 1 == CRTSH_ATTEMPTS:
                raise
            await asyncio.sleep(CRTSH_RETRY_DELAY)
    return []


async def _certspotter(client: httpx.AsyncClient, domain: str) -> list[str]:
    """All pages of issuances; the free API returns them in chunks."""
    params = {"domain": domain, "include_subdomains": "true", "expand": "dns_names"}
    names: list[str] = []
    for _ in range(CERTSPOTTER_PAGES):
        resp = await client.get(CERTSPOTTER_URL, params=params, timeout=30.0)
        resp.raise_for_status()
        rows = resp.json()
        if not rows:
            break
        names += parse_certspotter(rows)
        params["after"] = str(rows[-1].get("id", ""))
    return names


async def ct_subdomains(
    client: httpx.AsyncClient, domain: str, *, refresh: bool = False
) -> tuple[list[str], str]:
    """Subdomains seen in CT logs and the source used; cached for a day."""
    path = cache_dir() / "ct" / f"{domain}.json"
    if not refresh and is_fresh(path):
        cached = json.loads(path.read_text(encoding="utf-8"))
        return cached["names"], cached["source"]
    errors = []
    # An empty list is not trusted from one log: overloaded crt.sh answers 200 with
    # "[]" for big sites. The other log is asked, and an empty answer is not cached.
    empty: str | None = None
    for source, fetch in (("crt.sh", _crtsh), ("Cert Spotter", _certspotter)):
        try:
            names = clean_names(await fetch(client, domain), domain)
        except (httpx.HTTPError, ValueError, AttributeError, *TIMEOUTS) as exc:
            errors.append(f"{source}: {_why(exc)}")
            continue
        if not names and empty is None:
            empty = source
            continue
        if not names:
            source = f"{empty} и {source}"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({"names": names, "source": source}), encoding="utf-8")
        return names, source
    if empty:
        errors.insert(0, f"{empty}: пустой список")
    # Both logs fail often at night: a list from the last days beats "not checked", and
    # the source says how old it is.
    if path.exists() and is_fresh(path, STALE_TTL):
        cached = json.loads(path.read_text(encoding="utf-8"))
        return cached["names"], f"{cached['source']}, сохранённый список ({age_text(path)})"
    raise ModuleError(f"журналы сертификатов недоступны ({'; '.join(errors)}), попробуйте позже")


def _why(exc: BaseException) -> str:
    if isinstance(exc, httpx.HTTPStatusError):
        code = exc.response.status_code
        return "слишком много запросов" if code == 429 else f"HTTP {code}"
    if isinstance(exc, (httpx.TimeoutException, *TIMEOUTS)):
        return "не ответил вовремя"
    return describe(exc)


# --- DNS ------------------------------------------------------------------------------


@dataclass(slots=True)
class Subdomain:
    name: str
    cnames: list[str] = field(default_factory=list)  # CNAME chain, first hop first
    addresses: list[str] = field(default_factory=list)
    # DNS gave no trustworthy answer: whether the name exists is unknown.
    failed: bool = False

    @property
    def alive(self) -> bool:
        return bool(self.addresses)

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "cname": self.cnames, "addresses": self.addresses}


async def resolve_subdomain(resolver: DnsResolver, name: str) -> Subdomain:
    sub = Subdomain(name)
    current = name
    try:
        for _ in range(MAX_CNAME_HOPS):
            targets = await resolver.resolve(current, "CNAME")
            if not targets:
                break
            current = targets[0].rstrip(".").lower()
            sub.cnames.append(current)
        sub.addresses = await resolver.resolve(name, "A")
    except DnsLookupError:
        sub.failed = True
    return sub


# --- Takeover -------------------------------------------------------------------------


@dataclass(slots=True)
class Candidate:
    sub: Subdomain
    reason: str
    certain: bool  # the target domain is unregistered: anyone can buy it
    service: str | None = None
    # "Edge case" in the source: the service has hurdles (such as a domain check),
    # and takeover works only sometimes. Listed after the plain cases.
    edge: bool = False


def page_text(body: str) -> str:
    """Visible text: tags can split a fingerprint ("Request ID:<span>…")."""
    text = re.sub(r"(?s)<(script|style).*?</>", " ", body)
    return " ".join(html.unescape(re.sub(r"<[^>]+>", " ", text)).split())


def page_matches(sig: Signature, status: int, body: str) -> bool:
    texts = (body, page_text(body))
    for fp in sig.fingerprints:
        if fp.startswith("HTTP_STATUS="):
            if str(status) == fp.split("=", 1)[1]:
                return True
            continue
        for text in texts:
            try:
                if re.search(fp, text):
                    return True
            except re.error:
                if fp in text:
                    return True
    return False


async def _fetch(client: httpx.AsyncClient, name: str) -> tuple[int, str] | None:
    for url in (f"https://{name}/", f"http://{name}/"):
        try:
            # Fingerprints were collected with curl-like requests; some services (Netlify)
            # answer a browser's Accept: text/html with a page drawn by scripts instead.
            resp = await client.get(url, headers={"Accept": "*/*"})
        except (httpx.HTTPError, *TIMEOUTS):
            continue
        return resp.status_code, resp.text[:PAGE_BYTES]
    return None


async def _missing_from_dns(resolver: DnsResolver, target: str, own: str) -> str | None:
    """The CNAME target's domain if DNS says it does not exist."""
    reg = registrable_domain(target)
    if reg == own or "." not in reg:
        return None
    tld = reg.rsplit(".", 1)[1]
    # Internal names (host.lan, server.corp) are not domains anyone can register.
    if not await resolver.exists(tld) or await resolver.exists(reg):
        return None
    return reg


async def is_registered(client: httpx.AsyncClient, domain: str) -> bool | None:
    """Ask the registry: True if taken, False if free, None if it did not say.

    DNS alone can't tell: a registered domain without name servers (lamoda.tech,
    status "inactive") is missing from DNS too, yet nobody else can buy it.
    """
    tld = domain.rsplit(".", 1)[-1]
    try:
        if tld in NO_RDAP_ZONES:
            text = await whois_query(RU_WHOIS, domain, WHOIS_TIMEOUT)
            if re.search(r"(?im)^\s*domain:", text):
                return True
            return False if "No entries found" in text else None
        resp = await client.get(RDAP_URL.format(domain))
    except (httpx.HTTPError, OSError, *TIMEOUTS):
        return None
    if resp.status_code == 404:
        return False
    return True if resp.status_code == 200 else None


async def find_candidate(
    resolver: DnsResolver, client: httpx.AsyncClient, sub: Subdomain, own: str
) -> Candidate | None:
    # A failed lookup is not a missing resource: no takeover is claimed on it.
    if not sub.cnames or sub.failed:
        return None
    target = sub.cnames[-1]
    if not sub.alive:
        missing = await _missing_from_dns(resolver, target, own)
        registered = await is_registered(client, missing) if missing else True
        if registered is False:
            return Candidate(
                sub,
                f"CNAME ведёт на {target}, а домен {missing} не зарегистрирован: его может "
                "купить кто угодно и показывать на вашем поддомене свой сайт",
                certain=True,
            )
        if registered is None:
            return Candidate(
                sub,
                f"CNAME ведёт на {target}, а домена {missing} нет в DNS, и реестр не ответил: "
                "если домен свободен, его может купить кто угодно",
                certain=False,
            )
    sig = find_signature(sub.cnames)
    if sig is None:
        return None
    if sig.nxdomain:
        if sub.alive:
            return None
        return Candidate(
            sub,
            f"CNAME ведёт на {target} ({sig.service}), но такого ресурса больше нет: его "
            "можно создать заново в чужом аккаунте" + _edge_note(sig),
            certain=False,
            service=sig.service,
            edge=not sig.vulnerable,
        )
    if not sub.alive or not sig.fingerprints:
        return None
    page = await _fetch(client, sub.name)
    if page is None or not page_matches(sig, *page):
        return None
    return Candidate(
        sub,
        f"CNAME ведёт на {target} ({sig.service}), а сервис отвечает, что такого проекта "
        "у него нет: подключить этот поддомен может другой клиент сервиса" + _edge_note(sig),
        certain=False,
        service=sig.service,
        edge=not sig.vulnerable,
    )


def _edge_note(sig: Signature) -> str:
    if sig.vulnerable:
        return ""
    return (
        f". Захват на {sig.service} удаётся не всегда: у сервиса есть ограничения, "
        "например подтверждение владения доменом («Edge case» в «Can I take over XYZ?»)"
    )


# --- Checks ---------------------------------------------------------------------------


@dataclass(slots=True)
class SubdomainScan:
    domain: str
    names: list[str]
    source: str
    resolved: list[Subdomain]
    candidates: list[Candidate]

    @property
    def truncated(self) -> bool:
        return len(self.names) > len(self.resolved)


def evaluate(scan: SubdomainScan) -> list[Check]:
    alive = [s for s in scan.resolved if s.alive]
    external = [s for s in scan.resolved if s.cnames]
    failed = [s for s in scan.resolved if s.failed]
    more = (
        f" Проверены первые {len(scan.resolved)} по алфавиту, всего их {len(scan.names)}."
        if scan.truncated
        else ""
    )
    inventory = Check(
        GROUP_SUB,
        "Поддомены в публичных журналах сертификатов",
        Status.OK,
        f"Найдено поддоменов: {len(scan.names)} (источник: {scan.source}). Сейчас открываются "
        f"{len(alive)}, через CNAME на внешние сервисы указывают {len(external)}.{more} "
        "Этот список видит любой: проверьте, что среди них нет забытых тестовых и "
        "служебных адресов.",
    )
    if not scan.candidates:
        takeover = Check(
            GROUP_SUB,
            "Захват поддоменов",
            Status.OK,
            f"Признаков захвата не найдено среди {len(scan.resolved)} поддоменов."
            + (
                f" DNS не ответил для {len(failed)}, они не проверены: "
                + ", ".join(s.name for s in failed[:5])
                + ("…" if len(failed) > 5 else "")
                + "."
                if failed
                else ""
            ),
        )
    else:
        certain = any(c.certain for c in scan.candidates)
        lines = "; ".join(f"{c.sub.name}: {c.reason}" for c in scan.candidates[:5])
        rest = len(scan.candidates) - 5
        if rest > 0:
            lines += f"; и ещё {rest} в JSON-отчёте"
        takeover = Check(
            GROUP_SUB,
            "Захват поддоменов",
            Status.FAIL if certain else Status.WARN,
            f"Возможен захват, проверьте вручную. {lines}. Через захваченный поддомен "
            "мошенники размещают фишинговые страницы на настоящем домене компании и могут "
            "читать её cookies.",
            "Удалите DNS-записи поддоменов, которые больше не используются, или заново "
            "подключите их к сервису в своём аккаунте.",
            link=SOURCE_URL,
        )
        # The DNS answer for each candidate: where its CNAME points and what it resolves to.
        takeover.evidence = [
            Evidence(
                "dns",
                f"CNAME {c.sub.name}",
                " → ".join(c.sub.cnames) + f" ({', '.join(c.sub.addresses) or 'адреса нет'})",
            )
            for c in scan.candidates[:10]
        ]
    # A clean answer rests on the signatures too: services added since are not known.
    takeover.evidence.append(source_evidence(database_source()))
    return [inventory, takeover]


async def scan_subdomains(
    resolver: DnsResolver,
    client: httpx.AsyncClient,
    page_client: httpx.AsyncClient,
    domain: str,
    *,
    refresh: bool = False,
) -> SubdomainScan:
    names, source = await ct_subdomains(client, domain, refresh=refresh)
    semaphore = asyncio.Semaphore(DNS_CONCURRENCY)

    async def resolve(name: str) -> Subdomain:
        async with semaphore:
            return await resolve_subdomain(resolver, name)

    async def check(sub: Subdomain) -> Candidate | None:
        async with semaphore:
            return await find_candidate(resolver, page_client, sub, domain)

    resolved = list(await asyncio.gather(*(resolve(n) for n in names[:MAX_SUBDOMAINS])))
    found = await asyncio.gather(*(check(s) for s in resolved))
    candidates = [c for c in found if c is not None]
    candidates.sort(key=lambda c: (not c.certain, c.edge, c.sub.name))
    return SubdomainScan(domain, names, source, resolved, candidates)


async def run_subdomain_checks(
    resolver: DnsResolver,
    client: httpx.AsyncClient,
    page_client: httpx.AsyncClient,
    domain: str,
    *,
    refresh: bool = False,
) -> tuple[list[Check], dict[str, Any]]:
    """Checks for the report and raw data for the JSON facts."""
    try:
        scan = await asyncio.wait_for(
            scan_subdomains(resolver, client, page_client, domain, refresh=refresh),
            STAGE_BUDGET,
        )
    except TIMEOUTS:
        return [
            Check(
                GROUP_SUB,
                "Поддомены и их захват",
                Status.UNKNOWN,
                f"Не проверено: журналы сертификатов отвечали дольше {STAGE_BUDGET:.0f} с, "
                "попробуйте позже.",
            )
        ], {}
    except ModuleError as exc:
        return [
            Check(GROUP_SUB, "Поддомены и их захват", Status.UNKNOWN, f"Не проверено: {exc}.")
        ], {}
    data = {
        "source": scan.source,
        "total": len(scan.names),
        "checked": [s.to_dict() for s in scan.resolved],
        "takeover": [
            {
                "name": c.sub.name,
                "reason": c.reason,
                "certain": c.certain,
                "service": c.service,
                "edge": c.edge,
            }
            for c in scan.candidates
        ],
    }
    checks = evaluate(scan)
    # The list is cached for a day: its date is the day the log answered, not the scan's.
    path = cache_dir() / "ct" / f"{domain}.json"
    name = f"журналы сертификатов, {scan.source}"
    origin = copy_of(name, path, "список") if path.exists() else asked(name)
    for check in checks:
        check.evidence.append(source_evidence(origin))
    return checks, data
