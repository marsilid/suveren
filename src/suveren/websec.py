"""Web security of the site: whose code it runs, and how well the browser is told to
protect visitors (CSP, HSTS and other headers, cookie flags, TLS).

Passive only: the home page and inner pages already fetched for the other checks,
a few TLS handshakes like a browser makes, and DNS and registry lookups for the
domains scripts are loaded from. No paths are probed and nothing is sent to forms.
"""

from __future__ import annotations

import asyncio
import contextlib
import re
import ssl
import warnings
from dataclasses import dataclass, field
from datetime import datetime, timezone
from html.parser import HTMLParser
from typing import Any
from urllib.parse import urljoin, urlsplit

import httpx
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509 import ocsp

from suveren.checks import Check, Status
from suveren.collect import Facts, browser_trust
from suveren.dnsutil import DnsResolver
from suveren.errors import TIMEOUTS
from suveren.leaks import TITLE as LEAK_TITLE
from suveren.leaks import leak_check, scan_scripts
from suveren.scriptgraph import build as build_graph
from suveren.scriptgraph import graph_check
from suveren.scriptgraph import svg as graph_svg
from suveren.subdomains import is_registered
from suveren.utils import registrable_domain
from suveren.vulns import TITLE as VULN_TITLE
from suveren.vulns import detect, vuln_check

GROUP_WEB = "Безопасность сайта"

# Public CDNs serving fixed versions of libraries: here a file never changes, so an
# integrity hash (SRI) is possible and protects against a hacked CDN. Analytics and
# widget scripts change all the time and can't have one, so they are not asked for it.
LIBRARY_CDNS = (
    "cdnjs.cloudflare.com",
    "cdn.jsdelivr.net",
    "unpkg.com",
    "ajax.googleapis.com",
    "code.jquery.com",
    "stackpath.bootstrapcdn.com",
    "maxcdn.bootstrapcdn.com",
    "cdn.datatables.net",
    "ajax.aspnetcdn.com",
)

# Domains that served malware to every site using them. Sources: Sansec, "Polyfill
# supply chain attack hits 100K+ sites", 2024-06-25 (https://sansec.io/research/
# polyfill-supply-chain-attack); Censys and Silent Push linked bootcss/bootcdn/
# staticfile to the same owner the same week.
COMPROMISED = {
    "polyfill.io": "в 2024 году домен перешёл к новому владельцу и начал раздавать вредоносный код",
    "polyfill.com": "принадлежит тому же владельцу, что и захваченный polyfill.io",
    "polyfillcache.com": "принадлежит тому же владельцу, что и захваченный polyfill.io",
    "bootcss.com": "исследователи в 2024 году связали домен с атакой через polyfill.io",
    "bootcdn.net": "исследователи в 2024 году связали домен с атакой через polyfill.io",
    "staticfile.org": "исследователи в 2024 году связали домен с атакой через polyfill.io",
    "staticfile.net": "исследователи в 2024 году связали домен с атакой через polyfill.io",
}

HSTS_MIN_AGE = 180 * 24 * 3600  # what the HSTS preload list asks for at least
# Third-party script domains from which the inventory becomes a warning: each can run
# any code on the page. Calibrated in the browser on 17 sites (2026-10-21): 2 to 32
# domains, median 11; 10 warned on most of them, 15 marks the heavier 40%.
MANY_SCRIPT_DOMAINS = 15
CERT_FAIL_DAYS = 14
CERT_WARN_DAYS = 30
TLS_CHECK_TITLE = "TLS: сертификат и протоколы"
# Names that look like a login session. CSRF tokens are left out on purpose: they are
# meant to be read by the page's own scripts, so HttpOnly would break them.
_SESSION_COOKIE = re.compile(
    r"sess|^sid$|[._-]sid$|^sid[._-]|auth|jwt|remember|access[._-]?token|refresh[._-]?token", re.I
)
_CSRF_COOKIE = re.compile(r"csrf|xsrf", re.I)


# --- Scripts --------------------------------------------------------------------------


@dataclass(slots=True)
class Resource:
    url: str
    kind: str  # "script" or "style"
    integrity: bool
    page: str  # where it was found

    @property
    def host(self) -> str:
        return (urlsplit(self.url).hostname or "").lower()


class _ResourceParser(HTMLParser):
    def __init__(self, base: str, page: str) -> None:
        super().__init__(convert_charrefs=True)
        self.base, self.page = base, page
        self.found: list[Resource] = []
        self.csp_meta: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag == "script" and a.get("src"):
            self._add(a["src"], "script", a)
        elif tag == "link" and "stylesheet" in a.get("rel", "").lower() and a.get("href"):
            self._add(a["href"], "style", a)
        elif tag == "meta" and a.get("http-equiv", "").lower() == "content-security-policy":
            self.csp_meta.append(a.get("content", ""))

    def _add(self, src: str, kind: str, a: dict[str, str]) -> None:
        url = urljoin(self.base, src.strip())
        if url.startswith(("http://", "https://")):
            self.found.append(Resource(url, kind, bool(a.get("integrity")), self.page))


def page_resources(html: str, base: str, page: str = "/") -> tuple[list[Resource], list[str]]:
    """External scripts and stylesheets of a page, and CSP set in <meta> tags."""
    parser = _ResourceParser(base, page)
    with contextlib.suppress(Exception):  # malformed markup: keep what was parsed
        parser.feed(html)
        parser.close()
    return parser.found, parser.csp_meta


def is_third_party(host: str, domain: str) -> bool:
    return bool(host) and host != domain and not host.endswith("." + domain)


def is_library_cdn(host: str) -> bool:
    return any(host == c or host.endswith("." + c) for c in LIBRARY_CDNS)


def compromised(host: str) -> str | None:
    reg = registrable_domain(host)
    return COMPROMISED.get(reg)


# --- CSP ------------------------------------------------------------------------------


def parse_csp(policy: str) -> dict[str, list[str]]:
    directives: dict[str, list[str]] = {}
    for part in policy.split(";"):
        tokens = part.split()
        if tokens and tokens[0].lower() not in directives:  # the first one wins
            directives[tokens[0].lower()] = [t.lower() for t in tokens[1:]]
    return directives


def csp_policies(header: str) -> list[str]:
    """A repeated CSP header arrives joined by commas: each part is a policy of its own,
    and the browser enforces all of them (CSP Level 3, section 3.1)."""
    return [p for p in header.split(",") if p.strip()]


def frame_protected(policies: list[str]) -> bool:
    """frame-ancestors that limits who may frame the page: not *, http: or https:."""
    for policy in policies:
        sources = parse_csp(policy).get("frame-ancestors")
        if sources is not None and not any(s in ("*", "http:", "https:") for s in sources):
            return True
    return False


def csp_weaknesses(policy: str) -> list[str]:
    """What makes the policy useless against injected scripts, in plain words."""
    d = parse_csp(policy)
    scripts = d.get("script-src", d.get("default-src"))
    problems = []
    if scripts is None:
        problems.append("нет script-src и default-src: скрипты ничем не ограничены")
        scripts = []
    nonce_or_hash = any(
        t.startswith(("'nonce-", "'sha256-", "'sha384-", "'sha512-")) for t in scripts
    )
    strict_dynamic = "'strict-dynamic'" in scripts
    if "'unsafe-inline'" in scripts and not nonce_or_hash:
        problems.append(
            "'unsafe-inline' разрешает любые встроенные скрипты, в том числе внедрённые"
        )
    if "'unsafe-eval'" in scripts:
        problems.append("'unsafe-eval' разрешает выполнять код из строк (eval)")
    if not strict_dynamic:
        wide = [t for t in scripts if t in ("*", "http:", "https:", "data:")]
        if wide:
            problems.append(f"{', '.join(wide)} в script-src разрешает скрипты почти откуда угодно")
    if "object-src" not in d and "'none'" not in d.get("default-src", []):
        problems.append("нет object-src 'none': плагины (object, embed) не запрещены")
    return problems


# --- TLS ------------------------------------------------------------------------------


@dataclass(slots=True)
class TlsInfo:
    host: str = ""
    version: str | None = None  # negotiated by default
    expires: datetime | None = None
    legacy: dict[str, bool | None] = field(default_factory=dict)  # "TLS 1.0": accepted?
    # Why a browser would reject the certificate (OpenSSL's message), None if it is fine.
    verify_error: str | None = None
    issuer: str = ""
    verified: bool = True  # False when the verifying handshake itself failed (a timeout)
    # The server omits an intermediate that the AIA link supplies: browsers cope, apps not.
    chain_incomplete: bool = False
    revoked: datetime | None = None  # when the CA revoked it, by its OCSP responder


def _context(version: ssl.TLSVersion | None = None) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # the certificate is checked elsewhere; here we only look
    if version is not None:
        with contextlib.suppress(ssl.SSLError):
            ctx.set_ciphers("DEFAULT:@SECLEVEL=0")  # old protocols need old ciphers
        ctx.minimum_version = version
        ctx.maximum_version = version
    return ctx


async def _handshake(
    host: str, ctx: ssl.SSLContext, timeout: float, chain: list[bytes] | None = None
) -> tuple[str | None, bytes | None]:
    """(protocol version, certificate DER), read before the connection is closed. The
    certificates the server sent go to ``chain`` (DER), when asked."""
    _, writer = await asyncio.wait_for(
        asyncio.open_connection(host, 443, ssl=ctx, server_hostname=host), timeout
    )
    try:
        sslobj = writer.get_extra_info("ssl_object")
        if sslobj is None:
            return None, None
        if chain is not None and hasattr(sslobj, "get_unverified_chain"):  # Python 3.13+
            chain.extend(c for c in sslobj.get_unverified_chain() or [] if isinstance(c, bytes))
        return sslobj.version(), sslobj.getpeercert(binary_form=True)
    finally:
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()


async def legacy_accepted(host: str, version: ssl.TLSVersion, timeout: float) -> bool | None:
    """True if the server agrees to an obsolete protocol, None if we can't tell."""
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            ctx = _context(version)
        await _handshake(host, ctx, timeout)
        return True
    except ssl.SSLError as exc:
        # This Python/OpenSSL can't speak the protocol at all: no verdict.
        if "NO_PROTOCOLS_AVAILABLE" in str(exc).upper() or "NO PROTOCOLS" in str(exc).upper():
            return None
        return False
    except (ConnectionResetError, ConnectionAbortedError):
        return False  # servers often drop the connection instead of an alert
    except (OSError, *TIMEOUTS, ValueError):
        return None


async def _issuer_from_aia(cert: x509.Certificate, timeout: float) -> str | None:
    """The issuing certificate (PEM) from the certificate's AIA link, as browsers fetch a
    missing intermediate."""
    try:
        aia = cert.extensions.get_extension_for_class(x509.AuthorityInformationAccess).value
    except x509.ExtensionNotFound:
        return None
    urls = [
        d.access_location.value
        for d in aia
        if d.access_method == x509.oid.AuthorityInformationAccessOID.CA_ISSUERS
        and str(d.access_location.value).startswith("http")
    ]
    if not urls:
        return None
    try:
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
            resp = await client.get(urls[0])
        if resp.status_code != 200:
            return None
        body = resp.content
        if b"-----BEGIN CERTIFICATE-----" in body:
            return body.decode("ascii", "replace")
        return ssl.DER_cert_to_PEM_cert(body)
    except (httpx.HTTPError, ValueError, *TIMEOUTS):
        return None


def _ocsp_url(cert: x509.Certificate) -> str | None:
    try:
        aia = cert.extensions.get_extension_for_class(x509.AuthorityInformationAccess).value
    except x509.ExtensionNotFound:
        return None
    for d in aia:
        url = str(d.access_location.value)
        if d.access_method == x509.oid.AuthorityInformationAccessOID.OCSP and url.startswith(
            "http"
        ):
            return url
    return None


async def ocsp_revoked(
    cert: x509.Certificate, issuer: x509.Certificate, timeout: float
) -> datetime | None:
    """When the certificate authority's OCSP responder says the certificate was revoked,
    or None: not revoked, no responder (Let's Encrypt dropped OCSP in 2025) or no answer.
    The request goes to the CA, not to the site."""
    url = _ocsp_url(cert)
    if url is None:
        return None
    request = (
        ocsp.OCSPRequestBuilder()
        .add_certificate(cert, issuer, hashes.SHA1())  # SHA-1 is what responders accept
        .build()
        .public_bytes(serialization.Encoding.DER)
    )
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.post(
                url, content=request, headers={"Content-Type": "application/ocsp-request"}
            )
        if resp.status_code != 200:
            return None
        answer = ocsp.load_der_ocsp_response(resp.content)
    except (httpx.HTTPError, ValueError, *TIMEOUTS):
        return None
    if answer.response_status != ocsp.OCSPResponseStatus.SUCCESSFUL:
        return None
    if answer.serial_number != cert.serial_number:
        return None
    if answer.certificate_status == ocsp.OCSPCertStatus.REVOKED:
        return answer.revocation_time_utc
    return None


CRL_MAX_BYTES = 10_000_000  # Let's Encrypt shards its lists; a bigger one is not worth it


async def crl_revoked(
    cert: x509.Certificate, issuer: x509.Certificate, timeout: float
) -> datetime | None:
    """The same from the CA's revocation list (CRL), for CAs without OCSP. The list
    must be signed by the issuer, or it proves nothing."""
    try:
        points = cert.extensions.get_extension_for_class(x509.CRLDistributionPoints).value
    except x509.ExtensionNotFound:
        return None
    urls = [
        str(name.value)
        for point in points
        for name in point.full_name or []
        if isinstance(name, x509.UniformResourceIdentifier) and str(name.value).startswith("http")
    ]
    if not urls:
        return None
    try:
        async with (
            httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client,
            client.stream("GET", urls[0]) as resp,
        ):
            if resp.status_code != 200:
                return None
            body = b""
            async for chunk in resp.aiter_bytes():
                body += chunk
                if len(body) > CRL_MAX_BYTES:
                    return None
        crl = (
            x509.load_pem_x509_crl(body)
            if body.lstrip().startswith(b"-----")
            else x509.load_der_x509_crl(body)
        )
        if crl.issuer != issuer.subject or not crl.is_signature_valid(
            issuer.public_key()  # type: ignore[arg-type]
        ):
            return None
    except (httpx.HTTPError, ValueError, TypeError, *TIMEOUTS):
        return None
    entry = crl.get_revoked_certificate_by_serial_number(cert.serial_number)
    return entry.revocation_date_utc if entry is not None else None


async def probe_tls(host: str, timeout: float) -> TlsInfo:
    info = TlsInfo(host)
    cert = None
    chain: list[bytes] = []
    with contextlib.suppress(OSError, *TIMEOUTS, ssl.SSLError, ValueError):
        info.version, der = await _handshake(host, _context(), timeout, chain)
        if der:
            cert = x509.load_der_x509_certificate(der)
            info.expires = cert.not_valid_after_utc
            info.issuer = cert.issuer.rfc4514_string()
    if info.version is None:
        return info
    if cert is not None:
        issuer = None
        with contextlib.suppress(ValueError):
            issuer = next(
                (c for c in map(x509.load_der_x509_certificate, chain[1:])
                 if c.subject == cert.issuer),
                None,
            )  # fmt: skip
        if issuer is not None:
            check = ocsp_revoked if _ocsp_url(cert) else crl_revoked
            info.revoked = await check(cert, issuer, timeout)
    # The same check a browser makes: chain to a trusted root, host name, dates.
    try:
        await _handshake(host, browser_trust(), timeout)
    except ssl.SSLCertVerificationError as exc:
        info.verify_error = exc.verify_message or str(exc)
    except (OSError, *TIMEOUTS, ssl.SSLError, ValueError):
        info.verified = False
    if info.verify_error and "local issuer" in info.verify_error.lower() and cert is not None:
        # "unable to get local issuer" is either a missing intermediate, which browsers
        # fetch by the AIA link, or a root nobody trusts (a private CA): try as they do.
        pem = await _issuer_from_aia(cert, timeout)
        if pem:
            ctx = browser_trust()
            with contextlib.suppress(ssl.SSLError, ValueError):
                ctx.load_verify_locations(cadata=pem)
                with contextlib.suppress(OSError, *TIMEOUTS, ssl.SSLError, ValueError):
                    await _handshake(host, ctx, timeout)
                    info.chain_incomplete = True
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        versions = {"TLS 1.0": ssl.TLSVersion.TLSv1, "TLS 1.1": ssl.TLSVersion.TLSv1_1}
    for name, version in versions.items():
        info.legacy[name] = await legacy_accepted(host, version, timeout)
    return info


# --- Cookies --------------------------------------------------------------------------


@dataclass(slots=True)
class Cookie:
    name: str
    secure: bool
    http_only: bool
    same_site: str | None

    @property
    def session_like(self) -> bool:
        return bool(_SESSION_COOKIE.search(self.name)) and not _CSRF_COOKIE.search(self.name)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "secure": self.secure,
            "httponly": self.http_only,
            "samesite": self.same_site,
        }


def parse_set_cookie(line: str) -> Cookie | None:
    parts = [p.strip() for p in line.split(";")]
    name, sep, _ = parts[0].partition("=")
    if not sep or not name.strip():
        return None
    attrs = {}
    for p in parts[1:]:
        key, _, value = p.partition("=")
        attrs[key.strip().lower()] = value.strip()
    same_site = attrs.get("samesite")
    return Cookie(
        name.strip(),
        "secure" in attrs,
        "httponly" in attrs,
        same_site.lower() if same_site else None,
    )


# --- Checks ---------------------------------------------------------------------------


@dataclass(slots=True)
class WebFacts:
    domain: str
    https: bool
    headers: dict[str, str]
    resources: list[Resource]
    csp_meta: list[str]
    cookies: list[Cookie]
    tls: TlsInfo | None
    abandoned: dict[str, bool | None] = field(default_factory=dict)  # domain: certain?
    # A bot wall answered instead of the site: its headers and code say nothing.
    page_problem: str | None = None
    http_problem: str | None = None
    now: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def third_party(self) -> list[Resource]:
        return [r for r in self.resources if is_third_party(r.host, self.domain)]


def _hosts(resources: list[Resource]) -> list[str]:
    return sorted({r.host for r in resources})


def plural(n: int, one: str, few: str, many: str) -> str:
    """Russian plural form: 1 домен, 2 домена, 5 доменов, 21 домен."""
    if n % 10 == 1 and n % 100 != 11:
        return one
    if 2 <= n % 10 <= 4 and not 12 <= n % 100 <= 14:
        return few
    return many


def _list(items: list[str], limit: int = 8) -> str:
    shown = ", ".join(items[:limit])
    return shown + (f" и ещё {len(items) - limit}" if len(items) > limit else "")


def scripts_inventory(w: WebFacts) -> Check:
    scripts = [r for r in w.third_party if r.kind == "script"]
    hosts = _hosts(scripts)
    companies = sorted({registrable_domain(h) for h in hosts})
    if not hosts:
        return Check(
            GROUP_WEB,
            "Сторонний код на сайте",
            Status.OK,
            "Сторонних скриптов в коде страниц не найдено.",
        )
    found = (
        f"Страницы загружают скрипты с {len(hosts)} "
        f"{plural(len(hosts), 'стороннего адреса', 'сторонних адресов', 'сторонних адресов')} "
        f"({len(companies)} {plural(len(companies), 'домен', 'домена', 'доменов')}): "
        f"{_list(hosts)}."
    )
    if len(companies) < MANY_SCRIPT_DOMAINS:
        return Check(GROUP_WEB, "Сторонний код на сайте", Status.OK, found)
    # Every one of them can run any code on the page: the more there are, the more ways in.
    return Check(
        GROUP_WEB,
        "Сторонний код на сайте",
        Status.WARN,
        found + " Каждый из них может выполнить на сайте любой код: прочитать введённые "
        "данные, подменить реквизиты для оплаты, и взлом любого из этих сервисов становится "
        "взломом сайта.",
        "Уберите скрипты, которыми не пользуетесь, а нужные по возможности разместите на "
        "своём сервере.",
    )


def supply_chain(w: WebFacts) -> Check:
    title = "Скрипты с брошенных и скомпрометированных доменов"
    problems = []
    certain = False
    for host in _hosts([r for r in w.third_party if r.kind == "script"]):
        reason = compromised(host)
        if reason:
            problems.append(f"{host}: {reason}")
            certain = True
    for domain, is_certain in sorted(w.abandoned.items()):
        if is_certain:
            problems.append(
                f"{domain}: домен не зарегистрирован, его может купить кто угодно и раздавать "
                "свой код посетителям сайта"
            )
            certain = True
        else:
            problems.append(f"{domain}: домена нет в DNS, а реестр не ответил: проверьте")
    if not problems:
        return Check(GROUP_WEB, title, Status.OK, "Таких скриптов не найдено.")
    return Check(
        GROUP_WEB,
        title,
        Status.FAIL if certain else Status.WARN,
        "; ".join(problems) + ".",
        "Удалите эти скрипты со всех страниц или замените их копией на своём сервере.",
    )


def sri_check(w: WebFacts) -> Check | None:
    libs = [r for r in w.third_party if is_library_cdn(r.host)]
    if not libs:
        return None
    missing = [r for r in libs if not r.integrity]
    title = "Контроль целостности библиотек с CDN (SRI)"
    if not missing:
        return Check(
            GROUP_WEB,
            title,
            Status.OK,
            f"У всех библиотек с публичных CDN ({len(libs)}) есть integrity.",
        )
    names = sorted({r.url.split("?")[0].rsplit("/", 1)[-1] or r.host for r in missing})
    return Check(
        GROUP_WEB,
        title,
        Status.WARN,
        f"Библиотеки с публичных CDN подключены без атрибута integrity: {_list(names, 6)}. "
        "Если CDN взломают, как в 2024 году polyfill.io, браузер выполнит подменённый файл.",
        'Добавьте к тегам integrity="sha384-…" и crossorigin="anonymous" (готовые теги есть '
        "на страницах cdnjs и jsDelivr) или разместите библиотеки на своём сервере.",
    )


def csp_check(w: WebFacts) -> Check:
    title = "Политика безопасности контента (CSP)"
    policies = csp_policies(w.headers.get("content-security-policy", "")) or w.csp_meta
    report_only = w.headers.get("content-security-policy-report-only")
    if not policies:
        how = (
            " Есть только режим наблюдения (Report-Only), он ничего не блокирует."
            if report_only
            else ""
        )
        return Check(
            GROUP_WEB,
            title,
            Status.WARN,
            "Заголовка Content-Security-Policy нет: если на сайт внедрят скрипт (через "
            "уязвимость или взломанный сторонний сервис), браузер его выполнит." + how,
            "Режим наблюдения уже включён: разберите его отчёты о нарушениях и, когда "
            "настоящие скрипты перестанут в них попадать, отправляйте ту же политику в "
            "заголовке Content-Security-Policy."
            if report_only
            else "Начните с Content-Security-Policy-Report-Only, соберите список источников и "
            "включите политику со script-src без 'unsafe-inline' и object-src 'none'.",
        )
    # Every policy is enforced, so the strictest one decides.
    problems = min((csp_weaknesses(p) for p in policies), key=len)
    if not problems:
        return Check(GROUP_WEB, title, Status.OK, "CSP задана и ограничивает источники скриптов.")
    return Check(
        GROUP_WEB,
        title,
        Status.WARN,
        "CSP задана, но слабая: " + "; ".join(problems) + ".",
        _csp_fix(problems),
    )


def _csp_fix(problems: list[str]) -> str:
    """Advice for exactly the weaknesses found (skillbox.ru has no script-src at all,
    so "remove 'unsafe-inline'" would be advice about something it doesn't have)."""
    fixes = []
    for problem in problems:
        if problem.startswith("нет script-src"):
            fixes.append(
                "добавьте script-src со своими источниками ('self' и нужные домены, для "
                "встроенных скриптов — nonce)"
            )
        elif problem.startswith("'unsafe-inline'"):
            fixes.append("уберите 'unsafe-inline' из script-src (используйте nonce или хэши)")
        elif problem.startswith("'unsafe-eval'"):
            fixes.append("уберите 'unsafe-eval'")
        elif "в script-src разрешает" in problem:
            fixes.append("перечислите конкретные домены вместо *, http: и https:")
        elif problem.startswith("нет object-src"):
            fixes.append("добавьте object-src 'none'")
    text = ", ".join(fixes) or "ограничьте источники скриптов"
    return text[0].upper() + text[1:] + "."


def hsts_check(w: WebFacts) -> Check | None:
    if not w.https:
        return None
    title = "Принудительный HTTPS (HSTS)"
    value = w.headers.get("strict-transport-security")
    if not value:
        return Check(
            GROUP_WEB,
            title,
            Status.WARN,
            "Заголовка Strict-Transport-Security нет: браузер не запоминает, что сайт работает "
            "только по HTTPS, и любой заход по http:// (старая ссылка, адрес без https) можно "
            "перехватить в общественном Wi-Fi и подменить страницу.",
            "Добавьте заголовок Strict-Transport-Security: max-age=31536000; includeSubDomains.",
        )
    ages = re.findall(r"max-age\s*=\s*\"?(\d+)", value, re.I)
    if len(ages) > 1:
        # bi.zone sends the header four times; joined, it repeats max-age, and a header
        # with a repeated directive is invalid (RFC 6797, section 6.1).
        times = f"{len(ages)} {plural(len(ages), 'раз', 'раза', 'раз')}"
        return Check(
            GROUP_WEB,
            title,
            Status.WARN,
            f"Заголовок Strict-Transport-Security повторяется ({times}, max-age: "
            f"{', '.join(dict.fromkeys(ages))}). Директивы в нём не должны повторяться "
            "(RFC 6797, раздел 6.1), и браузеры могут отвергнуть его целиком.",
            "Оставьте один заголовок Strict-Transport-Security: max-age=31536000; "
            "includeSubDomains. Обычно повтор добавляют сразу веб-сервер и приложение.",
        )
    age = int(ages[0]) if ages else 0
    if age < HSTS_MIN_AGE:
        return Check(
            GROUP_WEB,
            title,
            Status.WARN,
            # max-age=0 tells browsers to forget HSTS: it is switched off, not short.
            "Заголовок Strict-Transport-Security есть, но с max-age=0: он выключает HSTS, "
            "и заход по http:// можно перехватить."
            if age == 0
            else f"HSTS включён, но на {_duration(age)}: этого мало, защита быстро истекает.",
            "Поставьте max-age не меньше 15552000 (180 дней), лучше 31536000.",
        )
    return Check(GROUP_WEB, title, Status.OK, f"HSTS включён на {age // 86400} дн.")


def headers_check(w: WebFacts) -> Check:
    title = "Защитные заголовки"
    missing = []
    fixes = []
    # ALLOW-FROM and other values are ignored by current browsers (OWASP Secure Headers);
    # a repeated header arrives joined, and the HTML Standard reads its values as a set.
    xfo = {v.strip().lower() for v in w.headers.get("x-frame-options", "").split(",")} - {""}
    framed = bool(xfo) and xfo <= {"deny", "sameorigin"}
    if not framed and not frame_protected(
        csp_policies(w.headers.get("content-security-policy", ""))
    ):
        missing.append(
            "X-Frame-Options или frame-ancestors (сайт можно встроить в чужую страницу и "
            "обманом заставить нажать кнопку — кликджекинг)"
        )
        fixes.append("X-Frame-Options: SAMEORIGIN (или CSP frame-ancestors 'self')")
    # Fetch's "determine nosniff" reads the first value of a repeated header.
    if w.headers.get("x-content-type-options", "").split(",")[0].strip().lower() != "nosniff":
        missing.append("X-Content-Type-Options: nosniff (браузер может принять файл за скрипт)")
        fixes.append("X-Content-Type-Options: nosniff")
    if not missing:
        return Check(
            GROUP_WEB, title, Status.OK, "Защита от встраивания и подмены типа файлов есть."
        )
    return Check(
        GROUP_WEB,
        title,
        Status.WARN,
        "Нет: " + "; ".join(missing) + ".",
        ("Добавьте заголовок " if len(fixes) == 1 else "Добавьте заголовки ")
        + " и ".join(fixes)
        + ".",
    )


def cookies_check(w: WebFacts) -> Check | None:
    if not w.cookies:
        return None
    title = "Флаги cookies"
    problems = []
    for c in w.cookies:
        flags = []
        if w.https and not c.secure:
            flags.append("Secure")
        if c.session_like and not c.http_only:
            flags.append("HttpOnly")
        if c.same_site == "none" and not c.secure:
            flags.append("Secure (обязателен при SameSite=None)")
        if flags and (c.session_like or c.same_site == "none"):
            problems.append(f"{c.name}: нет {', '.join(dict.fromkeys(flags))}")
    if not problems:
        return Check(
            GROUP_WEB, title, Status.OK, f"Проверено cookies: {len(w.cookies)}, замечаний нет."
        )
    return Check(
        GROUP_WEB,
        title,
        Status.WARN,
        "Cookies, похожие на сессионные, без защитных флагов: " + "; ".join(problems[:5]) + ". "
        "Без HttpOnly cookie может украсть внедрённый скрипт, без Secure она уходит по "
        "незашифрованному соединению.",
        "Выставляйте сессионным cookies флаги Secure, HttpOnly и SameSite=Lax.",
    )


def tls_check(w: WebFacts) -> Check | None:
    t = w.tls
    if t is None or t.version is None:
        return None
    title = TLS_CHECK_TITLE
    status = Status.OK
    details = [f"Сервер {t.host}, соединение {t.version.replace('TLSv', 'TLS ')}."]
    recommendation = ""
    if t.expires:
        days = (t.expires - w.now).days
        details.append(
            # A revoked certificate is not valid, whatever its dates say.
            f"Срок сертификата — до {t.expires:%d.%m.%Y}."
            if t.revoked is not None and days >= 0
            else f"Сертификат действует ещё {days} дн. (до {t.expires:%d.%m.%Y})."
            if days >= 0
            else f"Срок действия сертификата истёк {t.expires:%d.%m.%Y}."
        )
        if days < CERT_FAIL_DAYS:
            status = Status.FAIL
            recommendation = "Срочно продлите сертификат и включите автоматическое продление."
        elif days < CERT_WARN_DAYS:
            status = Status.WARN
            recommendation = (
                "Продлите сертификат и проверьте, что автоматическое продление работает."
            )
    # An expired certificate is already a FAIL above, with its date.
    if t.verify_error and _cert_reason(t.verify_error) != "срок действия истёк":
        mintsifry = "russian trusted" in t.issuer.lower()
        # Desktop Chrome fetches a missing intermediate itself; apps and some browsers don't.
        incomplete = t.chain_incomplete
        status = Status.WARN if mintsifry or incomplete else Status.FAIL
        details.append(
            "Сертификат выпущен НУЦ Минцифры: браузеры без российского корневого сертификата "
            "покажут посетителям ошибку."
            if mintsifry
            else "Сервер не отдаёт промежуточный сертификат: браузеры обычно скачивают его "
            "сами, а мобильные приложения, почтовые клиенты и часть браузеров покажут ошибку."
            if incomplete
            else f"Браузеры не примут сертификат ({_cert_reason(t.verify_error)}) и покажут "
            "посетителям ошибку."
        )
        recommendation = (
            "Поставьте второй сертификат от общепризнанного центра (например, Let's Encrypt) "
            "для посетителей без российского корневого сертификата."
            if mintsifry
            else "Установите на сервер полную цепочку: сертификат сайта вместе с "
            "промежуточными (обычно файл fullchain.pem)."
            if incomplete
            else "Выпустите сертификат у общепризнанного центра (например, Let's Encrypt) на "
            "это имя сайта и установите полную цепочку."
        )
    if t.revoked is not None:
        status = Status.FAIL
        details.append(
            f"Удостоверяющий центр отозвал сертификат {t.revoked:%d.%m.%Y} (по его "
            "OCSP-серверу или списку отзыва): так делают, когда ключ мог утечь или "
            "сертификат выпущен ошибочно. Браузеры, которые проверяют отзыв, покажут ошибку."
        )
        recommendation = (
            "Выпустите новый сертификат с новым ключом и замените отозванный на сервере."
        )
    if not t.verified:
        details.append("Доверие браузеров к сертификату проверить не удалось: сервер не ответил.")
    old = [name for name, ok in t.legacy.items() if ok]
    unknown = [name for name, ok in t.legacy.items() if ok is None]
    if old:
        status = max(status, Status.WARN, key=_rank)
        details.append(
            f"Сервер соглашается на устаревшие {', '.join(old)}: они уязвимы и запрещены "
            "стандартом RFC 8996 (2021), PCI DSS и NIST SP 800-52."
        )
        recommendation = recommendation or "Отключите TLS 1.0 и 1.1 в настройках веб-сервера."
    elif unknown:
        details.append(f"Поддержку {', '.join(unknown)} проверить не удалось.")
    else:
        details.append("TLS 1.0 и 1.1 отключены.")
    return Check(GROUP_WEB, title, status, " ".join(details), recommendation)


def _cert_reason(message: str) -> str:
    low = message.lower()
    if "hostname mismatch" in low or "ip address mismatch" in low:
        return "он выписан на другое имя"
    if "in certificate chain" in low:
        return "цепочка ведёт к недоверенному корневому сертификату"
    if "self-signed" in low or "self signed" in low:
        return "он самоподписанный"
    if "expired" in low:
        return "срок действия истёк"
    if "not yet valid" in low:
        return "срок действия ещё не начался"
    if "local issuer" in low or "unable to get issuer" in low:
        return "цепочка не ведёт к доверенному корневому сертификату"
    if "revoked" in low:
        return "он отозван"
    return message


def _rank(status: Status) -> int:
    return {Status.OK: 0, Status.UNKNOWN: 1, Status.WARN: 2, Status.FAIL: 3}[status]


def evaluate(w: WebFacts) -> list[Check]:
    checks: list[Check | None] = []
    if w.page_problem:
        checks.append(
            Check(
                GROUP_WEB,
                "Сторонний код на сайте",
                Status.UNKNOWN,
                f"Не проверено: {w.page_problem}. Попробуйте режим --browser.",
            )
        )
    else:
        checks += [scripts_inventory(w), supply_chain(w), sri_check(w)]
    if w.http_problem:
        checks.append(
            Check(
                GROUP_WEB,
                "Заголовки безопасности (CSP, HSTS и другие)",
                Status.UNKNOWN,
                f"Не проверено: {w.http_problem}, а у такой страницы свои заголовки, не "
                "заголовки сайта.",
            )
        )
    else:
        checks += [csp_check(w), hsts_check(w), headers_check(w), cookies_check(w)]
    checks.append(tls_check(w))
    return [c for c in checks if c is not None]


# --- Collection -----------------------------------------------------------------------


def gather_resources(facts: Facts) -> tuple[list[Resource], list[str]]:
    base = facts.final_url or f"https://{facts.host}/"
    resources, csp_meta = page_resources(facts.html, base, "/")
    for page in facts.extra_pages:
        found, _ = page_resources(page.html, page.url, urlsplit(page.url).path or "/")
        resources += found
    # In --browser mode scripts added by other scripts show up only as requests.
    seen = {r.url for r in resources}
    for url in facts.loaded_urls:
        if urlsplit(url).path.endswith(".js") and url not in seen:
            resources.append(Resource(url, "script", False, "/"))
            seen.add(url)
    return resources, csp_meta


async def find_abandoned(
    resolver: DnsResolver, client: httpx.AsyncClient, hosts: list[str], domain: str
) -> dict[str, bool | None]:
    """Script domains missing from DNS: True if the registry says they are free."""
    found: dict[str, bool | None] = {}
    for reg in sorted({registrable_domain(h) for h in hosts}):
        if reg == domain or "." not in reg or await resolver.exists(reg):
            continue
        tld = reg.rsplit(".", 1)[1]
        if not await resolver.exists(tld):
            continue
        registered = await is_registered(client, reg)
        if registered is not True:
            found[reg] = registered is False
    return found


async def run_web_checks(
    facts: Facts, resolver: DnsResolver, client: httpx.AsyncClient, timeout: float
) -> tuple[list[Check], dict[str, Any]]:
    if not facts.html and not facts.headers:
        return [], {}
    resources, csp_meta = gather_resources(facts)
    https = (facts.final_url or "").startswith("https://")
    headers, set_cookies, http_problem = facts.headers, facts.set_cookies, facts.http_problem
    if http_problem and facts.browser_headers and not facts.page_problem:
        # Plain HTTP got a bot wall, the browser got the site: its headers are the site's.
        headers = {k: v for k, v in facts.browser_headers.items() if k != "set-cookie"}
        set_cookies = facts.browser_headers.get("set-cookie", "").split("\n")
        http_problem = None
    cookies = [c for c in (parse_set_cookie(line) for line in set_cookies if line) if c]
    w = WebFacts(facts.domain, https, headers, resources, csp_meta, cookies, None)
    w.page_problem, w.http_problem = facts.page_problem, http_problem
    final_host = urlsplit(facts.final_url or "").hostname or ""
    if final_host and registrable_domain(final_host) != facts.domain and not w.http_problem:
        w.http_problem = f"сайт перенаправил на другой домен, {final_host}"
    w.abandoned = await find_abandoned(
        resolver, client, _hosts([r for r in w.third_party if r.kind == "script"]), facts.domain
    )
    if https:
        # The address that was asked for: a redirect may lead to another company's server
        # (yandex.ru → sso.passport.yandex.ru), whose TLS is not this site's.
        w.tls = await probe_tls(facts.host, timeout)
    data = {
        "third_party_scripts": _hosts([r for r in w.third_party if r.kind == "script"]),
        "without_sri": sorted(
            r.url for r in w.third_party if is_library_cdn(r.host) and not r.integrity
        ),
        "headers": {
            k: v
            for k, v in facts.headers.items()
            if k
            in (
                "content-security-policy",
                "content-security-policy-report-only",
                "strict-transport-security",
                "x-frame-options",
                "x-content-type-options",
                "referrer-policy",
                "permissions-policy",
            )
        },
        "cookies": [c.to_dict() for c in cookies],
        "tls": {
            "version": w.tls.version if w.tls else None,
            "expires": w.tls.expires.isoformat() if w.tls and w.tls.expires else None,
            "legacy": w.tls.legacy if w.tls else {},
        },
        "abandoned": w.abandoned,
    }
    checks = evaluate(w)
    if w.page_problem:
        why = f"Не проверено: {w.page_problem}."
        code_checks = [
            Check(GROUP_WEB, LEAK_TITLE, Status.UNKNOWN, why),
            Check(GROUP_WEB, VULN_TITLE, Status.UNKNOWN, why),
        ]
    else:
        own = [
            r.url for r in resources if r.kind == "script" and not is_third_party(r.host, w.domain)
        ]
        pages = [("главная", facts.html)] + [(p.path, p.html) for p in facts.extra_pages]
        heads: dict[str, str] = {}
        leaks, sources = await scan_scripts(client, list(dict.fromkeys(own)), pages, heads)
        data["leaks"] = [x.to_dict() for x in leaks]
        # Every script the pages load, the browser's requests included: versions are
        # often in CDN paths (/jquery/3.4.1/).
        scripts = [r.url for r in resources if r.kind == "script"]
        scripts += [u for u in facts.loaded_urls if urlsplit(u).path.endswith(".js")]
        libs = detect(list(dict.fromkeys(scripts)), heads)
        data["libraries"] = [{"name": x.name, "version": x.version, "where": x.where} for x in libs]
        code_checks = [leak_check(leaks, sources), vuln_check(libs)]
        if facts.initiators:  # --browser mode only: the browser said who loaded what
            graph = build_graph(facts.initiators, w.domain)
            code_checks.append(graph_check(graph))
            data["script_graph"] = graph.to_dict()
            data["script_graph_svg"] = graph_svg(graph)
    # Right after the checks about third-party code, where a reader looks for code risks.
    code = {c.id for c in checks} & {"SUV-WEB-001", "SUV-WEB-002", "SUV-WEB-003"}
    at = max((i + 1 for i, c in enumerate(checks) if c.id in code), default=0)
    checks[at:at] = code_checks
    return checks, data


def _duration(seconds: int) -> str:
    """max-age in words: days, or hours and seconds when under a day."""
    if seconds >= 86400:
        return f"{seconds // 86400} дн."
    if seconds >= 3600:
        return f"{seconds // 3600} ч."
    return f"{seconds} с"
