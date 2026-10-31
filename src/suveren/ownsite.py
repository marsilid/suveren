"""Checks for the owner's own site only (--own-site, after ownership.verify).

They ask for what a visitor never asks: service files left on the server, weak TLS
ciphers, the mail servers' STARTTLS. Never run against someone else's site, never in
batch.

* Exposed files (OWASP WSTG-CONF-04/05): /.git/HEAD and /.git/config give away the
  source code, /.env usually passwords and keys. Only the file's own format counts: a
  "not found" page answered with 200 is not a leak.
* TLS in depth: the certificate's key and signature, and whether the server agrees to
  3DES or RC4 (RFC 7465, RFC 8429). OCSP stapling is not checked: Python's TLS does not
  show it, and the report says so.
* Mail: STARTTLS on each MX (port 25) and DANE TLSA records (RFC 7672). Port 25 is often
  closed for home and cloud networks: then the answer is "not checked".
"""

from __future__ import annotations

import asyncio
import contextlib
import re
import smtplib
import ssl
from collections.abc import Awaitable, Callable
from dataclasses import dataclass

import httpx
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, rsa

from suveren.checks import Check, Evidence, Status
from suveren.collect import parse_mx
from suveren.dnsutil import DnsLookupError, DnsResolver
from suveren.errors import TIMEOUTS
from suveren.net import open_public, public_addresses

GROUP_OWN = "Свой сайт"

# path -> what the file looks like when it really is that file
SERVICE_FILES = {
    "/.git/HEAD": re.compile(r"\A(ref: refs/[\w./-]+|[0-9a-f]{40})\s*\Z"),
    "/.git/config": re.compile(r"(?m)^\[core\]\s*$"),
    "/.env": re.compile(r"(?m)^[A-Z][A-Z0-9_]{1,63}=\S*\s*$"),
    "/.env.production": re.compile(r"(?m)^[A-Z][A-Z0-9_]{1,63}=\S*\s*$"),
}


def looks_like(path: str, status: int, body: str) -> bool:
    if status != 200 or "<html" in body[:500].lower():
        return False
    return bool(SERVICE_FILES[path].search(body[:20000]))


async def exposed_files_check(client: httpx.AsyncClient, host: str) -> Check:
    title = "Открытые служебные файлы (.git, .env)"
    found: list[str] = []
    errors = 0
    for path in SERVICE_FILES:
        url = f"https://{host}{path}"
        try:
            resp = await client.get(url, follow_redirects=False)
        except (httpx.HTTPError, *TIMEOUTS):
            errors += 1
            continue
        if looks_like(path, resp.status_code, resp.text):
            found.append(url)
    if found:
        check = Check(
            GROUP_OWN,
            title,
            Status.FAIL,
            "Открыты служебные файлы: " + ", ".join(found) + ". По .git скачивается весь "
            "исходный код сайта, в .env обычно лежат пароли от базы и ключи сервисов.",
            "Закройте доступ к этим путям в настройках веб-сервера (например, location ~ /\\. "
            "{ deny all; } в nginx), удалите файлы из папки сайта и смените пароли и ключи, "
            "которые в них были.",
        )
        check.evidence = [Evidence("url", "Открыт", u) for u in found]
        return check
    if errors == len(SERVICE_FILES):
        return Check(GROUP_OWN, title, Status.UNKNOWN, "Не проверено: сайт не ответил.")
    return Check(
        GROUP_OWN,
        title,
        Status.OK,
        "Служебные файлы (" + ", ".join(SERVICE_FILES) + ") снаружи не открываются.",
    )


# --- TLS in depth -------------------------------------------------------------------

WEAK_CIPHERS = {"3DES": "DES-CBC3-SHA", "RC4": "RC4"}


@dataclass(slots=True)
class DeepTls:
    key: str | None = None  # "RSA 2048", "EC 256"
    key_weak: bool = False
    sha1: bool = False
    weak: dict[str, bool | None] | None = None  # cipher -> accepted (None: can't test)


def describe_key(cert: x509.Certificate) -> tuple[str, bool]:
    key = cert.public_key()
    if isinstance(key, rsa.RSAPublicKey):
        return f"RSA {key.key_size}", key.key_size < 2048
    if isinstance(key, ec.EllipticCurvePublicKey):
        return f"EC {key.curve.key_size}", key.curve.key_size < 256
    if isinstance(key, ed25519.Ed25519PublicKey | ed448.Ed448PublicKey):
        return "EdDSA", False
    return type(key).__name__, False


async def _cipher_accepted(host: str, cipher: str, timeout: float) -> bool | None:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    try:
        ctx.set_ciphers(f"{cipher}:@SECLEVEL=0")
    except ssl.SSLError:
        return None  # this OpenSSL has no such cipher at all
    try:
        _, writer = await open_public(host, 443, timeout, ssl=ctx, server_hostname=host)
    except ssl.SSLError:
        return False
    except (OSError, *TIMEOUTS):
        return None
    writer.close()
    with contextlib.suppress(Exception):
        await writer.wait_closed()
    return True


async def probe_deep_tls(host: str, timeout: float) -> DeepTls:
    info = DeepTls()
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with contextlib.suppress(OSError, ssl.SSLError, ValueError, *TIMEOUTS):
        _, writer = await open_public(host, 443, timeout, ssl=ctx, server_hostname=host)
        try:
            der = writer.get_extra_info("ssl_object").getpeercert(binary_form=True)
        finally:
            writer.close()
        cert = x509.load_der_x509_certificate(der)
        info.key, info.key_weak = describe_key(cert)
        algo = cert.signature_hash_algorithm
        info.sha1 = algo is not None and algo.name == "sha1"
    info.weak = {
        name: await _cipher_accepted(host, cipher, timeout) for name, cipher in WEAK_CIPHERS.items()
    }
    return info


def deep_tls_check(t: DeepTls) -> Check:
    title = "TLS подробно: ключ и слабые шифры"
    if t.key is None:
        return Check(GROUP_OWN, title, Status.UNKNOWN, "Не проверено: TLS-соединения не было.")
    weak = t.weak or {}
    accepted = [n for n, ok in weak.items() if ok]
    unknown = [n for n, ok in weak.items() if ok is None]
    problems = []
    if accepted:
        problems.append(
            f"сервер соглашается на шифры {', '.join(accepted)} (запрещены RFC 7465 и RFC 8429)"
        )
    if t.key_weak:
        problems.append(f"короткий ключ сертификата: {t.key}")
    if t.sha1:
        problems.append("сертификат подписан SHA-1")
    status = Status.FAIL if accepted else Status.WARN if problems else Status.OK
    details = f"Ключ сертификата: {t.key}."
    if problems:
        details += " Проблемы: " + "; ".join(problems) + "."
    if unknown:
        details += (
            f" Шифры {', '.join(unknown)} проверить не удалось (их нет в OpenSSL на этом "
            "компьютере)."
        )
    details += " OCSP stapling не проверяется."
    return Check(
        GROUP_OWN,
        title,
        status,
        details,
        "Отключите 3DES и RC4, выпустите сертификат с ключом RSA 2048+ или ECDSA P-256."
        if problems
        else "",
    )


# --- Mail: STARTTLS and DANE -------------------------------------------------------


@dataclass(slots=True)
class MxTransport:
    host: str
    starttls: bool | None  # None: port 25 did not answer
    tlsa: list[str]


def _starttls_sync(host: str, timeout: float) -> bool:
    with smtplib.SMTP(host, 25, timeout=timeout) as smtp:
        smtp.ehlo("suveren.local")
        return smtp.has_extn("starttls")


async def default_starttls(host: str, timeout: float) -> bool | None:
    try:
        await public_addresses(host, 25, timeout)  # never an internal address
        return await asyncio.to_thread(_starttls_sync, host, timeout)
    except (OSError, smtplib.SMTPException, *TIMEOUTS, Exception):
        return None


StarttlsProbe = Callable[[str, float], Awaitable[bool | None]]


async def collect_mail_transport(
    resolver: DnsResolver,
    domain: str,
    timeout: float,
    probe: StarttlsProbe = default_starttls,
) -> list[MxTransport]:
    try:
        hosts = parse_mx(await resolver.resolve(domain, "MX"))[:3]
    except DnsLookupError:
        return []
    found = []
    for host in hosts:
        try:
            tlsa = await resolver.resolve(f"_25._tcp.{host}", "TLSA")
        except DnsLookupError:
            tlsa = []
        found.append(MxTransport(host, await probe(host, timeout), tlsa))
    return found


def mail_transport_check(items: list[MxTransport]) -> Check:
    title = "Почтовые серверы: STARTTLS и DANE"
    if not items:
        return Check(
            GROUP_OWN, title, Status.UNKNOWN, "Не проверено: MX-записей нет или DNS не ответил."
        )
    plain = [m.host for m in items if m.starttls is False]
    silent = [m.host for m in items if m.starttls is None]
    dane = [m.host for m in items if m.tlsa]
    lines = []
    if dane:
        lines.append(
            f"DANE (TLSA) опубликован для {', '.join(dane)}; он работает только при DNSSEC."
        )
    else:
        lines.append("Записей DANE (TLSA) нет: это дополнительная защита, не ошибка.")
    if silent:
        lines.append(
            f"Порт 25 не ответил: {', '.join(silent)} (часто закрыт у домашних и облачных "
            "сетей), STARTTLS там не проверен."
        )
    if plain:
        return Check(
            GROUP_OWN,
            title,
            Status.FAIL,
            f"Серверы {', '.join(plain)} не предлагают STARTTLS: письма к вам идут открытым "
            "текстом. " + " ".join(lines),
            "Включите STARTTLS с действующим сертификатом на всех MX-серверах.",
        )
    if len(silent) == len(items):
        return Check(GROUP_OWN, title, Status.UNKNOWN, " ".join(lines))
    return Check(
        GROUP_OWN,
        title,
        Status.OK,
        "STARTTLS предлагают все ответившие серверы. " + " ".join(lines),
    )


async def run_own_site_checks(
    client: httpx.AsyncClient, resolver: DnsResolver, host: str, domain: str, timeout: float
) -> list[Check]:
    checks = [await exposed_files_check(client, host)]
    checks.append(deep_tls_check(await probe_deep_tls(host, timeout)))
    checks.append(mail_transport_check(await collect_mail_transport(resolver, domain, timeout)))
    return checks
