"""Proof that the site is yours, before Suveren does what it never does to other sites.

The "own site" mode types test data into forms (--form-leaks), asks for service files
(.git, .env), tries weak TLS ciphers and talks to the mail servers. To a site's owner
that is an audit; to anyone else's site it could look like an attack (ст. 272, 274.1 УК).
So it runs only after the owner proves control of the domain, like certificate
authorities do: a TXT record or a file with a token only this computer knows.

    _suveren-verify.example.ru.  TXT  "suveren-verify=<token>"
    https://example.ru/.well-known/suveren-verify.txt   (the token in the file)

The token is random and kept in the cache folder; it is never sent anywhere except
as the answer the site itself publishes. One site at a time, never in batch.
"""

from __future__ import annotations

import json
import re
import secrets
from dataclasses import dataclass

import httpx

from suveren.cache import cache_dir
from suveren.dnsutil import DnsLookupError, DnsResolver
from suveren.errors import TIMEOUTS

TXT_LABEL = "_suveren-verify"
FILE_PATH = "/.well-known/suveren-verify.txt"
PREFIX = "suveren-verify="


def token_for(domain: str) -> str:
    """This computer's token for the domain, made on first use."""
    path = cache_dir() / "ownership" / f"{domain}.json"
    try:
        token = json.loads(path.read_text("utf-8"))["token"]
        if re.fullmatch(r"[0-9a-f]{32}", token):
            return str(token)
    except (OSError, ValueError, KeyError, TypeError):
        pass
    token = secrets.token_hex(16)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"domain": domain, "token": token}), "utf-8")
    return token


def instructions(domain: str) -> str:
    token = token_for(domain)
    return (
        f"Подтвердите, что сайт {domain} ваш, одним из способов:\n"
        f'  1) DNS: TXT-запись {TXT_LABEL}.{domain} со значением "{PREFIX}{token}"\n'
        f"  2) файл https://{domain}{FILE_PATH} с текстом {token}\n"
        "Затем повторите команду. Запись и файл можно удалить после проверки."
    )


@dataclass(slots=True)
class Proof:
    ok: bool
    how: str  # "DNS" / "файл" / why not


async def verify(resolver: DnsResolver, client: httpx.AsyncClient, domain: str) -> Proof:
    token = token_for(domain)
    try:
        records = await resolver.resolve(f"{TXT_LABEL}.{domain}", "TXT")
    except DnsLookupError:
        records = []
    if any(r.strip().strip('"') == PREFIX + token for r in records):
        return Proof(True, f"TXT-запись {TXT_LABEL}.{domain}")
    url = f"https://{domain}{FILE_PATH}"
    try:
        resp = await client.get(url, follow_redirects=False)
    except (httpx.HTTPError, *TIMEOUTS):
        return Proof(False, "ни TXT-записи, ни файла с токеном не найдено")
    if resp.status_code == 200 and resp.text.strip() == token:
        return Proof(True, f"файл {url}")
    return Proof(False, "ни TXT-записи, ни файла с токеном не найдено")
