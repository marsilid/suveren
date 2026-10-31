"""DNS records that guard the site's name: CAA (who may issue its certificates) and
DNSSEC (whether answers about it are signed).

DNS only, the way a certificate authority and a validating resolver look at the zone:
the site never sees these queries.

* CAA, RFC 8659. The relevant record set is the first one found climbing from the name
  to its parents (section 3); without one, any authority may issue (that is allowed,
  so it is a note). Authorities must refuse when a record with the critical flag has a
  tag they do not know (section 4.1), and ``issue ";"`` allows nobody (4.2).
* DNSSEC, RFC 4035 section 5: a DS record in the parent zone must match a DNSKEY of the
  zone, or validating resolvers find the answers bogus and return SERVFAIL — the site
  and its mail disappear for their users. Algorithms per RFC 8624, section 3.1.
  Signatures (RRSIG) and their dates are not checked: the resolvers we use don't hand
  them over.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field

import dns.dnssec
import dns.exception
import dns.name
import dns.rdata
import dns.rdtypes.ANY.CAA
import dns.rdtypes.ANY.DNSKEY
import dns.rdtypes.dsbase

from suveren.checks import Check, Evidence, Status
from suveren.dnsutil import DnsLookupError, DnsResolver
from suveren.utils import registrable_domain

GROUP_WEB = "Безопасность сайта"
CAA_TITLE = "Ограничение центров сертификации (CAA)"
DNSSEC_TITLE = "Подпись DNS (DNSSEC)"

CAA_CRITICAL = 0x80  # RFC 8659, 4.1: the Issuer Critical flag
CAA_KNOWN_TAGS = frozenset({"issue", "issuewild", "iodef", "contactemail", "contactphone"})

# RFC 8624, section 3.1, the "DNSSEC Signing" column; algorithm numbers from the IANA
# registry. 23 is GOST R 34.10-2012 (RFC 9558), which replaced 12.
DNSSEC_ALGORITHMS = {
    1: "RSAMD5",
    3: "DSA",
    5: "RSASHA1",
    6: "DSA-NSEC3-SHA1",
    7: "RSASHA1-NSEC3-SHA1",
    8: "RSASHA256",
    10: "RSASHA512",
    12: "ECC-GOST",
    13: "ECDSAP256SHA256",
    14: "ECDSAP384SHA384",
    15: "ED25519",
    16: "ED448",
    23: "ECC-GOST12",
}
SIGN_MUST_NOT = frozenset({1, 3, 6, 12})
SIGN_NOT_RECOMMENDED = frozenset({5, 7, 10})
# RFC 8624, section 3.3: a SHA-1 digest MUST NOT be used for a new DS record.
DS_DIGESTS = {1: "SHA1", 2: "SHA256", 4: "SHA384"}


# --- CAA ------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Caa:
    flags: int
    tag: str
    value: str

    @property
    def issuer(self) -> str:
        """The authority domain of an issue/issuewild value, "" for "nobody"."""
        return self.value.split(";", 1)[0].strip().lower()


def parse_caa(record: str) -> Caa | None:
    """A CAA record as a resolver prints it, also in the generic "\\# n hex" form some
    DNS-over-HTTPS services return."""
    try:
        rdata = dns.rdata.from_text("IN", "CAA", record)
    except (dns.exception.DNSException, ValueError):
        return None
    assert isinstance(rdata, dns.rdtypes.ANY.CAA.CAA)
    return Caa(
        rdata.flags,
        rdata.tag.decode("ascii", "replace").lower(),
        rdata.value.decode("utf-8", "replace"),
    )


def caa_names(host: str) -> list[str]:
    """The names a certificate authority asks for ``host``, nearest first, without the
    root and the top-level domain (RFC 8659, section 3)."""
    labels = host.rstrip(".").lower().split(".")
    return [".".join(labels[i:]) for i in range(len(labels) - 1)]


@dataclass(slots=True)
class CaaResult:
    host: str
    name: str | None  # where the relevant record set was found
    records: list[str] = field(default_factory=list)
    problem: str | None = None  # the DNS did not answer


async def find_caa(resolver: DnsResolver, host: str) -> CaaResult:
    for name in caa_names(host):
        try:
            records = await resolver.resolve(name, "CAA")
        except DnsLookupError as exc:
            return CaaResult(host, None, problem=str(exc))
        if records:
            return CaaResult(host, name, records)
    return CaaResult(host, None)


def caa_check(result: CaaResult, *, https: bool) -> Check:
    if result.problem:
        return Check(GROUP_WEB, CAA_TITLE, Status.UNKNOWN, f"Не проверено: {result.problem}.")
    if result.name is None:
        return Check(
            GROUP_WEB,
            CAA_TITLE,
            Status.OK,
            f"Записи CAA нет ни у {result.host}, ни у родительских доменов: сертификат для "
            "сайта может выпустить любой центр сертификации. Это допустимо (RFC 8659), но "
            "CAA сужает круг тех, кого можно обмануть или взломать ради поддельного "
            "сертификата. Чтобы включить, добавьте запись вида "
            f'«{result.host}. CAA 0 issue "letsencrypt.org"» с вашими центрами.',
        )
    parsed = [c for c in (parse_caa(r) for r in result.records) if c]
    where = "" if result.name == result.host else f" (действует запись {result.name})"
    critical = [c for c in parsed if c.flags & CAA_CRITICAL and c.tag not in CAA_KNOWN_TAGS]
    if critical:
        tags = ", ".join(sorted({c.tag for c in critical}))
        return Check(
            GROUP_WEB,
            CAA_TITLE,
            Status.WARN,
            f"В CAA{where} есть тег {tags} с флагом critical (128). Центр сертификации, "
            "который не знает этого тега, обязан отказать в выпуске (RFC 8659, раздел 4.1): "
            "сертификат, скорее всего, не продлить.",
            "Уберите флаг 128 у нестандартных тегов CAA или сами теги, если они не нужны.",
        )
    issue = [c for c in parsed if c.tag == "issue"]
    wild = [c for c in parsed if c.tag == "issuewild"]
    allowed = sorted({c.issuer for c in issue if c.issuer})
    allowed_wild = sorted({c.issuer for c in wild if c.issuer})
    if issue and not allowed and https:
        extra = (
            f" Только для сертификатов на *.{result.host}: {', '.join(allowed_wild)}."
            if allowed_wild
            else ""
        )
        return Check(
            GROUP_WEB,
            CAA_TITLE,
            Status.WARN,
            f'CAA{where} запрещает выпуск всем центрам (issue ";"), а сайт работает по '
            "HTTPS: когда сертификат истечёт, новый не выпустят (RFC 8659, раздел 4.2)." + extra,
            "Впишите в CAA центр, который выпускает ваш сертификат: "
            f'«{result.name}. CAA 0 issue "<домен центра>"».',
        )
    if issue:
        who = (
            "сертификаты могут выпускать только " + ", ".join(allowed)
            if allowed
            else "выпуск сертификатов запрещён всем центрам"
        )
    else:
        who = "тега issue нет, поэтому обычные сертификаты может выпустить любой центр"
    if allowed_wild:
        who += f"; для *.{result.host} — " + ", ".join(allowed_wild)
    elif wild:
        who += "; сертификаты *. запрещены"
    iodef = [c.value for c in parsed if c.tag == "iodef"]
    report = f" Сообщения об отказах: {', '.join(iodef)}." if iodef else ""
    return Check(GROUP_WEB, CAA_TITLE, Status.OK, f"CAA{where}: {who}.{report}")


# --- DNSSEC ---------------------------------------------------------------------------


@dataclass(slots=True)
class DnssecResult:
    zone: str
    ds: list[str] = field(default_factory=list)
    dnskey: list[str] = field(default_factory=list)
    problem: str | None = None


async def find_dnssec(resolver: DnsResolver, zone: str) -> DnssecResult:
    try:
        ds, dnskey = await asyncio.gather(
            resolver.resolve(zone, "DS"), resolver.resolve(zone, "DNSKEY")
        )
    except DnsLookupError as exc:
        return DnssecResult(zone, problem=str(exc))
    return DnssecResult(zone, ds, dnskey)


def _rdata(rtype: str, text: str) -> dns.rdata.Rdata | None:
    try:
        return dns.rdata.from_text("IN", rtype, text)
    except (dns.exception.DNSException, ValueError):
        return None


def matching_ds(zone: str, ds_records: list[str], keys: list[str]) -> list[tuple[int, int]]:
    """(algorithm, digest type) of the DS records that match a DNSKEY of the zone."""
    name = dns.name.from_text(zone)
    dnskeys = [k for k in (_rdata("DNSKEY", t) for t in keys) if k is not None]
    found = []
    for text in ds_records:
        ds = _rdata("DS", text)
        if not isinstance(ds, dns.rdtypes.dsbase.DSBase) or ds.digest_type not in DS_DIGESTS:
            continue
        for key in dnskeys:
            assert isinstance(key, dns.rdtypes.ANY.DNSKEY.DNSKEY)
            if key.algorithm != ds.algorithm:
                continue
            try:
                made = dns.dnssec.make_ds(name, key, DS_DIGESTS[ds.digest_type], validating=True)
            except (dns.exception.DNSException, ValueError):
                continue
            if made == ds:
                found.append((int(ds.algorithm), ds.digest_type))
                break
    return found


def _algorithm(number: int) -> str:
    return f"{DNSSEC_ALGORITHMS.get(number, 'неизвестный')} ({number})"


def dnssec_check(result: DnssecResult) -> Check:
    zone = result.zone
    if result.problem:
        return Check(GROUP_WEB, DNSSEC_TITLE, Status.UNKNOWN, f"Не проверено: {result.problem}.")
    if not result.ds:
        island = (
            " Ключи DNSKEY в зоне есть, но записи DS у регистратора нет, поэтому подпись "
            "никто не проверяет."
            if result.dnskey
            else ""
        )
        return Check(
            GROUP_WEB,
            DNSSEC_TITLE,
            Status.OK,
            f"Зона {zone} не защищена DNSSEC.{island} Это допустимо, но без подписи ответы "
            "DNS о сайте и почте можно подменить по дороге к посетителю, и проверяющий "
            "резолвер этого не заметит. Подпись включается у DNS-хостинга, запись DS "
            "публикует регистратор; зона .ru DNSSEC поддерживает.",
        )
    fix = (
        "Сверьте запись DS у регистратора с текущим ключом KSK зоны: опубликуйте новую DS "
        "или, если подпись больше не нужна, удалите DS у регистратора."
    )
    if not result.dnskey:
        return Check(
            GROUP_WEB,
            DNSSEC_TITLE,
            Status.FAIL,
            f"У регистратора опубликована запись DS для {zone}, а ключей DNSKEY в зоне нет. "
            "Проверяющие резолверы (Google, Cloudflare, многие провайдеры) считают такие "
            "ответы поддельными и не открывают ни сайт, ни почту (RFC 4035, раздел 5).",
            fix,
        )
    matched = matching_ds(zone, result.ds, result.dnskey)
    if not matched:
        return Check(
            GROUP_WEB,
            DNSSEC_TITLE,
            Status.FAIL,
            f"Ни одна запись DS для {zone} не подходит к ключам DNSKEY зоны: так бывает, "
            "когда ключ сменили, а DS у регистратора оставили старую. Цепочка доверия "
            "разорвана, проверяющие резолверы не открывают ни сайт, ни почту "
            "(RFC 4035, раздел 5).",
            fix,
        )
    algorithms = sorted({a for a, _ in matched})
    names = ", ".join(_algorithm(a) for a in algorithms)
    old = [a for a in algorithms if a in SIGN_MUST_NOT | SIGN_NOT_RECOMMENDED]
    if len(old) == len(algorithms):
        must = any(a in SIGN_MUST_NOT for a in old)
        level = "подписывать им запрещено" if must else "подписывать им не рекомендуется"
        return Check(
            GROUP_WEB,
            DNSSEC_TITLE,
            Status.WARN,
            f"Зона {zone} подписана, цепочка DS → DNSKEY сходится, но алгоритм {names} "
            f"устарел: по RFC 8624 (раздел 3.1) {level}. Часть резолверов уже считает такую "
            "зону неподписанной.",
            "Перейдите на алгоритм 13 (ECDSAP256SHA256) или 8 (RSASHA256): у DNS-хостинга "
            "смените ключи, у регистратора — запись DS.",
        )
    sha1 = all(d == 1 for _, d in matched)
    digest = (
        " Запись DS посчитана по SHA-1: для новых DS это запрещено (RFC 8624, раздел 3.3), "
        "при следующей смене ключа выберите SHA-256."
        if sha1
        else ""
    )
    return Check(
        GROUP_WEB,
        DNSSEC_TITLE,
        Status.OK,
        f"Зона {zone} подписана ({names}), запись DS у регистратора подходит к ключу зоны."
        f"{digest} Сами подписи и их сроки Suveren не проверяет.",
    )


# --- Running --------------------------------------------------------------------------


def _evidence(name: str, rtype: str, records: list[str]) -> Evidence:
    return Evidence("dns", f"{rtype} {name}", "\n".join(records))


async def run_zone_checks(resolver: DnsResolver, host: str, *, https: bool) -> list[Check]:
    """CAA for the site's name and DNSSEC of its zone."""
    zone = registrable_domain(host)
    caa, sec = await asyncio.gather(find_caa(resolver, host), find_dnssec(resolver, zone))
    checks = [caa_check(caa, https=https), dnssec_check(sec)]
    if not caa.problem:
        names = caa_names(host)
        shown = names[: names.index(caa.name) + 1] if caa.name else names
        checks[0].evidence = [
            _evidence(n, "CAA", caa.records if n == caa.name else []) for n in shown
        ]
    if not sec.problem:
        checks[1].evidence = [
            _evidence(zone, "DS", sec.ds),
            _evidence(zone, "DNSKEY", sec.dnskey),
        ]
    return checks
