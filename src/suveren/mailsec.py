"""Can someone send a letter that looks like it came from the site's domain?

Everything here is DNS (SPF, DMARC, DKIM, MTA-STS, TLS-RPT records) plus one GET of
the public MTA-STS policy file, exactly what any receiving mail server looks at.

What actually stops a forged From: header is DMARC with an enforcing policy: big
receivers (Gmail, Яндекс, Mail.ru, Outlook) reject or junk letters that fail it.
SPF alone only covers the envelope sender, which the recipient never sees, so the
verdict is built on DMARC and SPF/DKIM are reported as supporting checks.
"""

from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass, field

import httpx

from suveren import services as db
from suveren.checks import Check, Status
from suveren.collect import parse_mx
from suveren.dnsutil import DnsLookupError, DnsResolver
from suveren.errors import TIMEOUTS

GROUP_MAIL = "Защита почты от подделки"

SPF_LOOKUP_LIMIT = 10  # RFC 7208, section 4.6.4
_SPF_LOOKUP_TERMS = frozenset({"include", "a", "mx", "ptr", "exists", "redirect"})
_MAX_SPF_RECORDS = 30  # safety cap on records fetched while following includes

# Selectors of popular mail services; DKIM keys can't be listed, only guessed.
DKIM_SELECTORS = (
    "default",
    "mail",  # Яндекс 360
    "mailru",  # VK WorkSpace
    "dkim",
    "google",
    "selector1",  # Microsoft 365
    "selector2",
    "k1",  # Mailchimp
    "s1",
    "s2",
    "smtp",
    "us",  # Unisender
    "sendsay",
    "x",
    "mx",
)


# --- SPF ------------------------------------------------------------------------------


@dataclass(slots=True)
class Spf:
    record: str
    all: str | None = None  # "-", "~", "?", "+" or None when there is no "all"
    redirect: str | None = None
    includes: list[str] = field(default_factory=list)
    lookups: int = 0  # DNS-querying terms in this record alone
    uses_ptr: bool = False  # "ptr" SHOULD NOT be used (RFC 7208, section 5.5)


def spf_records(txt: list[str]) -> list[str]:
    return [t for t in txt if re.match(r"(?i)v=spf1(\s|$)", t.strip())]


def parse_spf(record: str) -> Spf:
    spf = Spf(record.strip())
    for term in spf.record.split()[1:]:
        low = term.lower()
        if low.startswith("redirect="):
            spf.redirect = term.split("=", 1)[1].rstrip(".")
            spf.lookups += 1
            continue
        if "=" in low:  # exp= and unknown modifiers
            continue
        qualifier = low[0] if low[0] in "+-~?" else "+"
        mechanism = low.lstrip("+-~?")
        name, _, value = mechanism.partition(":")
        name = name.split("/", 1)[0]
        if name == "all":
            spf.all = qualifier
        elif name == "include" and value:
            spf.includes.append(value.rstrip("."))
        elif name == "ptr":
            spf.uses_ptr = True
        if name in _SPF_LOOKUP_TERMS:
            spf.lookups += 1
    if spf.all is not None and spf.redirect:
        # With an "all" mechanism the redirect is never evaluated (RFC 7208, section 6.1).
        spf.redirect = None
        spf.lookups -= 1
    return spf


@dataclass(slots=True)
class SpfResult:
    spf: Spf | None
    count: int  # records with v=spf1 at the domain
    lookups: int = 0  # total across includes and redirects
    effective_all: str | None = None
    problems: list[str] = field(default_factory=list)


async def _txt(resolver: DnsResolver, name: str) -> list[str]:
    return await resolver.resolve(name, "TXT")


async def check_spf(resolver: DnsResolver, domain: str) -> SpfResult:
    records = spf_records(await _txt(resolver, domain))
    if len(records) != 1:
        return SpfResult(None, len(records))
    spf = parse_spf(records[0])
    result = SpfResult(spf, 1)
    loaded: dict[str, Spf | None] = {}
    budget = [_MAX_SPF_RECORDS]  # records evaluated, a guard against huge trees

    async def load(name: str) -> Spf | None:
        if name not in loaded:
            loaded[name] = None
            try:
                found = spf_records(await _txt(resolver, name))
            except DnsLookupError:
                result.problems.append(f"{name}: DNS не ответил")
                return None
            if len(found) != 1:
                result.problems.append(
                    f"{name}: нет SPF-записи" if not found else f"{name}: несколько SPF"
                )
                return None
            loaded[name] = parse_spf(found[0])
        return loaded[name]

    async def walk(record: Spf, path: tuple[str, ...]) -> tuple[int, str | None]:
        """DNS lookups an evaluation of ``record`` makes, and its effective "all".

        A receiver evaluates an include each time it is reached, so a record included
        twice counts twice (RFC 7208, section 4.6.4); a redirect hands over its target's
        "all", however long the chain (section 6.1)."""
        total, effective = record.lookups, record.all
        targets = [(n, False) for n in record.includes]
        targets += [(record.redirect, True)] if record.redirect else []
        for target, is_redirect in targets:
            name = target.lower()
            # Macros can't be expanded without a sender; a loop is the record's own error.
            if "%{" in name or name in path or budget[0] <= 0:
                continue
            budget[0] -= 1
            inner = await load(name)
            if inner is None:
                continue
            lookups, inner_all = await walk(inner, (*path, name))
            total += lookups
            if is_redirect:
                effective = inner_all
        return total, effective

    result.lookups, result.effective_all = await walk(spf, (domain.lower(),))
    return result


# --- DMARC ----------------------------------------------------------------------------


@dataclass(slots=True)
class Dmarc:
    record: str
    policy: str | None  # none / quarantine / reject; None if the p= tag is missing or bad
    subdomain_policy: str | None
    pct: int = 100
    rua: str | None = None


def parse_dmarc(record: str) -> Dmarc:
    tags: dict[str, str] = {}
    for part in record.split(";"):
        key, sep, value = part.partition("=")
        if sep:
            tags[key.strip().lower()] = value.strip()
    policy = tags.get("p", "").lower() or None
    if policy not in ("none", "quarantine", "reject"):
        policy = None
    sub = tags.get("sp", "").lower() or None
    if sub not in ("none", "quarantine", "reject"):
        sub = None
    try:
        pct = max(0, min(100, int(tags.get("pct", "100"))))
    except ValueError:
        pct = 100
    return Dmarc(record.strip(), policy, sub, pct, tags.get("rua") or None)


def dmarc_records(txt: list[str]) -> list[str]:
    return [t for t in txt if re.match(r"(?i)v\s*=\s*DMARC1\s*(;|$)", t.strip())]


# --- Verdict --------------------------------------------------------------------------


@dataclass(slots=True)
class MailFacts:
    domain: str
    receives_mail: bool
    spf: SpfResult
    dmarc: Dmarc | None
    dmarc_count: int
    dkim: list[str]  # selectors with a published key
    mta_sts: str | None = None  # policy mode: enforce / testing / none
    tls_rpt: bool = False
    mx_hosts: list[str] = field(default_factory=list)  # by priority
    mta_sts_mx: list[str] = field(default_factory=list)  # "mx:" patterns of the policy


# What each mail provider asks to put in SPF; every name was checked to publish an SPF
# record on 2026-10-17. Keys are service names from services.py, found by MX.
SPF_INCLUDES = {
    "Яндекс 360": "_spf.yandex.net",
    "VK WorkSpace (Mail.ru)": "_spf.mail.ru",
    "Google Workspace": "_spf.google.com",
    "Microsoft 365": "spf.protection.outlook.com",
    "Zoho Mail": "zoho.com",
    "Timeweb": "_spf.timeweb.ru",
    "Beget": "beget.com",
    "REG.RU": "_spf.hosting.reg.ru",
    "RU-CENTER": "_spf.nic.ru",
    "Джино": "_spf.jino.ru",
    "Хостлэнд": "_spf.hostland.ru",
    "Proton Mail": "_spf.protonmail.ch",
    "Fastmail": "spf.messagingengine.com",
    "iCloud Mail": "icloud.com",
    "Mailgun": "mailgun.org",
    "SendGrid": "sendgrid.net",
}


def spf_example(m: MailFacts) -> str:
    """An SPF record to start from, for the provider that receives the domain's mail."""
    for host in m.mx_hosts:
        service = db.by_mx(host)
        include = SPF_INCLUDES.get(service.name) if service else None
        if service and include:
            if include == "zoho.com" and host.endswith(".eu"):
                include = "zoho.eu"
            return (
                f'"v=spf1 include:{include} ~all": почта домена у {service.name}. Если письма '
                "отправляют и другие сервисы (рассылки, CRM, сайт), добавьте их include: в ту "
                "же запись"
            )
    return (
        '"v=spf1 mx ~all", если письма отправляют те же серверы, что принимают почту, и '
        "добавьте include: каждого сервиса, который отправляет письма от имени домена "
        "(его даёт почтовый провайдер)"
    )


def _dmarc_hint(domain: str) -> str:
    return (
        f'Добавьте в DNS TXT-запись _dmarc.{domain} со значением "v=DMARC1; p=none; '
        f'rua=mailto:dmarc@{domain}". Через 2–4 недели, когда по отчётам станет видно, что '
        "вся настоящая почта проходит проверку, смените p=none на p=quarantine, а затем на "
        "p=reject."
    )


def verdict(m: MailFacts) -> Check:
    title = f"Можно ли подделать письмо от имени @{m.domain}"
    d = m.dmarc
    weak_sub = d is not None and d.subdomain_policy == "none"
    # Mail outside pct gets the next lower policy (RFC 7489, section 6.6.4): at pct=0
    # reject works as quarantine and quarantine as none.
    policy = d.policy if d is not None else None
    if d is not None and d.pct == 0:
        policy = {"reject": "quarantine", "quarantine": "none"}.get(policy or "", policy)
    if d is not None and m.dmarc_count == 1 and policy == "reject" and d.pct == 100:
        if weak_sub:
            return Check(
                GROUP_MAIL,
                title,
                Status.WARN,
                "Частично. Письма от самого домена почтовые сервисы отклонят (DMARC p=reject), "
                "но для поддоменов стоит sp=none: письмо от имени, например, "
                f"noreply@mail.{m.domain} дойдёт.",
                "Уберите sp=none из DMARC-записи или замените на sp=reject.",
            )
        return Check(
            GROUP_MAIL,
            title,
            Status.OK,
            "Нет. DMARC с политикой reject: Gmail, Яндекс, Mail.ru и другие отклонят письмо "
            "с поддельным адресом отправителя.",
        )
    if d is not None and m.dmarc_count == 1 and policy in ("quarantine", "reject"):
        if policy == "reject":
            how = f"будут отклонены в {d.pct}% случаев (pct={d.pct}), остальные попадут в спам"
        elif d.pct == 100:
            how = "попадут в спам, а не будут отклонены"
        elif d.pct == 0:  # p=reject; pct=0
            how = "попадут в спам (pct=0 смягчает reject до quarantine), а не будут отклонены"
        else:
            how = f"попадут в спам только в {d.pct}% случаев (pct={d.pct}), остальные дойдут"
        return Check(
            GROUP_MAIL,
            title,
            Status.WARN,
            f"Частично. Поддельные письма {how}: часть получателей их всё равно увидит.",
            "Когда убедитесь по отчётам DMARC, что настоящая почта проходит проверку, "
            "поставьте p=reject и уберите pct.",
        )
    if d is not None and m.dmarc_count == 1 and d.policy == "quarantine" and policy == "none":
        reason = "в DMARC стоит pct=0: политика quarantine не применяется ни к одному письму"
    elif d is not None and m.dmarc_count == 1 and d.policy == "none":
        reason = "DMARC стоит в режиме наблюдения (p=none): почтовые сервисы не отклоняют письма"
    elif m.dmarc_count > 1:
        reason = "DMARC-записей несколько, и почтовые сервисы игнорируют их все"
    elif d is not None:
        reason = "в DMARC-записи нет корректной политики p="
    else:
        reason = "у домена нет DMARC-записи"
    tail = (
        " Домен не принимает почту, но мошенники всё равно могут писать от его имени."
        if not m.receives_mail
        else ""
    )
    if m.spf.effective_all in ("-", "~"):
        tail += (
            " SPF у домена есть, но он проверяет только технический адрес возврата, а не "
            "адрес отправителя, который видит получатель: от подделки защищает DMARC."
        )
    return Check(
        GROUP_MAIL,
        title,
        Status.FAIL,
        f"Да: {reason}, поэтому письмо с адресом отправителя director@{m.domain}, скорее "
        "всего, дойдёт до получателя, и подмену он не заметит. Так рассылают фишинг и "
        f"поддельные счета от имени компании.{tail}",
        _dmarc_hint(m.domain)
        if m.receives_mail
        else f'Запретите отправку от имени домена: TXT {m.domain} "v=spf1 -all" и TXT '
        f'_dmarc.{m.domain} "v=DMARC1; p=reject".',
    )


def spf_check(m: MailFacts) -> Check:
    title = "SPF: кто может отправлять почту"
    r = m.spf
    if r.count == 0:
        return Check(
            GROUP_MAIL,
            title,
            Status.WARN if m.receives_mail else Status.FAIL,
            "SPF-записи нет: почтовые сервисы не знают, с каких серверов домен отправляет "
            "письма, и чаще отправляют настоящую почту в спам."
            if m.receives_mail
            else "SPF-записи нет: домен почту не отправляет, но и не запрещает этого, поэтому "
            "письмо от его имени может отправить любой сервер.",
            f"Опубликуйте TXT-запись для {m.domain}, например {spf_example(m)}."
            if m.receives_mail
            else f'Опубликуйте для {m.domain} TXT-запись "v=spf1 -all": домен не отправляет почту.',
        )
    if r.count > 1:
        return Check(
            GROUP_MAIL,
            title,
            Status.FAIL,
            f"SPF-записей {r.count}, а должна быть одна: по стандарту это ошибка, и проверка SPF "
            "не проходит ни у кого.",
            "Объедините все SPF-записи в одну.",
        )
    assert r.spf is not None
    details = [f"Запись: {r.spf.record}."]
    status = Status.OK
    recommendation = ""
    if r.lookups > SPF_LOOKUP_LIMIT:
        status = Status.FAIL
        details.append(
            f"Для проверки нужно {r.lookups} DNS-запросов при лимите {SPF_LOOKUP_LIMIT}: "
            "почтовые сервисы могут счесть запись ошибочной, и тогда SPF не пройдут даже "
            "настоящие письма, особенно с серверов из конца списка."
        )
        recommendation = (
            "Сократите число include: уберите сервисы, которыми больше не пользуетесь, или "
            "замените include на конкретные IP-адреса (ip4:)."
        )
    else:
        unread = " (без записей, которые не удалось прочитать)" if r.problems else ""
        details.append(f"DNS-запросов при проверке: {r.lookups} из {SPF_LOOKUP_LIMIT}{unread}.")
    redirect = (r.spf.redirect or "").lower()
    # positive.com: "redirect=" with a broken target; its "all" is unknown, not missing.
    redirect_broken = bool(redirect) and any(p.split(":", 1)[0] == redirect for p in r.problems)
    if r.effective_all == "+":
        status = Status.FAIL
        details.append("Стоит +all: отправлять почту от имени домена разрешено кому угодно.")
        recommendation = recommendation or "Замените +all на ~all или -all."
    elif r.effective_all in ("?", None) and not redirect_broken:
        status = max(status, Status.WARN, key=_rank)
        details.append(
            "В конце нет -all или ~all: про остальные серверы SPF ничего не говорит."
            if r.effective_all is None
            else "Стоит ?all: про остальные серверы SPF ничего не говорит."
        )
        recommendation = recommendation or "Завершите запись на ~all (или -all)."
    if r.spf.uses_ptr:
        status = max(status, Status.WARN, key=_rank)
        details.append(
            "Есть механизм ptr: стандарт не рекомендует его (RFC 7208, раздел 5.5), он медленный, "
            "а часть почтовых сервисов его не учитывает, и письма с этих серверов не пройдут SPF."
        )
        recommendation = (
            f"{recommendation} Замените ptr на ip4:/ip6: или a: с адресами ваших серверов."
        ).strip()
    if r.problems:
        # An include or redirect without exactly one SPF record is a permerror for the whole
        # check (RFC 7208, sections 5.2 and 6.1); a DNS timeout is only our failure to look.
        broken = any(not p.endswith("DNS не ответил") for p in r.problems)
        status = max(status, Status.FAIL if broken else Status.WARN, key=_rank)
        details.append("Не удалось разобрать: " + "; ".join(r.problems[:3]) + ".")
        if broken:
            details.append(
                "По стандарту (RFC 7208, разделы 5.2 и 6.1) такая запись даёт ошибку проверки "
                "(permerror): SPF не проходят даже письма с настоящих серверов, если они не "
                "перечислены в записи раньше."
            )
        fixes = []
        for problem in r.problems[:3]:
            name, _, what = problem.partition(": ")
            term = "redirect" if name == redirect else "include"
            if "@" in name:
                # auto.ru: "include:academyautoru@tbank.ru", a mailbox where a domain belongs.
                fixes.append(
                    f"В {term} указан адрес почты ({name}), а нужен домен, например "
                    f"{term}:{name.split('@', 1)[1]}; исправьте или уберите его."
                )
            elif what == "несколько SPF":
                fixes.append(f"У {name} (из {term}) несколько SPF-записей: объедините их в одну.")
            elif what == "нет SPF-записи":
                fixes.append(
                    f"У {name} (из {term}) нет своей SPF-записи: опубликуйте её или уберите "
                    f"этот {term}."
                )
            else:
                fixes.append(f"Проверьте {name} позже: DNS не ответил.")
        recommendation = " ".join([recommendation, *dict.fromkeys(fixes)]).strip()
    return Check(GROUP_MAIL, title, status, " ".join(details), recommendation)


def _rank(status: Status) -> int:
    return {Status.OK: 0, Status.UNKNOWN: 1, Status.WARN: 2, Status.FAIL: 3}[status]


def dmarc_check(m: MailFacts) -> Check:
    title = "DMARC: что делать с поддельными письмами"
    if m.dmarc_count > 1:
        return Check(
            GROUP_MAIL,
            title,
            Status.FAIL,
            f"DMARC-записей у _dmarc.{m.domain} {m.dmarc_count}: по стандарту это ошибка, "
            "и почтовые сервисы не применяют ни одну.",
            "Оставьте одну DMARC-запись.",
        )
    d = m.dmarc
    if d is None:
        return Check(
            GROUP_MAIL,
            title,
            Status.FAIL,
            "DMARC-записи нет: почтовые сервисы не знают, что делать с письмами, которые "
            "выдают себя за ваш домен, и пропускают их.",
            # A domain without mail has no real letters to watch first: reject at once,
            # as the verdict says (a gradual p=none start is for domains that send mail).
            _dmarc_hint(m.domain)
            if m.receives_mail
            else f'Добавьте TXT-запись _dmarc.{m.domain} со значением "v=DMARC1; p=reject": '
            "домен почту не отправляет, поэтому сразу запретите письма от его имени.",
        )
    reports = (
        # "mailto:a@b.ru!10m": the tail is a size limit, not part of the address.
        f" Отчёты приходят на {', '.join(u.strip().split('!')[0] for u in d.rua.split(','))}."
        if d.rua
        else " Адрес для отчётов (rua) не указан: вы не узнаете, кто рассылает письма от "
        "вашего имени."
    )
    if d.policy is None:
        return Check(
            GROUP_MAIL,
            title,
            Status.FAIL,
            f"Запись есть, но в ней нет корректной политики p=: {d.record}.",
            "Укажите p=none, p=quarantine или p=reject.",
        )
    if d.policy == "none":
        return Check(
            GROUP_MAIL,
            title,
            Status.WARN,
            "Режим наблюдения (p=none): поддельные письма доходят." + reports,
            "Изучите отчёты DMARC и переведите политику на p=quarantine, затем на p=reject.",
        )
    status = Status.OK if d.policy == "reject" and d.pct == 100 else Status.WARN
    pct = f", но только для {d.pct}% писем" if d.pct < 100 else ""
    return Check(
        GROUP_MAIL,
        title,
        status,
        f"Политика p={d.policy}{pct}." + reports,
        "" if status is Status.OK else "Переведите политику на p=reject без pct.",
    )


def dkim_check(m: MailFacts) -> Check:
    title = "DKIM: цифровая подпись писем"
    if m.dkim:
        return Check(
            GROUP_MAIL,
            title,
            Status.OK,
            "Найдены ключи DKIM с селекторами: " + ", ".join(m.dkim) + ".",
        )
    return Check(
        GROUP_MAIL,
        title,
        Status.UNKNOWN,
        "Ключи DKIM не найдены среди распространённых селекторов. Это не значит, что DKIM "
        "нет: селектор может называться иначе. Посмотрите заголовок DKIM-Signature (s=) в "
        "любом письме от компании.",
    )


def mx_matches(host: str, pattern: str) -> bool:
    """RFC 8461, section 4.1: "*." stands for exactly one leftmost label."""
    host, pattern = host.lower().rstrip("."), pattern.lower().rstrip(".")
    if pattern.startswith("*."):
        label, _, rest = host.partition(".")
        return bool(label) and rest == pattern[2:]
    return host == pattern


def transport_check(m: MailFacts) -> Check:
    title = "Шифрование входящей почты (MTA-STS)"
    rpt = " Отчёты TLS-RPT настроены." if m.tls_rpt else ""
    unmatched = [h for h in m.mx_hosts if not any(mx_matches(h, p) for p in m.mta_sts_mx)]
    if m.mta_sts == "enforce" and unmatched:
        return Check(
            GROUP_MAIL,
            title,
            Status.FAIL,
            "MTA-STS в режиме enforce, но MX-серверы "
            + ", ".join(unmatched)
            + " не перечислены в строках mx: политики. Отправители, которые соблюдают "
            "MTA-STS (например, Gmail), не доставят на них письма (RFC 8461, раздел 4.1)." + rpt,
            f"Добавьте эти серверы в строки mx: файла https://mta-sts.{m.domain}/.well-known/"
            "mta-sts.txt и смените id= в TXT-записи _mta-sts.",
        )
    if m.mta_sts == "enforce":
        return Check(
            GROUP_MAIL,
            title,
            Status.OK,
            "MTA-STS в режиме enforce: письма к вам передаются только по шифрованному "
            "каналу с проверкой сертификата." + rpt,
        )
    if m.mta_sts == "testing":
        return Check(
            GROUP_MAIL,
            title,
            Status.WARN,
            "MTA-STS в режиме testing: шифрование не обязательно." + rpt,
            "Когда отчёты TLS-RPT покажут, что почта доходит, поставьте в политике mode: enforce.",
        )
    return Check(
        GROUP_MAIL,
        title,
        Status.WARN,
        "MTA-STS не настроен: письма к вам можно перехватить, понизив соединение до "
        "незашифрованного. Это редкая атака, исправлять во вторую очередь." + rpt,
        f"Опубликуйте TXT-запись _mta-sts.{m.domain} и файл политики на "
        f"https://mta-sts.{m.domain}/.well-known/mta-sts.txt.",
    )


def evaluate(m: MailFacts) -> list[Check]:
    checks = [verdict(m), spf_check(m), dmarc_check(m)]
    if m.receives_mail:
        checks += [dkim_check(m), transport_check(m)]
    return checks


# --- Collection -----------------------------------------------------------------------


def parse_mta_sts_mode(policy: str) -> str | None:
    match = re.search(r"(?im)^\s*mode\s*:\s*(enforce|testing|none)\s*$", policy)
    return match.group(1).lower() if match else None


def parse_mta_sts_mx(policy: str) -> list[str]:
    return [m.lower() for m in re.findall(r"(?im)^\s*mx\s*:\s*(\S+)\s*$", policy)]


async def _dkim(resolver: DnsResolver, domain: str) -> list[str]:
    async def has_key(selector: str) -> bool:
        try:
            txt = await _txt(resolver, f"{selector}._domainkey.{domain}")
        except DnsLookupError:
            return False
        # "p=" with an empty value is a revoked key.
        return any(re.search(r"(?i)(^|;)\s*p=[A-Za-z0-9+/]", t) for t in txt)

    found = await asyncio.gather(*(has_key(s) for s in DKIM_SELECTORS))
    return [s for s, ok in zip(DKIM_SELECTORS, found, strict=True) if ok]


async def _mta_sts(
    resolver: DnsResolver, client: httpx.AsyncClient, domain: str
) -> tuple[str | None, list[str]]:
    """Policy mode and its mx patterns, fetched the way a sending server does."""
    txt = await _txt(resolver, f"_mta-sts.{domain}")
    sts = [t for t in txt if t.lower().startswith("v=stsv1")]
    if not sts:
        return None, []
    # Several records, or one without an id, mean "no policy" to senders (RFC 8461, 3.1).
    if len(sts) > 1 or not re.search(r"(?i);\s*id\s*=\s*[a-z0-9]{1,32}\s*(;|$)", sts[0]):
        return "none", []
    try:
        # Senders must not follow redirects for the policy (RFC 8461, section 3.3).
        resp = await client.get(
            f"https://mta-sts.{domain}/.well-known/mta-sts.txt", follow_redirects=False
        )
    except (httpx.HTTPError, *TIMEOUTS):
        return "none", []
    if resp.status_code != 200:
        return "none", []
    mode, mx = parse_mta_sts_mode(resp.text), parse_mta_sts_mx(resp.text)
    # Senders ignore a policy that is not text/plain or lacks a required field
    # (RFC 8461, sections 3.2 and 3.3): for them the domain has no MTA-STS.
    complete = re.search(r"(?im)^\s*version\s*:\s*STSv1\s*$", resp.text) and re.search(
        r"(?im)^\s*max_age\s*:\s*\d+\s*$", resp.text
    )
    plain = resp.headers.get("content-type", "text/plain").lower().startswith("text/plain")
    if not (mode and complete and plain) or (mode != "none" and not mx):
        return "none", []
    return mode, mx


async def collect_mail(resolver: DnsResolver, client: httpx.AsyncClient, domain: str) -> MailFacts:
    mx = await resolver.resolve(domain, "MX")
    # A null MX ("0 .") says the domain takes no mail at all (RFC 7505).
    receives = any(r.split()[-1] not in (".", "") for r in mx if r.split())
    spf = await check_spf(resolver, domain)
    dmarc_txt = dmarc_records(await _txt(resolver, f"_dmarc.{domain}"))
    facts = MailFacts(
        domain=domain,
        receives_mail=receives,
        spf=spf,
        dmarc=parse_dmarc(dmarc_txt[0]) if len(dmarc_txt) == 1 else None,
        dmarc_count=len(dmarc_txt),
        dkim=[],
        mx_hosts=parse_mx(mx),
    )
    if receives:
        facts.dkim = await _dkim(resolver, domain)
        facts.mta_sts, facts.mta_sts_mx = await _mta_sts(resolver, client, domain)
        rpt = await _txt(resolver, f"_smtp._tls.{domain}")
        facts.tls_rpt = any(t.lower().startswith("v=tlsrptv1") for t in rpt)
    return facts


async def run_mail_checks(
    resolver: DnsResolver, client: httpx.AsyncClient, domain: str
) -> list[Check]:
    try:
        return evaluate(await collect_mail(resolver, client, domain))
    except DnsLookupError as exc:
        return [
            Check(
                GROUP_MAIL,
                f"Можно ли подделать письмо от имени @{domain}",
                Status.UNKNOWN,
                f"DNS не ответил, проверка не выполнена ({exc}).",
            )
        ]
