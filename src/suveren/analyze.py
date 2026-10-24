"""Turns collected facts into dependencies and findings."""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable
from datetime import datetime, timezone
from urllib.parse import urlsplit

from suveren import services as db
from suveren.collect import Facts, HostInfo, NetInfo
from suveren.models import Category, Dependency, Finding, Report, Severity
from suveren.page import page_code
from suveren.services import Service
from suveren.utils import registrable_domain

# Layers where a domestic server next to a foreign one is real redundancy.
# Shown when the security stage did not run: its TLS check (SUV-WEB-008) says it better.
TLS_UNTRUSTED_NOTE = (
    "SSL-сертификату сайта не доверяет стандартный набор корневых сертификатов. "
    "Если он выпущен НУЦ Минцифры, браузеры без российского корневого сертификата "
    "(Chrome, Firefox, Safari по умолчанию) покажут посетителям ошибку."
)
REDUNDANT_LAYERS = frozenset({Category.DNS, Category.MAIL, Category.HOSTING, Category.CDN})

# Words that open many network names; a site called cloud.ru doesn't own CLOUD.DOG OU.
_GENERIC_LABELS = frozenset(
    {
        "cloud",
        "host",
        "hosting",
        "server",
        "servers",
        "data",
        "web",
        "net",
        "network",
        "online",
        "telecom",
        "digital",
        "global",
        "media",
        "group",
        "tech",
        "mail",
        "internet",
        "datacenter",
    }
)
_LEGAL_FORMS = frozenset(
    {"ooo", "llc", "jsc", "pjsc", "ao", "pao", "zao", "oao", "ltd", "gmbh", "inc", "as", "ou"}
)
OWN_NETWORK_NOTE = (
    "Похоже, это собственная сеть компании, а не внешний провайдер: отключить её по решению "
    "третьей стороны сложнее, но серверы находятся за рубежом."
)


def own_network(net: NetInfo | None, domain: str) -> bool:
    """The network is registered to the site's own company ('Habr Europe OU' for habr.com)."""
    if net is None or not net.as_name:
        return False
    label = domain.split(".")[0].lower()
    if len(label) < 4 or label in _GENERIC_LABELS:
        return False
    words = [w for w in re.findall(r"[a-z0-9]+", net.as_name.lower()) if w not in _LEGAL_FORMS]
    return bool(words) and words[0] == label


def _edge(headers: dict[str, str]) -> tuple[str, Service, str] | None:
    """(network's service, the edge service, the header that shows it) when the answer
    came from a CDN edge inside a hosting network: CloudFront in Amazon's AS16509."""
    if "x-amz-cf-id" in headers or "cloudfront" in headers.get("via", "").lower():
        cloudfront = next((s for s in db.INFRA_SERVICES if s.name == "Amazon CloudFront"), None)
        if cloudfront:
            shown = "x-amz-cf-id" if "x-amz-cf-id" in headers else f"via: {headers['via']}"
            return "Amazon Web Services", cloudfront, shown
    return None


def _from_service(category: Category, service: Service, evidence: str) -> Dependency:
    return Dependency(
        category=category,
        service=service.name,
        country=service.country,
        evidence=evidence,
        severity=(service.severity or category.info.severity) if service.foreign else None,
        note=service.note,
        alternative=service.alternative,
    )


def _from_network(
    category: Category, net: NetInfo | None, fallback: str, evidence: str
) -> Dependency:
    country = net.country if net else None
    name = (net.as_name if net else None) or fallback
    dep = Dependency(category=category, service=name, country=country, evidence=evidence)
    if dep.foreign:
        dep.severity = category.info.severity
    return dep


def _merge(deps: Iterable[Dependency]) -> list[Dependency]:
    """One row per (category, service); evidence is joined."""
    merged: dict[tuple[Category, str], Dependency] = {}
    for dep in deps:
        key = (dep.category, dep.service)
        if key in merged:
            existing = merged[key]
            if dep.evidence not in existing.evidence:
                existing.evidence += f", {dep.evidence}"
        else:
            merged[key] = dep
    return list(merged.values())


def _own(category: Category, net: NetInfo, evidence: str) -> Dependency:
    dep = _from_network(category, net, net.ip, evidence)
    dep.service = f"Собственная сеть ({dep.service})"
    if dep.foreign:
        dep.severity = Severity.LOW
        dep.note = OWN_NETWORK_NOTE
    return dep


def _name_domain(host: str) -> str:
    """ns1.dyna-ns.net -> dyna-ns.net."""
    return registrable_domain(host.lower().rstrip("."))


def _server_deps(
    category: Category,
    hosts: list[HostInfo],
    lookup: Callable[[str], Service | None],
    label: str,
    domain: str,
) -> list[Dependency]:
    deps = []
    for h in hosts:
        evidence = f"{label} {h.host}"
        service = lookup(h.host)
        if service:
            deps.append(_from_service(category, service, evidence))
            continue
        carrier = db.by_network(h.net.asn, h.net.as_name) if h.net else None
        if carrier:
            # The server's name is unknown but its network is: the network is only where
            # it runs. ns1.dyna-ns.net is Dynadot's DNS on Cloudflare's network — calling
            # it "Cloudflare" would send the reader to the wrong provider.
            dep = _from_service(category, carrier, evidence)
            dep.service = f"{_name_domain(h.host)} (на сети {carrier.name})"
            deps.append(dep)
        elif h.net is not None and own_network(h.net, domain):
            deps.append(_own(category, h.net, evidence))
        else:
            deps.append(_from_network(category, h.net, h.host, evidence))
    return deps


_RU_REGISTRAR = re.compile(r"^[A-Z0-9-]+-(?:RU|RF|SU)$")


def find_dependencies(facts: Facts) -> tuple[list[Dependency], list[str]]:
    deps: list[Dependency] = []
    notes: list[str] = []

    zone, zone_country = db.zone_info(facts.domain)
    if zone_country:
        deps.append(
            Dependency(
                Category.ZONE,
                zone,
                zone_country,
                facts.domain,
                severity=Category.ZONE.info.severity if zone_country != "RU" else None,
            )
        )

    if facts.registrar:
        service = db.by_registrar(facts.registrar)
        if service:
            deps.append(_from_service(Category.REGISTRAR, service, facts.registrar))
        else:
            # The .ru/.рф registry names accredited registrars "MASTERHOST-RU", "RD-RU":
            # they are Russian even when the base does not list them.
            country = "RU" if _RU_REGISTRAR.search(facts.registrar) else None
            deps.append(Dependency(Category.REGISTRAR, facts.registrar, country, "WHOIS"))

    deps += _server_deps(Category.DNS, facts.ns, db.by_ns, "NS", facts.domain)
    deps += _server_deps(Category.MAIL, facts.mx, db.by_mx, "MX", facts.domain)

    hidden_origin = False
    edge = _edge(facts.headers)
    for net in facts.web:
        evidence = f"IP {net.ip}" + (f" (AS{net.asn})" if net.asn else "")
        service = db.by_network(net.asn, net.as_name)
        if service and edge and service.name == edge[0]:
            # AWS serves CloudFront from its hosting AS: only the answer tells them apart.
            # As "hosting", aviasales.ru got "database abroad" (SUV-PD-007) and 6 млн ₽.
            service, evidence = edge[1], f"{evidence}, заголовок {edge[2]}"
        if service:
            category = Category.CDN if service.cdn else Category.HOSTING
            hidden_origin |= service.cdn
            deps.append(_from_service(category, service, evidence))
        elif own_network(net, facts.domain):
            deps.append(_own(Category.HOSTING, net, evidence))
        else:
            deps.append(_from_network(Category.HOSTING, net, net.ip, evidence))
    if hidden_origin and not any(d.category is Category.HOSTING for d in deps):
        notes.append(
            "Сайт работает через CDN, поэтому настоящий хостинг скрыт и не проверялся. "
            "Проверьте вручную, где находится сервер."
        )

    if facts.tls_issuer:
        service = db.by_issuer(facts.tls_issuer)
        if service:
            deps.append(_from_service(Category.TLS, service, facts.tls_issuer))
        else:
            deps.append(Dependency(Category.TLS, facts.tls_issuer, None, "сертификат"))

    page_text = page_code(facts.html, links=False) + "\n" + "\n".join(facts.loaded_urls)
    found: set[str] = set()
    own = facts.domain  # the site's own hosts are not a dependency on itself
    for service, matched in db.scan_page(page_text, own_domain=own):
        assert service.category is not None
        deps.append(_from_service(service.category, service, matched))
        found.add(service.name)
    # Services that appear only on inner pages say where they were seen.
    for extra in facts.extra_pages:
        text = page_code(extra.html, links=False) + "\n" + "\n".join(extra.loaded_urls)
        for service, matched in db.scan_page(text, own_domain=own):
            if service.name in found:
                continue
            assert service.category is not None
            deps.append(_from_service(service.category, service, f"{matched} · {extra.path}"))
            found.add(service.name)

    return _merge(deps), notes


def _join_unique(items: Iterable[str]) -> list[str]:
    return list(dict.fromkeys(i for i in items if i))


def build_findings(deps: list[Dependency]) -> list[Finding]:
    findings: list[Finding] = []
    for category in Category:
        in_cat = [d for d in deps if d.category is category]
        foreign = [d for d in in_cat if d.foreign]
        if not foreign:
            continue
        severity = max(d.severity or category.info.severity for d in foreign)
        description = category.info.risk
        if category in REDUNDANT_LAYERS and any(d.foreign is False for d in in_cat):
            severity = severity.lower()
            description += " Часть серверов находится в России, это снижает риск."
        notes = _join_unique(d.note for d in foreign)
        if notes:
            description += " " + " ".join(notes)
        names = ", ".join(f"{d.service} ({d.country_ru})" for d in foreign)
        # A service-specific tip only when it is the only one; several tips read badly
        # glued together, so the category's general advice is used instead.
        specific = _join_unique(d.alternative for d in foreign)
        alternatives = specific if len(specific) == 1 else [category.info.alternatives]
        findings.append(
            Finding(
                category=category,
                title=f"{category.title}: {names}",
                severity=severity,
                description=description,
                recommendation=" ".join(alternatives),
                services=[d.service for d in foreign],
            )
        )
    return findings


def redirect_target(facts: Facts) -> str | None:
    """The other registrable domain the homepage redirected to, if any."""
    host = urlsplit(facts.final_url or "").hostname
    if not host:
        return None
    target = registrable_domain(host.lower())
    return target if target != facts.domain else None


def analyze(facts: Facts, started_at: datetime | None = None) -> Report:
    report = Report(target=facts.host)
    if started_at is not None:
        report.started_at = started_at
    deps, notes = find_dependencies(facts)
    report.dependencies = deps
    report.findings = build_findings(deps)
    report.facts = facts.to_dict()
    report.notes = facts.notes + notes
    problem = facts.page_problem
    if problem:
        # An empty answer is said too: a proxy's bare 503 for an unreachable host left
        # the report silent and the grade at A.
        hint = (
            "" if facts.rendered else " Попробуйте режим --browser: он открывает сайт в браузере."
        )
        cap = ", оценки не выше B" if facts.page_unseen else ""
        report.notes.append(
            f"Главную страницу проанализировать не удалось: {facts.page_unseen or problem}. "
            f"Скрипты и виджеты не проверены{cap}, проверка 152-ФЗ неполная.{hint}"
        )
    elif facts.html:
        pages = 1 + len(facts.extra_pages)
        where = (
            f"Проверено страниц: {pages} (главная и ещё {pages - 1})"
            if pages > 1
            else "Проверена только главная страница"
        )
        if facts.rendered:
            how = "Сайт открывался в браузере, учтены все скрипты, загруженные страницами."
        else:
            how = (
                "Скрипты искались в коде страниц: то, что подгружается скриптами, может не "
                "попасть в отчёт (режим --browser находит больше)."
            )
        report.notes.append(f"{where}. {how}")
    moved = redirect_target(facts)
    if moved:
        # pochtabank.ru opens vtb.ru: the report mixed two companies without a word.
        report.notes.append(
            f"Сайт перенаправляет на другой домен: {moved}. Хостинг, DNS, почта и сертификат "
            f"измерены у {facts.domain}, а скрипты и проверки страниц — у {moved}. "
            f"Проверьте {moved} отдельно."
        )
    if facts.tls_trusted is False:
        report.notes.append(TLS_UNTRUSTED_NOTE)
    report.finished_at = datetime.now(timezone.utc)
    return report
