"""Turns collected facts into dependencies and findings."""

from __future__ import annotations

from collections.abc import Callable, Iterable
from datetime import datetime, timezone

from suveren import services as db
from suveren.collect import Facts, HostInfo, NetInfo
from suveren.models import Category, Dependency, Finding, Report
from suveren.services import Service

# Layers where a domestic server next to a foreign one is real redundancy.
REDUNDANT_LAYERS = frozenset({Category.DNS, Category.MAIL, Category.HOSTING, Category.CDN})


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


def _server_deps(
    category: Category,
    hosts: list[HostInfo],
    lookup: Callable[[str], Service | None],
    label: str,
) -> list[Dependency]:
    deps = []
    for h in hosts:
        evidence = f"{label} {h.host}"
        service = lookup(h.host) or (db.by_network(h.net.asn, h.net.as_name) if h.net else None)
        if service:
            deps.append(_from_service(category, service, evidence))
        else:
            deps.append(_from_network(category, h.net, h.host, evidence))
    return deps


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
            deps.append(Dependency(Category.REGISTRAR, facts.registrar, None, "WHOIS"))

    deps += _server_deps(Category.DNS, facts.ns, db.by_ns, "NS")
    deps += _server_deps(Category.MAIL, facts.mx, db.by_mx, "MX")

    hidden_origin = False
    for net in facts.web:
        evidence = f"IP {net.ip}" + (f" (AS{net.asn})" if net.asn else "")
        service = db.by_network(net.asn, net.as_name)
        if service:
            category = Category.CDN if service.cdn else Category.HOSTING
            hidden_origin |= service.cdn
            deps.append(_from_service(category, service, evidence))
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

    page_text = facts.html + "\n" + "\n".join(facts.loaded_urls)
    for service, matched in db.scan_page(page_text):
        assert service.category is not None
        deps.append(_from_service(service.category, service, matched))

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
    if facts.html and problem:
        hint = (
            "" if facts.rendered else " Попробуйте режим --browser: он открывает сайт в браузере."
        )
        report.notes.append(
            f"Главную страницу проанализировать не удалось: {problem}. Скрипты и виджеты не "
            f"проверены, проверка 152-ФЗ неполная.{hint}"
        )
    elif facts.rendered:
        report.notes.append(
            "Сайт открывался в браузере: учтены все скрипты, загруженные главной страницей. "
            "Сервисы с других страниц сайта могут не попасть в отчёт."
        )
    elif facts.html:
        report.notes.append(
            "Скрипты и виджеты искались в коде главной страницы. Сервисы, которые подключаются "
            "на других страницах или подгружаются скриптами, могут не попасть в отчёт "
            "(режим --browser находит больше)."
        )
    if facts.tls_trusted is False:
        report.notes.append(
            "SSL-сертификату сайта не доверяет стандартный набор корневых сертификатов. "
            "Если он выпущен НУЦ Минцифры, браузеры без российского корневого сертификата "
            "(Chrome, Firefox, Safari по умолчанию) покажут посетителям ошибку."
        )
    report.finished_at = datetime.now(timezone.utc)
    return report
