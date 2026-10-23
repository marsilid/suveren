"""`suveren company`: who is behind an ИНН or a website, and are they sanctioned."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date, datetime, timezone
from typing import Any

import httpx

from suveren.checks import Check, Status
from suveren.collect import make_client, page_problem, parse_whois_org, whois_raw
from suveren.discover import discover_inns
from suveren.errors import InvalidTargetError, ModuleError
from suveren.inn import classify
from suveren.registries import EgrulRecord, RknOperator, egrul_search, rkn_operator
from suveren.render import render
from suveren.sanctions import (
    SOURCE_TITLES,
    Hit,
    load_index,
    name_key,
    screen_company,
    screen_person,
)
from suveren.utils import normalize_domain, registrable_domain

GROUP = "Проверка компании"
YOUNG_DAYS = 365


@dataclass(slots=True)
class CompanyReport:
    query: str
    domain: str | None = None
    inn: str | None = None
    ogrn: str | None = None
    inn_source: str | None = None
    egrul: EgrulRecord | None = None
    operator: RknOperator | None = None
    # Set when a registry did not answer: "not found" then means "not checked".
    egrul_error: str | None = None
    operator_error: str | None = None
    company_hits: list[Hit] = field(default_factory=list)
    person_hits: list[Hit] = field(default_factory=list)
    sanctions_sources: list[str] = field(default_factory=list)
    whois_org: str | None = None
    site_problem: str | None = None
    checks: list[Check] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    finished_at: datetime | None = None

    @property
    def title(self) -> str:
        if self.egrul:
            return self.egrul.name_short or self.egrul.name_full
        return self.domain or self.query

    @property
    def duration(self) -> float:
        if self.finished_at is None:
            return 0.0
        return (self.finished_at - self.started_at).total_seconds()

    @property
    def hits(self) -> list[Hit]:
        return self.company_hits + self.person_hits

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": "suveren",
            "kind": "company",
            "query": self.query,
            "domain": self.domain,
            "inn": self.inn,
            "ogrn": self.ogrn,
            "inn_source": self.inn_source,
            "egrul": self.egrul.to_dict() if self.egrul else None,
            "rkn_operator": self.operator.to_dict() if self.operator else None,
            "sanctions": {
                "sources": [SOURCE_TITLES.get(s, s) for s in self.sanctions_sources],
                "company": [h.to_dict() for h in self.company_hits],
                "head": [h.to_dict() for h in self.person_hits],
            },
            "whois_org": self.whois_org,
            "checks": [c.to_dict() for c in self.checks],
            "notes": self.notes,
            "started_at": self.started_at.isoformat(),
        }


def _years(n: int) -> str:
    if n % 10 == 1 and n % 100 != 11:
        return f"{n} год"
    if n % 10 in (2, 3, 4) and n % 100 not in (12, 13, 14):
        return f"{n} года"
    return f"{n} лет"


def render_age(registered: date, today: date) -> str:
    days = (today - registered).days
    if days < 60:
        return f"{days} дн."
    if days < 730:
        return f"{days // 30} мес."
    return _years(days // 365)


def build_checks(report: CompanyReport, *, sanctions_ok: bool | None, today: date) -> list[Check]:
    """``sanctions_ok`` is None when screening was switched off."""
    checks: list[Check] = []
    rec = report.egrul

    if rec is None and report.egrul_error:
        # Offline, Sberbank came out "not found" under a red "ЕСТЬ ПРОБЛЕМЫ".
        checks.append(
            Check(
                GROUP,
                "ЕГРЮЛ / ЕГРИП",
                Status.UNKNOWN,
                "Не проверено: ЕГРЮЛ не ответил.",
                "Повторите проверку позже или найдите компанию на egrul.nalog.ru.",
            )
        )
    elif rec is None:
        checks.append(
            Check(
                GROUP,
                "ЕГРЮЛ / ЕГРИП",
                Status.FAIL if report.inn or report.ogrn else Status.UNKNOWN,
                "Организация с такими реквизитами не найдена."
                if report.inn or report.ogrn
                else "Реквизиты компании неизвестны.",
            )
        )
    elif rec.active:
        checks.append(Check(GROUP, "ЕГРЮЛ / ЕГРИП", Status.OK, "Действующая организация."))
    else:
        checks.append(
            Check(
                GROUP,
                "ЕГРЮЛ / ЕГРИП",
                Status.FAIL,
                f"Прекратила деятельность {rec.terminated:%d.%m.%Y}.",
                "Не заключайте договоры с ликвидированной организацией.",
            )
        )

    if rec and rec.registered:
        days = (today - rec.registered).days
        age = render_age(rec.registered, today)
        if days < YOUNG_DAYS:
            checks.append(
                Check(
                    GROUP,
                    "Возраст компании",
                    Status.WARN,
                    f"Зарегистрирована {rec.registered:%d.%m.%Y}, всего {age} назад.",
                    "Молодые компании чаще оказываются фирмами-однодневками: проверьте "
                    "контрагента внимательнее.",
                )
            )
        else:
            checks.append(
                Check(
                    GROUP,
                    "Возраст компании",
                    Status.OK,
                    f"Зарегистрирована {rec.registered:%d.%m.%Y} ({age}).",
                )
            )

    sources = ", ".join(SOURCE_TITLES.get(s, s) for s in report.sanctions_sources)
    # "Не найдена в списках: США" read as clean while the EU and UK lists had not loaded:
    # a clean answer from part of the lists is "not checked", with what is missing.
    missing = ", ".join(t for k, t in SOURCE_TITLES.items() if k not in report.sanctions_sources)
    clean = Status.UNKNOWN if missing else Status.OK
    gap = f" Не загрузились: {missing}." if missing else ""
    retry = "Повторите проверку позже с --refresh." if missing else ""
    if sanctions_ok is None:
        pass
    elif not sanctions_ok:
        checks.append(Check(GROUP, "Санкционные списки", Status.UNKNOWN, "Списки не загрузились."))
    elif rec is None and not (report.inn or report.ogrn):
        checks.append(
            Check(
                GROUP,
                "Санкционные списки",
                Status.UNKNOWN,
                "Не с чем сверять: ни ИНН, ни название компании не известны.",
            )
        )
    else:
        # FAIL takes the same ИНН/ОГРН: names repeat, and «Арсенал» with its own ИНН was
        # "in the sanctions lists" because an LLC ARSENAL with another one is.
        strong = [h for h in report.company_hits if h.how == "id"]
        named = [h for h in report.company_hits if h.how == "name"]
        partial = [h for h in report.company_hits if h.how == "partial"]
        others = [h for h in report.company_hits if h.how == "other"]
        also = (
            f" Похожие названия у организаций с другими ИНН/ОГРН ({len(others)}) — в таблице "
            "ниже, это другие компании."
            if others
            else ""
        )
        if strong:
            lists = ", ".join(dict.fromkeys(SOURCE_TITLES[h.entry.source] for h in strong))
            checks.append(
                Check(
                    GROUP,
                    "Санкционные списки",
                    Status.FAIL,
                    ("Предприниматель" if rec and rec.individual else "Организация")
                    + f" в санкционных списках: {lists} (совпали ИНН или ОГРН).",
                    "Сделки с ней несут риск вторичных санкций для банков и партнёров. "
                    "Подробности в таблице ниже.",
                )
            )
        elif named:
            lists = ", ".join(dict.fromkeys(SOURCE_TITLES[h.entry.source] for h in named))
            checks.append(
                Check(
                    GROUP,
                    "Санкционные списки",
                    Status.WARN,
                    f"Название совпадает с организацией в списках: {lists}. Реквизитов, "
                    "чтобы сверить, у записи нет или ИНН компании неизвестен.",
                    "Сверьте адрес и руководителя с записью в таблице ниже: под санкциями "
                    "бывают и новые юрлица со старым названием.",
                )
            )
        elif partial:
            checks.append(
                Check(
                    GROUP,
                    "Санкционные списки",
                    Status.WARN,
                    f"Под санкциями есть организации с похожим названием ({len(partial)}).",
                    "Скорее всего, это другие компании, но проверьте таблицу ниже.",
                )
            )
        else:
            checks.append(
                Check(
                    GROUP,
                    "Санкционные списки",
                    clean,
                    (f"Не найдена в списках: {sources}." if sources else "Не найдена.")
                    + gap
                    + also,
                    retry,
                )
            )
        head = rec.person_name if rec else None
        if head and rec and rec.head_is_org:
            # Screened by name only (no ИНН of the manager here): a lead, not a verdict.
            person_strong = any(h.how == "id" for h in report.person_hits)
            title = "Управляющая организация в санкционных списках"
            if report.person_hits:
                checks.append(
                    Check(
                        GROUP,
                        title,
                        Status.FAIL if person_strong else Status.WARN,
                        f"{head}: "
                        + (
                            "найдена в санкционных списках."
                            if person_strong
                            else "похожие названия."
                        ),
                        "Подробности в таблице ниже.",
                    )
                )
            else:
                checks.append(Check(GROUP, title, clean, f"{head}: совпадений нет.{gap}", retry))
        elif head:
            # A sole trader found by ИНН is that very person: "may be a namesake" next to
            # the ИНН match contradicted it.
            by_inn = {id(h.entry) for h in strong}
            if rec and rec.individual and any(id(h.entry) in by_inn for h in report.person_hits):
                checks.append(
                    Check(
                        GROUP,
                        "Руководитель в санкционных списках",
                        Status.FAIL,
                        f"{head}: предприниматель в санкционных списках, совпал ИНН.",
                        "Подробности в таблице ниже.",
                    )
                )
            elif report.person_hits:
                checks.append(
                    Check(
                        GROUP,
                        "Руководитель в санкционных списках",
                        Status.WARN,
                        f"{head}: найдены совпадения "
                        + (
                            "по фамилии, имени и отчеству"
                            if any(h.how == "person_full" for h in report.person_hits)
                            else "по фамилии и имени"
                        )
                        + f" ({len(report.person_hits)}). Записи с другим отчеством не учтены.",
                        "Это может быть полный тёзка: сверьте дату рождения и должность в списке.",
                    )
                )
            else:
                checks.append(
                    Check(
                        GROUP,
                        "Руководитель в санкционных списках",
                        clean,
                        f"{head}: совпадений нет.{gap}",
                        retry,
                    )
                )

    if report.inn:
        if report.operator:
            op = report.operator
            since = f" от {op.registered:%d.%m.%Y}" if op.registered else ""
            checks.append(
                Check(
                    GROUP,
                    "Реестр операторов персональных данных",
                    Status.OK,
                    f"№ {op.reg_number}{since}.",
                    link=op.url,
                )
            )
        elif report.operator_error:
            checks.append(
                Check(
                    GROUP,
                    "Реестр операторов персональных данных",
                    Status.UNKNOWN,
                    "Не проверено: реестр Роскомнадзора не ответил.",
                    "Повторите проверку позже или найдите компанию на pd.rkn.gov.ru.",
                )
            )
        else:
            checks.append(
                Check(
                    GROUP,
                    "Реестр операторов персональных данных",
                    Status.WARN,
                    "В реестре Роскомнадзора не найдена.",
                    "Если компания обрабатывает персональные данные клиентов или сотрудников, "
                    "она обязана подать уведомление (152-ФЗ, ст. 22).",
                )
            )

    if report.domain:
        checks.append(_site_check(report))
    laws = {"SUV-CO-006": "152-ФЗ, ст. 22", "SUV-CO-007": "ЗоЗПП, ст. 26.1"}
    for check in checks:
        check.law = laws.get(check.id)
    return checks


def _site_check(report: CompanyReport) -> Check:
    title = "Сайт и компания"
    rec = report.egrul
    if not report.inn and report.site_problem:
        return Check(
            GROUP,
            title,
            Status.UNKNOWN,
            f"Сайт {report.domain} проверить не удалось: {report.site_problem}.",
            "Попробуйте параметр --browser или укажите ИНН компании вручную: "
            "suveren company <ИНН>.",
        )
    if not report.inn:
        return Check(
            GROUP,
            title,
            Status.WARN,
            f"На сайте {report.domain} не найден ИНН владельца.",
            "Продавец обязан указывать на сайте наименование и ОГРН (закон «О защите прав "
            "потребителей», ст. 26.1). Отсутствие реквизитов — повод насторожиться.",
        )
    where = f"ИНН {report.inn} указан на сайте"
    if not report.whois_org or rec is None:
        return Check(
            GROUP,
            title,
            Status.OK,
            f"{where}. Владелец домена в WHOIS скрыт, сравнить не с чем.",
            link=report.inn_source,
        )
    org_key = name_key(report.whois_org)
    names = [rec.name_full, rec.name_short or ""]
    if any(org_key and (org_key <= name_key(n) or name_key(n) <= org_key) for n in names if n):
        return Check(
            GROUP,
            title,
            Status.OK,
            f"{where}, владелец домена в WHOIS совпадает: {report.whois_org}.",
            link=report.inn_source,
        )
    return Check(
        GROUP,
        title,
        Status.WARN,
        f"{where}, но домен в WHOIS записан на «{report.whois_org}».",
        "Так бывает, если домен оформлен на агентство или другую компанию группы. Но это и "
        "признак сайта-клона: убедитесь, что сайт действительно принадлежит этой компании.",
        link=report.inn_source,
    )


async def _from_site(
    client: httpx.AsyncClient, report: CompanyReport, timeout: float, *, browser: bool = False
) -> None:
    assert report.domain
    html, base, status = "", f"https://{report.domain}/", None
    for url in (base, f"http://{report.domain}/"):
        try:
            resp = await client.get(url)
            html, base, status = resp.text[:3_000_000], str(resp.url), resp.status_code
            break
        except httpx.HTTPError:
            continue
    problem = page_problem(status, html) if html else "сайт не открылся"
    if problem and browser:
        try:
            page = await render(base, timeout=max(timeout, 25.0))
            html, base = page.html, page.final_url
            problem = page_problem(page.status, html, rendered=True)
        except ModuleError as exc:
            report.notes.append(f"Режим --browser не сработал: {exc}.")
    report.site_problem = problem
    if problem:
        report.notes.append(f"Сайт {report.domain}: {problem}.")
    else:
        inns, source = await discover_inns(client, base, html)
        if inns:
            report.inn, report.inn_source = inns[0], source
            if len(inns) > 1:
                report.notes.append(
                    "На сайте указано несколько ИНН: " + ", ".join(inns) + f". Проверен {inns[0]}."
                )
    raw = await whois_raw(registrable_domain(report.domain), timeout)
    report.whois_org = parse_whois_org(raw) if raw else None


async def run_company(
    target: str,
    *,
    timeout: float = 15.0,
    sanctions: bool = True,
    refresh: bool = False,
    browser: bool = False,
) -> CompanyReport:
    value = target.strip()
    kind = classify(value)
    report = CompanyReport(query=value)
    if kind == "inn":
        report.inn = value
    elif kind == "ogrn":
        report.ogrn = value
    else:
        try:
            report.domain = normalize_domain(value)
        except InvalidTargetError as exc:
            raise InvalidTargetError(
                f"«{target}» — это не ИНН, не ОГРН и не домен (проверьте контрольную цифру)"
            ) from exc

    async with make_client(timeout) as client:
        if report.domain:
            await _from_site(client, report, timeout, browser=browser)

        query = report.inn or report.ogrn
        if query:
            try:
                rows = await egrul_search(client, query)
                exact = [r for r in rows if query in (r.inn, r.ogrn)]
                report.egrul = next(iter(exact or rows), None)
            except ModuleError as exc:
                report.egrul_error = str(exc)
                report.notes.append(f"ЕГРЮЛ: {exc}.")
            if report.egrul:
                report.inn = report.inn or report.egrul.inn
                report.ogrn = report.ogrn or report.egrul.ogrn
            if report.inn:
                try:
                    report.operator = await rkn_operator(client, report.inn)
                except ModuleError as exc:
                    report.operator_error = str(exc)
                    report.notes.append(f"Реестр операторов ПДн: {exc}.")

        sanctions_ok: bool | None = None
        if sanctions:
            sanctions_ok = False
            try:
                index = await load_index(client, refresh=refresh)
                sanctions_ok = True
                report.sanctions_sources = index.sources
                report.notes += index.notes
                rec = report.egrul
                ids = [i for i in (report.inn, report.ogrn) if i]
                names = [rec.name_full, rec.name_short or ""] if rec else []
                if ids or names:
                    # A sole trader is a person in the lists: its ИНН sits on a person entry.
                    report.company_hits = screen_company(
                        index, ids, names, persons=bool(rec and rec.individual)
                    )
                head = rec.person_name if rec else None
                if head and rec and rec.head_is_org:
                    # Run by a managing company: screen it as a company, not as a name.
                    report.person_hits = screen_company(index, [], [head])
                elif head:
                    report.person_hits = screen_person(index, head)
            except ModuleError as exc:
                report.notes.append(f"Санкционные списки: {exc}.")

    report.checks = build_checks(
        report, sanctions_ok=sanctions_ok, today=datetime.now(timezone.utc).date()
    )
    report.finished_at = datetime.now(timezone.utc)
    return report
