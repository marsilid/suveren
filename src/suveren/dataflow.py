"""Where the visitor's data goes: every third-party host the pages load, grouped by the
country of its owner (a known service) or of the network it sits in (an unknown one).

Opening the page sends the visitor's IP address, and often cookies, to each of them;
by Роскомнадзор's position that is personal data. Cross-border transfer is defined by
the recipient, a foreign company or state (152-ФЗ, ст. 3 п. 11), so a known foreign
service is a transfer under ст. 12, while an unknown host on a foreign network only
shows where its server is. Nothing is probed: the hosts are those the page itself
loads, and the lookups are DNS only.
"""

from __future__ import annotations

from typing import Any

from suveren.checks import GROUP_152, Check, Status
from suveren.cutoff import HostInfo, classify
from suveren.models import Dependency
from suveren.utils import country_name

TITLE = "Куда уходят данные посетителя"
UNKNOWN_COUNTRY = "??"


def flow(hosts: dict[str, HostInfo]) -> list[dict[str, Any]]:
    """Countries with their services, foreign first, most services first."""
    by_country: dict[str, list[str]] = {}
    known: dict[str, bool] = {}  # a service whose owner is known, in this country
    for info in hosts.values():
        code = (info.country or UNKNOWN_COUNTRY).upper()
        name = info.service or info.host
        names = by_country.setdefault(code, [])
        if name not in names:
            names.append(name)
        known[code] = known.get(code, False) or bool(info.service and not info.via_network)
    rows = [
        {
            "country": code,
            "name": "страна не определена" if code == UNKNOWN_COUNTRY else country_name(code),
            "foreign": code not in ("RU", UNKNOWN_COUNTRY),
            "known_owner": known[code],
            "services": sorted(names),
        }
        for code, names in by_country.items()
    ]
    return sorted(rows, key=lambda r: (not r["foreign"], -len(r["services"]), r["name"]))


def flow_check(rows: list[dict[str, Any]]) -> Check:
    if not rows:
        return Check(
            GROUP_152,
            TITLE,
            Status.OK,
            "Сторонних сервисов на проверенных страницах нет: данные посетителя получает "
            "только сам сайт.",
            law="152-ФЗ, ст. 12",
        )
    services = sum(len(r["services"]) for r in rows)
    foreign = [r for r in rows if r["foreign"]]
    listed = "; ".join(f"{r['name']} — {', '.join(r['services'])}" for r in rows)
    one = services % 10 == 1 and services % 100 != 11
    text = (
        f"Открыв сайт, браузер посетителя передаёт его IP-адрес, а часто и cookies "
        f"{services} {'стороннему сервису' if one else 'сторонним сервисам'}: {listed}. "
        "Страна — юрисдикция владельца сервиса, а для неизвестных базе — страна сети, "
        "где стоит сервер."
    )
    if not foreign:
        return Check(GROUP_152, TITLE, Status.OK, text, law="152-ФЗ, ст. 12")
    known = [r for r in foreign if r.get("known_owner", True)]
    # Hosts unknown to the base, on foreign networks only: the owner may be Russian.
    networks = [r for r in foreign if not r.get("known_owner", True)]
    advice = ""
    if known:
        advice = (
            f"Данные уходят иностранным компаниям ({_countries(len(known))}: "
            f"{', '.join(r['name'] for r in known)}): IP-адрес по позиции Роскомнадзора — "
            "персональные данные, а передача иностранному получателю — трансграничная "
            "(152-ФЗ, ст. 3 п. 11). Укажите эти страны и сервисы в политике и уведомите "
            "Роскомнадзор о трансграничной передаче (ст. 12) или замените сервисы "
            "российскими."
        )
    if networks:
        where = ", ".join(r["name"] for r in networks)
        advice += (
            f" {'Ещё в' if known else 'В'} стране «{where}» стоят серверы сервисов, чьи "
            "владельцы не известны. Если сервис принадлежит иностранной компании, это тоже "
            "трансграничная передача; если это ваш сервер или российской компании — вопрос "
            "хранения данных в России (ст. 18 ч. 5)."
            if len(networks) == 1
            else f" {'Ещё в' if known else 'В'} странах ({where}) стоят серверы сервисов, чьи "
            "владельцы не известны. Если сервис принадлежит иностранной компании, это тоже "
            "трансграничная передача; если это ваш сервер или российской компании — вопрос "
            "хранения данных в России (ст. 18 ч. 5)."
        )
    return Check(GROUP_152, TITLE, Status.WARN, text, advice.strip(), law="152-ФЗ, ст. 12")


def _countries(n: int) -> str:
    if n % 10 == 1 and n % 100 != 11:
        return f"{n} страна"
    if n % 10 in (2, 3, 4) and n % 100 not in (12, 13, 14):
        return f"{n} страны"
    return f"{n} стран"


async def run_dataflow(
    urls: list[str],
    site: str,
    collector: Any,
    landed: str | None = None,
    deps: list[Dependency] | None = None,
) -> tuple[Check, list[dict[str, Any]]]:
    """``deps``: services found in the page code (a pixel set up by an inline script is
    found there even when its request was not seen); the map never shows fewer."""
    hosts = await classify(urls, site, collector, (landed,) if landed else ())
    for d in deps or []:
        if d.category.info.visitor_data and d.country:
            hosts.setdefault(f"service:{d.service}", HostInfo(d.service, d.service, d.country))
    rows = flow(hosts)
    return flow_check(rows), rows
