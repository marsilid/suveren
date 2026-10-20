"""Where the visitor's data goes: every third-party host the pages load, grouped by the
country of its owner (a known service) or of the network it sits in (an unknown one).

Opening the page sends the visitor's IP address, and often cookies, to each of them;
by Роскомнадзор's position that is personal data, so foreign hosts are cross-border
transfer under 152-ФЗ, ст. 12. Nothing is probed: the hosts are those the page itself
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
    for info in hosts.values():
        code = (info.country or UNKNOWN_COUNTRY).upper()
        name = info.service or info.host
        names = by_country.setdefault(code, [])
        if name not in names:
            names.append(name)
    rows = [
        {
            "country": code,
            "name": "страна не определена" if code == UNKNOWN_COUNTRY else country_name(code),
            "foreign": code not in ("RU", UNKNOWN_COUNTRY),
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
    countries = len(foreign)
    return Check(
        GROUP_152,
        TITLE,
        Status.WARN,
        text,
        f"Данные уходят за рубеж ({_countries(countries)}): по позиции Роскомнадзора это "
        "трансграничная передача персональных данных. Укажите эти страны и сервисы в "
        "политике и уведомите Роскомнадзор о трансграничной передаче (152-ФЗ, ст. 12) "
        "или замените сервисы российскими.",
        law="152-ФЗ, ст. 12",
    )


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
