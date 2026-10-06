"""Russian public registries: ЕГРЮЛ/ЕГРИП (ФНС) and the РКН register of
personal-data operators. Both are free public search pages without an API key.
"""

from __future__ import annotations

import asyncio
import html
import re
from dataclasses import dataclass
from datetime import date, datetime
from typing import Any

import httpx

from suveren.errors import ModuleError

BROWSER_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/130.0 Safari/537.36"
)
EGRUL_URL = "https://egrul.nalog.ru/"
RKN_URL = "https://pd.rkn.gov.ru/operators-registry/operators-list/"
_ORG_NAME = re.compile(
    r"общество|акционерн|компани|предприяти|учреждени|\b(?:ооо|ао|пао|зао|оао|нко)\b", re.I
)


def parse_ru_date(value: str | None) -> date | None:
    if not value:
        return None
    try:
        return datetime.strptime(value.strip(), "%d.%m.%Y").date()
    except ValueError:
        return None


@dataclass(slots=True)
class EgrulRecord:
    name_full: str
    name_short: str | None
    inn: str | None
    ogrn: str | None
    kpp: str | None
    registered: date | None
    terminated: date | None
    head: str | None
    region: str | None
    individual: bool

    @property
    def active(self) -> bool:
        return self.terminated is None

    @property
    def head_name(self) -> str | None:
        """'ГЕНЕРАЛЬНЫЙ ДИРЕКТОР: Иванов Иван Иванович' -> 'Иванов Иван Иванович'."""
        if not self.head:
            return None
        return self.head.split(":", 1)[-1].strip() or None

    @property
    def head_is_org(self) -> bool:
        """The company is run by a managing company rather than a person."""
        name = self.head_name or ""
        return (
            bool(_ORG_NAME.search(name)) or "управляющая организация" in (self.head or "").lower()
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "name_full": self.name_full,
            "name_short": self.name_short,
            "inn": self.inn,
            "ogrn": self.ogrn,
            "kpp": self.kpp,
            "registered": self.registered.isoformat() if self.registered else None,
            "terminated": self.terminated.isoformat() if self.terminated else None,
            "head": self.head,
            "region": self.region,
            "individual": self.individual,
        }


def parse_egrul_rows(payload: dict[str, Any]) -> list[EgrulRecord]:
    records = []
    for row in payload.get("rows", []):
        records.append(
            EgrulRecord(
                name_full=row.get("n") or row.get("c") or "",
                name_short=row.get("c"),
                inn=row.get("i"),
                ogrn=row.get("o"),
                kpp=row.get("p"),
                registered=parse_ru_date(row.get("r")),
                terminated=parse_ru_date(row.get("e")),
                head=row.get("g"),
                region=row.get("rn"),
                individual=row.get("k") == "fl",
            )
        )
    return records


async def egrul_search(client: httpx.AsyncClient, query: str) -> list[EgrulRecord]:
    """Search ЕГРЮЛ/ЕГРИП by ИНН or ОГРН via the public egrul.nalog.ru form."""
    headers = {"User-Agent": BROWSER_UA, "Referer": EGRUL_URL}
    try:
        resp = await client.post(
            EGRUL_URL, data={"query": query, "region": "", "page": ""}, headers=headers
        )
        resp.raise_for_status()
        token = resp.json()
        if token.get("captchaRequired"):
            raise ModuleError("сайт ФНС запросил капчу, попробуйте позже")
        for _ in range(10):
            result = await client.get(f"{EGRUL_URL}search-result/{token['t']}", headers=headers)
            result.raise_for_status()
            data = result.json()
            if data.get("status") != "wait":
                return parse_egrul_rows(data)
            await asyncio.sleep(0.7)
    except (httpx.HTTPError, ValueError, KeyError) as exc:
        raise ModuleError(f"ЕГРЮЛ недоступен ({type(exc).__name__})") from exc
    raise ModuleError("ЕГРЮЛ не ответил вовремя")


@dataclass(slots=True)
class RknOperator:
    reg_number: str
    name: str
    inn: str | None
    basis: str
    registered: date | None
    processing_since: date | None

    @property
    def url(self) -> str:
        return f"{RKN_URL}?id={self.reg_number}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "reg_number": self.reg_number,
            "name": self.name,
            "inn": self.inn,
            "basis": self.basis,
            "registered": self.registered.isoformat() if self.registered else None,
            "processing_since": self.processing_since.isoformat()
            if self.processing_since
            else None,
            "url": self.url,
        }


_ROW_RE = re.compile(r"<tr[^>]*>(.*?)</tr>", re.S | re.I)
_CELL_RE = re.compile(r"<td[^>]*>(.*?)</td>", re.S | re.I)


def _text(fragment: str) -> str:
    fragment = re.sub(r"<br\s*/?>", "\n", fragment, flags=re.I)
    fragment = re.sub(r"<[^>]+>", "", fragment)
    return html.unescape(fragment).replace("\xa0", " ").strip()


def parse_rkn_operators(page: str) -> list[RknOperator]:
    operators = []
    for row in _ROW_RE.findall(page):
        if "?id=" not in row:
            continue
        cells = _CELL_RE.findall(row)
        if len(cells) < 5:
            continue
        lines = [ln.strip() for ln in _text(cells[1]).splitlines() if ln.strip()]
        inn = next(
            (ln.split(":", 1)[1].strip() for ln in lines if ln.upper().startswith("ИНН")), None
        )
        operators.append(
            RknOperator(
                reg_number=_text(cells[0]),
                name=lines[0] if lines else "",
                inn=inn,
                basis=_text(cells[2]),
                registered=parse_ru_date(_text(cells[3])),
                processing_since=parse_ru_date(_text(cells[4])),
            )
        )
    return operators


async def rkn_operator(client: httpx.AsyncClient, inn: str) -> RknOperator | None:
    """Look up an operator in the РКН register by ИНН; None if it is not registered."""
    params = {"act": "search", "name_full": "", "inn": inn, "regn": ""}
    try:
        resp = await client.get(RKN_URL, params=params, headers={"User-Agent": BROWSER_UA})
        resp.raise_for_status()
    except httpx.HTTPError as exc:
        raise ModuleError(f"реестр Роскомнадзора недоступен ({type(exc).__name__})") from exc
    matches = [op for op in parse_rkn_operators(resp.text) if op.inn == inn]
    return matches[0] if matches else None
